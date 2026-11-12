//! Read and write account logs held by the registry program. Every call blocks; there is no
//! async runtime.
//!
//! [`Registry::fetch`] verifies what the RPC returns against the address asked about, so an RPC
//! can withhold a log or serve an older one, but cannot forge one. A write is authorized by the
//! log's own signature; the payer configured with [`Registry::with_payer`] only pays its fee, so
//! any funded account can relay any account's log.
//!
//! [`Registry`] implements libchat's [`AccountProvider`] and [`AccountPublisher`], so it can back
//! an [`Account`](logos_account::Account) or an
//! [`AccountResolver`](logos_account::AccountResolver) directly. The program must be deployed
//! first, at the account the registry was connected to; the `account-registry` CLI does that.

use std::{
    thread,
    time::{Duration, Instant},
};

use account_log::{
    ACCOUNT_LOG_DOMAIN, AccountAddr, AccountLog, Ed25519SigningKey, SignedAccountLog,
};
use account_registry_core::{Instruction, LogUpdate};
pub use account_registry_core::{MAX_LOG_PAYLOAD_BYTES, append_gas_limit};
use borsh::BorshSerialize;
use lee::{
    FeeDeclaration, PublicKey, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use logos_account::{AccountProvider, AccountPublisher};

use rpc::{LeeTransaction, Sequencer};

pub use error::LezAccountRegError;
pub use lee::{Account, AccountId, PrivateKey, ProgramShardSelector};

mod error;
mod rpc;

/// How often to look for a submitted transaction's effect.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How long [`Registry::publish`] waits for its write to land. The public testnet makes about one
/// block a minute.
pub const PUBLISH_TIMEOUT: Duration = Duration::from_secs(300);

/// The base fee `max_fee` is sized against: 8x the genesis minimum, as LEZ's own wallet does,
/// so a transaction survives early congestion without re-signing.
const ASSUMED_BASE_FEE: u128 = 64;
const ASSUMED_DATA_BYTES: u128 = 100_000;

/// A connection to one sequencer, for the registry deployed at one program account.
#[derive(Clone)]
pub struct Registry {
    rpc: Sequencer,
    program: AccountId,
    payer: Option<PrivateKey>,
}

impl Registry {
    /// Connects to a sequencer, e.g. `http://localhost:3040`, for the registry whose program
    /// account is `program`. Does no I/O.
    pub fn connect(sequencer: &str, program: AccountId) -> Result<Self, LezAccountRegError> {
        let url = url::Url::parse(sequencer)?;
        Ok(Self {
            rpc: Sequencer::new(url.into()),
            program,
            payer: None,
        })
    }

    /// Pays the fees of every write with `payer`, a funded LEE public account.
    #[must_use]
    pub fn with_payer(mut self, payer: PrivateKey) -> Self {
        self.payer = Some(payer);
        self
    }

    /// The registry's program account.
    #[must_use]
    pub const fn program(&self) -> AccountId {
        self.program
    }

    /// The account holding `addr`'s log.
    #[must_use]
    pub fn account_id(&self, addr: &AccountAddr) -> AccountId {
        account_registry_core::derive_lee_account_id(&self.program, &addr_bytes(addr))
    }

    /// Fetches `addr`'s log, as libchat transmits it, after checking that `addr` signed it. `None`
    /// if nothing has been published for it.
    pub fn fetch(
        &self,
        addr: &AccountAddr,
    ) -> Result<Option<SignedAccountLog>, LezAccountRegError> {
        let account = self.rpc.get_account(self.account_id(addr))?;
        read(addr, account.data.shard(self.program).as_ref())
    }

    /// Publishes `log`, which must extend the log on chain, and waits until it is there.
    ///
    /// Only the new entries are part of the transaction; the signature covers the whole log. If
    /// another write lands first this fails with [`LezAccountRegError::Conflict`]: fetch, rebuild
    /// on top, and sign again.
    pub fn publish(
        &self,
        addr: &AccountAddr,
        log: &SignedAccountLog,
    ) -> Result<(), LezAccountRegError> {
        let prepared = self.prepare_append(addr, log)?;
        let _tx = self.send(
            prepared.program,
            vec![prepared.selector()],
            &[],
            &prepared.instruction,
            prepared.gas_limit,
        )?;
        self.await_append(&prepared, PUBLISH_TIMEOUT)
    }

    /// The write that takes the log on chain to `log`, for a caller that submits it itself, e.g.
    /// through a wallet. Refuses everything the program would refuse, since a refused
    /// transaction still pays.
    pub fn prepare_append(
        &self,
        addr: &AccountAddr,
        log: &SignedAccountLog,
    ) -> Result<PreparedAppend, LezAccountRegError> {
        let stored = self.fetch(addr)?;
        PreparedAppend::new(self.program, addr, stored.as_ref(), log)
    }

    /// Waits up to `timeout` for the chain to hold the log `prepared` was made for, after the
    /// caller submitted it. Call it only once the transaction was accepted: one that was never
    /// sent is indistinguishable from a slow one, and ends in
    /// [`LezAccountRegError::Timeout`].
    pub fn await_append(
        &self,
        prepared: &PreparedAppend,
        timeout: Duration,
    ) -> Result<(), LezAccountRegError> {
        poll_for(timeout, || {
            prepared.landed(self.fetch(&prepared.addr)?.as_ref())
        })
    }

    /// The current state of any account on the zone; a default account if nothing was ever
    /// written to it.
    pub fn account(&self, id: AccountId) -> Result<Account, LezAccountRegError> {
        self.rpc.get_account(id)
    }

    /// The native balance of any account on the zone, in its smallest unit.
    pub fn balance(&self, id: AccountId) -> Result<u128, LezAccountRegError> {
        self.rpc.get_account_balance(id)
    }

    /// The height of the zone's latest block.
    pub fn last_block(&self) -> Result<u64, LezAccountRegError> {
        self.rpc.get_last_block_id()
    }

    /// The block holding the transaction with hash `tx`, as [`Registry::send`] returned it, or
    /// `None` while it is in no block.
    pub fn transaction_block(&self, tx: &str) -> Result<Option<u64>, LezAccountRegError> {
        self.rpc.get_transaction_block(tx)
    }

    /// Sends a transaction to `program` over `selectors`, signed by `signers` and paid by the
    /// configured payer, each at its current nonce, reserving `gas_limit` execution gas. Returns
    /// the transaction's hash once the sequencer accepts it, not once it is in a block.
    pub fn send(
        &self,
        program: AccountId,
        selectors: Vec<ProgramShardSelector>,
        signers: &[&PrivateKey],
        instruction: impl BorshSerialize,
        gas_limit: u64,
    ) -> Result<String, LezAccountRegError> {
        let payer = self.payer.as_ref().ok_or(LezAccountRegError::NoPayer)?;
        let mut keys = signers.to_vec();
        if !keys.iter().any(|key| signer_id(key) == signer_id(payer)) {
            keys.push(payer);
        }
        let nonces = keys
            .iter()
            .map(|key| Ok(self.rpc.get_account(signer_id(key))?.nonce))
            .collect::<Result<_, LezAccountRegError>>()?;

        let fee = FeeDeclaration::new(
            signer_id(payer),
            gas_limit,
            0,
            (u128::from(gas_limit) + ASSUMED_DATA_BYTES) * ASSUMED_BASE_FEE,
        );
        let message = Message::try_new_with_fees(program, selectors, nonces, instruction, fee)?;
        let witnesses = WitnessSet::for_message(&message, &keys);
        let tx = PublicTransaction::new(message, witnesses);
        self.rpc.send_transaction(&LeeTransaction::Public(tx))
    }
}

/// An append ready to submit: a call to `program` over one account, `account`, not signing, in
/// `program`'s shard. It remembers the address and the log it was prepared for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedAppend {
    /// The registry's program account, which the transaction calls.
    pub program: AccountId,
    /// The account holding the log.
    pub account: AccountId,
    /// Execution gas to reserve; see [`append_gas_limit`].
    pub gas_limit: u64,
    addr: AccountAddr,
    log: SignedAccountLog,
    instruction: Instruction,
    base: Vec<u8>,
}

impl PreparedAppend {
    /// The write that takes `addr`'s log from `stored`, `None` if nothing is published, to `log`.
    fn new(
        program: AccountId,
        addr: &AccountAddr,
        stored: Option<&SignedAccountLog>,
        log: &SignedAccountLog,
    ) -> Result<Self, LezAccountRegError> {
        let base = stored.map_or(ACCOUNT_LOG_DOMAIN, |stored| stored.payload.as_bytes());
        let instruction = Instruction::Append(append_instruction(addr, base, log)?);
        Ok(Self {
            program,
            account: account_registry_core::derive_lee_account_id(&program, &addr_bytes(addr)),
            gas_limit: append_gas_limit(log.payload.as_bytes().len()),
            addr: addr.clone(),
            log: log.clone(),
            instruction,
            base: base.to_vec(),
        })
    }

    /// The instruction data: the borsh-encoded `Append`.
    #[must_use]
    pub fn instruction_data(&self) -> Vec<u8> {
        borsh::to_vec(&self.instruction).expect("borsh encoding into a Vec cannot fail")
    }

    fn selector(&self) -> ProgramShardSelector {
        ProgramShardSelector::new(self.account, self.program)
    }

    /// Whether `stored`, the log now on chain, is the one this append writes. Fails with
    /// [`LezAccountRegError::Conflict`] if it is neither that nor the log the append started from.
    fn landed(&self, stored: Option<&SignedAccountLog>) -> Result<bool, LezAccountRegError> {
        match stored {
            Some(stored) if stored == &self.log => Ok(true),
            Some(stored) if stored.payload.as_bytes() != self.base => {
                Err(LezAccountRegError::Conflict)
            }
            _ => Ok(false),
        }
    }
}

// Trait implementations for integrating with Logos-Accounts
impl AccountProvider for Registry {
    type Error = LezAccountRegError;

    fn fetch(&self, addr: &AccountAddr) -> Result<Option<SignedAccountLog>, Self::Error> {
        Registry::fetch(self, addr)
    }
}

impl AccountPublisher for Registry {
    type Error = LezAccountRegError;

    fn publish(&mut self, addr: &AccountAddr, log: &SignedAccountLog) -> Result<(), Self::Error> {
        Registry::publish(self, addr, log)
    }
}

/// Signs `log` with the account key, producing what [`Registry::publish`] takes.
pub fn sign(
    key: &Ed25519SigningKey,
    log: &AccountLog,
) -> Result<SignedAccountLog, LezAccountRegError> {
    let payload = log.encode()?;
    let signature = key.sign(payload.as_bytes());
    Ok(SignedAccountLog { payload, signature })
}

/// The LEE public account `key` signs for.
#[must_use]
pub fn signer_id(key: &PrivateKey) -> AccountId {
    AccountId::from(&PublicKey::new_from_private_key(key))
}

/// Decodes the data of `addr`'s log account and checks that `addr` signed it. `None` if nothing
/// has been published.
fn read(addr: &AccountAddr, data: &[u8]) -> Result<Option<SignedAccountLog>, LezAccountRegError> {
    if data.is_empty() {
        return Ok(None);
    }
    let stored = SignedAccountLog::from_bytes(data).map_err(LezAccountRegError::Unverified)?;
    stored
        .verify(addr)
        .map_err(LezAccountRegError::Unverified)?;
    Ok(Some(stored))
}

/// The write that takes `addr`'s stored log, whose payload is `base`, to `log`.
///
/// Refuses everything the program would refuse, since a refused transaction still pays.
fn append_instruction(
    addr: &AccountAddr,
    base: &[u8],
    log: &SignedAccountLog,
) -> Result<LogUpdate, LezAccountRegError> {
    log.verify(addr)?;
    if log.payload.as_bytes().len() > MAX_LOG_PAYLOAD_BYTES {
        return Err(LezAccountRegError::TooLarge(MAX_LOG_PAYLOAD_BYTES));
    }
    let entries = log
        .payload
        .as_bytes()
        .strip_prefix(base)
        .filter(|entries| !entries.is_empty())
        .ok_or(LezAccountRegError::NotAnExtension)?;

    Ok(LogUpdate {
        addr: addr_bytes(addr),
        new_signature: log.signature.to_bytes(),
        entries: entries.to_vec(),
    })
}

fn addr_bytes(addr: &AccountAddr) -> [u8; 32] {
    addr.to_bytes().try_into().expect("an address is 32 bytes")
}

/// Polls `done` until it returns true, at least once, or gives up after `timeout` with
/// [`LezAccountRegError::Timeout`].
fn poll_for(
    timeout: Duration,
    mut done: impl FnMut() -> Result<bool, LezAccountRegError>,
) -> Result<(), LezAccountRegError> {
    let start = Instant::now();
    loop {
        if done()? {
            return Ok(());
        }
        let left = timeout.saturating_sub(start.elapsed());
        if left.is_zero() {
            return Err(LezAccountRegError::Timeout);
        }
        thread::sleep(POLL_INTERVAL.min(left));
    }
}

#[cfg(test)]
mod tests {
    //! A write as the program applies it, and the read that finds it from the address alone. The RPC
    //! in between only moves bytes, so these cover everything but the transport.

    use account_log::{AccountLogDraft, Context, EntryData};

    use super::*;

    const PROGRAM: AccountId = AccountId::new([7; 32]);

    fn one_key_log() -> AccountLog {
        let device = Ed25519SigningKey::generate().verifying_key();
        let mut draft = AccountLogDraft::new();
        let data = EntryData::Ed25519Key(device.as_ref().try_into().unwrap());
        draft.add(Context::literal("chat.signer"), data).unwrap();
        draft.log().clone()
    }

    fn registry() -> Registry {
        Registry::connect("http://localhost:3040", PROGRAM).unwrap()
    }

    /// Alice publishes; Bob, given only her address, finds the log and verifies it.
    #[test]
    fn a_log_is_found_and_verified_from_the_address_alone() {
        let key = Ed25519SigningKey::generate();
        let addr = AccountAddr::from(key.verifying_key());
        let log = one_key_log();

        let append =
            append_instruction(&addr, ACCOUNT_LOG_DOMAIN, &sign(&key, &log).unwrap()).unwrap();
        let data = account_registry_program::apply(append, &[]).unwrap();

        let stored = read(&addr, &data)
            .unwrap()
            .expect("the log Alice published");
        assert_eq!(stored.verify(&addr).unwrap(), log);
    }

    /// The log verifies only for the address it was published under.
    #[test]
    fn a_log_does_not_verify_for_another_address() {
        let key = Ed25519SigningKey::generate();
        let addr = AccountAddr::from(key.verifying_key());
        let signed = sign(&key, &one_key_log()).unwrap();
        let data = signed.to_bytes();

        let other = AccountAddr::from(Ed25519SigningKey::generate().verifying_key());
        assert!(read(&addr, &data).unwrap().is_some());
        assert!(matches!(
            read(&other, &data),
            Err(LezAccountRegError::Unverified(_))
        ));
    }

    /// A log the address did not sign is refused before anything is sent.
    #[test]
    fn a_log_signed_by_another_key_is_refused() {
        let addr = AccountAddr::from(Ed25519SigningKey::generate().verifying_key());
        let forged = sign(&Ed25519SigningKey::generate(), &one_key_log()).unwrap();

        let refused = append_instruction(&addr, ACCOUNT_LOG_DOMAIN, &forged);
        assert!(
            matches!(refused, Err(LezAccountRegError::Log(_))),
            "{refused:?}"
        );
    }

    /// A log over the registry's limit is refused before anything is sent.
    #[test]
    fn a_log_over_the_size_limit_is_refused() {
        let key = Ed25519SigningKey::generate();
        let addr = AccountAddr::from(key.verifying_key());
        let mut draft = AccountLogDraft::new();
        let text = "x".repeat(250);
        while draft.log().encode().unwrap().as_bytes().len() <= MAX_LOG_PAYLOAD_BYTES {
            let data = EntryData::Text(text.clone());
            draft.add(Context::literal("test.text"), data).unwrap();
        }
        let signed = sign(&key, draft.log()).unwrap();

        let refused = append_instruction(&addr, ACCOUNT_LOG_DOMAIN, &signed);
        assert!(
            matches!(refused, Err(LezAccountRegError::TooLarge(_))),
            "{refused:?}"
        );
    }

    /// Reading needs no payer, writing does.
    #[test]
    fn a_write_without_a_payer_is_refused() {
        let refused = registry().send(PROGRAM, vec![], &[], (), 0);
        assert!(
            matches!(refused, Err(LezAccountRegError::NoPayer)),
            "{refused:?}"
        );
    }

    /// What a wallet is handed is the same write `publish` sends: only the new entries, under the
    /// signature of the whole log, addressed to the log's account in the registry's shard.
    #[test]
    fn a_prepared_append_is_the_write_the_program_applies() {
        let key = Ed25519SigningKey::generate();
        let addr = AccountAddr::from(key.verifying_key());
        let v1 = one_key_log();
        let stored = sign(&key, &v1).unwrap();
        let mut v2 = AccountLogDraft::from_log(&v1).unwrap();
        v2.revoke(0).unwrap();
        let log = sign(&key, v2.log()).unwrap();

        let prepared = PreparedAppend::new(PROGRAM, &addr, Some(&stored), &log).unwrap();

        assert_eq!(prepared.program, PROGRAM);
        assert_eq!(prepared.account, registry().account_id(&addr));
        assert_eq!(
            prepared.gas_limit,
            append_gas_limit(log.payload.as_bytes().len())
        );
        let Instruction::Append(update) = borsh::from_slice(&prepared.instruction_data()).unwrap();
        assert_eq!(
            update.entries,
            log.payload.as_bytes()[stored.payload.as_bytes().len()..]
        );
        let written = account_registry_program::apply(update, &stored.to_bytes()).unwrap();
        assert_eq!(written, log.to_bytes());

        let fee = FeeDeclaration::new(PROGRAM, prepared.gas_limit, 0, 1);
        let message = Message::try_new_with_fees(
            prepared.program,
            vec![prepared.selector()],
            vec![],
            &prepared.instruction,
            fee,
        )
        .unwrap();
        assert_eq!(message.instruction_data, prepared.instruction_data());
    }

    /// Waiting ends when the prepared log is on chain, goes on while the old one is, and reports
    /// a conflict for anything else.
    #[test]
    fn a_prepared_append_lands_waits_or_conflicts() {
        let key = Ed25519SigningKey::generate();
        let addr = AccountAddr::from(key.verifying_key());
        let v1 = one_key_log();
        let stored = sign(&key, &v1).unwrap();
        let mut v2 = AccountLogDraft::from_log(&v1).unwrap();
        v2.revoke(0).unwrap();
        let log = sign(&key, v2.log()).unwrap();
        let other = sign(&key, &one_key_log()).unwrap();

        let first = PreparedAppend::new(PROGRAM, &addr, None, &stored).unwrap();
        assert!(!first.landed(None).unwrap());
        assert!(first.landed(Some(&stored)).unwrap());

        let second = PreparedAppend::new(PROGRAM, &addr, Some(&stored), &log).unwrap();
        assert!(!second.landed(Some(&stored)).unwrap());
        assert!(second.landed(Some(&log)).unwrap());
        assert!(matches!(
            second.landed(Some(&other)),
            Err(LezAccountRegError::Conflict)
        ));
    }

    /// The wait checks at least once, and gives up when the caller's time is over.
    #[test]
    fn waiting_stops_at_the_callers_timeout() {
        let mut checks = 0;
        let waited = poll_for(Duration::ZERO, || {
            checks += 1;
            Ok(false)
        });
        assert!(matches!(waited, Err(LezAccountRegError::Timeout)));
        assert_eq!(checks, 1);
    }

    /// `rpc::LeeTransaction` must put exactly the bytes on the wire that LEZ's own type does.
    #[test]
    fn transactions_encode_like_lezs_own() {
        use lez_common::transaction::LeeTransaction as Lez;

        let addr = AccountAddr::from(Ed25519SigningKey::generate().verifying_key());
        let log = sign(&Ed25519SigningKey::generate(), &one_key_log()).unwrap();
        let update = LogUpdate {
            addr: addr_bytes(&addr),
            new_signature: log.signature.to_bytes(),
            entries: log.payload.as_bytes()[ACCOUNT_LOG_DOMAIN.len()..].to_vec(),
        };
        let payer = PrivateKey::try_new([3; 32]).unwrap();
        let registry = registry().with_payer(payer.clone());
        let message = Message::try_new_with_fees(
            PROGRAM,
            vec![ProgramShardSelector::new(
                registry.account_id(&addr),
                PROGRAM,
            )],
            vec![0_u128.into()],
            Instruction::Append(update),
            FeeDeclaration::new(
                signer_id(&payer),
                append_gas_limit(log.payload.as_bytes().len()),
                0,
                1,
            ),
        )
        .unwrap();
        let public = PublicTransaction::new(
            message.clone(),
            WitnessSet::for_message(&message, &[&payer]),
        );

        assert_eq!(
            serde_json::to_value(Lez::Public(public.clone())).unwrap(),
            LeeTransaction::Public(public).to_base64()
        );
    }
}
