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
//! first, at the account the registry was connected to; see [`Registry::deploy`].

use std::{thread, time::Duration};

use account_log::{
    ACCOUNT_LOG_DOMAIN, AccountAddr, AccountLog, Ed25519SigningKey, SignedAccountLog,
};
pub use account_registry_core::{MAX_LOG_PAYLOAD_BYTES, append_gas_limit};
use account_registry_core::{Instruction, LogUpdate};
use borsh::BorshSerialize;
use lee::{
    FeeDeclaration, ProgramShardSelector, PublicKey, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use logos_account::{AccountProvider, AccountPublisher};

use rpc::{LeeTransaction, Sequencer};

#[cfg(feature = "deploy")]
pub use deploy::{LOCAL_PAYER_ID, LOCAL_PAYER_KEY, LOCAL_PROGRAM_KEY};
pub use error::LezAccountRegError;
pub use lee::{AccountId, PrivateKey};

#[cfg(feature = "deploy")]
mod deploy;
mod error;
mod rpc;

/// How often, and how many times, to look for a submitted transaction's effect.
const POLL_INTERVAL: Duration = Duration::from_secs(1);
const POLL_ATTEMPTS: u32 = 60;

/// Execution gas reserved for a program loader transaction, which runs natively and meters none.
#[cfg(feature = "deploy")]
const LOADER_GAS_LIMIT: u64 = 1_000_000;

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
        let selector = ProgramShardSelector::new(prepared.account, self.program);
        let instruction = Instruction::Append(prepared.update.clone());
        self.send(
            self.program,
            vec![selector],
            &[],
            instruction,
            prepared.gas_limit,
        )?;
        self.await_append(addr, log, &prepared)
    }

    /// The write that takes the log on chain to `log`, for a caller that submits it itself, e.g.
    /// through a wallet. Refuses everything the program would refuse, since a refused
    /// transaction still pays.
    pub fn prepare_append(
        &self,
        addr: &AccountAddr,
        log: &SignedAccountLog,
    ) -> Result<PreparedAppend, LezAccountRegError> {
        let base = self.fetch(addr)?.map_or_else(
            || ACCOUNT_LOG_DOMAIN.to_vec(),
            |stored| stored.payload.as_bytes().to_vec(),
        );
        let update = append_instruction(addr, &base, log)?;
        Ok(PreparedAppend {
            account: self.account_id(addr),
            gas_limit: append_gas_limit(log.payload.as_bytes().len()),
            update,
            base,
        })
    }

    /// Waits until the chain holds `log`, after `prepared` was submitted.
    pub fn await_append(
        &self,
        addr: &AccountAddr,
        log: &SignedAccountLog,
        prepared: &PreparedAppend,
    ) -> Result<(), LezAccountRegError> {
        poll(|| match self.fetch(addr)? {
            Some(stored) if &stored == log => Ok(true),
            Some(stored) if stored.payload.as_bytes() != prepared.base => {
                Err(LezAccountRegError::Conflict)
            }
            _ => Ok(false),
        })
    }

    /// Sends a transaction to `program` over `selectors`, signed by `signers` and paid by the
    /// configured payer, each at its current nonce, reserving `gas_limit` execution gas. Returns
    /// once the sequencer accepts it.
    fn send(
        &self,
        program: AccountId,
        selectors: Vec<ProgramShardSelector>,
        signers: &[&PrivateKey],
        instruction: impl BorshSerialize,
        gas_limit: u64,
    ) -> Result<(), LezAccountRegError> {
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

/// An append ready to submit: the one account it writes, not signing, in the registry's shard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedAppend {
    /// The account holding the log.
    pub account: AccountId,
    /// Execution gas to reserve; see [`append_gas_limit`].
    pub gas_limit: u64,
    update: LogUpdate,
    base: Vec<u8>,
}

impl PreparedAppend {
    /// The instruction data: the borsh-encoded `Append`.
    #[must_use]
    pub fn instruction_data(&self) -> Vec<u8> {
        borsh::to_vec(&Instruction::Append(self.update.clone()))
            .expect("borsh encoding into a Vec cannot fail")
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

/// Polls `done` until it returns true, or gives up with [`LezAccountRegError::Timeout`].
fn poll(
    mut done: impl FnMut() -> Result<bool, LezAccountRegError>,
) -> Result<(), LezAccountRegError> {
    for _ in 0..POLL_ATTEMPTS {
        if done()? {
            return Ok(());
        }
        thread::sleep(POLL_INTERVAL);
    }
    Err(LezAccountRegError::Timeout)
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

    /// The round trip against a real sequencer, which also checks that `rpc` still speaks its wire
    /// format. Set `SEQUENCER_URL` to use one other than `./run-local-sequencer`'s, and
    /// `ACCOUNT_REGISTRY_PAYER` to a funded payer key other than the local genesis one.
    #[cfg(feature = "deploy")]
    #[test]
    #[ignore = "needs a running sequencer: ./run-local-sequencer"]
    fn against_a_sequencer() {
        let url = std::env::var("SEQUENCER_URL").unwrap_or("http://localhost:3040".into());
        let payer = std::env::var("ACCOUNT_REGISTRY_PAYER")
            .unwrap_or(LOCAL_PAYER_KEY.into())
            .parse::<PrivateKey>()
            .unwrap();
        let header = PrivateKey::try_new(rand_bytes()).unwrap();
        let registry = Registry::connect(&url, signer_id(&header))
            .unwrap()
            .with_payer(payer);
        registry.deploy(&header).unwrap();

        let key = Ed25519SigningKey::generate();
        let addr = AccountAddr::from(key.verifying_key());
        assert!(registry.fetch(&addr).unwrap().is_none());

        let v1 = one_key_log();
        registry.publish(&addr, &sign(&key, &v1).unwrap()).unwrap();
        let stored = registry.fetch(&addr).unwrap().unwrap();
        assert_eq!(stored.verify(&addr).unwrap(), v1);

        let mut v2 = AccountLogDraft::from_log(&v1).unwrap();
        v2.revoke(0).unwrap();
        let v2 = v2.log().clone();
        registry.publish(&addr, &sign(&key, &v2).unwrap()).unwrap();
        let stored = registry.fetch(&addr).unwrap().unwrap();
        assert_eq!(stored.verify(&addr).unwrap(), v2);
    }

    /// A fresh header key per run, so each run deploys its own copy of the program.
    #[cfg(feature = "deploy")]
    fn rand_bytes() -> [u8; 32] {
        Ed25519SigningKey::generate().verifying_key().to_bytes()
    }
}
