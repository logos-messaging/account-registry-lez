//! Read and write account logs held by the registry program. Every call blocks; there is no
//! async runtime.
//!
//! [`Registry::fetch`] verifies what the RPC returns against the address asked about, so an RPC
//! can withhold a log or serve an older one, but cannot forge one. No wallet is involved anywhere:
//! a write is authorized by the log's own signature, and deployment is unsigned.
//!
//! [`Registry`] implements libchat's [`AccountProvider`] and [`AccountPublisher`], so it can back
//! an [`Account`](logos_account::Account) or an
//! [`AccountResolver`](logos_account::AccountResolver) directly. [`Registry::deploy`] must have
//! run first; neither of those knows about it.

use std::{thread, time::Duration};

use account_log::{
    ACCOUNT_LOG_DOMAIN, AccountAddr, AccountLog, Ed25519SigningKey, SignedAccountLog,
};
use account_registry_core::{Instruction, LogUpdate};
use account_registry_methods::{ACCOUNT_REGISTRY_ELF, ACCOUNT_REGISTRY_ID as PROGRAM_ID};
use lee::{
    AccountId, ProgramDeploymentTransaction, PublicTransaction, program_deployment_transaction,
    public_transaction::{Message, WitnessSet},
};
use logos_account::{AccountProvider, AccountPublisher};

use rpc::{LeeTransaction, Sequencer};

pub use error::LezAccountRegError;

mod error;
mod rpc;

/// How often, and how many times, to look for a submitted transaction's effect.
const POLL_INTERVAL: Duration = Duration::from_secs(1);
const POLL_ATTEMPTS: u32 = 60;

/// A connection to one sequencer.
#[derive(Clone)]
pub struct Registry {
    rpc: Sequencer,
}

impl Registry {
    /// Connects to a sequencer, e.g. `http://localhost:3040`. Does no I/O.
    pub fn connect(sequencer: &str) -> Result<Self, LezAccountRegError> {
        let url = url::Url::parse(sequencer)?;
        Ok(Self {
            rpc: Sequencer::new(url.into()),
        })
    }

    /// The account holding `addr`'s log.
    #[must_use]
    pub fn account_id(addr: &AccountAddr) -> AccountId {
        account_registry_core::derive_lee_account_id(&PROGRAM_ID, &addr_bytes(addr))
    }

    /// Deploys the program, unless the zone already has it.
    pub fn deploy(&self) -> Result<(), LezAccountRegError> {
        if self.is_deployed()? {
            return Ok(());
        }
        let message = program_deployment_transaction::Message::new(ACCOUNT_REGISTRY_ELF.to_vec());
        let tx = ProgramDeploymentTransaction::new(message);
        self.rpc
            .send_transaction(&LeeTransaction::ProgramDeployment(tx))?;
        poll(|| self.is_deployed())
    }

    /// Fetches `addr`'s log, as libchat transmits it, after checking that `addr` signed it. `None`
    /// if nothing has been published for it.
    pub fn fetch(
        &self,
        addr: &AccountAddr,
    ) -> Result<Option<SignedAccountLog>, LezAccountRegError> {
        let account = self.rpc.get_account(Self::account_id(addr))?;
        read(addr, account.data.as_ref())
    }

    /// Publishes `log`, which must extend the log on chain, and waits until it is there.
    ///
    /// Only the new entries are part of the transaction; the signature covers the whole log. If another write lands
    /// first this fails with [`LezAccountRegError::Conflict`]: fetch, rebuild on top, and sign again.
    pub fn publish(
        &self,
        addr: &AccountAddr,
        log: &SignedAccountLog,
    ) -> Result<(), LezAccountRegError> {
        let current = self.fetch(addr)?;
        let base = current
            .as_ref()
            .map_or(ACCOUNT_LOG_DOMAIN, |stored| stored.payload.as_bytes());
        let append = append_instruction(addr, base, log)?;

        // No signers: the program checks the log's signature itself.
        let instruction = Instruction::Append(append);
        let message = Message::try_new(
            PROGRAM_ID,
            vec![Self::account_id(addr)],
            vec![],
            instruction,
        )?;
        let witnesses = WitnessSet::for_message(&message, &[]);
        let tx = PublicTransaction::new(message, witnesses);
        self.rpc.send_transaction(&LeeTransaction::Public(tx))?;

        poll(|| match self.fetch(addr)? {
            Some(stored) if &stored == log => Ok(true),
            Some(stored) if stored.payload.as_bytes() != base => Err(LezAccountRegError::Conflict),
            _ => Ok(false),
        })
    }

    fn is_deployed(&self) -> Result<bool, LezAccountRegError> {
        let program = self.rpc.get_account(AccountId::from(PROGRAM_ID))?;
        Ok(!program.data.as_ref().is_empty())
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
fn append_instruction(
    addr: &AccountAddr,
    base: &[u8],
    log: &SignedAccountLog,
) -> Result<LogUpdate, LezAccountRegError> {
    log.verify(addr)?;
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
    use lee_core::account::{Account, AccountWithMetadata};

    use super::*;

    fn one_key_log() -> AccountLog {
        let device = Ed25519SigningKey::generate().verifying_key();
        let mut draft = AccountLogDraft::new();
        let data = EntryData::Ed25519Key(device.as_ref().try_into().unwrap());
        draft.add(Context::literal("chat.signer"), data).unwrap();
        draft.log().clone()
    }

    /// Alice publishes; Bob, given only her address, finds the log and verifies it.
    #[test]
    fn a_log_is_found_and_verified_from_the_address_alone() {
        let key = Ed25519SigningKey::generate();
        let addr = AccountAddr::from(key.verifying_key());
        let log = one_key_log();

        let append =
            append_instruction(&addr, ACCOUNT_LOG_DOMAIN, &sign(&key, &log).unwrap()).unwrap();
        let account = AccountWithMetadata {
            account: Account::default(),
            is_authorized: false,
            account_id: Registry::account_id(&addr),
        };
        let post = account_registry_program::append(account, PROGRAM_ID, append);
        let data: &[u8] = post.account().data.as_ref();

        let stored = read(&addr, data).unwrap().expect("the log Alice published");
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
        let message = Message::try_new(
            PROGRAM_ID,
            vec![Registry::account_id(&addr)],
            vec![],
            Instruction::Append(update),
        )
        .unwrap();
        let public =
            PublicTransaction::new(message.clone(), WitnessSet::for_message(&message, &[]));
        let deployment = ProgramDeploymentTransaction::new(
            program_deployment_transaction::Message::new(ACCOUNT_REGISTRY_ELF[..64].to_vec()),
        );

        for (ours, theirs) in [
            (LeeTransaction::Public(public.clone()), Lez::Public(public)),
            (
                LeeTransaction::ProgramDeployment(deployment.clone()),
                Lez::ProgramDeployment(deployment),
            ),
        ] {
            assert_eq!(serde_json::to_value(theirs).unwrap(), ours.to_base64());
        }
    }

    /// The round trip against a real sequencer, which also checks that `rpc` still speaks its wire
    /// format. Set `SEQUENCER_URL` to use one other than `./run-local-sequencer`'s.
    #[test]
    #[ignore = "needs a running sequencer: ./run-local-sequencer"]
    fn against_a_sequencer() {
        let url = std::env::var("SEQUENCER_URL").unwrap_or("http://localhost:3040".into());
        let registry = Registry::connect(&url).unwrap();
        registry.deploy().unwrap();

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
}
