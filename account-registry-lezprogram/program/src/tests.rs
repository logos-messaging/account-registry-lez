#![cfg(test)]

use account_log::{
    ACCOUNT_LOG_DOMAIN, AccountAddr, AccountLogDraft, AccountRecord, Context, Ed25519SigningKey,
    EntryData, SignedAccountLog,
};
use account_registry_core::{Instruction, LogUpdate, MAX_LOG_PAYLOAD_BYTES, derive_lee_account_id};
use lee_core::{
    account::{AccountId, Actor},
    program::ReceiveInput,
};

use crate::handle;

const PROGRAM: AccountId = AccountId::new([7; 32]);

/// The canonical payload of a log holding `texts`, in order.
fn log(texts: &[&str]) -> Vec<u8> {
    let mut draft = AccountLogDraft::new();
    for text in texts {
        let context = Context::literal("test.text");
        draft.add(context, EntryData::Text((*text).into())).unwrap();
    }
    draft.log().encode().unwrap().as_bytes().to_vec()
}

struct Owner(Ed25519SigningKey);

impl Owner {
    fn new() -> Self {
        Self(Ed25519SigningKey::generate())
    }

    fn addr(&self) -> [u8; 32] {
        self.0.verifying_key().as_ref().try_into().unwrap()
    }

    /// The write moving `from` to `to`, signed by this owner.
    fn append(&self, from: &[u8], to: &[u8]) -> LogUpdate {
        LogUpdate {
            addr: self.addr(),
            new_signature: self.0.sign(to).as_ref().try_into().unwrap(),
            entries: to[from.len()..].to_vec(),
        }
    }

    fn account(&self) -> AccountId {
        derive_lee_account_id(&PROGRAM, &self.addr())
    }
}

/// Sends `update` to `account`, whose stored log is `stored`, as LEE would, and returns the
/// state the program leaves there.
fn run(account: AccountId, stored: &[u8], update: LogUpdate) -> Vec<u8> {
    let instruction = Instruction::Append(update);
    let input = ReceiveInput {
        receiver: Actor::new(account, PROGRAM),
        from: None,
        is_authorized: false,
        pre_state: stored.to_vec().into(),
        message: borsh::to_vec(&instruction).unwrap(),
    };
    let response = handle(&input, instruction);
    assert!(response.sync_messages.is_empty() && response.async_messages.is_empty());
    response
        .post_state
        .expect("an append always writes")
        .into_inner()
}

#[test]
fn creates_then_extends_a_log_readers_accept() {
    let owner = Owner::new();
    let (v1, v2) = (log(&["one"]), log(&["one", "two"]));

    let created = run(owner.account(), &[], owner.append(ACCOUNT_LOG_DOMAIN, &v1));
    let extended = run(owner.account(), &created, owner.append(&v1, &v2));

    let stored = SignedAccountLog::from_bytes(&extended).unwrap();
    let addr = AccountAddr::try_from(&owner.addr()[..]).unwrap();
    let record = AccountRecord::new(addr, stored).unwrap();
    assert_eq!(record.signed_log().payload.as_bytes(), v2);
}

#[test]
#[should_panic(expected = "not the log account of addr")]
fn rejects_another_addresss_account() {
    let (owner, victim) = (Owner::new(), Owner::new());
    let append = owner.append(ACCOUNT_LOG_DOMAIN, &log(&["one"]));
    run(victim.account(), &[], append);
}

#[test]
#[should_panic(expected = "not signed by addr")]
fn rejects_a_signature_by_another_key() {
    let (owner, forger) = (Owner::new(), Owner::new());
    let mut append = forger.append(ACCOUNT_LOG_DOMAIN, &log(&["one"]));
    append.addr = owner.addr();
    run(owner.account(), &[], append);
}

#[test]
#[should_panic(expected = "not signed by addr")]
fn rejects_a_write_prepared_against_a_stale_log() {
    let owner = Owner::new();
    let v1 = log(&["one"]);
    let at_v1 = run(owner.account(), &[], owner.append(ACCOUNT_LOG_DOMAIN, &v1));
    let at_v2 = run(
        owner.account(),
        &at_v1,
        owner.append(&v1, &log(&["one", "two"])),
    );

    // Prepared against v1, landing after v2.
    run(
        owner.account(),
        &at_v2,
        owner.append(&v1, &log(&["one", "other"])),
    );
}

#[test]
#[should_panic(expected = "exceeds the size limit")]
fn rejects_a_log_over_the_size_limit() {
    let owner = Owner::new();
    let payload = [ACCOUNT_LOG_DOMAIN, &vec![0; MAX_LOG_PAYLOAD_BYTES]].concat();
    run(
        owner.account(),
        &[],
        owner.append(ACCOUNT_LOG_DOMAIN, &payload),
    );
}

#[test]
fn accepts_a_log_at_the_size_limit() {
    let owner = Owner::new();
    let filler = MAX_LOG_PAYLOAD_BYTES - ACCOUNT_LOG_DOMAIN.len();
    let payload = [ACCOUNT_LOG_DOMAIN, &vec![0; filler]].concat();
    let stored = run(
        owner.account(),
        &[],
        owner.append(ACCOUNT_LOG_DOMAIN, &payload),
    );
    assert_eq!(stored.len(), 64 + MAX_LOG_PAYLOAD_BYTES);
}

/// The identity point is a valid encoding but small-order: anyone can forge a signature under
/// it, so it must not be accepted as an address.
#[test]
#[should_panic(expected = "addr is not an Ed25519 key")]
fn rejects_an_addr_that_is_not_an_ed25519_key() {
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut append = Owner::new().append(ACCOUNT_LOG_DOMAIN, &log(&["one"]));
    append.addr = identity;
    run(derive_lee_account_id(&PROGRAM, &identity), &[], append);
}

#[test]
#[should_panic(expected = "nothing to append")]
fn rejects_an_empty_append() {
    let owner = Owner::new();
    let append = owner.append(ACCOUNT_LOG_DOMAIN, ACCOUNT_LOG_DOMAIN);
    run(owner.account(), &[], append);
}
