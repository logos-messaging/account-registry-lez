//! Runs the compiled guest in the zkVM, as a node does for a public account, and checks that LEE
//! accepts what it proposes. The transition rules themselves are tested in the program crate.

use std::borrow::Cow;

use account_log::{
    ACCOUNT_LOG_DOMAIN, AccountLogDraft, Context, Ed25519SigningKey, EntryData, MAX_PAYLOAD_BYTES,
};
use account_registry_core::{Instruction, LogUpdate, derive_lee_account_id};
use account_registry_methods::{ACCOUNT_REGISTRY_ELF, ACCOUNT_REGISTRY_ID};
use lee::program::Program;
use lee_core::{
    account::{Account, AccountId, AccountWithMetadata},
    program::{AccountPostState, ProgramOutput, validate_execution},
};
use risc0_zkvm::{ExecutorEnv, default_executor};

/// LEE's cap on one public execution (`MAX_NUM_CYCLES_PUBLIC_EXECUTION`, not exported).
const LEE_CYCLE_LIMIT: u64 = 32 * 1024 * 1024;

fn program() -> Program {
    Program::new(Cow::Borrowed(ACCOUNT_REGISTRY_ELF)).unwrap()
}

/// Executes the guest under LEE's cycle limit; returns its output and cycle count, or the error.
fn run(pre: &AccountWithMetadata, append: LogUpdate) -> Result<(ProgramOutput, u64), String> {
    let program = program();
    let instruction_data = Program::serialize_instruction(Instruction::Append(append)).unwrap();
    let mut env = ExecutorEnv::builder();
    env.session_limit(Some(LEE_CYCLE_LIMIT));
    program
        .write_inputs(None, std::slice::from_ref(pre), &instruction_data, &mut env)
        .unwrap();
    let session = default_executor()
        .execute(env.build().unwrap(), program.elf())
        .map_err(|error| error.to_string())?;

    let output = borsh::from_slice(lee_core::from_frame(&session.journal.bytes).unwrap()).unwrap();
    Ok((output, session.cycles()))
}

/// Runs the guest, requires LEE to accept the result, and applies it as LEE would.
fn apply(pre: AccountWithMetadata, append: LogUpdate) -> (AccountWithMetadata, u64) {
    let (output, cycles) = run(&pre, append).expect("the guest should accept this");
    validate_execution(&output.pre_states, &output.post_states, ACCOUNT_REGISTRY_ID)
        .expect("LEE should accept the transition");

    let post: &AccountPostState = &output.post_states[0];
    let mut account = post.account().clone();
    if post.required_claim().is_some() {
        account.program_owner = AccountId::from(ACCOUNT_REGISTRY_ID);
    }
    (AccountWithMetadata { account, ..pre }, cycles)
}

struct Owner(Ed25519SigningKey);

impl Owner {
    fn addr(&self) -> [u8; 32] {
        self.0.verifying_key().as_ref().try_into().unwrap()
    }

    fn append(&self, from: &[u8], to: &[u8]) -> LogUpdate {
        LogUpdate {
            addr: self.addr(),
            new_signature: self.0.sign(to).as_ref().try_into().unwrap(),
            entries: to[from.len()..].to_vec(),
        }
    }

    fn empty_account(&self) -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account::default(),
            is_authorized: false,
            account_id: derive_lee_account_id(&ACCOUNT_REGISTRY_ID, &self.addr()),
        }
    }
}

/// The payload of a log of `n` endorsed Ed25519 keys.
fn keys_log(n: usize) -> Vec<u8> {
    let mut draft = AccountLogDraft::new();
    for _ in 0..n {
        let key = Ed25519SigningKey::generate().verifying_key();
        let data = EntryData::Ed25519Key(key.as_ref().try_into().unwrap());
        draft.add(Context::literal("chat.signer"), data).unwrap();
    }
    draft.log().encode().unwrap().as_bytes().to_vec()
}

#[test]
fn the_embedded_image_id_is_the_program_id() {
    assert_eq!(program().id(), ACCOUNT_REGISTRY_ID);
}

#[test]
fn creates_and_extends_in_the_zkvm() {
    let owner = Owner(Ed25519SigningKey::generate());
    let (v1, v2) = (keys_log(1), keys_log(2));
    let v2 = [&v1[..], &v2[v1.len()..]].concat();

    let (created, _) = apply(owner.empty_account(), owner.append(ACCOUNT_LOG_DOMAIN, &v1));
    assert_eq!(
        created.account.program_owner,
        AccountId::from(ACCOUNT_REGISTRY_ID)
    );

    let (extended, _) = apply(created, owner.append(&v1, &v2));
    let stored: &[u8] = extended.account.data.as_ref();
    assert_eq!(&stored[64..], &v2[..]);
}

#[test]
fn rejects_a_forged_signature_in_the_zkvm() {
    let (owner, forger) = (
        Owner(Ed25519SigningKey::generate()),
        Owner(Ed25519SigningKey::generate()),
    );
    let mut append = forger.append(ACCOUNT_LOG_DOMAIN, &keys_log(1));
    append.addr = owner.addr();

    let error = run(&owner.empty_account(), append).unwrap_err();
    assert!(error.contains("not signed by addr"), "{error}");
}

/// A write's cost grows with the stored log, which the signature covers. A full log must stay
/// writable under LEE's limit — validating every stored key on each write would not.
#[test]
fn a_full_log_stays_writable() {
    let entry_len = keys_log(1).len() - ACCOUNT_LOG_DOMAIN.len();
    let full = (MAX_PAYLOAD_BYTES - ACCOUNT_LOG_DOMAIN.len()) / entry_len;

    let owner = Owner(Ed25519SigningKey::generate());
    let target = keys_log(full);
    let stored = &target[..target.len() - entry_len];

    let (pre, _) = apply(
        owner.empty_account(),
        owner.append(ACCOUNT_LOG_DOMAIN, stored),
    );
    let (_, cycles) = apply(pre, owner.append(stored, &target));
    println!(
        "append to a full log ({} keys, {} bytes): {cycles} cycles",
        full - 1,
        stored.len()
    );
}
