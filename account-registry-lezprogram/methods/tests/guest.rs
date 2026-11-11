//! Runs the compiled guest through LEE's state machine, as a sequencer does, so a transaction
//! here plans and applies exactly as it would on chain. The transition rules themselves are
//! tested in the program crate.

use std::borrow::Cow;

use account_log::{ACCOUNT_LOG_DOMAIN, AccountLogDraft, Context, Ed25519SigningKey, EntryData};
use account_registry_core::{
    Instruction, LogUpdate, MAX_GAS_EXEC, MAX_LOG_PAYLOAD_BYTES, SIGNATURE_LEN, append_gas_limit,
    derive_lee_account_id,
};
use account_registry_methods::{ACCOUNT_REGISTRY_ELF, ACCOUNT_REGISTRY_ID};
use lee::{
    AccountId, ProgramShardSelector, PublicTransaction, V03State, ValidatedStateDiff,
    program::Program,
    public_transaction::{Message, WitnessSet},
};

/// Where the tests deploy the program, as a deployer's `CreateHeader` would.
const PROGRAM: AccountId = AccountId::new([0xA1; 32]);

fn program() -> Program {
    Program::new(Cow::Borrowed(ACCOUNT_REGISTRY_ELF)).unwrap()
}

fn state() -> V03State {
    V03State::new().with_named_programs([(PROGRAM, program())])
}

struct Owner(Ed25519SigningKey);

impl Owner {
    fn new() -> Self {
        Self(Ed25519SigningKey::generate())
    }

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

    fn stored(&self, state: &V03State) -> Vec<u8> {
        state
            .get_account_by_id(derive_lee_account_id(&PROGRAM, &self.addr()))
            .data
            .shard(PROGRAM)
            .as_ref()
            .to_vec()
    }
}

/// An unsigned, fee-exempt transaction: the state machine checks neither, the sequencer does.
fn append_tx(update: LogUpdate) -> PublicTransaction {
    let account = derive_lee_account_id(&PROGRAM, &update.addr);
    let selector = ProgramShardSelector::new(account, PROGRAM);
    let message =
        Message::try_new(PROGRAM, vec![selector], vec![], Instruction::Append(update)).unwrap();
    let witnesses = WitnessSet::for_message(&message, &[]);
    PublicTransaction::new(message, witnesses)
}

/// Applies `update` under the gas limit a client reserves for it, and returns the execution
/// cycles it cost.
fn apply(state: &mut V03State, update: LogUpdate) -> u64 {
    let stored = state
        .get_account_by_id(derive_lee_account_id(&PROGRAM, &update.addr))
        .data
        .shard(PROGRAM)
        .as_ref()
        .len();
    let base = if stored == 0 {
        ACCOUNT_LOG_DOMAIN.len()
    } else {
        stored - SIGNATURE_LEN
    };
    let gas_limit = append_gas_limit(base + update.entries.len());
    let tx = append_tx(update);
    let (_, charge) =
        ValidatedStateDiff::from_public_transaction_with_cycle_budget(&tx, state, 1, 0, gas_limit)
            .expect("the append fits the gas a client reserves for it");
    state
        .transition_from_public_transaction(&tx, 1, 0)
        .expect("LEE accepts the append");
    charge.cycles
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

fn entry_len() -> usize {
    keys_log(1).len() - ACCOUNT_LOG_DOMAIN.len()
}

#[test]
fn the_embedded_image_id_is_the_program_id() {
    assert_eq!(program().id(), ACCOUNT_REGISTRY_ID);
}

#[test]
fn creates_and_extends_on_lee() {
    let mut state = state();
    let owner = Owner::new();
    let (v1, v2) = (keys_log(1), keys_log(2));
    let v2 = [&v1[..], &v2[v1.len()..]].concat();

    apply(&mut state, owner.append(ACCOUNT_LOG_DOMAIN, &v1));
    apply(&mut state, owner.append(&v1, &v2));
    assert_eq!(&owner.stored(&state)[64..], &v2[..]);
}

#[test]
fn rejects_a_forged_signature_on_lee() {
    let mut state = state();
    let (owner, forger) = (Owner::new(), Owner::new());
    let mut append = forger.append(ACCOUNT_LOG_DOMAIN, &keys_log(1));
    append.addr = owner.addr();

    let refused = state.transition_from_public_transaction(&append_tx(append), 1, 0);
    assert!(refused.is_err(), "{refused:?}");
    assert!(owner.stored(&state).is_empty());
}

/// A write's cost grows with the stored log, which the signature covers. A log at the size limit
/// must stay writable under LEE's gas cap, or the account could never be written again.
#[test]
fn a_full_log_stays_writable() {
    let full = (MAX_LOG_PAYLOAD_BYTES - ACCOUNT_LOG_DOMAIN.len()) / entry_len();
    let target = keys_log(full);
    let stored = &target[..target.len() - entry_len()];

    let mut state = state();
    let owner = Owner::new();
    apply(&mut state, owner.append(ACCOUNT_LOG_DOMAIN, stored));
    let cycles = apply(&mut state, owner.append(stored, &target));
    println!(
        "append to a full log ({} keys, {} bytes): {cycles} cycles of {MAX_GAS_EXEC}",
        full - 1,
        stored.len()
    );
}

/// What one more key costs as the log grows, so the gas limit and the size cap can be set from
/// measurements. Run with `--nocapture` to see the table.
#[test]
fn append_cost_by_log_size() {
    let mut state = state();
    let owner = Owner::new();
    let full = (MAX_LOG_PAYLOAD_BYTES - ACCOUNT_LOG_DOMAIN.len()) / entry_len();
    let log = keys_log(full);
    let mut stored = ACCOUNT_LOG_DOMAIN.len();
    for keys in [1, 2, full / 8, full / 4, full / 2, full] {
        let next = ACCOUNT_LOG_DOMAIN.len() + keys * entry_len();
        if next <= stored {
            continue;
        }
        let cycles = apply(&mut state, owner.append(&log[..stored], &log[..next]));
        println!("log of {next:>6} bytes ({keys:>4} keys): {cycles:>9} cycles");
        stored = next;
    }
}
