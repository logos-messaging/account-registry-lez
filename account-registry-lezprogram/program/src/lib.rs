//! The registry's one state transition: append to an account's log.
//!
//! The log of the account with Ed25519 address `addr` lives in this program's shard of a PDA
//! seeded by `addr`, so anyone holding the address can find it. The shard's data is exactly the
//! bytes libchat transmits, `SignedAccountLog::to_bytes()` (`signature ‖ payload`), so a reader
//! verifies it with libchat's own `SignedAccountLog::verify` and trusts no one in between.
//!
//! Writes are authorized by that signature, not by a LEE signer: the account needs no key on
//! LEE, and anyone with a funded fee payer may relay an account's signed log. LEE runs a program
//! in two steps. [`plan`] sees only the instruction and the accounts it names, and accepts a
//! write only if the target is `addr`'s PDA and there is something to append. [`apply`] sees
//! the stored log and accepts the result only if it
//!
//! - is the stored payload plus new entries (append-only),
//! - stays within [`MAX_LOG_PAYLOAD_BYTES`](core::MAX_LOG_PAYLOAD_BYTES), and
//! - is signed by `addr`.
//!
//! It does not decode the entries. Readers must validate them anyway, and validating a log costs
//! about 240k cycles per stored key: re-validating on every write would exceed LEE's 10M-gas
//! transaction cap after a few dozen keys and leave the account unwritable for good.

pub use account_registry_core as core;

use account_log::{ACCOUNT_LOG_DOMAIN, Ed25519VerifyingKey, SignedAccountLog};
use account_registry_core::{
    ADDR_LEN, Instruction, LogUpdate, MAX_LOG_PAYLOAD_BYTES, SIGNATURE_LEN, derive_lee_account_id,
};
use lee_core::program::{Plan, PlanInput};

mod tests;

/// Plans `instruction` against the one account it targets.
///
/// # Panics
///
/// On every rejected instruction — a panic is how a LEE program refuses a transaction.
#[must_use]
pub fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    let [account] = input.accounts.as_slice() else {
        panic!(
            "account registry: every instruction takes exactly one account, got {}",
            input.accounts.len()
        )
    };

    let mut plan = Plan::new(input);
    match instruction {
        Instruction::Append(update) => {
            assert!(
                account.account_id == derive_lee_account_id(&input.self_account_id, &update.addr),
                "the account is not the log account of addr"
            );
            assert!(!update.entries.is_empty(), "nothing to append");
            plan.effect(account, &update);
        }
    }
    plan
}

/// Appends `update.entries` to the log stored in `stored`, and returns the new shard data.
///
/// # Panics
///
/// If `addr` is not an Ed25519 key, the result exceeds the log size limit, or `addr` did not
/// sign the result.
#[must_use]
pub fn apply(update: LogUpdate, stored: &[u8]) -> Option<Vec<u8>> {
    let encoded_log = get_encoded_log(stored);
    let signed_log_bytes = [&update.new_signature[..], encoded_log, &update.entries].concat();
    verify_log_bytes(&signed_log_bytes, &update.addr);
    Some(signed_log_bytes)
}

fn get_encoded_log(stored_data: &[u8]) -> &[u8] {
    if stored_data.is_empty() {
        return ACCOUNT_LOG_DOMAIN; // default to empty AccountLog
    }

    // remove signature prefix
    &stored_data[SIGNATURE_LEN..]
}

/// Checks the result is within the size limit and signed by `addr`. Does not decode the
/// entries: see the module doc.
fn verify_log_bytes(bytes: &[u8], addr: &[u8; ADDR_LEN]) {
    assert!(
        bytes.len() - SIGNATURE_LEN <= MAX_LOG_PAYLOAD_BYTES,
        "the log exceeds the size limit"
    );
    let key = Ed25519VerifyingKey::from_canonical_bytes(addr).expect("addr is not an Ed25519 key");
    let log = SignedAccountLog::from_bytes(bytes).expect("not a signed log");
    key.verify(log.payload.as_bytes(), &log.signature)
        .expect("not signed by addr");
}
