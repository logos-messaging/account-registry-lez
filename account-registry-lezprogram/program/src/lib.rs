//! The registry's one state transition: append to an account's log.
//!
//! The log of the account with Ed25519 address `addr` lives at a PDA of this program seeded by
//! `addr`, so anyone holding the address can find it. The account's data is exactly the bytes
//! libchat transmits, `SignedAccountLog::to_bytes()` (`signature ‖ payload`), so a reader
//! verifies it with libchat's own `SignedAccountLog::verify` and trusts no one in between.
//!
//! Writes are authorized by that signature, not by a LEE signer: a transaction needs no wallet,
//! and anyone may relay an account's signed log. The program accepts a write only if
//!
//! - the target account is `addr`'s PDA,
//! - the result is the stored payload plus new entries (append-only), within the size limit, and
//! - `addr` signed the result.
//!
//! It does not decode the entries. Readers must validate them anyway, and validating a log costs
//! about 240k cycles per stored key: re-validating on every write would exceed LEE's 32M-cycle
//! execution limit at around 120 keys and leave the account unwritable for good. Checking the
//! signature costs one hash of the payload, under 20M cycles even at the size limit.

pub use account_registry_core as core;

use account_log::{ACCOUNT_LOG_DOMAIN, Ed25519VerifyingKey, SignedAccountLog};
use account_registry_core::{
    ADDR_LEN, Instruction, LogUpdate, SIGNATURE_LEN, derive_lee_account_id,
};
use lee_core::{
    account::AccountWithMetadata,
    program::{AccountPostState, Claim, PdaSeed, ProgramId},
};

mod tests;

/// Applies `instruction` to the one account it targets.
///
/// # Panics
///
/// On every rejected instruction — a panic is how a LEE program refuses a transaction.
#[must_use]
pub fn execute(
    program_id: ProgramId,
    pre_states: Vec<AccountWithMetadata>,
    instruction: Instruction,
) -> Vec<AccountPostState> {
    let [account] = <[AccountWithMetadata; 1]>::try_from(pre_states).unwrap_or_else(|got| {
        panic!(
            "account registry: every instruction takes exactly one account, got {}",
            got.len()
        )
    });

    let post_state = match instruction {
        Instruction::Append(update) => append(account, program_id, update),
    };

    vec![post_state]
}

/// Appends `update.entries` to the log held in `lee_account`, claiming it on the first write.
///
/// # Panics
///
/// If `account` is not the log account of `addr`, there is nothing to append, `addr` is not an
/// Ed25519 key, the result exceeds the log size limit, or `addr` did not sign the result.
#[must_use]
pub fn append(
    lee_account: AccountWithMetadata,
    program_id: ProgramId,
    update: LogUpdate,
) -> AccountPostState {
    assert!(
        lee_account.account_id == derive_lee_account_id(&program_id, &update.addr),
        "the account is not the log account of addr"
    );
    assert!(!update.entries.is_empty(), "nothing to append");

    let mut lee_account = lee_account.account;
    let encoded_log = get_encoded_log(&lee_account.data);
    let signed_log_bytes = [&update.new_signature[..], encoded_log, &update.entries].concat();
    verify_log_bytes(&signed_log_bytes, &update.addr);

    // Save new log to the LeeAccount
    lee_account.data = signed_log_bytes
        .try_into()
        .expect("a valid log always fits in account data");

    let claim = Claim::Pda(PdaSeed::new(update.addr));
    AccountPostState::new_claimed_if_default(lee_account, claim)
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
    let key = Ed25519VerifyingKey::from_canonical_bytes(addr).expect("addr is not an Ed25519 key");
    let log = SignedAccountLog::from_bytes(bytes).expect("the log exceeds the size limit");
    key.verify(log.payload.as_bytes(), &log.signature)
        .expect("not signed by addr");
}
