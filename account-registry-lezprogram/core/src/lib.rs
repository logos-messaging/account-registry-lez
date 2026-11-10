//! The registry's wire types: what a client needs to build a write or find a log, without the
//! program logic.
//!
//! The log of the account with Ed25519 address `addr` lives in this program's shard of a PDA
//! seeded by `addr`, so anyone holding the address can find it. The shard's data is exactly the
//! bytes libchat transmits, `SignedAccountLog::to_bytes()` (`signature ‖ payload`).

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{account::AccountId, program::PdaSeed};

pub const ADDR_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// The largest payload the registry stores, domain prefix included.
///
/// Below the AccountLog spec's 128 KiB: every write re-hashes the whole log, and an append to a
/// log this size must still fit LEE's 10M-gas transaction cap, or the account could never be
/// written again. Clients must check it before sending, since a refused write still pays.
pub const MAX_LOG_PAYLOAD_BYTES: usize = 32 * 1024;

/// An instruction to the program: the type its instruction data decodes to.
///
/// Borsh writes the variant's index as a leading byte, so each operation's position is its opcode.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    Append(LogUpdate),
}

/// Appends `entries` to the log of the account `addr`.
///
/// `signature` covers the whole resulting payload: the stored payload (just the domain prefix,
/// for a new account) followed by `entries`. Signing the result rather than the entries makes
/// the signature its own compare-and-swap — a write prepared against a log that has since moved
/// on no longer verifies — and leaves the account holding a signature over exactly what it holds.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct LogUpdate {
    pub addr: [u8; ADDR_LEN],
    pub new_signature: [u8; SIGNATURE_LEN],
    pub entries: Vec<u8>,
}

/// The account holding `addr`'s log, for the registry deployed at `program`.
#[must_use]
pub fn derive_lee_account_id(program: &AccountId, addr: &[u8; ADDR_LEN]) -> AccountId {
    AccountId::for_public_pda(program, &PdaSeed::new(*addr))
}
