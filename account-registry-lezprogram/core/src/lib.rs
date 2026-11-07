//! The registry's wire types: what a client needs to build a write or find a log, without the
//! program logic.
//!
//! The log of the account with Ed25519 address `addr` lives at a PDA of this program seeded by
//! `addr`, so anyone holding the address can find it. The account's data is exactly the bytes
//! libchat transmits, `SignedAccountLog::to_bytes()` (`signature ‖ payload`).

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::AccountId,
    program::{PdaSeed, ProgramId},
};

pub const ADDR_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

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

/// The account holding `addr`'s log.
#[must_use]
pub fn derive_lee_account_id(program_id: &ProgramId, addr: &[u8; 32]) -> AccountId {
    AccountId::for_public_pda(program_id, &PdaSeed::new(*addr))
}
