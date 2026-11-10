//! The on-chain entry point. All logic lives in `account_registry_program`.

use account_registry_core::{Instruction, LogUpdate};
use account_registry_program::{apply, plan};
use lee_core::program::run_program;

fn main() {
    run_program::<Instruction, LogUpdate, [u8], Vec<u8>>(plan, apply)
}
