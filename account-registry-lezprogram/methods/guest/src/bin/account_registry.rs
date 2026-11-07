//! The on-chain entry point. All logic lives in `account_registry_program`.

use account_registry_core::Instruction;
use account_registry_program::execute;
use lee_core::program::{ProgramInput, ProgramOutput, read_lee_inputs};

fn main() {
    let (input, instruction_data) = read_lee_inputs::<Instruction>();
    let ProgramInput {
        self_program_id,
        caller_program_id,
        pre_states,
        instruction,
    } = input;

    // LEE checks the echoed pre-states against the real ones, so `execute` gets a copy.
    let post_states = execute(self_program_id, pre_states.clone(), instruction);

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .write();
}
