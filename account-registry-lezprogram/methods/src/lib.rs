//! The guest compiled for the zkVM. `ACCOUNT_REGISTRY_ID` is the program's on-chain identity,
//! and it changes with any change to the guest or its dependencies.
//!
//! TODO: build the guest reproducibly (RISC Zero's Docker image), so the ID does not also depend
//! on the checkout path and the local guest toolchain.

include!(concat!(env!("OUT_DIR"), "/methods.rs"));
