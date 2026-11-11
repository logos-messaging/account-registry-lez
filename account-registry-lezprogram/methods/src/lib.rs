//! The guest compiled for the zkVM. `ACCOUNT_REGISTRY_ID` is its image ID, which the program
//! loader records in the program's header; it changes with any change to the guest or its
//! dependencies.

include!(concat!(env!("OUT_DIR"), "/methods.rs"));
