fn main() {
    // `cargo clippy` sets RUSTC_WORKSPACE_WRAPPER, which the nested guest build inherits and
    // cannot use for the zkVM target. Lint the guest, its own workspace, with
    // `cargo clippy --manifest-path account-registry-lezprogram/methods/guest/Cargo.toml`.
    // SAFETY: build scripts are single-threaded.
    unsafe { std::env::remove_var("RUSTC_WORKSPACE_WRAPPER") };
    risc0_build::embed_methods();
}
