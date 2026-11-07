# account-registry

A [Logos Execution Zone](https://github.com/logos-blockchain/logos-execution-zone) (LEZ) program
that stores [λAccountLogs](https://github.com/logos-messaging/libchat) on chain. Anyone
holding an account's address can find its log and verify it.

## How it works

- Each address's log lives at a PDA seeded by the address. The account's data is
  `SignedAccountLog::to_bytes()`, exactly what libchat transmits.
- The one instruction, `Append`, adds entries to the log. The program accepts it only if the
  result extends the stored log, stays within 128 KiB, and is signed by the address. No wallet is
  needed: the log's signature authorizes the write.
- Readers verify the signature under the address they asked for, so an RPC node can withhold a
  log or serve an older one, but it cannot forge one.

## Layout

| Crate | Path | What it is |
|---|---|---|
| `account-registry-core` | `account-registry-lezprogram/core` | Wire types: the `Append` instruction, and the PDA that holds an address's log |
| `account-registry-program` | `account-registry-lezprogram/program` | The state transition, as plain Rust and unit tested on the host |
| `account-registry-methods` | `account-registry-lezprogram/methods` | The program compiled for the zkVM: `ACCOUNT_REGISTRY_ELF` and `ACCOUNT_REGISTRY_ID` |
| `account-registry-guest` | `account-registry-lezprogram/methods/guest` | The zkVM entry point. Its own workspace, so its `Cargo.lock` alone decides what goes into the image |
| `account-registry-client` | `account-registry-client` | Blocking JSON-RPC client (no async runtime) implementing libchat's `AccountProvider` and `AccountPublisher` |

## Usage

```rust
let registry = Registry::connect("http://localhost:3040")?;
registry.deploy()?; // does nothing if the program is already deployed

let mut account = Account::new(registry.clone());
account.update().set_display_name("Saro").publish()?;

let log = registry.fetch(&account.addr())?.expect("published").verify(&account.addr())?;
assert_eq!(log.display_name(), Some("Saro"));
```

Use libchat's `account` crate at the revision this repo pins, or `account-log` types won't match.
[`examples/account_publish.rs`](account-registry-client/examples/account_publish.rs) is the full
version.

## Running locally

Needs the [RISC Zero toolchain](https://dev.risczero.com/api/zkvm/install) (`rzup install`) to
build the guest.

```sh
./run-local-sequencer                                                     # LEZ sequencer at the pinned revision, on :3040
cargo run -p account-registry-client --example account_publish            # deploy, publish, read back
cargo test --workspace                                                    # includes the guest in the zkVM (a few minutes)
cargo test -p account-registry-client -- --ignored against_a_sequencer    # against the running sequencer
```

The local sequencer runs with `RISC0_DEV_MODE=1`, which skips proof verification. Its state
persists in cargo's checkout of LEZ (`.../lez/sequencer/service/rocksdb-*`); delete that to start
over.

## Program ID

`ACCOUNT_REGISTRY_ID` is the hash of the guest binary, and logs live at PDAs derived from it, so a
client only finds logs written under the same ID. The guest builds reproducibly, so the same
source gives the same ID on any machine.

TODO: build the guest in RISC Zero's Docker image, so the ID no longer depends on the checkout
path or the local guest toolchain.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option.
