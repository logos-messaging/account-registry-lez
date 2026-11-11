# account-registry

A [Logos Execution Zone](https://github.com/logos-blockchain/logos-execution-zone) (LEZ) program
that stores [λAccountLogs](https://github.com/logos-messaging/libchat) on chain. Anyone
holding an account's address can find its log and verify it. Built for LEZ v0.3.2, the version
the public testnet runs.

## How it works

- Each address's log lives in the program's shard of a PDA seeded by the address. The shard's
  data is `SignedAccountLog::to_bytes()`, exactly what libchat transmits.
- The one instruction, `Append`, adds entries to the log. The program accepts it only if the
  result extends the stored log, stays within 32 KiB, and is signed by the address. The log's
  signature authorizes the write; a separate, funded LEE account pays the fee, so anyone can relay
  an account's log.
- The limit is below the AccountLog spec's 128 KiB because each append re-hashes the whole log:
  about 3.3M cycles plus 120 per byte, against LEE's 10M-gas transaction cap. A 32 KiB log
  appends in about 7M.
- Readers verify the signature under the address they asked for, so an RPC node can withhold a
  log or serve an older one, but it cannot forge one.

## Layout

| Crate | Path | What it is |
|---|---|---|
| `account-registry-core` | `account-registry-lezprogram/core` | Wire types: the `Append` instruction, and the PDA that holds an address's log |
| `account-registry-program` | `account-registry-lezprogram/program` | The state transition, as plain Rust and unit tested on the host |
| `account-registry-methods` | `account-registry-lezprogram/methods` | The program compiled for the zkVM: `ACCOUNT_REGISTRY_ELF` and `ACCOUNT_REGISTRY_ID` |
| `account-registry-guest` | `account-registry-lezprogram/methods/guest` | The zkVM entry point. Its own workspace, so its `Cargo.lock` alone decides what goes into the image |
| `account-registry-client` | `account-registry-client` | Blocking JSON-RPC client (no async runtime) implementing libchat's `AccountProvider` and `AccountPublisher`. Does not link the guest |
| `account-registry-cli` | `account-registry-cli` | The `account-registry` binary: `keygen`, `deploy`, `fetch`, `balance` |

## Usage

```rust
let registry = Registry::connect("http://localhost:3040", program)?.with_payer(payer_key);

let mut account = Account::new(registry.clone());
account.update().set_display_name("Saro").publish()?;

let log = registry.fetch(&account.addr())?.expect("published").verify(&account.addr())?;
assert_eq!(log.display_name(), Some("Saro"));
```

`program` is the registry's address, which `account-registry deploy` prints. Use libchat's `account` crate at the revision this repo pins, or `account-log` types won't match.
[`examples/account_publish.rs`](account-registry-client/examples/account_publish.rs) is the full
version.

## Running locally

Needs the [RISC Zero toolchain](https://dev.risczero.com/api/zkvm/install) (`rzup install`) to
build the guest, and `python3` for `run-local-sequencer`, which funds the client's local payer
at genesis.

```sh
./run-local-sequencer                                                  # LEZ sequencer at the pinned revision, on :3040
cargo run -p account-registry-cli -- deploy                            # deploy the registry
cargo run -p account-registry-client --example account_publish         # publish an account, read it back
cargo run -p account-registry-cli -- fetch <ADDR>                      # print the log the example published
cargo test --workspace                                                 # includes the guest in the zkVM (a few minutes)
cargo test -p account-registry-cli -- --ignored against_a_sequencer    # against the running sequencer
```

The local sequencer runs with `RISC0_DEV_MODE=1`, which skips proof verification. Its state
persists in cargo's checkout of LEZ (`.../lez/sequencer/service/rocksdb-*`); delete that to start
over.

## Deploying

LEE deploys a program through its program loader: the guest's ELF goes up in segments, then a
header at an account the deployer chooses points at them. That header account is the program's
address, and logs live at PDAs derived from it. `account-registry deploy` does all of it, paid by
the payer, and leaves the program upgradable by the header key: deploying a new build with the same
key replaces the code and keeps every log. A new header key gives a separate, empty registry.

The CLI reads keys from the environment only. Against the testnet, with a funded payer
(`account-registry keygen` makes a key and prints its account to fund):

```sh
cargo install --path account-registry-cli    # or: cargo run -p account-registry-cli -- <command>
export SEQUENCER_URL=https://testnet.lez.logos.co
export ACCOUNT_REGISTRY_PAYER=<payer key hex>
export ACCOUNT_REGISTRY_PROGRAM_KEY=<program key hex>
account-registry balance    # the payer's
account-registry deploy
```

It prints the registry's address. Keep the program key: it is the only way to upgrade the
deployment. Without the two variables the CLI uses public keys, and only against a local
sequencer. LEZ's `wallet program-loader deploy` deploys the same ELF too.

To publish a test account to a deployed registry, and read any account's log back:

```sh
export ACCOUNT_REGISTRY_PROGRAM=<registry address>
cargo run -p account-registry-client --example account_publish https://testnet.lez.logos.co
account-registry fetch <account address, hex>
```

## Program ID

`ACCOUNT_REGISTRY_ID` is the hash of the guest binary, and the program loader records it in the
header. It changes with any change to the guest or its dependencies, but the program's address,
and with it every log, does not.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option.
