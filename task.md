## Target Plan

In this repo we want a registry for AccountLogs on the Logos Execution Zone (LEZ): a program that stores each account's signed log on chain, and a Rust client that publishes and fetches it. The specification is [here](https://github.com/logos-co/logos-lips/blob/f28cf3e5215db78e41249f32e3f5cde5cc1e8193/docs/identity/raw/accountlog.md?plain=1). It leaves open how a log is published and fetched by address, and this repo is that mechanism.

The log format, its verification and the `AccountProvider` / `AccountPublisher` traits come from the `account-log` and `account` crates in https://github.com/logos-messaging/logos-chat. Link them, do not reimplement them, so the chain accepts exactly what consumers accept.


## Requirements

- Runs natively in rust
- The client is blocking. No async runtime.
- No wallet or LEE signer. The log's own signature authorizes a write, and deployment is unsigned.
- Application-agnostic. The registry never interprets entries or contexts.
- Code documentation is minimal


## Decisions

### Storage
- An address's log lives at a public PDA of the program, seeded by the 32-byte address, so the address alone finds it.
- The account data is the spec's signed log, byte for byte. Empty data means nothing was published.

### Instruction
- One instruction, `Append(LogUpdate { addr, new_signature, entries })`, borsh-encoded. The variant index is the opcode, so new instructions go at the end.
- `entries` holds only the new bytes. `new_signature` covers the whole resulting payload, which makes it a compare-and-swap: a write prepared against a log that has since moved on no longer verifies.

### Program
- A rejected write panics, which is how a LEE program refuses a transaction.
- Reject anything but exactly one account, an account that is not `addr`'s PDA, empty `entries`, and a result that is not a signed log under the spec's signature and size rules.
- Claim the account for the program on its first write.
- Do not decode entries. Validating a log costs about 240k cycles per stored key, so re-validating on every write would exceed LEE's 32M-cycle limit at around 120 keys and leave the account unwritable for good. The signature check is one hash of the payload, under 20M cycles at the size limit. A correctly signed log with invalid entries is therefore stored, and consumers reject it as the spec requires.
- The logic is plain Rust, tested on the host. The zkVM guest only calls it.

### Client
- `fetch` verifies the signature under the address asked about before returning, so an RPC node can withhold a log or serve an older one but cannot forge one. The client keeps no state: retaining logs and validating entries stay with the consumer.
- `publish` requires a strict extension of the log on chain, sends only the new entries, and waits until the log is there. If another write lands first it fails with a conflict, and the caller fetches, rebuilds and signs again.
- `deploy` does nothing if the program is already deployed.
- Defaults: poll every 1s up to 60 times, request timeout 30s.
- Blocking JSON-RPC to the sequencer (`getAccount`, `sendTransaction`). LEZ's own RPC client and transaction enum pull in tokio, so keep a local copy of the enum and test that it encodes exactly like LEZ's.

### Versions and program ID
- One LEZ revision for every LEZ crate, the guest's included, and one logos-chat revision. Bump each set together.
- The local sequencer (`./run-local-sequencer`) is built from the pinned LEZ revision, never from a separate clone.
- The guest is its own workspace, so its `Cargo.lock` alone decides the image and with it the program ID. Logs live at PDAs derived from that ID, so any change to the guest or its lockfile moves every log.

### Project setup
- Crates `account-registry-core` (wire types), `-program` (state transition), `-methods` (embedded guest), `-guest` (zkVM entry point), `-client`.
- Rust edition 2024, toolchain pinned to upstream LEZ's, MIT/Apache-2.0 dual licence.
- Dependencies: `account-log`, `account`, `lee`, `lee_core`, `risc0-zkvm`, `risc0-build`, `borsh`, `ureq`, `url`, `serde`, `serde_json`, `base64`, `thiserror`.


## Done Criteria

- `cargo fmt` and `cargo clippy -- -D warnings` are clean for the workspace and for the guest's workspace. `cargo test --locked --workspace` and `cargo deny check` pass.
- Host unit tests for every program rule: create, extend, and each rejection.
- The compiled guest runs in the zkVM, LEE accepts its output, and appending to a full log stays within LEE's cycle limit.
- Client tests show a log is found and verified from the address alone, and that transactions encode exactly like LEZ's.
- A round trip against a local sequencer (deploy, publish, extend, fetch) passes. It is ignored by default.

Out of scope: async client, wallet or LEE-signer authorization, validating entries on chain.