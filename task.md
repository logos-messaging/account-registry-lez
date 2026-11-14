## Target Plan

In this repo we want a registry for AccountLogs on the Logos Execution Zone (LEZ): a program that stores each account's signed log on chain, a Rust client that publishes and fetches it, and a CLI that deploys the program. The specification is [here](https://github.com/logos-co/logos-lips/blob/f28cf3e5215db78e41249f32e3f5cde5cc1e8193/docs/identity/raw/accountlog.md?plain=1). It leaves open how a log is published and fetched by address, and this repo is that mechanism.

The log format, its verification and the `AccountProvider` / `AccountPublisher` traits come from the `account-log` and `account` crates in https://github.com/logos-messaging/logos-chat. Link them, do not reimplement them, so the chain accepts exactly what consumers accept.


## Requirements

- Runs natively in rust
- The client is blocking. No async runtime.
- The log's own signature authorizes a write. The account needs no LEE key: a separately funded LEE account pays the fee and signs only for that, so anyone with funds can relay any account's log.
- Application-agnostic. The registry never interprets entries or contexts.
- Code documentation is minimal


## Decisions

### Storage
- An address's log lives in the program's shard of a public PDA derived from the program account and seeded by the 32-byte address, so the address alone finds it.
- The shard's data is the spec's signed log, byte for byte. An empty shard means nothing was published.

### Instruction
- One instruction, `Append(LogUpdate { addr, new_signature, entries })`, borsh-encoded. The variant index is the opcode, so new instructions go at the end.
- `entries` holds only the new bytes. `new_signature` covers the whole resulting payload, which makes it a compare-and-swap: a write prepared against a log that has since moved on no longer verifies.

### Program
- LEE v0.3 runs a program in two steps, and the guest is `run_program(plan, apply)`. `plan` sees the instruction and the accounts it names, never their data; `apply` sees the stored shard.
- A rejected write panics, which is how a LEE program refuses a transaction.
- `plan` rejects anything but exactly one account, an account that is not `addr`'s PDA, a shard of another program, and empty `entries`. `apply` rejects a result over the size limit or not signed by `addr`.
- A program writes only its own shard and needs no claim on the account.
- Do not decode entries. Validating a log costs about 240k cycles per stored key, so re-validating on every write would exceed the gas cap after a few dozen keys and leave the account unwritable for good. A correctly signed log with invalid entries is therefore stored, and consumers reject it as the spec requires.
- The logic is plain Rust, tested on the host. The zkVM guest only calls it.

### Fees and limits
- Every user public transaction on LEE v0.3 declares a fee, signed by its payer. A refused transaction still pays its full reserved gas, so the client checks everything the program would refuse before sending.
- One transaction may execute at most 10M gas (`MAX_GAS_EXEC`), one gas per cycle summed over the plan and apply sessions. Measured on v0.3.2, an append costs about 3.3M cycles plus about 120 per byte of the resulting log, which the signature check hashes.
- The same 10M is the cap on a whole block's execution gas, and the base fee rises while blocks run above 5M. One block therefore fits one to three appends, from every account on the zone together.
- Logs are capped at 32 KiB (`MAX_LOG_PAYLOAD_BYTES`), below the spec's 128 KiB: an append to a 32 KiB log costs about 7.1M cycles, and appends stop fitting at about 55 KiB. v0.3.2 also caps a program's data in one account at 100 KiB. Removing the cap needs a change to what is signed and is out of scope here.
- The client reserves `append_gas_limit(len)` = 4M + 130 per byte, capped at 10M. The guest tests run every append under that reserve, so a cost change that outgrows it fails them.
- At the minimum base fee of 8, creating an account (two entries) cost 26.3M units, measured on a local v0.3.2 sequencer; an append to a 32 KiB log costs about 58M. The payer must hold the reserve, gas limit × base fee, while a write runs; the unused part is refunded.

### Client
- `fetch` verifies the signature under the address asked about before returning, so an RPC node can withhold a log or serve an older one but cannot forge one. The client keeps no state: retaining logs and validating entries stay with the consumer.
- `publish` requires a strict extension of the log on chain, sends only the new entries, and waits until the log is there. If another write lands first it fails with a conflict, and the caller fetches, rebuilds and signs again.
- Writes need a funded payer (`with_payer`); reads do not.
- An app that pays through its own wallet uses `prepare_append`, which returns the program, the log's account, the gas limit and the encoded `Append` without sending, then `await_append(&prepared, timeout)` once its wallet accepted the transaction. The prepared append remembers its address and log, so it cannot be awaited against another account. `publish` is the two with the configured payer in between, waiting `PUBLISH_TIMEOUT`.
- Defaults: poll every 2s up to 150 times (5 minutes), request timeout 30s. The public testnet makes about one block a minute, sometimes slower, so a write takes a minute or two to land and a deploy several.
- Blocking JSON-RPC to the sequencer (`getAccount`, `getAccountBalance`, `sendTransaction`, `getTransaction`, `getLastBlockId`). `send` returns the transaction's hash. LEZ's own RPC client and transaction enum pull in tokio, so keep a local copy of the enum and test that it encodes exactly like LEZ's.
- The client does not link the guest, so an application depending on it builds without the RISC Zero toolchain. It exposes `send`, `account` and `balance` for callers that build other transactions, which is all deploying needs from it.
- The one example, `account_publish`, publishes a test account and never deploys.

### CLI
- `account-registry` is the operator's tool, in its own crate so the client carries no argument parser and no guest: `keygen`, `deploy`, `fetch <addr>`, `balance [account]`.
- `deploy` goes through LEE's program loader: the guest's user ELF in 96 KiB segments, then a header at the program account. It creates the program, upgrades it in place if another mutable build is there, and does nothing if this build is. Deployments are mutable; the header key is the upgrade authority.
- Segment accounts are PDAs of the program account seeded by the image ID and index, so a half-done deploy resumes. Anyone may write a segment, so an existing one is reused only if it holds exactly this build's bytes.
- `deploy` reports each transaction on stderr: its hash, the block it landed in and its cost to the payer, then the totals. A transaction in no block after `--timeout` (300 s) ends the run with what is already on chain and how to resume; one that is in a block without effect is reported as refused. Only the registry's address goes to stdout.
- The Deploy workflow runs `deploy` from GitHub Actions, on manual dispatch. It deploys the ref it is started from, which must be `main`, a `release/*` branch or a `v*` tag; a ref without the workflow cannot be deployed with it. A build whose program version is not for the network's LEZ minor is refused before anything is sent. After deploying it reads one known account back, writing nothing. A network is a GitHub environment holding the two keys as secrets, exposed only to the deploy step; `lez-testnet` is the one network so far. Each transaction gets 10 minutes to land.
- Keys come from the environment only (`ACCOUNT_REGISTRY_PAYER`, `ACCOUNT_REGISTRY_PROGRAM_KEY`), never from arguments. `.env.example` lists every variable; a filled-in `.env` is ignored by git and sourced by the operator, and the CLI does not read it itself. `LOCAL_PAYER_KEY` and `LOCAL_PROGRAM_KEY` are public keys for a local sequencer; the CLI and the example fall back to them only against a local URL.

### Account relay
- `account-relay` publishes other accounts' signed logs and pays the fee, so a new account can be published before its owner holds funds. Anyone can run one: the log authorizes its own write, so a relay can only decline it.
- Submissions arrive over libp2p on `/logos/accounts/relay/1.0.0`, as JSON: version, address, the signed log in base64, and credentials. The relay answers once it has checked a submission; the client then waits for its log on chain and falls back to paying itself. Other transports implement `Transport`.
- The libp2p transport is what Logos Core's `libp2p_module` speaks with `protocolRequest`: TCP, Noise and mplex, the only muxer it offers over TCP; one request and one reply, each framed by an unsigned-varint length, the request read by its length since the client keeps its side open until the reply. The relay's identity is a secp256k1 key in its state directory, so its peer id stays the same across restarts.
- Logos Delivery is not a transport: on `logos.test`, a delivery node without an RLN membership cannot send, and a new user has none.
- One worker handles every submission in turn, so writes never race for an account or the payer's nonce. It checks everything a refused write would pay for before sending, and records a write in its ledger before sending it, since a sent write pays even if it fails.
- Limits: a new account's first log always, then sponsored updates per existing account in any 24 hours (2; 0 for new accounts only), log size (4 KiB), per hour and per day overall, and a minimum payer balance. The ledger keeps counts and used credentials on disk.
- Metrics: Prometheus on `--metrics`, at `/metrics`.
- Credentials are a `Scheme` per `kind`, after the RLN membership allocation service's auth vectors. A scheme may return a nullifier, sponsored once. The open and shared-token schemes are placeholders.

### Versions and program ID
- LEZ v0.3.2, the release the public testnet runs, pinned by tag for every LEZ crate, the guest's included, and one logos-chat revision. Bump each set together.
- The local sequencer (`./run-local-sequencer`) is built from the commit `Cargo.lock` resolves the LEZ tag to, never from a separate clone. Its genesis funds `LOCAL_PAYER_KEY`'s account, since no program can mint native balance once the chain runs.
- The program ID is the header account the deployer chooses, and logs live at PDAs derived from it, so redeploying a new build under the same header keeps every log. The guest is its own workspace, so its `Cargo.lock` alone decides the image ID the header records.

### Releases
- The version follows LEZ's: registry `0.<minor>.x` is built for LEZ `0.<minor>` and runs on no other, since LEZ versions share no program model or transaction format. The patch number is this repo's own.
- The crates compiled into the guest, `core`, `program` and the guest itself, share a program version of their own, written out in their manifests. A crate's version is part of the image, so it moves only when the program, its dependencies or the LEZ pin change: a release of the client or the CLI alone keeps the image ID, and `deploy` from it does nothing. CI checks the three agree, and that they moved if those crates changed since the last tag.
- `main` follows the newest LEZ version the registry is ported to. A commit that is deployed or released is tagged `v<version>`, e.g. `v0.3.0`.
- When `main` moves to the next LEZ version while a network still runs the previous one, a `release/v<minor>` branch is cut from the last tag of that line, e.g. `release/v0.3`, and deleted once no network runs it.
- A fix goes to `main` first and is cherry-picked to a release branch only if that network needs it. A fix to code that exists only on the old line goes to the release branch alone.

### Networks and migration
- The client talks to any LEZ sequencer. The public testnet's is `https://testnet.lez.logos.co`; it takes POST only and sends no CORS headers.
- Target the LEZ version the public testnet runs: v0.3.2 now, v0.4 once testnet moves to it at the end of November 2026. LEZ-version-specific code stays in the guest entry, transaction building and deploy, so a port leaves the rules in `program` untouched.
- A network upgrade may start a new genesis. A log then moves by being appended, whole, to the empty account on the new deployment with its stored signature, which anyone holding the log can do.

### Project setup
- Crates `account-registry-core` (wire types), `-program` (state transition), `-methods` (embedded guest), `-guest` (zkVM entry point), `-client`, `-cli`.
- Rust edition 2024, toolchain pinned to upstream LEZ's (1.98.1 for v0.3.2), MIT/Apache-2.0 dual licence.
- Dependencies: `account-log`, `account`, `lee`, `lee_core`, `program_loader_core`, `risc0-zkvm`, `risc0-build`, `risc0-binfmt`, `risc0-zkos-v1compat`, `borsh`, `clap`, `ureq`, `url`, `serde`, `serde_json`, `base64`, `thiserror`.


## Done Criteria

- `cargo fmt` and `cargo clippy -- -D warnings` are clean for the workspace and for the guest's workspace. `cargo test --locked --workspace` and `cargo deny check` pass.
- Host unit tests for every program rule: create, extend, and each rejection.
- The compiled guest runs through LEE's state machine, and every append, including one to a log at the size limit, fits the gas the client reserves for it.
- Client tests show a log is found and verified from the address alone, and that transactions encode exactly like LEZ's.
- A round trip against a local sequencer (deploy, publish, extend, fetch) passes. It lives in the CLI crate, is ignored by default and runs in CI's sequencer job.

Out of scope: async client, LEE-signer authorization of writes, validating entries on chain, logs over 32 KiB, and sponsored publishing: a relayer paying for other accounts' writes is a separate service built on the client.


## Open Questions

- Who holds the header key of the deployment apps depend on, and whether that one is mutable.
- A full log can no longer revoke a key. Whether the client should stop accepting endorsements shortly before the cap, keeping room for revocations (7 bytes each).
- Whether LEZ can raise the 10M-gas transaction cap, or the spec should sign a running digest so an append's cost stops growing with the log.
- Throughput: one to three appends per block for the whole zone, and sustained load raises the base fee past the client's fixed `max_fee` (sized for a base fee of 64). Whether that is enough for onboarding, and whether `max_fee` should follow the sequencer's fee state.
- A retry sent while an earlier transaction from the same payer is still pending reuses its nonce and is dropped.
- `publish` does not check that a program is deployed at the program account, so a wrong one only shows as a timeout.
- `deploy` replaces any other mutable build, including a newer one. Whether upgrading should be an explicit call.
- Writes from several clones of one `Registry` read the payer's nonce independently, so concurrent writes collide. Whether to serialize writes per payer.
- Segment addresses are predictable and need no authorization, so a squatter can block deploying a build at a program account, though not hijack it.