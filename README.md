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
| `account-registry-relay` | `account-registry-relay` | The `account-relay` service: publishes other accounts' signed logs and pays the fee |

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

The CLI reads keys from the environment only, never from arguments, so they stay out of shell
history. Keep them in a `.env` file, which git ignores, and edit it in an editor rather than
typing a key into a command:

```sh
cargo install --path account-registry-cli    # or: cargo run -p account-registry-cli -- <command>
account-registry keygen                      # twice: a payer and a program key
cp .env.example .env && chmod 600 .env       # then fill in the two keys
source .env
```

`.env` holds the keys in plain text, so use it for test networks only, one file per network.
Against the testnet, once the payer's account is funded:

```sh
account-registry balance    # the payer's
account-registry deploy
```

`deploy` sends one transaction per segment and one for the header, each waiting for a block. It
reports every one on stderr: its hash, the block it landed in, and what it cost the payer. If a
transaction is in no block after `--timeout` seconds (300 by default), it says how far it got;
running it again resumes from there.

The one line on stdout, `Registry deployed at <address>`, gives the address; put it in `.env` as `ACCOUNT_REGISTRY_PROGRAM`. Keep the
program key: it is the only way to upgrade the deployment. Without the two keys the CLI uses
public ones, and only against a local sequencer. LEZ's `wallet program-loader deploy` deploys the
same ELF too.

### From CI

The **Deploy** workflow does the same from GitHub Actions, on a manual run only: Actions →
Deploy → Run workflow. "Use workflow from" picks what is deployed: `main`, a `release/*`
branch or a `v*` tag that contains the workflow. Each network is a GitHub environment
of the same name holding two secrets, `ACCOUNT_REGISTRY_PAYER` and `ACCOUNT_REGISTRY_PROGRAM_KEY`;
only `lez-testnet` exists so far. Each transaction gets ten minutes to land, and the run's summary
gives the registry's address, the version deployed and the commit. A build for another LEZ
version than the network's is refused before anything is sent, and after deploying the run reads
one known account back. A build made in CI has its own
image ID, so the first CI run upgrades a deployment made from another machine.

To publish a test account to a deployed registry, and read any account's log back:

```sh
source .env
cargo run -p account-registry-client --example account_publish "$SEQUENCER_URL"
account-registry fetch <account address, hex>
```

## Account relay

A new account holds no funds, and the registry charges a fee for every write. An account relay
publishes the account's log for it and pays the fee. It can neither forge nor alter a log, since
the log's own signature authorizes the write, so anyone can run one; a relay can only decline.

A client signs its log and sends it to a relay in one of three ways:

- over libp2p, on `/logos/accounts/relay/1.0.0`, as Logos Core's `libp2p_module` sends with
  `protocolRequest`, the way the RLN membership allocation service is reached;
- over HTTP, to `POST /v1/submit`;
- over Logos Delivery, on the content topic `/logos-accounts/1/relay-submit/json`. On `logos.test`
  a node cannot send without an RLN membership, so this path suits clients that hold one.

The first two answer once the relay has checked the submission. The client then waits for the log
on chain, and pays the fee itself if it does not appear. `account_registry_client::relay` has the
format, and sending it over HTTP or Delivery.

The relay checks everything a failed write would pay for before sending: the signature, that the
log extends the one on chain, the size limits, its own quotas and its balance. By default it
sponsors up to 3 updates per account a day, appends included, logs up to 4 KiB, at most 30 an
hour and 200 a day overall, and refuses everything below 70M units. Credentials are pluggable; the open and shared-token schemes
here are placeholders for a test network.

```sh
# the relay's payer, funded; the registry from Deployments above
export ACCOUNT_REGISTRY_PAYER=<key> ACCOUNT_REGISTRY_PROGRAM=<program account>
# a logosdeliverynode with the Messaging API on :8645, e.g. wakuorg/nwaku:v0.39.2 with
# --entry-layer=messaging --preset=logos.test --rest=true
cargo run -p account-registry-relay -- --sequencer https://testnet.lez.logos.co \
  --p2p /ip4/0.0.0.0/tcp/9010 --http 127.0.0.1:8650 --delivery http://127.0.0.1:8645
# prints its libp2p peer id; the key is kept in relay-state/node_key.hex
curl -s 127.0.0.1:8650/v1/status

# a client with no funds
cargo run -p account-registry-client --example relay_publish -- http://127.0.0.1:8650
```

`account-registry-relay/compose.yaml` runs a relay on the public testnet next to a Logos Delivery
node on `logos.test`. It exposes libp2p on port 9010, HTTP on `127.0.0.1:8650`, and the node's
p2p port 30303:

```sh
cd account-registry-relay
cp .env.example .env   # set ACCOUNT_REGISTRY_PAYER
docker compose up -d
docker compose logs relay | grep peer   # the peer id clients dial
```

## Versions

The version follows LEZ's: registry `0.3.x` is built for LEZ v0.3 and `0.4.x` for LEZ v0.4, and
a build runs on no other LEZ version. `main` follows the newest LEZ version the registry is ported to;
`release/v<minor>` branches carry fixes for a version a network still runs. Deployed commits are
tagged `v<version>`.

The crates compiled into the guest carry a program version of their own, which moves only when
the program does, so a release of the client or the CLI leaves the image ID, and the deployment,
alone. `account-registry --version` prints both.

## Program ID

`ACCOUNT_REGISTRY_ID` is the hash of the guest binary, and the program loader records it in the
header. It changes with any change to the guest or its dependencies, but the program's address,
and with it every log, does not.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option.
