//! `account-relay`: publishes other accounts' signed logs to the registry and pays the fee, so an
//! account can be published before its owner holds any funds.
//!
//! Submissions arrive over libp2p, as Logos Core's `libp2p_module` sends them, over HTTP, and
//! over Logos Delivery, through a `logosdeliverynode`'s REST endpoint. Anyone can run a relay: a
//! log authorizes its own write, so a relay can only decline one, never forge or alter it. The
//! payer's key comes from `ACCOUNT_REGISTRY_PAYER`.

use std::{path::PathBuf, process::ExitCode, sync::mpsc, thread};

use account_registry_client::{AccountId, PrivateKey, Registry, signer_id};
use clap::{Parser, ValueEnum};

use crate::{
    auth::{Auth, Open, Scheme, SharedToken},
    ledger::Ledger,
    relay::{Policy, QUEUE, Relay},
};

mod auth;
mod delivery;
mod http;
mod ledger;
mod p2p;
mod relay;

/// The payer `./run-local-sequencer` funds at genesis. Never use it on a real network.
const LOCAL_PAYER_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

#[derive(Parser)]
#[command(name = "account-relay", version, about)]
struct Args {
    /// The sequencer's JSON-RPC URL.
    #[arg(long, env = "SEQUENCER_URL", default_value = "http://localhost:3040")]
    sequencer: String,

    /// The registry's program account, base58.
    #[arg(long, env = "ACCOUNT_REGISTRY_PROGRAM")]
    program: AccountId,

    /// Take submissions over HTTP on this address, e.g. 127.0.0.1:8650.
    #[arg(long, env = "ACCOUNT_RELAY_HTTP")]
    http: Option<String>,

    /// Take submissions over Logos Delivery through this node's REST endpoint, e.g.
    /// http://127.0.0.1:8645.
    #[arg(long, env = "ACCOUNT_RELAY_DELIVERY")]
    delivery: Option<String>,

    /// Take submissions over libp2p on this address, e.g. /ip4/0.0.0.0/tcp/9010, as Logos
    /// Core's libp2p_module sends them. The relay's peer id is printed on start.
    #[arg(long, env = "ACCOUNT_RELAY_P2P")]
    p2p: Option<libp2p::Multiaddr>,

    /// Where the relay keeps its record of what it sponsored, and its libp2p key.
    #[arg(long, env = "ACCOUNT_RELAY_STATE", default_value = "relay-state")]
    state: PathBuf,

    /// Who may be sponsored. `token` reads the shared token from ACCOUNT_RELAY_TOKEN.
    #[arg(long, value_enum, default_value_t = AuthKind::Open)]
    auth: AuthKind,

    /// Sponsored writes per account in any 24 hours, appends included.
    #[arg(long, default_value_t = 3)]
    max_per_account_per_day: usize,

    /// Sponsor only accounts with nothing published yet.
    #[arg(long)]
    new_accounts_only: bool,

    /// The largest log payload sponsored, in bytes.
    #[arg(long, default_value_t = 4096)]
    max_log_bytes: usize,

    /// Sponsored writes in any hour, across all accounts.
    #[arg(long, default_value_t = 30)]
    max_per_hour: usize,

    /// Sponsored writes in any 24 hours, across all accounts.
    #[arg(long, default_value_t = 200)]
    max_per_day: usize,

    /// Refuse everything below this payer balance, in units.
    #[arg(long, default_value_t = 70_000_000)]
    min_balance: u128,
}

#[derive(Clone, Copy, ValueEnum)]
enum AuthKind {
    Open,
    Token,
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<(), String> {
    if args.http.is_none() && args.delivery.is_none() && args.p2p.is_none() {
        return Err("take submissions somewhere: set --http, --p2p or --delivery".into());
    }
    let payer = payer_key(&args.sequencer)?;
    let payer_id = signer_id(&payer);
    let registry = Registry::connect(&args.sequencer, args.program)
        .map_err(|error| error.to_string())?
        .with_payer(payer);
    let auth = Auth::new(vec![scheme(args.auth)?]);
    let ledger = Ledger::open(&args.state).map_err(|error| error.to_string())?;
    let policy = Policy {
        max_per_account_per_day: args.max_per_account_per_day,
        new_accounts_only: args.new_accounts_only,
        max_log_bytes: args.max_log_bytes,
        max_per_hour: args.max_per_hour,
        max_per_day: args.max_per_day,
        min_balance: args.min_balance,
    };
    eprintln!(
        "account-relay: registry {} on {}, payer {payer_id}",
        args.program, args.sequencer
    );

    let (jobs, queue) = mpsc::sync_channel(QUEUE);
    let mut workers = Vec::new();
    if let Some(address) = args.http {
        let server = tiny_http::Server::http(&address).map_err(|error| error.to_string())?;
        eprintln!("http: listening on {address}");
        let jobs = jobs.clone();
        workers.push(thread::spawn(move || http::serve(&server, &jobs)));
    }
    if let Some(listen) = args.p2p {
        let key = p2p::identity(&args.state).map_err(|error| error.to_string())?;
        let jobs = jobs.clone();
        workers.push(thread::spawn(move || {
            if let Err(error) = p2p::serve(key, listen, &jobs) {
                eprintln!("error: p2p: {error}");
                std::process::exit(1);
            }
        }));
    }
    if let Some(rest) = args.delivery {
        let jobs = jobs.clone();
        workers.push(thread::spawn(move || delivery::listen(&rest, &jobs)));
    }
    drop(jobs);

    let mut relay = Relay::new(registry, payer_id, auth, policy, ledger);
    relay.run(&queue);
    for worker in workers {
        let _done = worker.join();
    }
    Ok(())
}

fn scheme(kind: AuthKind) -> Result<Box<dyn Scheme>, String> {
    match kind {
        AuthKind::Open => Ok(Box::new(Open)),
        AuthKind::Token => match std::env::var("ACCOUNT_RELAY_TOKEN") {
            Ok(token) if !token.is_empty() => Ok(Box::new(SharedToken(token))),
            _ => Err("--auth token needs ACCOUNT_RELAY_TOKEN".into()),
        },
    }
}

/// The payer's key from the environment, or the public local one against a local sequencer.
fn payer_key(sequencer: &str) -> Result<PrivateKey, String> {
    let key = match std::env::var("ACCOUNT_REGISTRY_PAYER") {
        Ok(key) if !key.is_empty() => key,
        _ if is_local(sequencer) => LOCAL_PAYER_KEY.to_owned(),
        _ => return Err("set ACCOUNT_REGISTRY_PAYER to the relay's funded key".into()),
    };
    key.parse()
        .map_err(|_| "ACCOUNT_REGISTRY_PAYER is not a 64-character hex key".into())
}

fn is_local(url: &str) -> bool {
    url::Url::parse(url)
        .is_ok_and(|url| matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
}
