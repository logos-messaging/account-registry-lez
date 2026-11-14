//! `account-relay`: the account relay as a service. See the crate docs. The payer's key comes
//! from `ACCOUNT_REGISTRY_PAYER`.

use std::{path::PathBuf, process::ExitCode, sync::Arc, sync::mpsc, thread};

use account_registry_client::{AccountId, PrivateKey, Registry, signer_id};
use account_registry_relay::{
    auth::{Auth, Open, Scheme, SharedToken},
    ledger::Ledger,
    metrics::{self, Metrics},
    p2p::{self, P2p},
    relay::{Policy, QUEUE, Relay},
    transport::Transport,
};
use clap::{Parser, ValueEnum};

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

    /// Take submissions over libp2p on this address, as Logos Core's libp2p_module sends them.
    /// The relay's peer id is printed on start.
    #[arg(
        long,
        env = "ACCOUNT_RELAY_P2P",
        default_value = "/ip4/0.0.0.0/tcp/9010"
    )]
    p2p: libp2p::Multiaddr,

    /// Serve Prometheus metrics on this address, at /metrics, e.g. 0.0.0.0:9464.
    #[arg(long, env = "ACCOUNT_RELAY_METRICS")]
    metrics: Option<String>,

    /// Where the relay keeps its record of what it sponsored, and its libp2p key.
    #[arg(long, env = "ACCOUNT_RELAY_STATE", default_value = "relay-state")]
    state: PathBuf,

    /// Who may be sponsored. `token` reads the shared token from ACCOUNT_RELAY_TOKEN.
    #[arg(long, env = "ACCOUNT_RELAY_AUTH", value_enum, default_value_t = AuthKind::Open)]
    auth: AuthKind,

    /// Sponsored updates per existing account in any 24 hours. A new account's first log is
    /// always sponsored; 0 sponsors new accounts only.
    #[arg(long, env = "ACCOUNT_RELAY_MAX_APPENDS_PER_DAY", default_value_t = 2)]
    max_appends_per_day: usize,

    /// The largest log payload sponsored, in bytes.
    #[arg(long, env = "ACCOUNT_RELAY_MAX_LOG_BYTES", default_value_t = 4096)]
    max_log_bytes: usize,

    /// Sponsored writes in any hour, across all accounts.
    #[arg(long, env = "ACCOUNT_RELAY_MAX_PER_HOUR", default_value_t = 30)]
    max_per_hour: usize,

    /// Sponsored writes in any 24 hours, across all accounts.
    #[arg(long, env = "ACCOUNT_RELAY_MAX_PER_DAY", default_value_t = 200)]
    max_per_day: usize,

    /// Refuse everything below this payer balance, in units.
    #[arg(long, env = "ACCOUNT_RELAY_MIN_BALANCE", default_value_t = 70_000_000)]
    min_balance: u128,
}

#[derive(Clone, Copy, ValueEnum)]
enum AuthKind {
    Open,
    Token,
}

impl AuthKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Token => "token",
        }
    }
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
    let payer = payer_key(&args.sequencer)?;
    let payer_id = signer_id(&payer);
    let registry = Registry::connect(&args.sequencer, args.program)
        .map_err(|error| error.to_string())?
        .with_payer(payer);
    let auth = Auth::new(vec![scheme(args.auth)?]);
    let ledger = Ledger::open(&args.state).map_err(|error| error.to_string())?;
    let policy = Policy {
        max_appends_per_day: args.max_appends_per_day,
        max_log_bytes: args.max_log_bytes,
        max_per_hour: args.max_per_hour,
        max_per_day: args.max_per_day,
        min_balance: args.min_balance,
    };
    let metrics = Arc::new(Metrics::new(vec![
        ("version".into(), env!("CARGO_PKG_VERSION").into()),
        ("program".into(), args.program.to_string()),
        ("payer".into(), payer_id.to_string()),
        ("auth".into(), args.auth.as_str().into()),
    ]));
    eprintln!(
        "account-relay: registry {} on {}, payer {payer_id}",
        args.program, args.sequencer
    );

    if let Some(address) = &args.metrics {
        let server = tiny_http::Server::http(address).map_err(|error| error.to_string())?;
        eprintln!("metrics: serving on http://{address}/metrics");
        let metrics = metrics.clone();
        thread::spawn(move || metrics::serve(&server, &metrics));
    }

    let key = p2p::identity(&args.state).map_err(|error| error.to_string())?;
    let transports: Vec<Box<dyn Transport>> =
        vec![Box::new(P2p::new(key, args.p2p, metrics.clone()))];

    let (jobs, queue) = mpsc::sync_channel(QUEUE);
    for transport in transports {
        let jobs = jobs.clone();
        thread::spawn(move || {
            let name = transport.name();
            if let Err(error) = transport.serve(jobs) {
                eprintln!("error: {name}: {error}");
                std::process::exit(1);
            }
        });
    }
    drop(jobs);

    let mut relay = Relay::new(registry, payer_id, auth, policy, ledger, metrics);
    relay.run(&queue);
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
