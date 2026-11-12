//! `account-registry`: the operator's tool for the registry program. It deploys the guest built
//! in this workspace and inspects what is on a zone; applications read and write logs through
//! `account-registry-client` instead.
//!
//! Keys are read from the environment only, so they stay out of shell history and process
//! listings: `ACCOUNT_REGISTRY_PAYER` pays the fees, `ACCOUNT_REGISTRY_PROGRAM_KEY` signs for the
//! program account. Against a local sequencer both default to public keys.

use std::{process::ExitCode, thread, time::Duration};

use account_log::{AccountAddr, AccountEntry, AccountLogDraft, EntryData, IndexedAccountEntry};
use account_registry_client::{AccountId, LezAccountRegError, PrivateKey, Registry, signer_id};
use clap::{Parser, Subcommand};

mod deploy;

/// The payer `./run-local-sequencer` funds at genesis. Never use it on a real network.
const LOCAL_PAYER_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// The program account key `deploy` uses on a local sequencer.
const LOCAL_PROGRAM_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";

const PAYER_VAR: &str = "ACCOUNT_REGISTRY_PAYER";
const PROGRAM_KEY_VAR: &str = "ACCOUNT_REGISTRY_PROGRAM_KEY";

/// How often, and how many times, to look for a submitted transaction's effect.
const WAIT_INTERVAL: Duration = Duration::from_secs(2);
const WAIT_ATTEMPTS: u32 = 150;

#[derive(Parser)]
#[command(name = "account-registry", version, about)]
struct Cli {
    /// The sequencer's JSON-RPC URL.
    #[arg(
        long,
        global = true,
        env = "SEQUENCER_URL",
        default_value = "http://localhost:3040"
    )]
    sequencer: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print a new LEE key and the public account it signs for.
    ///
    /// Use one as a fee payer and another as the program account. The key is the secret; the
    /// account is what others send funds to.
    Keygen,

    /// Deploy this build of the registry, or upgrade the build already at the program account.
    ///
    /// Signs with ACCOUNT_REGISTRY_PROGRAM_KEY, whose account becomes the registry's address,
    /// and pays with ACCOUNT_REGISTRY_PAYER. Does nothing if this build is already deployed, and
    /// resumes a deploy that stopped half way.
    Deploy,

    /// Print an account's log, after checking that the address signed it.
    Fetch {
        /// The account's address: 64 lowercase hex characters.
        addr: AccountAddr,

        /// The registry's program account, base58.
        #[arg(long, env = "ACCOUNT_REGISTRY_PROGRAM")]
        program: Option<AccountId>,
    },

    /// Print a LEE account's balance, the payer's if no account is given.
    Balance {
        /// The account, base58.
        account: Option<AccountId>,
    },
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    Registry(#[from] LezAccountRegError),
    #[error("deploying the program: {0}")]
    Deploy(String),
    #[error("set {0}: its default is a public key, for a local sequencer only")]
    MissingKey(&'static str),
    #[error("{0} is not a 64-character hex key")]
    InvalidKey(&'static str),
    #[error("pass --program or set ACCOUNT_REGISTRY_PROGRAM: the registry's program account")]
    MissingProgram,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Error> {
    let url = cli.sequencer;
    let local = is_local(&url);
    match cli.command {
        Command::Keygen => {
            let key = PrivateKey::new_os_random();
            let account = signer_id(&key);
            println!("key:     {key}");
            println!("account: {account}");
            println!("as hex:  {}", hex(account.value()));
        }
        Command::Deploy => {
            let payer = key_from_env(PAYER_VAR, local.then_some(LOCAL_PAYER_KEY))?;
            let header = key_from_env(PROGRAM_KEY_VAR, local.then_some(LOCAL_PROGRAM_KEY))?;
            let program = signer_id(&header);
            println!("Deploying the registry at {program} on {url}, unless it is already there...");
            let registry = Registry::connect(&url, program)?.with_payer(payer);
            deploy::deploy(&registry, &header)?;
            println!("Registry deployed at {program}");
        }
        Command::Fetch { addr, program } => {
            let program = match program {
                Some(program) => program,
                None if local => signer_id(&parse_key(PROGRAM_KEY_VAR, LOCAL_PROGRAM_KEY)?),
                None => return Err(Error::MissingProgram),
            };
            let registry = Registry::connect(&url, program)?;
            match registry.fetch(&addr)? {
                Some(stored) => print_log(&addr, &stored)?,
                None => println!("Nothing is published for {addr} at {program}"),
            }
        }
        Command::Balance { account } => {
            let account = match account {
                Some(account) => account,
                None => signer_id(&key_from_env(PAYER_VAR, local.then_some(LOCAL_PAYER_KEY))?),
            };
            let balance = Registry::connect(&url, account)?.balance(account)?;
            println!("{account}: {balance}");
        }
    }
    Ok(())
}

fn print_log(addr: &AccountAddr, stored: &account_log::SignedAccountLog) -> Result<(), Error> {
    let log = stored
        .verify(addr)
        .map_err(LezAccountRegError::Unverified)?;
    println!(
        "{addr}: {} bytes, signature valid",
        stored.payload.as_bytes().len()
    );
    let draft = AccountLogDraft::from_log(&log).map_err(LezAccountRegError::Log)?;
    for IndexedAccountEntry { index, entry } in draft.entries() {
        match entry {
            AccountEntry::Add {
                context,
                data: EntryData::Ed25519Key(key),
            } => println!(
                "{index:>3}  add     {:<20} ed25519 {}",
                context.as_str(),
                hex(key)
            ),
            AccountEntry::Add {
                context,
                data: EntryData::Text(text),
            } => println!(
                "{index:>3}  add     {:<20} text    {text:?}",
                context.as_str()
            ),
            AccountEntry::Add { context, data } => {
                println!("{index:>3}  add     {:<20} {data:?}", context.as_str());
            }
            AccountEntry::Remove { index: target } => println!("{index:>3}  revoke  #{target}"),
            AccountEntry::Unknown { opcode, .. } => {
                println!("{index:>3}  unknown opcode {opcode}");
            }
        }
    }
    Ok(())
}

/// The key in the variable `name`, or `default` if it is unset or empty, as in a `.env` not yet
/// filled in. With no default, it is required.
fn key_from_env(name: &'static str, default: Option<&str>) -> Result<PrivateKey, Error> {
    let set = std::env::var(name).ok().filter(|key| !key.is_empty());
    match (set, default) {
        (Some(key), _) => parse_key(name, &key),
        (None, Some(key)) => parse_key(name, key),
        (None, None) => Err(Error::MissingKey(name)),
    }
}

fn parse_key(name: &'static str, key: &str) -> Result<PrivateKey, Error> {
    key.parse().map_err(|_| Error::InvalidKey(name))
}

fn is_local(url: &str) -> bool {
    url::Url::parse(url)
        .is_ok_and(|url| matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Polls `landed` until it returns true, or gives up with [`LezAccountRegError::Timeout`].
fn wait(mut landed: impl FnMut() -> Result<bool, Error>) -> Result<(), Error> {
    for _ in 0..WAIT_ATTEMPTS {
        if landed()? {
            return Ok(());
        }
        thread::sleep(WAIT_INTERVAL);
    }
    Err(LezAccountRegError::Timeout.into())
}

#[cfg(test)]
mod tests {
    use account_log::{AccountLog, Context, Ed25519SigningKey};
    use account_registry_client::sign;

    use super::*;

    /// `LOCAL_PAYER_KEY`'s account, as `./run-local-sequencer` names it in the genesis config.
    const LOCAL_PAYER_ID: &str = "78Skt7EQTvVwfWVYnA1XMjghv3aUR1V5wgQAfVLKJZG5";

    #[test]
    fn the_local_payer_id_matches_its_key() {
        let key: PrivateKey = LOCAL_PAYER_KEY.parse().unwrap();
        assert_eq!(LOCAL_PAYER_ID, signer_id(&key).to_string());
    }

    #[test]
    fn public_keys_are_only_for_a_local_sequencer() {
        assert!(is_local("http://localhost:3040"));
        assert!(is_local("http://127.0.0.1:3040"));
        assert!(!is_local("https://testnet.lez.logos.co"));
        assert!(!is_local("http://localhost.example.org"));
    }

    /// The round trip against a real sequencer: deploy, publish, extend, fetch. It also checks
    /// that the client's RPC still speaks the sequencer's wire format. Set `SEQUENCER_URL` to use
    /// one other than `./run-local-sequencer`'s, and `ACCOUNT_REGISTRY_PAYER` to a funded payer
    /// key other than the local genesis one.
    #[test]
    #[ignore = "needs a running sequencer: ./run-local-sequencer"]
    fn against_a_sequencer() {
        let url = std::env::var("SEQUENCER_URL").unwrap_or("http://localhost:3040".into());
        let payer = key_from_env(PAYER_VAR, Some(LOCAL_PAYER_KEY)).unwrap();
        let header = PrivateKey::new_os_random();
        let registry = Registry::connect(&url, signer_id(&header))
            .unwrap()
            .with_payer(payer);
        deploy::deploy(&registry, &header).unwrap();
        deploy::deploy(&registry, &header).unwrap();

        let key = Ed25519SigningKey::generate();
        let addr = AccountAddr::from(key.verifying_key());
        assert!(registry.fetch(&addr).unwrap().is_none());

        let v1 = one_key_log();
        registry.publish(&addr, &sign(&key, &v1).unwrap()).unwrap();
        let stored = registry.fetch(&addr).unwrap().unwrap();
        assert_eq!(stored.verify(&addr).unwrap(), v1);

        let mut v2 = AccountLogDraft::from_log(&v1).unwrap();
        v2.revoke(0).unwrap();
        let v2 = v2.log().clone();
        registry.publish(&addr, &sign(&key, &v2).unwrap()).unwrap();
        let stored = registry.fetch(&addr).unwrap().unwrap();
        assert_eq!(stored.verify(&addr).unwrap(), v2);
    }

    fn one_key_log() -> AccountLog {
        let device = Ed25519SigningKey::generate().verifying_key();
        let mut draft = AccountLogDraft::new();
        let data = EntryData::Ed25519Key(device.as_ref().try_into().unwrap());
        draft.add(Context::literal("chat.signer"), data).unwrap();
        draft.log().clone()
    }
}
