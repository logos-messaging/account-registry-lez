//! Deploys the registry program, or upgrades the build already at the program account, and
//! prints the registry's address. Does nothing if this build is already deployed.
//!
//! Start a sequencer with `./run-local-sequencer`, then:
//!
//! ```sh
//! cargo run -p account-registry-client --example deploy [SEQUENCER_URL]
//! ```
//!
//! Against another network, set `ACCOUNT_REGISTRY_PAYER` to a funded payer's key and
//! `ACCOUNT_REGISTRY_PROGRAM_KEY` to the program account's key (hex). Both default to public
//! keys, which only a local sequencer accepts; its genesis funds the default payer.

use account_registry_client::{
    LOCAL_PAYER_KEY, LOCAL_PROGRAM_KEY, PrivateKey, Registry, signer_id,
};

fn main() {
    let url = std::env::args()
        .nth(1)
        .unwrap_or("http://localhost:3040".into());
    let local = is_local(&url);
    let payer = key_from_env("ACCOUNT_REGISTRY_PAYER", local.then_some(LOCAL_PAYER_KEY));
    let program = key_from_env(
        "ACCOUNT_REGISTRY_PROGRAM_KEY",
        local.then_some(LOCAL_PROGRAM_KEY),
    );
    let id = signer_id(&program);

    println!("Deploying the registry at {id} on {url}, unless it is already there...");
    Registry::connect(&url, id)
        .expect("registry failed init")
        .with_payer(payer)
        .deploy(&program)
        .expect("deploy failed");
    println!("Registry deployed at {id}");
}

/// The key in `name`, or `default` if it is unset. With no default, the key is required.
fn key_from_env(name: &str, default: Option<&str>) -> PrivateKey {
    let key = std::env::var(name)
        .ok()
        .or(default.map(str::to_owned))
        .unwrap_or_else(|| panic!("set {name}: the default key is public, for local use only"));
    key.parse()
        .unwrap_or_else(|_| panic!("{name} is not a 64-character hex key"))
}

fn is_local(url: &str) -> bool {
    url::Url::parse(url)
        .is_ok_and(|url| matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
}
