//! Publishes a throwaway account through an account relay, which pays the fee, and waits until
//! the chain holds it. The account needs no funds.
//!
//! ```sh
//! cargo run -p account-registry-relay --example relay_publish -- <peer id> /ip4/127.0.0.1/tcp/9010
//! ```
//!
//! `SEQUENCER_URL` and `ACCOUNT_REGISTRY_PROGRAM` name the registry, as for the CLI;
//! `ACCOUNT_RELAY_TOKEN`, if set, is sent as `token` credentials.

use std::time::Duration;

use account_log::{AccountAddr, AccountLogDraft, Context, Ed25519SigningKey, EntryData};
use account_registry_client::{
    AccountId, Registry,
    relay::{RelayAuth, RelayRequest},
    sign,
};
use account_registry_relay::p2p;

const WAIT: Duration = Duration::from_secs(600);

fn main() {
    let mut args = std::env::args().skip(1);
    let usage = "give the relay's peer id and multiaddr";
    let peer: libp2p::PeerId = args.next().expect(usage).parse().expect("a peer id");
    let addr: libp2p::Multiaddr = args.next().expect(usage).parse().expect("a multiaddr");
    let sequencer = std::env::var("SEQUENCER_URL").unwrap_or("http://localhost:3040".into());
    let program: AccountId = std::env::var("ACCOUNT_REGISTRY_PROGRAM")
        .expect("set ACCOUNT_REGISTRY_PROGRAM to the registry's program account")
        .parse()
        .expect("ACCOUNT_REGISTRY_PROGRAM is not a base58 account id");
    let registry = Registry::connect(&sequencer, program).expect("registry failed init");

    let key = Ed25519SigningKey::generate();
    let addr_of_account = AccountAddr::from(key.verifying_key());
    let mut draft = AccountLogDraft::new();
    let name = EntryData::Text("Saro".into());
    draft
        .add(Context::literal("profile.displayname"), name)
        .unwrap();
    let log = sign(&key, draft.log()).unwrap();
    let prepared = registry
        .prepare_append(&addr_of_account, &log)
        .expect("a new account");

    let auth = std::env::var("ACCOUNT_RELAY_TOKEN").map_or_else(
        |_| RelayAuth::default(),
        |token| RelayAuth {
            kind: "token".into(),
            payload: token,
        },
    );
    let request = RelayRequest::new(&addr_of_account, &log, auth);
    println!("Addr: {addr_of_account}");
    let reply = p2p::submit(peer, addr, &request).expect("reach the relay");
    assert!(reply.accepted, "the relay refused: {:?}", reply.reason);
    println!("the relay accepted it");

    registry
        .await_append(&prepared, WAIT)
        .expect("the log appears on chain");
    println!("on chain: {addr_of_account}");
}
