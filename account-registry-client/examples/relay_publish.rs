//! Publishes a throwaway account through an account relay, which pays the fee, and waits until
//! the chain holds it. The account needs no funds.
//!
//! ```sh
//! cargo run -p account-registry-client --example relay_publish -- http://127.0.0.1:8650
//! cargo run -p account-registry-client --example relay_publish -- delivery:http://127.0.0.1:8645
//! ```
//!
//! The first form submits over HTTP to the relay itself, the second publishes on Logos Delivery
//! through a node's REST endpoint. `SEQUENCER_URL` and `ACCOUNT_REGISTRY_PROGRAM` name the
//! registry, as for the CLI; `ACCOUNT_RELAY_TOKEN`, if set, is sent as `token` credentials.

use std::time::Duration;

use account_log::{AccountAddr, AccountLogDraft, Context, Ed25519SigningKey, EntryData};
use account_registry_client::{
    AccountId, Registry,
    relay::{RelayAuth, RelayRequest, submit_delivery, submit_http},
    sign,
};

const WAIT: Duration = Duration::from_secs(600);

fn main() {
    let target = std::env::args()
        .nth(1)
        .expect("give the relay's URL, or delivery:<node REST URL>");
    let sequencer = std::env::var("SEQUENCER_URL").unwrap_or("http://localhost:3040".into());
    let program: AccountId = std::env::var("ACCOUNT_REGISTRY_PROGRAM")
        .expect("set ACCOUNT_REGISTRY_PROGRAM to the registry's program account")
        .parse()
        .expect("ACCOUNT_REGISTRY_PROGRAM is not a base58 account id");
    let registry = Registry::connect(&sequencer, program).expect("registry failed init");

    let key = Ed25519SigningKey::generate();
    let addr = AccountAddr::from(key.verifying_key());
    let mut draft = AccountLogDraft::new();
    let name = EntryData::Text("Saro".into());
    draft
        .add(Context::literal("profile.displayname"), name)
        .unwrap();
    let log = sign(&key, draft.log()).unwrap();
    let prepared = registry.prepare_append(&addr, &log).expect("a new account");

    let auth = std::env::var("ACCOUNT_RELAY_TOKEN").map_or_else(
        |_| RelayAuth::default(),
        |token| RelayAuth {
            kind: "token".into(),
            payload: token,
        },
    );
    let request = RelayRequest::new(&addr, &log, auth);
    println!("Addr: {addr}");
    match target.strip_prefix("delivery:") {
        Some(rest) => {
            let id = submit_delivery(rest, &request).expect("publish on Delivery");
            println!("published on Delivery, request {id}");
        }
        None => {
            let reply = submit_http(&target, &request).expect("reach the relay");
            assert!(reply.accepted, "the relay refused: {:?}", reply.reason);
            println!("the relay accepted it");
        }
    }

    registry
        .await_append(&prepared, WAIT)
        .expect("the log appears on chain");
    println!("on chain: {addr}");
}
