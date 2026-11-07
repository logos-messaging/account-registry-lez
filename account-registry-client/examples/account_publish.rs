//! A libchat `Account` backed by the registry: publish a display name and a chat signer, then
//! fetch the log back by address alone and read the values out of it.
//!
//! Start a sequencer with `./run-local-sequencer`, then:
//!
//! ```sh
//! cargo run -p account-registry-client --example account_publish [SEQUENCER_URL]
//! ```

use account_log::{
    AccountAddr, AccountEntry, AccountLogDraft, Ed25519SigningKey, Ed25519VerifyingKey, EntryData,
    IndexedAccountEntry, SignedAccountLog,
};
use logos_account::{Account, ChatRead, ChatWrite, ProfileRead, ProfileWrite};

use account_registry_client::Registry;

fn main() {
    let url = get_sequencer_url();
    println!("Deploying the registry to {url}, unless it is already there... (~45 seconds)");
    let provider = Registry::connect(&url).expect("registry failed init");
    provider.deploy().expect("deploy failed");

    let mut account = Account::new(provider.clone());

    {
        // Account has not been published so it should not exist
        let fetched_slog = provider.fetch(&account.addr()).expect("fetch failed");
        assert!(fetched_slog.is_none())
    }

    {
        // Publish new AccountLog
        let slog = account
            .update()
            .set_display_name("Saro")
            .endorse_chat_signer(&Ed25519SigningKey::generate().verifying_key())
            .publish()
            .unwrap();
        pretty_print(&slog, &account.addr());
    }

    {
        // Fetch the AccountLog we created
        let fetched_slog = provider
            .fetch(&account.addr())
            .expect("fetch failed")
            .expect("log is missing");
        // Ensure the RPC endpoint did not tamper with the Log.
        let log = fetched_slog.verify(&account.addr()).expect("log is valid");

        println!(
            "Name: {:?}   ChatSigner: {:?}",
            log.display_name(),
            short(log.chat_signers().as_slice())
        )
    }
}

fn pretty_print(slog: &SignedAccountLog, addr: &AccountAddr) {
    let log = slog.verify(addr).expect("invalid signature");

    println!("Addr:{}       Signature: Valid", addr);
    let draft = AccountLogDraft::from_log(&log).expect("every entry readable by this build");
    for IndexedAccountEntry { index, entry } in draft.entries() {
        match entry {
            AccountEntry::Add {
                context,
                data: EntryData::Ed25519Key(key),
            } => {
                let hex: String = key[..4].iter().map(|b| format!("{b:02x}")).collect();
                println!(
                    "{index:>3}  add     {:<20} ed25519 {hex}…",
                    context.as_str()
                );
            }
            AccountEntry::Add {
                context,
                data: EntryData::Text(text),
            } => {
                println!(
                    "{index:>3}  add     {:<20} text    {text:?}",
                    context.as_str()
                );
            }
            AccountEntry::Add { context, data } => {
                println!("{index:>3}  add     {:<20} {data:?}", context.as_str());
            }
            AccountEntry::Remove { index: target } => println!("{index:>3}  revoke  #{target}"),
            AccountEntry::Unknown { opcode, .. } => {
                println!("{index:>3}  unknown opcode {opcode}")
            }
        }
    }
}

fn get_sequencer_url() -> String {
    std::env::args()
        .nth(1)
        .unwrap_or("http://localhost:3040".into())
}

/// The first bytes of each key, enough to tell them apart.
fn short(keys: &[Ed25519VerifyingKey]) -> String {
    let names: Vec<String> = keys
        .iter()
        .map(|key| {
            key.to_bytes()[..4]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        })
        .collect();
    names.join(", ")
}
