//! A libchat `Account` backed by the registry: publish a display name and a chat signer, then
//! fetch the log back by address alone and read the values out of it.
//!
//! Start a sequencer with `./run-local-sequencer`, then:
//!
//! ```sh
//! cargo run -p account-registry-client --example account_publish [SEQUENCER_URL]
//! ```
//!
//! Against another network, set `ACCOUNT_REGISTRY_PAYER` to a funded payer's key and
//! `ACCOUNT_REGISTRY_PROGRAM_KEY` to the program account's key (hex). The local sequencer's
//! genesis funds the default payer.

use account_log::{
    AccountAddr, AccountEntry, AccountLogDraft, Ed25519SigningKey, Ed25519VerifyingKey, EntryData,
    IndexedAccountEntry, SignedAccountLog,
};
use logos_account::{Account, ChatRead, ChatWrite, ProfileRead, ProfileWrite};

use account_registry_client::{
    LOCAL_PAYER_KEY, LOCAL_PROGRAM_KEY, PrivateKey, Registry, signer_id,
};

fn main() {
    let url = get_sequencer_url();
    let payer = key_from_env("ACCOUNT_REGISTRY_PAYER", LOCAL_PAYER_KEY);
    let program = key_from_env("ACCOUNT_REGISTRY_PROGRAM_KEY", LOCAL_PROGRAM_KEY);
    println!(
        "Deploying the registry at {} on {url}, unless it is already there...",
        signer_id(&program)
    );
    let provider = Registry::connect(&url, signer_id(&program))
        .expect("registry failed init")
        .with_payer(payer);
    provider.deploy(&program).expect("deploy failed");

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

fn key_from_env(name: &str, default: &str) -> PrivateKey {
    std::env::var(name)
        .unwrap_or(default.into())
        .parse()
        .unwrap_or_else(|_| panic!("{name} is not a 64-character hex key"))
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
