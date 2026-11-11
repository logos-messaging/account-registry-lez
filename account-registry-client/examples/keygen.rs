//! Prints a new LEE key and the public account it signs for, to use as a fee payer or as a
//! program account. Fund the account before using its key as `ACCOUNT_REGISTRY_PAYER`.
//!
//! ```sh
//! cargo run -p account-registry-client --example keygen
//! ```

use account_registry_client::{PrivateKey, signer_id};

fn main() {
    let key = PrivateKey::new_os_random();
    println!("key:     {key}");
    let account = signer_id(&key);
    println!("account: {account}");
    let hex: String = account.value().iter().map(|b| format!("{b:02x}")).collect();
    println!("as hex:  {hex}");
}
