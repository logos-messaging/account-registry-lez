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
    println!("account: {}", signer_id(&key));
}
