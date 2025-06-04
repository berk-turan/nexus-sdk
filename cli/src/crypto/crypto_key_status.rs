use {
    crate::{
        prelude::*,
        utils::secrets::master_key::{SERVICE, USER},
    },
    keyring::Entry,
};

/// Show where the key was loaded from.
pub fn crypto_key_status() -> AnyResult<()> {
    if let Ok(_) = std::env::var("NEXUS_CLI_STORE_PASSPHRASE") {
        println!("source: ENV var");
    } else if let Ok(_) = Entry::new(SERVICE, "passphrase")?.get_password() {
        println!("source: key-ring pass-phrase");
    } else if let Ok(hex) = Entry::new(SERVICE, USER)?.get_password() {
        println!("source: key-ring raw key ({:.8}…)", &hex[..8]);
    } else {
        println!(" no persistent master key found");
    }
    Ok(())
}
