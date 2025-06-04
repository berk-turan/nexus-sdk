use {
    crate::{
        prelude::*,
        utils::secrets::master_key::{MasterKeyError, KEY_LEN, SERVICE, USER},
    },
    anyhow::ensure,
    keyring::Entry,
    rand::{rngs::OsRng, RngCore},
};

/// Generate and store a new 32-byte key in the OS key-ring.
pub async fn crypto_init_key(force: bool) -> AnyResult<()> {
    // 1. Abort if any persistent key already exists (unless --force)
    if Entry::new(SERVICE, "passphrase")?.get_password().is_ok()
        || Entry::new(SERVICE, USER)?.get_password().is_ok()
    {
        ensure!(force, MasterKeyError::KeyAlreadyExists);
    }

    // 2. Generate and store a new 32-byte key
    let mut key = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut key);
    Entry::new(SERVICE, USER)?.set_password(&hex::encode(key))?;

    println!(" 32-byte master key saved to the OS key-ring");
    Ok(())
}
