use {
    crate::{
        prelude::*,
        utils::secrets::master_key::{MasterKeyError, SERVICE, USER},
    },
    anyhow::ensure,
    keyring::Entry,
};

/// Prompt for a pass-phrase and store it securely in the key-ring.
pub async fn crypto_set_passphrase(stdin: bool, force: bool) -> AnyResult<()> {
    // Guard against overwriting unless --force(are you really sure you want to do this?)
    // Will lose all existing sessions
    if Entry::new(SERVICE, USER)?.get_password().is_ok() && !force {
        bail!(MasterKeyError::KeyAlreadyExists);
    }

    let pass = if stdin {
        use std::io::{self, Read};
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        buf.trim_end_matches('\n').to_owned()
    } else {
        rpassword::prompt_password("Enter new pass-phrase: ")?
    };
    ensure!(!pass.trim().is_empty(), "pass-phrase cannot be empty");

    Entry::new(SERVICE, "passphrase")?.set_password(&pass)?;
    println!(" pass-phrase stored in the OS key-ring");
    Ok(())
}
