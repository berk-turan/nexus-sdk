use argon2::{Algorithm, Argon2, Params, Version};
use directories::ProjectDirs;
use hex::FromHexError;
use keyring::Entry;
use rand::rngs::OsRng;
use rand::RngCore;
use std::env;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::PathBuf;
use thiserror::Error;
use zeroize::Zeroizing;

pub const SERVICE: &str = "nexus-cli-store";
pub const USER: &str = "master-key";

/// Length of the master key in bytes (256-bit AES key).
pub const KEY_LEN: usize = 32;
/// Length of the salt used for Argon2 key derivation.
pub const SALT_LEN: usize = 16;

// Default Argon2id parameters.
/// Memory cost in KiB (64 MiB).
pub const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
/// Number of iterations.
pub const ARGON2_ITERATIONS: u32 = 4;
/// Parallelism degree.
pub const ARGON2_PARALLELISM: u32 = 1;


#[derive(Debug, Error)]
pub enum MasterKeyError {
    #[error("Key-ring error: {0}")]
    Keyring(#[from] keyring::Error),
    #[error("Hex decoding error: {0}")]
    HexDecode(#[from] FromHexError),
    #[error("Invalid key length in key-ring")]
    InvalidKeyLength,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Malformed salt on disk")]
    BadSalt,
    #[error("Argon2 failure: {0}")]
    Argon2(String),
    #[error("Keystore locked: state store present but key missing")]
    KeystoreLocked,
    #[error("Unable to determine a suitable project directory on this platform")]
    ProjectDirNotFound,
}

// Get the master key from the key-ring or try the passphrase from the environment variable
// If the key is not found, generate a new one and store it in the key-ring
pub fn get_master_key() -> Result<Zeroizing<[u8; KEY_LEN]>, MasterKeyError> {
    
    // 1. Try the OS key-ring first.
    let entry = Entry::new(SERVICE, USER)?;
    if let Ok(hex) = entry.get_password() {
        let bytes: [u8; KEY_LEN] = hex::decode(&hex)?
            .try_into()
            .map_err(|_| MasterKeyError::InvalidKeyLength)?;
        return Ok(Zeroizing::new(bytes));
    }

    // Get project directories once to reuse
    let dirs = project_dirs()?;

    // 2. Fallback to passphrase-derived key via env-var.
    if let Ok(pass) = env::var("NEXUS_CLI_STORE_PASSPHRASE") {
        let salt_path = dirs.config_dir().join("salt.bin");

        // Obtain or generate the application-scoped salt.
        let salt_bytes: [u8; SALT_LEN] = if salt_path.exists() {
            fs::read(&salt_path)?
                .try_into()
                .map_err(|_| MasterKeyError::BadSalt)?
        } else {
            let mut tmp = [0u8; SALT_LEN];
            OsRng.fill_bytes(&mut tmp);
            write_salt_securely(&salt_path, &tmp)?;
            tmp
        };

        // Derive a 256-bit key with Argon2id.
        let params = Params::new(
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
            Some(KEY_LEN),
        )
        .map_err(|e| MasterKeyError::Argon2(e.to_string()))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        argon2
            .hash_password_into(pass.as_bytes(), &salt_bytes, &mut *key)
            .map_err(|e| MasterKeyError::Argon2(e.to_string()))?;
        return Ok(key);
    }

    // 3. No existing key: create a fresh random one, unless the keystore is
    //    already initialised (state file present).
    let state_path = dirs.data_dir().join("state.cbor");
    if state_path.exists() {
        return Err(MasterKeyError::KeystoreLocked);
    }

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(&mut *key);
    entry.set_password(&hex::encode(&*key))?;
    Ok(key)
}

// Helper functions

fn project_dirs() -> Result<ProjectDirs, MasterKeyError> {
    ProjectDirs::from("com", "nexus", "nexus-cli")
        .ok_or(MasterKeyError::ProjectDirNotFound)
}


fn write_salt_securely(path: &PathBuf, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
    }

    #[cfg(not(unix))]
    {
        // Non-Unix: fall back to default perms 
        fs::write(path, bytes)?;
    }

    Ok(())
}


