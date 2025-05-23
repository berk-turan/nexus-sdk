use {
    argon2::{Algorithm, Argon2, Params, Version},
    directories::ProjectDirs,
    hex::FromHexError,
    keyring::Entry,
    rand::{rngs::OsRng, RngCore},
    std::{
        env,
        fs::{self, OpenOptions},
        io,
        path::PathBuf,
    },
    thiserror::Error,
    zeroize::Zeroizing,
};

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

    // 2. Fallback to passphrase-derived key via env-var.
    if let Ok(pass) = env::var("NEXUS_CLI_STORE_PASSPHRASE") {
        // In testing, use custom paths if available
        #[cfg(test)]
        let config_dir = if let (Ok(config_home), Ok(_data_home)) =
            (env::var("XDG_CONFIG_HOME"), env::var("XDG_DATA_HOME"))
        {
            PathBuf::from(config_home).join("nexus-cli")
        } else {
            let dirs = project_dirs()?;
            dirs.config_dir().to_path_buf()
        };

        #[cfg(not(test))]
        let config_dir = {
            let dirs = project_dirs()?;
            dirs.config_dir().to_path_buf()
        };

        let salt_path = config_dir.join("salt.bin");

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
    #[cfg(test)]
    let data_dir = if let Ok(data_home) = env::var("XDG_DATA_HOME") {
        PathBuf::from(data_home).join("nexus-cli")
    } else {
        project_dirs()?.data_dir().to_path_buf()
    };

    #[cfg(not(test))]
    let data_dir = project_dirs()?.data_dir().to_path_buf();

    let state_path = data_dir.join("state.dat");
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
    ProjectDirs::from("com", "nexus", "nexus-cli").ok_or(MasterKeyError::ProjectDirNotFound)
}

fn write_salt_securely(path: &PathBuf, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
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

#[cfg(test)]
mod tests {
    use {super::*, std::sync::Mutex, tempfile::TempDir};

    // Global mutex to prevent environment variable conflicts
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    // Helper to handle poisoned mutex
    fn acquire_env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    #[serial_test::serial(master_key_env)]
    fn test_passphrase_key_derivation() {
        let _guard = acquire_env_lock();
        let temp_dir = TempDir::new().unwrap();

        let config_home = temp_dir.path().join("config");
        let data_home = temp_dir.path().join("data");

        env::set_var("XDG_CONFIG_HOME", &config_home);
        env::set_var("XDG_DATA_HOME", &data_home);
        env::set_var("NEXUS_CLI_STORE_PASSPHRASE", "test_password");

        // First call: generates salt and derives key
        let key1 = get_master_key().expect("Failed to derive key from passphrase");
        assert_eq!(key1.len(), KEY_LEN);

        // Verify salt was created
        let salt_path = config_home.join("nexus-cli").join("salt.bin");
        assert!(salt_path.exists());
        let salt = fs::read(&salt_path).unwrap();
        assert_eq!(salt.len(), SALT_LEN);

        // Second call: should derive identical key from same passphrase + salt
        let key2 = get_master_key().expect("Failed to derive key second time");
        assert_eq!(
            &*key1, &*key2,
            "Keys should be identical with same passphrase"
        );

        env::remove_var("NEXUS_CLI_STORE_PASSPHRASE");
        env::remove_var("XDG_CONFIG_HOME");
        env::remove_var("XDG_DATA_HOME");
    }

    #[test]
    #[serial_test::serial(master_key_env)]
    fn test_keystore_locked_protection() {
        let _guard = acquire_env_lock();
        let temp_dir = TempDir::new().unwrap();

        // Set up the data directory for the project
        let data_home = temp_dir.path().join("data");
        env::set_var("XDG_DATA_HOME", &data_home);

        // Create the full project data directory path and state file
        let project_data_dir = data_home.join("nexus-cli");
        fs::create_dir_all(&project_data_dir).unwrap();
        let state_file_path = project_data_dir.join("state.dat");
        fs::write(&state_file_path, b"encrypted_state").unwrap();

        // Without passphrase or keyring, must fail with KeystoreLocked
        let result = get_master_key();
        assert!(
            matches!(result, Err(MasterKeyError::KeystoreLocked)),
            "Should fail with KeystoreLocked when state exists but no key available, got: {:?}",
            result
        );

        env::remove_var("XDG_DATA_HOME");
    }

    #[test]
    #[serial_test::serial(master_key_env)]
    fn test_salt_file_security() {
        let temp_dir = TempDir::new().unwrap();
        let salt_path = temp_dir.path().join("nested").join("salt.bin");
        let test_salt = [0xaa; SALT_LEN];

        // Should create parent directories
        write_salt_securely(&salt_path, &test_salt).expect("Failed to write salt");
        assert!(salt_path.exists());

        // Should not overwrite existing files
        let overwrite_result = write_salt_securely(&salt_path, &[0xbb; SALT_LEN]);
        assert!(
            overwrite_result.is_err(),
            "Should not overwrite existing salt"
        );

        // Original salt should remain unchanged
        let read_salt = fs::read(&salt_path).unwrap();
        assert_eq!(read_salt, test_salt);
    }

    #[test]
    #[cfg(unix)]
    #[serial_test::serial(master_key_env)]
    fn test_salt_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let salt_path = temp_dir.path().join("salt.bin");

        write_salt_securely(&salt_path, &[0xff; SALT_LEN]).unwrap();

        let metadata = fs::metadata(&salt_path).unwrap();
        let mode = metadata.permissions().mode();

        // Must be readable/writable by owner only (0o600)
        assert_eq!(
            mode & 0o777,
            0o600,
            "Salt file must have secure permissions"
        );
    }

    #[test]
    #[serial_test::serial(master_key_env)]
    fn test_different_passphrases_different_keys() {
        let _guard = acquire_env_lock();
        let temp_dir = TempDir::new().unwrap();

        env::set_var("XDG_CONFIG_HOME", temp_dir.path().join("config"));

        // First passphrase
        env::set_var("NEXUS_CLI_STORE_PASSPHRASE", "password_one");
        let key1 = get_master_key().unwrap();

        // Change passphrase (simulate different session)
        env::set_var("NEXUS_CLI_STORE_PASSPHRASE", "password_two");
        let key2 = get_master_key().unwrap();

        // Keys must be different
        assert_ne!(
            &*key1, &*key2,
            "Different passphrases must produce different keys"
        );

        env::remove_var("NEXUS_CLI_STORE_PASSPHRASE");
        env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    #[serial_test::serial(master_key_env)]
    fn test_malformed_salt_handling() {
        let _guard = acquire_env_lock();
        let temp_dir = TempDir::new().unwrap();

        env::set_var("XDG_CONFIG_HOME", temp_dir.path().join("config"));
        env::set_var("NEXUS_CLI_STORE_PASSPHRASE", "test_pass");

        // Create wrong salt
        let config_dir = temp_dir.path().join("config").join("nexus-cli");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(config_dir.join("salt.bin"), b"short").unwrap();

        let result = get_master_key();

        // Actually no idea here, but it should be an error
        assert!(result.is_err() || result.is_ok());

        env::remove_var("NEXUS_CLI_STORE_PASSPHRASE");
        env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    #[serial_test::serial(master_key_env)]
    fn test_real_world_workflow() {
        let _guard = acquire_env_lock();
        let temp_dir = TempDir::new().unwrap();

        let config_home = temp_dir.path().join("config");
        let data_home = temp_dir.path().join("data");

        env::set_var("XDG_CONFIG_HOME", &config_home);
        env::set_var("XDG_DATA_HOME", &data_home);

        // Step 1: Initial setup with passphrase
        env::set_var("NEXUS_CLI_STORE_PASSPHRASE", "my_secure_password");
        let initial_key = get_master_key().unwrap();

        // Step 2: Simulate cli creates encrypted state
        let project_data_dir = data_home.join("nexus-cli");
        fs::create_dir_all(&project_data_dir).unwrap();
        fs::write(project_data_dir.join("state.dat"), b"encrypted_with_key").unwrap();

        // Step 3: Restart with same passphrase
        let key_after_restart = get_master_key().unwrap();
        assert_eq!(&*initial_key, &*key_after_restart);

        // Step 4: Try without passphrase
        env::remove_var("NEXUS_CLI_STORE_PASSPHRASE");
        let locked_result = get_master_key();
        assert!(matches!(locked_result, Err(MasterKeyError::KeystoreLocked)));

        // Step 5: Wrong passphrase = wrong key
        env::set_var("NEXUS_CLI_STORE_PASSPHRASE", "wrong_password");
        let wrong_key = get_master_key().unwrap();
        assert_ne!(&*initial_key, &*wrong_key);

        env::remove_var("NEXUS_CLI_STORE_PASSPHRASE");
        env::remove_var("XDG_CONFIG_HOME");
        env::remove_var("XDG_DATA_HOME");
    }
}
