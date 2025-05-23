use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use std::path::Path;
use std::fs::{self, OpenOptions, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::io::{Write, self};
use rand::rngs::OsRng;
use thiserror::Error;
use super::{
    x3dh::IdentityKey,
    session::Session,
    double_ratchet::RatchetStateHE,
    secret_bytes::SecretBytes,
};
use x25519_dalek::{PublicKey, StaticSecret};
use aes_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes128SivAead,
    Nonce,
};
use rand::RngCore;

const STORE_VERSION: u8 = 1;     
const NONCE_LEN: usize = 16;     

#[derive(Debug, Error)]
pub enum StateStoreError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_cbor::Error),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Store file corrupt or too large")]
    CorruptStore,
    #[error("Unsupported store version: {0}")]
    UnsupportedVersion(u8),
}

impl From<aes_siv::Error> for StateStoreError {
    fn from(e: aes_siv::Error) -> Self {
        StateStoreError::Encryption(e.to_string())
    }
}

fn fresh_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    let _ = OsRng.try_fill_bytes(&mut n);
    n
}

// IdentityKey is stored in the state store
#[derive(Serialize, Deserialize)]
struct StoredIdentityKey { 
    /// The secret key of the identity key
    secret: SecretBytes 
}

impl From<&IdentityKey> for StoredIdentityKey {
    fn from(id: &IdentityKey) -> Self { Self { secret: id.secret().into() } }
}
impl TryFrom<StoredIdentityKey> for IdentityKey {
    type Error = StateStoreError;
    fn try_from(stored: StoredIdentityKey) -> Result<Self, Self::Error> {
        let secret: StaticSecret = stored.secret.into();
        Ok(IdentityKey::from_secret(secret))
    }
}

// Session is stored in the state store
#[derive(Serialize, Deserialize)]
struct StoredSession {
    /// The ratchet state of the session
    ratchet: RatchetStateHE,
    /// The remote identity of the session
    remote_identity: [u8; 32],
}

impl StoredSession {
    fn from_session(s: &Session) -> Result<Self, StateStoreError> {
        // Probably there is a better idea, dont want to give clone the ratchet state, that may be dangerous
        // TODO: find a better way to do this
        let serialized = serde_cbor::to_vec(s.ratchet())?;
        let ratchet: RatchetStateHE = serde_cbor::from_slice(&serialized)?;
        
        Ok(Self {
            ratchet,
            remote_identity: *s.remote_identity().as_bytes(),
        })
    }

    fn into_runtime(self, local_id: PublicKey) -> Session {
        Session::from_storage(
            Session::calculate_session_id(self.ratchet.root_key()),
            self.ratchet,
            local_id,
            PublicKey::from(self.remote_identity),
        )
    }
}

// The top-level store
#[derive(Serialize, Deserialize)]
pub struct StateStore {
    /// The identity key of the user
    identity: StoredIdentityKey,
    /// The sessions of the user
    /// One user can have multiple sessions, each session is identified by the session id
    sessions: HashMap<[u8; 32], StoredSession>,
}

impl StateStore {
    pub fn new(id: &IdentityKey) -> Self {
        Self { identity: id.into(), sessions: HashMap::new() }
    }

    pub fn insert_session(&mut self, s: &Session) {
        if let Ok(stored) = StoredSession::from_session(s) {
            self.sessions.insert(*s.id(), stored);
        }
    }

    pub fn to_runtime(self) -> Result<(IdentityKey, HashMap<[u8; 32], Session>), StateStoreError> {
        let id: IdentityKey = self.identity.try_into()?;
        let mut map = HashMap::with_capacity(self.sessions.len());
        for (sid, stored) in self.sessions {
            map.insert(sid, stored.into_runtime(id.dh_public));
        }
        Ok((id, map))
    }
}

/// Thin wrappers around the existing helper functions
pub fn save_store<P: AsRef<Path>>(path: P,
    master_key: &[u8; 32],
    store: &StateStore) -> Result<(), StateStoreError> {
    save_state(path, master_key, store)
}

pub fn load_store<P: AsRef<Path>>(path: P,
    master_key: &[u8; 32])
    -> Result<Option<StateStore>, StateStoreError> {
    load_state(path, master_key)
}

fn save_state<P: AsRef<Path>, T: Serialize>(
    path: P,
    key: &[u8; 32],
    state: &T,
) -> Result<(), StateStoreError> {
    let serialized = serde_cbor::to_vec(state)?;

    // 1. fresh nonce
    let nonce_bytes = fresh_nonce();
    let cipher = Aes128SivAead::new_from_slice(key)
        .map_err(|e| StateStoreError::Encryption(e.to_string()))?;
    let nonce  = Nonce::from_slice(&nonce_bytes);
    let mut ciphertext = cipher.encrypt(nonce, Payload { msg: &serialized, aad: &[] })?;

    // 2. prepend store-version | nonce
    let mut disk_blob = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    disk_blob.push(STORE_VERSION);
    disk_blob.extend_from_slice(&nonce_bytes);
    disk_blob.append(&mut ciphertext);

    // 3. Replace the file with the new one
    let path = path.as_ref();
    let dir  = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp  = dir.join(format!(".{}.tmp", path.file_name().unwrap().to_string_lossy()));

    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp)?;
    fs::set_permissions(&tmp, Permissions::from_mode(0o600))?;
    f.write_all(&disk_blob)?;
    f.sync_all()?;             
    std::fs::rename(&tmp, path)?;       
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

fn load_state<P: AsRef<Path>, T: for<'de> Deserialize<'de>>(
    path: P,
    key: &[u8; 32],
) -> Result<Option<T>, StateStoreError> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(None);
    }
    
    // 
    const MAX_STORE: usize = 10 * 1024 * 1024;
    let blob = fs::read(path)?;
    if blob.len() < 1 + NONCE_LEN || blob.len() > MAX_STORE {
        return Err(StateStoreError::CorruptStore);
    }
    
    // 1. format header
    let version = blob[0];
    if version != STORE_VERSION {
        return Err(StateStoreError::UnsupportedVersion(version));
    }
    let nonce_bytes = &blob[1..1 + NONCE_LEN];
    let ciphertext  = &blob[1 + NONCE_LEN..];

    // 2. decrypt
    let cipher = Aes128SivAead::new_from_slice(key)
        .map_err(|e| StateStoreError::Encryption(e.to_string()))?;
    let plaintext = cipher.decrypt(Nonce::from_slice(nonce_bytes), Payload { msg: ciphertext, aad: &[] })
        .map_err(|e| StateStoreError::Decryption(e.to_string()))?;

    let state: T = serde_cbor::from_slice(&plaintext)?;
    Ok(Some(state))
}