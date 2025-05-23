use {
    super::{
        double_ratchet::RatchetStateHE,
        secret_bytes::SecretBytes,
        session::Session,
        x3dh::IdentityKey,
    },
    aes_siv::{
        aead::{Aead, KeyInit, Payload},
        Aes128SivAead,
        Nonce,
    },
    rand::{rngs::OsRng, RngCore},
    serde::{Deserialize, Serialize},
    std::{
        collections::HashMap,
        fs::{self, OpenOptions, Permissions},
        io::{self, Write},
        os::unix::fs::PermissionsExt,
        path::Path,
    },
    thiserror::Error,
    x25519_dalek::{PublicKey, StaticSecret},
};

const STORE_VERSION: u8 = 1;
const NONCE_LEN: usize = 16;

#[derive(Debug, Error)]
pub enum StateStoreError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] ciborium::ser::Error<io::Error>),
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] ciborium::de::Error<io::Error>),
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
    secret: SecretBytes,
}

impl From<&IdentityKey> for StoredIdentityKey {
    fn from(id: &IdentityKey) -> Self {
        Self {
            secret: id.secret().into(),
        }
    }
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
        let mut serialized = Vec::new();
        ciborium::into_writer(s.ratchet(), &mut serialized)?;
        let ratchet: RatchetStateHE = ciborium::from_reader(serialized.as_slice())?;

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
        Self {
            identity: id.into(),
            sessions: HashMap::new(),
        }
    }

    pub fn insert_session(&mut self, s: &Session) -> Result<(), StateStoreError> {
        let stored = StoredSession::from_session(s)?;
        self.sessions.insert(*s.id(), stored);
        Ok(())
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
pub fn save_store<P: AsRef<Path>>(
    path: P,
    master_key: &[u8; 32],
    store: &StateStore,
) -> Result<(), StateStoreError> {
    save_state(path, master_key, store)
}

pub fn load_store<P: AsRef<Path>>(
    path: P,
    master_key: &[u8; 32],
) -> Result<Option<StateStore>, StateStoreError> {
    load_state(path, master_key)
}

fn save_state<P: AsRef<Path>, T: Serialize>(
    path: P,
    key: &[u8; 32],
    state: &T,
) -> Result<(), StateStoreError> {
    let mut serialized = Vec::new();
    ciborium::into_writer(state, &mut serialized)?;

    // 1. fresh nonce
    let nonce_bytes = fresh_nonce();
    let cipher = Aes128SivAead::new_from_slice(key)
        .map_err(|e| StateStoreError::Encryption(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut ciphertext = cipher.encrypt(
        nonce,
        Payload {
            msg: &serialized,
            aad: &[],
        },
    )?;

    // 2. prepend store-version | nonce
    let mut disk_blob = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    disk_blob.push(STORE_VERSION);
    disk_blob.extend_from_slice(&nonce_bytes);
    disk_blob.append(&mut ciphertext);

    // 3. Replace the file with the new one
    let path = path.as_ref();
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name().unwrap().to_string_lossy()
    ));

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
    let ciphertext = &blob[1 + NONCE_LEN..];

    // 2. decrypt
    let cipher = Aes128SivAead::new_from_slice(key)
        .map_err(|e| StateStoreError::Encryption(e.to_string()))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .map_err(|e| StateStoreError::Decryption(e.to_string()))?;

    let state: T = ciborium::from_reader(plaintext.as_slice())?;
    Ok(Some(state))
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::crypto::{session::Message, x3dh::PreKeyBundle},
        rand::rngs::OsRng,
        tempfile::TempDir,
        x25519_dalek::StaticSecret,
    };

    #[test]
    fn test_complete_session_persistence() {
        // Setup test directory and master key
        let temp_dir = TempDir::new().unwrap();
        let alice_store_path = temp_dir.path().join("alice_store.dat");
        let bob_store_path = temp_dir.path().join("bob_store.dat");
        let master_key = [42u8; 32];

        println!("Setting up Alice and Bob with initial session");

        // Create identities
        let alice_id = IdentityKey::generate();
        let bob_id = IdentityKey::generate();

        // Bob's prekey bundle
        let bob_spk_secret = StaticSecret::random_from_rng(OsRng);
        let spk_id = 1;
        let bundle = PreKeyBundle::new(&bob_id, spk_id, &bob_spk_secret, None, None);

        // Alice initiates session
        let initial_message =
            b"Hello, this is from the President of the United States(totally not a joke)";
        let (first_packet, mut alice_session) =
            Session::initiate(&alice_id, &bundle, initial_message).unwrap();

        // Bob receives and establishes session
        let (mut bob_session, received_initial) = Session::recv(
            &bob_id,
            &bob_spk_secret,
            &bundle,
            match &first_packet {
                Message::Initial(m) => m,
                _ => panic!("Expected initial message"),
            },
        )
        .unwrap();
        assert_eq!(received_initial, initial_message);

        println!("Exchanging messages before first save");

        // Alice sends the first post-handshake message
        let alice_msg1 = b"Hey, its me";
        let encrypted_alice1 = alice_session.encrypt(alice_msg1).unwrap();
        let decrypted_alice1 = bob_session.decrypt(&encrypted_alice1).unwrap();
        assert_eq!(decrypted_alice1, alice_msg1);

        // Bob responds
        let bob_msg1 = b"Hey, whats up?";
        let encrypted_bob1 = bob_session.encrypt(bob_msg1).unwrap();
        let decrypted_bob1 = alice_session.decrypt(&encrypted_bob1).unwrap();
        assert_eq!(decrypted_bob1, bob_msg1);

        println!("Saving session states");

        // Save Alice's state
        let mut alice_store = StateStore::new(&alice_id);
        alice_store.insert_session(&alice_session).unwrap();
        save_store(&alice_store_path, &master_key, &alice_store).unwrap();

        // Save Bob's state
        let mut bob_store = StateStore::new(&bob_id);
        bob_store.insert_session(&bob_session).unwrap();
        save_store(&bob_store_path, &master_key, &bob_store).unwrap();

        // Clear sessions from memory to simulate restart
        drop(alice_session);
        drop(bob_session);
        drop(alice_store);
        drop(bob_store);

        println!("Loading sessions and continuing conversation");

        // Load Alice's state
        let alice_loaded_store = load_store(&alice_store_path, &master_key)
            .unwrap()
            .expect("Alice's store should exist");
        let (alice_loaded_id, alice_sessions) = alice_loaded_store.to_runtime().unwrap();
        assert_eq!(
            alice_loaded_id.dh_public.as_bytes(),
            alice_id.dh_public.as_bytes()
        );

        // Load Bob's state
        let bob_loaded_store = load_store(&bob_store_path, &master_key)
            .unwrap()
            .expect("Bob's store should exist");
        let (bob_loaded_id, bob_sessions) = bob_loaded_store.to_runtime().unwrap();
        assert_eq!(
            bob_loaded_id.dh_public.as_bytes(),
            bob_id.dh_public.as_bytes()
        );

        // Get the sessions (there should be exactly one for each)
        assert_eq!(alice_sessions.len(), 1);
        assert_eq!(bob_sessions.len(), 1);

        let mut alice_session = alice_sessions.into_iter().next().unwrap().1;
        let mut bob_session = bob_sessions.into_iter().next().unwrap().1;

        println!("Verifying sessions work after load");

        // Bob sends a message with the loaded session
        let bob_msg_after_load = b"Just loaded my session from disk. I think it works";
        let encrypted_bob_after = bob_session.encrypt(bob_msg_after_load).unwrap();
        let decrypted_bob_after = alice_session.decrypt(&encrypted_bob_after).unwrap();
        assert_eq!(decrypted_bob_after, bob_msg_after_load);

        // Alice responds
        let alice_msg_after_load = b"Me too, this is totally working";
        let encrypted_alice_after = alice_session.encrypt(alice_msg_after_load).unwrap();
        let decrypted_alice_after = bob_session.decrypt(&encrypted_alice_after).unwrap();
        assert_eq!(decrypted_alice_after, alice_msg_after_load);

        println!("Testing multiple save/load cycles");

        for i in 0..3 {
            println!("  Cycle {}", i + 1);

            // Exchange messages
            let msg_from_alice = format!("Message {} from Alice", i).into_bytes();
            let encrypted = alice_session.encrypt(&msg_from_alice).unwrap();
            let decrypted = bob_session.decrypt(&encrypted).unwrap();
            assert_eq!(decrypted, msg_from_alice);

            let msg_from_bob = format!("Message {} from Bob", i).into_bytes();
            let encrypted = bob_session.encrypt(&msg_from_bob).unwrap();
            let decrypted = alice_session.decrypt(&encrypted).unwrap();
            assert_eq!(decrypted, msg_from_bob);

            // Save both sessions
            let mut alice_store = StateStore::new(&alice_id);
            alice_store.insert_session(&alice_session).unwrap();
            save_store(&alice_store_path, &master_key, &alice_store).unwrap();

            let mut bob_store = StateStore::new(&bob_id);
            bob_store.insert_session(&bob_session).unwrap();
            save_store(&bob_store_path, &master_key, &bob_store).unwrap();

            // Load both sessions
            let alice_loaded = load_store(&alice_store_path, &master_key).unwrap().unwrap();
            let (_, alice_sessions) = alice_loaded.to_runtime().unwrap();
            alice_session = alice_sessions.into_iter().next().unwrap().1;

            let bob_loaded = load_store(&bob_store_path, &master_key).unwrap().unwrap();
            let (_, bob_sessions) = bob_loaded.to_runtime().unwrap();
            bob_session = bob_sessions.into_iter().next().unwrap().1;
        }

        println!("Verifying double ratchet continues to work");

        // Send multiple messages in a row from Alice (tests sending chain)
        for i in 0..5 {
            let msg = format!("Rapid message {} from Alice", i).into_bytes();
            let encrypted = alice_session.encrypt(&msg).unwrap();
            let decrypted = bob_session.decrypt(&encrypted).unwrap();
            assert_eq!(decrypted, msg);
        }

        // Send multiple messages in a row from Bob (tests receiving chain)
        for i in 0..5 {
            let msg = format!("Rapid message {} from Bob", i).into_bytes();
            let encrypted = bob_session.encrypt(&msg).unwrap();
            let decrypted = alice_session.decrypt(&encrypted).unwrap();
            assert_eq!(decrypted, msg);
        }

        println!("Final verification");

        // One more save/load cycle
        let mut alice_store = StateStore::new(&alice_id);
        alice_store.insert_session(&alice_session).unwrap();
        save_store(&alice_store_path, &master_key, &alice_store).unwrap();

        let mut bob_store = StateStore::new(&bob_id);
        bob_store.insert_session(&bob_session).unwrap();
        save_store(&bob_store_path, &master_key, &bob_store).unwrap();

        // Load and send final messages
        let alice_final_store = load_store(&alice_store_path, &master_key).unwrap().unwrap();
        let (_, alice_sessions) = alice_final_store.to_runtime().unwrap();
        let mut alice_session_final = alice_sessions.into_iter().next().unwrap().1;

        let bob_final_store = load_store(&bob_store_path, &master_key).unwrap().unwrap();
        let (_, bob_sessions) = bob_final_store.to_runtime().unwrap();
        let mut bob_session_final = bob_sessions.into_iter().next().unwrap().1;

        // Final message exchange
        let final_msg = b"This is totally working";
        let encrypted_final = alice_session_final.encrypt(final_msg).unwrap();
        let decrypted_final = bob_session_final.decrypt(&encrypted_final).unwrap();
        assert_eq!(decrypted_final, final_msg);

        println!("Nice");
    }
}
