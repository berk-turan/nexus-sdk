// Session module for end2end encryption

use {
    super::{
        double_ratchet::RatchetStateHE,
        x3dh::{alice_init, bob_receive, IdentityKey, InitialMessage, PreKeyBundle, X3dhError},
    },
    hkdf::Hkdf,
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    thiserror::Error,
    x25519_dalek::{PublicKey, StaticSecret},
    zeroize::{Zeroize, Zeroizing},
};

/// Protocol version
const PROTOCOL_VERSION: u8 = 1;

/// Domain‑separation salt
const HKDF_SALT: [u8; 32] = *b"X3DH-DR-v1-2025-05-20-----------";

/// Errors that can occur during session setup or messaging.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("X3DH error: {0}")]
    X3DH(#[from] X3dhError),
    #[error("HKDF error")]
    HKDF,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Session state error: {0}")]
    InvalidState(String),
    #[error("Unsupported protocol version {0}")]
    Version(u8),
}

impl From<hkdf::InvalidLength> for SessionError {
    fn from(_: hkdf::InvalidLength) -> Self {
        SessionError::HKDF
    }
}

/// Standard Double‑Ratchet packet ( with header encryption).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardMessage {
    /// Protocol version
    pub version: u8,
    /// Encrypted header produced by `RatchetStateHE`.
    pub header: Vec<u8>,
    /// Cipher‑text payload.
    pub ciphertext: Vec<u8>,
}

/// Message types exchanged over the transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Message {
    /// X3DH initial handshake packet.
    Initial(InitialMessage),
    /// Standard Double‑Ratchet message (version‑tagged).
    Standard(StandardMessage),
}

pub struct Session {
    /// Stable session identifier (32‑byte random‑looking value).
    session_id: [u8; 32],
    /// Double‑Ratchet state (header‑encrypted variant).
    ratchet: RatchetStateHE,
    /// Peer ordering for Associated‑Data construction.
    local_identity: PublicKey,
    remote_identity: PublicKey,
}

impl Session {
    /// Derive the session‑ID from the shared secret only.
    fn calculate_session_id(shared_secret: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"session-id");
        hasher.update(shared_secret);
        hasher.finalize().into()
    }

    /// Construct Associated‑Data as `min(IK_A, IK_B) || max(IK_A, IK_B)`.
    fn make_associated_data(&self) -> Vec<u8> {
        let (first, second) = if self.local_identity.as_bytes() < self.remote_identity.as_bytes() {
            (
                self.local_identity.as_bytes(),
                self.remote_identity.as_bytes(),
            )
        } else {
            (
                self.remote_identity.as_bytes(),
                self.local_identity.as_bytes(),
            )
        };
        let mut ad = Vec::with_capacity(64);
        ad.extend_from_slice(first);
        ad.extend_from_slice(second);
        ad
    }

    /// Alice initiates a new session (X3DH handshake + DR initialisation).
    pub fn initiate(
        identity: &IdentityKey,
        bundle: &PreKeyBundle,
        plaintext: &[u8],
    ) -> Result<(Message, Self), SessionError> {
        // 1. Verify Bob's Signed‑Pre‑Key.  Fails early if data is tampered.
        if !bundle.verify_spk() {
            return Err(SessionError::InvalidState("Invalid SPK signature".into()));
        }

        // 2. X3DH: produce InitialMessage & shared secret SK.
        let (init_msg, sk_raw) = alice_init(identity, bundle, plaintext)?;
        let sk = Zeroizing::new(sk_raw); // zeroised on scope‑exit

        // 3. Derive header‑encryption keys via HKDF
        let hkdf = Hkdf::<Sha256>::new(Some(&HKDF_SALT), &sk[..]);
        let mut hks = [0u8; 32]; // send
        let mut hk_r = [0u8; 32]; // receive
        hkdf.expand(b"header-encrypt-sending", &mut hks)?;
        hkdf.expand(b"header-encrypt-receiving", &mut hk_r)?;

        // 4. Initialise Double‑Ratchet (Alice perspective).
        let mut ratchet = RatchetStateHE::new();
        let _ = ratchet.init_alice_he(&*sk, bundle.spk_pub, hks, hk_r);

        // 5. Compute session‑ID
        let session_id = Self::calculate_session_id(&*sk);

        // 6. Return the initial message and the session.
        Ok((
            Message::Initial(init_msg),
            Session {
                session_id,
                ratchet,
                local_identity: identity.dh_public,
                remote_identity: bundle.identity_pk,
            },
        ))
    }

    /// Bob receives an incoming X3DH handshake.
    pub fn recv(
        identity: &IdentityKey,
        spk_secret: &StaticSecret,
        bundle: &PreKeyBundle,
        msg: &InitialMessage,
    ) -> Result<(Self, Vec<u8>), SessionError> {
        // 1. Verify our own bundle to catch programming errors.
        if !bundle.verify_spk() {
            return Err(SessionError::InvalidState(
                "Local SPK signature invalid".into(),
            ));
        }

        // 2. Complete the X3DH handshake.
        let (plaintext, sk_raw) = bob_receive(identity, spk_secret, bundle.spk_id, None, msg)?;
        let sk = Zeroizing::new(sk_raw);

        // 3. Derive HE keys with domain‑separated HKDF.
        let hkdf = Hkdf::<Sha256>::new(Some(&HKDF_SALT), &sk[..]);
        let mut k_s = [0u8; 32]; // decrypt incoming (Alice→Bob)
        let mut k_r = [0u8; 32]; // encrypt outgoing (Bob→Alice)
        hkdf.expand(b"header-encrypt-sending", &mut k_s)?;
        hkdf.expand(b"header-encrypt-receiving", &mut k_r)?;

        // 4. Initialise DR (Bob perspective).
        let mut ratchet = RatchetStateHE::new();
        let bob_pub = PublicKey::from(spk_secret);
        let _ = ratchet.init_bob_he(&*sk, (spk_secret.clone(), bob_pub), k_s, k_r);

        // 5. Session‑ID.
        let session_id = Self::calculate_session_id(&*sk);

        Ok((
            Session {
                session_id,
                ratchet,
                local_identity: identity.dh_public,
                remote_identity: msg.ika_pub,
            },
            plaintext,
        ))
    }

    /// Stable 32‑byte identifier (suitable for database key as its black)
    pub fn id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Encrypt a message, advancing the ratchet.  Returns `SessionError` on failure.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Message, SessionError> {
        let ad = self.make_associated_data();
        self.ratchet
            .ratchet_encrypt_he(plaintext, &ad)
            .map(|(header, ciphertext)| {
                Message::Standard(StandardMessage {
                    version: PROTOCOL_VERSION,
                    header,
                    ciphertext,
                })
            })
            .map_err(|_| SessionError::InvalidState("Encryption failed".into()))
    }

    /// Decrypt a message, advancing the ratchet as required.
    pub fn decrypt(&mut self, message: &Message) -> Result<Vec<u8>, SessionError> {
        match message {
            Message::Initial(_) => Err(SessionError::InvalidState(
                "Cannot decrypt an initial message with an established session".into(),
            )),
            Message::Standard(StandardMessage {
                version,
                header,
                ciphertext,
            }) => {
                if *version != PROTOCOL_VERSION {
                    return Err(SessionError::Version(*version));
                }
                let ad = self.make_associated_data();
                self.ratchet
                    .ratchet_decrypt_he(header, ciphertext, &ad)
                    .map_err(|_| SessionError::DecryptionFailed)
            }
        }
    }

    /// Encrypt `plaintext` without advancing the sending chain.
    pub fn encrypt_without_advancing(&self, plaintext: &[u8]) -> Option<Message> {
        let ad = self.make_associated_data();
        self.ratchet
            .encrypt_static_he(plaintext, &ad)
            .map(|(header, ciphertext)| {
                Message::Standard(StandardMessage {
                    version: PROTOCOL_VERSION,
                    header,
                    ciphertext,
                })
            })
    }

    /// Decrypt a previously generated static packet.
    /// Useful when the sender is still working on the message, and construct the final message later.
    pub fn decrypt_own_without_advancing(
        &self,
        header: &[u8],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        let ad = self.make_associated_data();
        self.ratchet.decrypt_own_static_he(header, ciphertext, &ad)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.session_id.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use {super::*, rand::rngs::OsRng};

    #[test]
    fn test_x3dh_and_ratchet_roundtrip() {
        let alice_id = IdentityKey::generate();
        let bob_id = IdentityKey::generate();

        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let spk_id = 1;

        // Initialize the bundle for testing
        let bundle = PreKeyBundle::new(&bob_id, spk_id, &spk_secret, None, None);

        let init_payload = b"hello world";
        let (message, mut alice_sess) =
            Session::initiate(&alice_id, &bundle, init_payload).expect("Alice initiate failed");

        // Verify message type
        match &message {
            Message::Initial(_) => {} // Expected
            _ => panic!("Expected Initial message type"),
        }

        let initial_msg = match message {
            Message::Initial(msg) => msg,
            _ => panic!("Expected Initial message type"),
        };

        let (mut bob_sess, plaintext) =
            Session::recv(&bob_id, &spk_secret, &bundle, &initial_msg).expect("Bob respond failed");
        assert_eq!(plaintext, init_payload, "Initial plaintext mismatch");

        // Verify session IDs match
        assert_eq!(alice_sess.id(), bob_sess.id(), "Session IDs should match");

        // test symmetric messaging
        let msg1 = alice_sess.encrypt(b"second").expect("Alice encrypt failed");
        let pt1 = bob_sess.decrypt(&msg1).expect("Bob decrypt failed");
        assert_eq!(&pt1, b"second");

        let msg2 = bob_sess.encrypt(b"reply").expect("Bob encrypt failed");
        let pt2 = alice_sess.decrypt(&msg2).expect("Alice decrypt failed");
        assert_eq!(&pt2, b"reply");
    }

    #[test]
    fn test_decrypt_failure() {
        let alice_id = IdentityKey::generate();
        let bob_id = IdentityKey::generate();
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let bundle = PreKeyBundle::new(&bob_id, 1, &spk_secret, None, None);
        let (message, mut alice_sess) = Session::initiate(&alice_id, &bundle, b"msg").unwrap();

        let initial_msg = match message {
            Message::Initial(msg) => msg,
            _ => panic!("Expected Initial message type"),
        };

        let (mut bob_sess, _) = Session::recv(&bob_id, &spk_secret, &bundle, &initial_msg).unwrap();

        // tamper ciphertext
        let mut msg = alice_sess.encrypt(b"data").expect("Alice encrypt failed");
        if let Message::Standard(ref mut standard_msg) = msg {
            standard_msg.ciphertext[0] ^= 0xff;
        }

        assert!(
            bob_sess.decrypt(&msg).is_err(),
            "Tampered ciphertext should error"
        );
    }

    #[test]
    fn test_out_of_order_messages() {
        let alice_id = IdentityKey::generate();
        let bob_id = IdentityKey::generate();
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let bundle = PreKeyBundle::new(&bob_id, 1, &spk_secret, None, None);

        let (message, mut alice_sess) = Session::initiate(&alice_id, &bundle, b"initial").unwrap();
        let initial_msg = match message {
            Message::Initial(msg) => msg,
            _ => panic!("Expected Initial message type"),
        };

        let (mut bob_sess, _) = Session::recv(&bob_id, &spk_secret, &bundle, &initial_msg).unwrap();

        // Alice sends 3 messages
        let msg1 = alice_sess
            .encrypt(b"message 1")
            .expect("Alice encrypt 1 failed");
        let msg2 = alice_sess
            .encrypt(b"message 2")
            .expect("Alice encrypt 2 failed");
        let msg3 = alice_sess
            .encrypt(b"message 3")
            .expect("Alice encrypt 3 failed");

        // Bob receives them out of order: 2, 3, 1
        let pt2 = bob_sess.decrypt(&msg2).expect("Failed to decrypt msg2");
        assert_eq!(&pt2, b"message 2");

        let pt3 = bob_sess.decrypt(&msg3).expect("Failed to decrypt msg3");
        assert_eq!(&pt3, b"message 3");

        let pt1 = bob_sess.decrypt(&msg1).expect("Failed to decrypt msg1");
        assert_eq!(&pt1, b"message 1");
    }

    #[test]
    fn test_multiple_sessions() {
        // Bob identity and SPK
        let bob_id = IdentityKey::generate();
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let bundle = PreKeyBundle::new(&bob_id, 1, &spk_secret, None, None);

        // Multiple Alices
        let alice_count = 3;
        let mut alice_sessions = Vec::new();
        let mut alice_messages = Vec::new();

        // Each Alice initiates a session with Bob
        for i in 0..alice_count {
            let alice_id = IdentityKey::generate();
            let payload = format!("Hello from Alice {}", i);
            let (message, session) = Session::initiate(&alice_id, &bundle, payload.as_bytes())
                .expect("Alice initiate failed");

            alice_messages.push(message);
            alice_sessions.push(session);
        }

        // Bob handles all initial messages
        let mut bob_sessions = Vec::new();
        for message in &alice_messages {
            if let Message::Initial(msg) = message {
                let (session, _plaintext) =
                    Session::recv(&bob_id, &spk_secret, &bundle, msg).expect("Bob respond failed");
                bob_sessions.push(session);
            }
        }

        // Verify all session IDs match between Alice and Bob pairs
        for i in 0..alice_count {
            assert_eq!(
                alice_sessions[i].id(),
                bob_sessions[i].id(),
                "Session ID mismatch for session {}",
                i
            );

            // Also verify they're different from other sessions
            if i > 0 {
                assert_ne!(
                    alice_sessions[i].id(),
                    alice_sessions[i - 1].id(),
                    "Session IDs should be different between different peers"
                );
            }
        }
    }

    #[test]
    fn test_static_encrypt_decrypt_roundtrip() {
        // 1. bootstrap a normal session
        let alice_id = IdentityKey::generate();
        let bob_id = IdentityKey::generate();
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let bundle = PreKeyBundle::new(&bob_id, 1, &spk_secret, None, None);

        let (init_msg, mut alice_sess) =
            Session::initiate(&alice_id, &bundle, b"handshake").unwrap();

        // Extract the initial message
        let initial_message = match &init_msg {
            Message::Initial(m) => m,
            _ => unreachable!(),
        };

        // Initialize the bob session
        let (mut bob_sess, _) =
            Session::recv(&bob_id, &spk_secret, &bundle, initial_message).unwrap();

        // Do when you want to send that and the message can contain the data we want
        // Send a message in each direction to establish the ratchet
        let setup_msg = alice_sess
            .encrypt(b"setup-message")
            .expect("Alice encrypt failed");
        let _ = bob_sess.decrypt(&setup_msg).expect("Setup decrypt failed");

        let reply_msg = bob_sess
            .encrypt(b"setup-reply")
            .expect("Bob encrypt failed");
        let _ = alice_sess
            .decrypt(&reply_msg)
            .expect("Setup reply decrypt failed");

        // 2. Bob → Alice  (static / peek)
        let msg = bob_sess
            .encrypt_without_advancing(b"peek-hello")
            .expect("static encrypt failed");

        // 3. Alice decrypts WITHOUT advancing her ratchet
        if let Message::Standard(standard_msg) = &msg {
            let ad = alice_sess.make_associated_data();
            let plain = alice_sess
                .ratchet
                .decrypt_static_he(&standard_msg.header, &standard_msg.ciphertext, &ad)
                .expect("Alice static decrypt failed");
            assert_eq!(&plain, b"peek-hello");

            // 4. Bob can still read his own packet
            let own_plain = bob_sess
                .decrypt_own_without_advancing(&standard_msg.header, &standard_msg.ciphertext)
                .expect("Bob self-decrypt failed");
            assert_eq!(own_plain, b"peek-hello");
        } else {
            panic!("Expected StandardMessage");
        }

        // 5. Ensure neither side's counters moved
        let msg2 = bob_sess.encrypt(b"normal-1").expect("Bob encrypt failed");
        let pt2 = alice_sess.decrypt(&msg2).expect("Alice decrypt failed");
        assert_eq!(&pt2, b"normal-1");
    }

    #[test]
    fn test_many_users_random_order_work_in_first_ratchet_message() {
        use {
            super::*,
            rand::{
                rngs::{OsRng, StdRng},
                seq::SliceRandom,
                Rng,
                SeedableRng,
            },
        };

        const N_USERS: usize = 4; // concurrent Alices
        const N_STEPS: usize = 3; // intermediate snapshots per job

        // deterministic RNG → test is repeatable
        let mut rng = StdRng::seed_from_u64(0xdada_beef);

        // ── 1. Bob prepares ONE distinct pre-key bundle (SPK) per Alice
        let bob_id = IdentityKey::generate();
        let mut bob_spk_secrets = Vec::with_capacity(N_USERS);
        let mut bob_bundles = Vec::with_capacity(N_USERS);

        for i in 0..N_USERS {
            let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
            let bundle = PreKeyBundle::new(&bob_id, i as u32 + 1, &spk_secret, None, None);
            bob_spk_secrets.push(spk_secret);
            bob_bundles.push(bundle);
        }

        // ── 2.  Every Alice carries out the X3DH handshake (empty payload)
        let mut alice_sessions = Vec::with_capacity(N_USERS);
        let mut init_msgs = Vec::<(usize, Message)>::with_capacity(N_USERS);

        for (idx, bundle) in bob_bundles.iter().enumerate() {
            let alice_id = IdentityKey::generate();
            let (init_msg, sess) =
                Session::initiate(&alice_id, bundle, b"").expect("initiate failed");
            alice_sessions.push(sess);
            init_msgs.push((idx, init_msg)); // remember which bundle belongs to which Alice
        }

        // deliver the initial messages to Bob in random order
        init_msgs.shuffle(&mut rng);

        // Initialize without requiring Clone
        let mut bob_sessions = Vec::with_capacity(N_USERS);
        for _ in 0..N_USERS {
            bob_sessions.push(None);
        }

        for (idx, init_msg) in init_msgs {
            let (sess, _empty) = Session::recv(
                &bob_id,
                &bob_spk_secrets[idx],
                &bob_bundles[idx],
                match &init_msg {
                    Message::Initial(m) => m,
                    _ => unreachable!(),
                },
            )
            .expect("Bob respond failed");

            bob_sessions[idx] = Some(sess);
        }

        // ── 3.  Each Alice now sends her *work* as the FIRST Double-Ratchet message
        let mut work_packets: Vec<(usize, Vec<u8>, Message)> = Vec::new();

        for (idx, alice_sess) in alice_sessions.iter_mut().enumerate() {
            // produce random work (32–96 bytes)
            let len = rng.gen_range(32..97);
            let mut work = vec![0u8; len];
            rng.fill(&mut work[..]);

            let msg = alice_sess
                .encrypt(&work)
                .expect("Alice encrypt work failed"); // first DR packet
            work_packets.push((idx, work, msg));
        }

        // deliver those work packets to Bob in random order
        work_packets.shuffle(&mut rng);

        for (idx, work, pkt) in &work_packets {
            let bob_sess = bob_sessions[*idx].as_mut().unwrap();
            let pt = bob_sess.decrypt(pkt).expect("Bob decrypt work failed");
            assert_eq!(pt, *work, "work mismatch for user {idx}");
        }

        // ── 4.  Bob has sending-chain keys now → create N_STEPS snapshots per job
        {
            let mut snapshots: Vec<(usize, Vec<u8>, Message)> = Vec::new();

            for (idx, sess) in bob_sessions.iter_mut().enumerate() {
                let s = sess.as_mut().unwrap();
                for _ in 0..N_STEPS {
                    let mut data = vec![0u8; 24];
                    rng.fill(&mut data[..]);
                    let pkt = s
                        .encrypt_without_advancing(&data)
                        .expect("Bob encrypt snapshot failed");
                    snapshots.push((idx, data, pkt));
                }
            }
            // Bob later decrypts them in *another* random order
            snapshots.shuffle(&mut rng);

            for (idx, data, pkt) in &snapshots {
                let s = bob_sessions[*idx].as_mut().unwrap();
                if let Message::Standard(standard_msg) = pkt {
                    let out = s
                        .decrypt_own_without_advancing(
                            &standard_msg.header,
                            &standard_msg.ciphertext,
                        )
                        .expect("snapshot self-decrypt");
                    assert_eq!(out, *data, "snapshot mismatch for user {idx}");
                }
            }
        }

        // ── 5.  Bob sends a final reply to every Alice (again shuffled)
        let mut finals: Vec<(usize, Vec<u8>, Message)> = Vec::new();
        for (idx, sess) in bob_sessions.iter_mut().enumerate() {
            let s = sess.as_mut().unwrap();
            let mut ans = vec![0u8; 16];
            rng.fill(&mut ans[..]);
            let msg = s.encrypt(&ans).expect("Bob encrypt final failed");
            finals.push((idx, ans, msg));
        }
        finals.shuffle(&mut rng);

        for (idx, ans, pkt) in finals {
            let pt = alice_sessions[idx]
                .decrypt(&pkt)
                .expect("Alice decrypt final failed");
            assert_eq!(pt, ans, "final answer mismatch for user {idx}");
        }
    }

    #[test]
    fn test_many_users_random_order_all_static_intermediates() {
        use {
            super::*,
            rand::{
                rngs::{OsRng, StdRng},
                seq::SliceRandom,
                Rng,
                SeedableRng,
            },
        };

        const N_USERS: usize = 4; // concurrent users and one leader
        const N_STATIC: usize = 4; // size of the DAG(just for testing can be anything)

        // deterministic RNG → repeatable test
        let mut rng = StdRng::seed_from_u64(0xface_feed);

        // 1.  Leader publishes one SPK bundle per user
        let leader_id = IdentityKey::generate();
        let mut leader_spk_secrets = Vec::with_capacity(N_USERS); // can be the same SPK for all users
        let mut leader_bundles = Vec::with_capacity(N_USERS);
        for i in 0..N_USERS {
            let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
            let bundle = PreKeyBundle::new(&leader_id, i as u32 + 1, &spk_secret, None, None);
            leader_spk_secrets.push(spk_secret);
            leader_bundles.push(bundle); // publish the bundle somewhere so users can read it
        }

        // 2.  Each user performs X3DH at first interaction
        let mut user_sessions = Vec::with_capacity(N_USERS);
        let mut init_msgs = Vec::<(usize, Message)>::with_capacity(N_USERS);

        // leader can be offline and doesnt have to respond and you can send the first work here, you dont need to say hi
        for (idx, bundle) in leader_bundles.iter().enumerate() {
            let user_id = IdentityKey::generate();
            let (init_msg, sess) =
                Session::initiate(&user_id, bundle, b"hi leader, its good to meet you")
                    .expect("initiate"); // its nice to say hi
            user_sessions.push(sess);
            init_msgs.push((idx, init_msg)); // publish messages so leader can read them from somewhere, or send them to the leader directly
        }
        init_msgs.shuffle(&mut rng); // shuffle the messages to randomize the order, make it harder for the leader

        // Leader creates sessions , at first unknown users
        let mut leader_sessions: Vec<Option<Session>> = (0..N_USERS).map(|_| None).collect();
        for (idx, init_msg) in init_msgs {
            let (sess, _) = Session::recv(
                &leader_id,
                &leader_spk_secrets[idx],
                &leader_bundles[idx],
                match &init_msg {
                    Message::Initial(m) => m,
                    _ => unreachable!(),
                }, // leader doesnt actually respond this is local to the leader
            )
            .expect("respond");
            leader_sessions[idx] = Some(sess);
        }

        // 3.  User send work(encypted data)
        let mut work_pkts: Vec<(usize, Vec<u8>, Message)> = Vec::new();
        for (idx, user_sess) in user_sessions.iter_mut().enumerate() {
            let len = rng.gen_range(24..65);
            let mut work = vec![0u8; len];
            rng.fill(&mut work[..]); // do that
            let pkt = user_sess.encrypt(&work).expect("user encrypt work failed"); // ns = 0
            work_pkts.push((idx, work, pkt)); // publish somewhere
        }
        work_pkts.shuffle(&mut rng); // shuffle the work to randomize the order

        for (idx, work, pkt) in &work_pkts {
            let leader_sess = leader_sessions[*idx].as_mut().unwrap(); // get the right session
            let out = leader_sess
                .decrypt(pkt)
                .expect("leader decrypt work failed"); // start the work
            assert_eq!(out, *work, "work mismatch user {idx}");
        }

        // 4.  Leader does something and publishes new data, it uses static snapshots
        // static snapshots means that the leader sends encrypted data to the user but leaves temporal ability to understand the data
        let mut static_pkts: Vec<(usize, Vec<u8>, Message)> = Vec::new();
        for (idx, leader_sess) in leader_sessions.iter_mut().enumerate() {
            let s = leader_sess.as_mut().unwrap();
            for _ in 0..N_STATIC {
                // run along the DAG
                let mut data = vec![0u8; 24];
                rng.fill(&mut data[..]); // leader does the work
                let pkt = s
                    .encrypt_without_advancing(&data)
                    .expect("leader encrypt snapshot failed"); // leader pushes the data somewhere, but keeps temporal ability to understand the data
                static_pkts.push((idx, data, pkt));
            }
        }
        static_pkts.shuffle(&mut rng); // shuffle the work to randomize the order

        for (idx, data, pkt) in &static_pkts {
            let s = leader_sessions[*idx].as_mut().unwrap();
            // read from on-chain or somewhere else, the encrypted data and decryption happens one ofter another here just for testing
            if let Message::Standard(standard_msg) = pkt {
                let out = s
                    .decrypt_own_without_advancing(&standard_msg.header, &standard_msg.ciphertext)
                    .expect("snapshot self-decrypt"); // leader takes the data from somewhere that it encrypted previously and decrypts to do the next work in the instance
                assert_eq!(out, *data, "static snap mismatch user {idx}");
            }
        }

        // 5.  Leader sends a final result that DOES advance the ratchet(leader loses the ability to understand all the work it did) forward secrecy
        let mut finals: Vec<(usize, Vec<u8>, Message)> = Vec::new();
        for (idx, leader_sess) in leader_sessions.iter_mut().enumerate() {
            let s = leader_sess.as_mut().unwrap();
            let mut ans = vec![0u8; 12];
            rng.fill(&mut ans[..]);
            let pkt = s.encrypt(&ans).expect("leader encrypt final failed"); // normal advancing send
            finals.push((idx, ans, pkt));
        }
        finals.shuffle(&mut rng);

        for (idx, ans, pkt) in finals {
            let out = user_sessions[idx]
                .decrypt(&pkt)
                .expect("user decrypt final failed"); // user decrypt all the data the leader sent(even that in the edges and that intermidiate data), after reding advances the chain
            assert_eq!(out, ans, "final mismatch user {idx}");
        }
    }
}
