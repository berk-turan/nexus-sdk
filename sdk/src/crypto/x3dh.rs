//! Extended Triple Diffie-Hellman (X3DH) Implementation
//!
//! Follows the specs from https://signal.org/docs/specifications/x3dh/#the-x3dh-protocol
// The variable names are taken from the specs

#![forbid(unsafe_code)]

use subtle::ConstantTimeEq; // Constant‑time comparison
use {
    aead::{Aead, KeyInit, Payload},
    chacha20poly1305::{XChaCha20Poly1305, XNonce},
    hkdf::Hkdf,
    rand::rngs::OsRng,
    rand_core::RngCore,
    serde::{Deserialize, Serialize},
    sha2::Sha256,
    thiserror::Error,
    x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret},
    xeddsa::{
        xed25519::{PrivateKey as XEdPrivate, PublicKey as XEdPublic},
        Sign,
        Verify,
    },
    zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing},
};

/// Curve identifier for `Encode(PK)`, taken from `signal.org/docs/specifications/x3dh/#the-x3dh-protocol` 2.5
const CURVE_ID_X25519: u8 = 0x05;
/// Maximum ciphertext length accepted in a pre‑key message (16 KiB)
const MAX_PREKEY_MSG: usize = 16 * 1024;
/// Default HKDF --info-- label (can be overridden at call‑site)
const HKDF_INFO: &[u8] = b"X3DH";

/// Shared secret that automatically zeroises its bytes on drop
pub type SharedSecret = Zeroizing<[u8; 32]>;

// Error types
#[derive(Debug, Error)]
pub enum X3dhError {
    #[error("signature verification failed")]
    SigVerifyFailed,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("OTPK secret missing – refuse to process one‑time pre‑key message")]
    MissingOneTimeSecret,
    #[error("signed pre‑key id mismatch")]
    SpkIdMismatch,
    #[error("one‑time pre‑key id mismatch")]
    OtpkIdMismatch,
    #[error("identity DH and Ed keys do not match")]
    IdentityKeyMismatch,
    #[error("HKDF output length is wrong")]
    HkdfInvalidLength,
    #[error("AEAD error")]
    Aead,
    #[error("ciphertext too large")]
    CiphertextTooLarge,
}

impl From<hkdf::InvalidLength> for X3dhError {
    fn from(_: hkdf::InvalidLength) -> Self {
        Self::HkdfInvalidLength
    }
}

// Helper utilities

/// Extension trait for `XEdPublic` – convenient byte conversion
trait XEdPublicExt {
    fn as_bytes(&self) -> &[u8; 32];
    fn from_bytes(bytes: [u8; 32]) -> Self;
}

impl XEdPublicExt for XEdPublic {
    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_bytes(bytes: [u8; 32]) -> Self {
        XEdPublic(bytes)
    }
}

/// Encode a Curve25519 public key as `curve_id || u_coordinate` (33 bytes), from the specs
fn encode_pk(pk: &X25519PublicKey) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = CURVE_ID_X25519;
    out[1..].copy_from_slice(pk.as_bytes());
    out
}

/// HKDF wrapper with domain‑separator (0xFF×32) – returns a `SharedSecret`
fn kdf(dhs: &[&[u8]], info: &[u8]) -> Result<SharedSecret, X3dhError> {
    let mut ikm = Vec::with_capacity(32 + 32 * dhs.len());
    ikm.extend([0xffu8; 32]);
    for dh in dhs {
        ikm.extend_from_slice(dh);
    }

    // 32‑byte zero salt, from the specs
    let salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)?;

    ikm.zeroize();
    Ok(Zeroizing::new(okm))
}

// Identity keys (DH + XEdDSA for signing)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentityKey {
    secret: StaticSecret, // The secret key
    #[zeroize(skip)]
    pub dh_public: X25519PublicKey, // The public key for Diffie-Hellman
    signing: XEdPrivate,  // The private key for signing
    #[zeroize(skip)]
    pub verify: XEdPublic, // The public key for verification
}

impl IdentityKey {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(&mut OsRng); // The secret key
        let dh_public = X25519PublicKey::from(&secret); // The public key for Diffie-Hellman
                                                        // Conveniently, XEdDSA keys use the same DH public key for signing and verification
        let signing = XEdPrivate::from(&secret); // The private key for signing
        let verify = XEdPublic::from(&dh_public); // The public key for verification
        Self {
            secret,
            dh_public,
            signing,
            verify,
        }
    }
}

// Bob's published pre‑key bundle
pub struct PreKeyBundle {
    pub spk_id: u32,                       // The id of the signed pre-key
    pub spk_pub: X25519PublicKey,          // The public key of the signed pre-key
    pub spk_sig: [u8; 64],                 // The signature of the signed pre-key
    pub identity_verify_bytes: [u8; 32],   // The verification bytes of the identity key
    pub identity_pk: X25519PublicKey,      // The public key of the identity key
    pub otpk_id: Option<u32>, /* The id of the one-time pre-key, used to identify the one-time pre-key */
    pub otpk_pub: Option<X25519PublicKey>, // The public key of the one-time pre-key
}

impl PreKeyBundle {
    /// Build a bundle from Bob's identity key plus freshly generated SPK/OTPK.
    pub fn new(
        identity: &IdentityKey,
        spk_id: u32,
        spk_secret: &StaticSecret,
        otpk_id: Option<u32>,
        otpk_secret: Option<&StaticSecret>,
    ) -> Self {
        // The public key of the signed pre-key
        let spk_pub = X25519PublicKey::from(spk_secret);
        // Sign Encode(SPK) with XEdDSA, from the specs
        let spk_sig = identity.signing.sign(&encode_pk(&spk_pub), &mut OsRng);

        // The verification bytes of the identity key
        let identity_verify_bytes = *identity.verify.as_bytes();

        Self {
            spk_id,
            spk_pub,
            spk_sig,
            identity_verify_bytes,
            identity_pk: identity.dh_public,
            otpk_id,
            otpk_pub: otpk_secret.map(X25519PublicKey::from), /* The public key of the one-time pre-key */
        }
    }

    /// Verify the SPK signature
    pub fn verify_spk(&self) -> bool {
        let spk_bytes = encode_pk(&self.spk_pub);
        let identity_verify = self.get_identity_verify();

        // Ensure DH‑to‑Ed mapping is intact
        let expected_verify = XEdPublic::from(&self.identity_pk);
        if identity_verify
            .as_bytes()
            .ct_eq(expected_verify.as_bytes())
            .unwrap_u8()
            == 0
        {
            return false;
        }

        // Verify signature
        identity_verify.verify(&spk_bytes, &self.spk_sig).is_ok()
    }

    fn get_identity_verify(&self) -> XEdPublic {
        XEdPublic::from_bytes(self.identity_verify_bytes)
    }
}

// Serde helper for X25519 public keys
pub mod x25519_serde {
    use {
        super::X25519PublicKey,
        serde::{
            de::{Error, Visitor},
            Deserializer,
            Serializer,
        },
        std::fmt,
    };

    pub fn serialize<S>(key: &X25519PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(key.as_bytes())
    }

    struct PublicKeyVisitor;

    impl Visitor<'_> for PublicKeyVisitor {
        type Value = X25519PublicKey;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a 32‑byte X25519 public key")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: Error,
        {
            if v.len() != 32 {
                return Err(E::custom(format!("expected 32 bytes, got {}", v.len())));
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(v);
            Ok(X25519PublicKey::from(bytes))
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<X25519PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PublicKeyVisitor)
    }
}

// Initial pre‑key message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitialMessage {
    // Header (unencrypted)
    #[serde(with = "x25519_serde")]
    pub ika_pub: X25519PublicKey, // The public key of the identity key (the DH public key)
    #[serde(with = "x25519_serde")]
    pub ek_pub: X25519PublicKey, // The public key of the ephemeral key (the DH public key)
    pub spk_id: u32,          // The id of the signed pre-key
    pub otpk_id: Option<u32>, // The id of the one-time pre-key
    pub nonce: [u8; 24],      // A random nonce
    // Ciphertext
    pub ciphertext: Vec<u8>, // The encrypted message
}

// Alice side
pub fn alice_init(
    alice: &IdentityKey,
    bundle: &PreKeyBundle,
    plaintext: &[u8],
) -> Result<(InitialMessage, SharedSecret), X3dhError> {
    // 1. Verify SPK signature and identity binding
    let spk_bytes = encode_pk(&bundle.spk_pub);
    let identity_verify = bundle.get_identity_verify();

    // Ensure DH‑to‑Ed mapping is intact
    let expected_verify = XEdPublic::from(&bundle.identity_pk);
    if identity_verify
        .as_bytes()
        .ct_eq(expected_verify.as_bytes())
        .unwrap_u8()
        == 0
    {
        return Err(X3dhError::IdentityKeyMismatch);
    }

    identity_verify
        .verify(&spk_bytes, &bundle.spk_sig)
        .map_err(|_| X3dhError::SigVerifyFailed)?;

    // 2. Ephemeral key pair
    let ek_secret = StaticSecret::random_from_rng(&mut OsRng);
    let ek_pub = X25519PublicKey::from(&ek_secret);

    // 3. DH computations
    let mut dh1 = alice.secret.diffie_hellman(&bundle.spk_pub).to_bytes();
    let mut dh2 = ek_secret.diffie_hellman(&bundle.identity_pk).to_bytes();
    let mut dh3 = ek_secret.diffie_hellman(&bundle.spk_pub).to_bytes();
    let mut dh4_opt = bundle
        .otpk_pub
        .as_ref()
        .map(|otpk| ek_secret.diffie_hellman(otpk).to_bytes());

    let mut dh_slices: Vec<&[u8]> = vec![dh1.as_slice(), dh2.as_slice(), dh3.as_slice()];
    if let Some(ref d4) = dh4_opt {
        dh_slices.push(d4.as_slice());
    }
    let sk = kdf(&dh_slices, HKDF_INFO)?; // Derive the shared secret

    dh1.zeroize(); // Zeroise the DH values
    dh2.zeroize(); // Zeroise the DH values
    dh3.zeroize(); // Zeroise the DH values
    if let Some(ref mut d4) = dh4_opt {
        d4.zeroize();
    } // Zeroise the DH values

    // 4. Associated data
    let mut ad = Vec::with_capacity(66);
    ad.extend_from_slice(&encode_pk(&alice.dh_public));
    ad.extend_from_slice(&encode_pk(&bundle.identity_pk));

    // 5. Encrypt
    let cipher = XChaCha20Poly1305::new((&*sk).into());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &ad,
            },
        )
        .map_err(|_| X3dhError::Aead)?;

    let message = InitialMessage {
        ika_pub: alice.dh_public,
        ek_pub,
        spk_id: bundle.spk_id,
        otpk_id: bundle.otpk_id,
        nonce,
        ciphertext,
    };

    // 6. Return the message and the shared secret (zeroises on drop)
    Ok((message, sk)) // The shared secret can be used for post-X3DH encryption
}

// Bob side
pub fn bob_receive(
    bob_id: &IdentityKey,
    spk_secret: &StaticSecret,
    spk_id: u32,
    otpk_secret: Option<(&StaticSecret, u32)>,
    msg: &InitialMessage,
) -> Result<(Vec<u8>, SharedSecret), X3dhError> {
    // 0. Check SPK id
    if msg
        .spk_id
        .to_be_bytes()
        .ct_eq(&spk_id.to_be_bytes())
        .unwrap_u8()
        == 0
    {
        return Err(X3dhError::SpkIdMismatch);
    }

    // 1. OTPK book‑keeping / checks
    match (msg.otpk_id, otpk_secret) {
        (None, None) => {}                                              // No OTPKs
        (Some(_), None) => return Err(X3dhError::MissingOneTimeSecret), // Missing OTPK secret
        (Some(msg_id), Some((_, stored_id)))
            if msg_id
                .to_be_bytes()
                .ct_eq(&stored_id.to_be_bytes())
                .unwrap_u8()
                == 0 =>
        {
            return Err(X3dhError::OtpkIdMismatch); // OTPK id mismatch
        }
        _ => {} // Should never happen
    }

    // 2. Compute DH values, do the same as Alice
    let mut dh1 = spk_secret.diffie_hellman(&msg.ika_pub).to_bytes();
    let mut dh2 = bob_id.secret.diffie_hellman(&msg.ek_pub).to_bytes();
    let mut dh3 = spk_secret.diffie_hellman(&msg.ek_pub).to_bytes();
    let mut dh4_opt = otpk_secret.map(|(sk, _)| sk.diffie_hellman(&msg.ek_pub).to_bytes());

    let mut dh_slices: Vec<&[u8]> = vec![dh1.as_slice(), dh2.as_slice(), dh3.as_slice()];
    if let Some(ref d4) = dh4_opt {
        dh_slices.push(d4.as_slice());
    }
    let sk = kdf(&dh_slices, HKDF_INFO)?; // Derive the shared secret

    dh1.zeroize(); // Zeroise the DH values
    dh2.zeroize(); // Zeroise the DH values
    dh3.zeroize(); // Zeroise the DH values
    if let Some(ref mut d4) = dh4_opt {
        d4.zeroize();
    } // Zeroise the DH values

    // 3. Associated data, do the same as Alice
    let mut ad = Vec::with_capacity(66);
    ad.extend_from_slice(&encode_pk(&msg.ika_pub));
    ad.extend_from_slice(&encode_pk(&bob_id.dh_public));

    // 4. Defensive length check
    if msg.ciphertext.len() > MAX_PREKEY_MSG {
        return Err(X3dhError::CiphertextTooLarge);
    }

    // 5. Decrypt
    let cipher = XChaCha20Poly1305::new((&*sk).into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&msg.nonce),
            Payload {
                msg: &msg.ciphertext,
                aad: &ad,
            },
        )
        .map_err(|_| X3dhError::DecryptFailed)?;

    // 6. Return the plaintext and the shared secret (zeroises on drop)
    Ok((plaintext, sk)) // The shared secret can be used for post-X3DH encryption, it is the same as the one used by Alice
}

// Helpers for Bob to generate pre‑key material

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PreKeyBundleWithSecrets {
    #[zeroize(skip)]
    pub bundle: PreKeyBundle,
    spk_secret: StaticSecret,
    otpk_secrets: Vec<(u32, StaticSecret)>,
}

pub fn bob_generate_prekey_bundle(
    identity: &IdentityKey,
    spk_id: u32,
    next_otpk_id: &mut u32,
    n_otpks: usize,
) -> PreKeyBundleWithSecrets {
    let spk_secret = StaticSecret::random_from_rng(&mut OsRng);

    // Generate OTPKs
    let mut otpk_secrets = Vec::with_capacity(n_otpks);
    for _ in 0..n_otpks {
        let id = *next_otpk_id;
        *next_otpk_id = next_otpk_id.wrapping_add(1);
        let sk = StaticSecret::random_from_rng(&mut OsRng);
        otpk_secrets.push((id, sk));
    }

    let (first_otpk_id, first_otpk_secret) = otpk_secrets
        .first()
        .map(|(id, sk)| (Some(*id), Some(sk)))
        .unwrap_or((None, None));

    let bundle = PreKeyBundle::new(
        identity,
        spk_id,
        &spk_secret,
        first_otpk_id,
        first_otpk_secret,
    );

    PreKeyBundleWithSecrets {
        bundle,
        spk_secret,
        otpk_secrets,
    }
}

pub fn bob_generate_many_prekey_bundles(
    identity: &IdentityKey,
    count: usize,
    next_spk_id: &mut u32,
    next_otpk_id: &mut u32,
    otpks_per_bundle: usize,
) -> Vec<PreKeyBundleWithSecrets> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let bundle =
            bob_generate_prekey_bundle(identity, *next_spk_id, next_otpk_id, otpks_per_bundle);
        *next_spk_id = next_spk_id.wrapping_add(1);
        out.push(bundle);
    }
    out
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_no_otpk() {
        let alice = IdentityKey::generate();
        let bob = IdentityKey::generate();

        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let spk_id = 1u32;

        let bundle = PreKeyBundle::new(&bob, spk_id, &spk_secret, None, None);

        let plaintext = b"hi Bob!";
        let (msg, _) = alice_init(&alice, &bundle, plaintext).unwrap();
        let (out, _) = bob_receive(&bob, &spk_secret, spk_id, None, &msg).unwrap();
        assert_eq!(plaintext, &out[..]);
    }

    #[test]
    fn fails_without_otpk_secret() {
        let alice = IdentityKey::generate();
        let bob = IdentityKey::generate();

        // Bob SPK
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let spk_id = 7;

        // Bob OTPK
        let otpk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let otpk_id = 99;

        // Create bundle with OTPK
        let bundle =
            PreKeyBundle::new(&bob, spk_id, &spk_secret, Some(otpk_id), Some(&otpk_secret));

        let msg = alice_init(&alice, &bundle, b"test").unwrap();
        // Bob forgot to pass OTPK secret – should error
        assert!(matches!(
            bob_receive(&bob, &spk_secret, spk_id, None, &msg.0),
            Err(X3dhError::MissingOneTimeSecret)
        ));
    }

    #[test]
    fn roundtrip_with_otpk() {
        let alice = IdentityKey::generate();
        let bob = IdentityKey::generate();

        // Bob creates pre-keys
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let spk_id = 42u32;
        let otpk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let otpk_id = 123u32;

        // Create bundle with OTPK
        let bundle =
            PreKeyBundle::new(&bob, spk_id, &spk_secret, Some(otpk_id), Some(&otpk_secret));

        let plaintext = b"Secret message with one-time key";
        let msg = alice_init(&alice, &bundle, plaintext).unwrap();

        // Bob processes with the correct OTPK
        let out = bob_receive(
            &bob,
            &spk_secret,
            spk_id,
            Some((&otpk_secret, otpk_id)),
            &msg.0,
        )
        .unwrap();

        assert_eq!(plaintext, &out.0[..]);
    }

    #[test]
    fn bundle_can_be_stored() {
        // Demonstrate that bundles can be stored in a collection
        let bob = IdentityKey::generate();

        // Create multiple bundles
        let mut bundles = Vec::new();

        for i in 0..5 {
            let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
            let bundle = PreKeyBundle::new(&bob, i as u32, &spk_secret, None, None);

            bundles.push((bundle, spk_secret));
        }

        // Demonstrate we can retrieve and use a bundle
        let (bundle, spk_secret) = &bundles[2];
        let alice = IdentityKey::generate();
        let plaintext = b"Message for stored bundle";

        let msg = alice_init(&alice, bundle, plaintext).unwrap();
        let out = bob_receive(&bob, spk_secret, 2, None, &msg.0).unwrap();
        assert_eq!(plaintext, &out.0[..]);
    }

    #[test]
    fn test_signature_verification_failure() {
        let alice = IdentityKey::generate();
        let bob = IdentityKey::generate();
        let eve = IdentityKey::generate();

        // Bob creates SPK
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let spk_id = 1u32;

        // Create legitimate bundle
        let mut bundle = PreKeyBundle::new(&bob, spk_id, &spk_secret, None, None);

        // Tamper with signature - replace with Eve's signature
        let eve_sig = eve.signing.sign(&encode_pk(&bundle.spk_pub), &mut OsRng);
        bundle.spk_sig = eve_sig;

        // Alice should reject the tampered bundle
        let result = alice_init(&alice, &bundle, b"test message");
        assert!(matches!(result, Err(X3dhError::SigVerifyFailed)));
    }

    #[test]
    fn test_decryption_with_wrong_keys() {
        let alice = IdentityKey::generate();
        let bob = IdentityKey::generate();
        let mallory = IdentityKey::generate(); // Attacker

        // Bob's SPK
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let spk_id = 5u32;

        // Create bundle
        let bundle = PreKeyBundle::new(&bob, spk_id, &spk_secret, None, None);

        let plaintext = b"secret message";
        let msg = alice_init(&alice, &bundle, plaintext).unwrap();

        // Mallory attempts to decrypt with wrong identity key
        let result = bob_receive(&mallory, &spk_secret, spk_id, None, &msg.0);
        assert!(matches!(result, Err(X3dhError::DecryptFailed)));

        // Bob attempts to decrypt with wrong SPK
        let wrong_spk = StaticSecret::random_from_rng(&mut OsRng);
        let result = bob_receive(&bob, &wrong_spk, spk_id, None, &msg.0);
        assert!(matches!(result, Err(X3dhError::DecryptFailed)));
    }

    #[test]
    fn test_tampered_ciphertext() {
        let alice = IdentityKey::generate();
        let bob = IdentityKey::generate();

        // Bob SPK
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let spk_id = 3u32;

        // Create bundle
        let bundle = PreKeyBundle::new(&bob, spk_id, &spk_secret, None, None);

        let plaintext = b"authentic message";
        let mut msg = alice_init(&alice, &bundle, plaintext).unwrap();

        // Try to tamper with the ciphertext
        if !msg.0.ciphertext.is_empty() {
            msg.0.ciphertext[0] ^= 0x01; // Flip a bit
        }

        // Bob should detect tampering
        let result = bob_receive(&bob, &spk_secret, spk_id, None, &msg.0);
        assert!(matches!(result, Err(X3dhError::DecryptFailed)));
    }

    #[test]
    fn test_empty_message() {
        let alice = IdentityKey::generate();
        let bob = IdentityKey::generate();

        // Bob SPK
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let spk_id = 9u32;

        // Create bundle
        let bundle = PreKeyBundle::new(&bob, spk_id, &spk_secret, None, None);

        // Empty message should work fine
        let plaintext = b"";
        let msg = alice_init(&alice, &bundle, plaintext).unwrap();
        let out = bob_receive(&bob, &spk_secret, spk_id, None, &msg.0).unwrap();
        assert_eq!(plaintext, &out.0[..]);
    }

    #[test]
    fn test_large_message() {
        let alice = IdentityKey::generate();
        let bob = IdentityKey::generate();

        // Bob SPK
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let spk_id = 10u32;

        // Create bundle
        let bundle = PreKeyBundle::new(&bob, spk_id, &spk_secret, None, None);

        // Create a large message (8KB)
        let plaintext = vec![0xaa; 8 * 1024]; // I agree with everything said in the message
        let msg = alice_init(&alice, &bundle, &plaintext).unwrap();
        let out = bob_receive(&bob, &spk_secret, spk_id, None, &msg.0).unwrap();
        assert_eq!(plaintext, out.0);
    }

    #[test]
    fn test_binary_data() {
        let alice = IdentityKey::generate();
        let bob = IdentityKey::generate();

        // Bob SPK
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let spk_id = 11u32;

        // Create bundle
        let bundle = PreKeyBundle::new(&bob, spk_id, &spk_secret, None, None);

        // Binary data with all possible byte values
        let mut plaintext = Vec::with_capacity(256);
        for i in 0..=255u8 {
            plaintext.push(i);
        }

        let msg = alice_init(&alice, &bundle, &plaintext).unwrap();
        let out = bob_receive(&bob, &spk_secret, spk_id, None, &msg.0).unwrap();
        assert_eq!(plaintext, out.0);
    }

    #[test]
    fn test_multiple_otpks() {
        let alice = IdentityKey::generate();
        let bob = IdentityKey::generate();

        // Bob creates pre-keys
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let spk_id = 12u32;

        // Create multiple OTPKs
        let otpk_secrets: Vec<(StaticSecret, u32)> = (0..5)
            .map(|i| (StaticSecret::random_from_rng(&mut OsRng), 200 + i))
            .collect();

        // Test each OTPK separately
        for (idx, (otpk_secret, otpk_id)) in otpk_secrets.iter().enumerate() {
            // Create bundle with this OTPK
            let bundle =
                PreKeyBundle::new(&bob, spk_id, &spk_secret, Some(*otpk_id), Some(otpk_secret));

            let plaintext = format!("Message using OTPK #{}", idx).into_bytes();
            let msg = alice_init(&alice, &bundle, &plaintext).unwrap();

            // Bob processes with the correct OTPK
            let out = bob_receive(
                &bob,
                &spk_secret,
                spk_id,
                Some((otpk_secret, *otpk_id)),
                &msg.0,
            )
            .unwrap();

            assert_eq!(plaintext, out.0);
        }
    }

    #[test]
    fn test_different_identity_keys_produce_different_outputs() {
        // Generate two different identity keys for Alice
        let alice1 = IdentityKey::generate();
        let alice2 = IdentityKey::generate();
        let bob = IdentityKey::generate();

        // Bob SPK
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let spk_id = 13u32;

        // Create bundle
        let bundle = PreKeyBundle::new(&bob, spk_id, &spk_secret, None, None);

        let plaintext = b"Same message";

        // Encrypt with different identity keys
        let msg1 = alice_init(&alice1, &bundle, plaintext).unwrap();
        let msg2 = alice_init(&alice2, &bundle, plaintext).unwrap();

        // Ciphertexts should be different even with same plaintext
        assert_ne!(msg1.0.ciphertext, msg2.0.ciphertext);

        // Both should decrypt properly
        let out1 = bob_receive(&bob, &spk_secret, spk_id, None, &msg1.0).unwrap();
        let out2 = bob_receive(&bob, &spk_secret, spk_id, None, &msg2.0).unwrap();

        assert_eq!(plaintext, &out1.0[..]);
        assert_eq!(plaintext, &out2.0[..]);
    }

    #[test]
    fn test_different_nonce_produces_different_ciphertext() {
        let alice = IdentityKey::generate();
        let bob = IdentityKey::generate();

        // Bob SPK
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let spk_id = 14u32;

        // Create bundle
        let bundle = PreKeyBundle::new(&bob, spk_id, &spk_secret, None, None);

        let plaintext = b"test message";

        // Create two messages - they should have different nonces automatically
        let msg1 = alice_init(&alice, &bundle, plaintext).unwrap();
        let msg2 = alice_init(&alice, &bundle, plaintext).unwrap();

        // Nonces should be different
        assert_ne!(msg1.0.nonce, msg2.0.nonce);

        // Ciphertexts should be different even with same plaintext due to different nonces
        assert_ne!(msg1.0.ciphertext, msg2.0.ciphertext);
    }
}
