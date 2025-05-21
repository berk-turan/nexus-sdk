// Double Ratchet implementation in Rust
// https://signal.org/docs/specifications/doubleratchet/#security-considerations

use {
    aes_siv::{
        aead::{Aead, KeyInit, Payload},
        Aes128SivAead,
        Nonce,
    },
    hkdf::Hkdf,
    hmac::{Hmac, Mac},
    rand::{rngs::OsRng, RngCore},
    serde::{Deserialize, Deserializer, Serialize, Serializer},
    serde_cbor,
    sha2::Sha256,
    std::collections::HashMap,
    subtle::ConstantTimeEq,
    thiserror::Error,
    x25519_dalek::{PublicKey, StaticSecret},
    zeroize::Zeroize,
};

const MAX_SKIP_PER_CHAIN: usize = 1_000;
const MAX_SKIP_GLOBAL: usize = 2 * MAX_SKIP_PER_CHAIN;

// Each AES‑SIV nonce is 128‑bit. We use an 8‑byte random prefix + 8‑byte counter.
const NONCE_LEN: usize = 16;

// Type aliases

type HkdfSha256 = Hkdf<Sha256>;
type HmacSha256 = Hmac<Sha256>;

// Errors
#[derive(Debug, Error)]
pub enum RatchetError {
    #[error("missing sending chain")]
    MissingSendingChain,
    #[error("missing receiving chain")]
    MissingReceivingChain,
    #[error("missing header key")]
    MissingHeaderKey,
    #[error("crypto error")]
    CryptoError,
    #[error("header parse error")]
    HeaderParse,
    #[error("max skip exceeded")]
    MaxSkipExceeded,
    #[error("invalid public key")]
    InvalidPublicKey,
}

impl From<aes_siv::aead::Error> for RatchetError {
    fn from(_: aes_siv::aead::Error) -> Self {
        RatchetError::CryptoError
    }
}

// Nonce sequence generator (16‑byte)
#[derive(Clone)]
struct NonceSeq {
    prefix: [u8; 8],
    counter: u64, // big‑endian in output
}

impl NonceSeq {
    fn new() -> Self {
        let mut prefix = [0u8; 8];
        OsRng.fill_bytes(&mut prefix);
        Self { prefix, counter: 0 }
    }

    /// Return next unique 16‑byte nonce (prefix || counter_be).
    fn next(&mut self) -> [u8; NONCE_LEN] {
        let mut out = [0u8; NONCE_LEN];
        out[..8].copy_from_slice(&self.prefix);
        out[8..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);
        out
    }
}

// Manually implement Zeroize for NonceSeq
impl Zeroize for NonceSeq {
    fn zeroize(&mut self) {
        self.prefix.zeroize();
        self.counter = 0;
    }
}

// Header object
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Header {
    pub dh: PublicKey, // public key of the sender
    pub pn: u32,       // previous chain length
    pub n: u32,        // the message number in the current chain
}

impl Serialize for Header {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (self.dh.as_bytes(), self.pn, self.n).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Header {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (pk_bytes, pn, n): ([u8; 32], u32, u32) = Deserialize::deserialize(deserializer)?;
        Ok(Header {
            dh: PublicKey::from(pk_bytes),
            pn,
            n,
        })
    }
}

// Ratchet state with header encryption
pub struct RatchetStateHE {
    // DH ratchet keys
    dhs: StaticSecret,      // own private
    dhs_pub: PublicKey,     // own public
    dhr: Option<PublicKey>, // remote public key
    // Root/Chain/Header keys
    rk: [u8; 32],          // root key
    cks: Option<[u8; 32]>, // chain key for sending
    ckr: Option<[u8; 32]>, // chain key for receiving
    hks: Option<[u8; 32]>, // header key for sending
    hkr: Option<[u8; 32]>, // header key for receiving
    nhks: [u8; 32],        // next header key for sending
    nhkr: [u8; 32],        // next header key for receiving
    // Counters
    ns: u32, // message number in the sending chain
    nr: u32, // message number in the receiving chain
    pn: u32, // previous chain length
    // Skipped (header_key || n)  ->  msg_key
    mkskipped: HashMap<([u8; 32], u32), [u8; 32]>,
    // Nonce sequences
    nonce_seq_msg: NonceSeq,    // nonce sequence for message encryption
    nonce_seq_header: NonceSeq, // nonce sequence for header encryption
}

// Manually implement Zeroize for RatchetStateHE
impl Zeroize for RatchetStateHE {
    fn zeroize(&mut self) {
        // StaticSecret already implements Zeroize
        // PublicKey doesn't contain sensitive material
        self.rk.zeroize();
        if let Some(ref mut k) = self.cks {
            k.zeroize();
        }
        if let Some(ref mut k) = self.ckr {
            k.zeroize();
        }
        if let Some(ref mut k) = self.hks {
            k.zeroize();
        }
        if let Some(ref mut k) = self.hkr {
            k.zeroize();
        }
        self.nhks.zeroize();
        self.nhkr.zeroize();
        self.mkskipped.clear();
        self.nonce_seq_msg.zeroize();
        self.nonce_seq_header.zeroize();
    }
}

// Implement Drop for RatchetStateHE to zeroize on drop
impl Drop for RatchetStateHE {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Helper functions
impl RatchetStateHE {
    /// Generate new X25519 keypair.
    fn generate_dh() -> (StaticSecret, PublicKey) {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = PublicKey::from(&sk);
        (sk, pk)
    }

    /// Validate remote public key (reject small‑order / identity).
    fn validate_pk(pk: &PublicKey) -> Result<(), RatchetError> {
        // Reject identity (all‑zero) & blacklist of known small‑order points
        const SMALL_ORDER: [[u8; 32]; 1] = [[0u8; 32]]; // can be extended if needed
        for bad in SMALL_ORDER.iter() {
            if pk.as_bytes().ct_eq(bad).unwrap_u8() == 1 {
                return Err(RatchetError::InvalidPublicKey);
            }
        }
        Ok(())
    }

    #[inline]
    fn dh(sk: &StaticSecret, pk: &PublicKey) -> [u8; 32] {
        sk.diffie_hellman(pk).to_bytes()
    }

    // KDF‑RK‑HE: domain‑separated label "DR‑RootHE"
    fn kdf_rk_he(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let hk = HkdfSha256::new(Some(rk), dh_out);
        let mut okm = [0u8; 96];
        hk.expand(b"DR-RootHE", &mut okm).expect("hkdf expand");
        let mut new_rk = [0u8; 32];
        new_rk.copy_from_slice(&okm[..32]);
        let mut ck = [0u8; 32];
        ck.copy_from_slice(&okm[32..64]);
        let mut nhk = [0u8; 32];
        nhk.copy_from_slice(&okm[64..]);
        (new_rk, ck, nhk)
    }

    // KDF‑CK with byte labels 0x01 / 0x02 , from the specs
    fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let mut mac1 = <HmacSha256 as Mac>::new_from_slice(ck).expect("hmac");
        mac1.update(&[0x01]);
        let mut new_ck = [0u8; 32];
        new_ck.copy_from_slice(&mac1.finalize().into_bytes());

        let mut mac2 = <HmacSha256 as Mac>::new_from_slice(ck).expect("hmac");
        mac2.update(&[0x02]);
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&mac2.finalize().into_bytes());
        (new_ck, mk)
    }

    // Header encryption (AES‑SIV)
    fn hencrypt(&mut self, hk: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, RatchetError> {
        let cipher = Aes128SivAead::new_from_slice(hk).map_err(|_| RatchetError::CryptoError)?;
        let nonce_bytes = self.nonce_seq_header.next();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut ct = cipher.encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )?;
        let mut out = nonce_bytes.to_vec();
        out.append(&mut ct);
        Ok(out)
    }

    // Header decryption (AES‑SIV)
    fn hdecrypt(hk: &[u8; 32], data: &[u8]) -> Result<Header, RatchetError> {
        if data.len() < NONCE_LEN {
            return Err(RatchetError::HeaderParse);
        }
        let (nonce_bytes, ct) = data.split_at(NONCE_LEN);
        let cipher = Aes128SivAead::new_from_slice(hk).map_err(|_| RatchetError::CryptoError)?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let pt = cipher.decrypt(nonce, Payload { msg: ct, aad: &[] })?;
        serde_cbor::from_slice(&pt).map_err(|_| RatchetError::HeaderParse)
    }

    // Constructors
    pub fn new() -> Self {
        let (dhs_sk, dhs_pk) = Self::generate_dh();
        Self {
            dhs: dhs_sk,
            dhs_pub: dhs_pk,
            dhr: None,
            rk: [0u8; 32],
            cks: None,
            ckr: None,
            hks: None,
            hkr: None,
            nhks: [0u8; 32],
            nhkr: [0u8; 32],
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
            nonce_seq_msg: NonceSeq::new(),
            nonce_seq_header: NonceSeq::new(),
        }
    }

    // Init (Alice)
    pub fn init_alice_he(
        &mut self,
        sk: &[u8; 32],
        bob_pub: PublicKey,
        shared_hka: [u8; 32],
        shared_nhkb: [u8; 32],
    ) -> Result<(), RatchetError> {
        Self::validate_pk(&bob_pub)?;
        let (dhs_sk, dhs_pk) = Self::generate_dh();
        let dh_out = Self::dh(&dhs_sk, &bob_pub);
        let (new_rk, ck_s, nhk_s) = Self::kdf_rk_he(sk, &dh_out);

        self.dhs = dhs_sk;
        self.dhs_pub = dhs_pk;
        self.dhr = Some(bob_pub);
        self.rk = new_rk;
        self.cks = Some(ck_s);
        self.ckr = None;
        self.ns = 0;
        self.nr = 0;
        self.pn = 0;
        self.mkskipped.clear();
        self.hks = Some(shared_hka);
        self.hkr = None;
        self.nhks = nhk_s;
        self.nhkr = shared_nhkb;
        self.nonce_seq_msg = NonceSeq::new();
        self.nonce_seq_header = NonceSeq::new();
        Ok(())
    }

    // Init (Bob)
    pub fn init_bob_he(
        &mut self,
        sk: &[u8; 32],
        bob_kp: (StaticSecret, PublicKey),
        shared_hka: [u8; 32],
        shared_nhkb: [u8; 32],
    ) -> Result<(), RatchetError> {
        let (dhs_sk, dhs_pk) = bob_kp;
        self.dhs = dhs_sk;
        self.dhs_pub = dhs_pk;
        self.dhr = None;
        self.rk = *sk;
        self.cks = None;
        self.ckr = None;
        self.ns = 0;
        self.nr = 0;
        self.pn = 0;
        self.mkskipped.clear();
        self.hks = None;
        self.hkr = None;
        self.nhks = shared_nhkb;
        self.nhkr = shared_hka;
        self.nonce_seq_msg = NonceSeq::new();
        self.nonce_seq_header = NonceSeq::new();
        Ok(())
    }

    // Send with header encryption
    pub fn ratchet_encrypt_he(
        &mut self,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), RatchetError> {
        let cks = self.cks.ok_or(RatchetError::MissingSendingChain)?;
        let (new_cks, mk) = Self::kdf_ck(&cks);
        self.cks = Some(new_cks);

        // build & encrypt header
        let header = Header {
            dh: self.dhs_pub,
            pn: self.pn,
            n: self.ns,
        };
        let header_bytes = serde_cbor::to_vec(&header).expect("cbor");

        let hk = self.hks.clone().ok_or(RatchetError::MissingHeaderKey)?;
        let enc_header = self.hencrypt(&hk, &header_bytes)?;

        // payload encryption (AAD = AD || enc_header)
        let mut full_ad = ad.to_vec();
        full_ad.extend_from_slice(&enc_header);

        let cipher = Aes128SivAead::new_from_slice(&mk).map_err(|_| RatchetError::CryptoError)?;
        let nonce_bytes = self.nonce_seq_msg.next();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut ct = cipher.encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &full_ad,
            },
        )?;
        let mut payload = nonce_bytes.to_vec();
        payload.append(&mut ct);

        self.ns = self.ns.wrapping_add(1);
        Ok((enc_header, payload))
    }

    // Receive with header encryption
    pub fn ratchet_decrypt_he(
        &mut self,
        enc_header: &[u8],
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        if let Some(pt) = self.try_skipped_keys(enc_header, ciphertext, ad)? {
            return Ok(pt);
        }

        let (header, did_dh_ratchet) = self.decrypt_header(enc_header)?;
        if did_dh_ratchet {
            self.skip_message_keys_he(header.pn)?;
            self.dh_ratchet_he(&header)?;
        }
        self.skip_message_keys_he(header.n)?;

        let ckr = self.ckr.ok_or(RatchetError::MissingReceivingChain)?;
        let (new_ckr, mk) = Self::kdf_ck(&ckr);
        self.ckr = Some(new_ckr);
        self.nr = self.nr.wrapping_add(1);

        if ciphertext.len() < NONCE_LEN {
            return Err(RatchetError::CryptoError);
        }
        let (nonce_bytes, ct) = ciphertext.split_at(NONCE_LEN);
        let cipher = Aes128SivAead::new_from_slice(&mk).map_err(|_| RatchetError::CryptoError)?;
        let nonce = Nonce::from_slice(nonce_bytes);

        let mut full_ad = ad.to_vec();
        full_ad.extend_from_slice(enc_header);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ct,
                    aad: &full_ad,
                },
            )
            .map_err(Into::into)
    }

    // try to decrypt a skipped message
    fn try_skipped_keys(
        &mut self,
        enc_header: &[u8],
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Option<Vec<u8>>, RatchetError> {
        for ((hk_bytes, idx), mk) in &self.mkskipped {
            if ciphertext.len() < NONCE_LEN {
                continue;
            }

            // constant‑time compare header key before attempting decryption
            if hk_bytes.ct_eq(&self.nhkr).unwrap_u8() == 0
                && hk_bytes.ct_eq(&self.hkr.unwrap_or([0u8; 32])).unwrap_u8() == 0
            {
                continue;
            }

            if let Ok(hdr) = Self::hdecrypt(hk_bytes, enc_header) {
                if hdr.n == *idx {
                    let (nonce_bytes, ct) = ciphertext.split_at(NONCE_LEN);
                    let cipher =
                        Aes128SivAead::new_from_slice(mk).map_err(|_| RatchetError::CryptoError)?;
                    let nonce = Nonce::from_slice(nonce_bytes);
                    let mut full_ad = ad.to_vec();
                    full_ad.extend_from_slice(enc_header);
                    if let Ok(pt) = cipher.decrypt(
                        nonce,
                        Payload {
                            msg: ct,
                            aad: &full_ad,
                        },
                    ) {
                        self.mkskipped.remove(&(*hk_bytes, *idx));
                        return Ok(Some(pt));
                    }
                }
            }
        }
        Ok(None)
    }

    // Decrypt header
    fn decrypt_header(&self, enc_header: &[u8]) -> Result<(Header, bool), RatchetError> {
        if let Some(hk) = &self.hkr {
            if let Ok(hdr) = Self::hdecrypt(hk, enc_header) {
                return Ok((hdr, false));
            }
        }
        let hdr = Self::hdecrypt(&self.nhkr, enc_header)?;
        Ok((hdr, true))
    }

    // Skip message keys with header encryption
    fn skip_message_keys_he(&mut self, until: u32) -> Result<(), RatchetError> {
        if self.nr + (MAX_SKIP_PER_CHAIN as u32) < until {
            return Err(RatchetError::MaxSkipExceeded);
        }
        if let Some(mut ck_r) = self.ckr {
            while self.nr < until {
                let (new_ck, mk) = Self::kdf_ck(&ck_r);
                ck_r = new_ck;
                if let Some(hkr) = &self.hkr {
                    self.mkskipped.insert((*hkr, self.nr), mk);
                    if self.mkskipped.len() > MAX_SKIP_GLOBAL {
                        return Err(RatchetError::MaxSkipExceeded); // error instead of flush
                    }
                }
                self.nr = self.nr.wrapping_add(1);
            }
            self.ckr = Some(ck_r);
        }
        Ok(())
    }

    // DH ratchet with header encryption
    fn dh_ratchet_he(&mut self, header: &Header) -> Result<(), RatchetError> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;

        self.hks = Some(self.nhks.clone());
        self.hkr = Some(self.nhkr.clone());

        // store new remote DH
        Self::validate_pk(&header.dh)?;
        self.dhr = Some(header.dh);

        // Step 1: derive receiving chain
        let dh_out1 = Self::dh(&self.dhs, &header.dh);
        let (new_rk, ck_r, nhk_r) = Self::kdf_rk_he(&self.rk, &dh_out1);
        self.rk = new_rk;
        self.ckr = Some(ck_r);
        self.nhkr = nhk_r;

        // Step 2: generate new sending keys & chain
        let (dhs_sk, dhs_pk) = Self::generate_dh();
        self.dhs = dhs_sk;
        self.dhs_pub = dhs_pk;

        let dh_out2 = Self::dh(&self.dhs, &header.dh);
        let (new_rk2, ck_s2, nhk_s2) = Self::kdf_rk_he(&self.rk, &dh_out2);
        self.rk = new_rk2;
        self.cks = Some(ck_s2);
        self.nhks = nhk_s2;

        self.nonce_seq_msg = NonceSeq::new();
        self.nonce_seq_header = NonceSeq::new();
        Ok(())
    }

    // Convenience: compute Message Key from Chain Key
    fn mk_from_ck(ck: &[u8; 32]) -> [u8; 32] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(ck).unwrap();
        mac.update(&[0x02]);
        let tag = mac.finalize().into_bytes();
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&tag);
        mk
    }

    // Convenient: function for encryption that allows the sender to work on the message intermittently
    // Encrypt static HE
    pub fn encrypt_static_he(&self, plaintext: &[u8], ad: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        let ck_s = self.cks.as_ref()?;
        let hk_s = self.hks.as_ref()?;
        let mk = Self::mk_from_ck(ck_s);

        let header = Header {
            dh: self.dhs_pub,
            pn: self.pn,
            n: self.ns,
        };
        let hdr_bytes = serde_cbor::to_vec(&header).ok()?;

        let mut nonce_seq = NonceSeq::new();
        let nonce_bytes = nonce_seq.next();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes128SivAead::new_from_slice(hk_s).ok()?;
        let mut header_ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &hdr_bytes,
                    aad: &[],
                },
            )
            .ok()?;
        let mut enc_header = nonce_bytes.to_vec();
        enc_header.append(&mut header_ct);

        let mut full_ad = ad.to_vec();
        full_ad.extend_from_slice(&enc_header);

        let nonce_bytes2 = nonce_seq.next();
        let nonce2 = Nonce::from_slice(&nonce_bytes2);
        let cipher = Aes128SivAead::new_from_slice(&mk).ok()?;
        let mut ct = cipher
            .encrypt(
                nonce2,
                Payload {
                    msg: plaintext,
                    aad: &full_ad,
                },
            )
            .ok()?;
        let mut payload = nonce_bytes2.to_vec();
        payload.append(&mut ct);
        Some((enc_header, payload))
    }

    // Decrypt static HE
    pub fn decrypt_static_he(
        &self,
        enc_header: &[u8],
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Option<Vec<u8>> {
        let _header = self
            .hkr
            .and_then(|ref hk| Self::hdecrypt(hk, enc_header).ok())
            .or_else(|| Self::hdecrypt(&self.nhkr, enc_header).ok())?;
        let ck_r = self.ckr.as_ref()?;
        let mk = Self::mk_from_ck(ck_r);

        if ciphertext.len() < NONCE_LEN {
            return None;
        }
        let (nonce_bytes, ct) = ciphertext.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        let mut full_ad = ad.to_vec();
        full_ad.extend_from_slice(enc_header);
        let cipher = Aes128SivAead::new_from_slice(&mk).ok()?;
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ct,
                    aad: &full_ad,
                },
            )
            .ok()
    }

    // Decrypt own static HE, for the sender while it still works on the message final message
    pub fn decrypt_own_static_he(
        &self,
        enc_header: &[u8],
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Option<Vec<u8>> {
        let hk_s = self.hks.as_ref()?;
        let _header = Self::hdecrypt(hk_s, enc_header).ok()?;
        let ck_s = self.cks.as_ref()?;
        let mk = Self::mk_from_ck(ck_s);

        if ciphertext.len() < NONCE_LEN {
            return None;
        }
        let (nonce_bytes, ct) = ciphertext.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        let mut full_ad = ad.to_vec();
        full_ad.extend_from_slice(enc_header);
        let cipher = Aes128SivAead::new_from_slice(&mk).ok()?;
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ct,
                    aad: &full_ad,
                },
            )
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use {super::*, rand::rngs::OsRng};

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let initial_root = [0u8; 32];
        let shared_hka = [1u8; 32];
        let shared_nhkb = [2u8; 32];

        // Generate Bob's DH keypair
        let bob_sk = StaticSecret::random_from_rng(OsRng);
        let bob_pk = PublicKey::from(&bob_sk);

        // Initialize states
        let mut alice = RatchetStateHE::new();
        let mut bob = RatchetStateHE::new();
        alice
            .init_alice_he(&initial_root, bob_pk.clone(), shared_hka, shared_nhkb)
            .unwrap();
        bob.init_bob_he(
            &initial_root,
            (bob_sk, bob_pk.clone()),
            shared_hka,
            shared_nhkb,
        )
        .unwrap();

        let ad = b"associated data";
        let plaintext = b"hello, world";

        // Alice encrypts
        let (enc_hdr, payload) = alice
            .ratchet_encrypt_he(plaintext, ad)
            .expect("encryption failed");
        // Bob decrypts
        let decrypted = bob
            .ratchet_decrypt_he(&enc_hdr, &payload, ad)
            .expect("decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_header_decryption_fails_with_wrong_key() {
        let initial_root = [0u8; 32];
        let shared_hka = [3u8; 32];
        let shared_nhkb = [4u8; 32];

        let bob_sk = StaticSecret::random_from_rng(OsRng);
        let bob_pk = PublicKey::from(&bob_sk);

        let mut alice = RatchetStateHE::new();
        let mut bob = RatchetStateHE::new();
        alice
            .init_alice_he(&initial_root, bob_pk.clone(), shared_hka, shared_nhkb)
            .unwrap();
        // Bob with wrong header keys
        bob.init_bob_he(
            &initial_root,
            (bob_sk, bob_pk.clone()),
            shared_hka.map(|_| 0),
            shared_nhkb.map(|_| 0),
        )
        .unwrap();

        let ad = b"ad";
        let plaintext = b"data";
        let (enc_hdr, payload) = alice
            .ratchet_encrypt_he(plaintext, ad)
            .expect("encryption failed");
        // Bob attempts decryption, should fail
        assert!(bob.ratchet_decrypt_he(&enc_hdr, &payload, ad).is_err());
    }

    // Helper function to setup Alice and Bob
    fn setup_ratchet_pair() -> (RatchetStateHE, RatchetStateHE) {
        let initial_root = [0u8; 32];
        let shared_hka = [1u8; 32];
        let shared_nhkb = [2u8; 32];

        // Generate Bob's DH keypair
        let bob_sk = StaticSecret::random_from_rng(OsRng);
        let bob_pk = PublicKey::from(&bob_sk);

        // Initialize states
        let mut alice = RatchetStateHE::new();
        let mut bob = RatchetStateHE::new();
        alice
            .init_alice_he(&initial_root, bob_pk.clone(), shared_hka, shared_nhkb)
            .unwrap();
        bob.init_bob_he(&initial_root, (bob_sk, bob_pk), shared_hka, shared_nhkb)
            .unwrap();

        (alice, bob)
    }

    #[test]
    fn test_multiple_messages() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let ad = b"associated data";

        // Send multiple messages from Alice to Bob
        for i in 0..5 {
            let plaintext = format!("message {}", i).into_bytes();
            let (enc_hdr, payload) = alice
                .ratchet_encrypt_he(&plaintext, ad)
                .expect("encryption failed");
            let decrypted = bob.ratchet_decrypt_he(&enc_hdr, &payload, ad).unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn test_bidirectional_conversation() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let ad = b"associated data";

        // Alice sends to Bob
        let a_msg1 = b"Hello Bob!";
        let (enc_hdr1, payload1) = alice
            .ratchet_encrypt_he(a_msg1, ad)
            .expect("encryption failed");
        let decrypted1 = bob.ratchet_decrypt_he(&enc_hdr1, &payload1, ad).unwrap();
        assert_eq!(decrypted1, a_msg1);

        // Bob replies to Alice
        let b_msg1 = b"Hi Alice!";
        let (enc_hdr2, payload2) = bob
            .ratchet_encrypt_he(b_msg1, ad)
            .expect("encryption failed");
        let decrypted2 = alice.ratchet_decrypt_he(&enc_hdr2, &payload2, ad).unwrap();
        assert_eq!(decrypted2, b_msg1);

        // Alice sends another message
        let a_msg2 = b"How are you?";
        let (enc_hdr3, payload3) = alice
            .ratchet_encrypt_he(a_msg2, ad)
            .expect("encryption failed");
        let decrypted3 = bob.ratchet_decrypt_he(&enc_hdr3, &payload3, ad).unwrap();
        assert_eq!(decrypted3, a_msg2);

        // Bob sends another reply
        let b_msg2 = b"I'm good, thanks!";
        let (enc_hdr4, payload4) = bob
            .ratchet_encrypt_he(b_msg2, ad)
            .expect("encryption failed");
        let decrypted4 = alice.ratchet_decrypt_he(&enc_hdr4, &payload4, ad).unwrap();
        assert_eq!(decrypted4, b_msg2);
    }

    #[test]
    fn test_empty_associated_data() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let empty_ad = b"";
        let plaintext = b"message with empty AD";

        let (enc_hdr, payload) = alice
            .ratchet_encrypt_he(plaintext, empty_ad)
            .expect("encryption failed");
        let decrypted = bob
            .ratchet_decrypt_he(&enc_hdr, &payload, empty_ad)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_empty_message() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let ad = b"associated data";
        let empty_plaintext = b"";

        let (enc_hdr, payload) = alice
            .ratchet_encrypt_he(empty_plaintext, ad)
            .expect("encryption failed");
        let decrypted = bob.ratchet_decrypt_he(&enc_hdr, &payload, ad).unwrap();
        assert_eq!(decrypted, empty_plaintext);
    }

    #[test]
    fn test_large_message() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let ad = b"associated data";
        // Create a 10KB message
        let large_plaintext = vec![0xa5; 10 * 1024];

        let (enc_hdr, payload) = alice
            .ratchet_encrypt_he(&large_plaintext, ad)
            .expect("encryption failed");
        let decrypted = bob.ratchet_decrypt_he(&enc_hdr, &payload, ad).unwrap();
        assert_eq!(decrypted, large_plaintext);
    }

    #[test]
    fn test_out_of_order_messages() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let ad = b"associated data";

        // Alice encrypts multiple messages
        let msg1 = b"message 1";
        let (hdr1, payload1) = alice
            .ratchet_encrypt_he(msg1, ad)
            .expect("encryption failed");

        let msg2 = b"message 2";
        let (hdr2, payload2) = alice
            .ratchet_encrypt_he(msg2, ad)
            .expect("encryption failed");

        let msg3 = b"message 3";
        let (hdr3, payload3) = alice
            .ratchet_encrypt_he(msg3, ad)
            .expect("encryption failed");

        // Bob receives them out of order: 2, 1, 3
        let decrypted2 = bob.ratchet_decrypt_he(&hdr2, &payload2, ad).unwrap();
        assert_eq!(decrypted2, msg2);

        // Should still be able to decrypt message 1 even though it's "old"
        let decrypted1 = bob.ratchet_decrypt_he(&hdr1, &payload1, ad).unwrap();
        assert_eq!(decrypted1, msg1);

        // And continue with message 3
        let decrypted3 = bob.ratchet_decrypt_he(&hdr3, &payload3, ad).unwrap();
        assert_eq!(decrypted3, msg3);
    }

    #[test]
    fn test_dh_ratchet_step() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let ad = b"associated data";

        // 1. Alice sends a message to Bob
        let msg1 = b"First message from Alice";
        let (hdr1, payload1) = alice
            .ratchet_encrypt_he(msg1, ad)
            .expect("encryption failed");
        let decrypted1 = bob.ratchet_decrypt_he(&hdr1, &payload1, ad).unwrap();
        assert_eq!(decrypted1, msg1);

        // 2. Bob sends a reply - this triggers a DH ratchet on Alice's side
        let msg2 = b"First response from Bob";
        let (hdr2, payload2) = bob.ratchet_encrypt_he(msg2, ad).expect("encryption failed");
        let decrypted2 = alice.ratchet_decrypt_he(&hdr2, &payload2, ad).unwrap();
        assert_eq!(decrypted2, msg2);

        // 3. Alice sends another message - this uses the new ratchet keys
        let msg3 = b"Second message from Alice";
        let (hdr3, payload3) = alice
            .ratchet_encrypt_he(msg3, ad)
            .expect("encryption failed");
        let decrypted3 = bob.ratchet_decrypt_he(&hdr3, &payload3, ad).unwrap();
        assert_eq!(decrypted3, msg3);

        // 4. Bob sends another reply - another DH ratchet
        let msg4 = b"Second response from Bob";
        let (hdr4, payload4) = bob.ratchet_encrypt_he(msg4, ad).expect("encryption failed");
        let decrypted4 = alice.ratchet_decrypt_he(&hdr4, &payload4, ad).unwrap();
        assert_eq!(decrypted4, msg4);
    }

    #[test]
    fn test_skipped_message_keys_cleanup() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let ad = b"associated data";

        // Alice encrypts multiple messages
        let messages = (0..10)
            .map(|i| {
                let msg = format!("message {}", i).into_bytes();
                let result = alice
                    .ratchet_encrypt_he(&msg, ad)
                    .expect("encryption failed");
                (msg, result.0, result.1)
            })
            .collect::<Vec<_>>();

        // Bob only decrypts messages 0, 5, and 9
        let indices_to_decrypt = [0, 5, 9];

        for &idx in indices_to_decrypt.iter() {
            let (msg, hdr, payload) = &messages[idx];
            let decrypted = bob.ratchet_decrypt_he(hdr, payload, ad).unwrap();
            assert_eq!(&decrypted, msg);
        }

        // Bob should have stored skipped keys for messages 1-4 and 6-8
        // Verify the size of the skipped keys map
        assert_eq!(bob.mkskipped.len(), 7);

        // Now decrypt the remaining messages in reverse order
        for idx in (1..9).filter(|i| !indices_to_decrypt.contains(i)).rev() {
            let (msg, hdr, payload) = &messages[idx];
            let decrypted = bob.ratchet_decrypt_he(hdr, payload, ad).unwrap();
            assert_eq!(&decrypted, msg);
        }

        // All skipped keys should be used now
        assert_eq!(bob.mkskipped.len(), 0);
    }

    #[test]
    fn test_incorrect_associated_data() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let ad = b"correct associated data";
        let wrong_ad = b"wrong associated data";

        // Alice encrypts with correct AD
        let plaintext = b"secret message";
        let (enc_hdr, payload) = alice
            .ratchet_encrypt_he(plaintext, ad)
            .expect("encryption failed");

        // Bob tries to decrypt with wrong AD
        let result = bob.ratchet_decrypt_he(&enc_hdr, &payload, wrong_ad);
        assert!(result.is_err(), "Decryption should fail with incorrect AD");
    }

    #[test]
    #[should_panic]
    fn test_max_skip_limit() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let ad = b"associated data";

        // Alice encrypts MAX_SKIP_PER_CHAIN + 2 messages
        let max_plus_2 = MAX_SKIP_PER_CHAIN as usize + 2;
        let messages = (0..max_plus_2)
            .map(|i| {
                let msg = format!("message {}", i).into_bytes();
                let result = alice
                    .ratchet_encrypt_he(&msg, ad)
                    .expect("encryption failed");
                (msg, result.0, result.1)
            })
            .collect::<Vec<_>>();

        // Bob tries to decrypt the last message directly (skipping MAX_SKIP + 1 messages)
        let (_, last_hdr, last_payload) = &messages[max_plus_2 - 1];

        // This should panic due to too many skipped messages
        bob.ratchet_decrypt_he(last_hdr, last_payload, ad).unwrap();
    }

    #[test]
    fn test_header_deserialization() {
        // Create a header
        let header = Header {
            dh: PublicKey::from([1u8; 32]),
            pn: 42,
            n: 123,
        };

        // Serialize and deserialize
        let serialized = serde_cbor::to_vec(&header).unwrap();
        let deserialized: Header = serde_cbor::from_slice(&serialized).unwrap();

        // Compare
        assert_eq!(header.pn, deserialized.pn);
        assert_eq!(header.n, deserialized.n);
        assert_eq!(header.dh.as_bytes(), deserialized.dh.as_bytes());
    }

    #[test]
    fn test_different_associated_data_lengths() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let plaintext = b"test message";

        // Test with different AD lengths
        let ad_lengths = [0, 1, 16, 64, 1024];

        for len in ad_lengths.iter() {
            let ad = vec![0xbb; *len];
            let (enc_hdr, payload) = alice
                .ratchet_encrypt_he(plaintext, &ad)
                .expect("encryption failed");
            let decrypted = bob.ratchet_decrypt_he(&enc_hdr, &payload, &ad).unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn test_corrupted_header() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let ad = b"associated data";
        let plaintext = b"test message";

        // Alice encrypts a message
        let (mut enc_hdr, payload) = alice
            .ratchet_encrypt_he(plaintext, ad)
            .expect("encryption failed");

        // Corrupt the header by modifying a byte
        if !enc_hdr.is_empty() {
            let index = enc_hdr.len() / 2;
            enc_hdr[index] ^= 0x01; // Flip a bit
        }

        // Bob tries to decrypt
        let result = bob.ratchet_decrypt_he(&enc_hdr, &payload, ad);
        assert!(
            result.is_err(),
            "Decryption should fail with corrupted header"
        );
    }

    #[test]
    fn test_corrupted_payload() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let ad = b"associated data";
        let plaintext = b"test message";

        // Alice encrypts a message
        let (enc_hdr, mut payload) = alice
            .ratchet_encrypt_he(plaintext, ad)
            .expect("encryption failed");

        // Corrupt the payload by modifying a byte
        if !payload.is_empty() {
            let index = payload.len() / 2;
            payload[index] ^= 0x01; // Flip a bit
        }

        // Bob tries to decrypt
        let result = bob.ratchet_decrypt_he(&enc_hdr, &payload, ad);
        assert!(
            result.is_err(),
            "Decryption should fail with corrupted payload"
        );
    }

    #[test]
    fn test_alternating_conversation() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let ad = b"associated data";

        // Multiple rounds of back-and-forth conversation
        for i in 0..10 {
            // Alice to Bob
            let a_msg = format!("Alice message {}", i).into_bytes();
            let (a_hdr, a_payload) = alice
                .ratchet_encrypt_he(&a_msg, ad)
                .expect("encryption failed");
            let a_decrypted = bob.ratchet_decrypt_he(&a_hdr, &a_payload, ad).unwrap();
            assert_eq!(a_decrypted, a_msg);

            // Bob to Alice
            let b_msg = format!("Bob message {}", i).into_bytes();
            let (b_hdr, b_payload) = bob
                .ratchet_encrypt_he(&b_msg, ad)
                .expect("encryption failed");
            let b_decrypted = alice.ratchet_decrypt_he(&b_hdr, &b_payload, ad).unwrap();
            assert_eq!(b_decrypted, b_msg);
        }
    }

    #[test]
    fn test_multiple_messages_then_ratchet() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let ad = b"associated data";

        // Alice sends multiple messages
        for i in 0..5 {
            let msg = format!("Alice message {}", i).into_bytes();
            let (hdr, payload) = alice
                .ratchet_encrypt_he(&msg, ad)
                .expect("encryption failed");
            let decrypted = bob.ratchet_decrypt_he(&hdr, &payload, ad).unwrap();
            assert_eq!(decrypted, msg);
        }

        // Bob replies (triggering DH ratchet)
        let bob_msg = b"Bob's reply";
        let (hdr, payload) = bob
            .ratchet_encrypt_he(bob_msg, ad)
            .expect("encryption failed");
        let decrypted = alice.ratchet_decrypt_he(&hdr, &payload, ad).unwrap();
        assert_eq!(decrypted, bob_msg);

        // Alice sends more messages with new ratchet state
        for i in 0..5 {
            let msg = format!("Alice new message {}", i).into_bytes();
            let (hdr, payload) = alice
                .ratchet_encrypt_he(&msg, ad)
                .expect("encryption failed");
            let decrypted = bob.ratchet_decrypt_he(&hdr, &payload, ad).unwrap();
            assert_eq!(decrypted, msg);
        }
    }
}
