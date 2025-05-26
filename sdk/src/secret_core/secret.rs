use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

use super::traits::{EncryptionAlgo, EncryptionAlgoDefault, PlaintextCodec, BincodeCodec};

/// Wrapper that transparently encrypts / decrypts its inner value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenericSecret<
    T,
    E: EncryptionAlgo = EncryptionAlgoDefault,
    P: PlaintextCodec = BincodeCodec,
> {
    pub value: T,
    _enc: PhantomData<E>,
    _codec: PhantomData<P>,
}

impl<T, E, P> GenericSecret<T, E, P>
where
    E: EncryptionAlgo,
    P: PlaintextCodec,
{
    pub fn new(value: T) -> Self { Self { value, _enc: PhantomData, _codec: PhantomData } }
}

impl<T: Default, E: EncryptionAlgo, P: PlaintextCodec> Default for GenericSecret<T, E, P> {
    fn default() -> Self { Self::new(T::default()) }
}

impl<T, E: EncryptionAlgo, P: PlaintextCodec> Deref for GenericSecret<T, E, P> { type Target = T; fn deref(&self) -> &T { &self.value } }
impl<T, E: EncryptionAlgo, P: PlaintextCodec> DerefMut for GenericSecret<T, E, P> { fn deref_mut(&mut self) -> &mut T { &mut self.value } }

impl<T, E, P> Serialize for GenericSecret<T, E, P>
where
    T: Serialize,
    E: EncryptionAlgo,
    P: PlaintextCodec,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let plain = P::encode(&self.value).map_err(serde::ser::Error::custom)?;
        let mut nonce = vec![0u8; E::NONCE_LEN];
        if E::NONCE_LEN > 0 { rand::rngs::OsRng.fill_bytes(&mut nonce); }
        let ct = E::encrypt(&nonce, &plain).map_err(serde::ser::Error::custom)?;
        let buf = if E::NONCE_LEN > 0 {
            let mut v = Vec::with_capacity(E::NONCE_LEN + ct.len());
            v.extend_from_slice(&nonce); v.extend_from_slice(&ct); v
        } else { ct };
        let encoded = general_purpose::STANDARD.encode(&buf);
        serializer.serialize_str(&encoded)
    }
}

impl<'de, T, E, P> Deserialize<'de> for GenericSecret<T, E, P>
where
    T: DeserializeOwned,
    E: EncryptionAlgo,
    P: PlaintextCodec,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let encoded = String::deserialize(deserializer)?;
        let decoded = general_purpose::STANDARD.decode(&encoded).map_err(serde::de::Error::custom)?;
        let (nonce_bytes, ciphertext) = if E::NONCE_LEN > 0 {
            if decoded.len() < E::NONCE_LEN { return Err(serde::de::Error::custom("ciphertext too short")); }
            decoded.split_at(E::NONCE_LEN)
        } else { (&[][..], decoded.as_slice()) };
        let mut nonce = vec![0u8; E::NONCE_LEN]; if E::NONCE_LEN > 0 { nonce.copy_from_slice(nonce_bytes); }
        let plain = E::decrypt(&nonce, ciphertext).map_err(serde::de::Error::custom)?;
        let inner: T = P::decode(&plain).map_err(serde::de::Error::custom)?;
        Ok(GenericSecret::new(inner))
    }
}
