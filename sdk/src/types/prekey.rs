use {
    crate::{crypto::x3dh::PreKeyBundle, sui::UID},
    serde::{Deserialize, Deserializer},
};

/// A prekey structure containing a unique identifier, prekey ID, and cryptographic bundle
#[derive(Debug, Clone)]
pub struct Prekey {
    pub id: UID,
    pub prekey_id: u32,
    pub bundle: PreKeyBundle,
}

#[derive(Deserialize)]
struct RawPrekeyInner {
    id: UID,
    prekey_id: u32,
    #[serde(deserialize_with = "hex_or_base64_to_vec")]
    bytes: Vec<u8>,
}

fn hex_or_base64_to_vec<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::Deserialize;
    let s: &str = Deserialize::deserialize(d)?;
    let bytes = if s.starts_with("0x") {
        hex::decode(&s[2..]).map_err(serde::de::Error::custom)?
    } else {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)?
    };
    Ok(bytes)
}

impl<'de> Deserialize<'de> for Prekey {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// matches the outer `{ type, fields: { … } }` wrapper
        #[derive(Deserialize)]
        struct Wrapper {
            fields: RawPrekeyInner,
        }

        let Wrapper { fields } = Wrapper::deserialize(de)?;
        let bundle = bincode::deserialize(&fields.bytes).map_err(serde::de::Error::custom)?;
        Ok(Self {
            id: fields.id,
            prekey_id: fields.prekey_id,
            bundle,
        })
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{crypto::x3dh::IdentityKey, sui::ObjectID},
        rand::rngs::OsRng,
        x25519_dalek::StaticSecret,
    };

    /// Helper function to create a mock UID for testing
    fn mock_uid() -> UID {
        UID::new(ObjectID::random())
    }

    /// Helper function to create a test PreKeyBundle
    fn create_test_prekey_bundle() -> PreKeyBundle {
        let identity = IdentityKey::generate();
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let spk_id = 42u32;

        PreKeyBundle::new(&identity, spk_id, &spk_secret, None, None)
    }

    /// Helper function to create a test PreKeyBundle with OTPK
    fn create_test_prekey_bundle_with_otpk() -> PreKeyBundle {
        let identity = IdentityKey::generate();
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let spk_id = 123u32;
        let otpk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let otpk_id = 456u32;

        PreKeyBundle::new(
            &identity,
            spk_id,
            &spk_secret,
            Some(otpk_id),
            Some(&otpk_secret),
        )
    }

    #[test]
    fn test_multiple_prekeys_different_ids() {
        // Create multiple prekeys with different IDs
        let prekeys: Vec<Prekey> = (0..5)
            .map(|i| Prekey {
                id: mock_uid(),
                prekey_id: i as u32,
                bundle: create_test_prekey_bundle(),
            })
            .collect();

        // Verify each prekey has correct ID
        for (i, prekey) in prekeys.iter().enumerate() {
            assert_eq!(prekey.prekey_id, i as u32);
        }

        // Verify all prekeys have different object IDs
        let object_ids: Vec<_> = prekeys.iter().map(|p| p.id.object_id()).collect();
        for i in 0..object_ids.len() {
            for j in (i + 1)..object_ids.len() {
                assert_ne!(object_ids[i], object_ids[j]);
            }
        }
    }

    #[test]
    fn test_bincode_serialization_roundtrip() {
        let bundle = create_test_prekey_bundle();

        // Test that PreKeyBundle can be serialized and deserialized with bincode
        let serialized = bincode::serialize(&bundle).unwrap();
        let deserialized: PreKeyBundle = bincode::deserialize(&serialized).unwrap();

        // Verify key components match
        assert_eq!(bundle.spk_id, deserialized.spk_id);
        assert_eq!(bundle.spk_pub.as_bytes(), deserialized.spk_pub.as_bytes());
        assert_eq!(bundle.spk_sig, deserialized.spk_sig);
        assert_eq!(
            bundle.identity_verify_bytes,
            deserialized.identity_verify_bytes
        );
        assert_eq!(
            bundle.identity_pk.as_bytes(),
            deserialized.identity_pk.as_bytes()
        );
        assert_eq!(bundle.otpk_id, deserialized.otpk_id);
    }

    #[test]
    fn test_bincode_serialization_with_otpk_roundtrip() {
        let bundle = create_test_prekey_bundle_with_otpk();

        // Test that PreKeyBundle with OTPK can be serialized and deserialized with bincode
        let serialized = bincode::serialize(&bundle).unwrap();
        let deserialized: PreKeyBundle = bincode::deserialize(&serialized).unwrap();

        // Verify key components match
        assert_eq!(bundle.spk_id, deserialized.spk_id);
        assert_eq!(bundle.spk_pub.as_bytes(), deserialized.spk_pub.as_bytes());
        assert_eq!(bundle.spk_sig, deserialized.spk_sig);
        assert_eq!(
            bundle.identity_verify_bytes,
            deserialized.identity_verify_bytes
        );
        assert_eq!(
            bundle.identity_pk.as_bytes(),
            deserialized.identity_pk.as_bytes()
        );
        assert_eq!(bundle.otpk_id, deserialized.otpk_id);

        match (bundle.otpk_pub, deserialized.otpk_pub) {
            (Some(orig), Some(deser)) => {
                assert_eq!(orig.as_bytes(), deser.as_bytes());
            }
            (None, None) => {}
            _ => panic!("OTPK pub key serialization mismatch"),
        }
    }

    #[test]
    fn test_bundle_id_consistency() {
        // Test that different bundles with same SPK ID are consistent
        let identity = IdentityKey::generate();
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let spk_id = 999u32;

        let bundle1 = PreKeyBundle::new(&identity, spk_id, &spk_secret, None, None);
        let bundle2 = PreKeyBundle::new(&identity, spk_id, &spk_secret, None, None);

        assert_eq!(bundle1.spk_id, bundle2.spk_id);
        assert_eq!(bundle1.spk_pub.as_bytes(), bundle2.spk_pub.as_bytes());
        assert_eq!(
            bundle1.identity_pk.as_bytes(),
            bundle2.identity_pk.as_bytes()
        );
        assert_eq!(bundle1.identity_verify_bytes, bundle2.identity_verify_bytes);
    }

    #[test]
    fn test_bundle_with_different_identities() {
        // Test that bundles with different identities are different
        let identity1 = IdentityKey::generate();
        let identity2 = IdentityKey::generate();
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);
        let spk_id = 100u32;

        let bundle1 = PreKeyBundle::new(&identity1, spk_id, &spk_secret, None, None);
        let bundle2 = PreKeyBundle::new(&identity2, spk_id, &spk_secret, None, None);

        assert_eq!(bundle1.spk_id, bundle2.spk_id);
        assert_eq!(bundle1.spk_pub.as_bytes(), bundle2.spk_pub.as_bytes());
        assert_ne!(
            bundle1.identity_pk.as_bytes(),
            bundle2.identity_pk.as_bytes()
        );
        assert_ne!(bundle1.identity_verify_bytes, bundle2.identity_verify_bytes);
        assert_ne!(bundle1.spk_sig, bundle2.spk_sig); // Different signatures since different identities
    }

    #[test]
    fn test_extreme_values() {
        let identity = IdentityKey::generate();
        let spk_secret = StaticSecret::random_from_rng(&mut OsRng);

        // Test with edge case values
        let bundle_max = PreKeyBundle::new(&identity, u32::MAX, &spk_secret, None, None);
        assert_eq!(bundle_max.spk_id, u32::MAX);
        assert!(bundle_max.verify_spk());

        let bundle_zero = PreKeyBundle::new(&identity, 0, &spk_secret, None, None);
        assert_eq!(bundle_zero.spk_id, 0);
        assert!(bundle_zero.verify_spk());

        // Test with OTPK edge cases
        let bundle_otpk_max =
            PreKeyBundle::new(&identity, 1, &spk_secret, Some(u32::MAX), Some(&spk_secret));
        assert_eq!(bundle_otpk_max.otpk_id.unwrap(), u32::MAX);
        assert!(bundle_otpk_max.verify_spk());
    }
}
