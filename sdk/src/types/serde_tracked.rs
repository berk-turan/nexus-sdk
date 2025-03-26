use serde::{
    de::{DeserializeOwned, Deserializer},
    Deserialize, Serialize,
};
use serde_path_to_error;

/// A generic wrapper type that transparently serializes and deserializes the inner type `T`.
/// Deserialization uses `serde_path_to_error` to track errors and report the exact JSON path.
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct WithSerdeErrorPath<T>(pub T);

impl<'de, T> Deserialize<'de> for WithSerdeErrorPath<T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Create a mutable tracker.
        let mut track = serde_path_to_error::Track::new();
        // Wrap the deserializer with our tracker.
        let d = serde_path_to_error::Deserializer::new(deserializer, &mut track);
        let t = T::deserialize(d)?;
        Ok(WithSerdeErrorPath(t))
    }
}