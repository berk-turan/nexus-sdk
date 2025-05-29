use serde::{Deserialize, Serialize};

/// Prekey bytes are always 33 bytes long.
pub const PREKEY_BYTES_LENGTH: usize = 33;

/// Holds info about a public prekey. Specifically its internal ID and its bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Prekey {
    pub id: u32,
    pub bytes: Vec<u8>,
}
