//! Authentication handlers for the generic HTTP tool

use {
    schemars::JsonSchema,
    serde::{Deserialize, Serialize},
};

/// Authentication configuration
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    /// No authentication
    None,
    /// Bearer token authentication
    Bearer {
        /// The bearer token
        token: String,
    },
    /// API key authentication
    ApiKey {
        /// The API key value
        key: String,
        /// Where to place the key ("header" or "query")
        location: String,
        /// The parameter name (e.g., "Authorization", "X-API-Key")
        name: String,
    },
    /// Basic authentication
    Basic {
        /// The username
        username: String,
        /// The password
        password: String,
    },
}
