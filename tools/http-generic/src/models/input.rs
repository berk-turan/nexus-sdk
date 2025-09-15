//! Input models for the generic HTTP tool

use {
    crate::auth::AuthConfig,
    schemars::JsonSchema,
    serde::{Deserialize, Serialize},
    std::collections::HashMap,
};

/// Main input structure for HTTP requests
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Input {
    /// HTTP method (GET, POST, PUT, DELETE, etc.)
    pub method: String,

    /// Complete URL for the request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Base URL (used with path)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,

    /// Path to append to base_url
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// HTTP headers
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,

    /// Query parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<HashMap<String, String>>,

    /// Authentication configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthConfig>,

    /// Request body configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<BodyConfig>,

    /// Request timeout in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,

    /// Number of retry attempts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries: Option<u32>,

    /// Whether to follow HTTP redirects
    #[serde(skip_serializing_if = "Option::is_none")]
    pub follow_redirects: Option<bool>,

    /// Whether to expect JSON response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expect_json: Option<bool>,

    /// JSON schema to validate response against
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_schema: Option<String>,
}

/// Request body configuration
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BodyConfig {
    /// JSON request body
    Json {
        /// JSON data to send
        data: serde_json::Value,
    },
    /// Form URL-encoded request body
    FormUrlencoded {
        /// Form data
        data: HashMap<String, String>,
    },
    /// Multipart form data request body
    Multipart {
        /// Multipart data
        data: HashMap<String, String>,
    },
    /// Raw bytes request body
    Raw {
        /// Raw data (base64 encoded)
        data: String,
    },
}

impl BodyConfig {
    /// Apply body configuration to request builder
    pub fn apply(self, request_builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self {
            BodyConfig::Json { data } => request_builder.json(&data),
            BodyConfig::FormUrlencoded { data } => request_builder.form(&data),
            BodyConfig::Multipart { data } => {
                let mut form = reqwest::multipart::Form::new();
                for (key, value) in data {
                    form = form.text(key, value);
                }
                request_builder.multipart(form)
            }
            BodyConfig::Raw { data } => {
                match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &data) {
                    Ok(bytes) => request_builder.body(bytes),
                    Err(_) => request_builder.body(data), // Fallback to raw string
                }
            }
        }
    }
}
