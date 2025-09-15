//! Output models for the generic HTTP tool

use {
    crate::core::error::HttpErrorKind,
    schemars::JsonSchema,
    serde::Serialize,
    std::collections::HashMap,
};

/// Main output structure for HTTP requests
#[derive(Debug, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Output {
    /// Successful HTTP request
    Ok {
        /// HTTP status code
        status: u16,
        /// Response headers
        headers: HashMap<String, String>,
        /// Raw response body (base64 encoded)
        raw_base64: String,
        /// Response body as text (if valid UTF-8)
        #[serde(skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        /// Response body as JSON (if expect_json is true)
        #[serde(skip_serializing_if = "Option::is_none")]
        json: Option<serde_json::Value>,
        /// Whether response matches JSON schema (if provided)
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_valid: Option<bool>,
        /// Correlation ID for debugging (if available from API)
        #[serde(skip_serializing_if = "Option::is_none")]
        correlation_id: Option<String>,
        /// Request ID for debugging (if available from API)
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
    },
    /// Error response with detailed information
    Err {
        /// Detailed error message
        reason: String,
        /// Type of error based on HTTP status codes and common scenarios
        kind: HttpErrorKind,
        /// HTTP status code if available
        #[serde(skip_serializing_if = "Option::is_none")]
        status_code: Option<u16>,
        /// Response headers if available
        #[serde(skip_serializing_if = "Option::is_none")]
        headers: Option<HashMap<String, String>>,
        /// Correlation ID for debugging (if available from API)
        #[serde(skip_serializing_if = "Option::is_none")]
        correlation_id: Option<String>,
        /// Request ID for debugging (if available from API)
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
    },
}

/// HTTP error types for internal use
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // These variants are used in tests
pub enum HttpError {
    #[error("HTTP error: {reason} (status: {status})")]
    Http { reason: String, status: u16 },

    #[error("JSON parse error: {reason}")]
    JsonParse { reason: String },

    #[error("Schema validation error: {reason}")]
    SchemaValidation {
        reason: String,
        json: serde_json::Value,
    },

    #[error("Network error: {reason}")]
    Network { reason: String },
}

/// HTTP result type for internal use
pub type HttpResult = Result<HttpSuccess, HttpError>;

/// Successful HTTP response
#[derive(Debug)]
pub struct HttpSuccess {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub raw_base64: String,
    pub text: Option<String>,
    pub json: Option<serde_json::Value>,
    pub schema_valid: Option<bool>,
    pub correlation_id: Option<String>,
    pub request_id: Option<String>,
}

impl From<HttpSuccess> for Output {
    fn from(success: HttpSuccess) -> Self {
        Output::Ok {
            status: success.status,
            headers: success.headers,
            raw_base64: success.raw_base64,
            text: success.text,
            json: success.json,
            schema_valid: success.schema_valid,
            correlation_id: success.correlation_id,
            request_id: success.request_id,
        }
    }
}

impl From<HttpError> for Output {
    fn from(error: HttpError) -> Self {
        match error {
            HttpError::Http { reason, status } => Output::Err {
                reason,
                kind: HttpErrorKind::from_status_code(status),
                status_code: Some(status),
                headers: None,
                correlation_id: None,
                request_id: None,
            },
            HttpError::JsonParse { reason } => Output::Err {
                reason,
                kind: HttpErrorKind::JsonParseError,
                status_code: None,
                headers: None,
                correlation_id: None,
                request_id: None,
            },
            HttpError::SchemaValidation { reason, .. } => Output::Err {
                reason,
                kind: HttpErrorKind::JsonSchemaValidationError,
                status_code: None,
                headers: None,
                correlation_id: None,
                request_id: None,
            },
            HttpError::Network { reason } => Output::Err {
                reason,
                kind: HttpErrorKind::NetworkConnectionFailed,
                status_code: None,
                headers: None,
                correlation_id: None,
                request_id: None,
            },
        }
    }
}
