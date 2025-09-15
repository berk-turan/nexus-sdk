use {
    reqwest::StatusCode,
    schemars::JsonSchema,
    serde::{Deserialize, Serialize},
    std::collections::HashMap,
    thiserror::Error,
};

/// Error kind enumeration for HTTP operations
/// Based on HTTP status codes and common error scenarios
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HttpErrorKind {
    /// Bad request (HTTP 400)
    BadRequest,
    /// Unauthorized (HTTP 401)
    Unauthorized,
    /// Forbidden (HTTP 403)
    Forbidden,
    /// Not found (HTTP 404)
    NotFound,
    /// Method not allowed (HTTP 405)
    MethodNotAllowed,
    /// Not acceptable (HTTP 406)
    NotAcceptable,
    /// Request timeout (HTTP 408)
    RequestTimeout,
    /// Conflict (HTTP 409)
    Conflict,
    /// Gone (HTTP 410)
    Gone,
    /// Length required (HTTP 411)
    LengthRequired,
    /// Precondition failed (HTTP 412)
    PreconditionFailed,
    /// Payload too large (HTTP 413)
    PayloadTooLarge,
    /// URI too long (HTTP 414)
    UriTooLong,
    /// Unsupported media type (HTTP 415)
    UnsupportedMediaType,
    /// Range not satisfiable (HTTP 416)
    RangeNotSatisfiable,
    /// Expectation failed (HTTP 417)
    ExpectationFailed,
    /// Too many requests (HTTP 429)
    TooManyRequests,
    /// Internal server error (HTTP 500)
    InternalServerError,
    /// Not implemented (HTTP 501)
    NotImplemented,
    /// Bad gateway (HTTP 502)
    BadGateway,
    /// Service unavailable (HTTP 503)
    ServiceUnavailable,
    /// Gateway timeout (HTTP 504)
    GatewayTimeout,
    /// HTTP version not supported (HTTP 505)
    HttpVersionNotSupported,
    /// Network connection failed
    NetworkConnectionFailed,
    /// Network timeout
    NetworkTimeout,
    /// Network DNS failure
    NetworkDnsFailure,
    /// Network IP blocked
    NetworkIpBlocked,
    /// SSL/TLS error
    SslError,
    /// Invalid URL format
    InvalidUrl,
    /// Invalid HTTP method
    InvalidMethod,
    /// Invalid headers
    InvalidHeaders,
    /// Invalid body format
    InvalidBody,
    /// JSON parse error
    JsonParseError,
    /// JSON schema validation error
    JsonSchemaValidationError,
    /// Authentication error
    AuthenticationError,
    /// Authorization error
    AuthorizationError,
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Request validation error
    RequestValidationError,
    /// Response validation error
    ResponseValidationError,
    /// Unknown error
    Unknown,
}

/// A detailed HTTP error response
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct HttpErrorResponse {
    /// Detailed error message
    pub reason: String,
    /// Type of error based on HTTP status codes and common scenarios
    pub kind: HttpErrorKind,
    /// HTTP status code if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// Response headers if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
    /// Correlation ID for debugging (if available from API)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Request ID for debugging (if available from API)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Error type for HTTP operations
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum HttpError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Response parsing error: {0}")]
    ParseError(#[from] serde_json::Error),

    #[error("HTTP API error: {0}")]
    ApiError(String),

    #[error("HTTP status error: {0}")]
    StatusError(StatusCode),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Unknown error: {0}")]
    Other(String),
}

impl HttpErrorKind {
    /// Maps HTTP status code to our error kind
    pub fn from_status_code(status_code: u16) -> Self {
        match status_code {
            400 => Self::BadRequest,
            401 => Self::Unauthorized,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            405 => Self::MethodNotAllowed,
            406 => Self::NotAcceptable,
            408 => Self::RequestTimeout,
            409 => Self::Conflict,
            410 => Self::Gone,
            411 => Self::LengthRequired,
            412 => Self::PreconditionFailed,
            413 => Self::PayloadTooLarge,
            414 => Self::UriTooLong,
            415 => Self::UnsupportedMediaType,
            416 => Self::RangeNotSatisfiable,
            417 => Self::ExpectationFailed,
            429 => Self::TooManyRequests,
            500 => Self::InternalServerError,
            501 => Self::NotImplemented,
            502 => Self::BadGateway,
            503 => Self::ServiceUnavailable,
            504 => Self::GatewayTimeout,
            505 => Self::HttpVersionNotSupported,
            _ => Self::Unknown,
        }
    }

    /// Maps network error to our error kind
    #[allow(dead_code)]
    pub fn from_network_error(error: &reqwest::Error) -> Self {
        if error.is_timeout() {
            Self::NetworkTimeout
        } else if error.is_connect() {
            Self::NetworkConnectionFailed
        } else if error.is_request() {
            Self::NetworkIpBlocked
        } else if error.is_decode() {
            Self::JsonParseError
        } else {
            Self::NetworkConnectionFailed
        }
    }

    /// Maps validation error to our error kind
    #[allow(dead_code)]
    pub fn from_validation_error(error_type: &str) -> Self {
        match error_type {
            "invalid_url" => Self::InvalidUrl,
            "invalid_method" => Self::InvalidMethod,
            "invalid_headers" => Self::InvalidHeaders,
            "invalid_body" => Self::InvalidBody,
            "json_parse" => Self::JsonParseError,
            "json_schema" => Self::JsonSchemaValidationError,
            "auth" => Self::AuthenticationError,
            "authorization" => Self::AuthorizationError,
            _ => Self::RequestValidationError,
        }
    }
}

impl HttpErrorResponse {
    /// Creates a new error response
    #[allow(dead_code)]
    pub fn new(reason: String, kind: HttpErrorKind) -> Self {
        Self {
            reason,
            kind,
            status_code: None,
            headers: None,
            correlation_id: None,
            request_id: None,
        }
    }

    /// Creates an error response with status code
    #[allow(dead_code)]
    pub fn with_status_code(reason: String, kind: HttpErrorKind, status_code: u16) -> Self {
        Self {
            reason,
            kind,
            status_code: Some(status_code),
            headers: None,
            correlation_id: None,
            request_id: None,
        }
    }

    /// Creates an error response with headers
    #[allow(dead_code)]
    pub fn with_headers(
        reason: String,
        kind: HttpErrorKind,
        status_code: u16,
        headers: HashMap<String, String>,
    ) -> Self {
        Self {
            reason,
            kind,
            status_code: Some(status_code),
            headers: Some(headers),
            correlation_id: None,
            request_id: None,
        }
    }

    /// Adds correlation ID to error response
    #[allow(dead_code)]
    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    /// Adds request ID to error response
    #[allow(dead_code)]
    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }
}
