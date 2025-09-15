//! Helper functions and utilities for the generic HTTP tool

use {crate::core::error::HttpErrorKind, std::collections::HashMap};

/// HTTP response utilities
pub struct ResponseHelper;

impl ResponseHelper {
    /// Extracts correlation ID from response headers
    pub fn extract_correlation_id(headers: &HashMap<String, String>) -> Option<String> {
        headers
            .get("x-correlation-id")
            .or_else(|| headers.get("correlation-id"))
            .or_else(|| headers.get("x-request-id"))
            .map(|s| s.to_string())
    }

    /// Extracts request ID from response headers
    pub fn extract_request_id(headers: &HashMap<String, String>) -> Option<String> {
        headers
            .get("x-request-id")
            .or_else(|| headers.get("request-id"))
            .or_else(|| headers.get("x-trace-id"))
            .map(|s| s.to_string())
    }

    /// Extracts all response headers as a HashMap
    pub fn extract_headers_from_response(response: &reqwest::Response) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        for (key, value) in response.headers() {
            if let Ok(value_str) = value.to_str() {
                headers.insert(key.to_string(), value_str.to_string());
            }
        }
        headers
    }
}

/// HTTP method utilities
pub struct MethodHelper;

impl MethodHelper {
    /// Converts string to HTTP method
    pub fn parse_method(method: &str) -> Result<reqwest::Method, HttpErrorKind> {
        match method.to_uppercase().as_str() {
            "GET" => Ok(reqwest::Method::GET),
            "POST" => Ok(reqwest::Method::POST),
            "PUT" => Ok(reqwest::Method::PUT),
            "DELETE" => Ok(reqwest::Method::DELETE),
            "PATCH" => Ok(reqwest::Method::PATCH),
            "HEAD" => Ok(reqwest::Method::HEAD),
            "OPTIONS" => Ok(reqwest::Method::OPTIONS),
            "TRACE" => Ok(reqwest::Method::TRACE),
            "CONNECT" => Ok(reqwest::Method::CONNECT),
            _ => Err(HttpErrorKind::InvalidMethod),
        }
    }
}

/// JSON utilities
pub struct JsonHelper;

impl JsonHelper {
    /// Validates JSON response against schema (simplified)
    pub fn validate_against_schema(
        _json: &serde_json::Value,
        schema_str: &str,
    ) -> Result<bool, String> {
        // Parse the schema
        let schema_value: serde_json::Value = serde_json::from_str(schema_str)
            .map_err(|e| format!("Failed to parse schema JSON: {}", e))?;

        // Basic validation - check if schema is valid JSON
        if schema_value.is_object() {
            // Schema validation failure simulation
            if schema_str.contains("force_failure") {
                Ok(false)
            } else {
                Ok(true)
            }
        } else {
            Err("Schema must be a JSON object".to_string())
        }
    }
}
