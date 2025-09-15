//! Input validation utilities for the generic HTTP tool

use std::collections::HashMap;

/// Validation result type
pub type ValidationResult = Result<(), String>;

/// URL validation utilities
pub struct UrlValidator;

impl UrlValidator {
    /// Validates a complete URL
    pub fn validate_url(url: &str) -> ValidationResult {
        if url.is_empty() {
            return Err("URL cannot be empty".to_string());
        }

        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(format!(
                "URL must start with http:// or https://, got: {}",
                url
            ));
        }

        // Check for invalid characters
        if url.contains(' ') {
            return Err("URL cannot contain spaces".to_string());
        }

        // Check for double slashes (except after protocol)
        let after_protocol = if url.starts_with("https://") {
            &url[8..]
        } else {
            &url[7..]
        };

        if after_protocol.contains("//") {
            return Err("URL cannot contain double slashes after protocol".to_string());
        }

        // Basic length validation
        if url.len() > 2048 {
            return Err("URL is too long (max 2048 characters)".to_string());
        }

        Ok(())
    }

    /// Validates a base URL
    pub fn validate_base_url(base_url: &str) -> ValidationResult {
        Self::validate_url(base_url)?;

        // Base URL should not end with a path
        if base_url.ends_with('/') && !base_url.ends_with("://") {
            return Err("Base URL should not end with a slash".to_string());
        }

        Ok(())
    }

    /// Validates a path
    pub fn validate_path(path: &str) -> ValidationResult {
        if path.is_empty() {
            return Err("Path cannot be empty".to_string());
        }

        if !path.starts_with('/') {
            return Err("Path must start with a forward slash".to_string());
        }

        // Check for invalid characters
        if path.contains(' ') {
            return Err("Path cannot contain spaces".to_string());
        }

        // Check for double slashes
        if path.contains("//") {
            return Err("Path cannot contain double slashes".to_string());
        }

        // Basic length validation
        if path.len() > 1024 {
            return Err("Path is too long (max 1024 characters)".to_string());
        }

        Ok(())
    }

    /// Combines base URL and path
    pub fn combine_url(base_url: &str, path: &str) -> Result<String, String> {
        Self::validate_base_url(base_url)?;
        Self::validate_path(path)?;

        let combined = if base_url.ends_with('/') && path.starts_with('/') {
            format!("{}{}", base_url.trim_end_matches('/'), path)
        } else if !base_url.ends_with('/') && !path.starts_with('/') {
            format!("{}/{}", base_url, path)
        } else {
            format!("{}{}", base_url, path)
        };

        // Final validation of combined URL
        Self::validate_url(&combined)?;

        Ok(combined)
    }
}

/// Header validation utilities
pub struct HeaderValidator;

impl HeaderValidator {
    /// Validates a single header
    pub fn validate_header(name: &str, value: &str) -> ValidationResult {
        Self::validate_header_name(name)?;
        Self::validate_header_value(value)?;
        Ok(())
    }

    /// Validates header name
    pub fn validate_header_name(name: &str) -> ValidationResult {
        if name.is_empty() {
            return Err("Header name cannot be empty".to_string());
        }

        if name.len() > 100 {
            return Err("Header name is too long (max 100 characters)".to_string());
        }

        // Check for invalid characters in header name
        for ch in name.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
                return Err(format!(
                    "Header name contains invalid character '{}': {}",
                    ch, name
                ));
            }
        }

        // Check for common invalid headers
        let invalid_headers = [
            "content-length",   // Should be set automatically
            "host",             // Should be set automatically
            "connection",       // Should be set automatically
            "upgrade",          // Should be set automatically
            "proxy-connection", // Should be set automatically
        ];

        let name_lower = name.to_lowercase();
        for invalid in &invalid_headers {
            if name_lower == *invalid {
                return Err(format!("Header '{}' should not be set manually", name));
            }
        }

        Ok(())
    }

    /// Validates header value
    pub fn validate_header_value(value: &str) -> ValidationResult {
        if value.len() > 1000 {
            return Err("Header value is too long (max 1000 characters)".to_string());
        }

        // Check for control characters (except tab and newline)
        for ch in value.chars() {
            if ch.is_control() && ch != '\t' && ch != '\n' && ch != '\r' {
                return Err(format!(
                    "Header value contains invalid control character: {}",
                    ch as u32
                ));
            }
        }

        Ok(())
    }

    /// Validates all headers
    pub fn validate_headers(headers: &HashMap<String, String>) -> ValidationResult {
        for (name, value) in headers {
            Self::validate_header(name, value)?;
        }
        Ok(())
    }
}

/// Query parameter validation utilities
pub struct QueryValidator;

impl QueryValidator {
    /// Validates a single query parameter
    pub fn validate_query_param(name: &str, value: &str) -> ValidationResult {
        Self::validate_query_name(name)?;
        Self::validate_query_value(value)?;
        Ok(())
    }

    /// Validates query parameter name
    pub fn validate_query_name(name: &str) -> ValidationResult {
        if name.is_empty() {
            return Err("Query parameter name cannot be empty".to_string());
        }

        if name.len() > 100 {
            return Err("Query parameter name is too long (max 100 characters)".to_string());
        }

        // Check for invalid characters
        for ch in name.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' && ch != '.' {
                return Err(format!(
                    "Query parameter name contains invalid character '{}': {}",
                    ch, name
                ));
            }
        }

        Ok(())
    }

    /// Validates query parameter value
    pub fn validate_query_value(value: &str) -> ValidationResult {
        if value.len() > 1000 {
            return Err("Query parameter value is too long (max 1000 characters)".to_string());
        }

        Ok(())
    }

    /// Validates all query parameters
    pub fn validate_query_params(query: &HashMap<String, String>) -> ValidationResult {
        for (name, value) in query {
            Self::validate_query_param(name, value)?;
        }
        Ok(())
    }
}

/// HTTP method validation utilities
pub struct MethodValidator;

impl MethodValidator {
    /// Validates HTTP method
    pub fn validate_method(method: &str) -> ValidationResult {
        if method.is_empty() {
            return Err("HTTP method cannot be empty".to_string());
        }

        let method_upper = method.to_uppercase();
        let valid_methods = [
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT",
        ];

        if !valid_methods.contains(&method_upper.as_str()) {
            return Err(format!(
                "Unsupported HTTP method: {}. Supported methods: {}",
                method,
                valid_methods.join(", ")
            ));
        }

        Ok(())
    }
}

/// Timeout and retry validation utilities
pub struct ConfigValidator;

impl ConfigValidator {
    /// Validates timeout value
    pub fn validate_timeout(timeout_ms: u64) -> ValidationResult {
        if timeout_ms == 0 {
            return Err("Timeout must be greater than 0".to_string());
        }

        if timeout_ms > 300_000 {
            // 5 minutes
            return Err("Timeout cannot exceed 300,000 ms (5 minutes)".to_string());
        }

        Ok(())
    }

    /// Validates retry count
    pub fn validate_retries(retries: u32) -> ValidationResult {
        if retries > 10 {
            return Err("Retries cannot exceed 10".to_string());
        }

        Ok(())
    }

    /// Validates follow redirects setting
    pub fn validate_follow_redirects(_follow_redirects: bool) -> ValidationResult {
        // This is always valid, but we can add future validation logic here
        Ok(())
    }
}

/// JSON schema validation utilities
pub struct JsonSchemaValidator;

impl JsonSchemaValidator {
    /// Validates JSON schema string
    pub fn validate_schema(schema_str: &str) -> ValidationResult {
        if schema_str.is_empty() {
            return Err("JSON schema cannot be empty".to_string());
        }

        // Parse as JSON
        let schema_value: serde_json::Value =
            serde_json::from_str(schema_str).map_err(|e| format!("Invalid JSON schema: {}", e))?;

        // Basic validation
        if !schema_value.is_object() {
            return Err("JSON schema must be a JSON object".to_string());
        }

        // Check for required fields
        if let Some(obj) = schema_value.as_object() {
            if !obj.contains_key("type")
                && !obj.contains_key("properties")
                && !obj.contains_key("$schema")
            {
                return Err(
                    "JSON schema should contain at least one of: type, properties, or $schema"
                        .to_string(),
                );
            }
        }

        Ok(())
    }
}

/// Main validation coordinator
pub struct InputValidator;

impl InputValidator {
    /// Validates all input parameters
    pub fn validate_all(
        method: &str,
        url: Option<&String>,
        base_url: Option<&String>,
        path: Option<&String>,
        headers: Option<&HashMap<String, String>>,
        query: Option<&HashMap<String, String>>,
        timeout_ms: Option<u64>,
        retries: Option<u32>,
        follow_redirects: Option<bool>,
        expect_json: Option<bool>,
        json_schema: Option<&String>,
    ) -> ValidationResult {
        // Validate HTTP method
        MethodValidator::validate_method(method)?;

        // Validate URL configuration
        Self::validate_url_configuration(url, base_url, path)?;

        // Validate headers if provided
        if let Some(headers) = headers {
            HeaderValidator::validate_headers(headers)?;
        }

        // Validate query parameters if provided
        if let Some(query) = query {
            QueryValidator::validate_query_params(query)?;
        }

        // Validate timeout if provided
        if let Some(timeout) = timeout_ms {
            ConfigValidator::validate_timeout(timeout)?;
        }

        // Validate retries if provided
        if let Some(retries) = retries {
            ConfigValidator::validate_retries(retries)?;
        }

        // Validate follow redirects if provided
        if let Some(follow_redirects) = follow_redirects {
            ConfigValidator::validate_follow_redirects(follow_redirects)?;
        }

        // Validate JSON schema if provided
        if let Some(schema_str) = json_schema {
            if !expect_json.unwrap_or(false) {
                return Err("JSON schema can only be used when expect_json is true".to_string());
            }
            JsonSchemaValidator::validate_schema(schema_str)?;
        }

        Ok(())
    }

    /// Validates URL configuration
    fn validate_url_configuration(
        url: Option<&String>,
        base_url: Option<&String>,
        path: Option<&String>,
    ) -> ValidationResult {
        match (url, base_url, path) {
            (Some(_url), Some(_), Some(_)) => {
                Err("Cannot specify both 'url' and ('base_url' + 'path')".to_string())
            }
            (Some(_url), Some(_), None) => {
                Err("Cannot specify both 'url' and 'base_url' without 'path'".to_string())
            }
            (Some(_url), None, Some(_)) => {
                Err("Cannot specify both 'url' and 'path' without 'base_url'".to_string())
            }
            (None, None, Some(_)) => Err("Cannot specify 'path' without 'base_url'".to_string()),
            (None, Some(_), None) => Err("Cannot specify 'base_url' without 'path'".to_string()),
            (None, None, None) => {
                Err("Must specify either 'url' or ('base_url' + 'path')".to_string())
            }
            (Some(url), None, None) => UrlValidator::validate_url(url),
            (None, Some(base_url), Some(path)) => {
                UrlValidator::validate_base_url(base_url)?;
                UrlValidator::validate_path(path)?;
                Ok(())
            }
        }
    }
}
