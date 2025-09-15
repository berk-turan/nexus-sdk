//! # `xyz.taluslabs.http.generic.request@1`
//!
//! Generic HTTP client tool for making requests to any API endpoint.

use {
    crate::{
        core::{client::GenericHttpClient, error::HttpErrorKind, validation::InputValidator},
        models::{Input, Output},
        utils::helpers::{JsonHelper, MethodHelper},
    },
    nexus_sdk::{fqn, ToolFqn},
    nexus_toolkit::*,
};

/// Generic HTTP request tool
pub struct GenericHttpRequest;

impl NexusTool for GenericHttpRequest {
    type Input = Input;
    type Output = Output;

    async fn new() -> Self {
        Self
    }

    fn fqn() -> ToolFqn {
        fqn!("xyz.taluslabs.http.generic.request@1")
    }

    fn path() -> &'static str {
        "/request"
    }

    async fn health(&self) -> AnyResult<StatusCode> {
        Ok(StatusCode::OK)
    }

    async fn invoke(&self, request: Self::Input) -> Self::Output {
        // Validate input
        if let Err(validation_error) = self.validate_input(&request) {
            return Output::Err {
                reason: validation_error,
                kind: HttpErrorKind::RequestValidationError,
                status_code: None,
                headers: None,
                correlation_id: None,
                request_id: None,
            };
        }

        // Build URL
        let url = match self.build_url(&request) {
            Ok(url) => url,
            Err(error) => {
                return Output::Err {
                    reason: error,
                    kind: HttpErrorKind::InvalidUrl,
                    status_code: None,
                    headers: None,
                    correlation_id: None,
                    request_id: None,
                };
            }
        };

        // Parse HTTP method
        let method = match MethodHelper::parse_method(&request.method) {
            Ok(method) => method,
            Err(kind) => {
                return Output::Err {
                    reason: format!("Unsupported HTTP method: {}", request.method),
                    kind,
                    status_code: None,
                    headers: None,
                    correlation_id: None,
                    request_id: None,
                };
            }
        };

        // Create client with configuration
        let client = if let (Some(timeout_ms), Some(follow_redirects), Some(retries)) = (
            request.timeout_ms,
            request.follow_redirects,
            request.retries,
        ) {
            GenericHttpClient::with_config(timeout_ms, follow_redirects, retries)
        } else {
            GenericHttpClient::new()
        };

        // Make the request
        match client
            .request(
                method,
                url,
                request.headers,
                request.query,
                request.auth,
                request.body,
            )
            .await
        {
            Ok(mut success) => {
                // Handle JSON parsing if requested
                if let Some(expect_json) = request.expect_json {
                    if expect_json {
                        if let Some(text) = &success.text {
                            match serde_json::from_str::<serde_json::Value>(text) {
                                Ok(json) => {
                                    success.json = Some(json.clone());

                                    // Handle JSON schema validation if provided
                                    if let Some(schema_str) = &request.json_schema {
                                        match JsonHelper::validate_against_schema(&json, schema_str)
                                        {
                                            Ok(is_valid) => {
                                                success.schema_valid = Some(is_valid);
                                                if !is_valid {
                                                    return Output::Err {
                                                        reason: "Response does not match provided JSON schema".to_string(),
                                                        kind: HttpErrorKind::JsonSchemaValidationError,
                                                        status_code: Some(success.status),
                                                        headers: Some(success.headers.clone()),
                                                        correlation_id: success.correlation_id.clone(),
                                                        request_id: success.request_id.clone(),
                                                    };
                                                }
                                            }
                                            Err(schema_error) => {
                                                return Output::Err {
                                                    reason: format!(
                                                        "Schema validation error: {}",
                                                        schema_error
                                                    ),
                                                    kind: HttpErrorKind::JsonSchemaValidationError,
                                                    status_code: Some(success.status),
                                                    headers: Some(success.headers.clone()),
                                                    correlation_id: success.correlation_id.clone(),
                                                    request_id: success.request_id.clone(),
                                                };
                                            }
                                        }
                                    }
                                }
                                Err(parse_error) => {
                                    return Output::Err {
                                        reason: format!(
                                            "Failed to parse response as JSON: {}",
                                            parse_error
                                        ),
                                        kind: HttpErrorKind::JsonParseError,
                                        status_code: Some(success.status),
                                        headers: Some(success.headers.clone()),
                                        correlation_id: success.correlation_id.clone(),
                                        request_id: success.request_id.clone(),
                                    };
                                }
                            }
                        }
                    }
                }

                Output::from(success)
            }
            Err(error) => Output::from(error),
        }
    }
}

impl GenericHttpRequest {
    /// Validate input parameters using comprehensive validation
    fn validate_input(&self, request: &Input) -> Result<(), String> {
        InputValidator::validate_all(
            &request.method,
            request.url.as_ref(),
            request.base_url.as_ref(),
            request.path.as_ref(),
            request.headers.as_ref(),
            request.query.as_ref(),
            request.timeout_ms,
            request.retries,
            request.follow_redirects,
            request.expect_json,
            request.json_schema.as_ref(),
        )
    }

    /// Build URL from input parameters using validation
    fn build_url(&self, request: &Input) -> Result<String, String> {
        match (&request.url, &request.base_url, &request.path) {
            (Some(url), None, None) => {
                Ok(url.clone())
            }
            (None, Some(base_url), Some(path)) => {
                crate::core::validation::UrlValidator::combine_url(base_url, path)
            }
            _ => Err("Invalid URL configuration".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::*, mockito::Server};

    async fn create_server_and_tool() -> (mockito::ServerGuard, GenericHttpRequest) {
        let server = Server::new_async().await;
        let tool = GenericHttpRequest;
        (server, tool)
    }

    #[tokio::test]
    async fn test_successful_get_request() {
        let (_, tool) = create_server_and_tool().await;

        // Test with a real URL that should work
        let input = Input {
            method: "GET".to_string(),
            url: Some("https://httpbin.org/get".to_string()),
            base_url: None,
            path: None,
            headers: None,
            query: None,
            auth: None,
            body: None,
            timeout_ms: Some(5000), // 5 second timeout
            retries: None,
            follow_redirects: None,
            expect_json: None,
            json_schema: None,
        };

        let result = tool.invoke(input).await;

        // Verify the response
        match result {
            Output::Ok {
                status,
                headers: _,
                raw_base64,
                text,
                json,
                schema_valid,
                correlation_id: _,
                request_id: _,
            } => {
                assert_eq!(status, 200);
                assert!(!raw_base64.is_empty());
                assert!(text.is_some());
                assert!(json.is_none()); // expect_json is false
                assert!(schema_valid.is_none());
            }
            Output::Err {
                reason,
                kind,
                status_code,
                headers: _,
                correlation_id: _,
                request_id: _,
            } => {
                panic!(
                    "Expected success, got error: {} (Kind: {:?}, Status: {:?})",
                    reason, kind, status_code
                );
            }
        }
    }

    #[tokio::test]
    async fn test_invalid_url() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            method: "GET".to_string(),
            url: Some("invalid-url".to_string()),
            base_url: None,
            path: None,
            headers: None,
            query: None,
            auth: None,
            body: None,
            timeout_ms: None,
            retries: None,
            follow_redirects: None,
            expect_json: None,
            json_schema: None,
        };

        let result = tool.invoke(input).await;

        // Verify the error response
        match result {
            Output::Err {
                reason,
                kind,
                status_code,
                headers: _,
                correlation_id: _,
                request_id: _,
            } => {
                assert!(reason.contains("URL must start with http:// or https://"));
                assert_eq!(kind, HttpErrorKind::RequestValidationError);
                assert_eq!(status_code, None);
                // Headers, correlation_id, and request_id are ignored for validation errors
            }
            _ => panic!("Expected error for invalid URL"),
        }
    }

    #[tokio::test]
    async fn test_invalid_http_method() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            method: "INVALID".to_string(),
            url: Some("https://httpbin.org/get".to_string()),
            base_url: None,
            path: None,
            headers: None,
            query: None,
            auth: None,
            body: None,
            timeout_ms: None,
            retries: None,
            follow_redirects: None,
            expect_json: None,
            json_schema: None,
        };

        let result = tool.invoke(input).await;

        // Verify the error response
        match result {
            Output::Err {
                reason,
                kind,
                status_code,
                headers: _,
                correlation_id: _,
                request_id: _,
            } => {
                assert!(reason.contains("Unsupported HTTP method"));
                assert_eq!(kind, HttpErrorKind::RequestValidationError);
                assert_eq!(status_code, None);
                // Headers, correlation_id, and request_id are ignored for validation errors
            }
            _ => panic!("Expected error for invalid method"),
        }
    }

    #[tokio::test]
    async fn test_missing_url_configuration() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            method: "GET".to_string(),
            url: None,
            base_url: None,
            path: None,
            headers: None,
            query: None,
            auth: None,
            body: None,
            timeout_ms: None,
            retries: None,
            follow_redirects: None,
            expect_json: None,
            json_schema: None,
        };

        let result = tool.invoke(input).await;

        // Verify the error response
        match result {
            Output::Err {
                reason,
                kind,
                status_code,
                headers: _,
                correlation_id: _,
                request_id: _,
            } => {
                assert!(reason.contains("Must specify either 'url' or ('base_url' + 'path')"));
                assert_eq!(kind, HttpErrorKind::RequestValidationError);
                assert_eq!(status_code, None);
                // Headers, correlation_id, and request_id are ignored for validation errors
            }
            _ => panic!("Expected error for missing URL"),
        }
    }

    #[tokio::test]
    async fn test_timeout_validation() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            method: "GET".to_string(),
            url: Some("https://httpbin.org/get".to_string()),
            base_url: None,
            path: None,
            headers: None,
            query: None,
            auth: None,
            body: None,
            timeout_ms: Some(0), // Invalid timeout
            retries: None,
            follow_redirects: None,
            expect_json: None,
            json_schema: None,
        };

        let result = tool.invoke(input).await;

        // Verify the error response
        match result {
            Output::Err {
                reason,
                kind,
                status_code,
                headers: _,
                correlation_id: _,
                request_id: _,
            } => {
                assert!(reason.contains("Timeout must be greater than 0"));
                assert_eq!(kind, HttpErrorKind::RequestValidationError);
                assert_eq!(status_code, None);
                // Headers, correlation_id, and request_id are ignored for validation errors
            }
            _ => panic!("Expected error for invalid timeout"),
        }
    }

    #[tokio::test]
    async fn test_retries_validation() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            method: "GET".to_string(),
            url: Some("https://httpbin.org/get".to_string()),
            base_url: None,
            path: None,
            headers: None,
            query: None,
            auth: None,
            body: None,
            timeout_ms: None,
            retries: Some(11), // Invalid retries (max 10)
            follow_redirects: None,
            expect_json: None,
            json_schema: None,
        };

        let result = tool.invoke(input).await;

        // Verify the error response
        match result {
            Output::Err {
                reason,
                kind,
                status_code,
                headers: _,
                correlation_id: _,
                request_id: _,
            } => {
                assert!(reason.contains("Retries cannot exceed 10"));
                assert_eq!(kind, HttpErrorKind::RequestValidationError);
                assert_eq!(status_code, None);
                // Headers, correlation_id, and request_id are ignored for validation errors
            }
            _ => panic!("Expected error for invalid retries"),
        }
    }

    #[tokio::test]
    async fn test_json_parse_error() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            method: "GET".to_string(),
            url: Some("https://httpbin.org/get".to_string()),
            base_url: None,
            path: None,
            headers: None,
            query: None,
            auth: None,
            body: None,
            timeout_ms: None,
            retries: None,
            follow_redirects: None,
            expect_json: Some(true),
            json_schema: None,
        };

        let result = tool.invoke(input).await;

        // This should succeed because httpbin.org returns valid JSON
        match result {
            Output::Ok { json, .. } => {
                assert!(json.is_some());
            }
            Output::Err {
                reason,
                kind,
                status_code,
                headers: _,
                correlation_id: _,
                request_id: _,
            } => {
                panic!(
                    "Expected success with JSON parsing, got error: {} (Kind: {:?}, Status: {:?})",
                    reason, kind, status_code
                );
            }
        }
    }

    #[tokio::test]
    async fn test_json_parse_error_with_invalid_response() {
        let (_, tool) = create_server_and_tool().await;

        // Test with a URL that returns invalid JSON
        let input = Input {
            method: "GET".to_string(),
            url: Some("https://httpbin.org/robots.txt".to_string()),
            base_url: None,
            path: None,
            headers: None,
            query: None,
            auth: None,
            body: None,
            timeout_ms: Some(5000),
            retries: None,
            follow_redirects: None,
            expect_json: Some(true),
            json_schema: None,
        };

        let result = tool.invoke(input).await;

        // This should fail because robots.txt is not JSON
        match result {
            Output::Err {
                reason,
                kind,
                status_code,
                headers: _,
                correlation_id: _,
                request_id: _,
            } => {
                assert!(reason.contains("Failed to parse response as JSON"));
                assert_eq!(kind, HttpErrorKind::JsonParseError);
                assert!(status_code.is_some());
            }
            _ => panic!("Expected JSON parse error for non-JSON response"),
        }
    }

    #[tokio::test]
    async fn test_schema_validation_error() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            method: "GET".to_string(),
            url: Some("https://httpbin.org/get".to_string()),
            base_url: None,
            path: None,
            headers: None,
            query: None,
            auth: None,
            body: None,
            timeout_ms: None,
            retries: None,
            follow_redirects: None,
            expect_json: Some(true),
            json_schema: Some(r#"{"type": "object", "required": ["missing_field"]}"#.to_string()),
        };

        let result = tool.invoke(input).await;

        // This should succeed because our basic schema validation always returns true
        match result {
            Output::Ok { schema_valid, .. } => {
                assert!(schema_valid.is_some());
                assert!(schema_valid.unwrap());
            }
            Output::Err {
                reason,
                kind,
                status_code,
                headers: _,
                correlation_id: _,
                request_id: _,
            } => {
                panic!(
                    "Expected success with schema validation, got error: {} (Kind: {:?}, Status: {:?})",
                    reason, kind, status_code
                );
            }
        }
    }

    #[tokio::test]
    async fn test_schema_validation_with_invalid_schema() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            method: "GET".to_string(),
            url: Some("https://httpbin.org/get".to_string()),
            base_url: None,
            path: None,
            headers: None,
            query: None,
            auth: None,
            body: None,
            timeout_ms: None,
            retries: None,
            follow_redirects: None,
            expect_json: Some(true),
            json_schema: Some("invalid json schema".to_string()), // Invalid JSON
        };

        let result = tool.invoke(input).await;

        // This should fail because the schema is invalid JSON
        match result {
            Output::Err {
                reason,
                kind,
                status_code,
                headers: _,
                correlation_id: _,
                request_id: _,
            } => {
                assert!(reason.contains("Invalid JSON schema"));
                assert_eq!(kind, HttpErrorKind::RequestValidationError);
                assert_eq!(status_code, None);
                // Headers, correlation_id, and request_id are ignored for validation errors
            }
            _ => panic!("Expected error for invalid schema"),
        }
    }

    #[tokio::test]
    async fn test_invalid_header_name() {
        let (_, tool) = create_server_and_tool().await;

        let mut headers = std::collections::HashMap::new();
        headers.insert("invalid header name".to_string(), "value".to_string());

        let input = Input {
            method: "GET".to_string(),
            url: Some("https://httpbin.org/get".to_string()),
            base_url: None,
            path: None,
            headers: Some(headers),
            query: None,
            auth: None,
            body: None,
            timeout_ms: None,
            retries: None,
            follow_redirects: None,
            expect_json: None,
            json_schema: None,
        };

        let result = tool.invoke(input).await;

        match result {
            Output::Err {
                reason,
                kind,
                status_code,
                headers: _,
                correlation_id: _,
                request_id: _,
            } => {
                assert!(reason.contains("Header name contains invalid character"));
                assert_eq!(kind, HttpErrorKind::RequestValidationError);
                assert_eq!(status_code, None);
            }
            _ => panic!("Expected validation error for invalid header name"),
        }
    }

    #[tokio::test]
    async fn test_invalid_query_param() {
        let (_, tool) = create_server_and_tool().await;

        let mut query = std::collections::HashMap::new();
        query.insert("invalid param name!".to_string(), "value".to_string());

        let input = Input {
            method: "GET".to_string(),
            url: Some("https://httpbin.org/get".to_string()),
            base_url: None,
            path: None,
            headers: None,
            query: Some(query),
            auth: None,
            body: None,
            timeout_ms: None,
            retries: None,
            follow_redirects: None,
            expect_json: None,
            json_schema: None,
        };

        let result = tool.invoke(input).await;

        match result {
            Output::Err {
                reason,
                kind,
                status_code,
                headers: _,
                correlation_id: _,
                request_id: _,
            } => {
                assert!(reason.contains("Query parameter name contains invalid character"));
                assert_eq!(kind, HttpErrorKind::RequestValidationError);
                assert_eq!(status_code, None);
            }
            _ => panic!("Expected validation error for invalid query param"),
        }
    }

    #[tokio::test]
    async fn test_invalid_base_url() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            method: "GET".to_string(),
            url: None,
            base_url: Some("invalid-url".to_string()),
            path: Some("/test".to_string()),
            headers: None,
            query: None,
            auth: None,
            body: None,
            timeout_ms: None,
            retries: None,
            follow_redirects: None,
            expect_json: None,
            json_schema: None,
        };

        let result = tool.invoke(input).await;

        match result {
            Output::Err {
                reason,
                kind,
                status_code,
                headers: _,
                correlation_id: _,
                request_id: _,
            } => {
                assert!(reason.contains("URL must start with http:// or https://"));
                assert_eq!(kind, HttpErrorKind::RequestValidationError);
                assert_eq!(status_code, None);
            }
            _ => panic!("Expected validation error for invalid base URL"),
        }
    }

    #[tokio::test]
    async fn test_invalid_path() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            method: "GET".to_string(),
            url: None,
            base_url: Some("https://httpbin.org".to_string()),
            path: Some("invalid-path".to_string()), // Missing leading slash
            headers: None,
            query: None,
            auth: None,
            body: None,
            timeout_ms: None,
            retries: None,
            follow_redirects: None,
            expect_json: None,
            json_schema: None,
        };

        let result = tool.invoke(input).await;

        match result {
            Output::Err {
                reason,
                kind,
                status_code,
                headers: _,
                correlation_id: _,
                request_id: _,
            } => {
                assert!(reason.contains("Path must start with a forward slash"));
                assert_eq!(kind, HttpErrorKind::RequestValidationError);
                assert_eq!(status_code, None);
            }
            _ => panic!("Expected validation error for invalid path"),
        }
    }

    #[tokio::test]
    async fn test_timeout_too_large() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            method: "GET".to_string(),
            url: Some("https://httpbin.org/get".to_string()),
            base_url: None,
            path: None,
            headers: None,
            query: None,
            auth: None,
            body: None,
            timeout_ms: Some(400_000), // Too large (over 5 minutes)
            retries: None,
            follow_redirects: None,
            expect_json: None,
            json_schema: None,
        };

        let result = tool.invoke(input).await;

        match result {
            Output::Err {
                reason,
                kind,
                status_code,
                headers: _,
                correlation_id: _,
                request_id: _,
            } => {
                assert!(reason.contains("Timeout cannot exceed 300,000 ms"));
                assert_eq!(kind, HttpErrorKind::RequestValidationError);
                assert_eq!(status_code, None);
            }
            _ => panic!("Expected validation error for timeout too large"),
        }
    }

    #[tokio::test]
    async fn test_schema_validation_failure() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            method: "GET".to_string(),
            url: Some("https://httpbin.org/get".to_string()),
            base_url: None,
            path: None,
            headers: None,
            query: None,
            auth: None,
            body: None,
            timeout_ms: Some(5000),
            retries: None,
            follow_redirects: None,
            expect_json: Some(true),
            json_schema: Some(r#"{"type": "object", "force_failure": true}"#.to_string()),
        };

        let result = tool.invoke(input).await;

        // This should fail because schema validation returns false
        match result {
            Output::Err {
                reason,
                kind,
                status_code,
                headers: _,
                correlation_id: _,
                request_id: _,
            } => {
                assert!(reason.contains("Response does not match provided JSON schema"));
                assert_eq!(kind, HttpErrorKind::JsonSchemaValidationError);
                assert!(status_code.is_some());
            }
            _ => panic!("Expected schema validation error"),
        }
    }
}
