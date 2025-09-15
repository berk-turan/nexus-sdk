//! Generic HTTP client for making requests to any API

use {
    crate::{
        auth::AuthConfig,
        models::{BodyConfig, HttpError, HttpResult, HttpSuccess},
        utils::helpers::ResponseHelper,
    },
    reqwest::{header::HeaderValue, Client, ClientBuilder, Method},
    std::{collections::HashMap, time::Duration},
};

/// Generic HTTP client that can make requests to any API
pub struct GenericHttpClient {
    client: Client,
}

impl GenericHttpClient {
    /// Create a new HTTP client with default configuration
    pub fn new() -> Self {
        let client = ClientBuilder::new()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::default())
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }

    /// Create a new HTTP client with custom configuration
    pub fn with_config(timeout_ms: u64, follow_redirects: bool, _retries: u32) -> Self {
        let mut builder = ClientBuilder::new().timeout(Duration::from_millis(timeout_ms));

        if !follow_redirects {
            builder = builder.redirect(reqwest::redirect::Policy::none());
        }

        let client = builder.build().expect("Failed to create HTTP client");

        Self { client }
    }

    /// Make an HTTP request
    pub async fn request(
        &self,
        method: Method,
        url: String,
        headers: Option<HashMap<String, String>>,
        query: Option<HashMap<String, String>>,
        auth: Option<AuthConfig>,
        body: Option<BodyConfig>,
    ) -> HttpResult {
        let mut request_builder = self.client.request(method, &url);

        // Add headers
        if let Some(headers) = headers {
            for (key, value) in headers {
                if let (Ok(header_name), Ok(header_value)) = (
                    key.parse::<reqwest::header::HeaderName>(),
                    value.parse::<HeaderValue>(),
                ) {
                    request_builder = request_builder.header(header_name, header_value);
                }
            }
        }

        // Add query parameters
        if let Some(query) = query {
            request_builder = request_builder.query(&query);
        }

        // Add authentication
        if let Some(auth) = auth {
            request_builder = match auth {
                crate::auth::AuthConfig::None => request_builder,
                crate::auth::AuthConfig::Bearer { token } => {
                    if let Ok(header_value) = HeaderValue::from_str(&format!("Bearer {}", token)) {
                        request_builder.header("Authorization", header_value)
                    } else {
                        request_builder
                    }
                }
                crate::auth::AuthConfig::ApiKey {
                    key,
                    location,
                    name,
                } => match location.as_str() {
                    "header" => {
                        if let Ok(header_value) = HeaderValue::from_str(&key) {
                            request_builder.header(&name, header_value)
                        } else {
                            request_builder
                        }
                    }
                    "query" => {
                        let mut query_params = HashMap::new();
                        query_params.insert(name, key);
                        request_builder.query(&query_params)
                    }
                    _ => request_builder,
                },
                crate::auth::AuthConfig::Basic { username, password } => {
                    let credentials = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        format!("{}:{}", username, password),
                    );
                    if let Ok(header_value) =
                        HeaderValue::from_str(&format!("Basic {}", credentials))
                    {
                        request_builder.header("Authorization", header_value)
                    } else {
                        request_builder
                    }
                }
            };
        }

        // Add body
        if let Some(body) = body {
            request_builder = body.apply(request_builder);
        }

        // Execute request
        match request_builder.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let headers = ResponseHelper::extract_headers_from_response(&response);

                // Check if response is successful
                if response.status().is_success() {
                    match response.bytes().await {
                        Ok(bytes) => {
                            let raw_base64 = base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                &bytes,
                            );

                            // Try to extract text if valid UTF-8
                            let text = String::from_utf8(bytes.to_vec()).ok();

                            Ok(HttpSuccess {
                                status,
                                headers: headers.clone(),
                                raw_base64,
                                text,
                                json: None,         // Will be set later if needed
                                schema_valid: None, // Will be set later if needed
                                correlation_id: ResponseHelper::extract_correlation_id(&headers),
                                request_id: ResponseHelper::extract_request_id(&headers),
                            })
                        }
                        Err(e) => Err(HttpError::Network {
                            reason: format!("Failed to read response body: {}", e),
                        }),
                    }
                } else {
                    // Handle HTTP error responses
                    let error_text = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    Err(HttpError::Http {
                        reason: format!("HTTP error: {}", error_text),
                        status,
                    })
                }
            }
            Err(e) => {
                if e.is_timeout() {
                    Err(HttpError::Network {
                        reason: "Request timeout".to_string(),
                    })
                } else if e.is_connect() {
                    Err(HttpError::Network {
                        reason: "Connection failed".to_string(),
                    })
                } else {
                    Err(HttpError::Network {
                        reason: format!("Network error: {}", e),
                    })
                }
            }
        }
    }
}

impl Default for GenericHttpClient {
    fn default() -> Self {
        Self::new()
    }
}
