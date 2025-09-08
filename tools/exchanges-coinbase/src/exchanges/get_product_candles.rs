//! # `xyz.taluslabs.exchanges.coinbase.get-product-candles@1`
//!
//! Standard Nexus Tool that retrieves historical OHLCV candle data for a product from Coinbase Exchange API.

use {
    crate::{
        coinbase_client::CoinbaseClient,
        error::CoinbaseErrorKind,
        exchanges::{
            deserialize_trading_pair,
            models::CandleData,
            COINBASE_EXCHANGE_API_BASE,
        },
    },
    nexus_sdk::{fqn, ToolFqn},
    nexus_toolkit::*,
    schemars::JsonSchema,
    serde::{Deserialize, Serialize},
};

/// Validates granularity value (must be one of the allowed values)
fn validate_granularity(granularity: u32) -> Result<(), String> {
    match granularity {
        60 | 300 | 900 | 3600 | 21600 | 86400 => Ok(()),
        _ => Err(format!(
            "Granularity must be one of: 60 (1min), 300 (5min), 900 (15min), 3600 (1hr), 21600 (6hr), 86400 (1day). Got: {}",
            granularity
        )),
    }
}

/// Validates timestamp format (ISO 8601)
fn validate_timestamp(timestamp: &str) -> Result<(), String> {
    // Basic ISO 8601 format validation
    if timestamp.len() < 19 {
        return Err("Timestamp must be in ISO 8601 format (e.g., '2023-12-01T00:00:00Z')".to_string());
    }
    
    // Check for basic ISO 8601 patterns - must contain 'T' and proper format
    if !timestamp.contains('T') {
        return Err("Timestamp must be in ISO 8601 format (e.g., '2023-12-01T00:00:00Z')".to_string());
    }
    
    // Check for timezone indicator (Z, +offset, or -offset)
    if !timestamp.ends_with('Z') && !timestamp.matches(['+', '-']).any(|_| true) {
        return Err("Timestamp must be in ISO 8601 format (e.g., '2023-12-01T00:00:00Z')".to_string());
    }
    
    // Check that it doesn't use slashes (common mistake)
    if timestamp.contains('/') {
        return Err("Timestamp must be in ISO 8601 format (e.g., '2023-12-01T00:00:00Z')".to_string());
    }
    
    Ok(())
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    /// Product ID (currency pair) to get candles for (e.g., "BTC-USD", "ETH-EUR" or ["BTC", "USD"])
    /// Can also be just the base currency (e.g., "BTC") when quote_currency is provided
    #[serde(deserialize_with = "deserialize_trading_pair")]
    product_id: String,
    /// Optional quote currency (e.g., "USD", "EUR"). When provided, product_id should be just the base currency
    quote_currency: Option<String>,
    /// Optional start timestamp for historical data (ISO 8601 format, e.g., "2023-12-01T00:00:00Z")
    start: Option<String>,
    /// Optional end timestamp for historical data (ISO 8601 format, e.g., "2023-12-01T23:59:59Z")
    end: Option<String>,
    /// Optional granularity in seconds. Must be one of: 60 (1min), 300 (5min), 900 (15min), 3600 (1hr), 21600 (6hr), 86400 (1day)
    granularity: Option<u32>,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Output {
    Ok {
        /// Array of candle data, each containing time, low, high, open, close, volume
        candles: Vec<CandleData>,
    },
    Err {
        /// Detailed error message
        reason: String,
        /// Type of error (network, server, auth, etc.)
        kind: CoinbaseErrorKind,
        /// HTTP status code if available
        #[serde(skip_serializing_if = "Option::is_none")]
        status_code: Option<u16>,
    },
}

pub(crate) struct GetProductCandles {
    client: CoinbaseClient,
}

impl NexusTool for GetProductCandles {
    type Input = Input;
    type Output = Output;

    async fn new() -> Self {
        let client = CoinbaseClient::new(Some(COINBASE_EXCHANGE_API_BASE));
        Self { client }
    }

    fn fqn() -> ToolFqn {
        fqn!("xyz.taluslabs.exchanges.coinbase.get-product-candles@1")
    }

    fn path() -> &'static str {
        "/get-product-candles"
    }

    async fn health(&self) -> AnyResult<StatusCode> {
        Ok(StatusCode::OK)
    }

    async fn invoke(&self, request: Self::Input) -> Self::Output {
        // Validate and construct the final product ID
        let final_product_id = match (&request.product_id, &request.quote_currency) {
            (base, Some(quote)) => {
                // If quote_currency is provided, product_id should be just the base currency
                if base.contains('-') {
                    return Output::Err {
                        reason: "When quote_currency is provided, product_id should be just the base currency (e.g., 'BTC'), not a full pair (e.g., 'BTC-USD')".to_string(),
                        kind: CoinbaseErrorKind::InvalidRequest,
                        status_code: None,
                    };
                }
                if base.is_empty() || quote.is_empty() {
                    return Output::Err {
                        reason: "Both base currency and quote currency must be non-empty"
                            .to_string(),
                        kind: CoinbaseErrorKind::InvalidRequest,
                        status_code: None,
                    };
                }
                format!("{}-{}", base, quote)
            }
            (pair, None) => {
                // If no quote_currency provided, product_id should be a complete pair
                if pair.is_empty() {
                    return Output::Err {
                        reason: "Product ID cannot be empty".to_string(),
                        kind: CoinbaseErrorKind::InvalidRequest,
                        status_code: None,
                    };
                }
                pair.clone()
            }
        };

        // Validate granularity if provided
        if let Some(granularity) = request.granularity {
            if let Err(validation_error) = validate_granularity(granularity) {
                return Output::Err {
                    reason: validation_error,
                    kind: CoinbaseErrorKind::InvalidRequest,
                    status_code: None,
                };
            }
        }

        // Validate timestamps if provided
        if let Some(ref start) = request.start {
            if let Err(validation_error) = validate_timestamp(start) {
                return Output::Err {
                    reason: format!("Invalid start timestamp: {}", validation_error),
                    kind: CoinbaseErrorKind::InvalidRequest,
                    status_code: None,
                };
            }
        }

        if let Some(ref end) = request.end {
            if let Err(validation_error) = validate_timestamp(end) {
                return Output::Err {
                    reason: format!("Invalid end timestamp: {}", validation_error),
                    kind: CoinbaseErrorKind::InvalidRequest,
                    status_code: None,
                };
            }
        }

        // Create the endpoint path
        let mut endpoint = format!("products/{}/candles", final_product_id);
        
        // Build query parameters
        let mut query_params = Vec::new();
        
        if let Some(ref start) = request.start {
            query_params.push(format!("start={}", start));
        }
        
        if let Some(ref end) = request.end {
            query_params.push(format!("end={}", end));
        }
        
        if let Some(granularity) = request.granularity {
            query_params.push(format!("granularity={}", granularity));
        }
        
        if !query_params.is_empty() {
            endpoint.push('?');
            endpoint.push_str(&query_params.join("&"));
        }

        // Make the API request using the client
        // Coinbase returns candles as nested arrays: [[time, low, high, open, close, volume], ...]
        match self.client.get::<Vec<Vec<serde_json::Value>>>(&endpoint).await {
            Ok(raw_candles) => {
                let mut candles = Vec::new();
                
                for (index, raw_candle) in raw_candles.iter().enumerate() {
                    if raw_candle.len() != 6 {
                        return Output::Err {
                            reason: format!("Invalid candle data at index {}: expected 6 values, got {}", index, raw_candle.len()),
                            kind: CoinbaseErrorKind::Parse,
                            status_code: None,
                        };
                    }
                    
                    // Parse each field from the raw array
                    let time = match raw_candle[0].as_u64() {
                        Some(t) => t,
                        None => {
                            return Output::Err {
                                reason: format!("Invalid time value at candle index {}", index),
                                kind: CoinbaseErrorKind::Parse,
                                status_code: None,
                            };
                        }
                    };
                    
                    let low = raw_candle[1].to_string().trim_matches('"').to_string();
                    let high = raw_candle[2].to_string().trim_matches('"').to_string();
                    let open = raw_candle[3].to_string().trim_matches('"').to_string();
                    let close = raw_candle[4].to_string().trim_matches('"').to_string();
                    let volume = raw_candle[5].to_string().trim_matches('"').to_string();
                    
                    candles.push(CandleData {
                        time,
                        low,
                        high,
                        open,
                        close,
                        volume,
                    });
                }
                
                Output::Ok { candles }
            }
            Err(error_response) => Output::Err {
                reason: error_response.reason,
                kind: error_response.kind,
                status_code: error_response.status_code,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        ::{mockito::Server, serde_json::json},
    };

    async fn create_server_and_tool() -> (mockito::ServerGuard, GetProductCandles) {
        let server = Server::new_async().await;
        let client = CoinbaseClient::new(Some(&server.url()));
        let tool = GetProductCandles { client };
        (server, tool)
    }

    fn create_test_input() -> Input {
        Input {
            product_id: "BTC-USD".to_string(),
            quote_currency: None,
            start: None,
            end: None,
            granularity: None,
        }
    }

    fn create_test_input_from_tuple() -> Input {
        // This simulates deserializing from JSON: ["BTC", "USD"]
        let json = serde_json::json!({
            "product_id": ["BTC", "USD"]
        });
        serde_json::from_value(json).expect("Failed to deserialize test input")
    }

    fn create_test_input_with_quote_currency() -> Input {
        Input {
            product_id: "BTC".to_string(),
            quote_currency: Some("USD".to_string()),
            start: None,
            end: None,
            granularity: None,
        }
    }

    fn create_test_input_with_all_params() -> Input {
        Input {
            product_id: "BTC-USD".to_string(),
            quote_currency: None,
            start: Some("2023-12-01T00:00:00Z".to_string()),
            end: Some("2023-12-01T23:59:59Z".to_string()),
            granularity: Some(3600),
        }
    }

    #[tokio::test]
    async fn test_successful_candles_request() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock response
        let mock = server
            .mock("GET", "/products/BTC-USD/candles")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([
                    [1609459200, 29000.50, 30500.75, 29500.00, 30000.25, 150.75],
                    [1609462800, 30000.25, 31200.00, 29800.00, 31000.50, 200.50]
                ])
                .to_string(),
            )
            .create_async()
            .await;

        // Test the candles request
        let result = tool.invoke(create_test_input()).await;

        // Verify the response
        match result {
            Output::Ok { candles } => {
                assert_eq!(candles.len(), 2);
                
                let first_candle = &candles[0];
                assert_eq!(first_candle.time, 1609459200);
                assert_eq!(first_candle.low, "29000.5");
                assert_eq!(first_candle.high, "30500.75");
                assert_eq!(first_candle.open, "29500.0");
                assert_eq!(first_candle.close, "30000.25");
                assert_eq!(first_candle.volume, "150.75");
                
                let second_candle = &candles[1];
                assert_eq!(second_candle.time, 1609462800);
                assert_eq!(second_candle.low, "30000.25");
                assert_eq!(second_candle.high, "31200.0");
                assert_eq!(second_candle.open, "29800.0");
                assert_eq!(second_candle.close, "31000.5");
                assert_eq!(second_candle.volume, "200.5");
            }
            Output::Err {
                reason,
                kind,
                status_code,
            } => panic!(
                "Expected success, got error: {} (Kind: {:?}, Status Code: {:?})",
                reason, kind, status_code
            ),
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_successful_candles_request_with_tuple() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock response
        let mock = server
            .mock("GET", "/products/BTC-USD/candles")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([
                    [1609459200, 29000.50, 30500.75, 29500.00, 30000.25, 150.75]
                ])
                .to_string(),
            )
            .create_async()
            .await;

        // Test the candles request with tuple format
        let result = tool.invoke(create_test_input_from_tuple()).await;

        // Verify the response
        match result {
            Output::Ok { candles } => {
                assert_eq!(candles.len(), 1);
                let candle = &candles[0];
                assert_eq!(candle.time, 1609459200);
                assert_eq!(candle.low, "29000.5");
                assert_eq!(candle.high, "30500.75");
                assert_eq!(candle.open, "29500.0");
                assert_eq!(candle.close, "30000.25");
                assert_eq!(candle.volume, "150.75");
            }
            Output::Err {
                reason,
                kind,
                status_code,
            } => panic!(
                "Expected success, got error: {} (Kind: {:?}, Status Code: {:?})",
                reason, kind, status_code
            ),
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_successful_candles_request_with_quote_currency() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock response
        let mock = server
            .mock("GET", "/products/BTC-USD/candles")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([
                    [1609459200, 29000.50, 30500.75, 29500.00, 30000.25, 150.75]
                ])
                .to_string(),
            )
            .create_async()
            .await;

        // Test the candles request with separate base and quote currencies
        let result = tool.invoke(create_test_input_with_quote_currency()).await;

        // Verify the response
        match result {
            Output::Ok { candles } => {
                assert_eq!(candles.len(), 1);
                let candle = &candles[0];
                assert_eq!(candle.time, 1609459200);
            }
            Output::Err {
                reason,
                kind,
                status_code,
            } => panic!(
                "Expected success, got error: {} (Kind: {:?}, Status Code: {:?})",
                reason, kind, status_code
            ),
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_successful_candles_request_with_all_params() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock response for request with all parameters
        let mock = server
            .mock("GET", "/products/BTC-USD/candles?start=2023-12-01T00:00:00Z&end=2023-12-01T23:59:59Z&granularity=3600")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([
                    [1701388800, 42000.00, 42500.00, 41500.00, 42200.00, 100.50]
                ])
                .to_string(),
            )
            .create_async()
            .await;

        // Test the candles request with all parameters
        let result = tool.invoke(create_test_input_with_all_params()).await;

        // Verify the response
        match result {
            Output::Ok { candles } => {
                assert_eq!(candles.len(), 1);
                let candle = &candles[0];
                assert_eq!(candle.time, 1701388800);
                assert_eq!(candle.low, "42000.0");
                assert_eq!(candle.high, "42500.0");
                assert_eq!(candle.open, "41500.0");
                assert_eq!(candle.close, "42200.0");
                assert_eq!(candle.volume, "100.5");
            }
            Output::Err {
                reason,
                kind,
                status_code,
            } => panic!(
                "Expected success, got error: {} (Kind: {:?}, Status Code: {:?})",
                reason, kind, status_code
            ),
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_empty_product_id() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            product_id: "".to_string(),
            quote_currency: None,
            start: None,
            end: None,
            granularity: None,
        };

        let result = tool.invoke(input).await;

        match result {
            Output::Ok { .. } => panic!("Expected error, got success"),
            Output::Err {
                reason,
                kind,
                status_code,
            } => {
                assert_eq!(reason, "Product ID cannot be empty");
                assert_eq!(kind, CoinbaseErrorKind::InvalidRequest);
                assert_eq!(status_code, None);
            }
        }
    }

    #[tokio::test]
    async fn test_invalid_combination_with_quote_currency() {
        let (_, tool) = create_server_and_tool().await;

        // Test with full product ID and quote_currency (should fail)
        let input = Input {
            product_id: "BTC-USD".to_string(),
            quote_currency: Some("EUR".to_string()),
            start: None,
            end: None,
            granularity: None,
        };

        let result = tool.invoke(input).await;

        match result {
            Output::Ok { .. } => panic!("Expected error, got success"),
            Output::Err {
                reason,
                kind,
                status_code,
            } => {
                assert!(reason.contains("product_id should be just the base currency"));
                assert_eq!(kind, CoinbaseErrorKind::InvalidRequest);
                assert_eq!(status_code, None);
            }
        }
    }

    #[tokio::test]
    async fn test_invalid_granularity() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            product_id: "BTC-USD".to_string(),
            quote_currency: None,
            start: None,
            end: None,
            granularity: Some(123), // Invalid granularity
        };

        let result = tool.invoke(input).await;

        match result {
            Output::Ok { .. } => panic!("Expected error, got success"),
            Output::Err {
                reason,
                kind,
                status_code,
            } => {
                assert!(reason.contains("Granularity must be one of"));
                assert_eq!(kind, CoinbaseErrorKind::InvalidRequest);
                assert_eq!(status_code, None);
            }
        }
    }

    #[tokio::test]
    async fn test_invalid_start_timestamp() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            product_id: "BTC-USD".to_string(),
            quote_currency: None,
            start: Some("invalid-timestamp".to_string()),
            end: None,
            granularity: None,
        };

        let result = tool.invoke(input).await;

        match result {
            Output::Ok { .. } => panic!("Expected error, got success"),
            Output::Err {
                reason,
                kind,
                status_code,
            } => {
                assert!(reason.contains("Invalid start timestamp"));
                assert_eq!(kind, CoinbaseErrorKind::InvalidRequest);
                assert_eq!(status_code, None);
            }
        }
    }

    #[tokio::test]
    async fn test_invalid_end_timestamp() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            product_id: "BTC-USD".to_string(),
            quote_currency: None,
            start: None,
            end: Some("2023/12/01".to_string()),
            granularity: None,
        };

        let result = tool.invoke(input).await;

        match result {
            Output::Ok { .. } => panic!("Expected error, got success"),
            Output::Err {
                reason,
                kind,
                status_code,
            } => {
                assert!(reason.contains("Invalid end timestamp"));
                assert_eq!(kind, CoinbaseErrorKind::InvalidRequest);
                assert_eq!(status_code, None);
            }
        }
    }

    #[tokio::test]
    async fn test_empty_base_currency_with_quote() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            product_id: "".to_string(),
            quote_currency: Some("USD".to_string()),
            start: None,
            end: None,
            granularity: None,
        };

        let result = tool.invoke(input).await;

        match result {
            Output::Ok { .. } => panic!("Expected error, got success"),
            Output::Err {
                reason,
                kind,
                status_code,
            } => {
                assert_eq!(
                    reason,
                    "Both base currency and quote currency must be non-empty"
                );
                assert_eq!(kind, CoinbaseErrorKind::InvalidRequest);
                assert_eq!(status_code, None);
            }
        }
    }

    #[tokio::test]
    async fn test_empty_quote_currency_with_base() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            product_id: "BTC".to_string(),
            quote_currency: Some("".to_string()),
            start: None,
            end: None,
            granularity: None,
        };

        let result = tool.invoke(input).await;

        match result {
            Output::Ok { .. } => panic!("Expected error, got success"),
            Output::Err {
                reason,
                kind,
                status_code,
            } => {
                assert_eq!(
                    reason,
                    "Both base currency and quote currency must be non-empty"
                );
                assert_eq!(kind, CoinbaseErrorKind::InvalidRequest);
                assert_eq!(status_code, None);
            }
        }
    }

    #[tokio::test]
    async fn test_invalid_candle_data_structure() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock response with invalid candle structure (missing fields)
        let mock = server
            .mock("GET", "/products/BTC-USD/candles")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!([
                    [1609459200, 29000.50, 30500.75, 29500.00] // Missing close and volume
                ])
                .to_string(),
            )
            .create_async()
            .await;

        // Test the candles request
        let result = tool.invoke(create_test_input()).await;

        // Verify the error response
        match result {
            Output::Ok { .. } => panic!("Expected error, got success"),
            Output::Err {
                reason,
                kind,
                status_code,
            } => {
                assert!(reason.contains("Invalid candle data at index 0"));
                assert_eq!(kind, CoinbaseErrorKind::Parse);
                assert_eq!(status_code, None);
            }
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }

    #[test]
    fn test_validate_granularity_valid() {
        assert!(validate_granularity(60).is_ok());
        assert!(validate_granularity(300).is_ok());
        assert!(validate_granularity(900).is_ok());
        assert!(validate_granularity(3600).is_ok());
        assert!(validate_granularity(21600).is_ok());
        assert!(validate_granularity(86400).is_ok());
    }

    #[test]
    fn test_validate_granularity_invalid() {
        assert!(validate_granularity(123).is_err());
        assert!(validate_granularity(0).is_err());
        assert!(validate_granularity(1).is_err());
        assert!(validate_granularity(7200).is_err());
    }

    #[test]
    fn test_validate_timestamp_valid() {
        assert!(validate_timestamp("2023-12-01T00:00:00Z").is_ok());
        assert!(validate_timestamp("2023-12-01T12:30:45Z").is_ok());
        assert!(validate_timestamp("2023-12-01T00:00:00+00:00").is_ok());
        assert!(validate_timestamp("2023-12-01T00:00:00-05:00").is_ok());
    }

    #[test]
    fn test_validate_timestamp_invalid() {
        assert!(validate_timestamp("2023-12-01").is_err());
        assert!(validate_timestamp("2023/12/01T00:00:00Z").is_err());
        assert!(validate_timestamp("invalid-timestamp").is_err());
        assert!(validate_timestamp("2023-12-01 00:00:00").is_err());
    }

    #[test]
    fn test_deserialize_product_id_string() {
        let json = serde_json::json!({
            "product_id": "ETH-EUR"
        });
        let input: Input = serde_json::from_value(json).expect("Failed to deserialize");
        assert_eq!(input.product_id, "ETH-EUR");
        assert_eq!(input.quote_currency, None);
    }

    #[test]
    fn test_deserialize_product_id_tuple() {
        let json = serde_json::json!({
            "product_id": ["ETH", "EUR"]
        });
        let input: Input = serde_json::from_value(json).expect("Failed to deserialize");
        assert_eq!(input.product_id, "ETH-EUR");
        assert_eq!(input.quote_currency, None);
    }

    #[test]
    fn test_deserialize_with_all_fields() {
        let json = serde_json::json!({
            "product_id": "BTC-USD",
            "start": "2023-12-01T00:00:00Z",
            "end": "2023-12-01T23:59:59Z",
            "granularity": 3600
        });
        let input: Input = serde_json::from_value(json).expect("Failed to deserialize");
        assert_eq!(input.product_id, "BTC-USD");
        assert_eq!(input.start, Some("2023-12-01T00:00:00Z".to_string()));
        assert_eq!(input.end, Some("2023-12-01T23:59:59Z".to_string()));
        assert_eq!(input.granularity, Some(3600));
    }

    #[test]
    fn test_deserialize_product_id_invalid_tuple_length() {
        let json = serde_json::json!({
            "product_id": ["ETH"]
        });
        let result: Result<Input, _> = serde_json::from_value(json);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("exactly 2 elements"));
    }

    #[test]
    fn test_deserialize_product_id_invalid_tuple_type() {
        let json = serde_json::json!({
            "product_id": ["ETH", 123]
        });
        let result: Result<Input, _> = serde_json::from_value(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be a string"));
    }

    #[test]
    fn test_deserialize_product_id_invalid_type() {
        let json = serde_json::json!({
            "product_id": 123
        });
        let result: Result<Input, _> = serde_json::from_value(json);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be either a string"));
    }
}