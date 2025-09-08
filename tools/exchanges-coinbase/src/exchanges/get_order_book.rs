//! # `xyz.taluslabs.exchanges.coinbase.get-order-book@1`
//!
//! Standard Nexus Tool that retrieves order book data (L1/L2/L3) for a product from Coinbase Exchange.

use {
    crate::{
        coinbase_client::CoinbaseClient,
        error::CoinbaseErrorKind,
        exchanges::{
            deserialize_trading_pair,
            models::{OrderBookData, OrderBookLevel},
            COINBASE_EXCHANGE_API_BASE,
        },
    },
    nexus_sdk::{fqn, ToolFqn},
    nexus_toolkit::*,
    schemars::JsonSchema,
    serde::{Deserialize, Serialize},
};

/// Default level function for serde default
fn default_level() -> OrderBookLevel {
    OrderBookLevel::L1
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    /// Product ID to get order book for (e.g., "BTC-USD", "ETH-EUR" or ["BTC", "USD"])
    /// Can also be just the base currency (e.g., "BTC") when quote_currency is provided
    #[serde(deserialize_with = "deserialize_trading_pair")] 
    product_id: String,
    /// Optional quote currency (e.g., "USD", "EUR"). When provided, product_id should be just the base currency
    quote_currency: Option<String>,
    /// Order book level (1, 2, or 3) - defaults to 1 if not provided
    #[serde(default = "default_level")]
    level: OrderBookLevel,
}



#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Output {
    Ok {
        /// Bid orders: [price, size, num_orders/order_id]
        /// L1/L2: num_orders is integer, L3: order_id is string
        bids: Vec<(String, String, serde_json::Value)>,
        /// Ask orders: [price, size, num_orders/order_id]
        /// L1/L2: num_orders is integer, L3: order_id is string
        asks: Vec<(String, String, serde_json::Value)>,
        /// Sequence number for ordering
        sequence: u64,
        /// Auction mode status
        auction_mode: bool,
        /// Auction details (nullable)
        auction: Option<serde_json::Value>,
        /// Response timestamp
        time: String,
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

pub(crate) struct GetOrderBook {
    client: CoinbaseClient,
}

impl NexusTool for GetOrderBook {
    type Input = Input;
    type Output = Output;

    async fn new() -> Self {
        let client = CoinbaseClient::new(Some(COINBASE_EXCHANGE_API_BASE));
        Self { client }
    }

    fn fqn() -> ToolFqn {
        fqn!("xyz.taluslabs.exchanges.coinbase.get-order-book@1")
    }

    fn path() -> &'static str {
        "/get-order-book"
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

        // Construct level parameter
        let level_param = match request.level {
            OrderBookLevel::L1 => "1",
            OrderBookLevel::L2 => "2", 
            OrderBookLevel::L3 => "3",
        };

        // Create endpoint path with level parameter
        let endpoint = format!("products/{}/book?level={}", final_product_id, level_param);

        // Make API request
        match self.client.get::<OrderBookData>(&endpoint).await {
            Ok(order_book_data) => {
                Output::Ok {
                    bids: order_book_data.bids,
                    asks: order_book_data.asks,
                    sequence: order_book_data.sequence,
                    auction_mode: order_book_data.auction_mode,
                    auction: order_book_data.auction,
                    time: order_book_data.time,
                }
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
        ::mockito::Server,
        serde_json::json,
    };

    async fn create_server_and_tool() -> (mockito::ServerGuard, GetOrderBook) {
        let server = Server::new_async().await;
        let client = CoinbaseClient::new(Some(&server.url()));
        let tool = GetOrderBook { client };
        (server, tool)
    }

    fn create_test_input_l1() -> Input {
        Input {
            product_id: "BTC-USD".to_string(),
            quote_currency: None,
            level: OrderBookLevel::L1,
        }
    }

    #[tokio::test]
    async fn test_successful_l1_order_book() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/products/BTC-USD/book?level=1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "bids": [["111043.16", "0.59556416", 2]],
                    "asks": [["111043.17", "0.08721989", 2]],
                    "sequence": 111342351770_u64,
                    "auction_mode": false,
                    "auction": null,
                    "time": "2025-09-04T12:13:49.440575Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let result = tool.invoke(create_test_input_l1()).await;

        match result {
            Output::Ok {
                bids,
                asks,
                sequence,
                auction_mode,
                auction,
                time,
            } => {
                assert_eq!(bids.len(), 1);
                assert_eq!(asks.len(), 1);
                assert_eq!(bids[0], ("111043.16".to_string(), "0.59556416".to_string(), serde_json::json!(2)));
                assert_eq!(asks[0], ("111043.17".to_string(), "0.08721989".to_string(), serde_json::json!(2)));
                assert_eq!(sequence, 111342351770);
                assert_eq!(auction_mode, false);
                assert_eq!(auction, None);
                assert_eq!(time, "2025-09-04T12:13:49.440575Z");
            }
            Output::Err { reason, kind, status_code } => panic!(
                "Expected success, got error: {} (Kind: {:?}, Status Code: {:?})", 
                reason, kind, status_code
            ),
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_successful_l3_order_book() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/products/BTC-USD/book?level=3")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "bids": [
                        ["111043.16", "0.59556416", "cc68d69c-9d3d-4423-b605-233bccb511d5"],
                        ["111043.15", "0.12345678", "1466a601-ec3a-4de5-9f8c-07048103db41"]
                    ],
                    "asks": [
                        ["111043.17", "0.08721989", "fe210c3b-6249-431f-bc50-c881bd53d661"]
                    ],
                    "sequence": 111342351770_u64,
                    "auction_mode": false,
                    "auction": null,
                    "time": "2025-09-04T12:13:49.440575Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let input = Input {
            product_id: "BTC-USD".to_string(),
            quote_currency: None,
            level: OrderBookLevel::L3,
        };

        let result = tool.invoke(input).await;

        match result {
            Output::Ok {
                bids,
                asks,
                sequence,
                auction_mode,
                auction,
                time,
            } => {
                assert_eq!(bids.len(), 2);
                assert_eq!(asks.len(), 1);
                assert_eq!(bids[0], ("111043.16".to_string(), "0.59556416".to_string(), serde_json::json!("cc68d69c-9d3d-4423-b605-233bccb511d5")));
                assert_eq!(bids[1], ("111043.15".to_string(), "0.12345678".to_string(), serde_json::json!("1466a601-ec3a-4de5-9f8c-07048103db41")));
                assert_eq!(asks[0], ("111043.17".to_string(), "0.08721989".to_string(), serde_json::json!("fe210c3b-6249-431f-bc50-c881bd53d661")));
                assert_eq!(sequence, 111342351770);
                assert_eq!(auction_mode, false);
                assert_eq!(auction, None);
                assert_eq!(time, "2025-09-04T12:13:49.440575Z");
            }
            Output::Err { reason, kind, status_code } => panic!(
                "Expected success, got error: {} (Kind: {:?}, Status Code: {:?})", 
                reason, kind, status_code
            ),
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_empty_product_id() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            product_id: "".to_string(),
            quote_currency: None,
            level: OrderBookLevel::L1,
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
    async fn test_optional_level_defaults_to_l1() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/products/BTC-USD/book?level=1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "bids": [["111043.16", "0.59556416", 2]],
                    "asks": [["111043.17", "0.08721989", 2]],
                    "sequence": 111342351770_u64,
                    "auction_mode": false,
                    "auction": null,
                    "time": "2025-09-04T12:13:49.440575Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Test without level field - should default to L1
        let input_json = r#"{"product_id": "BTC-USD"}"#;
        let input: Input = serde_json::from_str(input_json).expect("Should deserialize without level");
        assert_eq!(matches!(input.level, OrderBookLevel::L1), true);

        let result = tool.invoke(input).await;

        match result {
            Output::Ok { bids, asks, .. } => {
                assert_eq!(bids.len(), 1);
                assert_eq!(asks.len(), 1);
            }
            Output::Err { reason, kind, status_code } => panic!(
                "Expected success, got error: {} (Kind: {:?}, Status Code: {:?})", 
                reason, kind, status_code
            ),
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_product_id_with_tuple_format() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/products/BTC-USD/book?level=1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "bids": [["111043.16", "0.59556416", 2]],
                    "asks": [["111043.17", "0.08721989", 2]],
                    "sequence": 111342351770_u64,
                    "auction_mode": false,
                    "auction": null,
                    "time": "2025-09-04T12:13:49.440575Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Test tuple format ["BTC", "USD"]
        let input_json = r#"{"product_id": ["BTC", "USD"]}"#;
        let input: Input = serde_json::from_str(input_json).expect("Should deserialize tuple format");
        assert_eq!(input.product_id, "BTC-USD");

        let result = tool.invoke(input).await;

        match result {
            Output::Ok { bids, asks, .. } => {
                assert_eq!(bids.len(), 1);
                assert_eq!(asks.len(), 1);
            }
            Output::Err { reason, kind, status_code } => panic!(
                "Expected success, got error: {} (Kind: {:?}, Status Code: {:?})", 
                reason, kind, status_code
            ),
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_product_id_with_quote_currency() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/products/BTC-USD/book?level=1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "bids": [["111043.16", "0.59556416", 2]],
                    "asks": [["111043.17", "0.08721989", 2]],
                    "sequence": 111342351770_u64,
                    "auction_mode": false,
                    "auction": null,
                    "time": "2025-09-04T12:13:49.440575Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let input = Input {
            product_id: "BTC".to_string(),
            quote_currency: Some("USD".to_string()),
            level: OrderBookLevel::L1,
        };

        let result = tool.invoke(input).await;

        match result {
            Output::Ok { bids, asks, .. } => {
                assert_eq!(bids.len(), 1);
                assert_eq!(asks.len(), 1);
            }
            Output::Err { reason, kind, status_code } => panic!(
                "Expected success, got error: {} (Kind: {:?}, Status Code: {:?})", 
                reason, kind, status_code
            ),
        }

        mock.assert_async().await;
    }
}