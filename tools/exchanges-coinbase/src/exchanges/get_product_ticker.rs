//! # `xyz.taluslabs.exchanges.coinbase.get-product-ticker@1`
//!
//! Standard Nexus Tool that retrieves the current ticker information for a product from Coinbase Exchange API.

use {
    crate::{
        coinbase_client::CoinbaseClient,
        exchanges::{models::ProductTickerData, COINBASE_EXCHANGE_API_BASE},
    },
    nexus_sdk::{fqn, ToolFqn},
    nexus_toolkit::*,
    schemars::JsonSchema,
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    /// Product ID (currency pair) to get ticker for (e.g., "BTC-USD", "ETH-EUR")
    product_id: String,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Output {
    Ok {
        /// Best ask price
        ask: String,
        /// Best bid price
        bid: String,
        /// 24h volume
        volume: String,
        /// Trade ID of the last trade
        trade_id: u64,
        /// Last trade price
        price: String,
        /// Last trade size
        size: String,
        /// Time of the last trade
        time: String,
        /// RFQ volume
        rfq_volume: String,
        /// Conversions volume (only included if present)
        #[serde(skip_serializing_if = "Option::is_none")]
        conversions_volume: Option<String>,
    },
    Err {
        /// Error message if the request failed
        reason: String,
    },
}

pub(crate) struct GetProductTicker {
    client: CoinbaseClient,
}

impl NexusTool for GetProductTicker {
    type Input = Input;
    type Output = Output;

    async fn new() -> Self {
        let client = CoinbaseClient::new(Some(COINBASE_EXCHANGE_API_BASE));
        Self { client }
    }

    fn fqn() -> ToolFqn {
        fqn!("xyz.taluslabs.exchanges.coinbase.get-product-ticker@1")
    }

    fn path() -> &'static str {
        "/get-product-ticker"
    }

    async fn health(&self) -> AnyResult<StatusCode> {
        Ok(StatusCode::OK)
    }

    async fn invoke(&self, request: Self::Input) -> Self::Output {
        // Validate product_id
        if request.product_id.is_empty() {
            return Output::Err {
                reason: "Product ID cannot be empty".to_string(),
            };
        }

        // Create the endpoint path
        let endpoint = format!("products/{}/ticker", request.product_id);

        // Make the API request using the client
        match self.client.get::<ProductTickerData>(&endpoint).await {
            Ok(ticker_data) => Output::Ok {
                ask: ticker_data.ask,
                bid: ticker_data.bid,
                volume: ticker_data.volume,
                trade_id: ticker_data.trade_id,
                price: ticker_data.price,
                size: ticker_data.size,
                time: ticker_data.time,
                rfq_volume: ticker_data.rfq_volume,
                conversions_volume: ticker_data.conversions_volume,
            },
            Err(error_response) => Output::Err {
                reason: error_response.reason,
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

    async fn create_server_and_tool() -> (mockito::ServerGuard, GetProductTicker) {
        let server = Server::new_async().await;
        let client = CoinbaseClient::new(Some(&server.url()));
        let tool = GetProductTicker { client };
        (server, tool)
    }

    fn create_test_input() -> Input {
        Input {
            product_id: "BTC-USD".to_string(),
        }
    }

    #[tokio::test]
    async fn test_successful_ticker_request() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock response
        let mock = server
            .mock("GET", "/products/BTC-USD/ticker")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "ask": "6267.71",
                    "bid": "6265.15",
                    "volume": "53602.03940154",
                    "trade_id": 86326522,
                    "price": "6268.48",
                    "size": "0.00698254",
                    "time": "2020-03-20T00:22:57.833Z",
                    "rfq_volume": "123.122"
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Test the ticker request
        let result = tool.invoke(create_test_input()).await;

        // Verify the response
        match result {
            Output::Ok {
                ask,
                bid,
                volume,
                trade_id,
                price,
                size,
                time,
                rfq_volume,
                conversions_volume,
            } => {
                assert_eq!(ask, "6267.71");
                assert_eq!(bid, "6265.15");
                assert_eq!(volume, "53602.03940154");
                assert_eq!(trade_id, 86326522);
                assert_eq!(price, "6268.48");
                assert_eq!(size, "0.00698254");
                assert_eq!(time, "2020-03-20T00:22:57.833Z");
                assert_eq!(rfq_volume, "123.122");
                assert_eq!(conversions_volume, None);
            }
            Output::Err { reason } => panic!("Expected success, got error: {}", reason),
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_empty_product_id() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            product_id: "".to_string(),
        };

        let result = tool.invoke(input).await;

        match result {
            Output::Ok { .. } => panic!("Expected error, got success"),
            Output::Err { reason } => {
                assert_eq!(reason, "Product ID cannot be empty");
            }
        }
    }

    #[tokio::test]
    async fn test_api_error() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock for API error response
        let mock = server
            .mock("GET", "/products/INVALID-PAIR/ticker")
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "message": "Invalid product ID"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let input = Input {
            product_id: "INVALID-PAIR".to_string(),
        };

        // Test the ticker request
        let result = tool.invoke(input).await;

        // Verify the error response
        match result {
            Output::Ok { .. } => panic!("Expected error, got success"),
            Output::Err { reason } => {
                assert!(reason.contains("API error") || reason.contains("Invalid"));
            }
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }

    #[test]
    fn test_deserialize_input() {
        let json = serde_json::json!({
            "product_id": "ETH-EUR"
        });
        let input: Input = serde_json::from_value(json).expect("Failed to deserialize");
        assert_eq!(input.product_id, "ETH-EUR");
    }

    #[tokio::test]
    async fn test_ticker_with_conversions_volume() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock response with conversions_volume
        let mock = server
            .mock("GET", "/products/BTC-USD/ticker")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "ask": "6267.71",
                    "bid": "6265.15",
                    "volume": "53602.03940154",
                    "trade_id": 86326522,
                    "price": "6268.48",
                    "size": "0.00698254",
                    "time": "2020-03-20T00:22:57.833Z",
                    "rfq_volume": "123.122",
                    "conversions_volume": "0.00"
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Test the ticker request
        let result = tool.invoke(create_test_input()).await;

        // Verify the response
        match result {
            Output::Ok {
                ask,
                bid,
                volume,
                trade_id,
                price,
                size,
                time,
                rfq_volume,
                conversions_volume,
            } => {
                assert_eq!(ask, "6267.71");
                assert_eq!(bid, "6265.15");
                assert_eq!(volume, "53602.03940154");
                assert_eq!(trade_id, 86326522);
                assert_eq!(price, "6268.48");
                assert_eq!(size, "0.00698254");
                assert_eq!(time, "2020-03-20T00:22:57.833Z");
                assert_eq!(rfq_volume, "123.122");
                assert_eq!(conversions_volume, Some("0.00".to_string()));
            }
            Output::Err { reason } => panic!("Expected success, got error: {}", reason),
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }
}
