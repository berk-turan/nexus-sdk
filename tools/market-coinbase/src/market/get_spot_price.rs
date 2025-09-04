//! # `xyz.taluslabs.market.coinbase.get-spot-price@1`
//!
//! Standard Nexus Tool that retrieves the current spot price for a currency pair from Coinbase.

use {
    crate::{
        coinbase_client::CoinbaseClient,
        market::{
            models::{CoinbaseApiResponse, SpotPriceData},
            COINBASE_API_BASE,
        },
    },
    nexus_sdk::{fqn, ToolFqn},
    nexus_toolkit::*,
    schemars::JsonSchema,
    serde::{Deserialize, Deserializer, Serialize},
    serde_json::Value,
};

/// Custom deserializer for currency_pair that accepts both string and tuple formats
fn deserialize_currency_pair<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;

    match value {
        Value::String(s) => {
            // Direct string format like "BTC-USD"
            Ok(s)
        }
        Value::Array(arr) => {
            // Tuple format like ["BTC", "USD"]
            if arr.len() == 2 {
                let base = arr[0].as_str().ok_or_else(|| {
                    serde::de::Error::custom("First element of currency pair array must be a string")
                })?;
                let quote = arr[1].as_str().ok_or_else(|| {
                    serde::de::Error::custom("Second element of currency pair array must be a string")
                })?;
                Ok(format!("{}-{}", base, quote))
            } else {
                Err(serde::de::Error::custom("Currency pair array must contain exactly 2 elements"))
            }
        }
        _ => Err(serde::de::Error::custom(
            "Currency pair must be either a string (e.g., 'BTC-USD') or an array of two strings (e.g., ['BTC', 'USD'])"
        )),
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    /// Currency pair to get spot price for (e.g., "BTC-USD", "ETH-EUR" or ["BTC", "USD"])
    #[serde(deserialize_with = "deserialize_currency_pair")]
    currency_pair: String,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Output {
    Ok {
        /// The price amount as a string
        amount: String,
        /// The base currency (e.g., "BTC", "ETH")
        base: String,
        /// The quote currency (e.g., "USD", "USDT")
        currency: String,
    },
    Err {
        /// Error message if the request failed
        reason: String,
    },
}

pub(crate) struct GetSpotPrice {
    client: CoinbaseClient,
}

impl NexusTool for GetSpotPrice {
    type Input = Input;
    type Output = Output;

    async fn new() -> Self {
        let client = CoinbaseClient::new(Some(COINBASE_API_BASE));
        Self { client }
    }

    fn fqn() -> ToolFqn {
        fqn!("xyz.taluslabs.market.coinbase.get-spot-price@1")
    }

    fn path() -> &'static str {
        "/get-spot-price"
    }

    async fn health(&self) -> AnyResult<StatusCode> {
        Ok(StatusCode::OK)
    }

    async fn invoke(&self, request: Self::Input) -> Self::Output {
        // Validate currency pair format
        if request.currency_pair.is_empty() {
            return Output::Err {
                reason: "Currency pair cannot be empty".to_string(),
            };
        }

        // Create the endpoint path
        let endpoint = format!("v2/prices/{}/spot", request.currency_pair);

        // Make the API request using the client
        match self
            .client
            .get::<CoinbaseApiResponse<SpotPriceData>>(&endpoint)
            .await
        {
            Ok(api_response) => {
                // Check for errors in the response
                if let Some(errors) = api_response.errors {
                    if let Some(first_error) = errors.first() {
                        return Output::Err {
                            reason: first_error
                                .error_message
                                .clone()
                                .unwrap_or_else(|| "API error".to_string()),
                        };
                    }
                }

                // Extract the data
                if let Some(data) = api_response.data {
                    Output::Ok {
                        amount: data.amount,
                        base: data.base,
                        currency: data.currency,
                    }
                } else {
                    Output::Err {
                        reason: "No data in API response".to_string(),
                    }
                }
            }
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

    async fn create_server_and_tool() -> (mockito::ServerGuard, GetSpotPrice) {
        let server = Server::new_async().await;
        let client = CoinbaseClient::new(Some(&server.url()));
        let tool = GetSpotPrice { client };
        (server, tool)
    }

    fn create_test_input() -> Input {
        Input {
            currency_pair: "BTC-USD".to_string(),
        }
    }

    fn create_test_input_from_tuple() -> Input {
        // This simulates deserializing from JSON: ["BTC", "USD"]
        let json = serde_json::json!({
            "currency_pair": ["BTC", "USD"]
        });
        serde_json::from_value(json).expect("Failed to deserialize test input")
    }

    #[tokio::test]
    async fn test_successful_spot_price() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock response
        let mock = server
            .mock("GET", "/v2/prices/BTC-USD/spot")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "data": {
                        "amount": "45000.00",
                        "base": "BTC",
                        "currency": "USD"
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Test the spot price request
        let result = tool.invoke(create_test_input()).await;

        // Verify the response
        match result {
            Output::Ok {
                amount,
                base,
                currency,
            } => {
                assert_eq!(amount, "45000.00");
                assert_eq!(base, "BTC");
                assert_eq!(currency, "USD");
            }
            Output::Err { reason } => panic!("Expected success, got error: {}", reason),
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_successful_spot_price_with_tuple() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock response
        let mock = server
            .mock("GET", "/v2/prices/BTC-USD/spot")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "data": {
                        "amount": "45000.00",
                        "base": "BTC",
                        "currency": "USD"
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Test the spot price request with tuple format
        let result = tool.invoke(create_test_input_from_tuple()).await;

        // Verify the response
        match result {
            Output::Ok {
                amount,
                base,
                currency,
            } => {
                assert_eq!(amount, "45000.00");
                assert_eq!(base, "BTC");
                assert_eq!(currency, "USD");
            }
            Output::Err { reason } => panic!("Expected success, got error: {}", reason),
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_empty_currency_pair() {
        let (_, tool) = create_server_and_tool().await;

        let input = Input {
            currency_pair: "".to_string(),
        };

        let result = tool.invoke(input).await;

        match result {
            Output::Ok { .. } => panic!("Expected error, got success"),
            Output::Err { reason } => {
                assert_eq!(reason, "Currency pair cannot be empty");
            }
        }
    }

    #[tokio::test]
    async fn test_api_error() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock for API error response
        let mock = server
            .mock("GET", "/v2/prices/INVALID-PAIR/spot")
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "errors": [{
                        "message": "Invalid currency pair",
                        "type": "invalid_request"
                    }]
                })
                .to_string(),
            )
            .create_async()
            .await;

        let input = Input {
            currency_pair: "INVALID-PAIR".to_string(),
        };

        // Test the spot price request
        let result = tool.invoke(input).await;

        // Verify the error response
        match result {
            Output::Ok { .. } => panic!("Expected error, got success"),
            Output::Err { reason } => {
                assert!(reason.contains("API error"));
            }
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }

    #[test]
    fn test_deserialize_currency_pair_string() {
        let json = serde_json::json!({
            "currency_pair": "ETH-EUR"
        });
        let input: Input = serde_json::from_value(json).expect("Failed to deserialize");
        assert_eq!(input.currency_pair, "ETH-EUR");
    }

    #[test]
    fn test_deserialize_currency_pair_tuple() {
        let json = serde_json::json!({
            "currency_pair": ["ETH", "EUR"]
        });
        let input: Input = serde_json::from_value(json).expect("Failed to deserialize");
        assert_eq!(input.currency_pair, "ETH-EUR");
    }

    #[test]
    fn test_deserialize_currency_pair_invalid_tuple_length() {
        let json = serde_json::json!({
            "currency_pair": ["ETH"]
        });
        let result: Result<Input, _> = serde_json::from_value(json);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("exactly 2 elements"));
    }

    #[test]
    fn test_deserialize_currency_pair_invalid_tuple_type() {
        let json = serde_json::json!({
            "currency_pair": ["ETH", 123]
        });
        let result: Result<Input, _> = serde_json::from_value(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be a string"));
    }

    #[test]
    fn test_deserialize_currency_pair_invalid_type() {
        let json = serde_json::json!({
            "currency_pair": 123
        });
        let result: Result<Input, _> = serde_json::from_value(json);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be either a string"));
    }
}
