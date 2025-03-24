//! # `xyz.taluslabs.social.twitter.single-tweet@1`
//!
//! Standard Nexus Tool that retrieves a single tweet from the Twitter API.
//!
//! ## Input
//!
//! - `bearer_token`: [`String`] - The bearer token for the user's Twitter account.
//! - `tweet_id`: [`String`] - The ID of the tweet to retrieve.
//!
//! ## Output
//!
//! - `ok` - The tweet was retrieved successfully.
//! - `err` - The tweet was not retrieved due to an error.
//!
//! ## Output Ports
//!
//! ### `ok`
//!
//! - `result`: [`SingleTweetResponse`] - The tweet data.
//!
//! ### `err`
//!
//! - `reason`: [`String`] - The reason the tweet was not retrieved.
//!

use ::{ nexus_toolkit::*, nexus_types::*, schemars::JsonSchema, serde::{ Deserialize, Serialize } };

use reqwest::Client;

use crate::twitter::TWITTER_API_BASE;
use crate::twitter::models::SingleTweetResponse;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    /// Bearer Token for user's Twitter account
    bearer_token: String,
    /// Tweet ID to retrieve
    tweet_id: String,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Output {
    Ok {
        /// The successful tweet response data
        result: SingleTweetResponse,
    },
    Err {
        /// Error message if the tweet failed
        reason: String,
    },
}

pub(crate) struct SingleTweet {
    api_base: String,
}

impl NexusTool for SingleTweet {
    type Input = Input;
    type Output = Output;

    async fn new() -> Self {
        Self {
            api_base: TWITTER_API_BASE.to_string() + "/tweets",
        }
    }

    fn fqn() -> ToolFqn {
        fqn!("xyz.taluslabs.social.twitter.single-tweet@1")
    }

    fn path() -> &'static str {
        "/twitter/single-tweet"
    }

    async fn health(&self) -> AnyResult<StatusCode> {
        Ok(StatusCode::OK)
    }

    async fn invoke(&self, request: Self::Input) -> Self::Output {
        let client = Client::new();

        // Add authentication header
        let url = format!("{}/{}", self.api_base, request.tweet_id);

        // Make the request
        match
            client
                .get(&url)
                .header("Authorization", format!("Bearer {}", request.bearer_token))
                .send().await
        {
            Ok(response) => {
                // Check if response is successful
                if !response.status().is_success() {
                    return Output::Err {
                        reason: format!("Twitter API returned error status: {}", response.status()),
                    };
                }

                // Try to parse response as JSON
                match response.text().await {
                    Ok(text) => {
                        match serde_json::from_str::<SingleTweetResponse>(&text) {
                            Ok(tweets_response) =>
                                Output::Ok {
                                    result: tweets_response,
                                },
                            Err(e) =>
                                Output::Err {
                                    reason: format!("Failed to parse Twitter API response: {}", e),
                                },
                        }
                    }
                    Err(e) =>
                        Output::Err {
                            reason: format!("Failed to read Twitter API response: {}", e),
                        },
                }
            }
            Err(e) =>
                Output::Err {
                    reason: format!("Failed to send request to Twitter API: {}", e),
                },
        }
    }
}
