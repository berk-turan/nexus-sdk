//! # `xyz.taluslabs.social.twitter.get-tweet@1`
//!
//! Standard Nexus Tool that retrieves a single tweet from the Twitter API.
//!

use ::{
    nexus_toolkit::*,
    nexus_types::*,
    schemars::JsonSchema,
    serde::{Deserialize, Serialize},
};

use reqwest::Client;

use crate::tweet::models::SingleTweetResponse;
use crate::tweet::TWITTER_API_BASE;

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

pub(crate) struct GetTweet {
    api_base: String,
}

impl NexusTool for GetTweet {
    type Input = Input;
    type Output = Output;

    async fn new() -> Self {
        Self {
            api_base: TWITTER_API_BASE.to_string() + "/tweets",
        }
    }

    fn fqn() -> ToolFqn {
        fqn!("xyz.taluslabs.social.twitter.get-tweet@1")
    }

    fn path() -> &'static str {
        "/twitter/get-tweet"
    }

    async fn health(&self) -> AnyResult<StatusCode> {
        Ok(StatusCode::OK)
    }

    async fn invoke(&self, request: Self::Input) -> Self::Output {
        let client = Client::new();

        // Add authentication header
        let url = format!("{}/{}", self.api_base, request.tweet_id);

        // Make the request
        match client
            .get(&url)
            .header("Authorization", format!("Bearer {}", request.bearer_token))
            .send()
            .await
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
                    Ok(text) => match serde_json::from_str::<SingleTweetResponse>(&text) {
                        Ok(tweets_response) => Output::Ok {
                            result: tweets_response,
                        },
                        Err(e) => Output::Err {
                            reason: format!("Failed to parse Twitter API response: {}", e),
                        },
                    },
                    Err(e) => Output::Err {
                        reason: format!("Failed to read Twitter API response: {}", e),
                    },
                }
            }
            Err(e) => Output::Err {
                reason: format!("Failed to send request to Twitter API: {}", e),
            },
        }
    }
}
