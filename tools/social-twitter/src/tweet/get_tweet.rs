//! # `xyz.taluslabs.social.twitter.get-tweet@1`
//!
//! Standard Nexus Tool that retrieves a single tweet from the Twitter API.

use {
    crate::tweet::{models::SingleTweetResponse, TWITTER_API_BASE},
    reqwest::Client,
    ::{
        nexus_sdk::{fqn, ToolFqn},
        nexus_toolkit::*,
        schemars::JsonSchema,
        serde::{Deserialize, Serialize},
    },
};

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

#[cfg(test)]
mod tests {
    use {super::*, ::mockito::Server, serde_json::json};

    impl GetTweet {
        fn with_api_base(api_base: &str) -> Self {
            Self {
                api_base: api_base.to_string(),
            }
        }
    }

    async fn create_server_and_tool() -> (mockito::ServerGuard, GetTweet) {
        let server = Server::new_async().await;
        let tool = GetTweet::with_api_base(&(server.url() + "/tweets"));
        (server, tool)
    }

    fn create_test_input() -> Input {
        Input {
            bearer_token: "test_bearer_token".to_string(),
            tweet_id: "test_tweet_id".to_string(),
        }
    }

    #[tokio::test]
    async fn test_get_tweet_successful() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock response
        let mock = server
            .mock("GET", "/tweets/test_tweet_id")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                   "data": {
                        "author_id": "2244994945",
                        "created_at": "Wed Jan 06 18:40:40 +0000 2021",
                        "id": "1346889436626259968",
                        "text": "Learn how to use the user Tweet timeline and user mention timeline endpoints in the X API v2 to explore Tweet\\u2026 https:\\/\\/t.co\\/56a0vZUx7i",
                        "username": "XDevelopers"
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Test the tweet request
        let output = tool.invoke(create_test_input()).await;

        // Verify the response
        match output {
            Output::Ok { result } => {
                if let Some(tweet) = result.data {
                    assert_eq!(tweet.id, "1346889436626259968");
                    assert_eq!(tweet.text, "Learn how to use the user Tweet timeline and user mention timeline endpoints in the X API v2 to explore Tweet\\u2026 https:\\/\\/t.co\\/56a0vZUx7i");
                } else {
                    panic!("Expected tweet data to be present");
                }
            }
            Output::Err { reason } => panic!("Expected success, got error: {}", reason),
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_tweet_not_found() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock response for not found
        let mock = server
            .mock("GET", "/tweets/test_tweet_id")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "errors": [
                        {
                            "message": "Not Found",
                            "code": 34
                        }
                    ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Test the tweet request
        let output = tool.invoke(create_test_input()).await;

        // Verify the response
        match output {
            Output::Err { reason } => {
                assert!(reason.contains("Not Found"));
            }
            Output::Ok { result } => panic!("Expected error, got success: {:?}", result),
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }
}
