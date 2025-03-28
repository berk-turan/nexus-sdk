//! # `xyz.taluslabs.social.twitter.get-tweet@1`
//!
//! Standard Nexus Tool that retrieves a single tweet from the Twitter API.

use {
    crate::{
        error::{parse_twitter_response, TwitterResult},
        tweet::{
            models::{GetTweetResponse, Includes, Meta, Tweet},
            TWITTER_API_BASE,
        },
    },
    nexus_sdk::{fqn, ToolFqn},
    nexus_toolkit::*,
    reqwest::Client,
    schemars::JsonSchema,
    serde::{Deserialize, Serialize},
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
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<Tweet>,
        #[serde(skip_serializing_if = "Option::is_none")]
        includes: Option<Includes>,
        #[serde(skip_serializing_if = "Option::is_none")]
        meta: Option<Meta>,
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
        "/get-tweet"
    }

    async fn health(&self) -> AnyResult<StatusCode> {
        Ok(StatusCode::OK)
    }

    async fn invoke(&self, request: Self::Input) -> Self::Output {
        let client = Client::new();

        // Add authentication header
        let url = format!("{}/{}", self.api_base, request.tweet_id);

        // Make the request
        match self.fetch_tweet(&client, &url, &request.bearer_token).await {
            Ok(response) => Output::Ok {
                data: response.data,
                includes: response.includes,
                meta: response.meta,
            },
            Err(e) => Output::Err {
                reason: e.to_string(),
            },
        }
    }
}

impl GetTweet {
    /// Fetch tweet from Twitter API
    async fn fetch_tweet(
        &self,
        client: &Client,
        url: &str,
        bearer_token: &str,
    ) -> TwitterResult<GetTweetResponse> {
        let response = client
            .get(url)
            .header("Authorization", format!("Bearer {}", bearer_token))
            .send()
            .await?;

        parse_twitter_response::<GetTweetResponse>(response).await
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
            Output::Ok {
                data,
                includes: _,
                meta: _,
            } => {
                if let Some(tweet) = data {
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
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/tweets/test_tweet_id")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "errors": [
                        {
                            "value": "test_tweet_id",
                            "detail": "Could not find tweet with id: [test_tweet_id].",
                            "title": "Not Found Error",
                            "type": "https://api.twitter.com/2/problems/resource-not-found"
                        }
                    ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        let output = tool.invoke(create_test_input()).await;

        match output {
            Output::Err { reason } => {
                assert!(
                    reason.contains("Not Found Error"),
                    "Expected error message to contain 'Not Found Error', got: {}",
                    reason
                );
                assert!(
                    reason.contains("Could not find tweet with id"),
                    "Expected error message to contain tweet ID details, got: {}",
                    reason
                );
            }
            Output::Ok { .. } => panic!("Expected error, got success"),
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_tweet_unauthorized() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/tweets/test_tweet_id")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "errors": [{
                        "message": "Unauthorized",
                        "code": 32
                    }]
                })
                .to_string(),
            )
            .create_async()
            .await;

        let output = tool.invoke(create_test_input()).await;

        match output {
            Output::Err { reason } => {
                assert!(
                    reason.contains("Unauthorized"),
                    "Expected error message to contain 'Unauthorized', got: {}",
                    reason
                );
            }
            Output::Ok { .. } => panic!("Expected error, got success"),
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_tweet_rate_limit() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/tweets/test_tweet_id")
            .match_header("Authorization", "Bearer test_bearer_token")
            .match_query(mockito::Matcher::Any)
            .with_status(429)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "errors": [{
                        "message": "Rate limit exceeded",
                        "code": 88
                    }]
                })
                .to_string(),
            )
            .create_async()
            .await;

        let output = tool.invoke(create_test_input()).await;

        match output {
            Output::Err { reason } => {
                assert!(
                    reason.contains("Rate limit exceeded"),
                    "Expected error message to contain 'Rate limit exceeded', got: {}",
                    reason
                );
            }
            Output::Ok { .. } => panic!("Expected error, got success"),
        }

        mock.assert_async().await;
    }
}
