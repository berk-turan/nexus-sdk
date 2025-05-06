//! # `xyz.taluslabs.social.twitter.get-user-followers@1`
//!
//! Standard Nexus Tool that retrieves followers of a user by their ID.

use {
    crate::{
        error::TwitterErrorKind,
        list::models::{Includes, Meta},
        tweet::models::{ExpansionField, TweetField, UserField},
        twitter_client::{TwitterClient, TWITTER_API_BASE},
        user::models::{FollowersByUserIDResponse, UserData},
    },
    nexus_sdk::{fqn, ToolFqn},
    nexus_toolkit::*,
    schemars::JsonSchema,
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    /// Bearer Token for user's Twitter account
    bearer_token: String,

    /// The ID of the User to lookup.
    /// Example: "2244994945"
    user_id: String,

    /// The maximum number of results to return per page
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 100))]
    max_results: Option<i32>,

    /// This parameter is used to get a specified 'page' of results
    #[serde(skip_serializing_if = "Option::is_none")]
    pagination_token: Option<String>,

    /// A comma separated list of User fields to display
    #[serde(skip_serializing_if = "Option::is_none")]
    user_fields: Option<Vec<UserField>>,

    /// A comma separated list of fields to expand
    #[serde(skip_serializing_if = "Option::is_none")]
    expansions_fields: Option<Vec<ExpansionField>>,

    /// A comma separated list of Tweet fields to display
    #[serde(skip_serializing_if = "Option::is_none")]
    tweet_fields: Option<Vec<TweetField>>,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Output {
    Ok {
        /// Array of user data for followers
        followers: Vec<UserData>,

        /// Pagination metadata
        #[serde(skip_serializing_if = "Option::is_none")]
        meta: Option<Meta>,

        /// Includes data
        #[serde(skip_serializing_if = "Option::is_none")]
        includes: Option<Includes>,
    },
    Err {
        /// Type of error (network, server, auth, etc.)
        kind: TwitterErrorKind,
        /// Detailed error message
        reason: String,
        /// HTTP status code if available
        #[serde(skip_serializing_if = "Option::is_none")]
        status_code: Option<u16>,
    },
}

pub(crate) struct GetUserFollowers {
    api_base: String,
}

impl NexusTool for GetUserFollowers {
    type Input = Input;
    type Output = Output;

    async fn new() -> Self {
        Self {
            api_base: TWITTER_API_BASE.to_string(),
        }
    }

    fn fqn() -> ToolFqn {
        fqn!("xyz.taluslabs.social.twitter.get-user-followers@1")
    }

    fn path() -> &'static str {
        "/get-user-followers"
    }

    async fn health(&self) -> AnyResult<StatusCode> {
        Ok(StatusCode::OK)
    }

    async fn invoke(&self, request: Self::Input) -> Self::Output {
        // Build the endpoint for the Twitter API
        let suffix = format!("users/{}/followers", request.user_id);

        // Create a Twitter client with the mock server URL
        let client = match TwitterClient::new(Some(&suffix), Some(&self.api_base)) {
            Ok(client) => client,
            Err(e) => {
                return Output::Err {
                    reason: e.to_string(),
                    kind: TwitterErrorKind::Network,
                    status_code: None,
                }
            }
        };

        // Build query parameters
        let mut query_params = Vec::new();

        // Add max_results if provided
        if let Some(max_results) = request.max_results {
            query_params.push(("max_results".to_string(), max_results.to_string()));
        }

        // Add pagination_token if provided
        if let Some(pagination_token) = &request.pagination_token {
            query_params.push(("pagination_token".to_string(), pagination_token.clone()));
        }

        // Add user fields if provided
        if let Some(user_fields) = request.user_fields {
            let fields: Vec<String> = user_fields
                .iter()
                .map(|f| {
                    serde_json::to_string(f)
                        .unwrap()
                        .replace("\"", "")
                        .to_lowercase()
                })
                .collect();
            query_params.push(("user.fields".to_string(), fields.join(",")));
        }

        // Add expansions if provided
        if let Some(expansions) = request.expansions_fields {
            let fields: Vec<String> = expansions
                .iter()
                .map(|f| {
                    serde_json::to_string(f)
                        .unwrap()
                        .replace("\"", "")
                        .to_lowercase()
                })
                .collect();
            query_params.push(("expansions".to_string(), fields.join(",")));
        }

        // Add tweet fields if provided
        if let Some(tweet_fields) = request.tweet_fields {
            let fields: Vec<String> = tweet_fields
                .iter()
                .map(|f| {
                    serde_json::to_string(f)
                        .unwrap()
                        .replace("\"", "")
                        .to_lowercase()
                })
                .collect();
            query_params.push(("tweet.fields".to_string(), fields.join(",")));
        }

        match client
            .get::<FollowersByUserIDResponse>(request.bearer_token, Some(query_params))
            .await
        {
            Ok((data, includes, meta)) => Output::Ok {
                followers: data,
                includes,
                meta,
            },
            Err(e) => Output::Err {
                reason: e.reason,
                kind: e.kind,
                status_code: e.status_code,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::*, ::mockito::Server, serde_json::json};

    impl GetUserFollowers {
        fn with_api_base(api_base: &str) -> Self {
            Self {
                api_base: api_base.to_string(),
            }
        }
    }

    async fn create_server_and_tool() -> (mockito::ServerGuard, GetUserFollowers) {
        let server = Server::new_async().await;
        let tool = GetUserFollowers::with_api_base(&server.url());
        (server, tool)
    }

    fn create_test_input() -> Input {
        Input {
            bearer_token: "test_bearer_token".to_string(),
            user_id: "2244994945".to_string(),
            max_results: Some(10),
            pagination_token: None,
            user_fields: None,
            expansions_fields: None,
            tweet_fields: None,
        }
    }

    #[tokio::test]
    async fn test_get_followers_successful() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/users/2244994945/followers")
            .match_header("Authorization", "Bearer test_bearer_token")
            .match_query(mockito::Matcher::UrlEncoded(
                "max_results".into(),
                "10".into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "data": [
                        {
                            "id": "1234567890",
                            "name": "Follower 1",
                            "username": "follower1",
                            "protected": false
                        },
                        {
                            "id": "0987654321",
                            "name": "Follower 2",
                            "username": "follower2",
                            "protected": true
                        }
                    ],
                    "meta": {
                        "result_count": 2,
                        "next_token": "next_cursor_value"
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let output = tool.invoke(create_test_input()).await;

        match output {
            Output::Ok {
                followers, meta, ..
            } => {
                assert_eq!(followers.len(), 2);
                assert_eq!(followers[0].id, "1234567890");
                assert_eq!(followers[0].name, "Follower 1");
                assert_eq!(followers[0].username, "follower1");
                assert_eq!(followers[0].protected, Some(false));

                assert_eq!(followers[1].id, "0987654321");
                assert_eq!(followers[1].name, "Follower 2");
                assert_eq!(followers[1].username, "follower2");
                assert_eq!(followers[1].protected, Some(true));

                assert!(meta.is_some());
                if let Some(meta_data) = meta {
                    assert_eq!(meta_data.result_count, Some(2));
                    assert_eq!(meta_data.next_token, Some("next_cursor_value".to_string()));
                }
            }
            Output::Err {
                reason,
                kind: _,
                status_code,
            } => panic!(
                "Expected success, got error: {} ({})",
                reason,
                status_code.unwrap_or(0)
            ),
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_user_not_found() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/users/2244994945/followers")
            .match_header("Authorization", "Bearer test_bearer_token")
            .match_query(mockito::Matcher::UrlEncoded(
                "max_results".into(),
                "10".into(),
            ))
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "errors": [{
                        "message": "User not found",
                        "code": 34
                    }]
                })
                .to_string(),
            )
            .create_async()
            .await;

        let output = tool.invoke(create_test_input()).await;

        match output {
            Output::Err {
                reason,
                kind: _,
                status_code,
            } => {
                assert!(
                    reason.contains("User not found"),
                    "Expected user not found error"
                );
                assert_eq!(status_code, Some(404));
            }
            Output::Ok { .. } => panic!("Expected error, got success"),
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_pagination() {
        let (mut server, tool) = create_server_and_tool().await;

        let mut input = create_test_input();
        input.pagination_token = Some("test_pagination_token".to_string());

        let mock = server
            .mock("GET", "/users/2244994945/followers")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("max_results".into(), "10".into()),
                mockito::Matcher::UrlEncoded(
                    "pagination_token".into(),
                    "test_pagination_token".into(),
                ),
            ]))
            .with_status(200)
            .with_body(
                json!({
                    "data": [
                        {
                            "id": "9876543210",
                            "name": "Follower 3",
                            "username": "follower3"
                        }
                    ],
                    "meta": {
                        "result_count": 1
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let output = tool.invoke(input).await;

        match output {
            Output::Ok { followers, .. } => {
                assert_eq!(followers.len(), 1);
                assert_eq!(followers[0].id, "9876543210");
                assert_eq!(followers[0].name, "Follower 3");
                assert_eq!(followers[0].username, "follower3");
            }
            Output::Err {
                reason,
                kind: _,
                status_code,
            } => panic!(
                "Expected success, got error: {} ({})",
                reason,
                status_code.unwrap_or(0)
            ),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_rate_limit_handling() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/users/2244994945/followers")
            .match_header("Authorization", "Bearer test_bearer_token")
            .match_query(mockito::Matcher::UrlEncoded(
                "max_results".into(),
                "10".into(),
            ))
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
            Output::Err {
                reason,
                kind,
                status_code,
            } => {
                // Check error type
                assert_eq!(
                    kind,
                    TwitterErrorKind::RateLimit,
                    "Expected error kind RateLimit, got: {:?}",
                    kind
                );

                // Check error message
                assert!(
                    reason.contains("Rate limit exceeded"),
                    "Expected error message to contain 'Rate limit exceeded', got: {}",
                    reason
                );

                // Check status code
                assert_eq!(
                    status_code,
                    Some(429),
                    "Expected status code 429, got: {:?}",
                    status_code
                );
            }
            Output::Ok { .. } => panic!("Expected error, got success"),
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_empty_followers() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/users/2244994945/followers")
            .match_header("Authorization", "Bearer test_bearer_token")
            .match_query(mockito::Matcher::UrlEncoded(
                "max_results".into(),
                "10".into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "data": [],
                    "meta": {
                        "result_count": 0
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let output = tool.invoke(create_test_input()).await;

        match output {
            Output::Ok {
                followers, meta, ..
            } => {
                assert_eq!(followers.len(), 0);
                assert!(meta.is_some());
                if let Some(meta_data) = meta {
                    assert_eq!(meta_data.result_count, Some(0));
                }
            }
            Output::Err {
                reason,
                kind: _,
                status_code,
            } => panic!(
                "Expected success, got error: {} ({})",
                reason,
                status_code.unwrap_or(0)
            ),
        }
        mock.assert_async().await;
    }
}
