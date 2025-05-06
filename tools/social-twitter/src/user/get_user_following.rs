//! # `xyz.taluslabs.social.twitter.get-user-following@1`
//!
//! Standard Nexus Tool that retrieves the users being followed by a specified user ID.

use {
    crate::{
        error::TwitterErrorKind,
        list::models::{Includes, Meta},
        tweet::models::{ExpansionField, TweetField, UserField},
        twitter_client::{TwitterClient, TWITTER_API_BASE},
        user::models::{FollowingByUserIDResponse, UserData},
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

    /// The ID of the User to lookup their following
    /// Example: "2244994945"
    user_id: String,

    /// The maximum number of results to return per page
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 1000))]
    max_results: Option<i32>,

    /// Token for pagination to get the next page of results
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 16))]
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
        /// List of users that the specified user is following
        users: Vec<UserData>,

        /// Expansion objects like tweets, users, etc.
        #[serde(skip_serializing_if = "Option::is_none")]
        includes: Option<Includes>,

        /// Pagination metadata
        #[serde(skip_serializing_if = "Option::is_none")]
        meta: Option<Meta>,
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

pub(crate) struct GetUserFollowing {
    api_base: String,
}

impl NexusTool for GetUserFollowing {
    type Input = Input;
    type Output = Output;

    async fn new() -> Self {
        Self {
            api_base: TWITTER_API_BASE.to_string(),
        }
    }

    fn fqn() -> ToolFqn {
        fqn!("xyz.taluslabs.social.twitter.get-user-following@1")
    }

    fn path() -> &'static str {
        "/get-user-following"
    }

    async fn health(&self) -> AnyResult<StatusCode> {
        Ok(StatusCode::OK)
    }

    async fn invoke(&self, request: Self::Input) -> Self::Output {
        // Build the endpoint for the Twitter API
        let suffix = format!("users/{}/following", request.user_id);

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
            .get::<FollowingByUserIDResponse>(request.bearer_token, Some(query_params))
            .await
        {
            Ok((data, includes, meta)) => Output::Ok {
                users: data,
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
    use mockito::Matcher;
    use {
        super::*,
        ::mockito::{self, Server},
        serde_json::json,
    };

    impl GetUserFollowing {
        fn with_api_base(api_base: &str) -> Self {
            Self {
                api_base: api_base.to_string(),
            }
        }
    }

    async fn create_server_and_tool() -> (mockito::ServerGuard, GetUserFollowing) {
        let server = Server::new_async().await;
        let tool = GetUserFollowing::with_api_base(&server.url());
        (server, tool)
    }

    fn create_test_input() -> Input {
        Input {
            bearer_token: "test_bearer_token".to_string(),
            user_id: "2244994945".to_string(),
            max_results: None,
            pagination_token: None,
            user_fields: None,
            expansions_fields: None,
            tweet_fields: None,
        }
    }

    #[tokio::test]
    async fn test_get_following_successful() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/users/2244994945/following")
            .match_header("Authorization", "Bearer test_bearer_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "data": [
                        {
                            "id": "6253282",
                            "name": "X API",
                            "username": "XApi"
                        },
                        {
                            "id": "2244994945",
                            "name": "X Dev",
                            "username": "TwitterDev"
                        }
                    ],
                    "meta": {
                        "result_count": 2,
                        "next_token": "NEXT_TOKEN"
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let output = tool.invoke(create_test_input()).await;

        match output {
            Output::Ok { users, meta, .. } => {
                assert_eq!(users.len(), 2);
                assert_eq!(users[0].id, "6253282");
                assert_eq!(users[0].name, "X API");
                assert_eq!(users[0].username, "XApi");
                assert_eq!(users[1].id, "2244994945");
                assert!(meta.is_some());
                if let Some(m) = meta {
                    assert_eq!(m.result_count, Some(2));
                    assert_eq!(m.next_token, Some("NEXT_TOKEN".to_string()));
                }
            }
            Output::Err {
                reason,
                kind,
                status_code,
            } => panic!(
                "Expected success, got error: {} : {:?} : {:?}",
                reason, kind, status_code
            ),
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_following_with_pagination() {
        let (mut server, tool) = create_server_and_tool().await;

        let mut input = create_test_input();
        input.pagination_token = Some("PAGINATION_TOKEN".to_string());
        input.max_results = Some(5);
        let query_params = vec![
            (
                "pagination_token".to_string(),
                input.pagination_token.clone().unwrap().to_string(),
            ),
            (
                "max_results".to_string(),
                input.max_results.clone().unwrap().to_string(),
            ),
        ];

        let mock = server
            .mock("GET", "/users/2244994945/following")
            .match_query(Matcher::AllOf(
                query_params
                    .iter()
                    .map(|(k, v)| Matcher::UrlEncoded(k.clone(), v.clone()))
                    .collect(),
            ))
            .match_header("Authorization", "Bearer test_bearer_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "data": [
                        {
                            "id": "783214",
                            "name": "X",
                            "username": "X"
                        }
                    ],
                    "meta": {
                        "result_count": 1,
                        "previous_token": "PAGINATION_TOKEN"
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let output = tool.invoke(input).await;

        match output {
            Output::Ok { users, meta, .. } => {
                assert_eq!(users.len(), 1);
                assert_eq!(users[0].id, "783214");
                assert_eq!(users[0].name, "X");
                assert!(meta.is_some());
                if let Some(m) = meta {
                    assert_eq!(m.result_count, Some(1));
                    assert_eq!(m.previous_token, Some("PAGINATION_TOKEN".to_string()));
                }
            }
            Output::Err {
                reason,
                kind,
                status_code,
            } => panic!(
                "Expected success, got error: {} : {:?} : {:?}",
                reason, kind, status_code
            ),
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_empty_following_list() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/users/2244994945/following")
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
            Output::Ok { users, meta, .. } => {
                assert!(users.is_empty());
                assert!(meta.is_some());
                if let Some(m) = meta {
                    assert_eq!(m.result_count, Some(0));
                }
            }
            Output::Err {
                reason,
                kind,
                status_code,
            } => panic!(
                "Expected success, got error: {} : {:?} : {:?}",
                reason, kind, status_code
            ),
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_user_not_found() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/users/2244994945/following")
            .with_status(404)
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
                kind,
                status_code,
            } => {
                assert!(
                    reason.contains("User not found"),
                    "Expected user not found error"
                );
                assert_eq!(kind, TwitterErrorKind::NotFound);
                assert_eq!(status_code, Some(404));
            }
            Output::Ok { .. } => panic!("Expected error, got success"),
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_unauthorized_access() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/users/2244994945/following")
            .with_status(401)
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
            Output::Err {
                reason,
                kind,
                status_code,
            } => {
                assert!(
                    reason.contains("Unauthorized"),
                    "Expected unauthorized error"
                );
                assert_eq!(kind, TwitterErrorKind::Auth);
                assert_eq!(status_code, Some(401));
            }
            Output::Ok { .. } => panic!("Expected error, got success"),
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_rate_limit_handling() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/users/2244994945/following")
            .with_status(429)
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
                assert!(
                    reason.contains("Rate limit exceeded"),
                    "Expected rate limit error"
                );
                assert_eq!(kind, TwitterErrorKind::RateLimit);
                assert_eq!(status_code, Some(429));
            }
            Output::Ok { .. } => panic!("Expected error, got success"),
        }

        mock.assert_async().await;
    }
}
