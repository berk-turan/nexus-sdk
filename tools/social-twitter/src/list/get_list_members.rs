//! # `xyz.taluslabs.social.twitter.get-list-members@1`
//!
//! Standard Nexus Tool that retrieves members of a list.

use {
    crate::{
        list::models::Expansion,
        tweet::{
            models::{TweetField, UserField},
            TWITTER_API_BASE,
        },
        user::models::UsersResponse,
    },
    nexus_sdk::{fqn, ToolFqn},
    nexus_toolkit::*,
    reqwest::Client,
    schemars::JsonSchema,
    serde::{Deserialize, Serialize},
    serde_json,
};

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct Input {
    /// Bearer Token for user's Twitter account
    bearer_token: String,
    /// List ID to retrieve
    list_id: String,

    /// The maximum number of results
    #[serde(skip_serializing_if = "Option::is_none")]
    max_results: Option<i32>,

    /// The pagination token
    #[serde(skip_serializing_if = "Option::is_none")]
    pagination_token: Option<String>,

    /// A comma separated list of User fields to display
    #[serde(skip_serializing_if = "Option::is_none")]
    user_fields: Option<Vec<UserField>>,

    /// A comma separated list of fields to expand
    #[serde(skip_serializing_if = "Option::is_none")]
    expansions: Option<Vec<Expansion>>,

    /// A comma separated list of Tweet fields to display
    #[serde(skip_serializing_if = "Option::is_none")]
    tweet_fields: Option<Vec<TweetField>>,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Output {
    Ok {
        /// The list of tweets
        result: UsersResponse,
    },
    Err {
        /// Error message if the list tweets failed
        reason: String,
    },
}

pub(crate) struct GetListMembers {
    api_base: String,
}

impl NexusTool for GetListMembers {
    type Input = Input;
    type Output = Output;

    async fn new() -> Self {
        Self {
            api_base: TWITTER_API_BASE.to_string() + "/lists",
        }
    }

    fn fqn() -> ToolFqn {
        fqn!("xyz.taluslabs.social.twitter.get-list-members@1")
    }

    fn path() -> &'static str {
        "/get-list-members"
    }

    async fn health(&self) -> AnyResult<StatusCode> {
        Ok(StatusCode::OK)
    }

    async fn invoke(&self, request: Self::Input) -> Self::Output {
        let client = Client::new();

        let url = format!("{}/{}/members", self.api_base, request.list_id);
        let mut req_builder = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", request.bearer_token));

        if let Some(max_results) = request.max_results {
            req_builder = req_builder.query(&[("max_results", max_results.to_string())]);
        }

        if let Some(pagination_token) = request.pagination_token {
            req_builder = req_builder.query(&[("pagination_token", pagination_token)]);
        }

        if let Some(user_fields) = &request.user_fields {
            let fields: Vec<String> = user_fields
                .iter()
                .map(|f| {
                    serde_json::to_string(f)
                        .unwrap()
                        .replace("\"", "")
                        .to_lowercase()
                })
                .collect();
            req_builder = req_builder.query(&[("user.fields", fields.join(","))]);
        }

        if let Some(expansions) = &request.expansions {
            let fields: Vec<String> = expansions
                .iter()
                .map(|f| {
                    serde_json::to_string(f)
                        .unwrap()
                        .replace("\"", "")
                        .to_lowercase()
                })
                .collect();
            req_builder = req_builder.query(&[("expansions", fields.join(","))]);
        }

        if let Some(tweet_fields) = &request.tweet_fields {
            let fields: Vec<String> = tweet_fields
                .iter()
                .map(|f| {
                    serde_json::to_string(f)
                        .unwrap()
                        .replace("\"", "")
                        .to_lowercase()
                })
                .collect();
            req_builder = req_builder.query(&[("tweet.fields", fields.join(","))]);
        }

        match req_builder.send().await {
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
                        // First check if response contains error
                        if let Ok(error) = serde_json::from_str::<serde_json::Value>(&text) {
                            if let Some(errors) = error.get("errors") {
                                if let Some(first_error) = errors.as_array().and_then(|e| e.first())
                                {
                                    let message = first_error
                                        .get("message")
                                        .and_then(|m| m.as_str())
                                        .unwrap_or("Unknown error");
                                    let code = first_error
                                        .get("code")
                                        .and_then(|c| c.as_u64())
                                        .unwrap_or(0);
                                    return Output::Err {
                                        reason: format!(
                                            "Twitter API error: {} (code: {})",
                                            message, code
                                        ),
                                    };
                                }
                            }
                        }

                        // If no error, try to parse as successful response
                        match serde_json::from_str::<UsersResponse>(&text) {
                            Ok(users_response) => Output::Ok {
                                result: users_response,
                            },
                            Err(e) => Output::Err {
                                reason: format!("Failed to parse Twitter API response: {}", e),
                            },
                        }
                    }
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

    impl GetListMembers {
        fn with_api_base(api_base: &str) -> Self {
            Self {
                api_base: api_base.to_string(),
            }
        }
    }

    async fn create_server_and_tool() -> (mockito::ServerGuard, GetListMembers) {
        let server = Server::new_async().await;
        let tool = GetListMembers::with_api_base(&(server.url() + "/lists"));
        (server, tool)
    }

    fn create_test_input() -> Input {
        Input {
            bearer_token: "test_bearer_token".to_string(),
            list_id: "test_list_id".to_string(),
            max_results: Some(10),
            pagination_token: None,
            user_fields: Some(vec![
                UserField::Username,
                UserField::Name,
                UserField::ProfileImageUrl,
            ]),
            tweet_fields: None,
            expansions: None,
        }
    }

    #[tokio::test]
    async fn test_get_list_members_successful() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock response
        let mock = server
            .mock("GET", "/lists/test_list_id/members")
            .match_header("Authorization", "Bearer test_bearer_token")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "data": [
                        {
                            "id": "12345",
                            "name": "Test User 1",
                            "username": "testuser1",
                            "profile_image_url": "https://pbs.twimg.com/profile_images/image1.jpg"
                        },
                        {
                            "id": "67890",
                            "name": "Test User 2",
                            "username": "testuser2",
                            "profile_image_url": "https://pbs.twimg.com/profile_images/image2.jpg"
                        }
                    ],
                    "meta": {
                        "result_count": 2,
                        "next_token": "next_page_token"
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Test the list members request
        let output = tool.invoke(create_test_input()).await;

        // Verify the response
        match output {
            Output::Ok { result } => {
                assert!(result.data.is_some());
                let data = result.data.unwrap();
                assert_eq!(data.len(), 2);
                assert_eq!(data[0].id, "12345");
                assert_eq!(data[0].username, "testuser1");
                assert_eq!(data[0].name, "Test User 1");
                assert_eq!(data[1].id, "67890");
                assert_eq!(data[1].username, "testuser2");

                // Check meta data
                let meta = result.meta.unwrap();
                assert_eq!(meta.result_count.unwrap(), 2);
                assert_eq!(meta.next_token.unwrap(), "next_page_token");
            }
            Output::Err { reason } => panic!("Expected success, got error: {}", reason),
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_list_members_not_found() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock response for not found
        let mock = server
            .mock("GET", "/lists/test_list_id/members")
            .match_header("Authorization", "Bearer test_bearer_token")
            .match_query(mockito::Matcher::Any)
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "errors": [
                        {
                            "message": "List not found",
                            "code": 34
                        }
                    ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Test the list members request
        let output = tool.invoke(create_test_input()).await;

        // Verify the response
        match output {
            Output::Err { reason } => {
                assert!(reason.contains("Twitter API returned error status: 404"), 
                       "Expected error message to contain 'Twitter API returned error status: 404', got: {}", reason);
            }
            Output::Ok { result } => panic!("Expected error, got success: {:?}", result),
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_unauthorized_error() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/lists/test_list_id/members")
            .match_header("Authorization", "Bearer test_bearer_token")
            .match_query(mockito::Matcher::Any)
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
                assert!(reason.contains("Twitter API returned error status: 401"), 
                       "Expected error message to contain 'Twitter API returned error status: 401', got: {}", reason);
            }
            Output::Ok { .. } => panic!("Expected error, got success"),
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_rate_limit_exceeded() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/lists/test_list_id/members")
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
                assert!(reason.contains("Twitter API returned error status: 429"), 
                       "Expected error message to contain 'Twitter API returned error status: 429', got: {}", reason);
            }
            Output::Ok { .. } => panic!("Expected error, got success"),
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_empty_response() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/lists/test_list_id/members")
            .match_header("Authorization", "Bearer test_bearer_token")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
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
            Output::Ok { result } => {
                assert!(result.data.is_none() || result.data.unwrap().is_empty());
                assert!(result.meta.is_some());
                if let Some(meta) = result.meta {
                    assert_eq!(meta.result_count.unwrap(), 0);
                }
            }
            Output::Err { reason } => panic!("Expected success, got error: {}", reason),
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_invalid_json_response() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/lists/test_list_id/members")
            .match_header("Authorization", "Bearer test_bearer_token")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("invalid json")
            .create_async()
            .await;

        let output = tool.invoke(create_test_input()).await;

        match output {
            Output::Err { reason } => {
                assert!(reason.contains("Failed to parse Twitter API response"), 
                       "Expected error message to contain 'Failed to parse Twitter API response', got: {}", reason);
            }
            Output::Ok { .. } => panic!("Expected error, got success"),
        }

        mock.assert_async().await;
    }
}
