//! # `xyz.taluslabs.social.twitter.get-list@1`
//!
//! Standard Nexus Tool that retrieves a list on Twitter.

use {
    crate::{
        list::models::{Expansion, ListData, ListField, ListResponse, UserField},
        tweet::TWITTER_API_BASE,
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

    /// A comma separated list of List fields to display
    #[serde(rename = "list.fields", skip_serializing_if = "Option::is_none")]
    pub list_fields: Option<Vec<ListField>>,

    /// A comma separated list of fields to expand
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expansions: Option<Vec<Expansion>>,

    /// A comma separated list of User fields to display
    #[serde(rename = "user.fields", skip_serializing_if = "Option::is_none")]
    pub user_fields: Option<Vec<UserField>>,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Output {
    Ok {
        /// The successful tweet response data
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<ListData>,
    },
    Err {
        /// Error message if the tweet failed
        reason: String,
    },
}

pub(crate) struct GetList {
    api_base: String,
}

impl NexusTool for GetList {
    type Input = Input;
    type Output = Output;

    async fn new() -> Self {
        Self {
            api_base: TWITTER_API_BASE.to_string() + "/lists",
        }
    }

    fn fqn() -> ToolFqn {
        fqn!("xyz.taluslabs.social.twitter.get-list@1")
    }

    fn path() -> &'static str {
        "/get-list"
    }

    async fn health(&self) -> AnyResult<StatusCode> {
        Ok(StatusCode::OK)
    }

    async fn invoke(&self, request: Self::Input) -> Self::Output {
        let client = Client::new();

        // Add authentication header
        let url = format!("{}/{}", self.api_base, request.list_id);
        let mut req_builder = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", request.bearer_token));

        // Add optional query parameters if they exist
        if let Some(list_fields) = &request.list_fields {
            let fields: Vec<String> = list_fields
                .iter()
                .map(|f| {
                    serde_json::to_string(f)
                        .unwrap()
                        .replace("\"", "")
                        .to_lowercase()
                })
                .collect();
            req_builder = req_builder.query(&[("list.fields", fields.join(","))]);
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

        // Make the request
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
                        match serde_json::from_str::<ListResponse>(&text) {
                            Ok(list_response) => Output::Ok {
                                data: list_response.data,
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

    impl GetList {
        fn with_api_base(api_base: &str) -> Self {
            Self {
                api_base: api_base.to_string(),
            }
        }
    }

    async fn create_server_and_tool() -> (mockito::ServerGuard, GetList) {
        let server = Server::new_async().await;
        let tool = GetList::with_api_base(&(server.url() + "/lists"));
        (server, tool)
    }

    fn create_test_input() -> Input {
        Input {
            bearer_token: "test_bearer_token".to_string(),
            list_id: "test_list_id".to_string(),
            list_fields: Some(vec![
                ListField::Name,
                ListField::Description,
                ListField::FollowerCount,
            ]),
            expansions: Some(vec![Expansion::OwnerId]),
            user_fields: Some(vec![UserField::Username, UserField::Name]),
        }
    }

    #[tokio::test]
    async fn test_get_list_successful() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock response
        let mock = server
            .mock("GET", "/lists/test_list_id")
            .match_header("Authorization", "Bearer test_bearer_token")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "data": {
                        "id": "test_list_id",
                        "name": "Test List",
                        "description": "A test list for unit testing",
                        "follower_count": 42,
                        "owner_id": "12345678"
                    },
                    "includes": {
                        "users": [
                            {
                                "id": "12345678",
                                "name": "Test User",
                                "username": "testuser"
                            }
                        ]
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Test the list request
        let output = tool.invoke(create_test_input()).await;

        // Verify the response
        match output {
            Output::Ok { data } => {
                let data = data.unwrap();
                assert_eq!(data.id, "test_list_id");
                assert_eq!(data.name, "Test List");
                assert_eq!(data.description.unwrap(), "A test list for unit testing");
                assert_eq!(data.follower_count.unwrap(), 42);
                assert_eq!(data.owner_id.unwrap(), "12345678");
            }
            Output::Err { reason } => panic!("Expected success, got error: {}", reason),
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_list_not_found() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock response for not found
        let mock = server
            .mock("GET", "/lists/test_list_id")
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

        // Test the list request
        let output = tool.invoke(create_test_input()).await;

        // Verify the response
        match output {
            Output::Err { reason } => {
                assert!(reason.contains("Twitter API returned error status: 404"), 
                       "Expected error message to contain 'Twitter API returned error status: 404', got: {}", reason);
            }
            Output::Ok { data } => panic!("Expected error, got success: {:?}", data),
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_unauthorized_error() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/lists/test_list_id")
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
    async fn test_get_list_rate_limit_exceeded() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock response for rate limit exceeded
        let mock = server
            .mock("GET", "/lists/test_list_id")
            .match_header("Authorization", "Bearer test_bearer_token")
            .match_query(mockito::Matcher::Any)
            .with_status(429)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "errors": [
                        {
                            "message": "Rate limit exceeded",
                            "code": 88
                        }
                    ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Test the list request
        let output = tool.invoke(create_test_input()).await;

        // Verify the response
        match output {
            Output::Err { reason } => {
                assert!(reason.contains("Twitter API returned error status: 429"), 
                       "Expected error message to contain 'Twitter API returned error status: 429', got: {}", reason);
            }
            Output::Ok { data } => panic!("Expected error, got success: {:?}", data),
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_invalid_json_response() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock response with invalid JSON
        let mock = server
            .mock("GET", "/lists/test_list_id")
            .match_header("Authorization", "Bearer test_bearer_token")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("invalid json")
            .create_async()
            .await;

        // Test the list request
        let output = tool.invoke(create_test_input()).await;

        // Verify the response
        match output {
            Output::Err { reason } => {
                assert!(reason.contains("Failed to parse Twitter API response"), 
                       "Expected error message to contain 'Failed to parse Twitter API response', got: {}", reason);
            }
            Output::Ok { data } => panic!("Expected error, got success: {:?}", data),
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }
}
