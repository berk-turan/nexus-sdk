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
        "/twitter/get-list-members"
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
