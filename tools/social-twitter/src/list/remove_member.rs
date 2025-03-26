//! # `xyz.taluslabs.social.twitter.remove-member@1`
//!
//! Standard Nexus Tool that removes a member from a list on Twitter.

use {
    super::models::ListMemberResponse,
    crate::{auth::TwitterAuth, tweet::TWITTER_API_BASE},
    nexus_sdk::{fqn, ToolFqn},
    nexus_toolkit::*,
    reqwest::Client,
    schemars::JsonSchema,
    serde::{Deserialize, Serialize},
    serde_json,
};

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub(crate) struct Input {
    /// Twitter API credentials
    #[serde(flatten)]
    auth: TwitterAuth,
    /// List ID to remove member from
    list_id: String,
    /// User ID to remove from list
    user_id: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Output {
    Ok {
        /// The successful tweet response data
        #[schemars(description = "Successfully removed member from list data")]
        result: ListMemberResponse,
    },
    Err {
        /// Error message if the tweet failed
        reason: String,
    },
}

pub(crate) struct RemoveMember {
    api_base: String,
}

impl NexusTool for RemoveMember {
    type Input = Input;
    type Output = Output;

    async fn new() -> Self {
        Self {
            api_base: TWITTER_API_BASE.to_string() + "/lists",
        }
    }

    fn fqn() -> ToolFqn {
        fqn!("xyz.taluslabs.social.twitter.remove-member@1")
    }

    fn path() -> &'static str {
        "/twitter/remove-member"
    }

    async fn health(&self) -> AnyResult<StatusCode> {
        Ok(StatusCode::OK)
    }

    async fn invoke(&self, request: Self::Input) -> Self::Output {
        // Add authentication header
        let url = format!(
            "{}/{}/members/{}",
            self.api_base, request.list_id, request.user_id
        );

        // Generate OAuth authorization header using the auth helper
        let auth_header = request.auth.generate_auth_header_for_delete(&url);

        // Initialize HTTP client
        let client = Client::new();

        // Make the request
        let response = client
            .delete(&url)
            .header("Authorization", auth_header)
            .send()
            .await;

        match response {
            Ok(result) => {
                let text = match result.text().await {
                    Err(e) => {
                        return Output::Err {
                            reason: format!("Failed to read Twitter API response: {}", e),
                        }
                    }
                    Ok(text) => text,
                };

                let json: serde_json::Value = match serde_json::from_str(&text) {
                    Err(e) => {
                        return Output::Err {
                            reason: format!("Invalid JSON response: {}", e),
                        }
                    }
                    Ok(json) => json,
                };

                // Check for error response with code/message format
                if let Some(code) = json.get("code") {
                    let message = json
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("Unknown error");

                    return Output::Err {
                        reason: format!("Twitter API error: {} (Code: {})", message, code),
                    };
                }

                // Check for error response with detail/status/title format
                if let Some(detail) = json.get("detail") {
                    let status = json.get("status").and_then(|s| s.as_u64()).unwrap_or(0);
                    let title = json
                        .get("title")
                        .and_then(|t| t.as_str())
                        .unwrap_or("Unknown");

                    return Output::Err {
                        reason: format!(
                            "Twitter API error: {} (Status: {}, Title: {})",
                            detail.as_str().unwrap_or("Unknown error"),
                            status,
                            title
                        ),
                    };
                }

                // Check for errors array
                if let Some(errors) = json.get("errors") {
                    return Output::Err {
                        reason: format!("Twitter API returned errors: {}", errors),
                    };
                }

                // Parse the list data
                match serde_json::from_value::<ListMemberResponse>(json) {
                    Ok(list_data) => Output::Ok { result: list_data },
                    Err(e) => Output::Err {
                        reason: format!("Failed to parse list data: {}", e),
                    },
                }
            }
            Err(e) => {
                return Output::Err {
                    reason: format!("Failed to send request to Twitter API: {}", e),
                }
            }
        }
    }
}
