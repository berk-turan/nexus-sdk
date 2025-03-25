//! # `xyz.taluslabs.social.twitter.mentioned-tweets@1`
//!
//! Standard Nexus Tool that retrieves tweets mentioning a specific user.

use {
    crate::tweet::{
        models::{
            ExpansionField,
            MediaField,
            PlaceField,
            PollField,
            TweetField,
            TweetsResponse,
            UserField,
        },
        TWITTER_API_BASE,
    },
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

    /// The ID of the User to lookup
    /// Example: "2244994945"
    id: String,

    /// The minimum Post ID to be included in the result set
    /// Takes precedence over start_time if both are specified
    #[serde(skip_serializing_if = "Option::is_none")]
    since_id: Option<String>,

    /// The maximum Post ID to be included in the result set
    /// Takes precedence over end_time if both are specified
    /// Example: "1346889436626259968"
    #[serde(skip_serializing_if = "Option::is_none")]
    until_id: Option<String>,

    /// The maximum number of results
    /// Required range: 5 <= x <= 100
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(range(min = 5, max = 100))]
    max_results: Option<i32>,

    /// This parameter is used to get the next 'page' of results
    /// Minimum length: 1
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(min = 1))]
    pagination_token: Option<String>,

    /// YYYY-MM-DDTHH:mm:ssZ. The earliest UTC timestamp from which the Posts will be provided
    /// The since_id parameter takes precedence if it is also specified
    /// Example: "2021-02-01T18:40:40.000Z"
    #[serde(skip_serializing_if = "Option::is_none")]
    start_time: Option<String>,

    /// YYYY-MM-DDTHH:mm:ssZ. The latest UTC timestamp to which the Posts will be provided
    /// The until_id parameter takes precedence if it is also specified
    /// Example: "2021-02-14T18:40:40.000Z"
    #[serde(skip_serializing_if = "Option::is_none")]
    end_time: Option<String>,

    /// A comma separated list of Tweet fields to display
    #[serde(skip_serializing_if = "Option::is_none")]
    tweet_fields: Option<Vec<TweetField>>,

    /// A comma separated list of fields to expand
    #[serde(skip_serializing_if = "Option::is_none")]
    expansions: Option<Vec<ExpansionField>>,

    /// A comma separated list of Media fields to display
    #[serde(skip_serializing_if = "Option::is_none")]
    media_fields: Option<Vec<MediaField>>,

    /// A comma separated list of Poll fields to display
    #[serde(skip_serializing_if = "Option::is_none")]
    poll_fields: Option<Vec<PollField>>,

    /// A comma separated list of User fields to display
    #[serde(skip_serializing_if = "Option::is_none")]
    user_fields: Option<Vec<UserField>>,

    /// A comma separated list of Place fields to display
    #[serde(skip_serializing_if = "Option::is_none")]
    place_fields: Option<Vec<PlaceField>>,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Output {
    Ok {
        /// The successful tweet response data
        result: TweetsResponse,
    },
    Err {
        /// Error message if the tweet failed
        reason: String,
    },
}

pub(crate) struct MentionedTweets {
    api_base: String,
}

impl NexusTool for MentionedTweets {
    type Input = Input;
    type Output = Output;

    async fn new() -> Self {
        Self {
            api_base: TWITTER_API_BASE.to_string() + "/users",
        }
    }

    fn fqn() -> ToolFqn {
        fqn!("xyz.taluslabs.social.twitter.mentioned-tweets@1")
    }

    fn path() -> &'static str {
        "/twitter/mentioned-tweets"
    }

    async fn health(&self) -> AnyResult<StatusCode> {
        Ok(StatusCode::OK)
    }

    async fn invoke(&self, request: Self::Input) -> Self::Output {
        let client = Client::new();

        // Construct URL with user ID
        let url = format!("{}/{}/mentions", self.api_base, request.id);
        let mut req_builder = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", request.bearer_token));

        // Add optional query parameters if they exist
        if let Some(since_id) = &request.since_id {
            req_builder = req_builder.query(&[("since_id", since_id)]);
        }
        if let Some(until_id) = &request.until_id {
            req_builder = req_builder.query(&[("until_id", until_id)]);
        }
        if let Some(max_results) = request.max_results {
            req_builder = req_builder.query(&[("max_results", max_results.to_string())]);
        }
        if let Some(pagination_token) = &request.pagination_token {
            req_builder = req_builder.query(&[("pagination_token", pagination_token)]);
        }
        if let Some(start_time) = &request.start_time {
            req_builder = req_builder.query(&[("start_time", start_time)]);
        }
        if let Some(end_time) = &request.end_time {
            req_builder = req_builder.query(&[("end_time", end_time)]);
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
        if let Some(media_fields) = &request.media_fields {
            let fields: Vec<String> = media_fields
                .iter()
                .map(|f| {
                    serde_json::to_string(f)
                        .unwrap()
                        .replace("\"", "")
                        .to_lowercase()
                })
                .collect();
            req_builder = req_builder.query(&[("media.fields", fields.join(","))]);
        }
        if let Some(poll_fields) = &request.poll_fields {
            let fields: Vec<String> = poll_fields
                .iter()
                .map(|f| {
                    serde_json::to_string(f)
                        .unwrap()
                        .replace("\"", "")
                        .to_lowercase()
                })
                .collect();
            req_builder = req_builder.query(&[("poll.fields", fields.join(","))]);
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
        if let Some(place_fields) = &request.place_fields {
            let fields: Vec<String> = place_fields
                .iter()
                .map(|f| {
                    serde_json::to_string(f)
                        .unwrap()
                        .replace("\"", "")
                        .to_lowercase()
                })
                .collect();
            req_builder = req_builder.query(&[("place.fields", fields.join(","))]);
        }

        match req_builder.send().await {
            Ok(response) => {
                let status = response.status();
                let response_text = match response.text().await {
                    Ok(text) => text,
                    Err(e) => {
                        return Output::Err {
                            reason: format!("Failed to read response body: {}", e),
                        }
                    }
                };

                if !status.is_success() {
                    return Output::Err {
                        reason: format!("Twitter API returned error status: {}", status),
                    };
                }

                if response_text.is_empty() {
                    return Output::Err {
                        reason: "Twitter API returned empty response".to_string(),
                    };
                }

                match serde_json::from_str::<TweetsResponse>(&response_text) {
                    Ok(tweets_response) => Output::Ok {
                        result: tweets_response,
                    },
                    Err(e) => {
                        // Log the response text for debugging
                        Output::Err {
                            reason: format!("Failed to parse Twitter API response: {}", e),
                        }
                    }
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

    impl MentionedTweets {
        fn with_api_base(api_base: &str) -> Self {
            Self {
                api_base: api_base.to_string() + "/users",
            }
        }
    }

    async fn create_server_and_tool() -> (mockito::ServerGuard, MentionedTweets) {
        let server = Server::new_async().await;
        let tool = MentionedTweets::with_api_base(&server.url());
        (server, tool)
    }

    fn create_test_input() -> Input {
        Input {
            bearer_token: "test_bearer_token".to_string(),
            id: "2244994945".to_string(),
            since_id: None,
            until_id: None,
            max_results: Some(10),
            pagination_token: None,
            start_time: None,
            end_time: None,
            tweet_fields: Some(vec![TweetField::Text, TweetField::AuthorId]),
            expansions: Some(vec![ExpansionField::AuthorId]),
            media_fields: None,
            poll_fields: None,
            user_fields: Some(vec![UserField::Username, UserField::Name]),
            place_fields: None,
        }
    }

    #[tokio::test]
    async fn test_mentioned_tweets_successful() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock response
        let mock = server
            .mock("GET", "/users/2244994945/mentions")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("max_results".into(), "10".into()),
                mockito::Matcher::UrlEncoded("tweet.fields".into(), "text,author_id".into()),
                mockito::Matcher::UrlEncoded("expansions".into(), "author_id".into()),
                mockito::Matcher::UrlEncoded("user.fields".into(), "username,name".into()),
            ]))
            .match_header("Authorization", "Bearer test_bearer_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "data": [
                        {
                            "author_id": "2244994945",
                            "created_at": "Wed Jan 06 18:40:40 +0000 2021",
                            "id": "1346889436626259968",
                            "text": "Learn how to use the user Tweet timeline and user mention timeline endpoints in the X API v2 to explore Tweet",
                            "username": "XDevelopers"
                        }
                    ],
                    "includes": {
                        "users": [
                            {
                                "created_at": "2013-12-14T04:35:55Z",
                                "id": "2244994945",
                                "name": "X Dev",
                                "protected": false,
                                "username": "TwitterDev"
                            }
                        ]
                    },
                    "meta": {
                        "newest_id": "1346889436626259968",
                        "next_token": "7140dibdnow9c7btw3w29n4v5uqcl4",
                        "oldest_id": "1346889436626259968",
                        "result_count": 1
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Test the mentions request
        let output = tool.invoke(create_test_input()).await;

        // Verify the response
        match output {
            Output::Ok { result } => {
                // Verify data array
                let data = result.data.expect("Expected data to be present");
                assert_eq!(data.len(), 1);
                assert_eq!(data[0].id, "1346889436626259968");
                assert_eq!(
                    data[0].text,
                    "Learn how to use the user Tweet timeline and user mention timeline endpoints in the X API v2 to explore Tweet"
                );
                assert_eq!(data[0].author_id, Some("2244994945".to_string()));

                // Verify includes
                if let Some(includes) = result.includes {
                    if let Some(users) = includes.users {
                        assert_eq!(users.len(), 1);
                        assert_eq!(users[0].id, "2244994945");
                        assert_eq!(users[0].name, "X Dev");
                        assert_eq!(users[0].username, "TwitterDev");
                        assert_eq!(users[0].protected, false);
                    } else {
                        panic!("Expected users in includes");
                    }
                } else {
                    panic!("Expected includes in response");
                }

                // Verify meta
                if let Some(meta) = result.meta {
                    assert_eq!(meta.result_count.unwrap(), 1);
                    assert_eq!(meta.newest_id, Some("1346889436626259968".to_string()));
                    assert_eq!(meta.oldest_id, Some("1346889436626259968".to_string()));
                    assert_eq!(
                        meta.next_token,
                        Some("7140dibdnow9c7btw3w29n4v5uqcl4".to_string())
                    );
                } else {
                    panic!("Expected meta in response");
                }
            }
            Output::Err { reason } => panic!("Expected success, got error: {}", reason),
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_mentioned_tweets_error_response() {
        // Create server and tool
        let (mut server, tool) = create_server_and_tool().await;

        // Set up mock response for error
        let mock = server
            .mock("GET", "/users/2244994945/mentions")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("max_results".into(), "10".into()),
                mockito::Matcher::UrlEncoded("tweet.fields".into(), "text,author_id".into()),
                mockito::Matcher::UrlEncoded("expansions".into(), "author_id".into()),
                mockito::Matcher::UrlEncoded("user.fields".into(), "username,name".into()),
            ]))
            .match_header("Authorization", "Bearer test_bearer_token")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "errors": [
                        {
                            "code": 32,
                            "message": "Could not authenticate you"
                        }
                    ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Test the mentions request
        let output = tool.invoke(create_test_input()).await;

        // Verify the error response
        match output {
            Output::Ok { result: _ } => panic!("Expected error, got success"),
            Output::Err { reason } => {
                assert!(reason.contains("Twitter API returned error status: 401"));
                assert!(reason.contains(
                    r#"{"errors":[{"code":32,"message":"Could not authenticate you"}]}"#
                ));
            }
        }

        // Verify that the mock was called
        mock.assert_async().await;
    }
}
