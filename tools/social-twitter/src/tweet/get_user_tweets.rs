//! # xyz.taluslabs.social.twitter.get-user-tweets@1
//!
//! Standard Nexus Tool that retrieves tweets from a user's Twitter account.

use {
    crate::{
        error::{parse_twitter_response, TwitterResult},
        tweet::{
            models::{
                ExcludeField,
                ExpansionField,
                Includes,
                MediaField,
                Meta,
                PlaceField,
                PollField,
                Tweet,
                TweetField,
                TweetsResponse,
                UserField,
            },
            TWITTER_API_BASE,
        },
    },
    reqwest::Client,
    ::{
        nexus_sdk::{fqn, ToolFqn},
        nexus_toolkit::*,
        schemars::JsonSchema,
        serde::{Deserialize, Serialize},
        serde_json,
    },
};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    /// Bearer Token for user's Twitter account
    bearer_token: String,

    /// User ID to retrieve tweets from
    user_id: String,

    /// The minimum Post ID to be included in the result set
    /// Takes precedence over start_time if both are specified
    #[serde(skip_serializing_if = "Option::is_none")]
    since_id: Option<String>,

    /// The maximum Post ID to be included in the result set
    /// Takes precedence over end_time if both are specified
    /// Example: "1346889436626259968"
    #[serde(skip_serializing_if = "Option::is_none")]
    until_id: Option<String>,

    /// The set of entities to exclude (e.g. 'replies' or 'retweets').
    #[serde(skip_serializing_if = "Option::is_none")]
    exclude: Option<Vec<ExcludeField>>,

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
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<Vec<Tweet>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        includes: Option<Includes>,
        #[serde(skip_serializing_if = "Option::is_none")]
        meta: Option<Meta>,
    },
    Err {
        /// Error message if the get user tweets failed
        reason: String,
    },
}

pub(crate) struct GetUserTweets {
    api_base: String,
}

impl NexusTool for GetUserTweets {
    type Input = Input;
    type Output = Output;

    async fn new() -> Self {
        Self {
            api_base: TWITTER_API_BASE.to_string() + "/users",
        }
    }

    fn fqn() -> ToolFqn {
        fqn!("xyz.taluslabs.social.twitter.get-user-tweets@1")
    }

    fn path() -> &'static str {
        "/get-user-tweets"
    }

    async fn health(&self) -> AnyResult<StatusCode> {
        Ok(StatusCode::OK)
    }

    async fn invoke(&self, request: Self::Input) -> Self::Output {
        match self.fetch_user_tweets(&request).await {
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

impl GetUserTweets {
    /// Fetch tweets from a user's Twitter account
    async fn fetch_user_tweets(&self, request: &Input) -> TwitterResult<TweetsResponse> {
        let client = Client::new();
        let url = format!("{}/{}/tweets", self.api_base, request.user_id);
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
        if let Some(exclude) = &request.exclude {
            req_builder = req_builder.query(&[(
                "exclude",
                exclude
                    .iter()
                    .map(|e| serde_json::to_string(e).unwrap())
                    .collect::<Vec<String>>()
                    .join(",")
                    .as_str(),
            )]);
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

        // Send the request and parse the response
        let response = req_builder.send().await?;
        parse_twitter_response::<TweetsResponse>(response).await
    }
}

#[cfg(test)]
mod tests {
    use {super::*, ::mockito::Server, serde_json::json};

    impl GetUserTweets {
        fn with_api_base(api_base: &str) -> Self {
            Self {
                api_base: api_base.to_string() + "/users",
            }
        }
    }

    async fn create_server_and_tool() -> (mockito::ServerGuard, GetUserTweets) {
        let server = Server::new_async().await;
        let tool = GetUserTweets::with_api_base(&server.url());
        (server, tool)
    }

    fn create_test_input() -> Input {
        Input {
            bearer_token: "test_bearer_token".to_string(),
            user_id: "2244994945".to_string(),
            since_id: None,
            until_id: None,
            exclude: None,
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
    async fn test_get_user_tweets_successful() {
        let (mut server, tool) = create_server_and_tool().await;

        // Match any query parameters
        let mock = server
            .mock("GET", "/users/2244994945/tweets")
            .match_header("Authorization", "Bearer test_bearer_token")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "data": [
                        {
                            "author_id": "2244994945",
                            "id": "1346889436626259968",
                            "text": "Learn how to use the user Tweet timeline"
                        }
                    ],
                    "includes": {
                        "users": [
                            {
                                "id": "2244994945",
                                "name": "X Dev",
                                "username": "TwitterDev",
                                "protected": false
                            }
                        ]
                    },
                    "meta": {
                        "newest_id": "1346889436626259968",
                        "oldest_id": "1346889436626259968",
                        "result_count": 1
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let output = tool.invoke(create_test_input()).await;

        match output {
            Output::Ok {
                data,
                includes: _,
                meta: _,
            } => {
                assert!(data.is_some());
                let tweet_data = data.unwrap();
                assert_eq!(tweet_data.len(), 1);
                assert_eq!(tweet_data[0].id, "1346889436626259968");
            }
            Output::Err { reason } => panic!("Expected success, got error: {}", reason),
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_unauthorized_error() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/users/2244994945/tweets")
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
    async fn test_rate_limit_error() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/users/2244994945/tweets")
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

    #[tokio::test]
    async fn test_invalid_json_response() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/users/2244994945/tweets")
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
                assert!(
                    reason.contains("Response parsing error"),
                    "Expected error message to contain 'Response parsing error', got: {}",
                    reason
                );
            }
            Output::Ok { .. } => panic!("Expected error, got success"),
        }

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_no_data_in_response() {
        let (mut server, tool) = create_server_and_tool().await;

        let mock = server
            .mock("GET", "/users/2244994945/tweets")
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
            Output::Ok {
                data,
                includes: _,
                meta,
            } => {
                assert!(data.is_none() || data.unwrap().is_empty());
                assert!(meta.is_some());
                if let Some(meta_data) = meta {
                    assert_eq!(meta_data.result_count, Some(0));
                }
            }
            Output::Err { reason } => panic!("Expected success, got error: {}", reason),
        }

        mock.assert_async().await;
    }
}
