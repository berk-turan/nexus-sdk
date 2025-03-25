use {
    schemars::JsonSchema,
    serde::{Deserialize, Serialize},
    serde_json::Value,
};

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct TweetsResponse {
    pub data: Option<Vec<Tweet>>,
    pub errors: Option<Vec<ApiError>>,
    pub includes: Option<Includes>,
    pub meta: Option<Meta>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct SingleTweetResponse {
    pub data: Option<Tweet>,
    pub errors: Option<Vec<ApiError>>,
    pub includes: Option<Includes>,
    pub meta: Option<Meta>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Tweet {
    pub id: String,   // mandatory
    pub text: String, // mandatory
    pub author_id: Option<String>,
    pub created_at: Option<String>,
    pub username: Option<String>,
    pub attachments: Option<Attachments>,
    pub community_id: Option<String>,
    pub context_annotations: Option<Vec<ContextAnnotation>>,
    pub conversation_id: Option<String>,
    pub edit_controls: Option<EditControls>,
    pub edit_history_tweet_ids: Option<Vec<String>>,
    pub entities: Option<Entities>,
    pub geo: Option<Geo>,
    pub in_reply_to_user_id: Option<String>,
    pub lang: Option<String>,
    pub non_public_metrics: Option<NonPublicMetrics>,
    pub note_tweet: Option<NoteTweet>,
    pub organic_metrics: Option<OrganicMetrics>,
    pub possibly_sensitive: Option<bool>,
    pub promoted_metrics: Option<PromotedMetrics>,
    pub public_metrics: Option<PublicMetrics>,
    pub referenced_tweets: Option<Vec<ReferencedTweet>>,
    pub reply_settings: Option<String>,
    pub scopes: Option<Scopes>,
    pub source: Option<String>,
    pub withheld: Option<Withheld>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Attachments {
    pub media_keys: Option<Vec<String>>,
    pub poll_ids: Option<Vec<String>>,
    pub media_source_tweet_id: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ContextAnnotation {
    pub domain: ContextAnnotationDomain,
    pub entity: ContextAnnotationEntity,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ContextAnnotationDomain {
    pub id: String,
    pub description: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ContextAnnotationEntity {
    pub id: String,
    pub description: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct EditControls {
    pub editable_until: String,
    pub edits_remaining: i32,
    pub is_edit_eligible: bool,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Entities {
    pub annotations: Option<Vec<Annotation>>,
    pub cashtags: Option<Vec<Cashtag>>,
    pub hashtags: Option<Vec<Hashtag>>,
    pub mentions: Option<Vec<Mention>>,
    pub urls: Option<Vec<UrlEntity>>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Annotation {
    pub end: i32,
    pub start: i32,
    pub normalized_text: Option<String>,
    pub probability: Option<f64>,
    #[serde(rename = "type")]
    pub annotation_type: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Cashtag {
    pub end: i32,
    pub start: i32,
    pub tag: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Hashtag {
    pub end: i32,
    pub start: i32,
    pub tag: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Mention {
    pub end: i32,
    pub start: i32,
    pub username: String,
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct UrlEntity {
    pub end: i32,
    pub start: i32,
    pub url: String,
    pub description: Option<String>,
    pub display_url: Option<String>,
    pub expanded_url: Option<String>,
    pub images: Option<Vec<UrlImage>>,
    pub media_key: Option<String>,
    pub status: Option<i32>,
    pub title: Option<String>,
    pub unwound_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct UrlImage {
    pub height: i32,
    pub url: String,
    pub width: i32,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Geo {
    pub coordinates: Option<Coordinates>,
    pub place_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Coordinates {
    pub coordinates: [f64; 2], // [longitude, latitude]
    #[serde(rename = "type")]
    pub coord_type: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct NonPublicMetrics {
    pub impression_count: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct NoteTweet {
    pub text: String,
    pub entities: Option<Entities>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct OrganicMetrics {
    pub impression_count: i32,
    pub like_count: i32,
    pub reply_count: i32,
    pub retweet_count: i32,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct PromotedMetrics {
    pub impression_count: Option<i32>,
    pub like_count: Option<i32>,
    pub reply_count: Option<i32>,
    pub retweet_count: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct PublicMetrics {
    pub bookmark_count: i32,
    pub impression_count: i32,
    pub like_count: i32,
    pub reply_count: i32,
    pub retweet_count: i32,
    pub quote_count: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub enum ReferencedTweetType {
    #[serde(rename = "retweeted")]
    Retweeted,
    #[serde(rename = "quoted")]
    Quoted,
    #[serde(rename = "replied_to")]
    RepliedTo,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ReferencedTweet {
    pub id: String,
    #[serde(rename = "type")]
    pub ref_type: ReferencedTweetType,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Scopes {
    pub followers: bool,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Withheld {
    pub copyright: bool,
    pub country_codes: Vec<String>,
    pub scope: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ApiError {
    pub title: String,
    #[serde(rename = "type")]
    pub error_type: String,
    pub detail: String,
    pub status: i32,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Includes {
    pub media: Option<Vec<Media>>,
    pub places: Option<Vec<Place>>,
    pub polls: Option<Vec<Poll>>,
    pub topics: Option<Vec<Topic>>,
    pub tweets: Option<Vec<Tweet>>,
    pub users: Option<Vec<User>>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Media {
    #[serde(rename = "type")]
    pub media_type: String,
    pub height: Option<i32>,
    pub media_key: String,
    pub width: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Place {
    pub full_name: String,
    pub id: String,
    pub contained_within: Option<Vec<String>>,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub geo: Option<GeoPlace>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct GeoPlace {
    pub bbox: Vec<f64>,
    pub properties: Value,
    #[serde(rename = "type")]
    pub geo_type: String,
    pub geometry: Option<Geometry>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Geometry {
    pub coordinates: Vec<f64>,
    #[serde(rename = "type")]
    pub geo_type: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Poll {
    pub duration_minutes: i32,
    pub end_datetime: String,
    pub id: String,
    pub options: Vec<PollOption>,
    pub voting_status: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct PollOption {
    pub label: String,
    pub position: i32,
    pub votes: i32,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Topic {
    pub description: String,
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct User {
    pub created_at: Option<String>,
    pub id: String,
    pub name: String,
    pub protected: bool,
    pub username: String,
    pub description: Option<String>,
    pub entities: Option<Value>,
    pub location: Option<String>,
    pub public_metrics: Option<PublicUserMetrics>,
    pub profile_image_url: Option<String>,
    pub verified: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct PublicUserMetrics {
    pub followers_count: Option<i32>,
    pub following_count: Option<i32>,
    pub tweet_count: Option<i32>,
    pub listed_count: Option<i32>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Meta {
    pub newest_id: Option<String>,
    pub next_token: Option<String>,
    pub oldest_id: Option<String>,
    pub previous_token: Option<String>,
    pub result_count: Option<i32>,
}

/// Available Tweet fields that can be requested
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TweetField {
    Article,
    Attachments,
    AuthorId,
    CardUri,
    CommunityId,
    ContextAnnotations,
    ConversationId,
    CreatedAt,
    DisplayTextRange,
    EditControls,
    EditHistoryTweetIds,
    Entities,
    Geo,
    Id,
    InReplyToUserId,
    Lang,
    MediaMetadata,
    NonPublicMetrics,
    NoteTweet,
    OrganicMetrics,
    PossiblySensitive,
    PromotedMetrics,
    PublicMetrics,
    ReferencedTweets,
    ReplySettings,
    Scopes,
    Source,
    Text,
    Withheld,
}

/// Available expansion fields
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExpansionField {
    #[serde(rename = "article.cover_media")]
    ArticleCoverMedia,
    #[serde(rename = "article.media_entities")]
    ArticleMediaEntities,
    #[serde(rename = "attachments.media_keys")]
    AttachmentsMediaKeys,
    #[serde(rename = "attachments.media_source_tweet")]
    AttachmentsMediaSourceTweet,
    #[serde(rename = "attachments.poll_ids")]
    AttachmentsPollIds,
    AuthorId,
    EditHistoryTweetIds,
    #[serde(rename = "entities.mentions.username")]
    EntitiesMentionsUsername,
    #[serde(rename = "geo.place_id")]
    GeoPlaceId,
    InReplyToUserId,
    #[serde(rename = "entities.note.mentions.username")]
    EntitiesNoteMentionsUsername,
    #[serde(rename = "referenced_tweets.id")]
    ReferencedTweetsId,
    #[serde(rename = "referenced_tweets.id.attachments.media_keys")]
    ReferencedTweetsIdAttachmentsMediaKeys,
    #[serde(rename = "referenced_tweets.id.author_id")]
    ReferencedTweetsIdAuthorId,
}

/// Available Media fields
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MediaField {
    AltText,
    DurationMs,
    Height,
    MediaKey,
    NonPublicMetrics,
    OrganicMetrics,
    PreviewImageUrl,
    PromotedMetrics,
    PublicMetrics,
    #[serde(rename = "type")]
    Type,
    Url,
    Variants,
    Width,
}

/// Available Poll fields
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PollField {
    DurationMinutes,
    EndDatetime,
    Id,
    Options,
    VotingStatus,
}

/// Available User fields
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UserField {
    Affiliation,
    ConnectionStatus,
    CreatedAt,
    Description,
    Entities,
    Id,
    IsIdentityVerified,
    Location,
    MostRecentTweetId,
    Name,
    Parody,
    PinnedTweetId,
    ProfileBannerUrl,
    ProfileImageUrl,
    Protected,
    PublicMetrics,
    ReceivesYourDm,
    Subscription,
    SubscriptionType,
    Url,
    Username,
    Verified,
    VerifiedFollowersCount,
    VerifiedType,
    Withheld,
}

/// Available Place fields
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlaceField {
    ContainedWithin,
    Country,
    CountryCode,
    FullName,
    Geo,
    Id,
    Name,
    PlaceType,
}
