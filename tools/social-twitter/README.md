# `xyz.taluslabs.social.twitter.get-tweet@1`

Standard Nexus Tool that retrieves a single tweet from the Twitter API. Twitter api [reference](https://developer.twitter.com/en/docs/twitter-api/tweets/lookup/api-reference/get-tweets-id)

## Input

**`bearer_token`: [`String`]**

The bearer token for the user's Twitter account.

**`tweet_id`: [`String`]**

The ID of the tweet to retrieve.

## Output Variants & Ports

**`ok`**

The tweet was retrieved successfully.

- **`ok.result`: [`SingleTweetResponse`]** - The tweet data containing all fields from the Twitter API response.

**`err`**

The tweet was not retrieved due to an error.

- **`err.reason`: [`String`]** - The reason for the error. This could be:
  - Twitter API error status
  - Failed to parse Twitter API response
  - Failed to read Twitter API response
  - Failed to send request to Twitter API

---

# `xyz.taluslabs.social.twitter.post-tweet@1`

Standard Nexus Tool that creates a new tweet using the Twitter API.Twitter api [reference](https://docs.x.com/x-api/posts/creation-of-a-post)

## Input

**`consumer_key`: [`String`]**

Twitter API application's Consumer Key.

**`consumer_secret_key`: [`String`]**

Twitter API application's Consumer Secret Key.

**`access_token`: [`String`]**

Access Token for user's Twitter account.

**`access_token_secret`: [`String`]**

Access Token Secret for user's Twitter account.

**`content`: [`String`]**

The content to tweet.

## Output Variants & Ports

**`ok`**

The tweet was created successfully.

- **`ok.result`: [`TweetResponse`]** - The created tweet data containing:
  - `id`: The tweet's unique identifier
  - `edit_history_tweet_ids`: List of tweet IDs in the edit history
  - `text`: The actual content of the tweet

**`err`**

The tweet creation failed.

- **`err.reason`: [`String`]** - The reason for the error. This could be:
  - Twitter API error status
  - Failed to parse tweet data
  - Invalid JSON response
  - Failed to read Twitter API response
  - Failed to send tweet to Twitter API

---

# `xyz.taluslabs.social.twitter.like-tweet@1`

Standard Nexus Tool that allows a user to like a specific tweet.
Twitter api [reference](https://docs.x.com/x-api/posts/causes-the-user-in-the-path-to-like-the-specified-post)

## Input

**`consumer_key`: [`String`]**

Twitter API application's Consumer Key.

**`consumer_secret_key`: [`String`]**

Twitter API application's Consumer Secret Key.

**`access_token`: [`String`]**

Access Token for user's Twitter account.

**`access_token_secret`: [`String`]**

Access Token Secret for user's Twitter account.

**`user_id`: [`String`]**

The ID of the authenticated user who will like the tweet.

**`tweet_id`: [`String`]**

The ID of the tweet to like.

## Output Variants & Ports

**`ok`**

The tweet was successfully liked.

- **`ok.tweet_id`: [`String`]** - The ID of the tweet that was liked
- **`ok.liked`: [`bool`]** - Confirmation that the tweet was liked (true)

**`err`**

The like operation failed.

- **`err.reason`: [`String`]** - The reason for the error. This could be:
  - Twitter API error status (Code/Message format)
  - Twitter API error details (Detail/Status/Title format)
  - "You have already liked this Tweet" error
  - Unauthorized error
  - Invalid JSON response
  - Failed to read Twitter API response
  - Failed to send like request to Twitter API

---

# `xyz.taluslabs.social.twitter.mentioned-tweets@1`

Standard Nexus Tool that retrieves tweets mentioning a specific user.
Twitter api [reference](https://docs.x.com/x-api/posts/user-mention-timeline-by-user-id)

## Input

**`bearer_token`: [`String`]**

The bearer token for the user's Twitter account.

**`id`: [`String`]**

The ID of the User to lookup for mentions.

**`since_id`: [`String`] (optional)**

The minimum Post ID to be included in the result set. Takes precedence over start_time if both are specified.

**`until_id`: [`String`] (optional)**

The maximum Post ID to be included in the result set. Takes precedence over end_time if both are specified.

**`max_results`: [`Integer`] (optional)**

The maximum number of results to retrieve (range: 5-100).

**`pagination_token`: [`String`] (optional)**

Used to get the next 'page' of results.

**`start_time`: [`String`] (optional)**

The earliest UTC timestamp (YYYY-MM-DDTHH:mm:ssZ) from which the Posts will be provided.

**`end_time`: [`String`] (optional)**

The latest UTC timestamp (YYYY-MM-DDTHH:mm:ssZ) to which the Posts will be provided.

**`tweet_fields`: [`Array[TweetField]`] (optional)**

A list of Tweet fields to display.

**`expansions`: [`Array[ExpansionField]`] (optional)**

A list of fields to expand.

**`media_fields`: [`Array[MediaField]`] (optional)**

A list of Media fields to display.

**`poll_fields`: [`Array[PollField]`] (optional)**

A list of Poll fields to display.

**`user_fields`: [`Array[UserField]`] (optional)**

A list of User fields to display.

**`place_fields`: [`Array[PlaceField]`] (optional)**

A list of Place fields to display.

## Output Variants & Ports

**`ok`**

The mentioned tweets were retrieved successfully.

- **`ok.result`: [`TweetsResponse`]** - The response containing tweets mentioning the specified user.

**`err`**

The tweet mentions retrieval failed.

- **`err.reason`: [`String`]** - The reason for the error. This could be:
  - Twitter API error status
  - Failed to parse Twitter API response
  - Failed to read Twitter API response
  - Failed to send request to Twitter API
