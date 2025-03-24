# `xyz.taluslabs.social.twitter.get-tweet@1`

Standard Nexus Tool that retrieves a single tweet from the Twitter API.

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

# `xyz.taluslabs.social.twitter.tweet@1`

Standard Nexus Tool that creates a new tweet using the Twitter API.

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
