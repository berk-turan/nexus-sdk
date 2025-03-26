//! # `xyz.taluslabs.social.twitter.*`
//!
//! This module contains tools for Twitter operations.
#![doc = include_str!("../README.md")]

use nexus_toolkit::bootstrap;
mod list;
mod tweet;

/// This function bootstraps the tool and starts the server.
#[tokio::main]
async fn main() {
    bootstrap!([
        tweet::post_tweet::PostTweet,
        tweet::get_tweet::GetTweet,
        tweet::like_tweet::LikeTweet,
        tweet::mentioned_tweets::MentionedTweets,
        tweet::get_user_tweets::GetUserTweets,
        list::create_list::CreateList,
    ]);
}
