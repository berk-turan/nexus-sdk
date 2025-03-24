//! # `xyz.taluslabs.social.twitter.*`
//!
//! This module contains tools for x-api operations. They are divided
//! into modules based on the datatype of the input.

use nexus_toolkit::bootstrap;
mod twitter;

/// This function bootstraps the tool and starts the server.
#[tokio::main]
async fn main() {
    bootstrap!([twitter::tweet::Tweet, twitter::single_tweet::SingleTweet]);
}
