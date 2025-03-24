//! # `xyz.taluslabs.social.twitter.*`
//!
//! This module contains tools for x-api operations. They are divided
//! into modules based on the datatype of the input.

pub(crate) mod tweet;
pub(crate) mod single_tweet;
pub(crate) mod models;

pub const TWITTER_API_BASE: &str = "https://api.twitter.com/2";
