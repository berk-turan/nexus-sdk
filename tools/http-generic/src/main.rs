#![doc = include_str!("../README.md")]

use nexus_toolkit::bootstrap;

mod auth;
mod core;
mod models;
mod tool;
mod utils;

#[tokio::main]
async fn main() {
    bootstrap!(tool::GenericHttpRequest);
}
