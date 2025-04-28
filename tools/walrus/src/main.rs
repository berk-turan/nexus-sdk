#![doc = include_str!("../README.md")]

use nexus_toolkit::bootstrap;

mod json;

#[tokio::main]
async fn main() {
    bootstrap!([json::upload_json::UploadJson])
}
