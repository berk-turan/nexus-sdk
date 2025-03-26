#![doc = include_str!("../README.md")]

use nexus_toolkit::bootstrap;

mod i64;

#[tokio::main]
async fn main() {
    let addr_str = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let addr: std::net::SocketAddr = addr_str
        .parse()
        .expect("Invalid socket address in BIND_ADDR");

    bootstrap!(
        addr,
        [
            i64::add::I64Add,
            i64::mul::I64Mul,
            i64::cmp::I64Cmp,
            //
        ]
    )
}
