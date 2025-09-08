#![doc = include_str!("../README.md")]

use nexus_toolkit::bootstrap;

mod coinbase_client;
mod error;
mod exchanges;

#[tokio::main]
async fn main() {
    bootstrap!([
        exchanges::get_spot_price::GetSpotPrice,
        exchanges::get_product_ticker::GetProductTicker,
        exchanges::get_product_candles::GetProductCandles,
    ]);
}
