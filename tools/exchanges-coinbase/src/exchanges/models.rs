//! Data models for Coinbase exchange endpoints

use {
    crate::error::CoinbaseApiError,
    schemars::JsonSchema,
    serde::{Deserialize, Serialize},
};

/// Spot price data from Coinbase API
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SpotPriceData {
    /// The price amount as a string
    pub amount: String,
    /// The base currency (e.g., "BTC", "ETH")
    pub base: String,
    /// The quote currency (e.g., "USD", "USDT")
    pub currency: String,
}

/// Product ticker data from Coinbase Exchange API
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProductTickerData {
    /// Best ask price
    pub ask: String,
    /// Best bid price
    pub bid: String,
    /// 24h volume
    pub volume: String,
    /// Trade ID of the last trade
    pub trade_id: u64,
    /// Last trade price
    pub price: String,
    /// Last trade size
    pub size: String,
    /// Time of the last trade
    pub time: String,
    /// RFQ volume (optional field)
    pub rfq_volume: Option<String>,
    /// Conversions volume (optional field)
    pub conversions_volume: Option<String>,
}

/// Coinbase API response with potential errors
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CoinbaseApiResponse<T> {
    /// The response data
    pub data: Option<T>,
    /// List of errors if any
    pub errors: Option<Vec<CoinbaseApiError>>,
}

/// Order book level specification
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum OrderBookLevel {
    #[serde(rename = "1")]
    L1,
    #[serde(rename = "2")]
    L2,
    #[serde(rename = "3")]
    L3,
}

/// Order book entry format with level-aware third field
/// L1/L2: [price, size, num_orders] where num_orders is u32
/// L3: [price, size, order_id] where order_id is string
pub type OrderEntry = (String, String, serde_json::Value);

/// Order book response from Coinbase Exchange API
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OrderBookData {
    /// Bid orders: [price, size, num_orders]
    pub bids: Vec<OrderEntry>,
    /// Ask orders: [price, size, num_orders]
    pub asks: Vec<OrderEntry>,
    /// Sequence number for ordering
    pub sequence: u64,
    /// Auction mode status
    pub auction_mode: bool,
    /// Auction details (nullable)
    pub auction: Option<serde_json::Value>,
    /// Response timestamp
    pub time: String,
}