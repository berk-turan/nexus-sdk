# `xyz.taluslabs.market.coinbase.get-spot-price@1`

Standard Nexus Tool that retrieves the current spot price for a currency pair from Coinbase. Coinbase API [reference](https://docs.cdp.coinbase.com/coinbase-app/track-apis/prices)

## Input

**`currency_pair`: [`String`]**

The currency pair to get spot price for (e.g., "BTC-USD", "ETH-EUR", "ADA-USD").

## Output Variants & Ports

**`ok`**

The spot price was retrieved successfully.

- **`ok.amount`: [`String`]** - The price amount as a string
- **`ok.base`: [`String`]** - The base currency (e.g., "BTC", "ETH")
- **`ok.currency`: [`String`]** - The quote currency (e.g., "USD", "USDT")

**`err`**

The spot price request failed due to an error.

- **`err.reason`: [`String`]** - A detailed error message describing what went wrong

