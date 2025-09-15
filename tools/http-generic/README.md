# `xyz.taluslabs.http.generic.request@1`

Standard Nexus Tool that makes generic HTTP requests to any API endpoint. Supports multiple authentication methods, body types, and response validation.

## Input

**`method`: [`String`]**

The HTTP method to use (e.g., "GET", "POST", "PUT", "DELETE").

**`url`: [`String`] (optional)**

The complete URL for the request. Either `url` or both `base_url` and `path` must be provided.

**`base_url`: [`String`] (optional)**

The base URL for the request. Must be used with `path` parameter.

**`path`: [`String`] (optional)**

The path to append to `base_url`. Must be used with `base_url` parameter.

**`headers`: [`Map<String, String>`] (optional)**

HTTP headers to include in the request.

**`query`: [`Map<String, String>`] (optional)**

Query parameters to append to the URL.

**`auth`: [`AuthConfig`] (optional)**

Authentication configuration. See AuthConfig variants below.

**`body`: [`BodyConfig`] (optional)**

Request body configuration. See BodyConfig variants below.

**`timeout_ms`: [`u64`] (optional)**

Request timeout in milliseconds. Defaults to 30000 (30 seconds).

**`retries`: [`u32`] (optional)**

Number of retry attempts on failure. Defaults to 0.

**`follow_redirects`: [`bool`] (optional)**

Whether to follow HTTP redirects. Defaults to true.

**`expect_json`: [`bool`] (optional)**

Whether to expect JSON response and parse it. Defaults to false.

**`json_schema`: [`String`] (optional)**

JSON schema to validate the response against (if `expect_json` is true).

### AuthConfig Variants

**`none`**

No authentication required.

**`bearer`**

Bearer token authentication.

- **`bearer.token`: [`String`]** - The bearer token

**`api_key`**

API key authentication.

- **`api_key.key`: [`String`]** - The API key value
- **`api_key.location`: [`String`]** - Where to place the key ("header" or "query")
- **`api_key.name`: [`String`]** - The parameter name (e.g., "Authorization", "X-API-Key")

**`basic`**

Basic authentication.

- **`basic.username`: [`String`]** - The username
- **`basic.password`: [`String`]** - The password

### BodyConfig Variants

**`json`**

JSON request body.

- **`json.data`: [`Value`]** - The JSON data to send

**`form_urlencoded`**

Form URL-encoded request body.

- **`form_urlencoded.data`: [`Map<String, String>`]** - The form data

**`multipart`**

Multipart form data request body.

- **`multipart.data`: [`Map<String, String>`]** - The multipart data

**`raw`**

Raw bytes request body.

- **`raw.data`: [`String`]** - The raw data (base64 encoded)

## Output Variants & Ports

**`ok`**

The HTTP request was successful.

- **`ok.status`: [`u16`]** - HTTP status code
- **`ok.headers`: [`Map<String, String>`]** - Response headers
- **`ok.raw_base64`: [`String`]** - Raw response body (base64 encoded)
- **`ok.text`: [`String`] (optional)** - Response body as text (if valid UTF-8)
- **`ok.json`: [`Value`] (optional)** - Response body as JSON (if `expect_json` is true)
- **`ok.schema_valid`: [`bool`] (optional)** - Whether response matches JSON schema (if provided)

**`err_http`**

HTTP request failed with an error status code.

- **`err_http.reason`: [`String`]** - Error description
- **`err_http.status`: [`u16`]** - HTTP status code
- **`err_http.headers`: [`Map<String, String>`]** - Response headers (if available)

**`err_json_parse`**

Failed to parse response as JSON.

- **`err_json_parse.reason`: [`String`]** - JSON parsing error description
- **`err_json_parse.text`: [`String`]** - Response text that failed to parse

**`err_schema_validation`**

Response failed JSON schema validation.

- **`err_schema_validation.reason`: [`String`]** - Schema validation error description
- **`err_schema_validation.json`: [`Value`]** - The JSON that failed validation

**`err_network`**

Network or connection error occurred.

- **`err_network.reason`: [`String`]** - Network error description
