# `xyz.taluslabs.math.i64.add@1`

Standard Nexus Tool that adds two [`i64`] numbers and returns the result.

## Input

### `a`: [`i64`]

The first number to add.

### `b`: [`i64`]

The second number to add.

## Output Variants & Ports

### `ok`

The addition was successful.

- **`ok.result`: [`i64`]** - The result of the addition.

### `err`

The addition failed due to overflow.

- **`err.reason`: [`String`]** - The reason for the error. This is always overflow.
