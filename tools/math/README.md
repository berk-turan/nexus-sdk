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

---

# `xyz.taluslabs.math.i64.mul@1`

Standard Nexus Tool that multiplies two [`i64`] numbers and returns the result.

## Input

### `a`: [`i64`]

The first number to multiply.

### `b`: [`i64`]

The second number to multiply.

## Output Variants & Ports

### `ok`

The multiplication was successful.

- **`ok.result`: [`i64`]** - The result of the multiplication.

### `err`

The multiplication failed due to overflow.

- **`err.reason`: [`String`]** - The reason for the error. This is always overflow.

---

# `xyz.taluslabs.math.i64.cmp@1`

Standard Nexus Tool that compares two [`i64`] numbers and returns the result.

## Input

### `a`: [`i64`]

The first number to compare.

### `b`: [`i64`]

The second number to compare.

## Output Variants & Ports

### `gt`

The first number is greater than the second.

- **`gt.a`: [`i64`]** - The first number.
- **`gt.b`: [`i64`]** - The second number.

### `eq`

The first number is equal to the second.

- **`eq.a`: [`i64`]** - The first number.
- **`eq.b`: [`i64`]** - The second number.

### `lt`

The first number is less than the second.

- **`lt.a`: [`i64`]** - The first number.
- **`lt.b`: [`i64`]** - The second number.
