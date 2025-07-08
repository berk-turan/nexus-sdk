import '../just/_helpers.just'

[private]
_default:
    @just --list pre-commit


check-toolchain-version: _check-cargo
    #!/usr/bin/env bash

    cargo_version=$(cargo --version | awk '{print $2}')
    toolchain_version=$(grep '^channel *= *"[^"]\+"' rust-toolchain.toml | sed -E 's/.*"([^"]+)".*/\1/')

    echo "Cargo version: $cargo_version"
    echo "Toolchain version: $toolchain_version"

    # cargo_version is 1.86.0 and toolchain_version is 1.86, so we need to compare them
    if [[ "$cargo_version" != "$toolchain_version"* ]]; then
      echo "Cargo version ($cargo_version) does not match toolchain version ($toolchain_version)." >&2
      exit 1
    fi

    echo "Cargo version matches toolchain version."


# cargo check --locked --workspace --bins --examples
cargo-check: _check-cargo
    cargo check --locked --workspace --bins --examples

# cargo +nightly-2025-01-06 fmt --all --check
cargo-nightly-fmt: _check-cargo
    #!/usr/bin/env bash

    cargo +nightly-2025-01-06 fmt --all --check || {
        echo "== Formatting failed. Please run 'cargo +nightly fmt --all' to format the code." >&2
        exit 1
    }

# cargo clippy --all-targets --all-features
cargo-clippy: _check-cargo
    cargo clippy --all-targets --all-features



# Note: [here](https://github.com/Talus-Network/nexus-sdk/blob/a9f6ed643c1b03094819984938ad357f6e596fc9/.github/workflows/sdk.yml#L60)
# we run [this](https://github.com/Talus-Network/nexus-sdk/blob/a9f6ed643c1b03094819984938ad357f6e596fc9/sdk/.just#L28),
# which uses `-D warnings` to fail the build if there are any Clippy warnings but apparently that fails.
# TODO: So when exactly does this run?
#
# cargo clippy --all-targets --all-features -- -D warnings
cargo-clippy-strict: _check-cargo
    cargo clippy --all-targets --all-features -- -D warnings


# cargo nextest run --locked --no-run --workspace --all-features --bins --examples --tests
cargo-nextest-build: _check-cargo
    cargo nextest run --locked --no-run --workspace --all-features --bins --examples --tests

# Note: The idea for `--fail-fast` is that the change we are commiting is the one responsible for
# the failure, so there is no need to keep running the remaining tests...
# cargo nextest run --locked --fail-fast --workspace --all-features --bins --examples --tests
cargo-nextest-run: _check-cargo
    cargo nextest run --locked --fail-fast --workspace --all-features --bins --examples --tests
