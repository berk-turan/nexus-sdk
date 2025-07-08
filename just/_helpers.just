
[private]
_check-cargo:
    #!/usr/bin/env bash
    if ! command -v cargo &> /dev/null
    then
        echo "cargo could not be found"
        echo "Install cargo from https://doc.rust-lang.org/cargo/getting-started/installation.html"
        exit 1
    fi

[private]
_check-cargo-nextest: _check-cargo
    #!/usr/bin/env bash
    if ! command -v cargo-nextest &> /dev/null
    then
        echo "cargo-nextest could not be found"
        echo "Install cargo-nextest from https://nexte.st/"
        exit 1
    fi
