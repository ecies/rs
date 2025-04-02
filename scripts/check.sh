#!/bin/sh
set -e

cargo check --no-default-features --features $CURVE,aes-openssl
cargo check --no-default-features --features $CURVE,aes-rust
cargo check --no-default-features --features $CURVE,xchacha20

cargo clippy --no-default-features --features $CURVE,aes-openssl
cargo clippy --no-default-features --features $CURVE,aes-rust
cargo clippy --no-default-features --features $CURVE,xchacha20
