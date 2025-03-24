#!/bin/sh
set -e

cargo check --no-default-features --features $CURVE,openssl
cargo check --no-default-features --features $CURVE,pure
cargo check --no-default-features --features $CURVE,xchacha20

cargo clippy --no-default-features --features $CURVE,openssl
cargo clippy --no-default-features --features $CURVE,pure
cargo clippy --no-default-features --features $CURVE,xchacha20
