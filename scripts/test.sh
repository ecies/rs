#!/bin/sh
set -e

# OpenSSL AES
cargo test --no-default-features --features $CURVE,openssl
cargo test --no-default-features --features $CURVE,openssl,std
cargo test --no-default-features --features $CURVE,openssl,aes-12bytes-nonce
cargo test --no-default-features --features $CURVE,openssl,aes-12bytes-nonce,std

# Pure Rust AES
cargo test --no-default-features --features $CURVE,pure
cargo test --no-default-features --features $CURVE,pure,std
cargo test --no-default-features --features $CURVE,pure,aes-12bytes-nonce
cargo test --no-default-features --features $CURVE,pure,aes-12bytes-nonce,std

# XChaCha20
cargo test --no-default-features --features $CURVE,xchacha20
cargo test --no-default-features --features $CURVE,xchacha20,std
