#!/bin/sh
set -e

# OpenSSL AES
cargo test --no-default-features --features $CURVE,aes-openssl
cargo test --no-default-features --features $CURVE,aes-openssl,std
cargo test --no-default-features --features $CURVE,aes-openssl,aes-12bytes-nonce
cargo test --no-default-features --features $CURVE,aes-openssl,aes-12bytes-nonce,std

# Pure Rust AES
cargo test --no-default-features --features $CURVE,aes-rust
cargo test --no-default-features --features $CURVE,aes-rust,std
cargo test --no-default-features --features $CURVE,aes-rust,aes-12bytes-nonce
cargo test --no-default-features --features $CURVE,aes-rust,aes-12bytes-nonce,std

# XChaCha20
cargo test --no-default-features --features $CURVE,xchacha20
cargo test --no-default-features --features $CURVE,xchacha20,std
