#!/bin/sh

# OpenSSL AES
cargo test --no-default-features --features openssl
cargo test --no-default-features --features openssl,std
cargo test --no-default-features --features openssl,aes-12bytes-nonce
cargo test --no-default-features --features openssl,std,aes-12bytes-nonce

# Pure Rust AES
cargo test --no-default-features --features pure
cargo test --no-default-features --features pure,std
cargo test --no-default-features --features pure,aes-12bytes-nonce
cargo test --no-default-features --features pure,std,aes-12bytes-nonce

# XChaCha20
cargo test --no-default-features --features xchacha20
cargo test --no-default-features --features xchacha20,std
