#!/bin/sh
set -e

# Pure Rust AES on WASM target
cargo test --no-default-features --features $CURVE,aes-rust --target=wasm32-unknown-unknown
cargo test --no-default-features --features $CURVE,aes-rust,std --target=wasm32-unknown-unknown
cargo test --no-default-features --features $CURVE,aes-rust,aes-12bytes-nonce --target=wasm32-unknown-unknown
cargo test --no-default-features --features $CURVE,aes-rust,aes-12bytes-nonce,std --target=wasm32-unknown-unknown

# XChaCha20 on WASM target
cargo test --no-default-features --features $CURVE,xchacha20 --target=wasm32-unknown-unknown
cargo test --no-default-features --features $CURVE,xchacha20,std --target=wasm32-unknown-unknown
