#!/bin/sh
set -e

# --lib --tests leaves out the doctests: wasm-bindgen-test-runner finds no `#[wasm_bindgen_test]` in them, so it would
# report them as passed without running them. test.sh runs them natively

# Pure Rust AES on WASM target
cargo test --no-default-features --features $CURVE,aes-rust --target=wasm32-unknown-unknown --lib --tests
cargo test --no-default-features --features $CURVE,aes-rust,std --target=wasm32-unknown-unknown --lib --tests
cargo test --no-default-features --features $CURVE,aes-rust,aes-12bytes-nonce --target=wasm32-unknown-unknown --lib --tests
cargo test --no-default-features --features $CURVE,aes-rust,aes-12bytes-nonce,std --target=wasm32-unknown-unknown --lib --tests

# XChaCha20 on WASM target
cargo test --no-default-features --features $CURVE,xchacha20 --target=wasm32-unknown-unknown --lib --tests
cargo test --no-default-features --features $CURVE,xchacha20,std --target=wasm32-unknown-unknown --lib --tests
