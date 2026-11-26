#!/bin/sh
set -e

# --lib --tests leaves out the doctests: wasm-bindgen-test-runner finds no `#[wasm_bindgen_test]` in them, so it would
# report them as passed without running them. test.sh runs them natively

# FEATURES: the features on top of --no-default-features. OpenSSL doesn't build for WASM, so leave out aes-openssl
cargo test --no-default-features --features $FEATURES --target=wasm32-unknown-unknown --lib --tests
cargo test --no-default-features --features $FEATURES,std --target=wasm32-unknown-unknown --lib --tests
