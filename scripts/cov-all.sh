#!/bin/sh
set -e

cargo llvm-cov clean --workspace

# every curve, with AES-256-GCM in pure Rust and then on OpenSSL
FEATURES=secp256k1,curve25519 ./scripts/cov.sh
FEATURES=secp256k1,curve25519,aes-openssl ./scripts/cov.sh

cargo llvm-cov report --lcov --output-path .lcov.info
cargo llvm-cov report
