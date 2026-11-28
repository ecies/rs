#!/bin/sh
set -e

# FEATURES: the features on top of --no-default-features, such as secp256k1,curve25519
cargo check --no-default-features --features $FEATURES
cargo clippy --no-default-features --features $FEATURES
