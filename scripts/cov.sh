#!/bin/sh
set -e

# FEATURES: the features on top of --no-default-features, such as secp256k1,curve25519
cargo llvm-cov --no-report --no-default-features --features $FEATURES
cargo llvm-cov --no-report --no-default-features --features $FEATURES,std
