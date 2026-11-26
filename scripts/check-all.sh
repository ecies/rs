#!/bin/sh
set -e

FEATURES=secp256k1 ./scripts/check.sh
FEATURES=secp256k1,curve25519 ./scripts/check.sh
FEATURES=curve25519 ./scripts/check.sh
FEATURES=secp256k1,curve25519,aes-openssl ./scripts/check.sh

# Every combination of the features with code behind them, as long as it has a curve. The no-ops compile nothing,
# and the tombstones fail the build by design, which check-features.sh checks
cargo hack check --feature-powerset --at-least-one-of secp256k1,curve25519 \
  --exclude-features default,aes-rust,zeroize,x25519,ed25519,xchacha20,aes-short-nonce,aes-12bytes-nonce

./scripts/check-features.sh
