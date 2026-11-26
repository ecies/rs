#!/bin/sh
set -e

# the default build
FEATURES=secp256k1 ./scripts/test.sh
FEATURES=secp256k1 ./scripts/test-wasm.sh

# every curve
FEATURES=secp256k1,curve25519 ./scripts/test.sh
FEATURES=secp256k1,curve25519 ./scripts/test-wasm.sh

# curve25519 without secp256k1, which compiles out `Config::DEFAULT`, `encrypt` and `decrypt`
FEATURES=curve25519 ./scripts/test.sh
FEATURES=curve25519 ./scripts/test-wasm.sh

# every curve, with AES-256-GCM on OpenSSL
FEATURES=secp256k1,curve25519,aes-openssl ./scripts/test.sh
