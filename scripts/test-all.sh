#!/bin/sh
set -e

./scripts/test.sh
./scripts/test-wasm.sh

CURVE=x25519 ./scripts/test.sh
CURVE=x25519 ./scripts/test-wasm.sh

# CURVE=ed25519 ./scripts/test.sh
# CURVE=ed25519 ./scripts/test-wasm.sh
