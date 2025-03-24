#!/bin/sh
set -e

cargo llvm-cov clean --workspace

./scripts/cov.sh
STD=std ./scripts/cov.sh

CURVE=x25519 ./scripts/cov.sh
CURVE=x25519 STD=std ./scripts/cov.sh

CURVE=ed25519 ./scripts/cov.sh
CURVE=ed25519 STD=std ./scripts/cov.sh

cargo llvm-cov report --lcov --output-path .lcov.info
cargo llvm-cov report
