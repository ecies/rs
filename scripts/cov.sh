#!/bin/sh
set -e

cargo llvm-cov --no-report --no-default-features --features $CURVE,openssl,$STD
cargo llvm-cov --no-report --no-default-features --features $CURVE,pure,$STD

