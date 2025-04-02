#!/bin/sh
set -e

cargo llvm-cov --no-report --no-default-features --features $CURVE,aes-openssl,$STD
cargo llvm-cov --no-report --no-default-features --features $CURVE,aes-rust,$STD

