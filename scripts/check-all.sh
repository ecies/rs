#!/bin/sh
set -e

./scripts/check.sh
CURVE=x25519 ./scripts/check.sh
CURVE=ed25519 ./scripts/check.sh
