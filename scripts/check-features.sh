#!/bin/sh
# Each tombstone feature, and a build with no curve feature, must fail with a message naming the replacement
set -u

status=0
# 0.2's calls still compile in 0.3 and change meaning, so the messages send users to every call site
no_default="with \`default-features = false\`"
find_default="cargo tree -e features -i ecies"
every_call="on every call"
# 0.2.16's docs told users to fill a `Config` from `Config::DEFAULT`, which now picks AES-256-GCM with a 16-byte nonce
from_default="each Config built from Config::DEFAULT or Config::default() still compile"
other_curves="Config::new(EllipticCurve::X25519) or Config::new(EllipticCurve::Ed25519)"

# expect_error <features> <text the errors must say>...
expect_error() {
  features=$1
  shift
  # without colour, so the errors printed below start with `error`, also under CI's CARGO_TERM_COLOR=always
  if output=$(cargo check --lib --quiet --color never --no-default-features --features "$features" 2>&1); then
    echo "FAIL [$features]: built, but should fail with: $1"
    status=1
    return
  fi
  for text in "$@"; do
    if ! printf '%s\n' "$output" | grep -qF -- "$text"; then
      echo "FAIL [$features]: the errors don't say: $text"
      printf '%s\n' "$output" | grep '^error'
      status=1
      return
    fi
  done
  echo "ok   [$features]"
}

expect_error "std" "enable the \`secp256k1\` feature" "\`curve25519\`"
expect_error "secp256k1,x25519" "removed the \`x25519\` feature" "enable \`curve25519\` instead, $no_default" \
  "Config::new(EllipticCurve::X25519)" "$find_default"
expect_error "secp256k1,ed25519" "removed the \`ed25519\` feature" "enable \`curve25519\` instead, $no_default" \
  "Config::new(EllipticCurve::Ed25519)" "$find_default"
expect_error "secp256k1,xchacha20" "removed the \`xchacha20\` feature" "$from_default" "$every_call" \
  "symmetric_algorithm: SymmetricAlgorithm::XChaCha20" "$other_curves"
expect_error "secp256k1,aes-short-nonce" "removed the \`aes-short-nonce\` feature" "$from_default" "$every_call" \
  "symmetric_nonce_length: NonceLength::Twelve" "$other_curves"
expect_error "secp256k1,aes-12bytes-nonce" "removed the \`aes-12bytes-nonce\` feature" "$from_default" "$every_call" \
  "symmetric_nonce_length: NonceLength::Twelve" "$other_curves"

exit $status
