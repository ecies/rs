# Changelog

## 0.2.12

- Bump MSRV to 1.85 and edition to 2024
- Bump dev dependencies
- Bump hkdf, sha2, aes-gcm and chacha20poly1305
- Revamp encapsulate and encrypt performance
- Reject malformed x25519/ed25519 key lengths instead of panicking
- Prepare for the upcoming curve libraries bump (k256, curve25519-dalek, x25519-dalek, ed25519-dalek). Those versions move to rand_core 0.10, where `OsRng` no longer exists (replaced by `getrandom::SysRng`)
  - Note: to make your code forward-compatible, prefer `utils::generate_keypair()`, or `SecretKey::generate()`/`SecretKey::generate_from_rng(rng)` added in this release

## 0.2.11

- Migrate to k256 from libsecp256k1
- Bump MSRV to 1.81 per openssl (1.80) and ed25519-dalek (1.81)

## 0.2.10

- Add homemade rwlock for `no_std`
- Add `zeroize` feature for x25519/ed25519
- Add `compressed` argument to encapsulate/decapsulate functions
  - Note: this might break a little of client code but can be easily fixed

## 0.2.9

- Add ed25519 support
- Add renamed features: `aes-openssl`, `aes-rust`, `aes-short-nonce`. The old features (`openssl`, `pure`, `aes-12bytes-nonce`) are still supported, but will be removed in the future

## 0.2.8

- Bump dependencies
- Add x25519 support

## 0.2.1 ~ 0.2.7

- Support `no_std`
- Revamp documentation
- Revamp configuration and add XChaCha20-Poly1305 backend
- Add configuration for more compatibility
- Revamp error handling
- Migrate to edition 2021
- Bump dependencies

## 0.2.0

- Revamp documentation
- Optional pure Rust AES backend
- WASM compatibility

## 0.1.1 ~ 0.1.5

- Bump dependencies
- Update documentation
- Fix error handling

## 0.1.0

- First beta version release
