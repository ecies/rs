# Changelog

## 0.2.14

- Stop printing secp256k1 `SecretKey` bytes in `Debug`, and compare secret keys in constant time

## 0.2.13

- Bump k256 to 0.14 to fix [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html) from crypto-bigint, without changing the public interface
- Bump MSRV to 1.87 per crypto-bigint (1.87) and elliptic-curve (1.87)

## 0.2.12

- Bump MSRV to 1.85 and edition to 2024
- Bump dev dependencies
- Bump hkdf, sha2, aes-gcm and chacha20poly1305
- Revamp encapsulate and encrypt performance
- Reject malformed x25519/ed25519 key lengths instead of panicking
- Prepare for the upcoming curve libraries bump (k256, curve25519-dalek, x25519-dalek, ed25519-dalek). Those versions move to rand_core 0.10, where `OsRng` no longer exists (replaced by `getrandom::SysRng`)
  - Note: to make your code forward-compatible, prefer `utils::generate_keypair()`, or `SecretKey::generate()` added in this release. `SecretKey::generate_from_rng(rng)` is also added, but its `rng` parameter will change to a rand_core 0.10 type

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
