# Changelog

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
