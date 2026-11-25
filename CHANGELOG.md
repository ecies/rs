# Changelog

## 0.2.16

- Reject small-order x25519 and ed25519 public keys, and mixed-order ed25519 keys, in `encrypt`, `decrypt`, their `_with_config` versions, `encapsulate` and `decapsulate`: ed25519 returns `Error::InvalidPublicKey`, and x25519 returns `Error::InvalidMessage`. With a small-order key the shared point is predictable, so anyone could decrypt a message sent to such a key, and a forged message carrying one as its ephemeral key decrypted under every secret key ([#180](https://github.com/ecies/rs/issues/180))
- Add `encrypt_with_config` and `decrypt_with_config`, which take additional authenticated data (AAD) and a `Config` instead of reading the global config. The AAD support comes from [#159](https://github.com/ecies/rs/pull/159) by beardedeagle
- Add `Config::DEFAULT` and `Config::ephemeral_key_size()`, and derive `Clone`, `Debug`, `PartialEq`, `Eq` and `Hash` for `Config`
- Deprecate the global config: `ECIES_CONFIG`, `update_config`, `reset_config`, `is_ephemeral_key_compressed`, `is_hkdf_key_compressed` and `get_ephemeral_key_size`. 0.3 removes them ([#178](https://github.com/ecies/rs/issues/178))
- Announce 0.3's feature changes: the `x25519`, `ed25519`, `xchacha20`, `aes-short-nonce` and `aes-12bytes-nonce` features will fail the build with a message naming the replacement `Config` field, and X25519 and Ed25519 move behind one `curve25519` feature. The backend aliases `openssl` and `pure` are removed. Pure Rust becomes the default AES backend; enable `aes-openssl` to keep OpenSSL ([#178](https://github.com/ecies/rs/issues/178))
- `encrypt` and `decrypt` read the global config once per call, so a concurrent `update_config` can no longer mix the two flags
- Document enabling `std` on targets with the standard library: outside wasm32, binaries fail to link without it unless another dependency enables `once_cell/std` or provides a `critical-section` implementation

## 0.2.15

- Fix the OpenSSL AES backend (`aes-openssl`, the default) panicking on messages over 2 GiB, in both `encrypt` and `decrypt` ([#174](https://github.com/ecies/rs/issues/174))

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
