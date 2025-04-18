# eciesrs

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/1c6d6ed949dd4836ab97421039e8be75)](https://app.codacy.com/gh/ecies/rs/dashboard)
[![License](https://img.shields.io/github/license/ecies/rs.svg)](https://github.com/ecies/rs)
[![Crates](https://img.shields.io/crates/v/ecies)](https://crates.io/crates/ecies)
[![Recent Downloads](https://img.shields.io/crates/dr/ecies)](https://lib.rs/crates/ecies)
[![Doc](https://docs.rs/ecies/badge.svg)](https://docs.rs/ecies/latest/ecies/)
[![CI](https://img.shields.io/github/actions/workflow/status/ecies/rs/ci.yml)](https://github.com/ecies/rs/actions)
[![Codecov](https://img.shields.io/codecov/c/github/ecies/rs.svg)](https://codecov.io/gh/ecies/rs)

Elliptic Curve Integrated Encryption Scheme for secp256k1/curve25519 in Rust, based on pure-Rust secp256k1/curve25519 implementation.

ECIES functionalities are built upon AES-256-GCM/XChaCha20-Poly1305 and HKDF-SHA256.

This is the Rust version of [eciesjs](https://github.com/ecies/js).

This library can be compiled to the WASM target at your option, see [WASM compatibility](#wasm-compatibility).

## Quick start

`no_std` is enabled by default. You can enable `std` with `std` feature.

```toml
ecies = {version = "0.2", features = ["std"]} # MSRV is 1.65
```

```rust
use ecies::{decrypt, encrypt, utils::generate_keypair};

const MSG: &str = "hello world🌍";
let (sk, pk) = generate_keypair();
#[cfg(all(not(feature = "x25519"), not(feature = "ed25519")))]
let (sk, pk) = (&sk.serialize(), &pk.serialize());
#[cfg(feature = "x25519")]
let (sk, pk) = (sk.as_bytes(), pk.as_bytes());
#[cfg(feature = "ed25519")]
let (sk, pk) = (&sk, &pk);

let msg = MSG.as_bytes();
assert_eq!(
    msg,
    decrypt(sk, &encrypt(pk, msg).unwrap()).unwrap().as_slice()
);
```

## Elliptic curve configuration

### Optional x25519/ed25519 support

You can choose to use x25519 (key exchange function on curve25519) or ed25519 (signature algorithm on curve25519) instead of secp256k1:

```toml
ecies = {version = "0.2", features = ["x25519"]} # recommended
ecies = {version = "0.2", features = ["ed25519"]} # or if you know what you are doing
```

### Secp256k1-specific configuration

Some behaviors can be configured by global static variable:

```rust
pub struct Config {
    pub is_ephemeral_key_compressed: bool,
    pub is_hkdf_key_compressed: bool
}
```

On `is_ephemeral_key_compressed: true`, the payload would be like: `33 Bytes + AES` instead of `65 Bytes + AES`.

On `is_hkdf_key_compressed: true`, the hkdf key would be derived from `ephemeral public key (compressed) + shared public key (compressed)` instead of `ephemeral public key (uncompressed) + shared public key (uncompressed)`.

```rust
use ecies::config::{Config, update_config};

update_config(Config {
    is_ephemeral_key_compressed: true,
    is_hkdf_key_compressed: true
});
```

For compatibility, make sure different applications share the same configuration. Normally configuration is only updated once on initialization, if not, beware of race condition.

## Symmetric cipher configuration

### Optional pure Rust AES backend

You can choose to use OpenSSL implementation or [pure Rust implementation](https://github.com/RustCrypto/AEADs) of AES-256-GCM:

```toml
ecies = {version = "0.2", default-features = false, features = ["aes-rust"]}
```

Due to some [performance problem](https://github.com/RustCrypto/AEADs/issues/243), OpenSSL is the default backend.

Pure Rust implementation is sometimes useful, such as building on WASM:

```bash
cargo build --no-default-features --features aes-rust --target=wasm32-unknown-unknown
```

#### Build on x86 CPUs

If you select the pure Rust backend on modern x86 CPUs, consider building with

```bash
RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"
```

It can speed up AES encryption/decryption. This would be no longer necessary when [`aes-gcm` supports automatic CPU detection](https://github.com/RustCrypto/AEADs/issues/243#issuecomment-738821935).

#### Build on ARM CPUs

On ARM CPUs (like Apple), consider building with

```bash
RUSTFLAGS="--cfg aes_armv8"
```

### Optional pure Rust XChaCha20-Poly1305 backend

You can also enable a pure Rust [XChaCha20-Poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305) backend.

```toml
ecies = {version = "0.2", default-features = false, features = ["xchacha20"]}
```

On ARM CPUs, enable SIMD with

```bash
RUSTFLAGS="--cfg chacha20_force_neon"
```

## WASM compatibility

It's also possible to build to the `wasm32-unknown-unknown` target (or `wasm32-wasip2`) with the pure Rust backend. Check out [this repo](https://github.com/ecies/rs-wasm) for more details.

## Security

### Why AES-256-GCM and HKDF-SHA256

AEAD scheme like AES-256-GCM should be your first option for symmetric ciphers, with unique IVs in each encryption.

For key derivation functions on shared points between two asymmetric keys, HKDFs are [proven](https://github.com/ecies/py/issues/82) to be more secure than simple hash functions like SHA256.

### Why XChaCha20-Poly1305 instead of AES-256-GCM

XChaCha20-Poly1305 is a competitive alternative to AES-256-GCM because it's fast and constant-time without dedicated hardware acceleration (resistant to cache-timing attacks). It also has longer nonce length to alleviate the risk of birthday attacks when nonces are generated randomly.

### Cross-language compatibility

All functionalities are mutually checked among [different languages](https://github.com/ecies): Python, Rust, JavaScript and Golang.

### Security audit

Following dependencies are audited:

- [aes-gcm and chacha20poly1305](https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/)
- [OpenSSL](https://ostif.org/the-ostif-and-quarkslab-audit-of-openssl-is-complete/)

## Benchmark

On Mac mini M4 Pro (24 GB) on Apr 2, 2025, secp256k1 only.

Rust version: 1.85.0 (4d91de4e4 2025-02-17)

### AES backend (OpenSSL)

```bash
$ cargo bench --no-default-features --features aes-openssl

encrypt 100M            time:   [29.237 ms 29.827 ms 30.628 ms]
Found 2 outliers among 10 measurements (20.00%)
  1 (10.00%) low mild
  1 (10.00%) high mild

encrypt 200M            time:   [86.005 ms 88.055 ms 89.282 ms]

decrypt 100M            time:   [17.222 ms 17.568 ms 17.977 ms]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high mild

decrypt 200M            time:   [38.884 ms 39.324 ms 39.693 ms]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high mild
```

### AES backend (Pure Rust)

```bash
$ export RUSTFLAGS="--cfg aes_armv8"
$ cargo bench --no-default-features --features aes-rust

encrypt 100M            time:   [120.40 ms 122.63 ms 127.09 ms]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high severe

encrypt 200M            time:   [253.86 ms 256.43 ms 258.01 ms]

decrypt 100M            time:   [113.73 ms 114.05 ms 114.39 ms]

decrypt 200M            time:   [236.41 ms 237.82 ms 239.12 ms]
```

### XChaCha20 backend

```bash
$ export RUSTFLAGS="--cfg chacha20_force_neon"
$ cargo bench --no-default-features --features xchacha20

encrypt 100M            time:   [120.24 ms 120.98 ms 121.63 ms]

encrypt 200M            time:   [257.24 ms 261.22 ms 264.06 ms]

decrypt 100M            time:   [114.39 ms 114.94 ms 116.03 ms]

decrypt 200M            time:   [238.09 ms 240.60 ms 242.55 ms]
```

## Changelog

See [CHANGELOG.md](./CHANGELOG.md).
