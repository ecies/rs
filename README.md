# eciesrs

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/1c6d6ed949dd4836ab97421039e8be75)](https://app.codacy.com/gh/ecies/rs/dashboard)
[![License](https://img.shields.io/github/license/ecies/rs.svg)](https://github.com/ecies/rs)
[![CI](https://img.shields.io/github/actions/workflow/status/ecies/rs/ci.yml)](https://github.com/ecies/rs/actions)
[![Codecov](https://img.shields.io/codecov/c/github/ecies/rs.svg)](https://codecov.io/gh/ecies/rs)
[![Crates](https://img.shields.io/crates/v/ecies)](https://crates.io/crates/ecies)
[![Doc](https://docs.rs/ecies/badge.svg)](https://docs.rs/ecies/latest/ecies/)

Elliptic Curve Integrated Encryption Scheme for secp256k1/x25519 in Rust, based on pure-Rust secp256k1/x25519 implementation.

ECIES functionalities are built upon AES-256-GCM/XChaCha20-Poly1305 and HKDF-SHA256.

This is the Rust version of [eciespy](https://github.com/ecies/py).

This library can be compiled to the WASM target at your option, see [WASM compatibility](#wasm-compatibility).

## Quick Start

`no_std` is enabled by default. You can enable `std` with `std` feature.

```toml
ecies = {version = "0.2", features = ["std"]}
```

```rust
use ecies::{decrypt, encrypt, utils::generate_keypair};

const MSG: &str = "helloworld🌍";
let (sk, pk) = generate_keypair();
#[cfg(not(feature = "x25519"))]
let (sk, pk) = (&sk.serialize(), &pk.serialize());
#[cfg(feature = "x25519")]
let (sk, pk) = (sk.as_bytes(), pk.as_bytes());

let msg = MSG.as_bytes();
assert_eq!(
    msg,
    decrypt(sk, &encrypt(pk, msg).unwrap()).unwrap().as_slice()
);
```

## Optional x25519 Support

You can choose to use x25519 (key exchange function on curve25519) instead of secp256k1:

```toml
ecies = {version = "0.2", default-features = false, features = ["x25519"]}
```

## Optional pure Rust AES backend

You can choose to use OpenSSL implementation or [pure Rust implementation](https://github.com/RustCrypto/AEADs) of AES-256-GCM:

```toml
ecies = {version = "0.2", default-features = false, features = ["pure"]}
```

Due to some [performance problem](https://github.com/RustCrypto/AEADs/issues/243), OpenSSL is the default backend.

Pure Rust implementation is sometimes useful, such as building on WASM:

```bash
cargo build --no-default-features --features pure --target=wasm32-unknown-unknown
```

If you select the pure Rust backend on modern x86 CPUs, consider building with

```bash
RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"
```

It can speed up AES encryption/decryption. This would be no longer necessary when [`aes-gcm` supports automatic CPU detection](https://github.com/RustCrypto/AEADs/issues/243#issuecomment-738821935).

On ARM CPUs, consider building with

```bash
RUSTFLAGS="--cfg aes_armv8" # Rust 1.61+
```

## WASM compatibility

It's also possible to build to the `wasm32-unknown-unknown` target (or `wasm32-wasip2`) with the pure Rust backend. Check out [this repo](https://github.com/ecies/rs-wasm) for more details.

## Configuration

You can enable 12 bytes nonce by `aes-12bytes-nonce` feature on OpenSSL or pure Rust AES backend.

```toml
ecies = {version = "0.2", features = ["aes-12bytes-nonce"]} # it also works with "pure"
```

You can also enable a pure Rust [XChaCha20-Poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305) backend.

```toml
ecies = {version = "0.2", default-features = false, features = ["xchacha20"]}
```

### Secp256k1-specific configuration

Other behaviors can be configured by global static variable:

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

## Security

### Why AES-256-GCM and HKDF-SHA256

AEAD scheme like AES-256-GCM should be your first option for symmetric ciphers, with unique IVs in each encryption.

For key derivation functions on shared points between two asymmetric keys, HKDFs are [proven](https://github.com/ecies/py/issues/82) to be more secure than simple hash functions like SHA256.

### Why XChaCha20-Poly1305 instead of AES-256-GCM

XChaCha20-Poly1305 is a competitive alternative to AES-256-GCM because it's fast and constant-time without hardware acceleration (resistant to cache-timing attacks). It also has longer nonce length to alleviate the risk of birthday attacks when nonces are generated randomly.

### Cross-language compatibility

All functionalities are mutually checked among [different languages](https://github.com/ecies): Python, Rust, JavaScript and Golang.

### Security audit

Following dependencies are audited:

- [aes-gcm and chacha20poly1305](https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/)
- [OpenSSL](https://ostif.org/the-ostif-and-quarkslab-audit-of-openssl-is-complete/)

## Benchmark

On MacBook Pro Mid 2015 (15-inch, 2.8 GHz Quad-Core Intel Core i7) on July 19, 2023.

### AES backend (OpenSSL)

```bash
$ cargo bench --no-default-features --features openssl
encrypt 100M            time:   [100.21 ms 100.79 ms 101.80 ms]

encrypt 200M            time:   [377.84 ms 384.42 ms 390.58 ms]
Found 2 outliers among 10 measurements (20.00%)
  2 (20.00%) high mild

decrypt 100M            time:   [52.430 ms 55.605 ms 60.900 ms]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high severe

decrypt 200M            time:   [157.87 ms 158.98 ms 160.01 ms]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high mild
```

### AES backend (Pure Rust)

```bash
$ export RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"
$ cargo bench --no-default-features --features pure
encrypt 100M            time:   [196.63 ms 205.63 ms 222.25 ms]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high severe

Benchmarking encrypt 200M: Warming up for 3.0000 s
encrypt 200M            time:   [587.78 ms 590.71 ms 592.46 ms]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high mild

decrypt 100M            time:   [144.78 ms 145.54 ms 147.17 ms]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high mild

decrypt 200M            time:   [363.14 ms 364.48 ms 365.74 ms]
```

### XChaCha20 backend

```bash
$ cargo bench --no-default-features --features xchacha20
encrypt 100M            time:   [149.52 ms 150.06 ms 150.59 ms]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high mild

encrypt 200M            time:   [482.27 ms 484.95 ms 487.45 ms]
Found 3 outliers among 10 measurements (30.00%)
  2 (20.00%) low severe
  1 (10.00%) high severe

decrypt 100M            time:   [98.232 ms 100.37 ms 105.65 ms]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high severe

decrypt 200M            time:   [265.62 ms 268.02 ms 269.85 ms]
```

## Changelog

See [CHANGELOG.md](./CHANGELOG.md).
