# eciesrs

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/1c6d6ed949dd4836ab97421039e8be75)](https://app.codacy.com/gh/ecies/rs/dashboard)
[![License](https://img.shields.io/github/license/ecies/rs.svg)](https://github.com/ecies/rs/blob/master/LICENSE)
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

`no_std` is enabled by default. On targets with the standard library, enable the `std` feature:

```toml
ecies = {version = "0.2", features = ["std"]} # MSRV is 1.87
```

Without `std`, ecies needs a [`critical-section`](https://crates.io/crates/critical-section) implementation, which embedded targets usually get from their HAL or runtime crate. wasm32 builds don't need one. On other targets with an operating system, a binary without `std` fails to link with `_critical_section_1_0_acquire` undefined, unless another dependency enables `once_cell`'s `std` feature or provides a `critical-section` implementation, such as `critical-section/std`.

The feature snippets further down leave `std` out for brevity, so add it on targets with the standard library.

```rust
use ecies::secp256k1::generate_keypair;
use ecies::{decrypt, encrypt};

const MSG: &str = "hello world🌍";
let (sk, pk) = generate_keypair();
let (sk, pk) = (&sk.serialize(), &pk.serialize());

let msg = MSG.as_bytes();
assert_eq!(
    msg,
    decrypt(sk, &encrypt(pk, msg).unwrap()).unwrap().as_slice()
);
```

### Additional authenticated data (AAD)

If you're storing encrypted values by name, you can use the entry name as AAD.
The ciphertext doesn't include the name, so pass it again when you decrypt the value.
If someone swaps two entries, neither value will decrypt under the other entry's name.

```rust
use ecies::secp256k1::generate_keypair;
use ecies::{Config, decrypt_with_config, encrypt_with_config};

let (sk, pk) = generate_keypair();
let (sk, pk) = (&sk.serialize(), &pk.serialize());

let encrypted = encrypt_with_config(pk, b"msg", b"DATABASE_PASSWORD", &Config::DEFAULT).unwrap();
assert_eq!(
    b"msg",
    decrypt_with_config(sk, &encrypted, b"DATABASE_PASSWORD", &Config::DEFAULT).unwrap().as_slice()
);
assert!(decrypt_with_config(sk, &encrypted, b"API_TOKEN", &Config::DEFAULT).is_err());
```

## Planned for 0.3

0.3 moves every payload format choice into `Config`, tracked in [#178](https://github.com/ecies/rs/issues/178):

- The global config (`ECIES_CONFIG`, `update_config`, `reset_config`) is removed. `encrypt_with_config` and `decrypt_with_config` already take the 0.3 arguments, so switch to them now. They ignore the global config, so if another crate in your build calls `update_config`, set the same flags in your own `Config`.
- `Config` gains fields for the curve, the cipher and the AES nonce length. The `x25519`, `ed25519`, `xchacha20`, `aes-short-nonce` and `aes-12bytes-nonce` features then fail the build with a message naming the replacement, and X25519 and Ed25519 move behind one `curve25519` feature. The backend aliases `openssl` and `pure` are removed: use `aes-openssl`, or nothing for pure Rust.
- `secp256k1`, still on by default, controls whether secp256k1 is built. With `default-features = false`, name `secp256k1` or `curve25519`; a build with neither fails with a message.
- Pure Rust becomes the default AES backend. Enable `aes-openssl` to keep OpenSSL.

Each 0.2 setup either produces the same bytes on 0.3 or fails to build, as long as its settings come from its own code and Cargo features. If another crate in your build calls `update_config` or enables `xchacha20`, `aes-short-nonce` or `aes-12bytes-nonce`, your bytes follow it today, and stop following it once you and that crate are on different ecies versions.

## Elliptic curve configuration

### Optional x25519/ed25519 support

You can choose to use x25519 (key exchange function on curve25519) or ed25519 (signature algorithm on curve25519) instead of secp256k1:

```toml
ecies = {version = "0.2", features = ["x25519"]} # recommended
ecies = {version = "0.2", features = ["ed25519"]} # or if you know what you are doing
```

### Secp256k1-specific configuration

`Config` has two flags that change the payload on secp256k1. x25519 and ed25519 ignore them.

On `is_ephemeral_key_compressed: true`, the payload would be like: `33 Bytes + AES` instead of `65 Bytes + AES`.

On `is_hkdf_key_compressed: true`, the hkdf key would be derived from `ephemeral public key (compressed) + shared public key (compressed)` instead of `ephemeral public key (uncompressed) + shared public key (uncompressed)`.

Pass the config to `encrypt_with_config` and `decrypt_with_config`, with empty AAD if you don't need any:

```rust
use ecies::secp256k1::generate_keypair;
use ecies::{Config, decrypt_with_config, encrypt_with_config};

const CONFIG: Config = Config {
    is_ephemeral_key_compressed: true,
    ..Config::DEFAULT
};

let (sk, pk) = generate_keypair();
let (sk, pk) = (&sk.serialize(), &pk.serialize());

let encrypted = encrypt_with_config(pk, b"msg", b"", &CONFIG).unwrap();
assert_eq!(b"msg", decrypt_with_config(sk, &encrypted, b"", &CONFIG).unwrap().as_slice());
```

Filling the other fields from `Config::DEFAULT` keeps this code compiling on 0.3, which adds fields. If you set both flags, Clippy's `needless_update` lint warns about `..Config::DEFAULT` until then.

For compatibility, make sure different applications share the same configuration.

`encrypt` and `decrypt` still read the global config set by `update_config`, but it's deprecated: any crate in the process can change it for every other caller.

## Symmetric cipher configuration

### Optional pure Rust AES backend

You can choose to use OpenSSL implementation or [pure Rust implementation](https://github.com/RustCrypto/AEADs) of AES-256-GCM:

```toml
ecies = {version = "0.2", default-features = false, features = ["secp256k1", "aes-rust"]}
```

With `default-features = false`, name the curve feature too, such as `secp256k1` above. The `secp256k1` feature has no effect in 0.2. From 0.3 it controls whether secp256k1 is built, so builds that leave it out won't include secp256k1.

Due to some [performance problem](https://github.com/RustCrypto/AEADs/issues/243), OpenSSL is the default backend.

Pure Rust implementation is sometimes useful, such as building on WASM:

```bash
cargo build --no-default-features --features secp256k1,aes-rust --target=wasm32-unknown-unknown
```

#### Build on x86 CPUs

For ecies 0.2.1 and earlier: if you select the pure Rust backend on modern x86 CPUs, consider building with

```bash
RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"
```

It can speed up AES encryption/decryption. Since ecies 0.2.2, this is no longer necessary, because [`aes-gcm` detects CPU features automatically](https://github.com/RustCrypto/AEADs/issues/243#issuecomment-738821935).

#### Build on ARM CPUs

For ecies 0.2.3 to 0.2.11, on ARM CPUs (like Apple), consider building with

```bash
RUSTFLAGS="--cfg aes_armv8"
```

Since ecies 0.2.12, ARMv8 AES instructions are used automatically.

### Optional pure Rust XChaCha20-Poly1305 backend

You can also enable a pure Rust [XChaCha20-Poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305) backend.

```toml
ecies = {version = "0.2", default-features = false, features = ["secp256k1", "xchacha20"]}
```

For ecies 0.2.11 and earlier, enable SIMD on ARM CPUs with

```bash
RUSTFLAGS="--cfg chacha20_force_neon"
```

Since ecies 0.2.12, NEON is used automatically.

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

- [k256](https://github.com/RustCrypto/elliptic-curves/tree/master/k256#security-notes)
- [aes-gcm](https://github.com/RustCrypto/AEADs/tree/master/aes-gcm#security-notes)
- [chacha20poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305#security-notes)
- [OpenSSL](https://ostif.org/the-ostif-and-quarkslab-audit-of-openssl-is-complete/)

## Benchmark

On Mac mini M4 Pro (24 GB) on Oct 30, 2026, secp256k1 only.

Rust version: 1.87.0 (17067e9ac 2025-05-09)

### AES backend (OpenSSL)

```bash
$ cargo bench --no-default-features --features aes-openssl

encrypt 32B             time:   [43.610 µs 44.109 µs 44.860 µs]

decrypt 32B             time:   [27.540 µs 27.879 µs 28.184 µs]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) low mild

encrypt 100M            time:   [12.529 ms 12.636 ms 12.748 ms]

encrypt 200M            time:   [24.703 ms 24.812 ms 24.994 ms]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high mild

decrypt 100M            time:   [12.268 ms 12.452 ms 12.721 ms]

decrypt 200M            time:   [24.102 ms 24.624 ms 25.574 ms]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high severe
```

### AES backend (Pure Rust)

```bash
$ cargo bench --no-default-features --features aes-rust

encrypt 32B             time:   [43.516 µs 44.269 µs 44.745 µs]

decrypt 32B             time:   [28.463 µs 28.885 µs 29.119 µs]

encrypt 100M            time:   [25.836 ms 26.286 ms 26.635 ms]

encrypt 200M            time:   [51.666 ms 52.654 ms 53.652 ms]

decrypt 100M            time:   [25.191 ms 25.443 ms 25.796 ms]

decrypt 200M            time:   [51.772 ms 52.944 ms 53.901 ms]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high mild
```

### XChaCha20 backend

```bash
$ cargo bench --no-default-features --features xchacha20

encrypt 32B             time:   [45.041 µs 45.650 µs 46.246 µs]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high mild

decrypt 32B             time:   [28.111 µs 28.628 µs 29.112 µs]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) low mild

encrypt 100M            time:   [108.56 ms 108.94 ms 109.68 ms]
Found 2 outliers among 10 measurements (20.00%)
  2 (20.00%) high mild

encrypt 200M            time:   [217.71 ms 218.86 ms 219.70 ms]

decrypt 100M            time:   [108.94 ms 109.84 ms 110.39 ms]

decrypt 200M            time:   [215.22 ms 219.89 ms 226.11 ms]
```

## Changelog

See [CHANGELOG.md](https://github.com/ecies/rs/blob/master/CHANGELOG.md).
