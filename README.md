# eciesrs

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/1c6d6ed949dd4836ab97421039e8be75)](https://app.codacy.com/gh/ecies/rs/dashboard)
[![License](https://img.shields.io/github/license/ecies/rs.svg)](https://github.com/ecies/rs)
[![CI](https://img.shields.io/github/workflow/status/ecies/rs/Build)](https://github.com/ecies/rs/actions)
[![Crates](https://img.shields.io/crates/v/ecies)](https://crates.io/crates/ecies)
[![Doc](https://docs.rs/ecies/badge.svg)](https://docs.rs/ecies/latest/ecies/)

Elliptic Curve Integrated Encryption Scheme for secp256k1 in Rust, based on [pure Rust implementation](https://github.com/paritytech/libsecp256k1) of secp256k1.

ECIES functionalities are built upon (AES-GCM-256 and HKDF-SHA256) and XChaCha20-Poly1305.

This is the Rust version of [eciespy](https://github.com/ecies/py).

This library can be compiled to the WASM target at your option, see [WASM compatibility](#wasm-compatibility).

## Quick Start

```rust
use ecies::{decrypt, encrypt, utils::generate_keypair};

const MSG: &str = "helloworld";
let (sk, pk) = generate_keypair();
let (sk, pk) = (&sk.serialize(), &pk.serialize());

let msg = MSG.as_bytes();
assert_eq!(
    msg,
    decrypt(sk, &encrypt(pk, msg).unwrap()).unwrap().as_slice()
);
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

If you select the pure Rust backend on modern CPUs, consider building with

```bash
RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"
```

to speed up AES encryption/decryption. This would be no longer necessary when [`aes-gcm` supports automatic CPU detection](https://github.com/RustCrypto/AEADs/issues/243#issuecomment-738821935).

## Alternative Rust XChaCha20-Poly1305 backend

You can choose to use OpenSSL implementation or [pure Rust implementation](https://github.com/RustCrypto/AEADs) of AES-256-GCM:

```toml
ecies = {version = "0.2", default-features = false, features = ["stream"]}
```

## WASM compatibility

It's also possible to build to the `wasm32-unknown-unknown` target with the pure Rust backend. Check out [this repo](https://github.com/ecies/rs-wasm) for more details.

## Security

### Why AES-GCM-256 and HKDF-SHA256

AEAD scheme like AES-GCM-256 should be your first option for symmetric ciphers, with unique IVs in each encryption.

For key derivation functions on shared points between two asymmetric keys, HKDFs are [proven](https://github.com/ecies/py/issues/82) to be more secure than simple hash functions like SHA256.

### Cross-language compatibility

All functionalities are mutually checked among [different languages](https://github.com/ecies): Python, Rust, JavaScript and Golang.

### Security audit

Following dependencies are audited:

- [aes-gcm](https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/)
- [chacha20-poly1305](https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/)
- [OpenSSL](https://ostif.org/the-ostif-and-quarkslab-audit-of-openssl-is-complete/)

## Benchmark

The result shows that the pure Rust backend is around 20% ~ 50% slower compared to OpenSSL on MacBook Pro mid-2015 (2.8 GHz Quad-Core Intel Core i7).

### OpenSSL backend

```bash
$ cargo bench --no-default-features --features openssl
encrypt 100M            time:   [110.25 ms 115.77 ms 120.22 ms]
                        change: [-10.123% -3.0504% +4.2342%] (p = 0.44 > 0.05)
                        No change in performance detected.

encrypt 200M            time:   [435.22 ms 450.50 ms 472.17 ms]
                        change: [-7.5254% +3.6572% +14.508%] (p = 0.56 > 0.05)
                        No change in performance detected.
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high mild

decrypt 100M            time:   [60.439 ms 66.276 ms 70.959 ms]
                        change: [+0.1986% +7.7620% +15.995%] (p = 0.08 > 0.05)
                        No change in performance detected.

decrypt 200M            time:   [182.10 ms 185.85 ms 190.63 ms]
                        change: [-4.8452% +5.2114% +16.370%] (p = 0.40 > 0.05)
                        No change in performance detected.
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high severe

```

### Pure Rust backend

```bash
$ export RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"
$ cargo bench --no-default-features --features pure
encrypt 100M            time:   [196.85 ms 201.97 ms 205.67 ms]
                        change: [-9.8235% -7.9098% -5.9849%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) low severe

encrypt 200M            time:   [554.62 ms 585.01 ms 599.71 ms]
                        change: [-15.036% -11.698% -8.6460%] (p = 0.00 < 0.05)
                        Performance has improved.

decrypt 100M            time:   [131.26 ms 134.39 ms 140.54 ms]
                        change: [-3.9509% +2.9485% +10.198%] (p = 0.42 > 0.05)
                        No change in performance detected.

decrypt 200M            time:   [288.13 ms 296.64 ms 311.78 ms]
                        change: [-16.887% -13.038% -8.6679%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high mild
```

## Release Notes

### 0.2.1 ~ 0.2.4

- Revamp error handling
- Migrate to edition 2021
- Bump dependencies

### 0.2.0

- Revamp documentation
- Optional pure Rust AES backend
- WASM compatibility

### 0.1.1 ~ 0.1.5

- Bump dependencies
- Update documentation
- Fix error handling

### 0.1.0

- First beta version release
