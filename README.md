# eciesrs

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/1c6d6ed949dd4836ab97421039e8be75)](https://www.codacy.com/app/ecies/rs)
[![License](https://img.shields.io/github/license/ecies/rs.svg)](https://github.com/ecies/rs)
[![Circle CI](https://img.shields.io/circleci/project/ecies/rs/master.svg)](https://circleci.com/gh/ecies/rs)
[![Crates](https://img.shields.io/crates/v/ecies)](https://crates.io/crates/ecies)
[![Doc](https://docs.rs/ecies/badge.svg)](https://docs.rs/ecies/latest/ecies/)

Elliptic Curve Integrated Encryption Scheme for secp256k1 in Rust, based on [pure Rust implementation](https://github.com/paritytech/libsecp256k1) of secp256k1.

ECIES functionalities are built upon AES-GCM-256 and HKDF-SHA256.

This is the Rust version of [eciespy](https://github.com/ecies/py).

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
# ecies = {version = "0.2", feature = "openssl"}
ecies = {version = "0.2", feature = "pure"}
```

Due to some [performance problem](https://github.com/RustCrypto/AEADs/issues/243), OpenSSL is the default backend.

Pure Rust implementation is sometimes useful, such as building a WASM target: `cargo build --no-default-features --features pure --target=wasm32-unknown-unknown`.

If you are using the pure Rust backend on modern CPUs, consider build with `RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"` to speed up AES encryption/decryption.

## Security notes

### Why AES-GCM-256 and HKDF-SHA256

AEAD scheme like AES-GCM-256 should be your first option for symmetric ciphers, with unique IVs in each encryption.

For key derivation functions on shared points between two asymmetric keys, HKDFs are [proven](https://github.com/ecies/py/issues/82) to be more secure than simple hash functions like SHA256.

### Cross-language compatibility

All functionalities are mutually checked among [different languages](https://github.com/ecies): Python, Rust, JavaScript and Golang.

### Security audit

Following dependencies are audited:

- [aes-gcm](https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/)
- [OpenSSL](https://ostif.org/the-ostif-and-quarkslab-audit-of-openssl-is-complete/)

## Release Notes

### 0.2.0

- Revamp documentations
- Optional pure Rust AES backend

### 0.1.1 ~ 0.1.5

- Bump dependencies
- Update documentation
- Fix error handling

### 0.1.0

- First beta version release
