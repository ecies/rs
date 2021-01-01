# eciesrs

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/1c6d6ed949dd4836ab97421039e8be75)](https://www.codacy.com/app/ecies/rs)
[![License](https://img.shields.io/github/license/ecies/rs.svg)](https://github.com/ecies/rs)
[![CI](https://img.shields.io/github/workflow/status/ecies/rs/Build)](https://github.com/ecies/rs/actions)
[![Crates](https://img.shields.io/crates/v/ecies)](https://crates.io/crates/ecies)
[![Doc](https://docs.rs/ecies/badge.svg)](https://docs.rs/ecies/latest/ecies/)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fecies%2Frs.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fecies%2Frs?ref=badge_shield)

Elliptic Curve Integrated Encryption Scheme for secp256k1 in Rust, based on [pure Rust implementation](https://github.com/paritytech/libsecp256k1) of secp256k1.

ECIES functionalities are built upon AES-GCM-256 and HKDF-SHA256.

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

## WASM compatibility

It's also possible to build to the `wasm32-unknown-unknown` target with the pure Rust backend. Check out [this repo](https://github.com/ecies/rs-wasm) for more details.

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

- Revamp documentation
- Optional pure Rust AES backend
- WASM compatibility

### 0.1.1 ~ 0.1.5

- Bump dependencies
- Update documentation
- Fix error handling

### 0.1.0

- First beta version release


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fecies%2Frs.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fecies%2Frs?ref=badge_large)