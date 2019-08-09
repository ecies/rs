# eciesrs

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/48d5be4149ad4fff8ccd47768f08db7d)](https://www.codacy.com/app/kigawas/eciesrs?utm_source=github.com&utm_medium=referral&utm_content=kigawas/eciesrs&utm_campaign=Badge_Grade)
[![License](https://img.shields.io/github/license/kigawas/eciesrs.svg)](https://github.com/kigawas/eciesrs)
[![Circle CI](https://img.shields.io/circleci/project/kigawas/eciesrs/master.svg)](https://circleci.com/gh/kigawas/eciesrs)

Elliptic Curve Integrated Encryption Scheme for secp256k1 in Rust.

This is the Rust version of [eciespy](https://github.com/kigawas/eciespy).

## API

```rust
pub fn encrypt(receiver_pub: &[u8], msg: &[u8]) -> Result<Vec<u8>, SecpError>
```

```rust
pub fn decrypt(receiver_sec: &[u8], msg: &[u8]) -> Result<Vec<u8>, SecpError>
```

## Example

```rust
const MSG: &str = "helloworld";
let (sk, pk) = generate_keypair();
let msg = MSG.as_bytes();
assert_eq!(
    msg,
    decrypt(
        &sk[..],
        &encrypt(&pk.serialize_uncompressed(), msg).unwrap()
    )
    .unwrap()
    .as_slice()
);
```
