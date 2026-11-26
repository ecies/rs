// the README's examples use secp256k1, so its doctests can't run without it
#![cfg_attr(feature = "secp256k1", doc = include_str!("../README.md"))]
// docs.rs passes `--cfg docsrs`, and rustdoc then marks each item with the features it needs
#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(not(any(feature = "secp256k1", feature = "curve25519")))]
compile_error!(
    "ecies needs a curve: enable the `secp256k1` feature (the default, which 0.2 always built), \
     or `curve25519`, or both."
);

// Tombstones: in 0.2 these features chose the wire format, which `Config` now holds. Removed in 0.4. 0.2's calls
// still compile in 0.3 with another meaning, so each message sends users to every call site
#[cfg(feature = "x25519")]
compile_error!(
    "ecies 0.3 removed the `x25519` feature; enable `curve25519` instead, with `default-features = false`. \
     The compiler then flags each `encrypt`, `decrypt`, `Config::DEFAULT`, `ecies::{PublicKey, SecretKey}` and \
     `ecies::utils` function, which mean secp256k1 in 0.3. Replace them with encrypt_with_config/decrypt_with_config, \
     Config::new(EllipticCurve::X25519) and the `ecies::x25519` module, rather than enabling `secp256k1` to silence \
     the errors. If `secp256k1` stays on anyway, `cargo tree -e features -i ecies` shows which crate enables it."
);
#[cfg(feature = "ed25519")]
compile_error!(
    "ecies 0.3 removed the `ed25519` feature; enable `curve25519` instead, with `default-features = false`. \
     The compiler then flags each `encrypt`, `decrypt`, `Config::DEFAULT`, `ecies::{PublicKey, SecretKey}` and \
     `ecies::utils` function, which mean secp256k1 in 0.3. Replace them with encrypt_with_config/decrypt_with_config, \
     Config::new(EllipticCurve::Ed25519) and the `ecies::ed25519` module, rather than enabling `secp256k1` to silence \
     the errors. If `secp256k1` stays on anyway, `cargo tree -e features -i ecies` shows which crate enables it."
);
#[cfg(feature = "xchacha20")]
compile_error!(
    "ecies 0.3 removed the `xchacha20` feature; XChaCha20-Poly1305 is always available. \
     `encrypt`, `decrypt` and each Config built from Config::DEFAULT or Config::default() still compile but now use \
     AES-256-GCM, so use encrypt_with_config/decrypt_with_config on every call, with \
     Config { symmetric_algorithm: SymmetricAlgorithm::XChaCha20, ..Config::DEFAULT } \
     (on X25519 or Ed25519, start from Config::new(EllipticCurve::X25519) or Config::new(EllipticCurve::Ed25519))."
);
#[cfg(feature = "aes-short-nonce")]
compile_error!(
    "ecies 0.3 removed the `aes-short-nonce` feature; both AES-256-GCM nonce lengths are always available. \
     `encrypt`, `decrypt` and each Config built from Config::DEFAULT or Config::default() still compile but now use \
     a 16-byte nonce, so use encrypt_with_config/decrypt_with_config on every call, with \
     Config { symmetric_nonce_length: NonceLength::Twelve, ..Config::DEFAULT } \
     (on X25519 or Ed25519, start from Config::new(EllipticCurve::X25519) or Config::new(EllipticCurve::Ed25519))."
);
#[cfg(feature = "aes-12bytes-nonce")]
compile_error!(
    "ecies 0.3 removed the `aes-12bytes-nonce` feature; both AES-256-GCM nonce lengths are always available. \
     `encrypt`, `decrypt` and each Config built from Config::DEFAULT or Config::default() still compile but now use \
     a 16-byte nonce, so use encrypt_with_config/decrypt_with_config on every call, with \
     Config { symmetric_nonce_length: NonceLength::Twelve, ..Config::DEFAULT } \
     (on X25519 or Ed25519, start from Config::new(EllipticCurve::X25519) or Config::new(EllipticCurve::Ed25519))."
);

/// ECIES configuration
pub mod config;
/// Fixed sizes. Sizes that depend on the config are [`Config::nonce_length`] and [`Config::ephemeral_key_size`]
pub mod consts;
/// Utility functions
pub mod utils;

mod elliptic;
mod error;
mod symmetric;

use alloc::vec::Vec;
use elliptic::Curve;
use symmetric::{sym_decrypt, sym_encrypt_into};

pub use config::{Config, EllipticCurve, NonceLength, SymmetricAlgorithm};
#[cfg(feature = "secp256k1")]
pub use elliptic::secp256k1;
#[cfg(feature = "curve25519")]
pub use elliptic::{ed25519, x25519};
pub use error::Error;
/// The default curve's public key, [`secp256k1::PublicKey`]
#[cfg(feature = "secp256k1")]
pub use secp256k1::PublicKey;
/// The default curve's secret key, [`secp256k1::SecretKey`]
#[cfg(feature = "secp256k1")]
pub use secp256k1::SecretKey;

/// Encrypt a message to a secp256k1 public key, with [`Config::DEFAULT`] and no AAD
///
/// # Arguments
///
/// * `receiver_pub` - The u8 array reference of a receiver's public key
/// * `msg` - The u8 array reference of the message to encrypt
#[cfg(feature = "secp256k1")]
pub fn encrypt(receiver_pub: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    encrypt_with_config(receiver_pub, msg, &[], &Config::DEFAULT)
}

/// Encrypt a message with additional authenticated data (AAD) and a config.
///
/// Pass the same `aad` and `config` to [`decrypt_with_config`]. The ciphertext doesn't include the AAD.
#[cfg_attr(
    feature = "secp256k1",
    doc = "With empty AAD and [`Config::DEFAULT`], this works the same as [`encrypt`]."
)]
///
/// # Arguments
///
/// * `receiver_pub` - The receiver's public key, encoded as [`EllipticCurve`] lists for `config.elliptic_curve`
/// * `msg` - The message to encrypt
/// * `aad` - The additional data to authenticate, or `&[]` for none
/// * `config` - The config both parties use
pub fn encrypt_with_config(receiver_pub: &[u8], msg: &[u8], aad: &[u8], config: &Config) -> Result<Vec<u8>, Error> {
    match config.elliptic_curve {
        #[cfg(feature = "secp256k1")]
        EllipticCurve::Secp256k1 => encrypt_on::<elliptic::Secp256k1>(receiver_pub, msg, aad, config),
        #[cfg(feature = "curve25519")]
        EllipticCurve::X25519 => encrypt_on::<elliptic::X25519>(receiver_pub, msg, aad, config),
        #[cfg(feature = "curve25519")]
        EllipticCurve::Ed25519 => encrypt_on::<elliptic::Ed25519>(receiver_pub, msg, aad, config),
    }
}

fn encrypt_on<C: Curve>(receiver_pub: &[u8], msg: &[u8], aad: &[u8], config: &Config) -> Result<Vec<u8>, Error> {
    let receiver_pk = C::parse_pk(receiver_pub)?;
    let (ephemeral_sk, ephemeral_pk) = C::generate_keypair();

    let sym_key = C::encapsulate_with_sender(
        &ephemeral_sk,
        &ephemeral_pk,
        &receiver_pk,
        config.is_hkdf_key_compressed,
    )?;

    let mut cipher_text = C::pk_to_vec(&ephemeral_pk, config.is_ephemeral_key_compressed);
    sym_encrypt_into(
        &mut cipher_text,
        sym_key.as_slice(),
        msg,
        aad,
        config.symmetric_algorithm,
        config.symmetric_nonce_length,
    )
    .ok_or(Error::InvalidMessage)?;

    Ok(cipher_text)
}

/// Decrypt a message with a secp256k1 secret key, with [`Config::DEFAULT`] and no AAD
///
/// # Arguments
///
/// * `receiver_sec` - The u8 array reference of a receiver's secret key
/// * `msg` - The u8 array reference of the encrypted message
#[cfg(feature = "secp256k1")]
pub fn decrypt(receiver_sec: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    decrypt_with_config(receiver_sec, msg, &[], &Config::DEFAULT)
}

/// Decrypt a message using the same AAD and config you passed to [`encrypt_with_config`].
///
/// If the AAD doesn't match, this returns `Error::InvalidMessage`.
///
/// # Arguments
///
/// * `receiver_sec` - The receiver's secret key, encoded as [`EllipticCurve`] lists for `config.elliptic_curve`
/// * `msg` - The encrypted message
/// * `aad` - The bytes you passed as AAD during encryption
/// * `config` - The config both parties use
pub fn decrypt_with_config(receiver_sec: &[u8], msg: &[u8], aad: &[u8], config: &Config) -> Result<Vec<u8>, Error> {
    match config.elliptic_curve {
        #[cfg(feature = "secp256k1")]
        EllipticCurve::Secp256k1 => decrypt_on::<elliptic::Secp256k1>(receiver_sec, msg, aad, config),
        #[cfg(feature = "curve25519")]
        EllipticCurve::X25519 => decrypt_on::<elliptic::X25519>(receiver_sec, msg, aad, config),
        #[cfg(feature = "curve25519")]
        EllipticCurve::Ed25519 => decrypt_on::<elliptic::Ed25519>(receiver_sec, msg, aad, config),
    }
}

fn decrypt_on<C: Curve>(receiver_sec: &[u8], msg: &[u8], aad: &[u8], config: &Config) -> Result<Vec<u8>, Error> {
    let receiver_sk = C::parse_sk(receiver_sec)?;
    let key_size = config.ephemeral_key_size();

    if msg.len() < key_size {
        return Err(Error::InvalidMessage);
    }

    let ephemeral_pk = C::parse_pk(&msg[..key_size])?;
    let encrypted = &msg[key_size..];

    let sym_key = C::decapsulate(&ephemeral_pk, &receiver_sk, config.is_hkdf_key_compressed)?;
    sym_decrypt(
        sym_key.as_slice(),
        encrypted,
        aad,
        config.symmetric_algorithm,
        config.symmetric_nonce_length,
    )
    .ok_or(Error::InvalidMessage)
}
