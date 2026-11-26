#![doc = include_str!("../README.md")]
#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[cfg(not(feature = "std"))]
extern crate alloc;

/// ECIES configuration
pub mod config;
/// Constant variables
pub mod consts;
/// Utility functions
pub mod utils;

mod compat;
mod elliptic;
mod error;
mod symmetric;

#[cfg(not(feature = "std"))]
mod sync;

use config::{Config, global_config};
use elliptic::feature_curve::{decapsulate, encapsulate_with_sender, generate_keypair, parse_pk, parse_sk, pk_to_vec};
use symmetric::{FEATURE_ALGORITHM, FEATURE_NONCE_LENGTH, sym_decrypt, sym_encrypt_into};

use crate::compat::Vec;
pub use elliptic::secp256k1;
#[cfg(feature = "curve25519")]
pub use elliptic::{ed25519, x25519};
pub use error::Error;
/// The default curve's public key, [`secp256k1::PublicKey`]
pub use secp256k1::PublicKey;
/// The default curve's secret key, [`secp256k1::SecretKey`]
pub use secp256k1::SecretKey;

/// Encrypt a message by a public key, with the global config
///
/// # Arguments
///
/// * `receiver_pub` - The u8 array reference of a receiver's public key
/// * `msg` - The u8 array reference of the message to encrypt
pub fn encrypt(receiver_pub: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    encrypt_with_config(receiver_pub, msg, &[], &global_config())
}

/// Encrypt a message with additional authenticated data (AAD) and a config.
///
/// This ignores the global config. Pass the same `aad` and `config` to [`decrypt_with_config`].
/// The ciphertext doesn't include the AAD. With empty AAD and the global config, this works the same as [`encrypt`].
///
/// # Arguments
///
/// * `receiver_pub` - The receiver's public key
/// * `msg` - The message to encrypt
/// * `aad` - The additional data to authenticate, or `&[]` for none
/// * `config` - The config both parties use
pub fn encrypt_with_config(receiver_pub: &[u8], msg: &[u8], aad: &[u8], config: &Config) -> Result<Vec<u8>, Error> {
    let receiver_pk = parse_pk(receiver_pub)?;
    let (ephemeral_sk, ephemeral_pk) = generate_keypair();

    let sym_key = encapsulate_with_sender(
        &ephemeral_sk,
        &ephemeral_pk,
        &receiver_pk,
        config.is_hkdf_key_compressed,
    )?;

    let mut cipher_text = pk_to_vec(&ephemeral_pk, config.is_ephemeral_key_compressed);
    sym_encrypt_into(
        &mut cipher_text,
        &sym_key,
        msg,
        aad,
        FEATURE_ALGORITHM,
        FEATURE_NONCE_LENGTH,
    )
    .ok_or(Error::InvalidMessage)?;

    Ok(cipher_text)
}

/// Decrypt a message by a secret key, with the global config
///
/// # Arguments
///
/// * `receiver_sec` - The u8 array reference of a receiver's secret key
/// * `msg` - The u8 array reference of the encrypted message
pub fn decrypt(receiver_sec: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    decrypt_with_config(receiver_sec, msg, &[], &global_config())
}

/// Decrypt a message using the same AAD and config you passed to [`encrypt_with_config`].
///
/// This ignores the global config. If the AAD doesn't match, this returns `Error::InvalidMessage`.
///
/// # Arguments
///
/// * `receiver_sec` - The receiver's secret key
/// * `msg` - The encrypted message
/// * `aad` - The bytes you passed as AAD during encryption
/// * `config` - The config both parties use
pub fn decrypt_with_config(receiver_sec: &[u8], msg: &[u8], aad: &[u8], config: &Config) -> Result<Vec<u8>, Error> {
    let receiver_sk = parse_sk(receiver_sec)?;
    let key_size = config.ephemeral_key_size();

    if msg.len() < key_size {
        return Err(Error::InvalidMessage);
    }

    let ephemeral_pk = parse_pk(&msg[..key_size])?;
    let encrypted = &msg[key_size..];

    let sym_key = decapsulate(&ephemeral_pk, &receiver_sk, config.is_hkdf_key_compressed)?;
    sym_decrypt(&sym_key, encrypted, aad, FEATURE_ALGORITHM, FEATURE_NONCE_LENGTH).ok_or(Error::InvalidMessage)
}
