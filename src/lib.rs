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
/// Symmetric encryption/decryption
pub mod symmetric;
/// Utility functions
pub mod utils;

mod compat;
mod elliptic;

#[cfg(not(feature = "std"))]
mod sync;

use config::{get_ephemeral_key_size, is_ephemeral_key_compressed, is_hkdf_key_compressed};
use elliptic::{decapsulate, encapsulate, generate_keypair, parse_pk, parse_sk, pk_to_vec, Error};
use symmetric::{sym_decrypt_with_aad, sym_encrypt_with_aad};

use crate::compat::Vec;
use crate::consts::EMPTY_BYTES;
pub use elliptic::{PublicKey, SecretKey};

/// Encrypt a message by a public key
///
/// # Arguments
///
/// * `receiver_pub` - The u8 array reference of a receiver's public key
/// * `msg` - The u8 array reference of the message to encrypt
pub fn encrypt(receiver_pub: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    encrypt_with_aad(receiver_pub, msg, &EMPTY_BYTES)
}

/// Encrypt a message by a public key, with additional authenticated data
/// (AAD).
///
/// The AAD is authenticated but not encrypted, and is not stored in the
/// ciphertext; the same AAD must be given to [`decrypt_with_aad`]. An
/// empty AAD produces output identical to [`encrypt`].
///
/// # Arguments
///
/// * `receiver_pub` - The u8 array reference of a receiver's public key
/// * `msg` - The u8 array reference of the message to encrypt
/// * `aad` - The u8 array reference of the additional authenticated data
pub fn encrypt_with_aad(receiver_pub: &[u8], msg: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let receiver_pk = parse_pk(receiver_pub)?;
    let (ephemeral_sk, ephemeral_pk) = generate_keypair();

    let sym_key = encapsulate(&ephemeral_sk, &receiver_pk, is_hkdf_key_compressed())?;
    let encrypted = sym_encrypt_with_aad(&sym_key, msg, aad).ok_or(Error::InvalidMessage)?;

    let is_compressed = is_ephemeral_key_compressed();
    let key_size = get_ephemeral_key_size();

    let mut cipher_text = Vec::with_capacity(key_size + encrypted.len());
    let ephemeral_pk = pk_to_vec(&ephemeral_pk, is_compressed);

    cipher_text.extend(&ephemeral_pk);
    cipher_text.extend(encrypted);

    Ok(cipher_text)
}

/// Decrypt a message by a secret key
///
/// # Arguments
///
/// * `receiver_sec` - The u8 array reference of a receiver's secret key
/// * `msg` - The u8 array reference of the encrypted message
pub fn decrypt(receiver_sec: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    decrypt_with_aad(receiver_sec, msg, &EMPTY_BYTES)
}

/// Decrypt a message by a secret key, with additional authenticated data
/// (AAD).
///
/// Authentication fails with [`Error::InvalidMessage`] if the AAD does
/// not match the one given to [`encrypt_with_aad`].
///
/// # Arguments
///
/// * `receiver_sec` - The u8 array reference of a receiver's secret key
/// * `msg` - The u8 array reference of the encrypted message
/// * `aad` - The u8 array reference of the additional authenticated data
pub fn decrypt_with_aad(receiver_sec: &[u8], msg: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let receiver_sk = parse_sk(receiver_sec)?;
    let key_size = get_ephemeral_key_size();

    if msg.len() < key_size {
        return Err(Error::InvalidMessage);
    }

    let ephemeral_pk = parse_pk(&msg[..key_size])?;
    let encrypted = &msg[key_size..];

    let sym_key = decapsulate(&ephemeral_pk, &receiver_sk, is_hkdf_key_compressed())?;
    sym_decrypt_with_aad(&sym_key, encrypted, aad).ok_or(Error::InvalidMessage)
}
