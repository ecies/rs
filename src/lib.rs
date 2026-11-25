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
use elliptic::{Error, decapsulate, encapsulate_with_sender, generate_keypair, parse_pk, parse_sk, pk_to_vec};
use symmetric::{sym_decrypt_with_aad, sym_encrypt_into};

use crate::compat::Vec;
pub use elliptic::{PublicKey, SecretKey};

/// Encrypt a message by a public key
///
/// # Arguments
///
/// * `receiver_pub` - The u8 array reference of a receiver's public key
/// * `msg` - The u8 array reference of the message to encrypt
pub fn encrypt(receiver_pub: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    encrypt_with_aad(receiver_pub, msg, &[])
}

/// Encrypt a message with additional authenticated data (AAD).
///
/// The ciphertext doesn't include the AAD, so pass the same bytes to [`decrypt_with_aad`].
/// If you pass an empty slice, this works the same as [`encrypt`].
///
/// # Arguments
///
/// * `receiver_pub` - The receiver's public key
/// * `msg` - The message to encrypt
/// * `aad` - The additional data to authenticate
pub fn encrypt_with_aad(receiver_pub: &[u8], msg: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let receiver_pk = parse_pk(receiver_pub)?;
    let (ephemeral_sk, ephemeral_pk) = generate_keypair();

    let sym_key = encapsulate_with_sender(&ephemeral_sk, &ephemeral_pk, &receiver_pk, is_hkdf_key_compressed())?;

    let mut cipher_text = pk_to_vec(&ephemeral_pk, is_ephemeral_key_compressed());
    sym_encrypt_into(&mut cipher_text, &sym_key, msg, aad).ok_or(Error::InvalidMessage)?;

    Ok(cipher_text)
}

/// Decrypt a message by a secret key
///
/// # Arguments
///
/// * `receiver_sec` - The u8 array reference of a receiver's secret key
/// * `msg` - The u8 array reference of the encrypted message
pub fn decrypt(receiver_sec: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    decrypt_with_aad(receiver_sec, msg, &[])
}

/// Decrypt a message using the same AAD you passed to [`encrypt_with_aad`].
///
/// If the AAD doesn't match, this returns `Error::InvalidMessage`.
///
/// # Arguments
///
/// * `receiver_sec` - The receiver's secret key
/// * `msg` - The encrypted message
/// * `aad` - The bytes you passed as AAD during encryption
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
