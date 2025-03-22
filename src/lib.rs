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

use config::{get_ephemeral_key_size, is_ephemeral_key_compressed};
use elliptic::{decapsulate, encapsulate, generate_keypair, parse_pk, parse_sk, pk_to_vec, Error};
use symmetric::{sym_decrypt, sym_encrypt};

use crate::compat::Vec;
pub use elliptic::{PublicKey, SecretKey};

/// Encrypt a message by a public key
///
/// # Arguments
///
/// * `receiver_pub` - The u8 array reference of a receiver's public key
/// * `msg` - The u8 array reference of the message to encrypt
pub fn encrypt(receiver_pub: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    let receiver_pk = parse_pk(receiver_pub)?;
    let (ephemeral_sk, ephemeral_pk) = generate_keypair();

    let sym_key = encapsulate(&ephemeral_sk, &receiver_pk)?;
    let encrypted = sym_encrypt(&sym_key, msg).ok_or(Error::InvalidMessage)?;

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
    let receiver_sk = parse_sk(receiver_sec)?;
    let key_size = get_ephemeral_key_size();

    if msg.len() < key_size {
        return Err(Error::InvalidMessage);
    }

    let ephemeral_pk = parse_pk(&msg[..key_size])?;
    let encrypted = &msg[key_size..];

    let sym_key = decapsulate(&ephemeral_pk, &receiver_sk)?;
    sym_decrypt(&sym_key, encrypted).ok_or(Error::InvalidMessage)
}
