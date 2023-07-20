#![doc = include_str!("../README.md")]

pub use libsecp256k1::{Error as SecpError, PublicKey, SecretKey};

/// ECIES configuration
pub mod config;
/// Constant variables
pub mod consts;
/// Symmetric encryption/decryption
pub mod symmetric;
/// Utility functions
pub mod utils;

use config::{get_ephemeral_key_size, is_ephemeral_key_compressed};
use symmetric::{sym_decrypt, sym_encrypt};
use utils::{decapsulate, encapsulate, generate_keypair};

/// Encrypt a message by a public key
///
/// # Arguments
///
/// * `receiver_pub` - The u8 array reference of a receiver's public key
/// * `msg` - The u8 array reference of the message to encrypt
pub fn encrypt(receiver_pub: &[u8], msg: &[u8]) -> Result<Vec<u8>, SecpError> {
    let receiver_pk = PublicKey::parse_slice(receiver_pub, None)?;
    let (ephemeral_sk, ephemeral_pk) = generate_keypair();

    let aes_key = encapsulate(&ephemeral_sk, &receiver_pk)?;
    let encrypted = sym_encrypt(&aes_key, msg).ok_or(SecpError::InvalidMessage)?;

    let key_size = get_ephemeral_key_size();
    let mut cipher_text = Vec::with_capacity(key_size + encrypted.len());

    if is_ephemeral_key_compressed() {
        cipher_text.extend(ephemeral_pk.serialize_compressed().iter());
    } else {
        cipher_text.extend(ephemeral_pk.serialize().iter());
    }

    cipher_text.extend(encrypted);

    Ok(cipher_text)
}

/// Decrypt a message by a secret key
///
/// # Arguments
///
/// * `receiver_sec` - The u8 array reference of a receiver's secret key
/// * `msg` - The u8 array reference of the encrypted message
pub fn decrypt(receiver_sec: &[u8], msg: &[u8]) -> Result<Vec<u8>, SecpError> {
    let receiver_sk = SecretKey::parse_slice(receiver_sec)?;
    let key_size = get_ephemeral_key_size();

    if msg.len() < key_size {
        return Err(SecpError::InvalidMessage);
    }

    let ephemeral_pk = PublicKey::parse_slice(&msg[..key_size], None)?;
    let encrypted = &msg[key_size..];

    let aes_key = decapsulate(&ephemeral_pk, &receiver_sk)?;

    sym_decrypt(&aes_key, encrypted).ok_or(SecpError::InvalidMessage)
}

#[cfg(test)]
mod tests {
    use super::*;

    use utils::generate_keypair;

    const MSG: &str = "helloworld";
    const BIG_MSG_SIZE: usize = 2 * 1024 * 1024; // 2 MB
    const BIG_MSG: [u8; BIG_MSG_SIZE] = [1u8; BIG_MSG_SIZE];

    pub(super) fn test_enc_dec(sk: &[u8], pk: &[u8]) {
        let msg = MSG.as_bytes();
        assert_eq!(msg, decrypt(sk, &encrypt(pk, msg).unwrap()).unwrap().as_slice());
    }

    pub(super) fn test_enc_dec_big(sk: &[u8], pk: &[u8]) {
        let msg = &BIG_MSG;
        assert_eq!(msg.to_vec(), decrypt(sk, &encrypt(pk, msg).unwrap()).unwrap());
    }

    #[test]
    fn attempts_to_decrypt_with_another_key() {
        let (_, pk1) = generate_keypair();

        let (sk2, _) = generate_keypair();

        assert_eq!(
            decrypt(
                &sk2.serialize(),
                encrypt(&pk1.serialize_compressed(), b"text").unwrap().as_slice()
            ),
            Err(SecpError::InvalidMessage)
        );
    }

    #[test]
    fn attempts_to_decrypt_incorrect_message() {
        let (sk, _) = generate_keypair();

        assert_eq!(decrypt(&sk.serialize(), &[]), Err(SecpError::InvalidMessage));

        assert_eq!(decrypt(&sk.serialize(), &[0u8; 65]), Err(SecpError::InvalidPublicKey));
    }

    #[test]
    fn attempts_to_encrypt_with_invalid_key() {
        assert_eq!(encrypt(&[0u8; 33], b"text"), Err(SecpError::InvalidPublicKey));
    }

    #[test]
    fn test_compressed_public() {
        let (sk, pk) = generate_keypair();
        let (sk, pk) = (&sk.serialize(), &pk.serialize_compressed());
        test_enc_dec(sk, pk);
    }

    #[test]
    fn test_uncompressed_public() {
        let (sk, pk) = generate_keypair();
        let (sk, pk) = (&sk.serialize(), &pk.serialize());
        test_enc_dec(sk, pk);
    }

    #[test]
    fn test_compressed_public_big_msg() {
        let (sk, pk) = generate_keypair();
        let (sk, pk) = (&sk.serialize(), &pk.serialize_compressed());
        test_enc_dec_big(sk, pk);
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use super::generate_keypair;
    use super::tests::{test_enc_dec, test_enc_dec_big};

    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_wasm() {
        let (sk, pk) = generate_keypair();
        let (sk, pk) = (&sk.serialize(), &pk.serialize());
        test_enc_dec(sk, pk);
        test_enc_dec_big(sk, pk);
    }
}
