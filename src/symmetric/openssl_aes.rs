use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use rand_core::{OsRng, RngCore};

use crate::consts::{AEAD_TAG_LENGTH, AES_NONCE_LENGTH, EMPTY_BYTES};
use crate::Vec;

const NONCE_TAG_LENGTH: usize = AES_NONCE_LENGTH + AEAD_TAG_LENGTH;

/// AES-256-GCM encryption wrapper
pub fn encrypt(key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let cipher = Cipher::aes_256_gcm();

    let mut iv = [0u8; AES_NONCE_LENGTH];
    OsRng.fill_bytes(&mut iv);

    let mut tag = [0u8; AEAD_TAG_LENGTH];

    if let Ok(encrypted) = encrypt_aead(cipher, key, Some(&iv), &EMPTY_BYTES, msg, &mut tag) {
        let mut output = Vec::with_capacity(NONCE_TAG_LENGTH + encrypted.len());
        output.extend(&iv);
        output.extend(&tag);
        output.extend(encrypted);

        Some(output)
    } else {
        None
    }
}

/// AES-256-GCM decryption wrapper
pub fn decrypt(key: &[u8], encrypted_msg: &[u8]) -> Option<Vec<u8>> {
    if encrypted_msg.len() < NONCE_TAG_LENGTH {
        return None;
    }

    let cipher = Cipher::aes_256_gcm();

    let iv = &encrypted_msg[..AES_NONCE_LENGTH];
    let tag = &encrypted_msg[AES_NONCE_LENGTH..NONCE_TAG_LENGTH];
    let encrypted = &encrypted_msg[NONCE_TAG_LENGTH..];

    decrypt_aead(cipher, key, Some(iv), &EMPTY_BYTES, encrypted, tag).ok()
}
