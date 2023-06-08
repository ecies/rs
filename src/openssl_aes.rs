use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use rand::{thread_rng, Rng};

use crate::consts::{AES_IV_LENGTH, AES_IV_PLUS_TAG_LENGTH, AES_TAG_LENGTH, EMPTY_BYTES};

/// AES-256-GCM encryption wrapper
pub fn symmetric_encrypt(key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let cipher = Cipher::aes_256_gcm();

    let mut iv = [0u8; AES_IV_LENGTH];
    thread_rng().fill(&mut iv);

    let mut tag = [0u8; AES_TAG_LENGTH];

    if let Ok(encrypted) = encrypt_aead(cipher, key, Some(&iv), &EMPTY_BYTES, msg, &mut tag) {
        let mut output = Vec::with_capacity(AES_IV_PLUS_TAG_LENGTH + encrypted.len());
        output.extend(&iv);
        output.extend(&tag);
        output.extend(encrypted);

        Some(output)
    } else {
        None
    }
}

/// AES-256-GCM decryption wrapper
pub fn symmetric_decrypt(key: &[u8], encrypted_msg: &[u8]) -> Option<Vec<u8>> {
    if encrypted_msg.len() < AES_IV_PLUS_TAG_LENGTH {
        return None;
    }

    let cipher = Cipher::aes_256_gcm();

    let iv = &encrypted_msg[..AES_IV_LENGTH];
    let tag = &encrypted_msg[AES_IV_LENGTH..AES_IV_PLUS_TAG_LENGTH];
    let encrypted = &encrypted_msg[AES_IV_PLUS_TAG_LENGTH..];

    decrypt_aead(cipher, key, Some(iv), &EMPTY_BYTES, encrypted, tag).ok()
}
