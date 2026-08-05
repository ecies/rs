use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};

use crate::consts::{AEAD_TAG_LENGTH, EMPTY_BYTES, NONCE_LENGTH, NONCE_TAG_LENGTH};
use crate::Vec;

/// AES-256-GCM encryption wrapper
pub fn encrypt(key: &[u8], nonce: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    encrypt_with_aad(key, nonce, msg, &EMPTY_BYTES)
}

/// AES-256-GCM encryption wrapper with additional authenticated data
/// (AAD).
///
/// The AAD is authenticated but not encrypted, and is not stored in the
/// output; the same AAD must be given to [`decrypt_with_aad`]. An empty
/// AAD is equivalent to [`encrypt`].
pub fn encrypt_with_aad(key: &[u8], nonce: &[u8], msg: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let cipher = Cipher::aes_256_gcm();

    let mut output = Vec::with_capacity(NONCE_TAG_LENGTH + msg.len());
    output.extend(nonce);
    output.extend([0u8; AEAD_TAG_LENGTH]);

    let tag = &mut output[NONCE_LENGTH..NONCE_TAG_LENGTH];
    encrypt_aead(cipher, key, Some(nonce), aad, msg, tag)
        .map(|encrypted| {
            output.extend(encrypted);
            output
        })
        .ok()
}

/// AES-256-GCM decryption wrapper
pub fn decrypt(key: &[u8], encrypted: &[u8]) -> Option<Vec<u8>> {
    decrypt_with_aad(key, encrypted, &EMPTY_BYTES)
}

/// AES-256-GCM decryption wrapper with additional authenticated data
/// (AAD).
///
/// Authentication fails if the AAD does not match the one given to
/// [`encrypt_with_aad`].
pub fn decrypt_with_aad(key: &[u8], encrypted: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    if encrypted.len() < NONCE_TAG_LENGTH {
        return None;
    }

    let cipher = Cipher::aes_256_gcm();

    let nonce = &encrypted[..NONCE_LENGTH];
    let tag = &encrypted[NONCE_LENGTH..NONCE_TAG_LENGTH];
    let encrypted = &encrypted[NONCE_TAG_LENGTH..];
    decrypt_aead(cipher, key, Some(nonce), aad, encrypted, tag).ok()
}
