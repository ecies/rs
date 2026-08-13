use openssl::symm::{Cipher, Crypter, Mode, decrypt_aead};

use crate::Vec;
use crate::consts::{AEAD_TAG_LENGTH, EMPTY_BYTES, NONCE_LENGTH, NONCE_TAG_LENGTH};

/// AES-256-GCM encryption wrapper, appending the nonce, tag and ciphertext to the provided buffer
pub fn encrypt(output: &mut Vec<u8>, key: &[u8], nonce: &[u8], msg: &[u8]) -> Option<()> {
    let cipher = Cipher::aes_256_gcm();
    // 1 for AES-256-GCM, but `Crypter` demands this slack space on top of the message size
    let block_size = cipher.block_size();

    let base = output.len();
    output.reserve(NONCE_TAG_LENGTH + msg.len() + block_size);
    output.extend(nonce);
    output.extend([0u8; AEAD_TAG_LENGTH]);

    let encrypted_start = base + NONCE_TAG_LENGTH;
    output.resize(encrypted_start + msg.len() + block_size, 0);

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(nonce)).ok()?;
    let mut count = crypter.update(msg, &mut output[encrypted_start..]).ok()?;
    count += crypter.finalize(&mut output[encrypted_start + count..]).ok()?;
    output.truncate(encrypted_start + count);

    crypter
        .get_tag(&mut output[base + NONCE_LENGTH..base + NONCE_TAG_LENGTH])
        .ok()
}

/// AES-256-GCM decryption wrapper
pub fn decrypt(key: &[u8], encrypted: &[u8]) -> Option<Vec<u8>> {
    if encrypted.len() < NONCE_TAG_LENGTH {
        return None;
    }

    let cipher = Cipher::aes_256_gcm();

    let nonce = &encrypted[..NONCE_LENGTH];
    let tag = &encrypted[NONCE_LENGTH..NONCE_TAG_LENGTH];
    let encrypted = &encrypted[NONCE_TAG_LENGTH..];
    decrypt_aead(cipher, key, Some(nonce), &EMPTY_BYTES, encrypted, tag).ok()
}
