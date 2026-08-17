use openssl::symm::{Cipher, Crypter, Mode, decrypt_aead};

use crate::Vec;
use crate::consts::{AEAD_TAG_LENGTH, EMPTY_BYTES, NONCE_LENGTH, NONCE_TAG_LENGTH};

/// AES-256-GCM encryption wrapper, appending the nonce, tag and ciphertext to the provided buffer
pub(super) fn encrypt_into(output: &mut Vec<u8>, key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Option<()> {
    let cipher = Cipher::aes_256_gcm();
    // 1 for AES-256-GCM, but `Crypter` demands this slack space on top of the message size
    let block_size = cipher.block_size();

    let base = output.len();
    output.reserve(NONCE_TAG_LENGTH + plaintext.len() + block_size);
    output.extend(nonce);
    output.extend([0u8; AEAD_TAG_LENGTH]);

    let encrypted_start = base + NONCE_TAG_LENGTH;
    output.resize(encrypted_start + plaintext.len() + block_size, 0);

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(nonce)).ok()?;
    let mut count = crypter.update(plaintext, &mut output[encrypted_start..]).ok()?;
    count += crypter.finalize(&mut output[encrypted_start + count..]).ok()?;
    output.truncate(encrypted_start + count);

    crypter
        .get_tag(&mut output[base + NONCE_LENGTH..base + NONCE_TAG_LENGTH])
        .ok()
}

/// AES-256-GCM decryption wrapper
pub(super) fn decrypt(key: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < NONCE_TAG_LENGTH {
        return None;
    }

    let cipher = Cipher::aes_256_gcm();

    let nonce = &ciphertext[..NONCE_LENGTH];
    let tag = &ciphertext[NONCE_LENGTH..NONCE_TAG_LENGTH];
    let ciphertext = &ciphertext[NONCE_TAG_LENGTH..];
    decrypt_aead(cipher, key, Some(nonce), &EMPTY_BYTES, ciphertext, tag).ok()
}
