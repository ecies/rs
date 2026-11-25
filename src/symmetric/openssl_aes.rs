use openssl::symm::{Cipher, Crypter, Mode};

#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(feature = "std")]
use std::vec;

use crate::Vec;
use crate::consts::{AEAD_TAG_LENGTH, NONCE_LENGTH, NONCE_TAG_LENGTH};

/// rust-openssl panics on more than `i32::MAX` bytes in one call, so longer messages go through in chunks
const CHUNK_LENGTH: usize = 1 << 30;

/// AES-256-GCM encryption wrapper, appending the nonce, tag and ciphertext to the provided buffer
pub(super) fn encrypt_into(output: &mut Vec<u8>, key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Option<()> {
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
    update_aad(&mut crypter, aad)?;
    let mut count = update_all(&mut crypter, plaintext, &mut output[encrypted_start..])?;
    count += crypter.finalize(&mut output[encrypted_start + count..]).ok()?;
    output.truncate(encrypted_start + count);

    crypter
        .get_tag(&mut output[base + NONCE_LENGTH..base + NONCE_TAG_LENGTH])
        .ok()
}

/// AES-256-GCM decryption wrapper
pub(super) fn decrypt(key: &[u8], ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < NONCE_TAG_LENGTH {
        return None;
    }

    let cipher = Cipher::aes_256_gcm();

    let nonce = &ciphertext[..NONCE_LENGTH];
    let tag = &ciphertext[NONCE_LENGTH..NONCE_TAG_LENGTH];
    let ciphertext = &ciphertext[NONCE_TAG_LENGTH..];

    // what `decrypt_aead` does, but in chunks: the tag goes in after the data, and finalizing checks it
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(nonce)).ok()?;
    update_aad(&mut crypter, aad)?;
    let mut plaintext = vec![0u8; ciphertext.len() + cipher.block_size()];
    let mut count = update_all(&mut crypter, ciphertext, &mut plaintext)?;
    crypter.set_tag(tag).ok()?;
    count += crypter.finalize(&mut plaintext[count..]).ok()?;
    plaintext.truncate(count);
    Some(plaintext)
}

/// OpenSSL takes an `int` length for AAD too, so feed it in chunks.
fn update_aad(crypter: &mut Crypter, aad: &[u8]) -> Option<()> {
    for chunk in aad.chunks(CHUNK_LENGTH) {
        crypter.aad_update(chunk).ok()?;
    }
    Some(())
}

/// Feeds `input` through the cipher in chunks, returning how many bytes it wrote to `output`
fn update_all(crypter: &mut Crypter, input: &[u8], output: &mut [u8]) -> Option<usize> {
    let mut count = 0;
    for chunk in input.chunks(CHUNK_LENGTH) {
        count += crypter.update(chunk, &mut output[count..]).ok()?;
    }
    Some(count)
}
