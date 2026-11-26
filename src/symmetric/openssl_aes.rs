use openssl::symm::{Cipher, Crypter, Mode};

#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(feature = "std")]
use std::vec;

use crate::Vec;
use crate::consts::AEAD_TAG_LENGTH;

/// rust-openssl panics on more than `i32::MAX` bytes in one call, so longer messages go through in chunks
const CHUNK_LENGTH: usize = 1 << 30;

/// AES-256-GCM encryption wrapper, appending the nonce, tag and ciphertext to the provided buffer.
/// The nonce is 12 or 16 bytes.
pub(super) fn encrypt_into(output: &mut Vec<u8>, key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Option<()> {
    #[cfg(test)]
    calls::record();
    let cipher = Cipher::aes_256_gcm();
    // 1 for AES-256-GCM, but `Crypter` demands this slack space on top of the message size
    let block_size = cipher.block_size();
    let nonce_tag_size = nonce.len() + AEAD_TAG_LENGTH;

    let base = output.len();
    output.reserve(nonce_tag_size + plaintext.len() + block_size);
    output.extend(nonce);
    output.extend([0u8; AEAD_TAG_LENGTH]);

    let encrypted_start = base + nonce_tag_size;
    output.resize(encrypted_start + plaintext.len() + block_size, 0);

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(nonce)).ok()?;
    update_aad(&mut crypter, aad)?;
    let mut count = update_all(&mut crypter, plaintext, &mut output[encrypted_start..])?;
    count += crypter.finalize(&mut output[encrypted_start + count..]).ok()?;
    output.truncate(encrypted_start + count);

    crypter
        .get_tag(&mut output[base + nonce.len()..base + nonce_tag_size])
        .ok()
}

/// AES-256-GCM decryption wrapper for payloads with `nonce_size`-byte nonces
pub(super) fn decrypt(key: &[u8], ciphertext: &[u8], aad: &[u8], nonce_size: usize) -> Option<Vec<u8>> {
    #[cfg(test)]
    calls::record();
    let nonce_tag_size = nonce_size + AEAD_TAG_LENGTH;
    if ciphertext.len() < nonce_tag_size {
        return None;
    }

    let cipher = Cipher::aes_256_gcm();

    let nonce = &ciphertext[..nonce_size];
    let tag = &ciphertext[nonce_size..nonce_tag_size];
    let ciphertext = &ciphertext[nonce_tag_size..];

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

/// Counts this thread's calls into OpenSSL, so tests can check which backend AES-256-GCM goes through
#[cfg(test)]
pub(super) mod calls {
    extern crate std;

    use core::cell::Cell;

    std::thread_local! {
        static COUNT: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn record() {
        COUNT.with(|count| count.set(count.get() + 1));
    }

    pub(in crate::symmetric) fn count() -> usize {
        COUNT.with(Cell::get)
    }
}
