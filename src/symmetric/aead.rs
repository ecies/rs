#[cfg(all(feature = "aes-rust", not(feature = "xchacha20")))]
use aes_gcm::{self as cipher, AesGcm, aes::Aes256};
#[cfg(all(feature = "xchacha20", not(feature = "aes-rust")))]
use chacha20poly1305::{self as cipher, XChaCha20Poly1305};

use cipher::{
    KeyInit,
    aead::{AeadInPlace, generic_array::GenericArray},
};

#[cfg(all(feature = "aes-rust", feature = "aes-short-nonce"))]
type Cipher = AesGcm<Aes256, typenum::consts::U12>;
#[cfg(all(feature = "aes-rust", not(feature = "aes-short-nonce")))]
type Cipher = AesGcm<Aes256, typenum::consts::U16>;
#[cfg(feature = "xchacha20")]
type Cipher = XChaCha20Poly1305;

use crate::compat::Vec;
use crate::consts::{AEAD_TAG_LENGTH, EMPTY_BYTES, NONCE_LENGTH, NONCE_TAG_LENGTH};

/// Pure Rust AES-256-GCM or XChaCha20-Poly1305 encryption wrapper,
/// appending the nonce, tag and ciphertext to the provided buffer.
/// Maximum message size: 64GB (AES) or 256GB (XChaCha20).
///
/// It's basically safe to just `unwrap` the returned `Option<()>`.
pub fn encrypt(output: &mut Vec<u8>, key: &[u8], nonce: &[u8], msg: &[u8]) -> Option<()> {
    let key = GenericArray::from_slice(key);
    let aead = Cipher::new(key);

    let base = output.len();
    output.reserve(NONCE_TAG_LENGTH + msg.len());
    output.extend(nonce);
    output.extend([0u8; AEAD_TAG_LENGTH]);
    output.extend(msg);

    let nonce = GenericArray::from_slice(nonce);
    aead.encrypt_in_place_detached(nonce, &EMPTY_BYTES, &mut output[base + NONCE_TAG_LENGTH..])
        .map(|tag| {
            output[base + NONCE_LENGTH..base + NONCE_TAG_LENGTH].copy_from_slice(tag.as_slice());
        })
        .ok()
}

/// Pure Rust AES-256-GCM or XChaCha20-Poly1305 decryption wrapper
pub fn decrypt(key: &[u8], encrypted: &[u8]) -> Option<Vec<u8>> {
    if encrypted.len() < NONCE_TAG_LENGTH {
        return None;
    }
    let key = GenericArray::from_slice(key);
    let aead = Cipher::new(key);

    let nonce = GenericArray::from_slice(&encrypted[..NONCE_LENGTH]);
    let tag = GenericArray::from_slice(&encrypted[NONCE_LENGTH..NONCE_TAG_LENGTH]);

    let mut out = Vec::with_capacity(encrypted.len() - NONCE_TAG_LENGTH);
    out.extend(&encrypted[NONCE_TAG_LENGTH..]);

    aead.decrypt_in_place_detached(nonce, &EMPTY_BYTES, &mut out, tag)
        .map(|_| out)
        .ok()
}
