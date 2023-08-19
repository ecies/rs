#[cfg(all(feature = "pure", not(feature = "xchacha20")))]
use aes_gcm::{
    aead::{generic_array::GenericArray, AeadInPlace},
    aes::Aes256,
    AesGcm, KeyInit,
};
#[cfg(all(feature = "xchacha20", not(feature = "pure")))]
use chacha20poly1305::{
    aead::{generic_array::GenericArray, AeadInPlace},
    KeyInit, XChaCha20Poly1305,
};
#[cfg(all(feature = "pure", feature = "aes-12bytes-nonce"))]
use typenum::consts::U12;
#[cfg(all(feature = "pure", not(feature = "aes-12bytes-nonce")))]
use typenum::consts::U16;

#[cfg(all(feature = "pure", feature = "aes-12bytes-nonce"))]
type Cipher = AesGcm<Aes256, U12>;
#[cfg(all(feature = "pure", not(feature = "aes-12bytes-nonce")))]
type Cipher = AesGcm<Aes256, U16>;
#[cfg(feature = "xchacha20")]
type Cipher = XChaCha20Poly1305;

use crate::compat::Vec;
use crate::consts::{AEAD_TAG_LENGTH, EMPTY_BYTES, NONCE_LENGTH, NONCE_TAG_LENGTH};

/// Pure Rust AES-256-GCM or XChaCha20-Poly1305 encryption wrapper.
/// Maximum message size: 64GB (AES) or 256GB (XChaCha20).
///
/// It's basically safe to just `unwrap` the returned `Option<Vec<u8>>`.
pub fn encrypt(key: &[u8], nonce: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let key = GenericArray::from_slice(key);
    let aead = Cipher::new(key);

    let mut output = Vec::with_capacity(NONCE_TAG_LENGTH + msg.len());
    output.extend(nonce);
    output.extend([0u8; AEAD_TAG_LENGTH]);
    output.extend(msg);

    let nonce = GenericArray::from_slice(nonce);
    if let Ok(tag) = aead.encrypt_in_place_detached(nonce, &EMPTY_BYTES, &mut output[NONCE_TAG_LENGTH..]) {
        output[NONCE_LENGTH..NONCE_TAG_LENGTH].copy_from_slice(tag.as_slice());
        Some(output)
    } else {
        None
    }
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

    if aead
        .decrypt_in_place_detached(nonce, &EMPTY_BYTES, &mut out, tag)
        .is_ok()
    {
        Some(out)
    } else {
        None
    }
}
