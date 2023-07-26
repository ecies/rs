use chacha20poly1305::{
    aead::{generic_array::GenericArray, AeadInPlace},
    KeyInit, XChaCha20Poly1305,
};
use rand_core::{OsRng, RngCore};

use crate::compat::Vec;
use crate::consts::{AEAD_TAG_LENGTH, EMPTY_BYTES, XCHACHA20_NONCE_LENGTH};

const NONCE_TAG_LENGTH: usize = XCHACHA20_NONCE_LENGTH + AEAD_TAG_LENGTH;

/// XChaCha20-Poly1305 encryption wrapper
pub fn encrypt(key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let key = GenericArray::from_slice(key);
    let aead = XChaCha20Poly1305::new(key);

    let mut iv = [0u8; XCHACHA20_NONCE_LENGTH];
    OsRng.fill_bytes(&mut iv);
    let nonce = GenericArray::from_slice(&iv);

    let mut out = Vec::with_capacity(msg.len());
    out.extend(msg);

    if let Ok(tag) = aead.encrypt_in_place_detached(nonce, &EMPTY_BYTES, &mut out) {
        let mut output = Vec::with_capacity(NONCE_TAG_LENGTH + msg.len());
        output.extend(nonce);
        output.extend(tag);
        output.extend(out);
        Some(output)
    } else {
        None
    }
}

/// XChaCha20-Poly1305 decryption wrapper
pub fn decrypt(key: &[u8], encrypted_msg: &[u8]) -> Option<Vec<u8>> {
    if encrypted_msg.len() < NONCE_TAG_LENGTH {
        return None;
    }
    let key = GenericArray::from_slice(key);
    let aead = XChaCha20Poly1305::new(key);

    let iv = GenericArray::from_slice(&encrypted_msg[..XCHACHA20_NONCE_LENGTH]);
    let tag = GenericArray::from_slice(&encrypted_msg[XCHACHA20_NONCE_LENGTH..NONCE_TAG_LENGTH]);

    let mut out = Vec::with_capacity(encrypted_msg.len() - NONCE_TAG_LENGTH);
    out.extend(&encrypted_msg[NONCE_TAG_LENGTH..]);

    if let Ok(_) = aead.decrypt_in_place_detached(iv, &EMPTY_BYTES, &mut out, tag) {
        Some(out)
    } else {
        None
    }
}
