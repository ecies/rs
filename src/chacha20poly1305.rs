use std::env::args;
use chacha20poly1305;
use chacha20poly1305::{AeadCore, AeadInPlace, Key, KeyInit, XChaCha20Poly1305, XNonce};
use chacha20poly1305::aead::{Aead, OsRng};
use rand::{Rng, thread_rng};
use crate::consts::{AES_IV_LENGTH, AES_IV_PLUS_TAG_LENGTH, EMPTY_BYTES, XCHACHA20POLY1305_NONCE_LENGTH};

/// XChaCha20-Poly1305 encryption wrapper
pub fn symmetric_encrypt(key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let key = Key::from_slice(key);
    let aead = XChaCha20Poly1305::new(key);
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let mut msg = aead.encrypt(&nonce, msg).ok()?;
    msg.extend(nonce.iter());

    Some(msg)
}

/// XChaCha20-Poly1305 decryption wrapper
pub fn symmetric_decrypt(key: &[u8], encrypted_msg: &[u8]) -> Option<Vec<u8>> {
    if encrypted_msg.len() < XCHACHA20POLY1305_NONCE_LENGTH {
        return None;
    }

    let nonce = &encrypted_msg[encrypted_msg.len()-XCHACHA20POLY1305_NONCE_LENGTH..encrypted_msg.len()];
    let nonce = XNonce::from_slice(nonce);

    let key = Key::from_slice(key);

    let encrypted_msg = &encrypted_msg[0..encrypted_msg.len()-XCHACHA20POLY1305_NONCE_LENGTH];
    let aead = XChaCha20Poly1305::new(key);

    aead.decrypt(&nonce, encrypted_msg).ok()
}
