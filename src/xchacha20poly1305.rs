use crate::consts::XCHACHAPOLY1305_XNONCE_LENGTH;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use rand::{thread_rng, Rng};

/// XChaCha20-Poly1305 encryption wrapper
pub fn symmetric_encrypt(key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let key = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(key);
    let mut xnonce = [0u8; XCHACHAPOLY1305_XNONCE_LENGTH];
    thread_rng().fill(&mut xnonce);
    let xnonce = XNonce::from(xnonce);
    let Ok(encrypted) = cipher.encrypt(&xnonce, msg) else {
        return None;
    };
    let mut output = Vec::with_capacity(XCHACHAPOLY1305_XNONCE_LENGTH + encrypted.len());
    output.extend(xnonce);
    output.extend(encrypted);

    Some(output)
}

/// XChaCha20-Poly1305 decryption wrapper
pub fn symmetric_decrypt(key: &[u8], encrypted_msg: &[u8]) -> Option<Vec<u8>> {
    if encrypted_msg.len() < XCHACHAPOLY1305_XNONCE_LENGTH {
        return None;
    }
    let key = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(key);
    let xnonce = &encrypted_msg[..XCHACHAPOLY1305_XNONCE_LENGTH];
    let encrypted = &encrypted_msg[XCHACHAPOLY1305_XNONCE_LENGTH..];

    let xnonce = XNonce::from_slice(xnonce);
    cipher.decrypt(xnonce, encrypted).ok()
}