use aes_gcm::aead::{generic_array::GenericArray, AeadInPlace};
use aes_gcm::{aes::Aes256, AesGcm, KeyInit};
use rand::{thread_rng, Rng};
use typenum::consts::U16;

use crate::consts::{AES_IV_LENGTH, AES_IV_PLUS_TAG_LENGTH, EMPTY_BYTES};

/// AES-256-GCM with 16 bytes Nonce/IV
pub type Aes256Gcm = AesGcm<Aes256, U16>;

/// AES-256-GCM encryption wrapper
pub fn symmetric_encrypt(key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let key = GenericArray::from_slice(key);
    let aead = Aes256Gcm::new(key);

    let mut iv = [0u8; AES_IV_LENGTH];
    thread_rng().fill(&mut iv);

    let nonce = GenericArray::from_slice(&iv);

    let mut out = Vec::with_capacity(msg.len());
    out.extend(msg);

    if let Ok(tag) = aead.encrypt_in_place_detached(nonce, &EMPTY_BYTES, &mut out) {
        let mut output = Vec::with_capacity(AES_IV_PLUS_TAG_LENGTH + msg.len());
        output.extend(&iv);
        output.extend(tag);
        output.extend(out);
        Some(output)
    } else {
        None
    }
}

/// AES-256-GCM decryption wrapper
pub fn symmetric_decrypt(key: &[u8], encrypted_msg: &[u8]) -> Option<Vec<u8>> {
    if encrypted_msg.len() < AES_IV_PLUS_TAG_LENGTH {
        return None;
    }

    let key = GenericArray::from_slice(key);
    let aead = Aes256Gcm::new(key);

    let iv = GenericArray::from_slice(&encrypted_msg[..AES_IV_LENGTH]);
    let tag = GenericArray::from_slice(&encrypted_msg[AES_IV_LENGTH..AES_IV_PLUS_TAG_LENGTH]);

    let mut out = Vec::with_capacity(encrypted_msg.len() - AES_IV_PLUS_TAG_LENGTH);
    out.extend(&encrypted_msg[AES_IV_PLUS_TAG_LENGTH..]);

    if let Ok(_) = aead.decrypt_in_place_detached(iv, &EMPTY_BYTES, &mut out, tag) {
        Some(out)
    } else {
        None
    }
}
