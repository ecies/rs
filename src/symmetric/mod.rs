use rand_core::{OsRng, RngCore};

use crate::compat::Vec;
use crate::consts::NONCE_LENGTH;

#[cfg(any(feature = "pure", feature = "xchacha20"))]
mod aead;
#[cfg(any(feature = "pure", feature = "xchacha20"))]
use aead::{decrypt, encrypt};

#[cfg(feature = "openssl")]
mod openssl_aes;
#[cfg(feature = "openssl")]
use openssl_aes::{decrypt, encrypt};

mod hash;

pub(crate) use hash::hkdf_derive;

/// Symmetric encryption wrapper. Openssl AES-256-GCM, pure Rust AES-256-GCM, or XChaCha20-Poly1305
/// Nonces are generated randomly.
///
/// For 16 bytes nonce AES-256-GCM and 24 bytes nonce XChaCha20-Poly1305 it's safe.
/// For 12 bytes nonce AES-256-GCM, the key SHOULD be unique for each message to avoid collisions.
pub fn sym_encrypt(key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce);
    encrypt(key, &nonce, msg)
}

/// Symmetric decryption wrapper
pub fn sym_decrypt(key: &[u8], encrypted: &[u8]) -> Option<Vec<u8>> {
    decrypt(key, encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{consts::NONCE_TAG_LENGTH, utils::tests::decode_hex};

    #[test]
    pub(super) fn attempts_to_decrypt_invalid_message() {
        assert!(decrypt(&[], &[]).is_none());
        assert!(decrypt(&[], &[1u8; 16]).is_none());
        assert!(decrypt(&[], &[1u8; NONCE_TAG_LENGTH - 1]).is_none());
    }

    #[test]
    pub(super) fn test_random_key() {
        let mut key = [0u8; 32];

        let texts = [b"this is a text", "😀😀😀😀".as_bytes()];
        for msg in texts.iter() {
            OsRng.fill_bytes(&mut key);
            let encrypted = sym_encrypt(&key, msg).unwrap();
            assert_eq!(msg.to_vec(), sym_decrypt(&key, &encrypted).unwrap());
        }
    }

    #[test]
    #[cfg(all(not(feature = "aes-12bytes-nonce"), not(feature = "xchacha20")))]
    pub(super) fn test_aes_known_key() {
        let text = b"helloworld";
        let key = decode_hex("0000000000000000000000000000000000000000000000000000000000000000");
        let nonce = decode_hex("f3e1ba810d2c8900b11312b7c725565f");
        let tag = decode_hex("ec3b71e17c11dbe31484da9450edcf6c");
        let encrypted = decode_hex("02d2ffed93b856f148b9");

        check_known(text, &key, &nonce, &tag, &encrypted);
    }

    #[test]
    #[cfg(all(feature = "aes-12bytes-nonce", not(feature = "xchacha20")))]
    pub(super) fn test_aes_known_key() {
        let text = b"";
        let key = decode_hex("0000000000000000000000000000000000000000000000000000000000000000");
        let nonce = decode_hex("000000000000000000000000");
        let tag = decode_hex("530f8afbc74536b9a963b4f1c4cb738b");
        let encrypted = decode_hex("");

        check_known(text, &key, &nonce, &tag, &encrypted);
    }

    #[test]
    #[cfg(feature = "xchacha20")]
    pub(super) fn test_xchacha20_known_key() {
        let text = b"helloworld";
        let key = decode_hex("27bd6ec46292a3b421cdaf8a3f0ca759cbc67bcbe7c5855aa0d1e0700fd0e828");
        let nonce = decode_hex("fbd5dd10431af533c403d6f4fa629931e5f31872d2f7e7b6");
        let tag = decode_hex("5b5ccc27324af03b7ca92dd067ad6eb5");
        let encrypted = decode_hex("aa0664f3c00a09d098bf");

        check_known(text, &key, &nonce, &tag, &encrypted);
    }

    fn check_known(msg: &[u8], key: &[u8], nonce: &[u8], tag: &[u8], encrypted: &[u8]) {
        let mut cipher_text = Vec::new();
        cipher_text.extend(nonce);
        cipher_text.extend(tag);
        cipher_text.extend(encrypted);
        assert_eq!(msg, &sym_decrypt(key, &cipher_text).unwrap());
        assert_eq!(cipher_text, encrypt(key, nonce, msg).unwrap());
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_wasm() {
        super::tests::test_random_key();
        #[cfg(all(not(feature = "aes-12bytes-nonce"), not(feature = "xchacha20")))]
        super::tests::test_aes_known_key();
        #[cfg(feature = "xchacha20")]
        super::tests::test_xchacha20_known_key();
    }

    #[wasm_bindgen_test]
    fn test_wasm_error() {
        super::tests::attempts_to_decrypt_invalid_message();
    }
}
