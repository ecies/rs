#[cfg(feature = "openssl")]
mod openssl_aes;
#[cfg(feature = "pure")]
mod pure_aes;
#[cfg(feature = "xchacha20")]
mod xchacha20;

#[cfg(feature = "openssl")]
use openssl_aes::{decrypt, encrypt};
#[cfg(feature = "pure")]
use pure_aes::{decrypt, encrypt};
#[cfg(feature = "xchacha20")]
use xchacha20::{decrypt, encrypt};

use crate::compat::Vec;

/// Symmetric encryption wrapper. Openssl AES-256-GCM, pure Rust AES-256-GCM, or XChaCha20-Poly1305
pub fn sym_encrypt(key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    encrypt(key, msg)
}

/// Symmetric decryption wrapper
pub fn sym_decrypt(key: &[u8], encrypted_msg: &[u8]) -> Option<Vec<u8>> {
    decrypt(key, encrypted_msg)
}

#[cfg(test)]
pub(crate) mod tests {
    use hex::decode; // dev dep
    use rand_core::{OsRng, RngCore};

    use super::*;

    /// Remove 0x prefix of a hex string
    pub fn remove0x(hex: &str) -> &str {
        if hex.starts_with("0x") || hex.starts_with("0X") {
            return &hex[2..];
        }
        hex
    }

    /// Convert hex string to u8 vector
    pub fn decode_hex(hex: &str) -> Vec<u8> {
        decode(remove0x(hex)).unwrap()
    }

    #[test]
    fn test_attempt_to_decrypt_invalid_message() {
        assert!(decrypt(&[], &[]).is_none());
        assert!(decrypt(&[], &[0; 16]).is_none());
    }

    #[test]
    fn test_random_key() {
        let text = b"this is a text";
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        assert_eq!(
            text,
            decrypt(&key, encrypt(&key, text).unwrap().as_slice())
                .unwrap()
                .as_slice()
        );

        let utf8_text = "😀😀😀😀".as_bytes();
        assert_eq!(
            utf8_text,
            decrypt(&key, encrypt(&key, utf8_text).unwrap().as_slice())
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    #[cfg(all(not(feature = "aes-12bytes-nonce"), not(feature = "xchacha20")))]
    fn test_aes_known_key() {
        let text = b"helloworld";
        let key = decode_hex("0000000000000000000000000000000000000000000000000000000000000000");
        let iv = decode_hex("f3e1ba810d2c8900b11312b7c725565f");
        let tag = decode_hex("ec3b71e17c11dbe31484da9450edcf6c");
        let encrypted = decode_hex("02d2ffed93b856f148b9");

        let mut cipher_text = Vec::new();
        cipher_text.extend(iv);
        cipher_text.extend(tag);
        cipher_text.extend(encrypted);

        assert_eq!(text, decrypt(&key, &cipher_text).unwrap().as_slice());
    }

    #[test]
    #[cfg(feature = "xchacha20")]
    fn test_xchacha20_known_key() {
        let text = b"helloworld";
        let key = decode_hex("27bd6ec46292a3b421cdaf8a3f0ca759cbc67bcbe7c5855aa0d1e0700fd0e828");
        let nonce = decode_hex("fbd5dd10431af533c403d6f4fa629931e5f31872d2f7e7b6");
        let tag = decode_hex("5b5ccc27324af03b7ca92dd067ad6eb5");
        let encrypted = decode_hex("aa0664f3c00a09d098bf");

        let mut cipher_text = Vec::with_capacity(encrypted.len() + 24);
        cipher_text.extend(nonce);
        cipher_text.extend(tag);
        cipher_text.extend(encrypted);

        assert_eq!(text, sym_decrypt(&key, &cipher_text).unwrap().as_slice());
    }
}
