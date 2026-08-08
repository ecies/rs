use crypto_common::Generate;
use getrandom::SysRng;
use rand_core::UnwrapErr;

use crate::compat::Vec;
use crate::consts::NONCE_LENGTH;

#[cfg(any(feature = "aes-rust", feature = "xchacha20"))]
mod aead;
#[cfg(any(feature = "aes-rust", feature = "xchacha20"))]
use aead::{decrypt, encrypt_into};

#[cfg(feature = "aes-openssl")]
mod openssl_aes;
#[cfg(feature = "aes-openssl")]
use openssl_aes::{decrypt, encrypt_into};

mod hash;

pub(crate) use hash::hkdf_derive;

/// Symmetric encryption wrapper. Openssl AES-256-GCM, pure Rust AES-256-GCM, or XChaCha20-Poly1305
/// Nonces are generated randomly.
///
/// For 16 bytes nonce AES-256-GCM and 24 bytes nonce XChaCha20-Poly1305 it's safe.
/// For 12 bytes nonce AES-256-GCM, the key SHOULD be unique for each message to avoid collisions.
pub fn sym_encrypt(key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    sym_encrypt_with_aad(key, msg, &[])
}

/// Encrypt `msg` with a random nonce and authenticate `aad`. Pass the same `aad` to [`sym_decrypt_with_aad`].
/// With `aes-short-nonce`, use a fresh key for each AES-GCM message. See [`sym_encrypt`] for nonce sizes.
pub(crate) fn sym_encrypt_with_aad(key: &[u8], msg: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    sym_encrypt_into(&mut output, key, msg, aad)?;
    Some(output)
}

/// Symmetric encryption appending the nonce, tag and ciphertext to the provided buffer
pub(crate) fn sym_encrypt_into(output: &mut Vec<u8>, key: &[u8], msg: &[u8], aad: &[u8]) -> Option<()> {
    let nonce: [u8; NONCE_LENGTH] = Generate::generate_from_rng(&mut UnwrapErr(SysRng));
    encrypt_into(output, key, &nonce, msg, aad)
}

/// Symmetric decryption wrapper
pub fn sym_decrypt(key: &[u8], encrypted: &[u8]) -> Option<Vec<u8>> {
    sym_decrypt_with_aad(key, encrypted, &[])
}

/// Decrypt with the AAD you passed to [`sym_encrypt_with_aad`]. Returns `None` if it doesn't match.
pub(crate) fn sym_decrypt_with_aad(key: &[u8], encrypted: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    decrypt(key, encrypted, aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{consts::NONCE_TAG_LENGTH, utils::tests::decode_hex};

    #[test]
    pub(super) fn attempts_to_decrypt_invalid_message() {
        assert!(sym_decrypt(&[], &[]).is_none());
        assert!(sym_decrypt(&[], &[1u8; 16]).is_none());
        assert!(sym_decrypt(&[], &[1u8; NONCE_TAG_LENGTH - 1]).is_none());
    }

    #[test]
    pub(super) fn test_random_key() {
        let texts = [b"this is a text", "😀😀😀😀".as_bytes()];
        for msg in texts.iter() {
            let key: [u8; 32] = Generate::generate_from_rng(&mut UnwrapErr(SysRng));
            let encrypted = sym_encrypt(&key, msg).unwrap();
            assert_eq!(msg.to_vec(), sym_decrypt(&key, &encrypted).unwrap());
        }
    }

    #[test]
    pub(super) fn test_aad() {
        let key = [7u8; 32];
        let aad = b"entry-name";
        let encrypted = sym_encrypt_with_aad(&key, b"", aad).unwrap();
        assert_eq!(encrypted.len(), NONCE_TAG_LENGTH);
        assert!(sym_decrypt_with_aad(&key, &encrypted, aad).unwrap().is_empty());
        assert!(sym_decrypt_with_aad(&key, &encrypted, b"other-name").is_none());
        assert!(sym_decrypt(&key, &encrypted).is_none());
    }

    #[test]
    #[cfg(all(feature = "aes-rust", not(feature = "aes-short-nonce")))]
    fn test_aes_aad_layout() {
        use aes_gcm::aead::AeadInOut;
        use aes_gcm::{AesGcm, KeyInit, aes::Aes256};

        let key = [7u8; 32];
        let nonce = [3u8; NONCE_LENGTH];
        let aad = b"entry-name";
        let msg = b"bound plaintext";

        let cipher = AesGcm::<Aes256, typenum::consts::U16>::new_from_slice(&key).unwrap();
        let mut body = *msg;
        let tag = cipher
            .encrypt_inout_detached((&nonce).into(), aad, body.as_mut_slice().into())
            .unwrap();

        let mut encrypted = Vec::new();
        encrypt_into(&mut encrypted, &key, &nonce, msg, aad).unwrap();
        assert_eq!(&encrypted[..NONCE_LENGTH], &nonce);
        assert_eq!(&encrypted[NONCE_LENGTH..NONCE_TAG_LENGTH], tag.as_slice());
        assert_eq!(&encrypted[NONCE_TAG_LENGTH..], &body);
    }

    #[test]
    #[cfg(all(not(feature = "aes-short-nonce"), not(feature = "xchacha20")))]
    pub(super) fn test_aes_known_key() {
        let text = b"helloworld";
        let key = decode_hex("0000000000000000000000000000000000000000000000000000000000000000");
        let nonce = decode_hex("f3e1ba810d2c8900b11312b7c725565f");
        let tag = decode_hex("ec3b71e17c11dbe31484da9450edcf6c");
        let encrypted = decode_hex("02d2ffed93b856f148b9");

        check_known(text, &key, &nonce, &tag, &encrypted);
    }

    #[test]
    #[cfg(all(feature = "aes-short-nonce", not(feature = "xchacha20")))]
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

        let mut encrypted_out = Vec::new();
        encrypt_into(&mut encrypted_out, key, nonce, msg, &[]).unwrap();
        assert_eq!(cipher_text, encrypted_out);
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_wasm() {
        super::tests::test_random_key();
        super::tests::test_aad();
        #[cfg(all(not(feature = "aes-short-nonce"), not(feature = "xchacha20")))]
        super::tests::test_aes_known_key();
        #[cfg(feature = "xchacha20")]
        super::tests::test_xchacha20_known_key();
    }

    #[wasm_bindgen_test]
    fn test_wasm_error() {
        super::tests::attempts_to_decrypt_invalid_message();
    }
}
