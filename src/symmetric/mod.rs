use alloc::vec::Vec;

use getrandom::SysRng;
use rand_core::{Rng, UnwrapErr};

use crate::config::{NonceLength, SymmetricAlgorithm, nonce_size};
use crate::consts::XCHACHA20_NONCE_LENGTH;

mod aead;
#[cfg(feature = "aes-openssl")]
mod openssl_aes;

mod hash;

pub(crate) use hash::hkdf_derive;

/// Encrypt `msg` with a random nonce and authenticate `aad`, appending the nonce, tag and ciphertext to `output`.
///
/// With 12-byte AES-256-GCM nonces, use a fresh key for each message, since random nonces that short can collide.
pub(crate) fn sym_encrypt_into(
    output: &mut Vec<u8>,
    key: &[u8],
    msg: &[u8],
    aad: &[u8],
    algorithm: SymmetricAlgorithm,
    nonce_length: NonceLength,
) -> Option<()> {
    let mut nonce = [0u8; XCHACHA20_NONCE_LENGTH];
    let nonce = &mut nonce[..nonce_size(algorithm, nonce_length)];
    UnwrapErr(SysRng).fill_bytes(nonce);
    encrypt_into(output, key, nonce, msg, aad, algorithm, nonce_length)
}

/// Encrypt with a given nonce, which must be as long as the algorithm and nonce length call for
fn encrypt_into(
    output: &mut Vec<u8>,
    key: &[u8],
    nonce: &[u8],
    msg: &[u8],
    aad: &[u8],
    algorithm: SymmetricAlgorithm,
    nonce_length: NonceLength,
) -> Option<()> {
    if nonce.len() != nonce_size(algorithm, nonce_length) {
        return None;
    }
    match algorithm {
        #[cfg(feature = "aes-openssl")]
        SymmetricAlgorithm::Aes256Gcm => openssl_aes::encrypt_into(output, key, nonce, msg, aad),
        _ => aead::encrypt_into(output, key, nonce, msg, aad, algorithm, nonce_length),
    }
}

/// Decrypt a payload made with the same AAD, algorithm and nonce length. Returns `None` if any of them differ.
pub(crate) fn sym_decrypt(
    key: &[u8],
    encrypted: &[u8],
    aad: &[u8],
    algorithm: SymmetricAlgorithm,
    nonce_length: NonceLength,
) -> Option<Vec<u8>> {
    match algorithm {
        #[cfg(feature = "aes-openssl")]
        SymmetricAlgorithm::Aes256Gcm => openssl_aes::decrypt(key, encrypted, aad, nonce_size(algorithm, nonce_length)),
        _ => aead::decrypt(key, encrypted, aad, algorithm, nonce_length),
    }
}

#[cfg(test)]
mod tests {
    use crypto_common::Generate;

    use super::*;
    use crate::utils::tests::decode_hex;

    /// Every cipher setting, with the bytes its nonce and tag add to a payload
    const SETTINGS: [(SymmetricAlgorithm, NonceLength, usize); 3] = [
        (SymmetricAlgorithm::Aes256Gcm, NonceLength::Sixteen, 32),
        (SymmetricAlgorithm::Aes256Gcm, NonceLength::Twelve, 28),
        (SymmetricAlgorithm::XChaCha20, NonceLength::Sixteen, 40),
    ];

    #[test]
    pub(super) fn attempts_to_decrypt_invalid_message() {
        let key = [1u8; 32];
        let too_short = [1u8; 40];
        for (algorithm, nonce_length, overhead) in SETTINGS {
            assert!(sym_decrypt(&key, &[], &[], algorithm, nonce_length).is_none());
            assert!(sym_decrypt(&key, &too_short[..overhead - 1], &[], algorithm, nonce_length).is_none());
            assert!(sym_decrypt(&[], &too_short[..overhead], &[], algorithm, nonce_length).is_none());
        }
    }

    #[test]
    pub(super) fn test_random_key() {
        let texts = [b"this is a text".as_slice(), "😀😀😀😀".as_bytes()];
        for (algorithm, nonce_length, overhead) in SETTINGS {
            for msg in texts {
                let key: [u8; 32] = Generate::generate_from_rng(&mut UnwrapErr(SysRng));
                let mut encrypted = Vec::new();
                sym_encrypt_into(&mut encrypted, &key, msg, &[], algorithm, nonce_length).unwrap();
                assert_eq!(encrypted.len(), overhead + msg.len());
                let decrypted = sym_decrypt(&key, &encrypted, &[], algorithm, nonce_length);
                assert_eq!(decrypted.as_deref(), Some(msg));
            }
        }
    }

    #[test]
    pub(super) fn test_aad() {
        let key = [7u8; 32];
        let aad = b"entry-name";
        for (algorithm, nonce_length, overhead) in SETTINGS {
            let mut encrypted = Vec::new();
            sym_encrypt_into(&mut encrypted, &key, b"", aad, algorithm, nonce_length).unwrap();
            assert_eq!(encrypted.len(), overhead);
            let decrypted = sym_decrypt(&key, &encrypted, aad, algorithm, nonce_length);
            assert_eq!(decrypted.as_deref(), Some(b"".as_slice()));
            assert!(sym_decrypt(&key, &encrypted, b"other-name", algorithm, nonce_length).is_none());
            assert!(sym_decrypt(&key, &encrypted, &[], algorithm, nonce_length).is_none());
        }
    }

    #[test]
    fn rejects_wrong_nonce_size() {
        // OpenSSL would take any IV length, so the nonce size is checked before either backend runs
        let key = [7u8; 32];
        let nonce = [3u8; 41];
        for (algorithm, nonce_length, overhead) in SETTINGS {
            let nonce_size = overhead - 16;
            for wrong in [nonce_size - 1, nonce_size + 1] {
                let mut out = Vec::new();
                let result = encrypt_into(&mut out, &key, &nonce[..wrong], b"msg", &[], algorithm, nonce_length);
                assert_eq!(result, None, "{algorithm:?} {nonce_length:?} with a {wrong}-byte nonce");
            }
        }
    }

    #[test]
    fn nonces_are_fresh() {
        let key = [7u8; 32];
        for (algorithm, nonce_length, overhead) in SETTINGS {
            let nonce_size = overhead - 16;
            let nonces: Vec<Vec<u8>> = (0..256)
                .map(|_| {
                    let mut encrypted = Vec::new();
                    sym_encrypt_into(&mut encrypted, &key, b"", &[], algorithm, nonce_length).unwrap();
                    encrypted.truncate(nonce_size);
                    encrypted
                })
                .collect();

            // every byte position changes across draws, which catches a fixed or partly filled nonce
            for i in 0..nonce_size {
                let changes = nonces.iter().any(|nonce| nonce[i] != nonces[0][i]);
                assert!(changes, "{algorithm:?} {nonce_length:?}: byte {i} never changes");
            }
            let mut distinct = nonces.clone();
            distinct.sort_unstable();
            distinct.dedup();
            assert_eq!(distinct.len(), nonces.len(), "{algorithm:?} {nonce_length:?}");
        }
    }

    #[test]
    #[cfg(feature = "aes-openssl")]
    fn aes_goes_through_openssl() {
        use NonceLength::{Sixteen, Twelve};
        use SymmetricAlgorithm::{Aes256Gcm, XChaCha20};

        let key = [7u8; 32];
        // one encryption and one decryption each
        let expected_calls = [(Aes256Gcm, Sixteen, 2), (Aes256Gcm, Twelve, 2), (XChaCha20, Sixteen, 0)];
        for (algorithm, nonce_length, openssl_calls) in expected_calls {
            let before = openssl_aes::calls::count();
            let mut encrypted = Vec::new();
            sym_encrypt_into(&mut encrypted, &key, b"msg", &[], algorithm, nonce_length).unwrap();
            sym_decrypt(&key, &encrypted, &[], algorithm, nonce_length).unwrap();
            let calls = openssl_aes::calls::count() - before;
            assert_eq!(calls, openssl_calls, "{algorithm:?} {nonce_length:?}");
        }
    }

    #[test]
    fn test_aes_aad_layout() {
        use NonceLength::Sixteen;
        use SymmetricAlgorithm::Aes256Gcm;
        use aes_gcm::aead::{AeadInOut, KeyInit, consts::U16};
        use aes_gcm::{AesGcm, aes::Aes256};

        let key = [7u8; 32];
        let nonce = [3u8; 16];
        let aad = b"entry-name";
        let msg = b"bound plaintext";

        let cipher = AesGcm::<Aes256, U16>::new_from_slice(&key).unwrap();
        let mut body = *msg;
        let tag = cipher
            .encrypt_inout_detached((&nonce).into(), aad, body.as_mut_slice().into())
            .unwrap();

        let mut encrypted = Vec::new();
        encrypt_into(&mut encrypted, &key, &nonce, msg, aad, Aes256Gcm, Sixteen).unwrap();
        assert_eq!(&encrypted[..16], &nonce);
        assert_eq!(&encrypted[16..32], tag.as_slice());
        assert_eq!(&encrypted[32..], &body);
    }

    #[test]
    #[cfg(feature = "aes-openssl")]
    fn openssl_and_pure_rust_aes_interchange() {
        use SymmetricAlgorithm::Aes256Gcm;

        let key = [7u8; 32];
        let aad = b"entry-name";
        let msg = b"either backend";
        for nonce_length in [NonceLength::Sixteen, NonceLength::Twelve] {
            let nonce = &[3u8; 16][..nonce_length as usize];

            let mut openssl = Vec::new();
            openssl_aes::encrypt_into(&mut openssl, &key, nonce, msg, aad).unwrap();
            let mut rust = Vec::new();
            aead::encrypt_into(&mut rust, &key, nonce, msg, aad, Aes256Gcm, nonce_length).unwrap();
            assert_eq!(openssl, rust, "{nonce_length:?}");

            let from_openssl = aead::decrypt(&key, &openssl, aad, Aes256Gcm, nonce_length);
            assert_eq!(from_openssl.as_deref(), Some(msg.as_slice()), "{nonce_length:?}");
            let from_rust = openssl_aes::decrypt(&key, &rust, aad, nonce_length as usize);
            assert_eq!(from_rust.as_deref(), Some(msg.as_slice()), "{nonce_length:?}");
        }
    }

    /// A payload from a fixed key and nonce, whatever the Cargo features select
    struct Known {
        algorithm: SymmetricAlgorithm,
        nonce_length: NonceLength,
        msg: &'static [u8],
        key: &'static str,
        nonce: &'static str,
        tag: &'static str,
        encrypted: &'static str,
    }

    const AES_16: Known = Known {
        algorithm: SymmetricAlgorithm::Aes256Gcm,
        nonce_length: NonceLength::Sixteen,
        msg: b"helloworld",
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "f3e1ba810d2c8900b11312b7c725565f",
        tag: "ec3b71e17c11dbe31484da9450edcf6c",
        encrypted: "02d2ffed93b856f148b9",
    };

    const AES_12: Known = Known {
        algorithm: SymmetricAlgorithm::Aes256Gcm,
        nonce_length: NonceLength::Twelve,
        msg: b"",
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "000000000000000000000000",
        tag: "530f8afbc74536b9a963b4f1c4cb738b",
        encrypted: "",
    };

    const XCHACHA20: Known = Known {
        algorithm: SymmetricAlgorithm::XChaCha20,
        nonce_length: NonceLength::Sixteen,
        msg: b"helloworld",
        key: "27bd6ec46292a3b421cdaf8a3f0ca759cbc67bcbe7c5855aa0d1e0700fd0e828",
        nonce: "fbd5dd10431af533c403d6f4fa629931e5f31872d2f7e7b6",
        tag: "5b5ccc27324af03b7ca92dd067ad6eb5",
        encrypted: "aa0664f3c00a09d098bf",
    };

    #[test]
    pub(super) fn test_known_keys() {
        // XChaCha20-Poly1305 always uses 24-byte nonces, so it ignores the nonce length
        let xchacha20_twelve = Known {
            nonce_length: NonceLength::Twelve,
            ..XCHACHA20
        };
        for known in [AES_16, AES_12, XCHACHA20, xchacha20_twelve] {
            let Known {
                algorithm,
                nonce_length,
                msg,
                ..
            } = known;
            let key = decode_hex(known.key);
            let nonce = decode_hex(known.nonce);
            let mut payload = nonce.clone();
            payload.extend(decode_hex(known.tag));
            payload.extend(decode_hex(known.encrypted));

            let decrypted = sym_decrypt(&key, &payload, &[], algorithm, nonce_length);
            assert_eq!(decrypted.as_deref(), Some(msg), "{algorithm:?} {nonce_length:?}");

            let mut encrypted = Vec::new();
            encrypt_into(&mut encrypted, &key, &nonce, msg, &[], algorithm, nonce_length).unwrap();
            assert_eq!(encrypted, payload, "{algorithm:?} {nonce_length:?}");
        }
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_wasm() {
        super::tests::test_random_key();
        super::tests::test_aad();
        super::tests::test_known_keys();
    }

    #[wasm_bindgen_test]
    fn test_wasm_error() {
        super::tests::attempts_to_decrypt_invalid_message();
    }
}
