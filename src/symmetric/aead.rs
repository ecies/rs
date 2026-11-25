use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag};
use aes_gcm::{AesGcm, aes::Aes256};
use chacha20poly1305::XChaCha20Poly1305;

use super::{NonceLength, SymmetricAlgorithm, nonce_size};
use crate::compat::Vec;
use crate::consts::AEAD_TAG_LENGTH;

/// Pure Rust AES-256-GCM or XChaCha20-Poly1305 encryption wrapper,
/// appending the nonce, tag and ciphertext to the provided buffer.
/// Maximum message size: 64GB (AES) or 256GB (XChaCha20).
///
/// It's basically safe to just `unwrap` the returned `Option<()>`.
pub(super) fn encrypt_into(
    output: &mut Vec<u8>,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    algorithm: SymmetricAlgorithm,
    nonce_length: NonceLength,
) -> Option<()> {
    match (algorithm, nonce_length) {
        (SymmetricAlgorithm::Aes256Gcm, NonceLength::Sixteen) => {
            encrypt_with::<AesGcm<Aes256, U16>>(output, key, nonce, plaintext, aad)
        }
        (SymmetricAlgorithm::Aes256Gcm, NonceLength::Twelve) => {
            encrypt_with::<AesGcm<Aes256, U12>>(output, key, nonce, plaintext, aad)
        }
        (SymmetricAlgorithm::XChaCha20, _) => encrypt_with::<XChaCha20Poly1305>(output, key, nonce, plaintext, aad),
    }
}

/// Pure Rust AES-256-GCM or XChaCha20-Poly1305 decryption wrapper
pub(super) fn decrypt(
    key: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
    algorithm: SymmetricAlgorithm,
    nonce_length: NonceLength,
) -> Option<Vec<u8>> {
    let nonce_size = nonce_size(algorithm, nonce_length);
    match (algorithm, nonce_length) {
        (SymmetricAlgorithm::Aes256Gcm, NonceLength::Sixteen) => {
            decrypt_with::<AesGcm<Aes256, U16>>(key, ciphertext, aad, nonce_size)
        }
        (SymmetricAlgorithm::Aes256Gcm, NonceLength::Twelve) => {
            decrypt_with::<AesGcm<Aes256, U12>>(key, ciphertext, aad, nonce_size)
        }
        (SymmetricAlgorithm::XChaCha20, _) => decrypt_with::<XChaCha20Poly1305>(key, ciphertext, aad, nonce_size),
    }
}

fn encrypt_with<C: AeadInOut + KeyInit>(
    output: &mut Vec<u8>,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Option<()> {
    let aead = C::new_from_slice(key).ok()?;
    let nonce = Nonce::<C>::try_from(nonce).ok()?;
    let nonce_size = nonce.len();
    let nonce_tag_size = nonce_size + AEAD_TAG_LENGTH;

    let base = output.len();
    output.reserve(nonce_tag_size + plaintext.len());
    output.extend(nonce.iter());
    output.extend([0u8; AEAD_TAG_LENGTH]);
    output.extend(plaintext);

    aead.encrypt_inout_detached(&nonce, aad, (&mut output[base + nonce_tag_size..]).into())
        .map(|tag| {
            output[base + nonce_size..base + nonce_tag_size].copy_from_slice(&tag);
        })
        .ok()
}

fn decrypt_with<C: AeadInOut + KeyInit>(
    key: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
    nonce_size: usize,
) -> Option<Vec<u8>> {
    let nonce_tag_size = nonce_size + AEAD_TAG_LENGTH;
    if ciphertext.len() < nonce_tag_size {
        return None;
    }
    let aead = C::new_from_slice(key).ok()?;

    let nonce = Nonce::<C>::try_from(&ciphertext[..nonce_size]).ok()?;
    let tag = Tag::<C>::try_from(&ciphertext[nonce_size..nonce_tag_size]).ok()?;

    let mut out = Vec::with_capacity(ciphertext.len() - nonce_tag_size);
    out.extend(&ciphertext[nonce_tag_size..]);

    aead.decrypt_inout_detached(&nonce, aad, out.as_mut_slice().into(), &tag)
        .map(|_| out)
        .ok()
}
