#[cfg(all(feature = "aes-rust", not(feature = "xchacha20")))]
use aes_gcm::{self as cipher, AesGcm, aes::Aes256};
#[cfg(all(feature = "xchacha20", not(feature = "aes-rust")))]
use chacha20poly1305::{self as cipher, XChaCha20Poly1305};

use cipher::aead::{AeadInOut, KeyInit, Nonce, Tag};

#[cfg(all(feature = "aes-rust", feature = "aes-short-nonce"))]
type Cipher = AesGcm<Aes256, typenum::consts::U12>;
#[cfg(all(feature = "aes-rust", not(feature = "aes-short-nonce")))]
type Cipher = AesGcm<Aes256, typenum::consts::U16>;
#[cfg(feature = "xchacha20")]
type Cipher = XChaCha20Poly1305;

use crate::compat::Vec;
use crate::consts::{AEAD_TAG_LENGTH, EMPTY_BYTES, NONCE_LENGTH, NONCE_TAG_LENGTH};

/// Pure Rust AES-256-GCM or XChaCha20-Poly1305 encryption wrapper,
/// appending the nonce, tag and ciphertext to the provided buffer.
/// Maximum message size: 64GB (AES) or 256GB (XChaCha20).
///
/// It's basically safe to just `unwrap` the returned `Option<()>`.
pub(super) fn encrypt_into(output: &mut Vec<u8>, key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Option<()> {
    let aead = Cipher::new_from_slice(key).ok()?;

    let base = output.len();
    output.reserve(NONCE_TAG_LENGTH + plaintext.len());
    output.extend(nonce);
    output.extend([0u8; AEAD_TAG_LENGTH]);
    output.extend(plaintext);

    let nonce = Nonce::<Cipher>::try_from(nonce).ok()?;
    aead.encrypt_inout_detached(&nonce, &EMPTY_BYTES, (&mut output[base + NONCE_TAG_LENGTH..]).into())
        .map(|tag| {
            output[base + NONCE_LENGTH..base + NONCE_TAG_LENGTH].copy_from_slice(&tag);
        })
        .ok()
}

/// Pure Rust AES-256-GCM or XChaCha20-Poly1305 decryption wrapper
pub(super) fn decrypt(key: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < NONCE_TAG_LENGTH {
        return None;
    }
    let aead = Cipher::new_from_slice(key).ok()?;

    let nonce = Nonce::<Cipher>::try_from(&ciphertext[..NONCE_LENGTH]).ok()?;
    let tag = Tag::<Cipher>::try_from(&ciphertext[NONCE_LENGTH..NONCE_TAG_LENGTH]).ok()?;

    let mut out = Vec::with_capacity(ciphertext.len() - NONCE_TAG_LENGTH);
    out.extend(&ciphertext[NONCE_TAG_LENGTH..]);

    aead.decrypt_inout_detached(&nonce, &EMPTY_BYTES, out.as_mut_slice().into(), &tag)
        .map(|_| out)
        .ok()
}
