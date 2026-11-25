//! rust-openssl takes at most `i32::MAX` bytes per call, including calls that pass AAD.
//! Messages over that limit used to panic. See <https://github.com/ecies/rs/issues/174>.
//!
//! Run these with `cargo test --release` on a machine with about 4 GiB of memory to spare.
//! Only 64-bit targets can hold such messages. The bug is in the AES layer, so the default curve is enough.
#![cfg(all(target_pointer_width = "64", not(feature = "x25519"), not(feature = "ed25519")))]

use ecies::config::get_ephemeral_key_size;
use ecies::consts::NONCE_TAG_LENGTH;
use ecies::utils::generate_keypair;
use ecies::{decrypt, encrypt};

/// Over `i32::MAX`, and not a multiple of the 16 bytes AES block
const SIZE: usize = (1 << 31) + 5;

/// 251 is odd, so the pattern never repeats at a power-of-two distance, and misplaced bytes show
fn byte_at(i: usize) -> u8 {
    (i % 251) as u8
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "allocates about 4 GiB, so it runs in release builds only"
)]
fn encrypts_and_decrypts_messages_over_2_gib() {
    let (sk, pk) = generate_keypair();
    let msg: Vec<u8> = (0..SIZE).map(byte_at).collect();

    let encrypted = encrypt(&pk.serialize(), &msg).unwrap();
    drop(msg);
    assert_eq!(encrypted.len(), get_ephemeral_key_size() + NONCE_TAG_LENGTH + SIZE);

    // one copy of the message in memory at a time, on top of the encrypted one
    let decrypted = decrypt(&sk.serialize(), &encrypted).unwrap();
    drop(encrypted);
    assert!(decrypted.iter().copied().eq((0..SIZE).map(byte_at)));
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "allocates about 4 GiB, so it runs in release builds only"
)]
fn rejects_a_forged_message_over_2_gib() {
    // a valid ephemeral public key, then a nonce, a tag and a body that nobody encrypted
    let (sk, pk) = generate_keypair();
    let key_size = get_ephemeral_key_size();
    let valid = encrypt(&pk.serialize(), b"hello").unwrap();
    let mut forged = vec![0u8; key_size + NONCE_TAG_LENGTH + SIZE];
    forged[..key_size].copy_from_slice(&valid[..key_size]);

    let result = decrypt(&sk.serialize(), &forged);
    assert_eq!(result.unwrap_err().to_string(), "Invalid message");
}

#[test]
#[cfg(feature = "aes-openssl")]
#[cfg_attr(debug_assertions, ignore = "allocates over 2 GiB, so it runs in release builds only")]
fn authenticates_aad_over_2_gib() {
    use ecies::{decrypt_with_aad, encrypt_with_aad};

    let (sk, pk) = generate_keypair();
    let mut aad = vec![0u8; SIZE];
    let encrypted = encrypt_with_aad(&pk.serialize(), b"", &aad).unwrap();
    assert!(decrypt_with_aad(&sk.serialize(), &encrypted, &aad).unwrap().is_empty());

    aad[SIZE - 1] ^= 1;
    assert!(decrypt_with_aad(&sk.serialize(), &encrypted, &aad).is_err());
}
