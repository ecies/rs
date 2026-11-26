use crypto_common::Generate;
use curve25519_dalek::EdwardsPoint;
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, edwards::CompressedEdwardsY};
use ed25519_dalek::SigningKey;
use getrandom::SysRng;
use rand_core::UnwrapErr;

pub use ed25519_dalek::SecretKey;

use crate::compat::Vec;
use crate::consts::{PUBLIC_KEY_SIZE, SharedSecret};
use crate::symmetric::hkdf_derive;

pub type PublicKey = [u8; PUBLIC_KEY_SIZE];

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    InvalidPublicKey,
    InvalidMessage,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidPublicKey => write!(f, "Invalid public key"),
            Error::InvalidMessage => write!(f, "Invalid message"),
        }
    }
}

/// Generate a `(SecretKey, PublicKey)` pair
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let sk: SecretKey = Generate::generate_from_rng(&mut UnwrapErr(SysRng));
    (sk, to_public_key(&sk).to_bytes())
}

/// Calculate a shared symmetric key of our secret key and peer's public key by hkdf
pub fn encapsulate(sk: &SecretKey, peer_pk: &PublicKey, compressed: bool) -> Result<SharedSecret, Error> {
    encapsulate_with_sender(sk, &to_public_key(sk).to_bytes(), peer_pk, compressed)
}

/// Same as [`encapsulate`], but with the sender's public key provided to skip its derivation
pub(crate) fn encapsulate_with_sender(
    sk: &SecretKey,
    sender_pk: &PublicKey,
    peer_pk: &PublicKey,
    _compressed: bool,
) -> Result<SharedSecret, Error> {
    let shared_point = multiply(sk, peer_pk)?;
    Ok(hkdf_derive(sender_pk, shared_point.compress().as_bytes()))
}

/// Calculate a shared symmetric key of our public key and peer's secret key by hkdf
pub fn decapsulate(pk: &PublicKey, peer_sk: &SecretKey, _compressed: bool) -> Result<SharedSecret, Error> {
    let shared_point = multiply(peer_sk, pk)?;
    Ok(hkdf_derive(pk, shared_point.compress().as_bytes()))
}

/// Parse secret key bytes
pub fn parse_sk(sk: &[u8]) -> Result<SecretKey, Error> {
    sk.try_into().map_err(|_| Error::InvalidMessage)
}

/// Parse public key bytes
pub fn parse_pk(pk: &[u8]) -> Result<PublicKey, Error> {
    pk.try_into().map_err(|_| Error::InvalidPublicKey)
}

/// Public key to bytes
pub fn pk_to_vec(pk: &PublicKey, _compressed: bool) -> Vec<u8> {
    pk.to_vec()
}

fn multiply(sk: &SecretKey, pk: &PublicKey) -> Result<EdwardsPoint, Error> {
    let point = CompressedEdwardsY::from_slice(pk)
        .unwrap() // never fails
        .decompress()
        .ok_or(Error::InvalidPublicKey)?;

    // A small-order point makes the shared point the identity, so anyone could decrypt. A mixed-order point is
    // harmless here, but eciesjs usually computes a different shared point for it, so it is refused too, as
    // ecies/js#922 proposes for eciesjs. The identity is torsion-free, so it needs the first check
    if point.is_small_order() || !point.is_torsion_free() {
        return Err(Error::InvalidPublicKey);
    }
    Ok(point.mul_clamped(to_scalar(sk)))
}

fn to_scalar(sk: &SecretKey) -> SecretKey {
    SigningKey::from_bytes(sk).to_scalar_bytes()
}

fn to_public_key(sk: &SecretKey) -> CompressedEdwardsY {
    let scalar = to_scalar(sk);
    G.mul_clamped(scalar).compress()
}

#[cfg(test)]
mod known_tests {
    use super::{multiply, parse_pk, parse_sk};

    use crate::decrypt;
    use crate::utils::tests::decode_hex;

    fn test_known(sk: &str, pk: &str, shared: &str) {
        let sk = parse_sk(&decode_hex(sk)).unwrap();
        let pk = parse_pk(&decode_hex(pk)).unwrap();
        let shared = parse_pk(&decode_hex(shared)).unwrap();

        assert_eq!(multiply(&sk, &pk).unwrap().compress().as_bytes(), shared.as_slice());
    }

    #[test]
    pub fn test_known_shared_point() {
        // scalar of sk 0: 3140620980319341722849076354004524857726602937622481303882784251885505225391
        test_known(
            "0000000000000000000000000000000000000000000000000000000000000000", // sk 0
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29", // peer pk (from sk 1)
            "79a82a4ed2cbf9cab6afbf353df0a225b58642c0c7b3760a99856bf01785817f",
        );
        test_known(
            "0000000000000000000000000000000000000000000000000000000000000001", // sk 1
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29", // peer pk (from sk 0)
            "79a82a4ed2cbf9cab6afbf353df0a225b58642c0c7b3760a99856bf01785817f",
        );
    }

    #[test]
    #[cfg(all(not(feature = "xchacha20"), not(feature = "aes-short-nonce")))]
    pub fn test_known_encrypted() {
        let sk = decode_hex("8be70d30035b24e13377678a3f612cf72333327ff2865def5544ea877ff50c82");
        let encrypted = decode_hex(
            "2c82dd9f8525e0f430e3e548817d4aa990e14c2732bc828aaf837e8a06a797845e1928fa4edd620fd6a966915e8a6f2b57236098f666156f34f86a8e2fbaeba3c7fb8572838464f0fb036f59da75db",
        );
        assert_eq!(decrypt(&sk, &encrypted).unwrap(), "hello world🌍".as_bytes());
    }

    #[cfg(all(not(feature = "xchacha20"), feature = "aes-short-nonce"))]
    #[test]
    pub fn test_known_encrypted_short_nonce() {
        let sk = decode_hex("558eee18659895fc5f2acaef8ca78856cbfd25a33934302a0994eedd43dda03e");
        let encrypted = decode_hex(
            "37762d915f19e2aba8a36695b7a9aefffe40837ba19b2e7bbbfa905fe31e50416bde970c71ffbc96c279235015f6a6c258e58c8161446aeee8bb15857a3681eb0afa1b2a19c7070ca5280b",
        );
        assert_eq!(decrypt(&sk, &encrypted).unwrap(), "hello world🌍".as_bytes());
    }

    #[cfg(feature = "xchacha20")]
    #[test]
    pub fn test_known_encrypted_xchacha20() {
        let sk = decode_hex("b39f66f08a6a56816d55a55bb61c5013be547f3018f363046be5433be3a112c3");
        let encrypted = decode_hex(
            "966a90cdd649b65b04ed1879c483ae001a1ec8dc03892c430adc95310d665af06ad3561d413a99ce8b1405a19c313330ec8a05f5f271eb770a55bcad345303b65c9558a1a739a345b7bfb778540318d0cbfe20d400ebfe",
        );
        assert_eq!(decrypt(&sk, &encrypted).unwrap(), "hello world🌍".as_bytes());
    }
}

#[cfg(test)]
mod random_tests {
    use super::generate_keypair;
    use crate::{decrypt, encrypt};

    const MSG: &str = "hello world🌍";
    const BIG_MSG_SIZE: usize = 2 * 1024 * 1024; // 2 MB
    const BIG_MSG: [u8; BIG_MSG_SIZE] = [1u8; BIG_MSG_SIZE];

    fn test_enc_dec(sk: &[u8], pk: &[u8]) {
        let msg = MSG.as_bytes();
        assert_eq!(msg.to_vec(), decrypt(sk, &encrypt(pk, msg).unwrap()).unwrap());
        let msg = &BIG_MSG;
        assert_eq!(msg.to_vec(), decrypt(sk, &encrypt(pk, msg).unwrap()).unwrap());
    }

    #[test]
    pub fn test_keypair() {
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();

        assert_ne!(sk1, sk2);
        assert_ne!(pk1, pk2);
    }

    #[test]
    pub fn test_random() {
        let (sk, pk) = generate_keypair();
        test_enc_dec(&sk, &pk);
    }
}

#[cfg(test)]
mod error_tests {
    use super::{Error, generate_keypair};
    use crate::consts::ZERO_SECRET;
    use crate::{decrypt, encrypt};

    #[cfg(not(feature = "std"))]
    use alloc::format;
    #[cfg(feature = "std")]
    use std::format;

    const MSG: &str = "hello world🌍";

    #[test]
    fn test_error_fmt() {
        assert_eq!(format!("{}", Error::InvalidMessage), "Invalid message");
        assert_eq!(format!("{}", Error::InvalidPublicKey), "Invalid public key");
    }

    #[test]
    pub fn rejects_invalid_key_lengths() {
        let invalid_keys: [&[u8]; 3] = [&[], &[0u8; 31], &[0u8; 33]];

        for key in invalid_keys {
            assert_eq!(encrypt(key, MSG.as_bytes()), Err(Error::InvalidPublicKey));
            assert_eq!(decrypt(key, &[]), Err(Error::InvalidMessage));
        }
    }

    #[test]
    pub fn attempts_to_decrypt_with_invalid_key() {
        assert_eq!(decrypt(&ZERO_SECRET, &[]), Err(Error::InvalidMessage));
    }

    #[test]
    pub fn attempts_to_decrypt_incorrect_message() {
        let (sk, pk) = generate_keypair();

        assert_eq!(decrypt(&sk, &[]), Err(Error::InvalidMessage));
        // a valid ephemeral key with nothing after it
        assert_eq!(decrypt(&sk, &pk), Err(Error::InvalidMessage));
    }

    #[test]
    pub fn attempts_to_decrypt_with_another_key() {
        let (_, pk1) = generate_keypair();
        let (sk2, _) = generate_keypair();

        let encrypted = encrypt(&pk1, MSG.as_bytes()).unwrap();
        assert_eq!(decrypt(&sk2, &encrypted), Err(Error::InvalidMessage));
    }
}

/// #180: a small-order public key makes the shared point the identity, so anyone can decrypt. Mixed-order keys are
/// refused too, as ecies/js#922 proposes for eciesjs
#[cfg(test)]
mod small_order_tests {
    use curve25519_dalek::{
        EdwardsPoint, constants::ED25519_BASEPOINT_POINT as G, edwards::CompressedEdwardsY, scalar::Scalar,
    };

    use super::{Error, PUBLIC_KEY_SIZE, PublicKey, decapsulate, encapsulate, generate_keypair};
    use crate::symmetric::{FEATURE_ALGORITHM, FEATURE_NONCE_LENGTH, hkdf_derive, sym_encrypt_into};
    use crate::utils::tests::decode_hex;
    use crate::{compat::Vec, decrypt, encrypt};

    const MSG: &[u8] = b"hello world";

    /// The 8 points of order dividing 8, as `ED25519_TORSION_SUBGROUP` in @noble/curves lists them. The first is the
    /// identity
    const SMALL_ORDER: [&str; 8] = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    ];

    /// Non-canonical encodings of small-order points that curve25519-dalek still decodes: the sign bit set where x is 0
    /// (the identity and the order-2 point), and y written as p or p + 1, with either sign bit
    const NON_CANONICAL_SMALL_ORDER: [&str; 6] = [
        "0100000000000000000000000000000000000000000000000000000000000080",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ];

    fn point(hex: &str) -> EdwardsPoint {
        let point = CompressedEdwardsY(decode_hex(hex).try_into().unwrap())
            .decompress()
            .unwrap();
        assert!(point.is_small_order(), "{hex} is not small order");
        point
    }

    /// The bytes of every small-order encoding curve25519-dalek decodes, canonical ones first
    fn small_order_encodings() -> Vec<PublicKey> {
        let canonical = SMALL_ORDER.map(|hex| point(hex).compress().to_bytes());
        let non_canonical = NON_CANONICAL_SMALL_ORDER.map(|hex| {
            let bytes: PublicKey = decode_hex(hex).try_into().unwrap();
            assert_ne!(point(hex).compress().to_bytes(), bytes, "{hex} is canonical");
            bytes
        });
        let encodings: Vec<PublicKey> = canonical.into_iter().chain(non_canonical).collect();
        for (i, encoding) in encodings.iter().enumerate() {
            assert!(!encodings[..i].contains(encoding), "{encoding:02x?} is listed twice");
        }
        encodings
    }

    /// An honest public key plus each small-order point other than the identity
    fn mixed_order_keys(pk: &PublicKey) -> [PublicKey; 7] {
        let honest = CompressedEdwardsY(*pk).decompress().unwrap();
        core::array::from_fn(|i| (honest + point(SMALL_ORDER[i + 1])).compress().to_bytes())
    }

    /// A payload as its author makes it: the ephemeral key, then the message encrypted with the key both sides derive
    fn forge(ephemeral: &PublicKey, shared_point: &[u8; PUBLIC_KEY_SIZE]) -> Vec<u8> {
        let mut payload = ephemeral.to_vec();
        let key = hkdf_derive(ephemeral, shared_point);
        sym_encrypt_into(&mut payload, &key, MSG, &[], FEATURE_ALGORITHM, FEATURE_NONCE_LENGTH).unwrap();
        payload
    }

    #[test]
    pub fn rejects_small_order_public_keys() {
        let (sk, _) = generate_keypair();
        for pk in small_order_encodings() {
            assert_eq!(encrypt(&pk, MSG), Err(Error::InvalidPublicKey));
            assert_eq!(encapsulate(&sk, &pk, false), Err(Error::InvalidPublicKey));
        }
    }

    #[test]
    pub fn rejects_mixed_order_public_keys() {
        let (sk, pk) = generate_keypair();
        assert!(encrypt(&pk, MSG).is_ok());
        for mixed in mixed_order_keys(&pk) {
            assert_eq!(encrypt(&mixed, MSG), Err(Error::InvalidPublicKey));
            assert_eq!(encapsulate(&sk, &mixed, false), Err(Error::InvalidPublicKey));
        }
    }

    #[test]
    pub fn rejects_small_order_ephemeral_keys() {
        // the shared point is the identity whatever the secret key, so these payloads used to decrypt under any key
        let identity = point(SMALL_ORDER[0]).compress().to_bytes();
        let (sk, _) = generate_keypair();
        for ephemeral in small_order_encodings() {
            assert_eq!(
                decrypt(&sk, &forge(&ephemeral, &identity)),
                Err(Error::InvalidPublicKey)
            );
            assert_eq!(decapsulate(&ephemeral, &sk, false), Err(Error::InvalidPublicKey));
        }
    }

    #[test]
    pub fn rejects_mixed_order_ephemeral_keys() {
        // [r]G + T: the clamped scalar is a multiple of 8, so the torsion part used to cancel and leave [r]pk
        let (sk, pk) = generate_keypair();
        let r = Scalar::from(0x0123_4567_89ab_cdef_u64);
        let shared_point = (CompressedEdwardsY(pk).decompress().unwrap() * r).compress().to_bytes();

        let honest = (G * r).compress().to_bytes();
        assert_eq!(decrypt(&sk, &forge(&honest, &shared_point)).unwrap(), MSG);

        for ephemeral in mixed_order_keys(&honest) {
            assert_eq!(
                decrypt(&sk, &forge(&ephemeral, &shared_point)),
                Err(Error::InvalidPublicKey)
            );
        }
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_small_order() {
        super::small_order_tests::rejects_small_order_public_keys();
        super::small_order_tests::rejects_mixed_order_public_keys();
        super::small_order_tests::rejects_small_order_ephemeral_keys();
        super::small_order_tests::rejects_mixed_order_ephemeral_keys();
    }

    #[wasm_bindgen_test]
    fn test_random() {
        super::random_tests::test_keypair();
        super::random_tests::test_random();
    }

    #[wasm_bindgen_test]
    fn test_known() {
        super::known_tests::test_known_shared_point();
        #[cfg(all(not(feature = "xchacha20"), not(feature = "aes-short-nonce")))]
        super::known_tests::test_known_encrypted();
        #[cfg(all(not(feature = "xchacha20"), feature = "aes-short-nonce"))]
        super::known_tests::test_known_encrypted_short_nonce();
        #[cfg(feature = "xchacha20")]
        super::known_tests::test_known_encrypted_xchacha20();
    }

    #[wasm_bindgen_test]
    fn test_error() {
        super::error_tests::rejects_invalid_key_lengths();
        super::error_tests::attempts_to_decrypt_with_invalid_key();
        super::error_tests::attempts_to_decrypt_incorrect_message();
        super::error_tests::attempts_to_decrypt_with_another_key();
    }
}
