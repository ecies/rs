use alloc::vec::Vec;

use crypto_common::Generate;
use curve25519_dalek::EdwardsPoint;
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, edwards::CompressedEdwardsY};
use ed25519_dalek::SigningKey;
use getrandom::SysRng;
use rand_core::UnwrapErr;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Error;
use crate::consts::{CURVE25519_PUBLIC_KEY_SIZE as PUBLIC_KEY_SIZE, SharedSecret};
use crate::symmetric::hkdf_derive;

/// An Ed25519 secret key: the 32-byte seed RFC 8032 hashes into the scalar
#[derive(Clone)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for SecretKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SecretKey").finish_non_exhaustive()
    }
}

// in constant time, so the time taken doesn't reveal how many leading bytes match
impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }
}

impl Eq for SecretKey {}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // through `zeroize`, whose volatile writes the compiler keeps. A plain `self.0 = [0; 32]` is a dead store it
        // may remove, though tests/curve_modules.rs can't tell, since it reads the bytes back
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

pub type PublicKey = [u8; PUBLIC_KEY_SIZE];

/// Generate a `(SecretKey, PublicKey)` pair
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let sk = SecretKey(Generate::generate_from_rng(&mut UnwrapErr(SysRng)));
    let pk = to_public_key(&sk).to_bytes();
    (sk, pk)
}

/// Calculate a shared symmetric key of our secret key and peer's public key by hkdf. The key clears its bytes on drop
pub fn encapsulate(sk: &SecretKey, peer_pk: &PublicKey, compressed: bool) -> Result<Zeroizing<SharedSecret>, Error> {
    encapsulate_with_sender(sk, &to_public_key(sk).to_bytes(), peer_pk, compressed)
}

/// Same as [`encapsulate`], but with the sender's public key provided to skip its derivation
pub(crate) fn encapsulate_with_sender(
    sk: &SecretKey,
    sender_pk: &PublicKey,
    peer_pk: &PublicKey,
    _compressed: bool,
) -> Result<Zeroizing<SharedSecret>, Error> {
    let shared_point = multiply(sk, peer_pk)?;
    Ok(hkdf_derive(sender_pk, shared_point.compress().as_bytes()))
}

/// Calculate a shared symmetric key of our public key and peer's secret key by hkdf. The key clears its bytes on drop
pub fn decapsulate(pk: &PublicKey, peer_sk: &SecretKey, _compressed: bool) -> Result<Zeroizing<SharedSecret>, Error> {
    let shared_point = multiply(peer_sk, pk)?;
    Ok(hkdf_derive(pk, shared_point.compress().as_bytes()))
}

/// Parse secret key bytes
pub(crate) fn parse_sk(sk: &[u8]) -> Result<SecretKey, Error> {
    <[u8; 32]>::try_from(sk)
        .map(SecretKey)
        .map_err(|_| Error::InvalidSecretKey)
}

/// Parse public key bytes
pub(crate) fn parse_pk(pk: &[u8]) -> Result<PublicKey, Error> {
    pk.try_into().map_err(|_| Error::InvalidPublicKey)
}

/// Public key to bytes
pub(crate) fn pk_to_vec(pk: &PublicKey, _compressed: bool) -> Vec<u8> {
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

fn to_scalar(sk: &SecretKey) -> [u8; 32] {
    SigningKey::from_bytes(&sk.0).to_scalar_bytes()
}

fn to_public_key(sk: &SecretKey) -> CompressedEdwardsY {
    let scalar = to_scalar(sk);
    G.mul_clamped(scalar).compress()
}

/// `encrypt` and `decrypt` on Ed25519, with the other settings at their defaults
#[cfg(test)]
mod on_curve {
    use alloc::vec::Vec;

    use crate::{Config, EllipticCurve, Error, NonceLength, SymmetricAlgorithm};

    // every field, so the known answers don't depend on `Config::new`
    pub(super) const CONFIG: Config = Config {
        elliptic_curve: EllipticCurve::Ed25519,
        is_ephemeral_key_compressed: false,
        is_hkdf_key_compressed: false,
        symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
        symmetric_nonce_length: NonceLength::Sixteen,
    };

    pub(super) fn encrypt(pk: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
        crate::encrypt_with_config(pk, msg, &[], &CONFIG)
    }

    pub(super) fn decrypt(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
        crate::decrypt_with_config(sk, msg, &[], &CONFIG)
    }
}

#[cfg(test)]
mod known_tests {
    use super::on_curve::CONFIG;
    use super::{multiply, parse_pk, parse_sk};

    use crate::utils::tests::decode_hex;
    use crate::{Config, NonceLength, SymmetricAlgorithm, decrypt_with_config};

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

    /// One payload per cipher, made by the 0.2 builds with each feature
    #[test]
    pub fn test_known_encrypted() {
        let payloads = [
            (
                CONFIG,
                "8be70d30035b24e13377678a3f612cf72333327ff2865def5544ea877ff50c82",
                "2c82dd9f8525e0f430e3e548817d4aa990e14c2732bc828aaf837e8a06a797845e1928fa4edd620fd6a966915e8a6f2b57236098f666156f34f86a8e2fbaeba3c7fb8572838464f0fb036f59da75db",
            ),
            (
                Config {
                    symmetric_nonce_length: NonceLength::Twelve,
                    ..CONFIG
                },
                "558eee18659895fc5f2acaef8ca78856cbfd25a33934302a0994eedd43dda03e",
                "37762d915f19e2aba8a36695b7a9aefffe40837ba19b2e7bbbfa905fe31e50416bde970c71ffbc96c279235015f6a6c258e58c8161446aeee8bb15857a3681eb0afa1b2a19c7070ca5280b",
            ),
            (
                Config {
                    symmetric_algorithm: SymmetricAlgorithm::XChaCha20,
                    ..CONFIG
                },
                "b39f66f08a6a56816d55a55bb61c5013be547f3018f363046be5433be3a112c3",
                "966a90cdd649b65b04ed1879c483ae001a1ec8dc03892c430adc95310d665af06ad3561d413a99ce8b1405a19c313330ec8a05f5f271eb770a55bcad345303b65c9558a1a739a345b7bfb778540318d0cbfe20d400ebfe",
            ),
        ];

        for (config, sk, encrypted) in payloads {
            let decrypted = decrypt_with_config(&decode_hex(sk), &decode_hex(encrypted), &[], &config);
            assert_eq!(decrypted.as_deref(), Ok("hello world🌍".as_bytes()), "{config:?}");
        }
    }
}

#[cfg(test)]
mod random_tests {
    use super::generate_keypair;
    use super::on_curve::{decrypt, encrypt};

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
        test_enc_dec(sk.as_bytes(), &pk);
    }
}

#[cfg(test)]
mod error_tests {
    use super::generate_keypair;
    use super::on_curve::{decrypt, encrypt};
    use crate::Error;
    use crate::consts::ZERO_SECRET;

    const MSG: &str = "hello world🌍";

    #[test]
    pub fn rejects_invalid_key_lengths() {
        let invalid_keys: [&[u8]; 3] = [&[], &[0u8; 31], &[0u8; 33]];

        for key in invalid_keys {
            assert_eq!(encrypt(key, MSG.as_bytes()), Err(Error::InvalidPublicKey));
            assert_eq!(decrypt(key, &[]), Err(Error::InvalidSecretKey));
        }
    }

    #[test]
    pub fn attempts_to_decrypt_with_invalid_key() {
        assert_eq!(decrypt(&ZERO_SECRET, &[]), Err(Error::InvalidMessage));
    }

    #[test]
    pub fn attempts_to_decrypt_incorrect_message() {
        let (sk, pk) = generate_keypair();

        assert_eq!(decrypt(sk.as_bytes(), &[]), Err(Error::InvalidMessage));
        // a valid ephemeral key with nothing after it
        assert_eq!(decrypt(sk.as_bytes(), &pk), Err(Error::InvalidMessage));
    }

    #[test]
    pub fn attempts_to_decrypt_with_another_key() {
        let (_, pk1) = generate_keypair();
        let (sk2, _) = generate_keypair();

        let encrypted = encrypt(&pk1, MSG.as_bytes()).unwrap();
        assert_eq!(decrypt(sk2.as_bytes(), &encrypted), Err(Error::InvalidMessage));
    }
}

/// Secret keys clear their bytes on `zeroize()`, and are marked `ZeroizeOnDrop` as the x25519 keys are. The drop
/// itself needs `unsafe` to observe, so `tests/curve_modules.rs` checks it
#[cfg(test)]
mod zeroize_tests {
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use super::SecretKey;

    #[test]
    pub fn zeroizes_secret_keys() {
        let mut sk = SecretKey::from([0x42; 32]);
        sk.zeroize();
        assert_eq!(sk.to_bytes(), [0; 32]);
    }

    #[test]
    pub fn marks_secret_keys_zeroize_on_drop() {
        fn zeroize_on_drop<T: ZeroizeOnDrop>() {}
        zeroize_on_drop::<SecretKey>();
        zeroize_on_drop::<super::super::x25519::SecretKey>();
    }
}

/// #180: a small-order public key makes the shared point the identity, so anyone can decrypt. Mixed-order keys are
/// refused too, as ecies/js#922 proposes for eciesjs
#[cfg(test)]
mod small_order_tests {
    use alloc::vec::Vec;

    use curve25519_dalek::{
        EdwardsPoint, constants::ED25519_BASEPOINT_POINT as G, edwards::CompressedEdwardsY, scalar::Scalar,
    };

    use super::on_curve::{CONFIG, decrypt, encrypt};
    use super::{PUBLIC_KEY_SIZE, PublicKey, decapsulate, encapsulate, generate_keypair};
    use crate::Error;
    use crate::symmetric::{hkdf_derive, sym_encrypt_into};
    use crate::utils::tests::decode_hex;

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
        sym_encrypt_into(
            &mut payload,
            key.as_slice(),
            MSG,
            &[],
            CONFIG.symmetric_algorithm,
            CONFIG.symmetric_nonce_length,
        )
        .unwrap();
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
                decrypt(sk.as_bytes(), &forge(&ephemeral, &identity)),
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
        assert_eq!(decrypt(sk.as_bytes(), &forge(&honest, &shared_point)).unwrap(), MSG);

        for ephemeral in mixed_order_keys(&honest) {
            assert_eq!(
                decrypt(sk.as_bytes(), &forge(&ephemeral, &shared_point)),
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
        super::known_tests::test_known_encrypted();
    }

    #[wasm_bindgen_test]
    fn test_error() {
        super::error_tests::rejects_invalid_key_lengths();
        super::error_tests::attempts_to_decrypt_with_invalid_key();
        super::error_tests::attempts_to_decrypt_incorrect_message();
        super::error_tests::attempts_to_decrypt_with_another_key();
    }

    #[wasm_bindgen_test]
    fn test_zeroize() {
        super::zeroize_tests::zeroizes_secret_keys();
        super::zeroize_tests::marks_secret_keys_zeroize_on_drop();
    }
}
