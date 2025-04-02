use rand_core::OsRng;

pub use x25519_dalek::{PublicKey, StaticSecret as SecretKey};

use crate::compat::Vec;
use crate::consts::{SharedSecret, ZERO_SECRET};
use crate::symmetric::hkdf_derive;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    InvalidMessage,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidMessage => write!(f, "Invalid message"),
        }
    }
}

/// Generate a `(SecretKey, PublicKey)` pair
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let sk = SecretKey::random_from_rng(OsRng);
    let pk = PublicKey::from(&sk);
    (sk, pk)
}

/// Calculate a shared symmetric key of our secret key and peer's public key by hkdf
pub fn encapsulate(sk: &SecretKey, peer_pk: &PublicKey) -> Result<SharedSecret, Error> {
    let shared_point = sk.diffie_hellman(peer_pk);
    let sender_point = PublicKey::from(sk);
    Ok(hkdf_derive(sender_point.as_bytes(), shared_point.as_bytes()))
}

/// Calculate a shared symmetric key of our public key and peer's secret key by hkdf
pub fn decapsulate(pk: &PublicKey, peer_sk: &SecretKey) -> Result<SharedSecret, Error> {
    let shared_point = peer_sk.diffie_hellman(pk);
    Ok(hkdf_derive(pk.as_bytes(), shared_point.as_bytes()))
}

/// Parse secret key bytes
pub fn parse_sk(sk: &[u8]) -> Result<SecretKey, Error> {
    let mut data = ZERO_SECRET;
    data.copy_from_slice(sk);
    Ok(SecretKey::from(data))
}

/// Parse public key bytes
pub fn parse_pk(pk: &[u8]) -> Result<PublicKey, Error> {
    let mut data = ZERO_SECRET;
    data.copy_from_slice(pk);
    Ok(PublicKey::from(data))
}

/// Public key to bytes
pub fn pk_to_vec(pk: &PublicKey, _compressed: bool) -> Vec<u8> {
    pk.as_bytes().to_vec()
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

        assert_ne!(sk1.to_bytes(), sk2.to_bytes());
        assert_ne!(pk1.to_bytes(), pk2.to_bytes());
    }

    #[test]
    pub fn test_random() {
        let (sk, pk) = generate_keypair();
        let (sk, pk) = (sk.as_bytes(), pk.as_bytes());
        test_enc_dec(sk, pk);
    }
}

#[cfg(test)]
mod known_tests {
    use super::{parse_pk, parse_sk};

    use crate::decrypt;
    use crate::utils::tests::decode_hex;

    fn test_known(sk: &str, pk: &str, shared: &str) {
        let sk = parse_sk(&decode_hex(sk)).unwrap();
        let pk = parse_pk(&decode_hex(pk)).unwrap();
        let shared = decode_hex(shared);
        assert_eq!(sk.diffie_hellman(&pk).as_bytes(), shared.as_slice());
    }

    #[test]
    pub fn test_known_shared_point() {
        // https://datatracker.ietf.org/doc/html/rfc7748.html#section-6.1
        test_known(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
        )
    }

    #[cfg(all(not(feature = "xchacha20"), not(feature = "aes-short-nonce")))]
    #[test]
    pub fn test_known_encrypted() {
        let sk = decode_hex("9434b8fc5036bf967b8483a1bf7378f094d90e01393e4e880db0080022ce6330");
        let encrypted = decode_hex("02c351532928d20b9be0c354e029fd387e032d5318d71ca0ea361b8c62bae86794f6208f17b01affe66ab9edc728a25fac317b41dee123c3aee8684e9c771cfbc2c94c0fe0945ea7cad55b3eb11712");
        assert_eq!(decrypt(&sk, &encrypted).unwrap(), "hello world🌍".as_bytes());
    }

    #[cfg(all(not(feature = "xchacha20"), feature = "aes-short-nonce"))]
    #[test]
    pub fn test_known_encrypted_short_nonce() {
        let sk = decode_hex("abba7856619f7923038f03e7365bb166334075cc6b2d57a5c801776a8b506a52");
        let encrypted = decode_hex("0a16e5b8df916e845aca761353a4776f61785601768e21ca2b359c893d8a304b3cda271597715650d17f43b37379cd587d5466579e3a59da051b5ed49739a91c996cb34c65c8b7ae68fdf3");
        assert_eq!(decrypt(&sk, &encrypted).unwrap(), "hello world🌍".as_bytes());
    }

    #[cfg(feature = "xchacha20")]
    #[test]
    pub fn test_known_encrypted_xchacha20() {
        let sk = decode_hex("6e180c5ae2528fd4799111629b397b2faa48d8074f37cc686aa4139c74103049");
        let encrypted = decode_hex("6093c37db0385e92860f1213a6e3c75f82b529fad9ddcfdfbcf997dcdf5d8166e275a5ff509362bb50fbbe4f9ef1617ae10c6a7e93f1ef7e5bed7da681278126cd8114f41843d7797007509565b4aca0a3dd473f48265b");
        assert_eq!(decrypt(&sk, &encrypted).unwrap(), "hello world🌍".as_bytes());
    }
}

#[cfg(test)]
mod error_tests {
    use super::{generate_keypair, Error};
    use crate::{consts::ZERO_SECRET, decrypt, encrypt};

    #[cfg(not(feature = "std"))]
    use alloc::format;
    #[cfg(feature = "std")]
    use std::format;

    const MSG: &str = "hello world🌍";

    #[test]
    fn test_error_fmt() {
        assert_eq!(format!("{}", Error::InvalidMessage), "Invalid message");
    }

    #[test]
    pub fn attempts_to_decrypt_with_invalid_key() {
        assert_eq!(decrypt(&ZERO_SECRET, &[]), Err(Error::InvalidMessage));
    }

    #[test]
    pub fn attempts_to_decrypt_incorrect_message() {
        let (sk, _) = generate_keypair();

        assert_eq!(decrypt(sk.as_bytes(), &[]), Err(Error::InvalidMessage));
        assert_eq!(decrypt(sk.as_bytes(), &ZERO_SECRET), Err(Error::InvalidMessage));
    }

    #[test]
    pub fn attempts_to_decrypt_with_another_key() {
        let (_, pk1) = generate_keypair();
        let (sk2, _) = generate_keypair();

        let encrypted = encrypt(pk1.as_bytes(), MSG.as_bytes()).unwrap();
        assert_eq!(decrypt(sk2.as_bytes(), &encrypted), Err(Error::InvalidMessage));
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use wasm_bindgen_test::*;

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
        super::error_tests::attempts_to_decrypt_with_invalid_key();
        super::error_tests::attempts_to_decrypt_incorrect_message();
        super::error_tests::attempts_to_decrypt_with_another_key();
    }
}
