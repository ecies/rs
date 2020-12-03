use hex::decode;
use hkdf::Hkdf;
use rand::thread_rng;
use secp256k1::{util::FULL_PUBLIC_KEY_SIZE, PublicKey, SecretKey};
use sha2::Sha256;

use crate::consts::EMPTY_BYTES;
use crate::types::AesKey;

#[cfg(feature = "pure")]
pub use crate::pure_aes::{aes_decrypt, aes_encrypt};

#[cfg(feature = "openssl")]
pub use crate::openssl_aes::{aes_decrypt, aes_encrypt};

/// Generate a `(SecretKey, PublicKey)` pair
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let sk = SecretKey::random(&mut thread_rng());
    (sk.clone(), PublicKey::from_secret_key(&sk))
}

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

/// Calculate a shared AES key of our secret key and peer's public key by hkdf
pub fn encapsulate(sk: &SecretKey, peer_pk: &PublicKey) -> AesKey {
    let mut shared_point = peer_pk.clone();
    shared_point.tweak_mul_assign(&sk).unwrap();

    let mut master = Vec::with_capacity(FULL_PUBLIC_KEY_SIZE * 2);
    master.extend(PublicKey::from_secret_key(&sk).serialize().iter());
    master.extend(shared_point.serialize().iter());

    hkdf_sha256(master.as_slice())
}

/// Calculate a shared AES key of our public key and peer's secret key by hkdf
pub fn decapsulate(pk: &PublicKey, peer_sk: &SecretKey) -> AesKey {
    let mut shared_point = pk.clone();
    shared_point.tweak_mul_assign(&peer_sk).unwrap();

    let mut master = Vec::with_capacity(FULL_PUBLIC_KEY_SIZE * 2);
    master.extend(pk.serialize().iter());
    master.extend(shared_point.serialize().iter());

    hkdf_sha256(master.as_slice())
}

// private below
fn hkdf_sha256(master: &[u8]) -> AesKey {
    let h = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; 32];
    h.expand(&EMPTY_BYTES, &mut out).unwrap();
    out
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};
    use secp256k1::Error;

    use super::*;
    use crate::consts::{AES_IV_LENGTH, EMPTY_BYTES};

    #[test]
    fn test_remove_0x_decode_hex() {
        assert_eq!(remove0x("0x0011"), "0011");
        assert_eq!(remove0x("0X0011"), "0011");
        assert_eq!(remove0x("0011"), "0011");
        assert_eq!(decode_hex("0x0011"), [0u8, 17u8]);
    }

    #[test]
    fn test_generate_keypair() {
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();
        assert_ne!(sk1, sk2);
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn test_attempt_to_decrypt_invalid_message() {
        assert!(aes_decrypt(&[], &[]).is_none());

        assert!(aes_decrypt(&[], &[0; AES_IV_LENGTH]).is_none());
    }

    #[test]
    fn test_aes_random_key() {
        let text = b"this is a text";
        let mut key = [0u8; 32];
        thread_rng().fill(&mut key);

        assert_eq!(
            text,
            aes_decrypt(&key, aes_encrypt(&key, text).unwrap().as_slice())
                .unwrap()
                .as_slice()
        );

        let utf8_text = "😀😀😀😀".as_bytes();
        assert_eq!(
            utf8_text,
            aes_decrypt(&key, aes_encrypt(&key, utf8_text).unwrap().as_slice())
                .unwrap()
                .as_slice()
        );
    }

    #[test]
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

        assert_eq!(text, aes_decrypt(&key, &cipher_text).unwrap().as_slice());
    }

    #[test]
    fn test_valid_secret() {
        // 0 < private key < group order int is valid
        let zero = [0u8; 32];
        assert_eq!(SecretKey::parse_slice(&zero).err().unwrap(), Error::InvalidSecretKey);

        let group_order_minus_1 = decode_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
        SecretKey::parse_slice(&group_order_minus_1).unwrap();

        let group_order = decode_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        assert_eq!(
            SecretKey::parse_slice(&group_order).err().unwrap(),
            Error::InvalidSecretKey
        );
    }

    #[test]
    fn test_hkdf() {
        let text = b"secret";

        let h = Hkdf::<Sha256>::new(None, text);
        let mut out = [0u8; 32];
        let r = h.expand(&EMPTY_BYTES, &mut out);

        assert!(r.is_ok());
        assert_eq!(
            out.to_vec(),
            decode_hex("2f34e5ff91ec85d53ca9b543683174d0cf550b60d5f52b24c97b386cfcf6cbbf")
        );

        let mut two = [0u8; 32];
        let mut three = [0u8; 32];
        two[31] = 2u8;
        three[31] = 3u8;

        let sk2 = SecretKey::parse_slice(&two).unwrap();
        let pk2 = PublicKey::from_secret_key(&sk2);
        let sk3 = SecretKey::parse_slice(&three).unwrap();
        let pk3 = PublicKey::from_secret_key(&sk3);

        assert_eq!(encapsulate(&sk2, &pk3), decapsulate(&pk2, &sk3));
        assert_eq!(
            encapsulate(&sk2, &pk3).to_vec(),
            decode_hex("6f982d63e8590c9d9b5b4c1959ff80315d772edd8f60287c9361d548d5200f82")
        );
    }
}
