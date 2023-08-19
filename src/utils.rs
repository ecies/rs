use hkdf::Hkdf;
use libsecp256k1::{Error as SecpError, PublicKey, SecretKey};
use rand_core::OsRng;
use sha2::Sha256;

use crate::compat::Vec;
use crate::config::{get_ephemeral_key_size, is_hkdf_key_compressed};
use crate::consts::EMPTY_BYTES;

/// Shared secret derived from key exchange by hkdf
pub type SharedSecret = [u8; 32];

/// Generate a `(SecretKey, PublicKey)` pair
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let sk = SecretKey::random(&mut OsRng);
    (sk, PublicKey::from_secret_key(&sk))
}

/// Calculate a shared AES key of our secret key and peer's public key by hkdf
pub fn encapsulate(sk: &SecretKey, peer_pk: &PublicKey) -> Result<SharedSecret, SecpError> {
    let mut shared_point = *peer_pk;
    shared_point.tweak_mul_assign(sk)?;

    let pk = PublicKey::from_secret_key(sk);
    Ok(derive_key(&pk, &shared_point, is_hkdf_key_compressed()))
}

/// Calculate a shared AES key of our public key and peer's secret key by hkdf
pub fn decapsulate(pk: &PublicKey, peer_sk: &SecretKey) -> Result<SharedSecret, SecpError> {
    let mut shared_point = *pk;
    shared_point.tweak_mul_assign(peer_sk)?;

    Ok(derive_key(pk, &shared_point, is_hkdf_key_compressed()))
}

// private below
fn derive_key(pk: &PublicKey, shared_point: &PublicKey, is_compressed: bool) -> SharedSecret {
    let key_size = get_ephemeral_key_size();
    let mut master = Vec::with_capacity(key_size * 2);

    if is_compressed {
        master.extend(&pk.serialize_compressed());
        master.extend(&shared_point.serialize_compressed());
    } else {
        master.extend(&pk.serialize());
        master.extend(&shared_point.serialize());
    }
    hkdf_sha256(&master)
}

fn hkdf_sha256(master: &[u8]) -> SharedSecret {
    let h = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; 32];
    // never fails because 32 < 255 * chunk_len, which is 32 on SHA256
    h.expand(&EMPTY_BYTES, &mut out).unwrap();
    out
}

#[cfg(test)]
pub mod tests {
    use hex::decode;

    use super::*;

    /// Convert hex string to u8 vector
    pub fn decode_hex(hex: &str) -> Vec<u8> {
        let hex = if hex.starts_with("0x") || hex.starts_with("0X") {
            &hex[2..]
        } else {
            hex
        };
        decode(hex).unwrap()
    }

    #[test]
    fn test_key_exchange() {
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();
        assert_ne!(sk1, sk2);
        assert_ne!(pk1, pk2);
        assert_eq!(encapsulate(&sk2, &pk1).unwrap(), decapsulate(&pk2, &sk1).unwrap());
    }

    #[test]
    fn test_secret_validity() {
        // 0 < private key < group order is valid
        let mut zero = [0u8; 32];
        let group_order = decode_hex("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let invalid_sks = [zero.to_vec(), group_order];

        for sk in invalid_sks.iter() {
            assert_eq!(SecretKey::parse_slice(sk).err().unwrap(), SecpError::InvalidSecretKey);
        }

        zero[31] = 1;

        let one = zero;
        let group_order_minus_1 = decode_hex("0Xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
        let valid_sks = [one.to_vec(), group_order_minus_1];
        for sk in valid_sks.iter() {
            SecretKey::parse_slice(sk).unwrap();
        }
    }

    #[test]
    fn test_known_hkdf_vector() {
        assert_eq!(
            hkdf_sha256(b"secret").to_vec(),
            decode_hex("2f34e5ff91ec85d53ca9b543683174d0cf550b60d5f52b24c97b386cfcf6cbbf")
        );
    }

    /// Generate two secret keys with values 2 and 3
    pub fn get_sk2_sk3() -> (SecretKey, SecretKey) {
        let mut two = [0u8; 32];
        let mut three = [0u8; 32];
        two[31] = 2u8;
        three[31] = 3u8;

        let sk2 = SecretKey::parse_slice(&two).unwrap();
        let sk3 = SecretKey::parse_slice(&three).unwrap();
        (sk2, sk3)
    }

    #[test]
    pub(super) fn test_known_shared_secret() {
        let (sk2, sk3) = get_sk2_sk3();
        let pk3 = PublicKey::from_secret_key(&sk3);

        assert_eq!(
            encapsulate(&sk2, &pk3).unwrap().to_vec(),
            decode_hex("6f982d63e8590c9d9b5b4c1959ff80315d772edd8f60287c9361d548d5200f82")
        );
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_wasm() {
        super::tests::test_known_shared_secret();
    }
}
