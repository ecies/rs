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
    derive_key(&pk, &shared_point)
}

/// Calculate a shared AES key of our public key and peer's secret key by hkdf
pub fn decapsulate(pk: &PublicKey, peer_sk: &SecretKey) -> Result<SharedSecret, SecpError> {
    let mut shared_point = *pk;
    shared_point.tweak_mul_assign(peer_sk)?;

    derive_key(pk, &shared_point)
}

// private below
fn derive_key(pk: &PublicKey, shared_point: &PublicKey) -> Result<SharedSecret, SecpError> {
    let key_size = get_ephemeral_key_size();
    let mut master = Vec::with_capacity(key_size * 2);

    if is_hkdf_key_compressed() {
        master.extend(pk.serialize_compressed().iter());
        master.extend(shared_point.serialize_compressed().iter());
    } else {
        master.extend(pk.serialize().iter());
        master.extend(shared_point.serialize().iter());
    }
    hkdf_sha256(master.as_slice())
}

fn hkdf_sha256(master: &[u8]) -> Result<SharedSecret, SecpError> {
    let h = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; 32];
    h.expand(&EMPTY_BYTES, &mut out)
        .map_err(|_| SecpError::InvalidInputLength)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use libsecp256k1::Error;

    use super::*;
    use crate::symmetric::tests::decode_hex;

    #[test]
    fn test_generate_keypair() {
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();
        assert_ne!(sk1, sk2);
        assert_ne!(pk1, pk2);
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
    fn test_known_hkdf_vector() {
        let text = b"secret";

        assert_eq!(
            hkdf_sha256(text).unwrap().to_vec(),
            decode_hex("2f34e5ff91ec85d53ca9b543683174d0cf550b60d5f52b24c97b386cfcf6cbbf")
        );
    }

    #[test]
    fn test_known_shared_secret() {
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
            encapsulate(&sk2, &pk3).unwrap().to_vec(),
            decode_hex("6f982d63e8590c9d9b5b4c1959ff80315d772edd8f60287c9361d548d5200f82")
        );
    }
}
