use hkdf::Hkdf;
use sha2::Sha256;

use crate::compat::Vec;
use crate::consts::{SharedSecret, EMPTY_BYTES};

#[cfg(not(feature = "x25519"))]
mod secp256k1;
#[cfg(not(feature = "x25519"))]
pub use secp256k1::{decapsulate, encapsulate, generate_keypair};
#[cfg(not(feature = "x25519"))]
pub(crate) use secp256k1::{parse_pk, parse_sk, pk_to_vec, Error};

#[cfg(feature = "x25519")]
mod x25519;
#[cfg(feature = "x25519")]
pub use x25519::{decapsulate, encapsulate, generate_keypair};
#[cfg(feature = "x25519")]
pub(crate) use x25519::{parse_pk, parse_sk, pk_to_vec, Error};

fn hkdf_derive(sender_point: &[u8], shared_point: &[u8]) -> SharedSecret {
    let size = sender_point.len() + shared_point.len();
    let mut master = Vec::with_capacity(size);
    master.extend(sender_point);
    master.extend(shared_point);
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
mod tests {
    use super::hkdf_sha256;

    use crate::utils::tests::decode_hex;

    #[test]
    fn test_known_hkdf_vector() {
        assert_eq!(
            hkdf_sha256(b"secret").to_vec(),
            decode_hex("2f34e5ff91ec85d53ca9b543683174d0cf550b60d5f52b24c97b386cfcf6cbbf")
        );
    }
}
