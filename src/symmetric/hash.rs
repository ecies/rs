use alloc::vec::Vec;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::consts::{SharedSecret, ZERO_SECRET};

pub fn hkdf_derive(part1: &[u8], part2: &[u8]) -> Zeroizing<SharedSecret> {
    let size = part1.len() + part2.len();
    let mut master = Vec::with_capacity(size);
    master.extend(part1);
    master.extend(part2);
    hkdf_sha256(&master)
}

fn hkdf_sha256(master: &[u8]) -> Zeroizing<SharedSecret> {
    let h = Hkdf::<Sha256>::new(None, master);
    // expanded into `Zeroizing` directly, though hkdf leaves its own copy of the key, and its HMAC state, unwiped
    let mut out = Zeroizing::new(ZERO_SECRET);
    // never fails because 32 < 255 * chunk_len, which is 32 on SHA256
    h.expand(&[], out.as_mut_slice()).unwrap();
    out
}

#[cfg(test)]
mod tests {
    use super::hkdf_sha256;

    use crate::utils::tests::decode_hex;

    #[test]
    fn test_known_vector() {
        assert_eq!(
            hkdf_sha256(b"secret").to_vec(),
            decode_hex("2f34e5ff91ec85d53ca9b543683174d0cf550b60d5f52b24c97b386cfcf6cbbf")
        );
    }
}
