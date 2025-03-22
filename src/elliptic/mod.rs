#[cfg(not(feature = "x25519"))]
mod secp256k1;
#[cfg(not(feature = "x25519"))]
pub use secp256k1::{decapsulate, encapsulate, generate_keypair, PublicKey, SecretKey};
#[cfg(not(feature = "x25519"))]
pub(crate) use secp256k1::{parse_pk, parse_sk, pk_to_vec, Error};

#[cfg(feature = "x25519")]
mod x25519;
#[cfg(feature = "x25519")]
pub use x25519::{decapsulate, encapsulate, generate_keypair, PublicKey, SecretKey};
#[cfg(feature = "x25519")]
pub(crate) use x25519::{parse_pk, parse_sk, pk_to_vec, Error};

#[cfg(test)]
mod tests {
    use super::{decapsulate, encapsulate, generate_keypair};

    #[test]
    fn test_key_exchange() {
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();
        assert_eq!(encapsulate(&sk2, &pk1).unwrap(), decapsulate(&pk2, &sk1).unwrap());
    }
}
