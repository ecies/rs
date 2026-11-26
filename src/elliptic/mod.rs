use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::Error;
use crate::consts::SharedSecret;

/// secp256k1 keys and key exchange
#[cfg(feature = "secp256k1")]
pub mod secp256k1;

/// X25519 keys and key exchange
#[cfg(feature = "curve25519")]
pub mod x25519;

/// Ed25519 keys and key exchange
#[cfg(feature = "curve25519")]
pub mod ed25519;

/// What `encrypt_with_config` and `decrypt_with_config` need from a curve, which `Config::elliptic_curve` picks
pub(crate) trait Curve {
    type SecretKey;
    type PublicKey;

    fn generate_keypair() -> (Self::SecretKey, Self::PublicKey);
    fn parse_sk(sk: &[u8]) -> Result<Self::SecretKey, Error>;
    fn parse_pk(pk: &[u8]) -> Result<Self::PublicKey, Error>;
    fn pk_to_vec(pk: &Self::PublicKey, compressed: bool) -> Vec<u8>;
    fn encapsulate_with_sender(
        sk: &Self::SecretKey,
        sender_pk: &Self::PublicKey,
        peer_pk: &Self::PublicKey,
        compressed: bool,
    ) -> Result<Zeroizing<SharedSecret>, Error>;
    fn decapsulate(
        pk: &Self::PublicKey,
        peer_sk: &Self::SecretKey,
        compressed: bool,
    ) -> Result<Zeroizing<SharedSecret>, Error>;
}

/// Implements [`Curve`] for `$curve` with the functions of the module `$module`
macro_rules! impl_curve {
    ($curve:ident, $module:ident) => {
        pub(crate) struct $curve;

        impl Curve for $curve {
            type SecretKey = $module::SecretKey;
            type PublicKey = $module::PublicKey;

            fn generate_keypair() -> (Self::SecretKey, Self::PublicKey) {
                $module::generate_keypair()
            }

            fn parse_sk(sk: &[u8]) -> Result<Self::SecretKey, Error> {
                $module::parse_sk(sk)
            }

            fn parse_pk(pk: &[u8]) -> Result<Self::PublicKey, Error> {
                $module::parse_pk(pk)
            }

            fn pk_to_vec(pk: &Self::PublicKey, compressed: bool) -> Vec<u8> {
                $module::pk_to_vec(pk, compressed)
            }

            fn encapsulate_with_sender(
                sk: &Self::SecretKey,
                sender_pk: &Self::PublicKey,
                peer_pk: &Self::PublicKey,
                compressed: bool,
            ) -> Result<Zeroizing<SharedSecret>, Error> {
                $module::encapsulate_with_sender(sk, sender_pk, peer_pk, compressed)
            }

            fn decapsulate(
                pk: &Self::PublicKey,
                peer_sk: &Self::SecretKey,
                compressed: bool,
            ) -> Result<Zeroizing<SharedSecret>, Error> {
                $module::decapsulate(pk, peer_sk, compressed)
            }
        }
    };
}

#[cfg(feature = "secp256k1")]
impl_curve!(Secp256k1, secp256k1);
#[cfg(feature = "curve25519")]
impl_curve!(X25519, x25519);
#[cfg(feature = "curve25519")]
impl_curve!(Ed25519, ed25519);

#[cfg(test)]
mod tests {
    use super::*;

    /// Both sides of an exchange derive the same key, through the trait as `encrypt_with_config` calls it
    fn exchanges_keys<C: Curve>() {
        let (sk1, pk1) = C::generate_keypair();
        let (sk2, pk2) = C::generate_keypair();
        for compressed in [false, true] {
            assert_eq!(
                C::encapsulate_with_sender(&sk2, &pk2, &pk1, compressed).unwrap(),
                C::decapsulate(&pk2, &sk1, compressed).unwrap()
            );
        }
    }

    #[test]
    fn test_key_exchange() {
        #[cfg(feature = "secp256k1")]
        exchanges_keys::<Secp256k1>();
        #[cfg(feature = "curve25519")]
        {
            exchanges_keys::<X25519>();
            exchanges_keys::<Ed25519>();
        }
    }
}
