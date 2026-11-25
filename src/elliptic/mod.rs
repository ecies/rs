// Until `Config` picks the curve at run time (#178), only the curve the features pick uses its crate-internal helpers

/// secp256k1 keys and key exchange
#[cfg_attr(any(feature = "x25519", feature = "ed25519"), allow(dead_code))]
pub mod secp256k1;

/// X25519 keys and key exchange
#[cfg(feature = "curve25519")]
#[cfg_attr(not(feature = "x25519"), allow(dead_code))]
pub mod x25519;

/// Ed25519 keys and key exchange
#[cfg(feature = "curve25519")]
#[cfg_attr(not(feature = "ed25519"), allow(dead_code))]
pub mod ed25519;

#[cfg(all(feature = "x25519", feature = "ed25519"))]
compile_error!("the `x25519` and `ed25519` features each pick the curve for `encrypt` and `decrypt`: enable one");

// `feature_curve` is the curve `encrypt` and `decrypt` use, picked by Cargo features until `Config` takes over (#178)

#[cfg(all(feature = "ed25519", not(feature = "x25519")))]
pub(crate) use ed25519 as feature_curve;
#[cfg(all(not(feature = "x25519"), not(feature = "ed25519")))]
pub(crate) use secp256k1 as feature_curve;
#[cfg(all(feature = "x25519", not(feature = "ed25519")))]
pub(crate) use x25519 as feature_curve;

#[cfg(test)]
mod tests {
    use super::feature_curve::{decapsulate, encapsulate, generate_keypair};

    #[test]
    fn test_key_exchange() {
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();
        assert_eq!(
            encapsulate(&sk2, &pk1, false).unwrap(),
            decapsulate(&pk2, &sk1, false).unwrap()
        );
    }
}
