//! Keys live in one public module per curve, and every curve reports the crate's one `Error` (#178).
//! wasm-bindgen-test-runner skips plain `#[test]` functions, so these run natively only
#![cfg(not(target_arch = "wasm32"))]

use ecies::Error;

#[test]
fn top_level_keys_are_secp256k1() {
    let (sk, pk): (ecies::secp256k1::SecretKey, ecies::secp256k1::PublicKey) = ecies::utils::generate_keypair();
    let _: (ecies::SecretKey, ecies::PublicKey) = (sk.clone(), pk);

    let (peer_sk, peer_pk) = ecies::secp256k1::generate_keypair();
    assert_eq!(
        ecies::utils::encapsulate(&sk, &peer_pk, false).unwrap(),
        ecies::secp256k1::decapsulate(&pk, &peer_sk, false).unwrap()
    );
    assert_eq!(
        ecies::secp256k1::encapsulate(&sk, &peer_pk, false).unwrap(),
        ecies::utils::decapsulate(&pk, &peer_sk, false).unwrap()
    );
}

#[test]
fn parses_secp256k1_public_keys_in_each_format() {
    use ecies::secp256k1::{PublicKey, PublicKeyFormat};

    let (_, pk) = ecies::secp256k1::generate_keypair();
    let full = pk.serialize();
    let compressed = pk.serialize_compressed();
    let raw = &full[1..];

    assert_eq!(PublicKey::parse_slice(&full, Some(PublicKeyFormat::Full)), Ok(pk));
    assert_eq!(
        PublicKey::parse_slice(&compressed, Some(PublicKeyFormat::Compressed)),
        Ok(pk)
    );
    assert_eq!(PublicKey::parse_slice(raw, Some(PublicKeyFormat::Raw)), Ok(pk));

    // a length the format doesn't have
    let mismatched: [(&[u8], PublicKeyFormat); 3] = [
        (&full, PublicKeyFormat::Compressed),
        (&compressed, PublicKeyFormat::Raw),
        (raw, PublicKeyFormat::Full),
    ];
    for (bytes, format) in mismatched {
        assert_eq!(
            PublicKey::parse_slice(bytes, Some(format)),
            Err(Error::InvalidPublicKey),
            "{} bytes as {format:?}",
            bytes.len()
        );
    }
}

#[test]
#[cfg(feature = "curve25519")]
fn curve25519_modules_build_together() {
    let (sk, pk) = ecies::x25519::generate_keypair();
    let (peer_sk, peer_pk) = ecies::x25519::generate_keypair();
    assert_eq!(
        ecies::x25519::encapsulate(&sk, &peer_pk, false).unwrap(),
        ecies::x25519::decapsulate(&pk, &peer_sk, false).unwrap()
    );

    let (sk, pk) = ecies::ed25519::generate_keypair();
    let (peer_sk, peer_pk) = ecies::ed25519::generate_keypair();
    assert_eq!(
        ecies::ed25519::encapsulate(&sk, &peer_pk, false).unwrap(),
        ecies::ed25519::decapsulate(&pk, &peer_sk, false).unwrap()
    );
}

#[test]
#[cfg(feature = "curve25519")]
fn ed25519_secret_keys_hide_their_bytes() {
    let sk = ecies::ed25519::SecretKey::from([0x42; 32]);
    assert_eq!(format!("{sk:?}"), "SecretKey(..)");
}

#[test]
#[cfg(feature = "curve25519")]
fn ed25519_secret_keys_hold_their_bytes() {
    use ecies::ed25519::SecretKey;

    let bytes = [0x42; 32];
    let sk = SecretKey::from(bytes);
    assert_eq!(sk.as_bytes(), &bytes);
    assert_eq!(sk.to_bytes(), bytes);
    assert_eq!(sk, SecretKey::from(bytes));

    for i in 0..32 {
        let mut other = bytes;
        other[i] ^= 1;
        assert_ne!(sk, SecretKey::from(other), "byte {i} differs");
    }
}

#[test]
fn reports_the_crate_error() {
    // too short for a key on every curve
    assert_eq!(ecies::encrypt(&[1u8; 3], b"msg"), Err(Error::InvalidPublicKey));
    assert_eq!(ecies::decrypt(&[1u8; 3], b"msg"), Err(Error::InvalidSecretKey));
}
