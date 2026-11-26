//! Keys live in one public module per curve, and every curve reports the crate's one `Error` (#178).
//! wasm-bindgen-test-runner skips plain `#[test]` functions, so these run natively only
#![cfg(not(target_arch = "wasm32"))]

#[cfg(feature = "secp256k1")]
use ecies::Error;

#[test]
#[cfg(feature = "secp256k1")]
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
#[cfg(feature = "secp256k1")]
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

/// ecies's own key types, so x25519-dalek's major version stays out of the interface
#[test]
#[cfg(feature = "curve25519")]
fn x25519_keys_hold_their_bytes() {
    use ecies::x25519::{PublicKey, SecretKey};

    // Alice's key pair in RFC 7748, section 6.1
    let sk_bytes: [u8; 32] = hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        .unwrap()
        .try_into()
        .unwrap();
    let pk_bytes: [u8; 32] = hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        .unwrap()
        .try_into()
        .unwrap();

    let sk = SecretKey::from(sk_bytes);
    let pk = PublicKey::from(&sk);
    assert_eq!(pk.as_bytes(), &pk_bytes);
    assert_eq!(pk.to_bytes(), pk_bytes);
    assert_eq!(pk, PublicKey::from(pk_bytes));
    assert_eq!(AsRef::<[u8]>::as_ref(&pk), pk_bytes.as_slice());
    assert_eq!(sk.as_bytes(), &sk_bytes);
    assert_eq!(sk.to_bytes(), sk_bytes);
    assert_eq!(AsRef::<[u8]>::as_ref(&sk), sk_bytes.as_slice());
    assert_eq!(sk, SecretKey::from(sk_bytes));

    for i in 0..32 {
        let mut other = sk_bytes;
        other[i] ^= 1;
        assert_ne!(sk, SecretKey::from(other), "byte {i} differs");
    }
}

#[test]
#[cfg(feature = "curve25519")]
fn x25519_secret_keys_hide_their_bytes() {
    let sk = ecies::x25519::SecretKey::from([0x42; 32]);
    assert_eq!(format!("{sk:?}"), "SecretKey(..)");
}

#[test]
#[cfg(feature = "curve25519")]
fn curve25519_secret_keys_clear_their_bytes_on_drop() {
    use core::mem::ManuallyDrop;

    let mut ed25519_sk = ManuallyDrop::new(ecies::ed25519::SecretKey::from([0x42; 32]));
    let mut x25519_sk = ManuallyDrop::new(ecies::x25519::SecretKey::from([0x42; 32]));
    // SAFETY: each key holds only its 32 bytes, which stay in place and initialized after the drop runs. The test
    // reads them, and doesn't drop the keys again
    unsafe {
        ManuallyDrop::drop(&mut ed25519_sk);
        ManuallyDrop::drop(&mut x25519_sk);
    }
    assert_eq!(ed25519_sk.as_bytes(), &[0; 32]);
    assert_eq!(x25519_sk.as_bytes(), &[0; 32]);
}

/// Both sides derive the same symmetric key, and it clears its bytes on drop, so callers needn't wipe it
#[test]
fn shared_secrets_clear_their_bytes_on_drop() {
    use core::mem::ManuallyDrop;

    macro_rules! check {
        ($curve:ident, $encapsulate:path, $decapsulate:path) => {{
            let (sk, pk) = ecies::$curve::generate_keypair();
            let (peer_sk, peer_pk) = ecies::$curve::generate_keypair();
            let mut ours = ManuallyDrop::new($encapsulate(&sk, &peer_pk, false).unwrap());
            let mut theirs = ManuallyDrop::new($decapsulate(&pk, &peer_sk, false).unwrap());
            assert_eq!(*ours, *theirs, "{}", stringify!($encapsulate));
            // so the zeros after the drop come from the drop
            assert_ne!(ours.as_slice(), &[0; 32], "{}", stringify!($encapsulate));
            // SAFETY: each secret holds only its 32 bytes, which stay in place and initialized after the drop runs.
            // The test reads them, and doesn't drop the secrets again
            unsafe {
                ManuallyDrop::drop(&mut ours);
                ManuallyDrop::drop(&mut theirs);
            }
            assert_eq!(ours.as_slice(), &[0; 32], "{}", stringify!($encapsulate));
            assert_eq!(theirs.as_slice(), &[0; 32], "{}", stringify!($decapsulate));
        }};
    }

    #[cfg(feature = "secp256k1")]
    {
        check!(secp256k1, ecies::secp256k1::encapsulate, ecies::secp256k1::decapsulate);
        check!(secp256k1, ecies::utils::encapsulate, ecies::utils::decapsulate);
    }
    #[cfg(feature = "curve25519")]
    {
        check!(x25519, ecies::x25519::encapsulate, ecies::x25519::decapsulate);
        check!(ed25519, ecies::ed25519::encapsulate, ecies::ed25519::decapsulate);
    }
}

#[test]
#[cfg(feature = "secp256k1")]
fn reports_the_crate_error() {
    // too short for a key on every curve
    assert_eq!(ecies::encrypt(&[1u8; 3], b"msg"), Err(Error::InvalidPublicKey));
    assert_eq!(ecies::decrypt(&[1u8; 3], b"msg"), Err(Error::InvalidSecretKey));
}
