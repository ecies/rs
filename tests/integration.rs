#[test]
#[cfg(all(
    not(target_arch = "wasm32"),
    all(not(feature = "x25519"), not(feature = "ed25519")),
    not(feature = "aes-short-nonce"),
    not(feature = "xchacha20"),
))]
fn is_compatible_with_python() {
    use futures_util::FutureExt;
    use hex::{decode, encode};
    use tokio::runtime::Runtime;

    use ecies::{decrypt, encrypt, utils::generate_keypair};

    const MSG: &str = "hello world🌍";
    const PYTHON_BACKEND: &str = "https://demo.ecies.org/";

    let (sk, pk) = generate_keypair();

    let sk_hex = encode(sk.serialize());
    let uncompressed_pk = &pk.serialize();
    let pk_hex = encode(uncompressed_pk);

    let client = reqwest::Client::new();
    let params = [("data", MSG), ("pub", pk_hex.as_str())];

    let rt = Runtime::new().unwrap();
    let res = rt
        .block_on(
            client
                .post(PYTHON_BACKEND)
                .form(&params)
                .send()
                .then(|r| r.unwrap().text()),
        )
        .unwrap();

    let server_encrypted = decode(res).unwrap();
    let local_decrypted = decrypt(&sk.serialize(), &server_encrypted).unwrap();
    assert_eq!(local_decrypted, MSG.as_bytes());

    let local_encrypted = encrypt(uncompressed_pk, MSG.as_bytes()).unwrap();
    let params = [("data", encode(local_encrypted)), ("prv", sk_hex)];

    let res = rt
        .block_on(
            client
                .post(PYTHON_BACKEND)
                .form(&params)
                .send()
                .then(|r| r.unwrap().text()),
        )
        .unwrap();

    assert_eq!(res.as_bytes(), MSG.as_bytes());
}

#[test]
#[cfg(all(not(target_arch = "wasm32"), not(feature = "x25519"), not(feature = "ed25519"),))]
fn test_aad() {
    use ecies::config::Config;
    use ecies::utils::generate_keypair;
    use ecies::{decrypt, decrypt_with_config, encrypt, encrypt_with_config};
    let (sk, pk) = generate_keypair();
    let (sk, pk) = (sk.serialize(), pk.serialize());

    const MSG: &[u8] = b"hello aad";
    const AAD: &[u8] = b"entry:DATABASE_PASSWORD";
    const CONFIG: Config = Config::DEFAULT;

    let ct = encrypt_with_config(&pk, MSG, AAD, &CONFIG).unwrap();
    assert_eq!(decrypt_with_config(&sk, &ct, AAD, &CONFIG).unwrap(), MSG);
    assert!(decrypt_with_config(&sk, &ct, b"entry:API_TOKEN", &CONFIG).is_err());
    assert!(decrypt(&sk, &ct).is_err());

    // With empty AAD and the default config, callers can switch APIs one side at a time.
    let legacy = encrypt(&pk, MSG).unwrap();
    assert_eq!(decrypt_with_config(&sk, &legacy, b"", &CONFIG).unwrap(), MSG);
    let empty_aad = encrypt_with_config(&pk, MSG, b"", &CONFIG).unwrap();
    assert_eq!(decrypt(&sk, &empty_aad).unwrap(), MSG);
}

/// A 33-byte secp256k1 key starts with `0x02` or `0x03` (SEC1). k256 also reads `0x05`, the sec1 crate's compact
/// form, which names a point by x alone, so encrypting to one could miss the receiver's key (#185)
#[test]
#[cfg(all(not(target_arch = "wasm32"), not(feature = "x25519"), not(feature = "ed25519"),))]
fn rejects_compact_receiver_keys() {
    use ecies::secp256k1::{PublicKey, PublicKeyFormat};
    use ecies::{Error, encrypt, utils::generate_keypair};

    let (_, pk) = generate_keypair();
    let compressed = pk.serialize_compressed();
    // the same x with the other y, so both prefixes are checked on every run
    let mut negated = compressed;
    negated[0] ^= 1;
    for key in [compressed, negated] {
        for format in [None, Some(PublicKeyFormat::Compressed)] {
            assert_eq!(
                PublicKey::parse_slice(&key, format).map(|pk| pk.serialize_compressed()),
                Ok(key),
                "{format:?}"
            );
        }
    }

    let mut compact = compressed;
    compact[0] = 0x05;
    assert_eq!(PublicKey::parse_slice(&compact, None), Err(Error::InvalidPublicKey));
    assert_eq!(
        PublicKey::parse_slice(&compact, Some(PublicKeyFormat::Compressed)),
        Err(Error::InvalidPublicKey)
    );
    assert_eq!(encrypt(&compact, b"msg"), Err(Error::InvalidPublicKey));
}

/// A payload whose compressed ephemeral key is rewritten to the compact `0x05` form decrypted whenever that form
/// named the same point, so one message had two encodings (#185)
#[test]
#[cfg(all(not(target_arch = "wasm32"), not(feature = "x25519"), not(feature = "ed25519"),))]
fn rejects_compact_ephemeral_keys() {
    use ecies::config::Config;
    use ecies::{Error, decrypt_with_config, encrypt_with_config, utils::generate_keypair};

    const COMPRESSED: Config = Config {
        is_ephemeral_key_compressed: true,
        ..Config::DEFAULT
    };

    let (sk, pk) = generate_keypair();
    let (sk, pk) = (sk.serialize(), pk.serialize());
    let mut encrypted = encrypt_with_config(&pk, b"msg", b"", &COMPRESSED).unwrap();
    assert_eq!(decrypt_with_config(&sk, &encrypted, b"", &COMPRESSED).unwrap(), b"msg");

    // the payload starts with the ephemeral key
    assert!(matches!(encrypted[0], 0x02 | 0x03));
    encrypted[0] = 0x05;
    assert_eq!(
        decrypt_with_config(&sk, &encrypted, b"", &COMPRESSED),
        Err(Error::InvalidPublicKey)
    );
}

/// The compression flags apply to secp256k1 only
#[test]
#[cfg(all(not(target_arch = "wasm32"), any(feature = "x25519", feature = "ed25519")))]
fn ignores_compression_flags_on_curve25519() {
    use ecies::config::Config;
    use ecies::consts::PUBLIC_KEY_SIZE;
    #[cfg(feature = "ed25519")]
    use ecies::ed25519::generate_keypair;
    #[cfg(feature = "x25519")]
    use ecies::x25519::generate_keypair;
    use ecies::{decrypt_with_config, encrypt_with_config};

    const COMPRESSED: Config = Config {
        is_ephemeral_key_compressed: true,
        is_hkdf_key_compressed: true,
    };
    assert_eq!(COMPRESSED.ephemeral_key_size(), PUBLIC_KEY_SIZE);

    let (sk, pk) = generate_keypair();
    #[cfg(feature = "x25519")]
    let (sk, pk) = (sk.as_bytes(), pk.as_bytes());
    #[cfg(feature = "ed25519")]
    let (sk, pk) = (sk.as_bytes(), &pk);

    for (encrypt_config, decrypt_config) in [
        (COMPRESSED, Config::DEFAULT),
        (Config::DEFAULT, COMPRESSED),
        (COMPRESSED, COMPRESSED),
    ] {
        let encrypted = encrypt_with_config(pk, b"msg", b"aad", &encrypt_config).unwrap();
        assert_eq!(
            decrypt_with_config(sk, &encrypted, b"aad", &decrypt_config).unwrap(),
            b"msg"
        );
    }
}
