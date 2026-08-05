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
    use ecies::utils::generate_keypair;
    use ecies::{decrypt, decrypt_with_aad, encrypt, encrypt_with_aad};
    let (sk, pk) = generate_keypair();
    let (sk, pk) = (sk.serialize(), pk.serialize());

    const MSG: &[u8] = b"hello aad";
    const AAD: &[u8] = b"entry:DATABASE_PASSWORD";

    // Correct AAD round-trips.
    let ct = encrypt_with_aad(&pk, MSG, AAD).unwrap();
    assert_eq!(decrypt_with_aad(&sk, &ct, AAD).unwrap(), MSG);

    // Wrong or missing AAD fails closed.
    assert!(decrypt_with_aad(&sk, &ct, b"entry:API_TOKEN").is_err());
    assert!(decrypt(&sk, &ct).is_err());

    // Empty AAD is equivalent to the legacy API in both directions.
    let legacy = encrypt(&pk, MSG).unwrap();
    assert_eq!(decrypt_with_aad(&sk, &legacy, b"").unwrap(), MSG);
    assert_eq!(decrypt(&sk, &legacy).unwrap(), MSG);
    assert_eq!(encrypt_with_aad(&pk, MSG, b"").unwrap().len(), legacy.len());
}
