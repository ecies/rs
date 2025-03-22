#[test]
#[cfg(all(
    not(target_arch = "wasm32"),
    not(feature = "x25519"),
    not(feature = "aes-12bytes-nonce"),
    not(feature = "xchacha20"),
))]
fn is_compatible_with_python() {
    use futures_util::FutureExt;
    use hex::{decode, encode};
    use tokio::runtime::Runtime;

    use ecies::{decrypt, encrypt, utils::generate_keypair};

    const MSG: &str = "helloworld🌍";
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
