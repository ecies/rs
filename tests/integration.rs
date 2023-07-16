use ecies::{
    config::{reset_config, update_config, Config},
    decrypt, encrypt,
    utils::{decapsulate, encapsulate, generate_keypair},
    PublicKey, SecretKey,
};
use hex::decode;

const MSG: &str = "helloworld🌍";

#[test]
fn can_change_behavior_with_config() {
    let mut two = [0u8; 32];
    let mut three = [0u8; 32];
    two[31] = 2u8;
    three[31] = 3u8;

    let sk2 = SecretKey::parse_slice(&two).unwrap();
    let pk2 = PublicKey::from_secret_key(&sk2);
    let sk3 = SecretKey::parse_slice(&three).unwrap();
    let pk3 = PublicKey::from_secret_key(&sk3);

    update_config(Config {
        is_hkdf_key_compressed: true,
        ..Config::default()
    });

    assert_eq!(encapsulate(&sk2, &pk3), decapsulate(&pk2, &sk3));

    assert_eq!(
        encapsulate(&sk2, &pk3).map(|v| v.to_vec()).unwrap(),
        decode("b192b226edb3f02da11ef9c6ce4afe1c7e40be304e05ae3b988f4834b1cb6c69").unwrap()
    );

    update_config(Config {
        is_ephemeral_key_compressed: true,
        is_hkdf_key_compressed: true,
        ..Config::default()
    });

    let (sk, pk) = generate_keypair();
    let (sk, pk) = (&sk.serialize(), &pk.serialize_compressed());

    assert_eq!(
        MSG.as_bytes(),
        decrypt(sk, &encrypt(pk, MSG.as_bytes()).unwrap()).unwrap().as_slice()
    );

    reset_config();
}

#[test]
#[cfg(all(not(target_arch = "wasm32"), not(feature = "aes_12bytes_nonce")))]
fn is_compatible_with_python() {
    use futures_util::FutureExt;
    use hex::encode;
    use tokio::runtime::Runtime;

    const PYTHON_BACKEND: &str = "https://eciespydemo-1-d5397785.deta.app/";

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
    let local_decrypted = decrypt(&sk.serialize(), server_encrypted.as_slice()).unwrap();
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
