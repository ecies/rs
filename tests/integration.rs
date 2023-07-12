use ecies::{
    config::{reset_config, update_config, Config, SymmetricAlgorithm},
    decrypt, encrypt,
    utils::{decapsulate, encapsulate, generate_keypair},
    PublicKey, SecretKey,
};

use hex::decode;

const MSG: &[u8] = "helloworld".as_bytes();

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
        is_ephemeral_key_compressed: false,
        is_hkdf_key_compressed: true,
        symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
    });

    assert_eq!(encapsulate(&sk2, &pk3), decapsulate(&pk2, &sk3));

    assert_eq!(
        encapsulate(&sk2, &pk3).map(|v| v.to_vec()).unwrap(),
        decode("b192b226edb3f02da11ef9c6ce4afe1c7e40be304e05ae3b988f4834b1cb6c69").unwrap()
    );

    update_config(Config {
        is_ephemeral_key_compressed: true,
        is_hkdf_key_compressed: true,
        symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
    });

    let (sk, pk) = generate_keypair();
    let (sk, pk) = (&sk.serialize(), &pk.serialize_compressed());

    assert_eq!(MSG, decrypt(sk, &encrypt(pk, MSG).unwrap()).unwrap().as_slice());

    reset_config();
}
