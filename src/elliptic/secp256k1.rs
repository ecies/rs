use rand_core::OsRng;

pub use libsecp256k1::{Error, PublicKey, SecretKey};

use crate::compat::Vec;
use crate::config::is_hkdf_key_compressed;
use crate::consts::SharedSecret;
use crate::symmetric::hkdf_derive;

/// Generate a `(SecretKey, PublicKey)` pair
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let sk = SecretKey::random(&mut OsRng);
    let pk = PublicKey::from_secret_key(&sk);
    (sk, pk)
}

/// Calculate a shared symmetric key of our secret key and peer's public key by hkdf
pub fn encapsulate(sk: &SecretKey, peer_pk: &PublicKey) -> Result<SharedSecret, Error> {
    let mut shared_point = *peer_pk;
    shared_point.tweak_mul_assign(sk)?;
    let sender_point = &PublicKey::from_secret_key(sk);
    // TODO: move compressed: bool to arg
    Ok(get_shared_secret(sender_point, &shared_point, is_hkdf_key_compressed()))
}

/// Calculate a shared symmetric key of our public key and peer's secret key by hkdf
pub fn decapsulate(pk: &PublicKey, peer_sk: &SecretKey) -> Result<SharedSecret, Error> {
    let mut shared_point = *pk;
    shared_point.tweak_mul_assign(peer_sk)?;
    // TODO: move compressed: bool to arg
    Ok(get_shared_secret(pk, &shared_point, is_hkdf_key_compressed()))
}

/// Parse secret key bytes
pub fn parse_sk(sk: &[u8]) -> Result<SecretKey, Error> {
    SecretKey::parse_slice(sk)
}

/// Parse public key bytes
pub fn parse_pk(pk: &[u8]) -> Result<PublicKey, Error> {
    PublicKey::parse_slice(pk, None)
}

/// Public key to bytes
pub fn pk_to_vec(pk: &PublicKey, compressed: bool) -> Vec<u8> {
    if compressed {
        pk.serialize_compressed().to_vec()
    } else {
        pk.serialize().to_vec()
    }
}

fn get_shared_secret(sender_point: &PublicKey, shared_point: &PublicKey, compressed: bool) -> SharedSecret {
    if compressed {
        hkdf_derive(
            &sender_point.serialize_compressed(),
            &shared_point.serialize_compressed(),
        )
    } else {
        hkdf_derive(&sender_point.serialize(), &shared_point.serialize())
    }
}

#[cfg(test)]
mod known_tests {
    use super::{encapsulate, parse_sk, Error, PublicKey, SecretKey};

    use crate::consts::ZERO_SECRET;
    use crate::decrypt;
    use crate::utils::tests::decode_hex;
    pub fn get_sk(i: u8) -> SecretKey {
        let mut sk = ZERO_SECRET;
        sk[31] = i;
        SecretKey::parse_slice(&sk).unwrap()
    }

    #[test]
    fn test_invalid_secret() {
        // 0 < private key < group order is valid
        let zero = ZERO_SECRET;
        let group_order = decode_hex("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let invalid_sks = [zero.to_vec(), group_order];

        for sk in invalid_sks.iter() {
            assert_eq!(parse_sk(sk).err().unwrap(), Error::InvalidSecretKey);
        }
    }

    #[test]
    fn test_valid_secret() {
        let one = get_sk(1);
        assert!(parse_sk(&one.serialize()).is_ok());

        let group_order_minus_1 = decode_hex("0Xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
        let valid_sks = [group_order_minus_1];
        for sk in valid_sks.iter() {
            parse_sk(sk).unwrap();
        }
    }

    #[test]
    pub fn test_known_shared_secret() {
        let sk2 = get_sk(2);
        let sk3 = get_sk(3);
        let pk3 = PublicKey::from_secret_key(&sk3);

        assert_eq!(
            encapsulate(&sk2, &pk3).unwrap().to_vec(),
            decode_hex("6f982d63e8590c9d9b5b4c1959ff80315d772edd8f60287c9361d548d5200f82")
        );
    }

    #[cfg(all(not(feature = "xchacha20"), not(feature = "aes-12bytes-nonce")))]
    #[test]
    pub fn test_known_encrypted() {
        let sk = decode_hex("e520872701d9ec44dbac2eab85512ad14ad0c42e01de56d7b528abd8524fcb47");
        let encrypted = decode_hex("0x047be1885aeb48d4d4db0c992996725d3264784fef88c5b60782f8d0f940c213227fc3f904f846d5ec3d0fba6653754501e8ebadc421aa3892a20fef33cff0206047058a4cfb4efbeae96b2d019b4ab2edce33328748a0d008a69c8f5816b72d45bd9b5a41bb6ea0127ab23057ec6fcd");
        assert_eq!(decrypt(&sk, &encrypted).unwrap(), "hello world🌍".as_bytes());
    }

    #[cfg(all(not(feature = "xchacha20"), feature = "aes-12bytes-nonce"))]
    #[test]
    pub fn test_known_encrypted_short_nonce() {
        let sk = decode_hex("562b6cd3611d463f2c59218f1be2816472ad4a489450873dd585de7df662bb68");
        let encrypted = decode_hex("04e1b4678e49066bb9e12cc39aa303bf46b1bf4f565ffa56b9e5ebfa05b756612a548b06dfdd1d06afb64ab7a7e52e26e3a1c69da8fe0c3ea125848d44066f90c826f9a8b0c8951a06d9b20b3d434dc650862d85fcd4fb4b3f30e0658661d24cb9c31bcae0bf56564495c64b");
        assert_eq!(decrypt(&sk, &encrypted).unwrap(), "hello world🌍".as_bytes());
    }

    #[cfg(feature = "xchacha20")]
    #[test]
    pub fn test_known_encrypted_xchacha20() {
        let sk = decode_hex("9445d8b9911622546a266b2e663bf2b498073a64279409afb9ef20f8259c651f");
        let encrypted = decode_hex("04eaf35ad4dde0ace3f673fec6be164dc68e11aa9c1988d4c1b91f0ccdef94cf591aae4e9daf5f8a87837136fc70811df852015a8b4e2cb374c27db16933536085f34470ffef72667bbe984c145302fc8d37f66563339c47f41ef871ee0ebda8c1bad133c3b203c769cb694e5adbd6c9f02b2eedd939875a");
        assert_eq!(decrypt(&sk, &encrypted).unwrap(), "hello world🌍".as_bytes());
    }
}

#[cfg(test)]
mod random_tests {
    use super::generate_keypair;
    use crate::{decrypt, encrypt};

    const MSG: &str = "helloworld🌍";
    const BIG_MSG_SIZE: usize = 2 * 1024 * 1024; // 2 MB
    const BIG_MSG: [u8; BIG_MSG_SIZE] = [1u8; BIG_MSG_SIZE];

    fn test_enc_dec(sk: &[u8], pk: &[u8]) {
        let msg = MSG.as_bytes();
        assert_eq!(msg.to_vec(), decrypt(sk, &encrypt(pk, msg).unwrap()).unwrap());
        let msg = &BIG_MSG;
        assert_eq!(msg.to_vec(), decrypt(sk, &encrypt(pk, msg).unwrap()).unwrap());
    }

    #[test]
    fn test_keypair() {
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();

        assert_ne!(sk1, sk2);
        assert_ne!(pk1, pk2);
    }

    #[test]
    pub fn test_compressed_public() {
        let (sk, pk) = generate_keypair();
        let (sk, pk) = (&sk.serialize(), &pk.serialize_compressed());
        test_enc_dec(sk, pk);
    }

    #[test]
    pub fn test_uncompressed_public() {
        let (sk, pk) = generate_keypair();
        let (sk, pk) = (&sk.serialize(), &pk.serialize());
        test_enc_dec(sk, pk);
    }
}

#[cfg(test)]
mod error_tests {
    use super::{generate_keypair, Error};
    use crate::{decrypt, encrypt};

    const MSG: &str = "helloworld🌍";

    #[test]
    pub fn attempts_to_encrypt_with_invalid_key() {
        assert_eq!(encrypt(&[0u8; 33], MSG.as_bytes()), Err(Error::InvalidPublicKey));
    }

    #[test]
    pub fn attempts_to_decrypt_with_invalid_key() {
        assert_eq!(decrypt(&[0u8; 32], &[]), Err(Error::InvalidSecretKey));
    }

    #[test]
    pub fn attempts_to_decrypt_incorrect_message() {
        let (sk, _) = generate_keypair();

        assert_eq!(decrypt(&sk.serialize(), &[]), Err(Error::InvalidMessage));
        assert_eq!(decrypt(&sk.serialize(), &[0u8; 65]), Err(Error::InvalidPublicKey));
    }

    #[test]
    pub fn attempts_to_decrypt_with_another_key() {
        let (_, pk1) = generate_keypair();
        let (sk2, _) = generate_keypair();

        let encrypted = encrypt(&pk1.serialize_compressed(), MSG.as_bytes()).unwrap();
        assert_eq!(decrypt(&sk2.serialize(), &encrypted), Err(Error::InvalidMessage));
    }
}

#[cfg(test)]
mod config_tests {
    use super::known_tests::get_sk;
    use super::{encapsulate, generate_keypair, PublicKey};

    use crate::config::{reset_config, update_config, Config};
    use crate::utils::tests::decode_hex;
    use crate::{decrypt, encrypt};

    const MSG: &str = "helloworld🌍";

    #[test]
    pub fn test_known_hkdf_config() {
        let sk2 = get_sk(2);
        let sk3 = get_sk(3);
        let pk3 = PublicKey::from_secret_key(&sk3);

        update_config(Config {
            is_hkdf_key_compressed: true,
            ..Config::default()
        });

        assert_eq!(
            encapsulate(&sk2, &pk3).unwrap().to_vec(),
            decode_hex("b192b226edb3f02da11ef9c6ce4afe1c7e40be304e05ae3b988f4834b1cb6c69")
        );

        reset_config();
    }

    #[test]
    pub fn test_ephemeral_key_config() {
        let (sk, pk) = generate_keypair();
        let (sk, pk) = (&sk.serialize(), &pk.serialize_compressed());
        let encrypted_1 = encrypt(pk, MSG.as_bytes()).unwrap();
        assert_eq!(MSG.as_bytes(), &decrypt(sk, &encrypted_1).unwrap());

        update_config(Config {
            is_ephemeral_key_compressed: true,
            ..Config::default()
        });

        let encrypted_2 = encrypt(pk, MSG.as_bytes()).unwrap();
        assert_eq!(encrypted_1.len() - encrypted_2.len(), 32);
        assert_eq!(MSG.as_bytes(), &decrypt(sk, &encrypted_2).unwrap());

        reset_config();
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_known() {
        super::known_tests::test_known_shared_secret();
        #[cfg(all(not(feature = "xchacha20"), not(feature = "aes-12bytes-nonce")))]
        super::known_tests::test_known_encrypted();
        #[cfg(all(not(feature = "xchacha20"), feature = "aes-12bytes-nonce"))]
        super::known_tests::test_known_encrypted_short_nonce();
        #[cfg(feature = "xchacha20")]
        super::known_tests::test_known_encrypted_xchacha20();
    }

    #[wasm_bindgen_test]
    fn test_config() {
        super::config_tests::test_ephemeral_key_config();
        super::config_tests::test_known_hkdf_config();
    }

    #[wasm_bindgen_test]
    fn test_random() {
        super::random_tests::test_compressed_public();
        super::random_tests::test_uncompressed_public();
    }

    #[wasm_bindgen_test]
    fn test_error() {
        super::error_tests::attempts_to_encrypt_with_invalid_key();
        super::error_tests::attempts_to_decrypt_with_invalid_key();
        super::error_tests::attempts_to_decrypt_incorrect_message();
        super::error_tests::attempts_to_decrypt_with_another_key();
    }
}
