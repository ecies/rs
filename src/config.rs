use once_cell::sync::Lazy;
use parking_lot::RwLock;

use crate::consts::{COMPRESSED_PUBLIC_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE};

/// ECIES config. Make sure all parties use the same config
#[derive(Default)]
pub struct Config {
    pub is_ephemeral_key_compressed: bool,
    pub is_hkdf_key_compressed: bool,
}

/// Global config variable
pub static ECIES_CONFIG: Lazy<RwLock<Config>> = Lazy::new(|| {
    let config: Config = Config::default();
    RwLock::new(config)
});

/// Update global config
pub fn update_config(config: Config) {
    *ECIES_CONFIG.write() = config;
}

/// Reset global config to default
pub fn reset_config() {
    update_config(Config::default())
}

/// Get ephemeral key compressed or not
pub fn is_ephemeral_key_compressed() -> bool {
    ECIES_CONFIG.read().is_ephemeral_key_compressed
}

/// Get ephemeral key size: compressed(33) or uncompressed(65)
pub fn get_ephemeral_key_size() -> usize {
    if is_ephemeral_key_compressed() {
        COMPRESSED_PUBLIC_KEY_SIZE
    } else {
        UNCOMPRESSED_PUBLIC_KEY_SIZE
    }
}

/// Get hkdf key derived from compressed shared point or not
pub fn is_hkdf_key_compressed() -> bool {
    ECIES_CONFIG.read().is_hkdf_key_compressed
}

#[cfg(test)]
mod tests {
    use super::{reset_config, update_config, Config};
    use libsecp256k1::PublicKey;

    use crate::{
        decrypt, encrypt,
        utils::{
            encapsulate, generate_keypair,
            tests::{decode_hex, get_sk2_sk3},
        },
    };

    const MSG: &str = "helloworld🌍";

    #[test]
    pub(super) fn test_known_hkdf_config() {
        let (sk2, sk3) = get_sk2_sk3();
        let pk3 = PublicKey::from_secret_key(&sk3);

        update_config(Config {
            is_hkdf_key_compressed: true,
            ..Config::default()
        });

        let encapsulated = encapsulate(&sk2, &pk3).unwrap();

        assert_eq!(
            encapsulated.to_vec(),
            decode_hex("b192b226edb3f02da11ef9c6ce4afe1c7e40be304e05ae3b988f4834b1cb6c69")
        );

        reset_config();
    }

    #[test]
    pub(super) fn test_ephemeral_key_config() {
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
    fn test_wasm() {
        super::tests::test_ephemeral_key_config();
        super::tests::test_known_hkdf_config();
    }
}
