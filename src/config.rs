use once_cell::sync::Lazy;
use parking_lot::RwLock;

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

/// Get hkdf key derived from compressed shared point or not
pub fn is_hkdf_key_compressed() -> bool {
    ECIES_CONFIG.read().is_hkdf_key_compressed
}

/// Get ephemeral key size: compressed(33) or uncompressed(65) on secp256k1 or 32 on x25519
#[cfg(not(feature = "x25519"))]
pub fn get_ephemeral_key_size() -> usize {
    use crate::consts::{COMPRESSED_PUBLIC_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE};

    if is_ephemeral_key_compressed() {
        COMPRESSED_PUBLIC_KEY_SIZE
    } else {
        UNCOMPRESSED_PUBLIC_KEY_SIZE
    }
}

#[cfg(feature = "x25519")]
pub fn get_ephemeral_key_size() -> usize {
    use crate::consts::PUBLIC_KEY_SIZE;

    PUBLIC_KEY_SIZE
}
