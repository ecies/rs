use std::sync::Mutex;

use once_cell::sync::Lazy;

use crate::consts::{COMPRESSED_PUBLIC_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE};

#[derive(Default)]
pub enum SymmetricAlgorithm {
    #[default]
    Aes256Gcm,
}

#[derive(Default)]
pub struct Config {
    pub is_ephemeral_key_compressed: bool,
    pub is_hkdf_key_compressed: bool,
    pub symmetric_algorithm: SymmetricAlgorithm,
}

/// Global config variable
pub static ECIES_CONFIG: Lazy<Mutex<Config>> = Lazy::new(|| {
    let config: Config = Config::default();
    Mutex::new(config)
});

pub fn update_config(config: Config) {
    *ECIES_CONFIG.lock().unwrap() = config;
}

pub fn reset_config() {
    update_config(Config::default())
}

pub fn is_ephemeral_key_compressed() -> bool {
    ECIES_CONFIG.lock().unwrap().is_ephemeral_key_compressed
}

pub fn get_ephemeral_key_size() -> usize {
    if is_ephemeral_key_compressed() {
        COMPRESSED_PUBLIC_KEY_SIZE
    } else {
        UNCOMPRESSED_PUBLIC_KEY_SIZE
    }
}

pub fn is_hkdf_key_compressed() -> bool {
    ECIES_CONFIG.lock().unwrap().is_hkdf_key_compressed
}
