use once_cell::sync::Lazy;

#[cfg(not(feature = "std"))]
use crate::sync::RwLock;
#[cfg(feature = "std")]
use parking_lot::RwLock;

/// ECIES config. Make sure all parties use the same config.
///
/// Pass it to [`encrypt_with_config`](crate::encrypt_with_config) and
/// [`decrypt_with_config`](crate::decrypt_with_config). Both flags apply to secp256k1 only; in 0.2 the curve, cipher
/// and nonce length still come from Cargo features.
///
/// 0.3 adds fields for those, so fill the fields you don't set from [`Config::DEFAULT`] to keep this code compiling:
///
/// ```
/// use ecies::config::Config;
///
/// const CONFIG: Config = Config {
///     is_ephemeral_key_compressed: true,
///     ..Config::DEFAULT
/// };
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Config {
    /// Send the ephemeral public key as 33 bytes instead of 65
    pub is_ephemeral_key_compressed: bool,
    /// Derive the symmetric key from compressed points instead of uncompressed ones
    pub is_hkdf_key_compressed: bool,
}

impl Config {
    /// Both flags off, the same as [`Config::default()`]
    pub const DEFAULT: Config = Config {
        is_ephemeral_key_compressed: false,
        is_hkdf_key_compressed: false,
    };

    /// Ephemeral public key size at the start of a payload: compressed (33) or uncompressed (65) on secp256k1, or 32 on
    /// x25519 and ed25519
    pub const fn ephemeral_key_size(&self) -> usize {
        #[cfg(all(not(feature = "x25519"), not(feature = "ed25519")))]
        let size = if self.is_ephemeral_key_compressed {
            crate::consts::COMPRESSED_PUBLIC_KEY_SIZE
        } else {
            crate::consts::UNCOMPRESSED_PUBLIC_KEY_SIZE
        };
        #[cfg(any(feature = "x25519", feature = "ed25519"))]
        let size = crate::consts::PUBLIC_KEY_SIZE;

        size
    }
}

/// Global config variable
#[deprecated(
    since = "0.2.16",
    note = "removed in 0.3.0; pass a `Config` to `encrypt_with_config` and `decrypt_with_config` instead"
)]
pub static ECIES_CONFIG: Lazy<RwLock<Config>> = Lazy::new(|| {
    let config: Config = Config::default();
    RwLock::new(config)
});

/// The global config, read once so both flags come from the same update
#[allow(deprecated)]
pub(crate) fn global_config() -> Config {
    ECIES_CONFIG.read().clone()
}

/// Update global config
#[deprecated(
    since = "0.2.16",
    note = "removed in 0.3.0; pass a `Config` to `encrypt_with_config` and `decrypt_with_config` instead"
)]
#[allow(deprecated)]
pub fn update_config(config: Config) {
    *ECIES_CONFIG.write() = config;
}

/// Reset global config to default
#[deprecated(
    since = "0.2.16",
    note = "removed in 0.3.0; pass a `Config` to `encrypt_with_config` and `decrypt_with_config` instead"
)]
#[allow(deprecated)]
pub fn reset_config() {
    update_config(Config::default())
}

/// Get ephemeral key compressed or not
#[deprecated(
    since = "0.2.16",
    note = "removed in 0.3.0 with the global config; keep the flags in your own `Config`"
)]
pub fn is_ephemeral_key_compressed() -> bool {
    global_config().is_ephemeral_key_compressed
}

/// Get hkdf key derived from compressed shared point or not
#[deprecated(
    since = "0.2.16",
    note = "removed in 0.3.0 with the global config; keep the flags in your own `Config`"
)]
pub fn is_hkdf_key_compressed() -> bool {
    global_config().is_hkdf_key_compressed
}

/// Get ephemeral key size: compressed(33) or uncompressed(65) on secp256k1 or 32 on x25519
#[deprecated(
    since = "0.2.16",
    note = "removed in 0.3.0; use `Config::ephemeral_key_size` instead"
)]
pub fn get_ephemeral_key_size() -> usize {
    global_config().ephemeral_key_size()
}
