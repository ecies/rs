/// Compressed public key size
// #[cfg(feature = "secp256k1")]
pub use libsecp256k1::util::COMPRESSED_PUBLIC_KEY_SIZE;
/// Uncompressed public key size
// #[cfg(feature = "secp256k1")]
pub use libsecp256k1::util::FULL_PUBLIC_KEY_SIZE as UNCOMPRESSED_PUBLIC_KEY_SIZE;

/// Nonce length. AES (12/16 bytes) or XChaCha20 (24 bytes)
#[cfg(all(not(feature = "aes-12bytes-nonce"), not(feature = "xchacha20")))]
pub const NONCE_LENGTH: usize = 16;
#[cfg(all(feature = "aes-12bytes-nonce", not(feature = "xchacha20")))]
pub const NONCE_LENGTH: usize = 12;
#[cfg(feature = "xchacha20")]
pub const NONCE_LENGTH: usize = 24;

/// AEAD tag length
pub const AEAD_TAG_LENGTH: usize = 16;

/// Nonce + tag length
pub const NONCE_TAG_LENGTH: usize = NONCE_LENGTH + AEAD_TAG_LENGTH;

/// Empty bytes array
pub const EMPTY_BYTES: [u8; 0] = [];

/// Shared secret derived from key exchange by hkdf
pub type SharedSecret = [u8; 32];
