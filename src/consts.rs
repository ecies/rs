/// Compressed public key size
pub use libsecp256k1::util::COMPRESSED_PUBLIC_KEY_SIZE;
/// Uncompressed public key size
pub use libsecp256k1::util::FULL_PUBLIC_KEY_SIZE as UNCOMPRESSED_PUBLIC_KEY_SIZE;

/// AES nonce length
#[cfg(not(feature = "aes-12bytes-nonce"))]
pub const AES_NONCE_LENGTH: usize = 16;
#[cfg(feature = "aes-12bytes-nonce")]
pub const AES_NONCE_LENGTH: usize = 12;

/// XChaCha20 nonce length
#[cfg(feature = "xchacha20")]
pub const XCHACHA20_NONCE_LENGTH: usize = 24;

/// AEAD tag length
pub const AEAD_TAG_LENGTH: usize = 16;

/// Empty bytes array
pub const EMPTY_BYTES: [u8; 0] = [];
