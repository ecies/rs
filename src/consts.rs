pub use libsecp256k1::util::{COMPRESSED_PUBLIC_KEY_SIZE, FULL_PUBLIC_KEY_SIZE as UNCOMPRESSED_PUBLIC_KEY_SIZE};

/// AES nonce length
#[cfg(not(feature = "aes_12bytes_nonce"))]
pub const AES_NONCE_LENGTH: usize = 16;
#[cfg(feature = "aes_12bytes_nonce")]
pub const AES_NONCE_LENGTH: usize = 12;

/// AEAD tag length
pub const AEAD_TAG_LENGTH: usize = 16;

/// Nonce and tag length
pub const NONCE_TAG_LENGTH: usize = AES_NONCE_LENGTH + AEAD_TAG_LENGTH;

/// Empty bytes array
pub const EMPTY_BYTES: [u8; 0] = [];
