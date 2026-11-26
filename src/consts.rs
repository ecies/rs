/// Compressed secp256k1 public key size
pub const COMPRESSED_PUBLIC_KEY_SIZE: usize = 33;

/// Uncompressed secp256k1 public key size
pub const UNCOMPRESSED_PUBLIC_KEY_SIZE: usize = 65;

/// X25519 and Ed25519 public key size
pub const CURVE25519_PUBLIC_KEY_SIZE: usize = 32;

/// AEAD tag length
pub const AEAD_TAG_LENGTH: usize = 16;

/// XChaCha20-Poly1305 nonce length
pub const XCHACHA20_NONCE_LENGTH: usize = 24;

/// Shared secret derived from key exchange by hkdf
pub type SharedSecret = [u8; 32];

pub(crate) const ZERO_SECRET: [u8; 32] = [0u8; 32];
