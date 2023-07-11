pub use libsecp256k1::util::{COMPRESSED_PUBLIC_KEY_SIZE, FULL_PUBLIC_KEY_SIZE as UNCOMPRESSED_PUBLIC_KEY_SIZE};

/// AES IV/nonce length
pub const AES_IV_LENGTH: usize = 16;
/// AES tag length
pub const AES_TAG_LENGTH: usize = 16;
/// AES IV + tag length
pub const AES_IV_PLUS_TAG_LENGTH: usize = AES_IV_LENGTH + AES_TAG_LENGTH;
/// Empty bytes array
pub const EMPTY_BYTES: [u8; 0] = [];
