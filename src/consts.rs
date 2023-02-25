/// AES IV/nonce length
pub const AES_IV_LENGTH: usize = 16;
/// AES tag length
pub const AES_TAG_LENGTH: usize = 16;
/// AES IV + tag length
pub const AES_IV_PLUS_TAG_LENGTH: usize = AES_IV_LENGTH + AES_TAG_LENGTH;
/// Empty bytes array
pub const EMPTY_BYTES: [u8; 0] = [];

pub const XCHACHAPOLY1305_XNONCE_LENGTH: usize = 24;