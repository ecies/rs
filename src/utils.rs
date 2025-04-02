pub use crate::consts::SharedSecret;
pub use crate::elliptic::{decapsulate, encapsulate, generate_keypair};

#[cfg(test)]
pub mod tests {
    use crate::compat::Vec;
    use hex::decode;

    /// Convert hex string to u8 vector
    pub fn decode_hex(hex: &str) -> Vec<u8> {
        let hex = if hex.starts_with("0x") || hex.starts_with("0X") {
            &hex[2..]
        } else {
            hex
        };
        decode(hex).unwrap()
    }

    #[test]
    fn test_decode_hex() {
        assert_eq!(decode_hex("0x1234").as_slice(), &[0x12, 0x34]);
        assert_eq!(decode_hex("0X1234").as_slice(), &[0x12, 0x34]);
        assert_eq!(decode_hex("1234").as_slice(), &[0x12, 0x34]);
    }
}
