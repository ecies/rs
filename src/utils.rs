pub use crate::consts::SharedSecret;
/// The default curve's, [`secp256k1::decapsulate`](crate::secp256k1::decapsulate)
#[cfg(feature = "secp256k1")]
pub use crate::elliptic::secp256k1::decapsulate;
/// The default curve's, [`secp256k1::encapsulate`](crate::secp256k1::encapsulate)
#[cfg(feature = "secp256k1")]
pub use crate::elliptic::secp256k1::encapsulate;
/// The default curve's, [`secp256k1::generate_keypair`](crate::secp256k1::generate_keypair)
#[cfg(feature = "secp256k1")]
pub use crate::elliptic::secp256k1::generate_keypair;

#[cfg(test)]
pub mod tests {
    use alloc::vec::Vec;

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
