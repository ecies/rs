use crypto::{digest::Digest, sha2::Sha256};
use hex::decode;

pub fn sha256(msg: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.input(msg);

    let mut v = [0; 32];
    hasher.result(v.as_mut());
    v.to_vec()
}

pub fn remove0x(hex: &str) -> &str {
    if hex.starts_with("0x") || hex.starts_with("0X") {
        return &hex[2..];
    }
    return hex;
}

pub fn decode_hex(hex: &str) -> Vec<u8> {
    decode(remove0x(hex)).unwrap()
}

pub fn aes_encrypt(plain_text: &[u8]) -> Vec<u8> {
    Vec::new()
}

pub fn aes_decrypt(cipher_text: &[u8]) -> Vec<u8> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;

    #[test]
    fn check_sha256() {
        let zeros = [0; 16];
        let digest = sha256(&zeros);
        let expected_digest = decode(concat!(
            "374708fff7719dd5979ec875d56cd228",
            "6f6d3cf7ec317a3b25632aab28ec37bb"
        ))
        .unwrap();
        assert_eq!(digest, expected_digest);
    }

    #[test]
    fn check_remove_0x_decode_hex() {
        assert_eq!(remove0x("0x0011"), "0011");
        assert_eq!(remove0x("0X0011"), "0011");
        assert_eq!(remove0x("0011"), "0011");
        assert_eq!(decode_hex("0x0011"), [0u8, 17u8]);
    }
}
