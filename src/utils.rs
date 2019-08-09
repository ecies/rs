use hex::decode;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use rand::{rngs::OsRng, RngCore};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

const AES_IV_LENGTH: usize = 16;
const AES_TAG_LENGTH: usize = 16;
const AES_IV_PLUS_TAG_LENGTH: usize = AES_IV_LENGTH + AES_TAG_LENGTH;
const EMPTY_BYTES: [u8; 0] = [];

pub fn get_valid_secret() -> SecretKey {
    let mut key = [0u8; 32];

    loop {
        OsRng.fill_bytes(&mut key);
        if let Ok(k) = SecretKey::from_slice(&key) {
            return k;
        }
    }
}

pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let sk = get_valid_secret();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    (sk, pk)
}

pub fn remove0x(hex: &str) -> &str {
    if hex.starts_with("0x") || hex.starts_with("0X") {
        return &hex[2..];
    }
    hex
}

pub fn decode_hex(hex: &str) -> Vec<u8> {
    decode(remove0x(hex)).unwrap()
}

pub fn aes_encrypt(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_256_gcm();

    let mut iv = [0u8; AES_IV_LENGTH];
    OsRng.fill_bytes(&mut iv);

    let mut tag = [0u8; AES_TAG_LENGTH];

    let encrypted = encrypt_aead(cipher, key, Some(&iv), &EMPTY_BYTES, msg, &mut tag).unwrap();

    let mut output = Vec::with_capacity(AES_IV_LENGTH + AES_TAG_LENGTH + encrypted.len());
    output.extend_from_slice(&iv);
    output.extend_from_slice(&tag);
    output.extend(encrypted);
    output
}

pub fn aes_decrypt(key: &[u8], encrypted_msg: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_256_gcm();

    let iv = &encrypted_msg[..AES_IV_LENGTH];
    let tag = &encrypted_msg[AES_IV_LENGTH..AES_IV_PLUS_TAG_LENGTH];
    let encrypted = &encrypted_msg[AES_IV_PLUS_TAG_LENGTH..];

    decrypt_aead(cipher, key, Some(&iv), &EMPTY_BYTES, encrypted, tag).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;
    use openssl::sha::sha256;
    use secp256k1::{ecdh::SharedSecret, Error};

    #[test]
    fn check_sha256() {
        let zeros = [0; 16];
        let digest = sha256(&zeros);
        let expected_digest = decode(concat!(
            "374708fff7719dd5979ec875d56cd228",
            "6f6d3cf7ec317a3b25632aab28ec37bb"
        ))
        .unwrap();
        assert_eq!(digest, expected_digest.as_slice());
    }

    #[test]
    fn check_remove_0x_decode_hex() {
        assert_eq!(remove0x("0x0011"), "0011");
        assert_eq!(remove0x("0X0011"), "0011");
        assert_eq!(remove0x("0011"), "0011");
        assert_eq!(decode_hex("0x0011"), [0u8, 17u8]);
    }

    #[test]
    fn check_aes_random_key() {
        let text = b"this is a text";
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        assert_eq!(
            text,
            aes_decrypt(&key, aes_encrypt(&key, text).as_slice()).as_slice()
        );
    }

    #[test]
    fn check_aes_known_key() {
        let text = b"helloworld";
        let key = decode_hex("0000000000000000000000000000000000000000000000000000000000000000");
        let iv = decode_hex("f3e1ba810d2c8900b11312b7c725565f");
        let tag = decode_hex("ec3b71e17c11dbe31484da9450edcf6c");
        let encrypted = decode_hex("02d2ffed93b856f148b9");

        let mut cipher_text = Vec::new();
        cipher_text.extend(iv);
        cipher_text.extend(tag);
        cipher_text.extend(encrypted);

        assert_eq!(text, aes_decrypt(&key, &cipher_text).as_slice());
    }

    #[test]
    fn test_get_valid_secret() {
        get_valid_secret();

        // 0 < private key < group order int is valid
        let zero = [0u8; 32];
        assert_eq!(
            SecretKey::from_slice(&zero).err().unwrap(),
            Error::InvalidSecretKey
        );

        let group_order_minus_1 =
            decode_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
        SecretKey::from_slice(&group_order_minus_1).unwrap();

        let group_order =
            decode_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        assert_eq!(
            SecretKey::from_slice(&group_order).err().unwrap(),
            Error::InvalidSecretKey
        );
    }

    #[test]
    fn test_ecdh() {
        let secp = Secp256k1::new();
        let mut one = [0u8; 32];
        let mut two = [0u8; 32];
        one[31] = 1u8;
        two[31] = 2u8;

        let k1 = SecretKey::from_slice(&one).unwrap();
        let k2 = SecretKey::from_slice(&two).unwrap();

        let known_ecdh =
            decode_hex("b1c9938f01121e159887ac2c8d393a22e4476ff8212de13fe1939de2a236f0a7");

        assert_eq!(
            &SharedSecret::new(&PublicKey::from_secret_key(&secp, &k1), &k2)[..],
            known_ecdh.as_slice()
        )
    }
}
