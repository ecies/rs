#[cfg(feature = "curve25519")]
use crate::consts::CURVE25519_PUBLIC_KEY_SIZE;
use crate::consts::XCHACHA20_NONCE_LENGTH;
#[cfg(feature = "secp256k1")]
use crate::consts::{COMPRESSED_PUBLIC_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE};

/// Wire-format settings. Both sides must agree on every field their curve and cipher read.
///
/// Pass it to [`encrypt_with_config`](crate::encrypt_with_config) and
/// [`decrypt_with_config`](crate::decrypt_with_config). Start from [`Config::new`] with the curve, and set what
/// differs:
///
/// ```
/// # #[cfg(feature = "curve25519")] {
/// use ecies::{Config, EllipticCurve, SymmetricAlgorithm};
///
/// const CONFIG: Config = Config {
///     symmetric_algorithm: SymmetricAlgorithm::XChaCha20,
///     ..Config::new(EllipticCurve::X25519)
/// };
/// # }
/// ```
///
/// With the `secp256k1` feature, `Config::DEFAULT` and `Config::default()` are `Config::new(EllipticCurve::Secp256k1)`.
///
/// `==` and `Hash` compare every field, including the ones a curve or cipher ignores: the compression flags outside
/// secp256k1, and `symmetric_nonce_length` under XChaCha20-Poly1305. So two configs that read each other's payloads
/// can still compare unequal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "secp256k1", derive(Default))]
pub struct Config {
    /// Curve for the ephemeral key exchange
    pub elliptic_curve: EllipticCurve,
    /// secp256k1 only: send the ephemeral public key as 33 bytes instead of 65
    pub is_ephemeral_key_compressed: bool,
    /// secp256k1 only: derive the symmetric key from compressed points instead of uncompressed ones
    pub is_hkdf_key_compressed: bool,
    /// AEAD for the payload
    pub symmetric_algorithm: SymmetricAlgorithm,
    /// AES-256-GCM only. XChaCha20-Poly1305 always uses 24 bytes
    pub symmetric_nonce_length: NonceLength,
}

/// Curve for the ephemeral key exchange. Each curve exists only when its feature compiles it.
///
/// Each variant's value (`as u8`) is fixed, whichever features the build has.
///
/// The curve also sets how [`encrypt_with_config`](crate::encrypt_with_config) and
/// [`decrypt_with_config`](crate::decrypt_with_config) read the receiver's key:
///
/// | Curve | Public key | Secret key |
/// | --- | --- | --- |
/// | `Secp256k1` | 65 bytes uncompressed or 33 compressed (SEC1), or the 64 bytes of x and y | 32 bytes, big-endian |
/// | `X25519` | 32 bytes, the u-coordinate (RFC 7748) | 32 bytes, clamped when used (RFC 7748) |
/// | `Ed25519` | 32 bytes, the compressed point (RFC 8032) | 32 bytes, the seed (RFC 8032) |
///
/// Each curve rejects a key of the wrong length, and a public key that would let others compute the shared secret.
/// secp256k1 and Ed25519 also reject a public key that isn't a point of their curve, and Ed25519 one that has a
/// small-order component. X25519 takes any other 32 bytes, so it can't tell an X25519 public key from an Ed25519 key,
/// or from a secret key passed by mistake: encryption succeeds, and only the receiver finds out, when decryption fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "secp256k1", derive(Default))]
#[non_exhaustive]
// Each new curve takes the next unused value explicitly, since an implicit one follows the previous variant, which
// a feature may compile out. Variants hold no data, which would turn every `as` cast into a compile error
pub enum EllipticCurve {
    /// secp256k1, with the `secp256k1` feature
    #[cfg(feature = "secp256k1")]
    #[default]
    Secp256k1 = 0,
    /// X25519, with the `curve25519` feature
    #[cfg(feature = "curve25519")]
    X25519 = 1,
    /// Ed25519 keys, exchanged on the Edwards curve, with the `curve25519` feature
    #[cfg(feature = "curve25519")]
    Ed25519 = 2,
}

/// AEAD for the payload
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SymmetricAlgorithm {
    /// AES-256-GCM, with a 16- or 12-byte nonce
    #[default]
    Aes256Gcm,
    /// XChaCha20-Poly1305, with a 24-byte nonce
    XChaCha20,
}

/// AES-256-GCM nonce length
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum NonceLength {
    /// 12 bytes. Use a fresh key for each message, as ECIES does, since random nonces this short can collide
    Twelve = 12,
    /// 16 bytes
    #[default]
    Sixteen = 16,
}

impl Config {
    /// secp256k1 with uncompressed keys, and AES-256-GCM with a 16-byte nonce: the same as [`Config::default()`] and
    /// `Config::new(EllipticCurve::Secp256k1)`
    #[cfg(feature = "secp256k1")]
    pub const DEFAULT: Config = Config::new(EllipticCurve::Secp256k1);

    /// `elliptic_curve`, with uncompressed keys and AES-256-GCM with a 16-byte nonce. It exists in every build, so
    /// a build without `secp256k1` can still write `Config { ..., ..Config::new(EllipticCurve::X25519) }`
    pub const fn new(elliptic_curve: EllipticCurve) -> Config {
        Config {
            elliptic_curve,
            is_ephemeral_key_compressed: false,
            is_hkdf_key_compressed: false,
            symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
            symmetric_nonce_length: NonceLength::Sixteen,
        }
    }

    /// Nonce length inside a payload: 16 or 12 for AES-256-GCM, 24 for XChaCha20-Poly1305
    pub const fn nonce_length(&self) -> usize {
        nonce_size(self.symmetric_algorithm, self.symmetric_nonce_length)
    }

    /// Ephemeral public key size at the start of a payload: compressed (33) or uncompressed (65) on secp256k1, or 32 on
    /// X25519 and Ed25519
    pub const fn ephemeral_key_size(&self) -> usize {
        match self.elliptic_curve {
            #[cfg(feature = "secp256k1")]
            EllipticCurve::Secp256k1 if self.is_ephemeral_key_compressed => COMPRESSED_PUBLIC_KEY_SIZE,
            #[cfg(feature = "secp256k1")]
            EllipticCurve::Secp256k1 => UNCOMPRESSED_PUBLIC_KEY_SIZE,
            #[cfg(feature = "curve25519")]
            EllipticCurve::X25519 | EllipticCurve::Ed25519 => CURVE25519_PUBLIC_KEY_SIZE,
        }
    }
}

/// Nonce length inside a payload: 16 or 12 for AES-256-GCM, 24 for XChaCha20-Poly1305
pub(crate) const fn nonce_size(algorithm: SymmetricAlgorithm, nonce_length: NonceLength) -> usize {
    match algorithm {
        SymmetricAlgorithm::Aes256Gcm => nonce_length as usize,
        SymmetricAlgorithm::XChaCha20 => XCHACHA20_NONCE_LENGTH,
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, EllipticCurve, NonceLength, SymmetricAlgorithm};

    /// A crate may store `elliptic_curve as u8`, so a feature that adds a curve mustn't move the others
    #[test]
    fn elliptic_curve_values_ignore_features() {
        #[cfg(feature = "secp256k1")]
        assert_eq!(EllipticCurve::Secp256k1 as u8, 0);
        #[cfg(feature = "curve25519")]
        {
            assert_eq!(EllipticCurve::X25519 as u8, 1);
            assert_eq!(EllipticCurve::Ed25519 as u8, 2);
        }
    }

    /// `..Config::new(curve)` fills the other fields in any build, including one without `Config::DEFAULT`
    #[test]
    fn new_sets_only_the_curve() {
        let curves = [
            #[cfg(feature = "secp256k1")]
            EllipticCurve::Secp256k1,
            #[cfg(feature = "curve25519")]
            EllipticCurve::X25519,
            #[cfg(feature = "curve25519")]
            EllipticCurve::Ed25519,
        ];
        for elliptic_curve in curves {
            let expected = Config {
                elliptic_curve,
                is_ephemeral_key_compressed: false,
                is_hkdf_key_compressed: false,
                symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
                symmetric_nonce_length: NonceLength::Sixteen,
            };
            assert_eq!(Config::new(elliptic_curve), expected);
        }
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn default_is_new_on_secp256k1() {
        let expected = Config {
            elliptic_curve: EllipticCurve::Secp256k1,
            is_ephemeral_key_compressed: false,
            is_hkdf_key_compressed: false,
            symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
            symmetric_nonce_length: NonceLength::Sixteen,
        };
        assert_eq!(Config::DEFAULT, expected);
        assert_eq!(Config::default(), expected);
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn nonce_length_follows_the_cipher() {
        use NonceLength::{Sixteen, Twelve};
        use SymmetricAlgorithm::{Aes256Gcm, XChaCha20};

        let expected = [
            (Aes256Gcm, Sixteen, 16),
            (Aes256Gcm, Twelve, 12),
            (XChaCha20, Sixteen, 24),
            (XChaCha20, Twelve, 24),
        ];
        for (symmetric_algorithm, symmetric_nonce_length, nonce_length) in expected {
            let config = Config {
                symmetric_algorithm,
                symmetric_nonce_length,
                ..Config::DEFAULT
            };
            assert_eq!(config.nonce_length(), nonce_length, "{config:?}");
        }
    }
}
