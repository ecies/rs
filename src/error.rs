/// Why encryption or decryption failed
///
/// A minor release can add variants, so a `match` needs a wildcard arm:
///
/// ```
/// fn describe(error: ecies::Error) -> &'static str {
///     match error {
///         ecies::Error::InvalidPublicKey => "bad public key",
///         ecies::Error::InvalidSecretKey => "bad secret key",
///         ecies::Error::InvalidMessage => "bad message",
///         _ => "something else",
///     }
/// }
/// assert_eq!(describe(ecies::Error::InvalidMessage), "bad message");
/// ```
///
/// Without one, it doesn't compile:
///
/// ```compile_fail,E0004
/// fn describe(error: ecies::Error) -> &'static str {
///     match error {
///         ecies::Error::InvalidPublicKey => "bad public key",
///         ecies::Error::InvalidSecretKey => "bad secret key",
///         ecies::Error::InvalidMessage => "bad message",
///     }
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    /// The public key, or the ephemeral key in a payload, has the wrong length, is not on the curve, or is unsafe
    /// to use, such as a small-order curve25519 point
    InvalidPublicKey,
    /// The secret key has the wrong length or is out of range
    InvalidSecretKey,
    /// The payload is too short or fails authentication (a wrong key, AAD or config, or a changed payload), or the
    /// cipher refuses to encrypt the message, such as one too long for it
    InvalidMessage,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidPublicKey => write!(f, "Invalid public key"),
            Error::InvalidSecretKey => write!(f, "Invalid secret key"),
            Error::InvalidMessage => write!(f, "Invalid message"),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::format;
    #[cfg(feature = "std")]
    use std::format;

    use super::Error;

    #[test]
    fn formats_errors() {
        let expected = [
            (Error::InvalidPublicKey, "Invalid public key"),
            (Error::InvalidSecretKey, "Invalid secret key"),
            (Error::InvalidMessage, "Invalid message"),
        ];

        for (error, message) in expected {
            assert_eq!(format!("{error}"), message);
            let error: &dyn core::error::Error = &error;
            assert_eq!(format!("{error}"), message);
        }
    }
}
