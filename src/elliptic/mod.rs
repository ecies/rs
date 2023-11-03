// #[cfg(feature = "secp256k1")]
mod secp256k1;
// #[cfg(feature = "secp256k1")]
pub use secp256k1::{decapsulate, encapsulate, generate_keypair};
// #[cfg(feature = "secp256k1")]
pub(crate) use secp256k1::{parse_pk, parse_sk, pk_to_vec, Error};

// #[cfg(feature = "x25519")]
// mod x25519;
// #[cfg(feature = "x25519")]
// pub use x25519::{decapsulate, encapsulate, generate_keypair};
// #[cfg(feature = "x25519")]
// pub(crate) use x25519::{parse_pk, parse_sk, pk_to_vec, Error};
