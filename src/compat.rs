#[cfg(feature = "std")]
pub(crate) use std::vec::Vec;

#[cfg(not(feature = "std"))]
pub(crate) use alloc::vec::Vec;
