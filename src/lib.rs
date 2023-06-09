#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod algorithms;
pub mod b64data;
pub mod claims;

#[cfg(feature = "fmt")]
pub mod fmt;

pub mod jose;
pub mod key;
mod numeric_date;
pub mod token;

pub use claims::{Claims, RegisteredClaims};
#[cfg(feature = "fmt")]
pub use fmt::JWTFormat;
pub use jose::{Header, RegisteredHeader};
pub use token::{SignedToken, Token, UnsignedToken};
