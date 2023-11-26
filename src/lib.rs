#![cfg_attr(all(feature = "rsa", feature = "fmt"), doc = include_str!("../README.md"))]
#![cfg_attr(
    not(all(feature = "rsa", feature = "fmt")),
    doc = "# JAWS: JSON Web tokens

JSON Web Tokens are used to send signed, authenticated and/or encrypted data using
a JavaScript Object Notation (JSON) object. This crate provides a strongly typed
interface for creating and validating [JWTs][JWT], built on top of the [RustCrypto][]
ecosystem.


[RustCrypto]: https://github.com/RustCrypto
[JWT]: https://tools.ietf.org/html/rfc7519
"
)]
#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod algorithms;
pub mod base64data;
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
pub use token::Token;
pub use token::{Compact, Flat, FlatUnprotected};
