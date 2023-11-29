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
//! # Working with dyn Keys (supporting multiple algorithms)
//!
//! This crate supports working with multiple different types of keys simultaneously.
//! Most of the traits are designed to be object-safe when used with the [`Token`] type,
//! so that they can be used with a single type-erased key type.
//!
//! Since RustCrypto [signature](https://docs.rs/signature/latest/signature/) signing and
//! verifying traits are generic over the signature type, to allow for optimizations
//! from specific signature algorithms to be applied. When using a type-erased keys,
//! this is not possible, so the [`TokenSigner`] and [`TokenVerifier`] traits are
//! also designed to work with the [`SignatureBytes`] type, which is a type-erased
//! signature type.
//!
//! ```rust
//! use jaws::algorithms::SignatureBytes;
//! use jaws::algorithms::TokenSigner;
//! use jaws::algorithms::TokenVerifier;
//!
//! type Signer = Box<dyn TokenSigner<SignatureBytes>>;
//! type Verifier = Box<dyn TokenVerifier<SignatureBytes>>;
//!
//! ```

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

pub use algorithms::{SignatureBytes, TokenSigner, TokenVerifier};
pub use claims::{Claims, RegisteredClaims};
#[cfg(feature = "fmt")]
pub use fmt::JWTFormat;
pub use token::Token;
pub use token::{Compact, Flat, FlatUnprotected};
