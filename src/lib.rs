#![cfg_attr(docsrs, feature(doc_auto_cfg))]
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
//! RustCrypto [signature](https://docs.rs/signature/latest/signature/) signing and
//! verifying traits are generic over the signature type, to allow for optimizations
//! from specific signature algorithms to be used when desired. When using a type-erased
//! keys, this is not possible, so the [`TokenSigner`] and [`TokenVerifier`] traits are
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
#![deny(clippy::self_named_module_files)]
#![deny(clippy::dbg_macro)]

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

/// Module for re-exports of related crates
///
/// Use these aliases to access related traits and types.
pub mod crypto {
    pub use digest;
    #[cfg(feature = "ecdsa")]
    pub use ecdsa;
    #[cfg(feature = "p256")]
    pub use p256;
    #[cfg(feature = "p384")]
    pub use p384;
    #[cfg(feature = "p521")]
    pub use p521;
    pub use pkcs8;
    #[cfg(feature = "rand")]
    pub use rand_core;
    #[cfg(feature = "rsa")]
    pub use rsa;
    pub use sha2;
    pub use signature;
}
