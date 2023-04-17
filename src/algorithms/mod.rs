//! JSON Web Algorithms (RFC 7518)
//!
//! This module implements the JWA format for representing cryptographic algorithms.

use serde::{Deserialize, Serialize};

use crate::key;

pub mod ecdsa;
pub mod hmac;
pub mod rsa;

/// The identifiers used in JWA to indicate how a JWS or JWE is signed or encrypted.
///
/// This is the list of standard identifiers defined in [RFC 7518](https://tools.ietf.org/html/rfc7518#section-3.1).
/// Not all of them are implemented herin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum AlgorithmIdentifier {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
    PS256,
    PS384,
    PS512,
    EdDSA,
    #[serde(rename = "none")]
    None,
}

/// A trait to associate an alogritm identifier with an algorithm.
///
/// Algorithm identifiers are used in JWS and JWE to indicate how a token is signed or encrypted.
/// They are set in the [crate::jose::JOSEHeader] automatically when signing the JWT.
pub trait Algorithm {
    const IDENTIFIER: AlgorithmIdentifier;
}

/// A trait to represent an algorithm which can sign a JWT.
pub trait SigningAlgorithm: Algorithm {
    /// Error type returned when signing fails.
    type Error;
    /// Signature type returned upon sucess. This is the JWS Signature value.
    type Signature: AsRef<[u8]>;

    /// The inner key type (e.g. [::rsa::RsaPrivateKey]) used to complete the registered
    /// header values.
    type Key: key::KeyInfo;

    /// Sign the contents of the JWT, when provided with the base64url-encoded header
    /// and payload. This is the JWS Signature value, and will be base64url-encoded
    /// and appended to the compact representation of the JWT.
    fn sign(&self, header: &str, payload: &str) -> Result<Self::Signature, Self::Error>;

    /// Return a reference to the key used to sign the JWT.
    fn key(&self) -> &Self::Key;
}
