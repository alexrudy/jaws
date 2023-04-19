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

pub trait VerifyAlgorithm: Algorithm {
    /// Error type returned when verification fails.
    type Error;

    /// The inner key type (e.g. [::rsa::RsaPublicKey]) used to complete the registered
    /// header values.
    type Key: key::KeyInfo;

    /// Verify the signature of the JWT, when provided with the base64url-encoded header
    /// and payload.
    fn verify(&self, header: &str, payload: &str, signature: &[u8]) -> Result<(), Self::Error>;

    /// Return a reference to the key used to verify the JWT.
    fn key(&self) -> &Self::Key;
}

/// A signature which has not been matched to an algorithm or key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Signature(Vec<u8>);

impl Signature {
    pub fn extend_from_slice(&mut self, other: &[u8]) {
        self.0.extend_from_slice(other);
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Signature(Vec::with_capacity(capacity))
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for Signature {
    fn from(bytes: &[u8]) -> Self {
        Signature(bytes.to_vec())
    }
}

impl From<Vec<u8>> for Signature {
    fn from(bytes: Vec<u8>) -> Self {
        Signature(bytes)
    }
}
