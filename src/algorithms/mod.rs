//! JSON Web Algorithms ([RFC 7518][RFC7518])
//!
//! This module implements the JWA format for representing cryptographic algorithms.
//!
//! See the submodules for specific algorithm implementations for signing.
//!
//! [RFC7518]: https://tools.ietf.org/html/rfc7518

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
    /// Hash-based Message Authentication Code using SHA-256
    HS256,

    /// Hash-based Message Authentication Code using SHA-384
    HS384,

    /// Hash-based Message Authentication Code using SHA-512
    HS512,

    /// RSA PKCS#1 v1.5 signature using SHA-256
    RS256,

    /// RSA PKCS#1 v1.5 signature using SHA-348
    RS384,

    /// RSA PKCS#1 v1.5 signature using SHA-512
    RS512,

    /// ECDSA using P-256 and SHA-256
    ES256,

    /// ECDSA using P-384 and SHA-384
    ES384,

    /// ECDSA using P-521 and SHA-512
    ES512,

    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    PS256,

    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    PS384,

    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    PS512,

    /// EdDSA using Ed25519
    EdDSA,

    /// No signature is applied.
    #[serde(rename = "none")]
    None,
}

/// A trait to associate an alogritm identifier with an algorithm.
///
/// Algorithm identifiers are used in JWS and JWE to indicate how a token is signed or encrypted.
/// They are set in the [crate::jose::SignedHeader] automatically when signing the JWT.
pub trait Algorithm {
    /// The identifier for this algorithm when used in a JWT registered header.
    ///
    /// This is the `alg` field in the JOSE header.
    const IDENTIFIER: AlgorithmIdentifier;

    type Signature: AsRef<[u8]>;
}

/// A trait to represent an algorithm which can sign a JWT.
///
/// This trait should apply to signing keys.
pub trait SigningAlgorithm: Algorithm {
    /// Error type returned when signing fails.
    type Error;

    /// The inner key type (e.g. [::rsa::RsaPrivateKey]) used to complete the registered
    /// header values.
    type Key: key::SerializeJWK;

    /// Sign the contents of the JWT, when provided with the base64url-encoded header
    /// and payload. This is the JWS Signature value, and will be base64url-encoded
    /// and appended to the compact representation of the JWT.
    fn sign(&self, header: &str, payload: &str) -> Result<Self::Signature, Self::Error>;

    /// Return a reference to the key used to sign the JWT.
    fn key(&self) -> &Self::Key;
}

/// A trait to represent an algorithm which can verify a JWT.
///
/// This trait should apply to the equivalent of public keys, which have enough information
/// to verify a JWT signature, but not necessarily to sing it.
pub trait VerifyAlgorithm: Algorithm {
    /// Error type returned when verification fails.
    type Error;

    /// The inner key type (e.g. [::rsa::RsaPublicKey]) used to complete the registered
    /// header values.
    type Key: key::SerializeJWK;

    /// Verify the signature of the JWT, when provided with the base64url-encoded header
    /// and payload.
    fn verify(
        &self,
        header: &str,
        payload: &str,
        signature: &[u8],
    ) -> Result<Self::Signature, Self::Error>;

    /// Return a reference to the key used to verify the JWT.
    fn key(&self) -> &Self::Key;
}

/// A signature which has not been matched to an algorithm or key.
///
/// This is a basic signature `struct` which can be used to store any signature
/// on the heap. It is used to store the signature of a JWT before it is verified,
/// or if a signature has a variable length.
#[derive(Debug, Clone, PartialEq, Eq, Hash, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Add to this signature from a byte slice.
    pub fn extend_from_slice(&mut self, other: &[u8]) {
        self.0.extend_from_slice(other);
    }

    /// Create a new signature with the given capacity.
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
