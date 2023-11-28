//! JSON Web Algorithms ([RFC 7518][RFC7518])
//!
//! This module implements the JWA format for representing cryptographic algorithms.
//!
//! See the submodules for specific algorithm implementations for signing.
//!
//! # Algorithm Traits
//!
//! JOSE uses a few traits to define appropriate signing algorithms. [`JoseAlgorithm`] is the main trait,
//! which defines the algorithm identifier and the type of the signature. [`JoseDigestAlgorithm`] is a
//! subtrait which defines the digest algorithm used by the signature, for algorithms which use digest
//! signing (e.g. RSA-PSS, RSA-PKCS1-v1_5, ECDSA), and where a specific digest is specified by the algorithm
//! identifier.
//!
//! [`TokenSigner`] and [`TokenVerifier`] are traits which define the ability to sign and verify a JWT.
//! They are implemented for any [`JoseDigestAlgorithm`] which is also a [`DigestSigner`][signature::DigestSigner] or [`DigestVerifier`][signature::DigestVerifier].
//!
//! # Supported Algorithms
//!
//! ## HMAC
//!
//! - HS256: HMAC using SHA-256
//! - HS384: HMAC using SHA-384
//! - HS512: HMAC using SHA-512
//!
//! ## RSA
//!
//! - RS256: RSASSA-PKCS1-v1_5 using SHA-256
//! - RS384: RSASSA-PKCS1-v1_5 using SHA-384
//! - RS512: RSASSA-PKCS1-v1_5 using SHA-512
//! - PS256: RSASSA-PSS using SHA-256 and MGF1 with SHA-256
//! - PS384: RSASSA-PSS using SHA-384 and MGF1 with SHA-384
//!
//! ## ECDSA
//!
//! - ES256: ECDSA using P-256 and SHA-256
//! - ES384: ECDSA using P-384 and SHA-384
//!
//! # Unsupported algorithms
//!
//! This crate does not support signing or verification with the `none` algorithm,
//! as it is generally a security vulnerability.
//!
//! Currently, there is no support for the following algorithms:
//!
//! - EdDSA: EdDSA using Ed25519 is not yet supported.
//! - ES512: ECDSA using P-521 and SHA-512 is not yet supported.
//!
//! All of these algorithms could be supported by providing suitable implementations
//! of the [`JoseAlgorithm`] trait and the [`TokenSigner`] and [`TokenVerifier`] traits.
//!
//! [RFC7518]: https://tools.ietf.org/html/rfc7518

use std::fmt;

use base64ct::Encoding as _;
use bytes::Bytes;
use digest::Digest;
use serde::{Deserialize, Serialize};
use signature::SignatureEncoding;

#[cfg(any(feature = "p256", feature = "hmac", feature = "rsa"))]
pub use sha2::Sha256;

#[cfg(any(feature = "p348", feature = "hmac", feature = "rsa"))]
pub use sha2::Sha384;

#[cfg(any(feature = "hmac", feature = "rsa"))]
pub use sha2::Sha512;

#[cfg(feature = "ecdsa")]
pub mod ecdsa;

#[cfg(feature = "hmac")]
pub mod hmac;

#[cfg(feature = "rsa")]
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

impl AlgorithmIdentifier {
    /// Return whether this algorithm is available for signing.
    pub fn available(&self) -> bool {
        match self {
            Self::None => true,

            Self::HS256 | Self::HS384 | Self::HS512 => cfg!(feature = "hmac"),
            Self::RS256 | Self::RS384 | Self::RS512 => cfg!(feature = "rsa"),
            Self::ES256 | Self::ES384 | Self::ES512 => cfg!(feature = "ecdsa"),
            Self::EdDSA => cfg!(feature = "ed25519"),
            Self::PS256 | Self::PS384 | Self::PS512 => cfg!(feature = "rsa"),
        }
    }
}

/// A trait to associate an alogritm identifier with an algorithm.
///
/// Algorithm identifiers are used in JWS and JWE to indicate how a token is signed or encrypted.
/// They are set in the [crate::jose::Header] automatically when signing the JWT.
pub trait JoseAlgorithm {
    /// The identifier for this algorithm when used in a JWT registered header.
    ///
    /// This is the `alg` field in the JOSE header.
    const IDENTIFIER: AlgorithmIdentifier;
}

/// A trait to associate an alogritm identifier with an algorithm.
///
/// This is a dynamic version of [`JoseAlgorithm`], which allows for
/// dynamic dispatch of the algorithm, and object-safety for the trait.
///
/// This trait does not need to be implemented manually, as it is implemented
/// for any type which implements [`JoseAlgorithm`].
pub trait DynJoseAlgorithm {
    /// The identifier for this algorithm when used in a JWT registered header.
    fn identifier(&self) -> AlgorithmIdentifier;
}

impl<T> DynJoseAlgorithm for T
where
    T: JoseAlgorithm,
{
    fn identifier(&self) -> AlgorithmIdentifier {
        T::IDENTIFIER
    }
}

/// A trait to associate an algorithm with a digest for signing.
pub trait JoseDigestAlgorithm: JoseAlgorithm {
    /// The digest algorithm used by this signature.
    type Digest: Digest;
}

/// A trait to represent an algorithm which can sign a JWT.
///
/// This trait should apply to signing keys.
pub trait TokenSigner<S>: DynJoseAlgorithm
where
    S: SignatureEncoding,
{
    /// Sign the contents of the JWT, when provided with the base64url-encoded header
    /// and payload. This is the JWS Signature value, and will be base64url-encoded
    /// and appended to the compact representation of the JWT.
    fn try_sign_token(&self, header: &str, payload: &str) -> Result<S, signature::Error>;

    /// Sign the contents of the JWT, when provided with the base64url-encoded header
    /// and payload. This is the JWS Signature value, and will be base64url-encoded
    /// and appended to the compact representation of the JWT.
    ///
    /// # Panics
    ///
    /// This function will panic if the signature cannot be computed.
    fn sign_token(&self, header: &str, payload: &str) -> S {
        self.try_sign_token(header, payload).unwrap()
    }
}

impl<K, S> TokenSigner<S> for K
where
    K: JoseDigestAlgorithm,
    K: signature::DigestSigner<K::Digest, S>,
    S: SignatureEncoding,
{
    fn try_sign_token(&self, header: &str, payload: &str) -> Result<S, signature::Error> {
        let message = format!("{}.{}", header, payload);

        let mut digest = <Self as JoseDigestAlgorithm>::Digest::new();
        digest.update(message.as_bytes());

        self.try_sign_digest(digest)
    }
}

/// A trait to represent an algorithm which can verify a JWT.
///
/// This trait should apply to the equivalent of public keys, which have enough information
/// to verify a JWT signature, but not necessarily to sing it.
pub trait TokenVerifier<S>: DynJoseAlgorithm
where
    S: SignatureEncoding,
{
    /// Verify the signature of the JWT, when provided with the base64url-encoded header
    /// and payload.
    fn verify_token(
        &self,
        header: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<S, signature::Error>;
}

impl<K, S> TokenVerifier<S> for K
where
    K: JoseDigestAlgorithm + std::fmt::Debug,
    K: signature::DigestVerifier<K::Digest, S>,
    K::Digest: Clone + std::fmt::Debug,
    S: SignatureEncoding + std::fmt::Debug,
    for<'a> <S as TryFrom<&'a [u8]>>::Error: std::error::Error + Send + Sync + 'static,
{
    fn verify_token(
        &self,
        header: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<S, signature::Error> {
        let mut digest = <Self as JoseDigestAlgorithm>::Digest::new();
        digest.update(header);
        digest.update(b".");
        digest.update(payload);

        let signature = signature
            .try_into()
            .map_err(signature::Error::from_source)?;

        self.verify_digest(digest, &signature)?;
        Ok(signature)
    }
}

/// A signature which has not been matched to an algorithm or key.
///
/// This is a basic signature `struct` which can be used to store any signature
/// on the heap. It is used to store the signature of a JWT before it is verified,
/// or if a signature has a variable length.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SignatureBytes(Bytes);

impl fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SignatureBytes")
            .field(&base64ct::Base64UrlUnpadded::encode_string(self.0.as_ref()))
            .finish()
    }
}

impl AsRef<[u8]> for SignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for SignatureBytes {
    fn from(bytes: &[u8]) -> Self {
        SignatureBytes(bytes.to_owned().into())
    }
}

impl From<Bytes> for SignatureBytes {
    fn from(bytes: Bytes) -> Self {
        SignatureBytes(bytes)
    }
}

impl From<SignatureBytes> for Bytes {
    fn from(bytes: SignatureBytes) -> Self {
        bytes.0.clone()
    }
}

impl From<Vec<u8>> for SignatureBytes {
    fn from(bytes: Vec<u8>) -> Self {
        SignatureBytes(bytes.into())
    }
}

impl signature::SignatureEncoding for SignatureBytes {
    type Repr = Bytes;
}

/// A macro to implement the required traits for common JWS alogorithms.
#[macro_export]
macro_rules! jose_algorithm {
    ($alg:ident, $signer:ty, $verifier:ty, $digest:ty, $signature:ty) => {
        impl $crate::algorithms::JoseAlgorithm for $signer {
            const IDENTIFIER: $crate::algorithms::AlgorithmIdentifier =
                $crate::algorithms::AlgorithmIdentifier::$alg;
        }

        impl $crate::algorithms::JoseDigestAlgorithm for $signer {
            type Digest = $digest;
        }

        impl signature::DigestSigner<$digest, $crate::algorithms::SignatureBytes> for $signer {
            fn try_sign_digest(
                &self,
                digest: $digest,
            ) -> Result<$crate::algorithms::SignatureBytes, signature::Error> {
                #[allow(unused_imports)]
                use signature::SignatureEncoding as _;

                let sig = <Self as signature::DigestSigner<$digest, $signature>>::sign_digest(
                    self, digest,
                );
                Ok($crate::algorithms::SignatureBytes::from(
                    sig.to_bytes().as_ref(),
                ))
            }
        }

        impl $crate::algorithms::JoseAlgorithm for $verifier {
            const IDENTIFIER: $crate::algorithms::AlgorithmIdentifier =
                $crate::algorithms::AlgorithmIdentifier::$alg;
        }

        impl $crate::algorithms::JoseDigestAlgorithm for $verifier {
            type Digest = $digest;
        }

        impl signature::DigestVerifier<$digest, $crate::algorithms::SignatureBytes> for $verifier {
            fn verify_digest(
                &self,
                digest: $digest,
                signature: &$crate::algorithms::SignatureBytes,
            ) -> Result<(), signature::Error> {
                #[allow(unused_imports)]
                use signature::SignatureEncoding as _;

                let sig: $signature = signature
                    .to_bytes()
                    .as_ref()
                    .try_into()
                    .map_err(|error| signature::Error::from_source(error))?;

                <Self as signature::DigestVerifier<$digest, $signature>>::verify_digest(
                    self, digest, &sig,
                )
            }
        }
    };
}

#[cfg(test)]
mod test {
    use super::*;

    use static_assertions as sa;

    // NOTE: The test requires an explicit value for the signature
    // associated type, and we use `SignatureBytes` for this.
    // it is assumed that external dependencies will provide either
    // a concrete `Signature` type, or an object-safe trait.
    sa::assert_obj_safe!(TokenSigner<SignatureBytes>);
    sa::assert_obj_safe!(TokenVerifier<SignatureBytes>);
}
