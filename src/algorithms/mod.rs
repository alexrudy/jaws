//! JSON Web Algorithms ([RFC 7518][RFC7518])
//!
//! This module implements the JWA format for representing cryptographic algorithms.
//!
//! See the submodules for specific algorithm implementations for signing.
//!
//! # Algorithm Traits
//!
//! JOSE uses a few traits to define appropriate signing algorithms. [`JsonWebAlgorithm`] is the main trait,
//! which defines the algorithm identifier and the type of the signature. [`JsonWebAlgorithmDigest`] is a
//! subtrait which defines the digest algorithm used by the signature, for algorithms which use digest
//! signing (e.g. RSA-PSS, RSA-PKCS1-v1_5, ECDSA), and where a specific digest is specified by the algorithm
//! identifier.
//!
//! [`TokenSigner`] and [`TokenVerifier`] are traits which define the ability to sign and verify a JWT.
//! They are implemented for any [`JsonWebAlgorithmDigest`] which is also a [`DigestSigner`][signature::DigestSigner] or [`DigestVerifier`][signature::DigestVerifier].
//!
//! # Supported Algorithms
//!
//! ## HMAC
//!
//! - HS256: HMAC using SHA-256 via [`HmacKey<Sha256>`][crate::algorithms::hmac::HmacKey]
//! - HS384: HMAC using SHA-384 via [`HmacKey<Sha341>`][crate::algorithms::hmac::HmacKey]
//! - HS512: HMAC using SHA-512 via [`HmacKey<Sha512>`][crate::algorithms::hmac::HmacKey]
//!
//! ## RSA
//!
//! - RS256: RSASSA-PKCS1-v1_5 using SHA-256 via [`rsa::pkcs1v15::SigningKey<Sha256>`][rsa::pkcs1v15::SigningKey] / [`rsa::pkcs1v15::VerifyingKey<Sha256>`][rsa::pkcs1v15::VerifyingKey]
//! - RS384: RSASSA-PKCS1-v1_5 using SHA-384 via [`rsa::pkcs1v15::SigningKey<Sha348>`][rsa::pkcs1v15::SigningKey] / [`rsa::pkcs1v15::VerifyingKey<Sha384>`][rsa::pkcs1v15::VerifyingKey]
//! - RS512: RSASSA-PKCS1-v1_5 using SHA-512 via [`rsa::pkcs1v15::SigningKey<Sha512>`][rsa::pkcs1v15::SigningKey] / [`rsa::pkcs1v15::VerifyingKey<Sha512>`][rsa::pkcs1v15::VerifyingKey]
//! - PS256: RSASSA-PSS using SHA-256 and MGF1 with SHA-256 via [`rsa::pss::SigningKey<Sha256>`][rsa::pss::SigningKey] / [`rsa::pss::VerifyingKey<Sha256>`][rsa::pss::VerifyingKey]
//! - PS384: RSASSA-PSS using SHA-384 and MGF1 with SHA-384 via [`rsa::pss::SigningKey<Sha384>`][rsa::pss::SigningKey] / [`rsa::pss::VerifyingKey<Sha384>`][rsa::pss::VerifyingKey]
//! - PS512: RSASSA-PSS using SHA-512 and MGF1 with SHA-384 via [`rsa::pss::SigningKey<Sha512>`][rsa::pss::SigningKey] / [`rsa::pss::VerifyingKey<Sha512>`][rsa::pss::VerifyingKey]
//!
//! ## ECDSA
//!
//! - ES256: ECDSA using P-256 and SHA-256 via [`ecdsa::SigningKey<p256::NistP256>`] / [`ecdsa::VerifyingKey<p256::NistP256>`]
//! - ES384: ECDSA using P-384 and SHA-384 via [`ecdsa::SigningKey<p348::NistP348>`] / [`ecdsa::VerifyingKey<p348::NistP348>`]
//!
//! # Unsupported algorithms
//!
//! This crate does not support signing or verification with the `none` algorithm,
//! as it is generally a security vulnerability.
//!
//! Currently, there is no support for the following algorithms:
//!
//! - EdDSA: EdDSA using Ed25519 is not yet supported, but using the [`ed25519-dalek`] crate
//!   this should be possible.
//! - ES512: ECDSA using P-521 and SHA-512 is not yet supported, since it is non-trivial to adapt
//!   the [`p521`] crate to the [`signature`] crate.
//!
//! All of these algorithms could be supported by providing suitable implementations
//! of the [`JsonWebAlgorithm`] trait and the [`TokenSigner`] and [`TokenVerifier`] traits.
//!
//! [RFC7518]: https://tools.ietf.org/html/rfc7518

use ::signature::SignatureEncoding;

use digest::Digest;
#[cfg(feature = "rand")]
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

#[cfg(any(feature = "p256", feature = "hmac", feature = "rsa"))]
pub use sha2::Sha256;

#[cfg(any(feature = "p384", feature = "hmac", feature = "rsa"))]
pub use sha2::Sha384;

#[cfg(any(feature = "hmac", feature = "rsa"))]
pub use sha2::Sha512;

use crate::key::SerializePublicJWK;

mod sig;

pub use sig::SignatureBytes;

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
#[non_exhaustive]
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
            Self::None => false,

            Self::HS256 | Self::HS384 | Self::HS512 => cfg!(feature = "hmac"),
            Self::RS256 | Self::RS384 | Self::RS512 => cfg!(feature = "rsa"),
            Self::ES256 | Self::ES384 | Self::ES512 => cfg!(feature = "ecdsa"),
            Self::EdDSA => false, //TODO: implement cfg!(feature = "ed25519"),
            Self::PS256 | Self::PS384 | Self::PS512 => cfg!(feature = "rsa"),
        }
    }
}

/// A trait to associate an alogritm identifier with an algorithm.
///
/// Algorithm identifiers are used in JWS and JWE to indicate how a token is signed or encrypted.
/// They are set in the [crate::jose::Header] automatically when signing the JWT.
pub trait JsonWebAlgorithm {
    /// The identifier for this algorithm when used in a JWT registered header.
    ///
    /// This is the `alg` field in the JOSE header.
    const IDENTIFIER: AlgorithmIdentifier;
}

/// An object-safe trait to associate an alogritm identifier with an algorithm.
///
/// This is a dynamic version of [`JsonWebAlgorithm`], which allows for
/// dynamic dispatch of the algorithm, and object-safety for the trait.
///
/// This trait does not need to be implemented manually, as it is implemented
/// for any type which implements [`JsonWebAlgorithm`].
pub trait DynJsonWebAlgorithm {
    /// The identifier for this algorithm when used in a JWT registered header.
    fn identifier(&self) -> AlgorithmIdentifier;
}

impl<T> DynJsonWebAlgorithm for T
where
    T: JsonWebAlgorithm,
{
    fn identifier(&self) -> AlgorithmIdentifier {
        T::IDENTIFIER
    }
}

/// A trait to associate an algorithm with a digest for signing.
pub trait JsonWebAlgorithmDigest: JsonWebAlgorithm {
    /// The digest algorithm used by this signature.
    type Digest: Digest;
}

/// A trait to represent an algorithm which can sign a JWT.
///
/// This trait should be implemented by signing keys. It is not designed for direct
/// use by end-users of the JAWS library, rather it is designed to be easily implemented
/// by other [RustCrypto](https://github.com/RustCrypto) crates, such as [`rsa`] or [`ecdsa`].
pub trait TokenSigner<S = SignatureBytes>: DynJsonWebAlgorithm + SerializePublicJWK
where
    S: SignatureEncoding,
{
    /// Sign the contents of the JWT, when provided with the base64url-encoded header
    /// and payload. The header and payload are already serialized to JSON and then
    /// base64url-encoded, so this function should not perform any additional encoding.
    ///
    /// The signature must implement [`SignatureEncoding`], and will be base64url-encoded
    /// and appended to the compact representation of the JWT. Signatures should not be
    /// pre-encoded, rather they should be in a format appropriate for verification.
    ///
    /// This method is not intended to be called directly, rather it is designed to be
    /// easily implemented within the [RustCrypto](https://github.com/RustCrypto) ecosystem.
    ///
    /// To sign a token, use the [`Token::sign`](crate::token::Token::sign) method, which provides the correct wrapping
    /// and format to produce a signed JWT.
    fn try_sign_token(&self, header: &str, payload: &str) -> Result<S, sig::Error>;

    /// Sign the contents of the JWT, when provided with the base64url-encoded header
    /// and payload. See [`TokenSigner::try_sign_token`] for more details.
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
    K: JsonWebAlgorithmDigest + SerializePublicJWK,
    K: sig::DigestSigner<K::Digest, S>,
    S: SignatureEncoding,
{
    fn try_sign_token(&self, header: &str, payload: &str) -> Result<S, sig::Error> {
        let mut digest = <Self as JsonWebAlgorithmDigest>::Digest::new();
        digest.update(header.as_bytes());
        digest.update(b".");
        digest.update(payload.as_bytes());

        self.try_sign_digest(digest)
    }
}

#[cfg(feature = "rand")]
/// A trait to represent an algorithm which can sign a JWT, with a source of
/// randomness.
///
/// This trait should be implemented by signing keys. It is not designed for direct
/// use by end-users of the JAWS library, rather it is designed to be easily implemented
/// by other [RustCrypto](https://github.com/RustCrypto) crates, such as [`rsa`] or [`ecdsa`].
pub trait RandomizedTokenSigner<S = SignatureBytes>:
    DynJsonWebAlgorithm + SerializePublicJWK
where
    S: SignatureEncoding,
{
    /// Sign the contents of the JWT, when provided with the base64url-encoded header
    /// and payload, and a source of randomness. The header and payload are already
    /// serialized to JSON and then base64url-encoded, so this function should not perform
    /// any additional encoding.
    ///
    /// The signature must implement [`SignatureEncoding`], and will be base64url-encoded
    /// and appended to the compact representation of the JWT. Signatures should not be
    /// pre-encoded, rather they should be in a format appropriate for verification.
    ///
    /// This method is not intended to be called directly, rather it is designed to be
    /// easily implemented within the [RustCrypto](https://github.com/RustCrypto) ecosystem.
    ///
    /// To sign a token, use the [`Token::sign_randomized`](crate::token::Token::sign_randomized) method, which provides the correct
    /// wrapping and format to produce a signed JWT.
    fn try_sign_token(
        &self,
        header: &str,
        payload: &str,
        rng: &mut impl CryptoRngCore,
    ) -> Result<S, sig::Error>;

    /// Sign the contents of the JWT, when provided with the base64url-encoded header
    /// and payload. See [`RandomizedTokenSigner::try_sign_token`] for more details.
    ///
    /// # Panics
    ///
    /// This function will panic if the signature cannot be computed.
    fn sign_token(&self, header: &str, payload: &str, rng: &mut impl CryptoRngCore) -> S {
        self.try_sign_token(header, payload, rng).unwrap()
    }
}

/// A trait to represent an algorithm which can verify a JWT.
///
/// This trait should apply to the equivalent of public keys, which have enough information
/// to verify a JWT signature, but not necessarily to sign it. It is designed to be easily
/// implemented by other [RustCrypto](https://github.com/RustCrypto) crates, such as [`rsa`]
/// or [`ecdsa`].
pub trait TokenVerifier<S = SignatureBytes>: DynJsonWebAlgorithm
where
    S: SignatureEncoding,
{
    /// Verify the signature of the JWT, when provided with the base64url-encoded header
    /// and payload, along side the signature. The header and payload are already encoded,
    /// so this function should not perform any additional encoding.
    ///
    /// The signature must implement [`SignatureEncoding`], and will be base64url-encoded
    /// and appended to the compact representation of the JWT. JAWS retains the signature
    /// in the typed form returned by this method to preserve the ability to render the
    /// JWS token.
    fn verify_token(
        &self,
        header: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<S, sig::Error>;
}

impl<K, S> TokenVerifier<S> for K
where
    K: JsonWebAlgorithmDigest + std::fmt::Debug,
    K: sig::DigestVerifier<K::Digest, S>,
    K::Digest: Clone + std::fmt::Debug,
    S: SignatureEncoding + std::fmt::Debug,
    for<'a> <S as TryFrom<&'a [u8]>>::Error: std::error::Error + Send + Sync + 'static,
{
    fn verify_token(
        &self,
        header: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<S, sig::Error> {
        let mut digest = <Self as JsonWebAlgorithmDigest>::Digest::new();
        digest.update(header);
        digest.update(b".");
        digest.update(payload);

        let signature = signature.try_into().map_err(sig::Error::from_source)?;

        self.verify_digest(digest, &signature)?;
        Ok(signature)
    }
}

/// A macro to implement the required traits for common JWS alogorithms.
#[doc(hidden)]
#[macro_export]
macro_rules! jose_algorithm {
    ($alg:ident, $signer:ty, $verifier:ty, $digest:ty, $signature:ty) => {
        impl $crate::algorithms::JsonWebAlgorithm for $signer {
            const IDENTIFIER: $crate::algorithms::AlgorithmIdentifier =
                $crate::algorithms::AlgorithmIdentifier::$alg;
        }

        impl $crate::algorithms::JsonWebAlgorithmDigest for $signer {
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

        impl $crate::algorithms::JsonWebAlgorithm for $verifier {
            const IDENTIFIER: $crate::algorithms::AlgorithmIdentifier =
                $crate::algorithms::AlgorithmIdentifier::$alg;
        }

        impl $crate::algorithms::JsonWebAlgorithmDigest for $verifier {
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

// Make this macro importable
#[cfg(any(feature = "p256", feature = "p384", feature = "p521", feature = "rsa"))]
pub(crate) use jose_algorithm;

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
    sa::assert_obj_safe!(DynJsonWebAlgorithm);
}
