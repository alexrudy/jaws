//! A wrapper around a key that restricts the algorithms that can be used with it.

use crate::{
    algorithms::{AlgorithmIdentifier, DynJsonWebAlgorithm},
    SignatureBytes, TokenSigner, TokenVerifier,
};

use super::{
    DynJwkKeyType, IntoVerifyingKey, JWKSetVerifyError, JwkSet, KeyType, Parameters, SerializeJWK,
    SerializePublicJWK, UnsupportedAlgorithmError, VerifyJWKSet,
};

/// Error when an algorithm is not allowed by the restricted key.
#[derive(Debug, Clone)]
pub struct RestrictedAlgorithmError {
    /// The algorithm that is not allowed.
    pub algorithm: AlgorithmIdentifier,
}

impl From<AlgorithmIdentifier> for RestrictedAlgorithmError {
    fn from(algorithm: AlgorithmIdentifier) -> Self {
        Self { algorithm }
    }
}

impl std::fmt::Display for RestrictedAlgorithmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Algorithm {:?} is not allowed", self.algorithm)
    }
}

impl std::error::Error for RestrictedAlgorithmError {}

/// A Verifying or Signing key that has been restricted to a set of allowed algorithms.
#[derive(Debug, Clone)]
pub struct Restricted<K> {
    /// The underlying key/inner object.
    pub inner: K,

    /// The set of allowed algorithms.
    pub allowed_algorithms: Vec<AlgorithmIdentifier>,
}

impl<K> Restricted<K> {
    /// Creates a K that allows all available algorithms except `None`.
    pub fn all(inner: K) -> Self {
        Self {
            inner,
            allowed_algorithms: crate::algorithms::AVAILABLE_ALGORITHMS
                .iter()
                .copied()
                .filter(|a| *a != AlgorithmIdentifier::None)
                .collect(),
        }
    }

    /// Creates a K that allows all available algorithms, including `None`.
    pub fn insecure(inner: K) -> Self {
        Self {
            inner,
            allowed_algorithms: crate::algorithms::AVAILABLE_ALGORITHMS.to_vec(),
        }
    }

    /// Creates a K that only allows asymmetric algorithms.
    pub fn asymmetric(inner: K) -> Self {
        Self {
            inner,
            allowed_algorithms: crate::algorithms::AVAILABLE_ALGORITHMS
                .iter()
                .copied()
                .filter(|&a| a.is_asymmetric())
                .collect(),
        }
    }

    /// Returns whether the algorithm is supported by this key.
    pub fn supports_algorithm(&self, algorithm: AlgorithmIdentifier) -> bool {
        self.allowed_algorithms.contains(&algorithm)
    }

    /// Validates that the algorithm is supported by this key.
    pub fn validate_algorithm(
        &self,
        algorithm: AlgorithmIdentifier,
    ) -> Result<(), UnsupportedAlgorithmError> {
        if self.supports_algorithm(algorithm) {
            Ok(())
        } else {
            Err(algorithm.into())
        }
    }
}

impl<K> DynJsonWebAlgorithm for Restricted<K>
where
    K: DynJsonWebAlgorithm,
{
    fn identifier(&self) -> AlgorithmIdentifier {
        self.inner.identifier()
    }
}

impl<K> TokenVerifier for Restricted<K>
where
    K: TokenVerifier,
{
    fn verify_token(
        &self,
        header: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<SignatureBytes, signature::Error> {
        if !self.supports_algorithm(self.identifier()) {
            return Err(signature::Error::from_source(
                RestrictedAlgorithmError::from(self.identifier()),
            ));
        }

        self.inner.verify_token(header, payload, signature)
    }
}

impl<K> DynJwkKeyType for Restricted<K>
where
    K: DynJwkKeyType,
{
    fn key_type(&self) -> KeyType {
        self.inner.key_type()
    }
}

impl<K> SerializeJWK for Restricted<K>
where
    K: SerializeJWK,
{
    fn parameters(&self) -> Parameters {
        self.inner.parameters()
    }
}

impl<K> SerializePublicJWK for Restricted<K>
where
    K: SerializePublicJWK,
{
    fn public_parameters(&self) -> Parameters {
        self.inner.public_parameters()
    }
}

impl<K> TokenSigner for Restricted<K>
where
    K: TokenSigner,
{
    fn try_sign_token(
        &self,
        header: &str,
        payload: &str,
    ) -> Result<SignatureBytes, signature::Error> {
        if !self.supports_algorithm(self.identifier()) {
            return Err(signature::Error::from_source(
                RestrictedAlgorithmError::from(self.identifier()),
            ));
        }

        self.inner.try_sign_token(header, payload)
    }
}

impl<K> VerifyJWKSet<K> for Restricted<JwkSet<K>>
where
    K: IntoVerifyingKey + Clone,
{
    fn verify_token_any<P, H, F>(
        &self,
        token: crate::Token<P, crate::token::Unverified<H>, F>,
    ) -> Result<
        crate::Token<P, crate::token::Signed<H, <K as super::IntoVerifyingKey>::Key>, F>,
        super::JWKSetVerifyError<P, H, F>,
    >
    where
        F: crate::token::TokenFormat + 'static,
    {
        if let Err(kind) = self.validate_algorithm(*token.header().algorithm()) {
            return Err(JWKSetVerifyError::new(token, kind.into()));
        }

        self.inner.verify_token_any(token)
    }

    fn verify_token_guess<P, H, F>(
        &self,
        token: crate::Token<P, crate::token::Unverified<H>, F>,
    ) -> Result<
        crate::Token<P, crate::token::Signed<H, <K as super::IntoVerifyingKey>::Key>, F>,
        super::JWKSetVerifyError<P, H, F>,
    >
    where
        F: crate::token::TokenFormat + 'static,
    {
        if let Err(kind) = self.validate_algorithm(*token.header().algorithm()) {
            return Err(JWKSetVerifyError::new(token, kind.into()));
        }

        self.inner.verify_token_guess(token)
    }

    fn verify_token<P, H, F>(
        &self,
        token: crate::Token<P, crate::token::Unverified<H>, F>,
    ) -> Result<
        crate::Token<P, crate::token::Signed<H, <K as super::IntoVerifyingKey>::Key>, F>,
        super::JWKSetVerifyError<P, H, F>,
    >
    where
        F: crate::token::TokenFormat + 'static,
    {
        if let Err(kind) = self.validate_algorithm(*token.header().algorithm()) {
            return Err(JWKSetVerifyError::new(token, kind.into()));
        }

        self.inner.verify_token(token)
    }
}

#[cfg(all(test, feature = "rsa", feature = "none"))]
mod tests {
    use rsa::Generate;

    use crate::{algorithms::none::NoneAlgorithm, key::Identified, Token};

    use super::*;

    #[test]
    fn restricted_allows_allowed_algorithm() {
        let key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::from(rsa::PrivateKey::generate());
        let restricted_key = Restricted::all(key);

        assert!(
            Token::compact((), ()).sign(&restricted_key).is_ok(),
            "signing should succeed with allowed algorithm"
        );
    }

    #[test]
    fn restricted_denies_unsupported_algorithm() {
        let key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::from(rsa::PrivateKey::generate());
        let mut restricted_key = Restricted::all(key);
        restricted_key
            .allowed_algorithms
            .retain(|&a| a != AlgorithmIdentifier::RS256);

        assert!(
            Token::compact((), ()).sign(&restricted_key).is_err(),
            "signing should fail with unsupported algorithm"
        );
    }

    #[test]
    fn restricted_all_denies_none() {
        let key = Restricted::all(NoneAlgorithm);

        assert!(
            Token::compact((), ()).sign(&key).is_err(),
            "signing should fail with None algorithm"
        );
    }

    #[test]
    fn restricted_denies_none_jwks() {
        let keyset: JwkSet<NoneAlgorithm> = [Identified::unidentified(NoneAlgorithm)]
            .into_iter()
            .collect();

        let token: Token<(), crate::token::Unverified<()>> = Token::compact((), ())
            .sign(&NoneAlgorithm)
            .unwrap()
            .unverify();

        assert!(
            keyset.verify_token_any(token.clone()).is_ok(),
            "signing should succeed with None algorithm"
        );

        let restricted_keyset = Restricted::all(keyset);

        assert!(
            restricted_keyset.verify_token_any(token).is_err(),
            "signing should fail with None algorithm"
        );
    }
}
