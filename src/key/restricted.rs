use crate::{
    algorithms::{AlgorithmIdentifier, DynJsonWebAlgorithm},
    SignatureBytes, TokenSigner, TokenVerifier,
};

use super::{DynJwkKeyType, KeyType, Parameters, SerializeJWK, SerializePublicJWK};

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
    /// The underlying key.
    pub key: K,

    /// The set of allowed algorithms.
    pub allowed_algorithms: Vec<AlgorithmIdentifier>,
}

impl<K> Restricted<K> {
    /// Creates a K that allows all available algorithms.
    pub fn all(key: K) -> Self {
        Self {
            key,
            allowed_algorithms: crate::algorithms::AVAILABLE_ALGORITHMS
                .iter()
                .copied()
                .collect(),
        }
    }

    /// Creates a K that excludes the `None` algorithm.
    pub fn except_none(key: K) -> Self {
        Self {
            key,
            allowed_algorithms: crate::algorithms::AVAILABLE_ALGORITHMS
                .iter()
                .copied()
                .filter(|a| *a != AlgorithmIdentifier::None)
                .collect(),
        }
    }

    /// Creates a K that only allows asymmetric algorithms.
    pub fn asymmetric(key: K) -> Self {
        Self {
            key,
            allowed_algorithms: crate::algorithms::AVAILABLE_ALGORITHMS
                .iter()
                .copied()
                .filter(|&a| a.is_asymmetric())
                .collect(),
        }
    }
}

impl<K> DynJsonWebAlgorithm for Restricted<K>
where
    K: DynJsonWebAlgorithm,
{
    fn identifier(&self) -> AlgorithmIdentifier {
        self.key.identifier()
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
        if !self
            .allowed_algorithms
            .iter()
            .any(|&a| a == self.identifier())
        {
            return Err(signature::Error::from_source(
                RestrictedAlgorithmError::from(self.identifier()),
            ));
        }

        self.key.verify_token(header, payload, signature)
    }
}

impl<K> DynJwkKeyType for Restricted<K>
where
    K: DynJwkKeyType,
{
    fn key_type(&self) -> KeyType {
        self.key.key_type()
    }
}

impl<K> SerializeJWK for Restricted<K>
where
    K: SerializeJWK,
{
    fn parameters(&self) -> Parameters {
        self.key.parameters()
    }
}

impl<K> SerializePublicJWK for Restricted<K>
where
    K: SerializePublicJWK,
{
    fn public_parameters(&self) -> Parameters {
        self.key.public_parameters()
    }
}

impl<K> TokenSigner for Restricted<K>
where
    K: TokenSigner + DynJwkKeyType,
{
    fn try_sign_token(
        &self,
        header: &str,
        payload: &str,
    ) -> Result<SignatureBytes, signature::Error> {
        if !self
            .allowed_algorithms
            .iter()
            .any(|&a| a == self.identifier())
        {
            return Err(signature::Error::from_source(
                RestrictedAlgorithmError::from(self.identifier()),
            ));
        }

        self.key.try_sign_token(header, payload)
    }
}
