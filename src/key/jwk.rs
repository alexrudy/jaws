//! JWK key types for deserializing from a JSON Web Key (JWK)

use serde::{Deserialize, Serialize};
#[cfg(feature = "rsa")]
use sha2::Digest;
use signature::Keypair;

#[cfg(feature = "ecdsa")]
use crate::algorithms::ecdsa::{JWEcSigningKey, JWEcVerifyingKey};
#[cfg(feature = "hmac")]
use crate::algorithms::hmac::{Hmac, HmacKey};
#[cfg(feature = "none")]
use crate::algorithms::none::NoneAlgorithm;
#[cfg(feature = "rand")]
use crate::algorithms::RandomizedTokenSigner;
use crate::{
    algorithms::{AlgorithmIdentifier, DynJsonWebAlgorithm},
    SignatureBytes, TokenSigner, TokenVerifier,
};

use super::{DeserializeJWK, DynJwkKeyType, JsonWebKeyError, KeyType, Parameters, SerializeJWK};

/// A concrete key type that can be used to deserialize from a JWK
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
#[serde(tag = "kty")]
pub enum PrivateWebKey {
    #[cfg(feature = "hmac")]
    #[serde(rename = "oct")]
    /// Hash-based Message Authentication Code using SHA-256
    HMac(#[serde(with = "self::serde_keys")] HmacKey),

    #[cfg(feature = "rsa")]
    #[serde(rename = "RSA")]
    /// RSA Key
    Rsa(#[serde(with = "self::serde_keys")] rsa::PrivateKey),

    #[cfg(feature = "ecdsa")]
    #[serde(rename = "EC")]
    /// ECDSA Key
    EcDsa(#[serde(with = "self::serde_keys")] crate::algorithms::ecdsa::JWEcSigningKey),

    #[cfg(feature = "ed25519")]
    /// EdDSA using Ed25519
    EdDSA,
}

#[cfg(feature = "hmac")]
impl From<HmacKey> for PrivateWebKey {
    fn from(key: HmacKey) -> Self {
        PrivateWebKey::HMac(key)
    }
}

#[cfg(feature = "hmac")]
impl<D> From<Hmac<D>> for PrivateWebKey {
    fn from(key: Hmac<D>) -> Self {
        PrivateWebKey::HMac(key.into())
    }
}

#[cfg(feature = "rsa")]
impl From<rsa::PrivateKey> for PrivateWebKey {
    fn from(key: rsa::PrivateKey) -> Self {
        PrivateWebKey::Rsa(key)
    }
}

#[cfg(feature = "rsa")]
impl<D> From<rsa::pkcs1v15::SigningKey<D>> for PrivateWebKey
where
    D: Digest,
{
    fn from(key: rsa::pkcs1v15::SigningKey<D>) -> Self {
        PrivateWebKey::Rsa(rsa::PrivateKey::from(key))
    }
}

#[cfg(feature = "pss")]
impl<D> From<rsa::pss::SigningKey<D>> for PrivateWebKey
where
    D: Digest,
{
    fn from(key: rsa::pss::SigningKey<D>) -> Self {
        PrivateWebKey::Rsa(rsa::PrivateKey::from(key))
    }
}

#[cfg(feature = "ecdsa")]
impl From<crate::algorithms::ecdsa::JWEcSigningKey> for PrivateWebKey {
    fn from(key: crate::algorithms::ecdsa::JWEcSigningKey) -> Self {
        PrivateWebKey::EcDsa(key)
    }
}

#[cfg(all(feature = "ecdsa", feature = "p256"))]
impl From<ecdsa::SigningKey<p256::NistP256>> for PrivateWebKey {
    fn from(key: ecdsa::SigningKey<p256::NistP256>) -> Self {
        PrivateWebKey::EcDsa(key.into())
    }
}

#[cfg(all(feature = "ecdsa", feature = "p384"))]
impl From<ecdsa::SigningKey<p384::NistP384>> for PrivateWebKey {
    fn from(key: ecdsa::SigningKey<p384::NistP384>) -> Self {
        PrivateWebKey::EcDsa(key.into())
    }
}

#[cfg(all(feature = "ecdsa", feature = "p521"))]
impl From<ecdsa::SigningKey<p521::NistP521>> for PrivateWebKey {
    fn from(key: ecdsa::SigningKey<p521::NistP521>) -> Self {
        PrivateWebKey::EcDsa(key.into())
    }
}

impl PrivateWebKey {
    /// Returns whether this key supports the given algorithm.
    pub fn supports_algorithm(&self, algorithm: AlgorithmIdentifier) -> bool {
        match (self, algorithm) {
            #[cfg(feature = "hmac")]
            (Self::HMac(_), AlgorithmIdentifier::HS256) => true,
            #[cfg(feature = "hmac")]
            (Self::HMac(_), AlgorithmIdentifier::HS384) => true,
            #[cfg(feature = "hmac")]
            (Self::HMac(_), AlgorithmIdentifier::HS512) => true,
            #[cfg(feature = "rsa")]
            (Self::Rsa(_), AlgorithmIdentifier::RS256) => true,
            #[cfg(feature = "rsa")]
            (Self::Rsa(_), AlgorithmIdentifier::RS384) => true,
            #[cfg(feature = "rsa")]
            (Self::Rsa(_), AlgorithmIdentifier::RS512) => true,
            #[cfg(feature = "ecdsa")]
            (Self::EcDsa(_), AlgorithmIdentifier::ES256) => true,
            #[cfg(feature = "ecdsa")]
            (Self::EcDsa(_), AlgorithmIdentifier::ES384) => true,
            #[cfg(feature = "ecdsa")]
            (Self::EcDsa(_), AlgorithmIdentifier::ES512) => true,
            #[cfg(feature = "pss")]
            (Self::Rsa(_), AlgorithmIdentifier::PS256) => true,
            #[cfg(feature = "pss")]
            (Self::Rsa(_), AlgorithmIdentifier::PS384) => true,
            #[cfg(feature = "pss")]
            (Self::Rsa(_), AlgorithmIdentifier::PS512) => true,
            #[cfg(feature = "ed25519")]
            (Self::EdDSA, AlgorithmIdentifier::EdDSA) => true,
            _ => false,
        }
    }

    /// Converts this key into a [`SigningWebKey`] for the given algorithm.
    pub fn into_algorithm(
        self,
        algorithm: AlgorithmIdentifier,
    ) -> Result<SigningWebKey, JsonWebKeyError> {
        match (self, algorithm) {
            #[cfg(feature = "hmac")]
            (Self::HMac(h), AlgorithmIdentifier::HS256) => Ok(SigningWebKey::HS256(h.into())),
            #[cfg(feature = "hmac")]
            (Self::HMac(h), AlgorithmIdentifier::HS384) => Ok(SigningWebKey::HS384(h.into())),
            #[cfg(feature = "hmac")]
            (Self::HMac(h), AlgorithmIdentifier::HS512) => Ok(SigningWebKey::HS512(h.into())),
            #[cfg(feature = "rsa")]
            (Self::Rsa(k), AlgorithmIdentifier::RS256) => Ok(SigningWebKey::RS256(k.into())),
            #[cfg(feature = "rsa")]
            (Self::Rsa(k), AlgorithmIdentifier::RS384) => Ok(SigningWebKey::RS384(k.into())),
            #[cfg(feature = "rsa")]
            (Self::Rsa(k), AlgorithmIdentifier::RS512) => Ok(SigningWebKey::RS512(k.into())),
            #[cfg(all(feature = "ecdsa", feature = "p256"))]
            (Self::EcDsa(JWEcSigningKey::P256(k)), AlgorithmIdentifier::ES256) => {
                Ok(SigningWebKey::ES256(k))
            }
            #[cfg(all(feature = "ecdsa", feature = "p384"))]
            (Self::EcDsa(JWEcSigningKey::P384(k)), AlgorithmIdentifier::ES384) => {
                Ok(SigningWebKey::ES384(k))
            }
            #[cfg(all(feature = "ecdsa", feature = "p521"))]
            (Self::EcDsa(JWEcSigningKey::P521(k)), AlgorithmIdentifier::ES512) => {
                Ok(SigningWebKey::ES512(k))
            }
            #[cfg(feature = "none")]
            (_, AlgorithmIdentifier::None) => Ok(SigningWebKey::None),

            #[allow(unreachable_patterns)]
            (_, alg) => Err(JsonWebKeyError::UnsupportedAlgorithm(alg)),
        }
    }
}

impl Keypair for PrivateWebKey {
    type VerifyingKey = PublicWebKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        match self {
            #[cfg(feature = "hmac")]
            Self::HMac(hmac) => PublicWebKey::HMac(hmac.clone()),
            #[cfg(feature = "rsa")]
            Self::Rsa(rsa) => PublicWebKey::Rsa(rsa.to_public_key()),
            #[cfg(feature = "ecdsa")]
            Self::EcDsa(ecdsa) => PublicWebKey::EcDsa(ecdsa.verifying_key().clone()),
            #[cfg(feature = "ed25519")]
            Self::EdDSA => PublicWebKey::EdDSA,
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }
}

impl DynJwkKeyType for PrivateWebKey {
    fn key_type(&self) -> KeyType {
        match self {
            #[cfg(feature = "hmac")]
            Self::HMac(_) => KeyType::Octet,
            #[cfg(feature = "rsa")]
            Self::Rsa(_) => KeyType::Rsa,
            #[cfg(feature = "ecdsa")]
            Self::EcDsa(_) => KeyType::EllipticCurve,
            #[cfg(feature = "ed25519")]
            Self::EdDSA => unimplemented!(),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }
}

impl SerializeJWK for PrivateWebKey {
    fn parameters(&self) -> Parameters {
        #[cfg(any(feature = "hmac", feature = "rsa", feature = "ecdsa"))]
        {
            let mut params = match self {
                #[cfg(feature = "hmac")]
                Self::HMac(hmac) => hmac.parameters(),
                #[cfg(feature = "rsa")]
                Self::Rsa(signing_key) => signing_key.parameters(),
                #[cfg(feature = "ecdsa")]
                Self::EcDsa(signing_key) => signing_key.parameters(),
                #[cfg(feature = "ed25519")]
                Self::EdDSA => unimplemented!(),
                #[allow(unreachable_patterns)]
                _ => unimplemented!(),
            };

            params
                .insert("kty", self.key_type())
                .expect("Serialize kty to JSON");
            params
        }
        #[cfg(not(any(feature = "hmac", feature = "rsa", feature = "ecdsa")))]
        {
            panic!("No JWK parameters for algorithm 'none'")
        }
    }
}

impl DeserializeJWK for PrivateWebKey {
    fn build(parameters: Parameters) -> Result<Self, JsonWebKeyError> {
        let kty = parameters.get("kty").cloned();
        match kty.as_ref().and_then(|k| k.as_str()) {
            #[cfg(feature = "hmac")]
            Some("oct") => Ok(Self::HMac(HmacKey::build(parameters)?)),
            #[cfg(feature = "rsa")]
            Some("RSA") => Ok(Self::Rsa(rsa::PrivateKey::build(parameters)?)),
            #[cfg(feature = "ecdsa")]
            Some("EC") => Ok(Self::EcDsa(
                crate::algorithms::ecdsa::JWEcSigningKey::build(parameters)?,
            )),
            _ => Err(JsonWebKeyError::UnsupportedKeyType(
                kty.as_ref()
                    .and_then(|k| k.as_str())
                    .ok_or_else(|| JsonWebKeyError::MissingParameter("kty"))?
                    .into(),
            )),
        }
    }
}

/// A concrete key type that can be used to sign JWTs
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
#[serde(tag = "kty")]
pub enum PublicWebKey {
    #[cfg(feature = "hmac")]
    #[serde(rename = "oct")]
    /// Hash-based Message Authentication Code using SHA-256
    HMac(#[serde(with = "self::serde_keys")] HmacKey),

    #[cfg(feature = "rsa")]
    #[serde(rename = "RSA")]
    /// RSA Key
    Rsa(#[serde(with = "self::serde_keys")] rsa::PublicKey),

    #[cfg(feature = "ecdsa")]
    #[serde(rename = "EC")]
    /// ECDSA Key
    EcDsa(#[serde(with = "self::serde_keys")] crate::algorithms::ecdsa::JWEcVerifyingKey),

    #[cfg(feature = "ed25519")]
    /// EdDSA using Ed25519
    EdDSA,
}

#[cfg(feature = "hmac")]
impl From<HmacKey> for PublicWebKey {
    fn from(key: HmacKey) -> Self {
        PublicWebKey::HMac(key)
    }
}

#[cfg(feature = "hmac")]
impl<D> From<Hmac<D>> for PublicWebKey {
    fn from(key: Hmac<D>) -> Self {
        PublicWebKey::HMac(key.into())
    }
}

#[cfg(feature = "rsa")]
impl From<rsa::PublicKey> for PublicWebKey {
    fn from(key: rsa::PublicKey) -> Self {
        PublicWebKey::Rsa(key)
    }
}

#[cfg(feature = "rsa")]
impl<D> From<rsa::pkcs1v15::VerifyingKey<D>> for PublicWebKey
where
    D: Digest,
{
    fn from(key: rsa::pkcs1v15::VerifyingKey<D>) -> Self {
        PublicWebKey::Rsa(rsa::PublicKey::from(key))
    }
}

#[cfg(feature = "pss")]
impl<D> From<rsa::pss::VerifyingKey<D>> for PublicWebKey
where
    D: Digest,
{
    fn from(key: rsa::pss::VerifyingKey<D>) -> Self {
        PublicWebKey::Rsa(rsa::PublicKey::from(key))
    }
}

#[cfg(feature = "ecdsa")]
impl From<crate::algorithms::ecdsa::JWEcVerifyingKey> for PublicWebKey {
    fn from(key: crate::algorithms::ecdsa::JWEcVerifyingKey) -> Self {
        PublicWebKey::EcDsa(key)
    }
}

#[cfg(all(feature = "ecdsa", feature = "p256"))]
impl From<ecdsa::VerifyingKey<p256::NistP256>> for PublicWebKey {
    fn from(key: ecdsa::VerifyingKey<p256::NistP256>) -> Self {
        PublicWebKey::EcDsa(key.into())
    }
}

#[cfg(all(feature = "ecdsa", feature = "p384"))]
impl From<ecdsa::VerifyingKey<p384::NistP384>> for PublicWebKey {
    fn from(key: ecdsa::VerifyingKey<p384::NistP384>) -> Self {
        PublicWebKey::EcDsa(key.into())
    }
}

#[cfg(all(feature = "ecdsa", feature = "p521"))]
impl From<ecdsa::VerifyingKey<p521::NistP521>> for PublicWebKey {
    fn from(key: ecdsa::VerifyingKey<p521::NistP521>) -> Self {
        PublicWebKey::EcDsa(key.into())
    }
}

impl PublicWebKey {
    /// Returns whether this public key supports the given algorithm
    pub fn supports_algorithm(&self, algorithm: AlgorithmIdentifier) -> bool {
        match (self, algorithm) {
            #[cfg(feature = "hmac")]
            (Self::HMac(_), AlgorithmIdentifier::HS256) => true,
            #[cfg(feature = "hmac")]
            (Self::HMac(_), AlgorithmIdentifier::HS384) => true,
            #[cfg(feature = "hmac")]
            (Self::HMac(_), AlgorithmIdentifier::HS512) => true,
            #[cfg(feature = "rsa")]
            (Self::Rsa(_), AlgorithmIdentifier::RS256) => true,
            #[cfg(feature = "rsa")]
            (Self::Rsa(_), AlgorithmIdentifier::RS384) => true,
            #[cfg(feature = "rsa")]
            (Self::Rsa(_), AlgorithmIdentifier::RS512) => true,
            #[cfg(feature = "ecdsa")]
            (Self::EcDsa(_), AlgorithmIdentifier::ES256) => true,
            #[cfg(feature = "ecdsa")]
            (Self::EcDsa(_), AlgorithmIdentifier::ES384) => true,
            #[cfg(feature = "ecdsa")]
            (Self::EcDsa(_), AlgorithmIdentifier::ES512) => true,
            #[cfg(feature = "pss")]
            (Self::Rsa(_), AlgorithmIdentifier::PS256) => true,
            #[cfg(feature = "pss")]
            (Self::Rsa(_), AlgorithmIdentifier::PS384) => true,
            #[cfg(feature = "pss")]
            (Self::Rsa(_), AlgorithmIdentifier::PS512) => true,
            #[cfg(feature = "ed25519")]
            (Self::EdDSA, AlgorithmIdentifier::EdDSA) => true,
            _ => false,
        }
    }

    /// Converts this public key into a verifying key for the given algorithm
    pub fn into_algorithm(
        self,
        algorithm: AlgorithmIdentifier,
    ) -> Result<VerifyingWebKey, JsonWebKeyError> {
        match (self, algorithm) {
            #[cfg(feature = "hmac")]
            (Self::HMac(h), AlgorithmIdentifier::HS256) => Ok(VerifyingWebKey::HS256(h.into())),
            #[cfg(feature = "hmac")]
            (Self::HMac(h), AlgorithmIdentifier::HS384) => Ok(VerifyingWebKey::HS384(h.into())),
            #[cfg(feature = "hmac")]
            (Self::HMac(h), AlgorithmIdentifier::HS512) => Ok(VerifyingWebKey::HS512(h.into())),
            #[cfg(feature = "rsa")]
            (Self::Rsa(k), AlgorithmIdentifier::RS256) => Ok(VerifyingWebKey::RS256(k.into())),
            #[cfg(feature = "rsa")]
            (Self::Rsa(k), AlgorithmIdentifier::RS384) => Ok(VerifyingWebKey::RS384(k.into())),
            #[cfg(feature = "rsa")]
            (Self::Rsa(k), AlgorithmIdentifier::RS512) => Ok(VerifyingWebKey::RS512(k.into())),
            #[cfg(all(feature = "ecdsa", feature = "p256"))]
            (Self::EcDsa(JWEcVerifyingKey::P256(k)), AlgorithmIdentifier::ES256) => {
                Ok(VerifyingWebKey::ES256(k))
            }
            #[cfg(all(feature = "ecdsa", feature = "p384"))]
            (Self::EcDsa(JWEcVerifyingKey::P384(k)), AlgorithmIdentifier::ES384) => {
                Ok(VerifyingWebKey::ES384(k))
            }
            #[cfg(all(feature = "ecdsa", feature = "p521"))]
            (Self::EcDsa(JWEcVerifyingKey::P521(k)), AlgorithmIdentifier::ES512) => {
                Ok(VerifyingWebKey::ES512(k))
            }

            #[allow(unreachable_patterns)]
            (_, alg) => Err(JsonWebKeyError::UnsupportedAlgorithm(alg)),
        }
    }
}

impl DynJwkKeyType for PublicWebKey {
    fn key_type(&self) -> KeyType {
        match self {
            #[cfg(feature = "hmac")]
            Self::HMac(_) => KeyType::Octet,
            #[cfg(feature = "rsa")]
            Self::Rsa(_) => KeyType::Rsa,
            #[cfg(feature = "ecdsa")]
            Self::EcDsa(_) => KeyType::EllipticCurve,
            #[cfg(feature = "ed25519")]
            Self::EdDSA => unimplemented!(),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }
}

impl DeserializeJWK for PublicWebKey {
    fn build(parameters: Parameters) -> Result<Self, JsonWebKeyError> {
        let kty = parameters.get("kty").cloned();
        match kty.as_ref().and_then(|k| k.as_str()) {
            #[cfg(feature = "hmac")]
            Some("oct") => Ok(Self::HMac(HmacKey::build(parameters)?)),
            #[cfg(feature = "rsa")]
            Some("RSA") => Ok(Self::Rsa(rsa::PublicKey::build(parameters)?)),
            #[cfg(feature = "ecdsa")]
            Some("EC") => Ok(Self::EcDsa(
                crate::algorithms::ecdsa::JWEcVerifyingKey::build(parameters)?,
            )),
            _ => Err(JsonWebKeyError::UnsupportedKeyType(
                kty.as_ref()
                    .and_then(|k| k.as_str())
                    .ok_or_else(|| JsonWebKeyError::MissingParameter("kty"))?
                    .into(),
            )),
        }
    }
}

impl SerializeJWK for PublicWebKey {
    fn parameters(&self) -> Parameters {
        #[cfg(any(feature = "hmac", feature = "rsa", feature = "ecdsa"))]
        {
            let mut parameters = match self {
                #[cfg(feature = "hmac")]
                PublicWebKey::HMac(hmac_key) => hmac_key.parameters(),
                #[cfg(feature = "rsa")]
                PublicWebKey::Rsa(public_key) => public_key.parameters(),
                #[cfg(feature = "ecdsa")]
                PublicWebKey::EcDsa(jwec_verifying_key) => jwec_verifying_key.parameters(),
                #[cfg(feature = "ed25519")]
                PublicWebKey::EdDSA => unimplemented!(),
            };

            parameters
                .insert("kty", self.key_type())
                .expect("kty is valid JSON");
            parameters
        }
        #[cfg(not(any(feature = "hmac", feature = "rsa", feature = "ecdsa")))]
        {
            panic!("No JWK parameters for algorithm 'none'")
        }
    }
}

macro_rules! dispatch {

    ($type:tt: $driver:ident.$method:ident($($args:expr),*) eddsa($eddsa:expr) none($none:expr)) => {
        match $driver {
            #[cfg(feature = "hmac")]
            $type::HS256(hmac) => hmac.$method($($args),*),
            #[cfg(feature = "hmac")]
            $type::HS384(hmac) => hmac.$method($($args),*),
            #[cfg(feature = "hmac")]
            $type::HS512(hmac) => hmac.$method($($args),*),
            #[cfg(feature = "rsa")]
            $type::RS256(signing_key) => signing_key.$method($($args),*),
            #[cfg(feature = "rsa")]
            $type::RS384(signing_key) => signing_key.$method($($args),*),
            #[cfg(feature = "rsa")]
            $type::RS512(signing_key) => signing_key.$method($($args),*),
            #[cfg(all(feature = "ecdsa", feature = "p256"))]
            $type::ES256(signing_key) => signing_key.$method($($args),*),
            #[cfg(all(feature = "ecdsa", feature = "p384"))]
            $type::ES384(signing_key) => signing_key.$method($($args),*),
            #[cfg(all(feature = "ecdsa", feature = "p521"))]
            $type::ES512(signing_key) => signing_key.$method($($args),*),
            #[cfg(feature = "pss")]
            $type::PS256(signing_key) => signing_key.$method($($args),*),
            #[cfg(feature = "pss")]
            $type::PS384(signing_key) => signing_key.$method($($args),*),
            #[cfg(feature = "pss")]
            $type::PS512(signing_key) => signing_key.$method($($args),*),
            #[cfg(feature = "ed25519")]
            $type::EdDSA => $eddsa,
            #[cfg(feature = "none")]
            $type::None => $none,
            #[allow(unreachable_patterns)]
            _ => unimplemented!()
        }
    };
    ($type:tt: $driver:ident Ok($method:ident($($args:expr),*)) eddsa($eddsa:expr) none($none:expr)) => {
        match $driver {
            #[cfg(feature = "hmac")]
            $type::HS256(hmac) => Ok(hmac.$method($($args),*)),
            #[cfg(feature = "hmac")]
            $type::HS384(hmac) => Ok(hmac.$method($($args),*)),
            #[cfg(feature = "hmac")]
            $type::HS512(hmac) => Ok(hmac.$method($($args),*)),
            #[cfg(feature = "rsa")]
            $type::RS256(signing_key) => Ok(signing_key.$method($($args),*)),
            #[cfg(feature = "rsa")]
            $type::RS384(signing_key) => Ok(signing_key.$method($($args),*)),
            #[cfg(feature = "rsa")]
            $type::RS512(signing_key) => Ok(signing_key.$method($($args),*)),
            #[cfg(all(feature = "ecdsa", feature = "p256"))]
            $type::ES256(signing_key) => Ok(signing_key.$method($($args),*)),
            #[cfg(all(feature = "ecdsa", feature = "p384"))]
            $type::ES384(signing_key) => Ok(signing_key.$method($($args),*)),
            #[cfg(all(feature = "ecdsa", feature = "p521"))]
            $type::ES512(signing_key) => Ok(signing_key.$method($($args),*)),
            #[cfg(feature = "pss")]
            $type::PS256(signing_key) => Ok(signing_key.$method($($args),*)),
            #[cfg(feature = "pss")]
            $type::PS384(signing_key) => Ok(signing_key.$method($($args),*)),
            #[cfg(feature = "pss")]
            $type::PS512(signing_key) => Ok(signing_key.$method($($args),*)),
            #[cfg(feature = "ed25519")]
            $type::EdDSA => $eddsa,
            #[cfg(feature = "none")]
            $type::None => $none,
            #[allow(unreachable_patterns)]
            _ => unimplemented!()
        }
    };

    ($type:tt: $driver:ident.$method:ident($($args:expr),*) eddsa($eddsa:expr)) => {
        dispatch!($type: $driver.$method($($args),*) eddsa($eddsa) none(NoneAlgorithm.$method($($args),*)))
    };
    ($type:tt: $driver:ident Ok($method:ident($($args:expr),*)) eddsa($eddsa:expr)) => {
        dispatch!($type: $driver Ok($method($($args),*)) eddsa($eddsa) none(NoneAlgorithm.$method($($args),*)))
    };

    ($driver:ident Ok($method:ident($($args:expr),*)) eddsa($eddsa:expr) ) => {
        dispatch!(Self: $driver Ok($method($($args),*)) eddsa($eddsa))
    };

    ($driver:ident.$method:ident($($args:expr),*) eddsa($eddsa:expr) ) => {
        dispatch!(Self: $driver.$method($($args),*) eddsa($eddsa))
    };

    ($driver:ident.$method:ident($($args:expr),*)) => {
        dispatch!($driver.$method($($args),*) eddsa(unimplemented!("EdDSA is not supported")))
    }
}

/// A concrete key type that can be used to sign JWTs
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub enum SigningWebKey {
    #[cfg(feature = "hmac")]
    /// Hash-based Message Authentication Code using SHA-256
    HS256(#[serde(with = "self::serde_sigs")] Hmac<sha2::Sha256>),

    #[cfg(feature = "hmac")]
    /// Hash-based Message Authentication Code using SHA-384
    HS384(#[serde(with = "self::serde_sigs")] Hmac<sha2::Sha384>),

    #[cfg(feature = "hmac")]
    /// Hash-based Message Authentication Code using SHA-512
    HS512(#[serde(with = "self::serde_sigs")] Hmac<sha2::Sha512>),

    #[cfg(feature = "rsa")]
    /// RSA PKCS#1 v1.5 signature using SHA-256
    RS256(#[serde(with = "self::serde_sigs")] rsa::pkcs1v15::SigningKey<sha2::Sha256>),

    #[cfg(feature = "rsa")]
    /// RSA PKCS#1 v1.5 signature using SHA-348
    RS384(#[serde(with = "self::serde_sigs")] rsa::pkcs1v15::SigningKey<sha2::Sha384>),

    #[cfg(feature = "rsa")]
    /// RSA PKCS#1 v1.5 signature using SHA-512
    RS512(#[serde(with = "self::serde_sigs")] rsa::pkcs1v15::SigningKey<sha2::Sha512>),

    #[cfg(all(feature = "ecdsa", feature = "p256"))]
    /// ECDSA using P-256 and SHA-256
    ES256(#[serde(with = "self::serde_sigs")] ecdsa::SigningKey<p256::NistP256>),

    #[cfg(all(feature = "ecdsa", feature = "p384"))]
    /// ECDSA using P-384 and SHA-384
    ES384(#[serde(with = "self::serde_sigs")] ecdsa::SigningKey<p384::NistP384>),

    #[cfg(all(feature = "ecdsa", feature = "p521"))]
    /// ECDSA using P-521 and SHA-512
    ES512(#[serde(with = "self::serde_sigs")] ecdsa::SigningKey<p521::NistP521>),

    #[cfg(feature = "pss")]
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    PS256(#[serde(with = "self::serde_sigs")] rsa::pss::SigningKey<sha2::Sha256>),

    #[cfg(feature = "pss")]
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    PS384(#[serde(with = "self::serde_sigs")] rsa::pss::SigningKey<sha2::Sha384>),

    #[cfg(feature = "pss")]
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    PS512(#[serde(with = "self::serde_sigs")] rsa::pss::SigningKey<sha2::Sha512>),

    #[cfg(feature = "ed25519")]
    /// EdDSA using Ed25519
    EdDSA,

    #[cfg(feature = "none")]
    /// No signature
    None,
}

impl TryFrom<SigningWebKey> for PrivateWebKey {
    type Error = JsonWebKeyError;

    fn try_from(value: SigningWebKey) -> Result<Self, Self::Error> {
        dispatch!(SigningWebKey: value Ok(into()) eddsa(Ok(PrivateWebKey::EdDSA)) none(Err(JsonWebKeyError::UnsupportedAlgorithm(AlgorithmIdentifier::None))))
    }
}

#[cfg(feature = "hmac")]
impl From<Hmac<sha2::Sha256>> for SigningWebKey {
    fn from(key: Hmac<sha2::Sha256>) -> Self {
        Self::HS256(key)
    }
}

#[cfg(feature = "hmac")]
impl From<Hmac<sha2::Sha384>> for SigningWebKey {
    fn from(key: Hmac<sha2::Sha384>) -> Self {
        Self::HS384(key)
    }
}

#[cfg(feature = "hmac")]
impl From<Hmac<sha2::Sha512>> for SigningWebKey {
    fn from(key: Hmac<sha2::Sha512>) -> Self {
        Self::HS512(key)
    }
}

#[cfg(feature = "rsa")]
impl From<rsa::pkcs1v15::SigningKey<sha2::Sha256>> for SigningWebKey {
    fn from(key: rsa::pkcs1v15::SigningKey<sha2::Sha256>) -> Self {
        Self::RS256(key)
    }
}

#[cfg(feature = "rsa")]
impl From<rsa::pkcs1v15::SigningKey<sha2::Sha384>> for SigningWebKey {
    fn from(key: rsa::pkcs1v15::SigningKey<sha2::Sha384>) -> Self {
        Self::RS384(key)
    }
}

#[cfg(feature = "rsa")]
impl From<rsa::pkcs1v15::SigningKey<sha2::Sha512>> for SigningWebKey {
    fn from(key: rsa::pkcs1v15::SigningKey<sha2::Sha512>) -> Self {
        Self::RS512(key)
    }
}

#[cfg(all(feature = "ecdsa", feature = "p256"))]
impl From<ecdsa::SigningKey<p256::NistP256>> for SigningWebKey {
    fn from(key: ecdsa::SigningKey<p256::NistP256>) -> Self {
        Self::ES256(key)
    }
}

#[cfg(all(feature = "ecdsa", feature = "p384"))]
impl From<ecdsa::SigningKey<p384::NistP384>> for SigningWebKey {
    fn from(key: ecdsa::SigningKey<p384::NistP384>) -> Self {
        Self::ES384(key)
    }
}

#[cfg(all(feature = "ecdsa", feature = "p521"))]
impl From<ecdsa::SigningKey<p521::NistP521>> for SigningWebKey {
    fn from(key: ecdsa::SigningKey<p521::NistP521>) -> Self {
        Self::ES512(key)
    }
}

#[cfg(feature = "pss")]
impl From<rsa::pss::SigningKey<sha2::Sha256>> for SigningWebKey {
    fn from(key: rsa::pss::SigningKey<sha2::Sha256>) -> Self {
        Self::PS256(key)
    }
}

#[cfg(feature = "pss")]
impl From<rsa::pss::SigningKey<sha2::Sha384>> for SigningWebKey {
    fn from(key: rsa::pss::SigningKey<sha2::Sha384>) -> Self {
        Self::PS384(key)
    }
}

#[cfg(feature = "pss")]
impl From<rsa::pss::SigningKey<sha2::Sha512>> for SigningWebKey {
    fn from(key: rsa::pss::SigningKey<sha2::Sha512>) -> Self {
        Self::PS512(key)
    }
}

impl Keypair for SigningWebKey {
    type VerifyingKey = VerifyingWebKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        match self {
            #[cfg(feature = "hmac")]
            SigningWebKey::HS256(hmac) => VerifyingWebKey::HS256(hmac.clone()),
            #[cfg(feature = "hmac")]
            SigningWebKey::HS384(hmac) => VerifyingWebKey::HS384(hmac.clone()),
            #[cfg(feature = "hmac")]
            SigningWebKey::HS512(hmac) => VerifyingWebKey::HS512(hmac.clone()),
            #[cfg(feature = "rsa")]
            SigningWebKey::RS256(signing_key) => {
                VerifyingWebKey::RS256(signing_key.verifying_key())
            }
            #[cfg(feature = "rsa")]
            SigningWebKey::RS384(signing_key) => {
                VerifyingWebKey::RS384(signing_key.verifying_key())
            }
            #[cfg(feature = "rsa")]
            SigningWebKey::RS512(signing_key) => {
                VerifyingWebKey::RS512(signing_key.verifying_key())
            }
            #[cfg(all(feature = "ecdsa", feature = "p256"))]
            SigningWebKey::ES256(signing_key) => {
                VerifyingWebKey::ES256(*signing_key.verifying_key())
            }
            #[cfg(all(feature = "ecdsa", feature = "p384"))]
            SigningWebKey::ES384(signing_key) => {
                VerifyingWebKey::ES384(*signing_key.verifying_key())
            }
            #[cfg(all(feature = "ecdsa", feature = "p521"))]
            SigningWebKey::ES512(signing_key) => {
                VerifyingWebKey::ES512(*signing_key.verifying_key())
            }
            #[cfg(feature = "pss")]
            SigningWebKey::PS256(signing_key) => {
                VerifyingWebKey::PS256(signing_key.verifying_key())
            }
            #[cfg(feature = "pss")]
            SigningWebKey::PS384(signing_key) => {
                VerifyingWebKey::PS384(signing_key.verifying_key())
            }
            #[cfg(feature = "pss")]
            SigningWebKey::PS512(signing_key) => {
                VerifyingWebKey::PS512(signing_key.verifying_key())
            }
            #[cfg(feature = "ed25519")]
            SigningWebKey::EdDSA => todo!(),

            #[cfg(feature = "none")]
            SigningWebKey::None => VerifyingWebKey::None,
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }
}

impl DynJsonWebAlgorithm for SigningWebKey {
    fn identifier(&self) -> AlgorithmIdentifier {
        dispatch!(self.identifier() eddsa(AlgorithmIdentifier::EdDSA))
    }
}

impl DynJwkKeyType for SigningWebKey {
    fn key_type(&self) -> KeyType {
        dispatch!(self.key_type() eddsa(unimplemented!("EdDSA is not supported")))
    }
}

impl SerializeJWK for SigningWebKey {
    fn parameters(&self) -> Parameters {
        #[cfg(any(feature = "hmac", feature = "rsa", feature = "ecdsa"))]
        {
            let mut params: Parameters = dispatch!(self.parameters());
            params
                .insert("alg", self.identifier())
                .expect("alg is valid JSON");
            params
                .insert("kty", self.key_type())
                .expect("kty is valid JSON");

            params
        }
        #[cfg(not(any(feature = "hmac", feature = "rsa", feature = "ecdsa")))]
        {
            panic!("No JWK parameters for algorithm 'none'")
        }
    }
}

#[cfg(feature = "rand")]
impl RandomizedTokenSigner<SignatureBytes> for SigningWebKey {
    #[cfg_attr(
        not(any(
            feature = "hmac",
            feature = "rsa",
            feature = "p256",
            feature = "p384",
            feature = "p521"
        )),
        expect(unused_variables)
    )]
    fn try_sign_token(
        &self,
        header: &str,
        payload: &str,

        #[cfg_attr(not(feature = "pss"), expect(unused_variables))]
        rng: &mut impl rand_core::TryCryptoRng,
    ) -> Result<SignatureBytes, signature::Error> {
        match self {
            #[cfg(feature = "hmac")]
            SigningWebKey::HS256(hmac) => hmac.try_sign_token(header, payload),
            #[cfg(feature = "hmac")]
            SigningWebKey::HS384(hmac) => hmac.try_sign_token(header, payload),
            #[cfg(feature = "hmac")]
            SigningWebKey::HS512(hmac) => hmac.try_sign_token(header, payload),
            #[cfg(feature = "rsa")]
            SigningWebKey::RS256(signing_key) => signing_key.try_sign_token(header, payload),
            #[cfg(feature = "rsa")]
            SigningWebKey::RS384(signing_key) => signing_key.try_sign_token(header, payload),
            #[cfg(feature = "rsa")]
            SigningWebKey::RS512(signing_key) => signing_key.try_sign_token(header, payload),
            #[cfg(all(feature = "ecdsa", feature = "p256"))]
            SigningWebKey::ES256(signing_key) => {
                TokenSigner::<SignatureBytes>::try_sign_token(signing_key, header, payload)
            }
            #[cfg(all(feature = "ecdsa", feature = "p384"))]
            SigningWebKey::ES384(signing_key) => {
                TokenSigner::<SignatureBytes>::try_sign_token(signing_key, header, payload)
            }
            #[cfg(all(feature = "ecdsa", feature = "p521"))]
            SigningWebKey::ES512(signing_key) => {
                TokenSigner::<SignatureBytes>::try_sign_token(signing_key, header, payload)
            }
            #[cfg(feature = "pss")]
            SigningWebKey::PS256(signing_key) => signing_key.try_sign_token(header, payload, rng),
            #[cfg(feature = "pss")]
            SigningWebKey::PS384(signing_key) => signing_key.try_sign_token(header, payload, rng),
            #[cfg(feature = "pss")]
            SigningWebKey::PS512(signing_key) => signing_key.try_sign_token(header, payload, rng),
            #[cfg(feature = "ed25519")]
            SigningWebKey::EdDSA => unimplemented!("EdDSA is not supported"),
            #[cfg(feature = "none")]
            SigningWebKey::None => NoneAlgorithm.try_sign_token(header, payload),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }
}

impl TokenSigner<SignatureBytes> for SigningWebKey {
    #[cfg_attr(
        not(any(
            feature = "hmac",
            feature = "rsa",
            feature = "p256",
            feature = "p384",
            feature = "p521"
        )),
        allow(unused_variables)
    )]
    fn try_sign_token(
        &self,
        header: &str,
        payload: &str,
    ) -> Result<SignatureBytes, signature::Error> {
        match self {
            #[cfg(feature = "hmac")]
            SigningWebKey::HS256(hmac) => hmac.try_sign_token(header, payload),
            #[cfg(feature = "hmac")]
            SigningWebKey::HS384(hmac) => hmac.try_sign_token(header, payload),
            #[cfg(feature = "hmac")]
            SigningWebKey::HS512(hmac) => hmac.try_sign_token(header, payload),
            #[cfg(feature = "rsa")]
            SigningWebKey::RS256(signing_key) => signing_key.try_sign_token(header, payload),
            #[cfg(feature = "rsa")]
            SigningWebKey::RS384(signing_key) => signing_key.try_sign_token(header, payload),
            #[cfg(feature = "rsa")]
            SigningWebKey::RS512(signing_key) => signing_key.try_sign_token(header, payload),
            #[cfg(all(feature = "ecdsa", feature = "p256"))]
            SigningWebKey::ES256(signing_key) => {
                TokenSigner::<SignatureBytes>::try_sign_token(signing_key, header, payload)
            }
            #[cfg(all(feature = "ecdsa", feature = "p384"))]
            SigningWebKey::ES384(signing_key) => {
                TokenSigner::<SignatureBytes>::try_sign_token(signing_key, header, payload)
            }
            #[cfg(all(feature = "ecdsa", feature = "p521"))]
            SigningWebKey::ES512(signing_key) => {
                TokenSigner::<SignatureBytes>::try_sign_token(signing_key, header, payload)
            }
            #[cfg(feature = "pss")]
            SigningWebKey::PS256(_) => {
                unimplemented!("RSA PSS requires a randomized signer")
            }
            #[cfg(feature = "pss")]
            SigningWebKey::PS384(_) => {
                unimplemented!("RSA PSS requires a randomized signer")
            }
            #[cfg(feature = "pss")]
            SigningWebKey::PS512(_) => {
                unimplemented!("RSA PSS requires a randomized signer")
            }
            #[cfg(feature = "ed25519")]
            SigningWebKey::EdDSA => unimplemented!(),
            #[cfg(feature = "none")]
            SigningWebKey::None => NoneAlgorithm.try_sign_token(header, payload),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }
}

/// A concrete key type that can be used to sign JWTs
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
#[serde(tag = "alg")]
pub enum VerifyingWebKey {
    #[cfg(feature = "hmac")]
    /// Hash-based Message Authentication Code using SHA-256
    HS256(#[serde(with = "self::serde_sigs")] Hmac<sha2::Sha256>),

    #[cfg(feature = "hmac")]
    /// Hash-based Message Authentication Code using SHA-384
    HS384(#[serde(with = "self::serde_sigs")] Hmac<sha2::Sha384>),

    #[cfg(feature = "hmac")]
    /// Hash-based Message Authentication Code using SHA-512
    HS512(#[serde(with = "self::serde_sigs")] Hmac<sha2::Sha512>),

    #[cfg(feature = "rsa")]
    /// RSA PKCS#1 v1.5 signature using SHA-256
    RS256(#[serde(with = "self::serde_sigs")] rsa::pkcs1v15::VerifyingKey<sha2::Sha256>),

    #[cfg(feature = "rsa")]
    /// RSA PKCS#1 v1.5 signature using SHA-348
    RS384(#[serde(with = "self::serde_sigs")] rsa::pkcs1v15::VerifyingKey<sha2::Sha384>),

    #[cfg(feature = "rsa")]
    /// RSA PKCS#1 v1.5 signature using SHA-512
    RS512(#[serde(with = "self::serde_sigs")] rsa::pkcs1v15::VerifyingKey<sha2::Sha512>),

    #[cfg(all(feature = "ecdsa", feature = "p256"))]
    /// ECDSA using P-256 and SHA-256
    ES256(#[serde(with = "self::serde_sigs")] ecdsa::VerifyingKey<p256::NistP256>),

    #[cfg(all(feature = "ecdsa", feature = "p384"))]
    /// ECDSA using P-384 and SHA-384
    ES384(#[serde(with = "self::serde_sigs")] ecdsa::VerifyingKey<p384::NistP384>),

    #[cfg(all(feature = "ecdsa", feature = "p521"))]
    /// ECDSA using P-521 and SHA-512
    ES512(#[serde(with = "self::serde_sigs")] ecdsa::VerifyingKey<p521::NistP521>),

    #[cfg(feature = "pss")]
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    PS256(#[serde(with = "self::serde_sigs")] rsa::pss::VerifyingKey<sha2::Sha256>),

    #[cfg(feature = "pss")]
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    PS384(#[serde(with = "self::serde_sigs")] rsa::pss::VerifyingKey<sha2::Sha384>),

    #[cfg(feature = "pss")]
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    PS512(#[serde(with = "self::serde_sigs")] rsa::pss::VerifyingKey<sha2::Sha512>),

    #[cfg(feature = "ed25519")]
    /// EdDSA using Ed25519
    EdDSA,

    #[cfg(feature = "none")]
    /// No signature
    None,
}

impl TryFrom<VerifyingWebKey> for PublicWebKey {
    type Error = JsonWebKeyError;

    fn try_from(value: VerifyingWebKey) -> Result<Self, Self::Error> {
        dispatch!(VerifyingWebKey: value Ok(into()) eddsa(Ok(PublicWebKey::EdDSA)) none(Err(JsonWebKeyError::UnsupportedAlgorithm(AlgorithmIdentifier::None))))
    }
}

#[cfg(feature = "hmac")]
impl From<Hmac<sha2::Sha256>> for VerifyingWebKey {
    fn from(key: Hmac<sha2::Sha256>) -> Self {
        Self::HS256(key)
    }
}

#[cfg(feature = "hmac")]
impl From<Hmac<sha2::Sha384>> for VerifyingWebKey {
    fn from(key: Hmac<sha2::Sha384>) -> Self {
        Self::HS384(key)
    }
}

#[cfg(feature = "hmac")]
impl From<Hmac<sha2::Sha512>> for VerifyingWebKey {
    fn from(key: Hmac<sha2::Sha512>) -> Self {
        Self::HS512(key)
    }
}

#[cfg(feature = "rsa")]
impl From<rsa::pkcs1v15::VerifyingKey<sha2::Sha256>> for VerifyingWebKey {
    fn from(key: rsa::pkcs1v15::VerifyingKey<sha2::Sha256>) -> Self {
        Self::RS256(key)
    }
}

#[cfg(feature = "rsa")]
impl From<rsa::pkcs1v15::VerifyingKey<sha2::Sha384>> for VerifyingWebKey {
    fn from(key: rsa::pkcs1v15::VerifyingKey<sha2::Sha384>) -> Self {
        Self::RS384(key)
    }
}

#[cfg(feature = "rsa")]
impl From<rsa::pkcs1v15::VerifyingKey<sha2::Sha512>> for VerifyingWebKey {
    fn from(key: rsa::pkcs1v15::VerifyingKey<sha2::Sha512>) -> Self {
        Self::RS512(key)
    }
}

#[cfg(all(feature = "ecdsa", feature = "p256"))]
impl From<ecdsa::VerifyingKey<p256::NistP256>> for VerifyingWebKey {
    fn from(key: ecdsa::VerifyingKey<p256::NistP256>) -> Self {
        Self::ES256(key)
    }
}

#[cfg(all(feature = "ecdsa", feature = "p384"))]
impl From<ecdsa::VerifyingKey<p384::NistP384>> for VerifyingWebKey {
    fn from(key: ecdsa::VerifyingKey<p384::NistP384>) -> Self {
        Self::ES384(key)
    }
}

#[cfg(all(feature = "ecdsa", feature = "p521"))]
impl From<ecdsa::VerifyingKey<p521::NistP521>> for VerifyingWebKey {
    fn from(key: ecdsa::VerifyingKey<p521::NistP521>) -> Self {
        Self::ES512(key)
    }
}

#[cfg(feature = "pss")]
impl From<rsa::pss::VerifyingKey<sha2::Sha256>> for VerifyingWebKey {
    fn from(key: rsa::pss::VerifyingKey<sha2::Sha256>) -> Self {
        Self::PS256(key)
    }
}

#[cfg(feature = "pss")]
impl From<rsa::pss::VerifyingKey<sha2::Sha384>> for VerifyingWebKey {
    fn from(key: rsa::pss::VerifyingKey<sha2::Sha384>) -> Self {
        Self::PS384(key)
    }
}

#[cfg(feature = "pss")]
impl From<rsa::pss::VerifyingKey<sha2::Sha512>> for VerifyingWebKey {
    fn from(key: rsa::pss::VerifyingKey<sha2::Sha512>) -> Self {
        Self::PS512(key)
    }
}

impl DynJsonWebAlgorithm for VerifyingWebKey {
    fn identifier(&self) -> AlgorithmIdentifier {
        dispatch!(self.identifier() eddsa(AlgorithmIdentifier::EdDSA))
    }
}

impl DynJwkKeyType for VerifyingWebKey {
    fn key_type(&self) -> KeyType {
        dispatch!(self.key_type())
    }
}

impl SerializeJWK for VerifyingWebKey {
    fn parameters(&self) -> Parameters {
        #[cfg(any(feature = "hmac", feature = "rsa", feature = "ecdsa"))]
        {
            let mut params = dispatch!(self.parameters());
            params
                .insert("alg", self.identifier())
                .expect("alg is valid JSON");
            params
                .insert("kty", self.key_type())
                .expect("kty is valid JSON");

            params
        }
        #[cfg(not(any(feature = "hmac", feature = "rsa", feature = "ecdsa")))]
        {
            panic!("No JWK parameters for algorithm 'none'")
        }
    }
}

impl TokenVerifier for VerifyingWebKey {
    #[cfg_attr(
        not(any(
            feature = "hmac",
            feature = "rsa",
            feature = "p256",
            feature = "p384",
            feature = "p521"
        )),
        allow(unused_variables)
    )]
    fn verify_token(
        &self,
        header: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<SignatureBytes, signature::Error> {
        dispatch!(self.verify_token(header, payload, signature))
    }
}

#[cfg(any(feature = "hmac", feature = "rsa", feature = "ecdsa"))]
mod serde_keys {
    use serde::{de, Serialize as _};

    use crate::key::{DeserializeJWK, Parameters, SerializeJWK};

    pub(super) fn serialize<S, T>(key: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: SerializeJWK,
        S: serde::Serializer,
    {
        key.parameters().serialize(serializer)
    }

    pub(super) fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        T: DeserializeJWK,
        D: de::Deserializer<'de>,
    {
        let parameters: Parameters = de::Deserialize::deserialize(deserializer)?;
        T::build(parameters).map_err(de::Error::custom)
    }
}

#[cfg(any(feature = "hmac", feature = "rsa", feature = "ecdsa"))]
mod serde_sigs {
    use serde::{de, Serialize as _};

    use crate::key::{DeserializeJWK, Parameters, SerializeJWK};

    pub(super) fn serialize<S, T>(key: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: SerializeJWK,
        S: serde::Serializer,
    {
        let mut parameters = key.parameters();
        parameters
            .insert("kty", key.key_type())
            .expect("kty must be valid JSON");
        parameters.serialize(serializer)
    }

    pub(super) fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        T: DeserializeJWK,
        D: de::Deserializer<'de>,
    {
        let parameters: Parameters = de::Deserialize::deserialize(deserializer)?;
        T::build(parameters).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "rsa")]
    #[test]
    fn rsa_public_web_key_serde() {
        use rsa::Generate;

        let key = PublicWebKey::from(rsa::PrivateKey::generate().to_public_key());

        let rendered = serde_json::to_string(&key).unwrap();
        assert_eq!(
            rendered.matches("\"kty\"").count(),
            1,
            "expected exactly one kty field"
        );

        let value = serde_json::to_value(key).unwrap();
        let jwk = value.as_object().unwrap();
        assert!(jwk.contains_key("kty"), "expected kty field");
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn rsa_private_web_key_serde() {
        use rsa::Generate;

        let key = PrivateWebKey::from(rsa::PrivateKey::generate());

        let rendered = serde_json::to_string(&key).unwrap();
        assert_eq!(
            rendered.matches("\"kty\"").count(),
            1,
            "expected exactly one kty field"
        );

        let value = serde_json::to_value(key).unwrap();
        let jwk = value.as_object().unwrap();
        assert!(jwk.contains_key("kty"), "expected kty field");
    }
}
