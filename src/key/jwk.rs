//! JWK key types for deserializing from a JSON Web Key (JWK)
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use signature::Keypair;

#[cfg(feature = "hmac")]
use crate::algorithms::hmac::{Hmac, HmacKey};
#[cfg(feature = "rand")]
use crate::algorithms::RandomizedTokenSigner;
use crate::{
    algorithms::{AlgorithmIdentifier, DynJsonWebAlgorithm},
    SignatureBytes, TokenSigner, TokenVerifier,
};

use super::{DeserializeJWK, DynJwkKeyType, JsonWebKeyError, SerializeJWK};

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
    #[serde(rename = "ECDSA")]
    /// ECDSA Key
    EcDsa(#[serde(with = "self::serde_keys")] crate::algorithms::ecdsa::JWEcSigningKey),

    #[cfg(feature = "ed25519")]
    /// EdDSA using Ed25519
    EdDSA,

    /// No signature is applied.
    #[serde(rename = "none")]
    None,
}

impl From<SigningWebKey> for PrivateWebKey {
    fn from(value: SigningWebKey) -> Self {
        match value {
            #[cfg(feature = "hmac")]
            SigningWebKey::HS256(hmac) => PrivateWebKey::HMac(hmac.into()),
            #[cfg(feature = "hmac")]
            SigningWebKey::HS384(hmac) => PrivateWebKey::HMac(hmac.into()),
            #[cfg(feature = "hmac")]
            SigningWebKey::HS512(hmac) => PrivateWebKey::HMac(hmac.into()),
            #[cfg(feature = "rsa")]
            SigningWebKey::RS256(verifying_key) => PrivateWebKey::Rsa(verifying_key.into()),
            #[cfg(feature = "rsa")]
            SigningWebKey::RS384(verifying_key) => PrivateWebKey::Rsa(verifying_key.into()),
            #[cfg(feature = "rsa")]
            SigningWebKey::RS512(verifying_key) => PrivateWebKey::Rsa(verifying_key.into()),
            #[cfg(all(feature = "ecdsa", feature = "p256"))]
            SigningWebKey::ES256(verifying_key) => PrivateWebKey::EcDsa(verifying_key.into()),
            #[cfg(all(feature = "ecdsa", feature = "p384"))]
            SigningWebKey::ES384(verifying_key) => PrivateWebKey::EcDsa(verifying_key.into()),
            #[cfg(all(feature = "ecdsa", feature = "p521"))]
            SigningWebKey::ES512(verifying_key) => PrivateWebKey::EcDsa(verifying_key.into()),
            #[cfg(feature = "pss")]
            SigningWebKey::PS256(verifying_key) => PrivateWebKey::Rsa(verifying_key.into()),
            #[cfg(feature = "pss")]
            SigningWebKey::PS384(verifying_key) => PrivateWebKey::Rsa(verifying_key.into()),
            #[cfg(feature = "pss")]
            SigningWebKey::PS512(verifying_key) => PrivateWebKey::Rsa(verifying_key.into()),
            #[cfg(feature = "ed25519")]
            SigningWebKey::EdDSA => PrivateWebKey::EdDSA,
            SigningWebKey::None => PrivateWebKey::None,
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
            Self::None => PublicWebKey::None,
        }
    }
}

impl DynJwkKeyType for PrivateWebKey {
    fn key_type(&self) -> &'static str {
        match self {
            #[cfg(feature = "hmac")]
            Self::HMac(_) => "oct",
            #[cfg(feature = "rsa")]
            Self::Rsa(_) => "RSA",
            #[cfg(feature = "ecdsa")]
            Self::EcDsa(_) => "ECDSA",
            #[cfg(feature = "ed25519")]
            Self::EdDSA => "EdDSA",
            Self::None => "none",
        }
    }
}

impl SerializeJWK for PrivateWebKey {
    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        let mut params = match self {
            #[cfg(feature = "hmac")]
            Self::HMac(hmac) => hmac.parameters(),
            #[cfg(feature = "rsa")]
            Self::Rsa(signing_key) => signing_key.parameters(),
            #[cfg(feature = "ecdsa")]
            Self::EcDsa(signing_key) => signing_key.parameters(),
            #[cfg(feature = "ed25519")]
            Self::EdDSA => vec![],
            Self::None => vec![],
        };

        params.push(("kty".to_string(), self.key_type().into()));
        params
    }
}

impl DeserializeJWK for PrivateWebKey {
    fn build(parameters: BTreeMap<String, serde_json::Value>) -> Result<Self, JsonWebKeyError> {
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
    /// Hash-based Message Authentication Code using SHA-256
    HMac(#[serde(with = "self::serde_keys")] HmacKey),

    #[cfg(feature = "rsa")]
    /// RSA Key
    Rsa(#[serde(with = "self::serde_keys")] rsa::PublicKey),

    #[cfg(feature = "ecdsa")]
    /// ECDSA Key
    EcDsa(#[serde(with = "self::serde_keys")] crate::algorithms::ecdsa::JWEcVerifyingKey),

    #[cfg(feature = "ed25519")]
    /// EdDSA using Ed25519
    EdDSA,

    /// No signature is applied.
    #[serde(rename = "none")]
    None,
}

impl From<VerifyingWebKey> for PublicWebKey {
    fn from(value: VerifyingWebKey) -> Self {
        match value {
            #[cfg(feature = "hmac")]
            VerifyingWebKey::HS256(hmac) => PublicWebKey::HMac(hmac.into()),
            #[cfg(feature = "hmac")]
            VerifyingWebKey::HS384(hmac) => PublicWebKey::HMac(hmac.into()),
            #[cfg(feature = "hmac")]
            VerifyingWebKey::HS512(hmac) => PublicWebKey::HMac(hmac.into()),
            #[cfg(feature = "rsa")]
            VerifyingWebKey::RS256(verifying_key) => PublicWebKey::Rsa(verifying_key.into()),
            #[cfg(feature = "rsa")]
            VerifyingWebKey::RS384(verifying_key) => PublicWebKey::Rsa(verifying_key.into()),
            #[cfg(feature = "rsa")]
            VerifyingWebKey::RS512(verifying_key) => PublicWebKey::Rsa(verifying_key.into()),
            #[cfg(all(feature = "ecdsa", feature = "p256"))]
            VerifyingWebKey::ES256(verifying_key) => PublicWebKey::EcDsa(verifying_key.into()),
            #[cfg(all(feature = "ecdsa", feature = "p384"))]
            VerifyingWebKey::ES384(verifying_key) => PublicWebKey::EcDsa(verifying_key.into()),
            #[cfg(all(feature = "ecdsa", feature = "p521"))]
            VerifyingWebKey::ES512(verifying_key) => PublicWebKey::EcDsa(verifying_key.into()),
            #[cfg(feature = "pss")]
            VerifyingWebKey::PS256(verifying_key) => PublicWebKey::Rsa(verifying_key.into()),
            #[cfg(feature = "pss")]
            VerifyingWebKey::PS384(verifying_key) => PublicWebKey::Rsa(verifying_key.into()),
            #[cfg(feature = "pss")]
            VerifyingWebKey::PS512(verifying_key) => PublicWebKey::Rsa(verifying_key.into()),
            #[cfg(feature = "ed25519")]
            VerifyingWebKey::EdDSA => PublicWebKey::EdDSA,
            VerifyingWebKey::None => PublicWebKey::None,
        }
    }
}

impl DynJwkKeyType for PublicWebKey {
    fn key_type(&self) -> &'static str {
        match self {
            #[cfg(feature = "hmac")]
            Self::HMac(_) => "oct",
            #[cfg(feature = "rsa")]
            Self::Rsa(_) => "RSA",
            #[cfg(feature = "ecdsa")]
            Self::EcDsa(_) => "ECDSA",
            #[cfg(feature = "ed25519")]
            Self::EdDSA => "EdDSA",
            Self::None => "none",
        }
    }
}

impl DeserializeJWK for PublicWebKey {
    fn build(parameters: BTreeMap<String, serde_json::Value>) -> Result<Self, JsonWebKeyError> {
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

macro_rules! dispatch {

    ($driver:ident.$method:ident($($args:expr),*) eddsa($eddsa:expr) none($none:expr)) => {
        match $driver {
            #[cfg(feature = "hmac")]
            Self::HS256(hmac) => hmac.$method($($args),*),
            #[cfg(feature = "hmac")]
            Self::HS384(hmac) => hmac.$method($($args),*),
            #[cfg(feature = "hmac")]
            Self::HS512(hmac) => hmac.$method($($args),*),
            #[cfg(feature = "rsa")]
            Self::RS256(signing_key) => signing_key.$method($($args),*),
            #[cfg(feature = "rsa")]
            Self::RS384(signing_key) => signing_key.$method($($args),*),
            #[cfg(feature = "rsa")]
            Self::RS512(signing_key) => signing_key.$method($($args),*),
            #[cfg(all(feature = "ecdsa", feature = "p256"))]
            Self::ES256(signing_key) => signing_key.$method($($args),*),
            #[cfg(all(feature = "ecdsa", feature = "p384"))]
            Self::ES384(signing_key) => signing_key.$method($($args),*),
            #[cfg(all(feature = "ecdsa", feature = "p521"))]
            Self::ES512(signing_key) => signing_key.$method($($args),*),
            #[cfg(feature = "pss")]
            Self::PS256(signing_key) => signing_key.$method($($args),*),
            #[cfg(feature = "pss")]
            Self::PS384(signing_key) => signing_key.$method($($args),*),
            #[cfg(feature = "pss")]
            Self::PS512(signing_key) => signing_key.$method($($args),*),
            #[cfg(feature = "ed25519")]
            Self::EdDSA => $eddsa,
            Self::None => $none,
        }
    };
    ($driver:ident.$method:ident($($args:expr),*) none($none:expr)) => {
        dispatch!($driver.$method($($args),*) eddsa(unimplemented!("EdDSA is not supported")) none($none))
    }
}

/// A concrete key type that can be used to sign JWTs
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub enum SigningWebKey {
    #[cfg(feature = "hmac")]
    /// Hash-based Message Authentication Code using SHA-256
    HS256(#[serde(with = "self::serde_keys")] Hmac<sha2::Sha256>),

    #[cfg(feature = "hmac")]
    /// Hash-based Message Authentication Code using SHA-384
    HS384(#[serde(with = "self::serde_keys")] Hmac<sha2::Sha384>),

    #[cfg(feature = "hmac")]
    /// Hash-based Message Authentication Code using SHA-512
    HS512(#[serde(with = "self::serde_keys")] Hmac<sha2::Sha512>),

    #[cfg(feature = "rsa")]
    /// RSA PKCS#1 v1.5 signature using SHA-256
    RS256(#[serde(with = "self::serde_keys")] rsa::pkcs1v15::SigningKey<sha2::Sha256>),

    #[cfg(feature = "rsa")]
    /// RSA PKCS#1 v1.5 signature using SHA-348
    RS384(#[serde(with = "self::serde_keys")] rsa::pkcs1v15::SigningKey<sha2::Sha384>),

    #[cfg(feature = "rsa")]
    /// RSA PKCS#1 v1.5 signature using SHA-512
    RS512(#[serde(with = "self::serde_keys")] rsa::pkcs1v15::SigningKey<sha2::Sha512>),

    #[cfg(all(feature = "ecdsa", feature = "p256"))]
    /// ECDSA using P-256 and SHA-256
    ES256(#[serde(with = "self::serde_keys")] ecdsa::SigningKey<p256::NistP256>),

    #[cfg(all(feature = "ecdsa", feature = "p384"))]
    /// ECDSA using P-384 and SHA-384
    ES384(#[serde(with = "self::serde_keys")] ecdsa::SigningKey<p384::NistP384>),

    #[cfg(all(feature = "ecdsa", feature = "p521"))]
    /// ECDSA using P-521 and SHA-512
    ES512(#[serde(with = "self::serde_keys")] ecdsa::SigningKey<p521::NistP521>),

    #[cfg(feature = "pss")]
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    PS256(#[serde(with = "self::serde_keys")] rsa::pss::SigningKey<sha2::Sha256>),

    #[cfg(feature = "pss")]
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    PS384(#[serde(with = "self::serde_keys")] rsa::pss::SigningKey<sha2::Sha384>),

    #[cfg(feature = "pss")]
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    PS512(#[serde(with = "self::serde_keys")] rsa::pss::SigningKey<sha2::Sha512>),

    #[cfg(feature = "ed25519")]
    /// EdDSA using Ed25519
    EdDSA,

    /// No signature is applied.
    #[serde(rename = "none")]
    None,
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
                VerifyingWebKey::ES256(signing_key.verifying_key().clone())
            }
            #[cfg(all(feature = "ecdsa", feature = "p384"))]
            SigningWebKey::ES384(signing_key) => {
                VerifyingWebKey::ES384(signing_key.verifying_key().clone())
            }
            #[cfg(all(feature = "ecdsa", feature = "p521"))]
            SigningWebKey::ES512(signing_key) => {
                VerifyingWebKey::ES512(signing_key.verifying_key().clone())
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
            SigningWebKey::None => todo!(),
        }
    }
}

impl DynJsonWebAlgorithm for SigningWebKey {
    fn identifier(&self) -> AlgorithmIdentifier {
        dispatch!(self.identifier() eddsa(AlgorithmIdentifier::EdDSA) none(AlgorithmIdentifier::None))
    }
}

impl DynJwkKeyType for SigningWebKey {
    fn key_type(&self) -> &'static str {
        dispatch!(self.key_type() eddsa("EdDSA") none("none"))
    }
}

impl SerializeJWK for SigningWebKey {
    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        dispatch!(self.parameters() none(vec![]))
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
            SigningWebKey::EdDSA => todo!(),
            SigningWebKey::None => todo!(),
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
        expect(unused_variables)
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
            SigningWebKey::None => todo!(),
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
    HS256(#[serde(with = "self::serde_keys")] Hmac<sha2::Sha256>),

    #[cfg(feature = "hmac")]
    /// Hash-based Message Authentication Code using SHA-384
    HS384(#[serde(with = "self::serde_keys")] Hmac<sha2::Sha384>),

    #[cfg(feature = "hmac")]
    /// Hash-based Message Authentication Code using SHA-512
    HS512(#[serde(with = "self::serde_keys")] Hmac<sha2::Sha512>),

    #[cfg(feature = "rsa")]
    /// RSA PKCS#1 v1.5 signature using SHA-256
    RS256(#[serde(with = "self::serde_keys")] rsa::pkcs1v15::VerifyingKey<sha2::Sha256>),

    #[cfg(feature = "rsa")]
    /// RSA PKCS#1 v1.5 signature using SHA-348
    RS384(#[serde(with = "self::serde_keys")] rsa::pkcs1v15::VerifyingKey<sha2::Sha384>),

    #[cfg(feature = "rsa")]
    /// RSA PKCS#1 v1.5 signature using SHA-512
    RS512(#[serde(with = "self::serde_keys")] rsa::pkcs1v15::VerifyingKey<sha2::Sha512>),

    #[cfg(all(feature = "ecdsa", feature = "p256"))]
    /// ECDSA using P-256 and SHA-256
    ES256(#[serde(with = "self::serde_keys")] ecdsa::VerifyingKey<p256::NistP256>),

    #[cfg(all(feature = "ecdsa", feature = "p384"))]
    /// ECDSA using P-384 and SHA-384
    ES384(#[serde(with = "self::serde_keys")] ecdsa::VerifyingKey<p384::NistP384>),

    #[cfg(all(feature = "ecdsa", feature = "p521"))]
    /// ECDSA using P-521 and SHA-512
    ES512(#[serde(with = "self::serde_keys")] ecdsa::VerifyingKey<p521::NistP521>),

    #[cfg(feature = "pss")]
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    PS256(#[serde(with = "self::serde_keys")] rsa::pss::VerifyingKey<sha2::Sha256>),

    #[cfg(feature = "pss")]
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    PS384(#[serde(with = "self::serde_keys")] rsa::pss::VerifyingKey<sha2::Sha384>),

    #[cfg(feature = "pss")]
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    PS512(#[serde(with = "self::serde_keys")] rsa::pss::VerifyingKey<sha2::Sha512>),

    #[cfg(feature = "ed25519")]
    /// EdDSA using Ed25519
    EdDSA,

    /// No signature is applied.
    #[serde(rename = "none")]
    None,
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
        dispatch!(self.identifier() eddsa(AlgorithmIdentifier::EdDSA) none(AlgorithmIdentifier::None))
    }
}

impl DynJwkKeyType for VerifyingWebKey {
    fn key_type(&self) -> &'static str {
        dispatch!(self.key_type() eddsa("EdDSA") none("none"))
    }
}

impl SerializeJWK for VerifyingWebKey {
    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        dispatch!(self.parameters() none(vec![]))
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
        expect(unused_variables)
    )]
    fn verify_token(
        &self,
        header: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<SignatureBytes, signature::Error> {
        dispatch!(self.verify_token(header, payload, signature) none(todo!()))
    }
}

#[cfg(any(feature = "hmac", feature = "rsa", feature = "ecdsa"))]
mod serde_keys {
    use serde::{de, Serialize as _};

    use crate::key::{DeserializeJWK, JsonWebKey, SerializeJWK};

    pub(super) fn serialize<S, T>(key: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: SerializeJWK,
        S: serde::Serializer,
    {
        JsonWebKey::build(key).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        T: DeserializeJWK,
        D: de::Deserializer<'de>,
    {
        let key: JsonWebKey = de::Deserialize::deserialize(deserializer)?;
        Ok(T::from_jwk(&key).map_err(de::Error::custom)?)
    }
}
