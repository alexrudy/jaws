//! JSON Web Keys ([RFC 7517][RFC7517])
//!
//! This module implements the JWK format for representing cryptographic keys.
//! For now, it only supports serialization for Keys and Thumbprints.
//!
//! [RFC7517]: https://tools.ietf.org/html/rfc7517

use std::{collections::BTreeMap, hash::Hash, marker::PhantomData};

use base64ct::Encoding;
use serde::{
    de,
    ser::{self, SerializeMap},
    Deserialize, Serialize,
};
use signature::Keypair;

#[cfg(feature = "hmac")]
use crate::algorithms::hmac::{Hmac, HmacKey};
#[cfg(feature = "rand")]
use crate::algorithms::RandomizedTokenSigner;
use crate::{
    algorithms::{AlgorithmIdentifier, DynJsonWebAlgorithm},
    SignatureBytes, TokenSigner, TokenVerifier,
};

/// Error when building or deserializing a JWK.
#[derive(Debug, thiserror::Error)]
pub enum JsonWebKeyError {
    /// JSON errors which occur while building a JWK
    #[error(transparent)]
    JSON(#[from] serde_json::Error),

    /// Key type mismatch error
    #[error("key type mismatch: expected {expected}, got {got}")]
    KeyType {
        /// The expected key type
        expected: String,

        /// The actual key type in the data
        got: String,
    },

    /// Missing a jwk parameter
    #[error("missing expected jwk parameter {0}")]
    MissingParameter(&'static str),

    /// Invalid key for the expected algorithm
    #[error("invalid key for algorithm {0}: {1}")]
    InvalidKey(
        &'static str,
        #[source] Box<dyn std::error::Error + Send + Sync>,
    ),

    /// Unsupported key type error
    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(String),
}

/// Trait for keys which can be used as a JWK.
pub trait JWKeyType {
    /// The string used to identify the JWK type in the `kty` field.
    const KEY_TYPE: &'static str;
}

impl<T> JWKeyType for &T
where
    T: JWKeyType,
{
    const KEY_TYPE: &'static str = T::KEY_TYPE;
}

/// Trait for keys which can be used as a JWK, automatically implemented for
/// types which implement `JWKeyType`, to make `SerializeJWK` object-safe.
pub trait DynJwkKeyType {
    /// The string used to identify the JWK type in the `kty` field.
    fn key_type(&self) -> &'static str;
}

impl<T> DynJwkKeyType for T
where
    T: JWKeyType,
{
    fn key_type(&self) -> &'static str {
        T::KEY_TYPE
    }
}

/// Trait for keys which can be serialized as a JWK.
pub trait SerializeJWK: DynJwkKeyType {
    /// Return a list of parameters to be serialized in the JWK.
    fn parameters(&self) -> Vec<(String, serde_json::Value)>;
}

/// Trait for keys which can be serialized as a public JWK.
pub trait SerializePublicJWK: DynJwkKeyType {
    /// Return a list of parameters to be serialized in the JWK.
    fn public_parameters(&self) -> Vec<(String, serde_json::Value)>;
}

impl<K> SerializePublicJWK for K
where
    K: Keypair + DynJwkKeyType,
    K::VerifyingKey: SerializeJWK,
{
    fn public_parameters(&self) -> Vec<(String, serde_json::Value)> {
        self.verifying_key().parameters()
    }
}

/// Trait for keys which can be deserialized from a JWK.
pub trait DeserializeJWK: DynJwkKeyType + Sized {
    /// From a set of parameters, build a key.
    fn build(parameters: BTreeMap<String, serde_json::Value>) -> Result<Self, JsonWebKeyError>;

    /// Build a concrete key type from [`JsonWebKey`].
    fn from_jwk(jwk: &JsonWebKey) -> Result<Self, JsonWebKeyError> {
        let mut parameters = jwk.parameters().clone();
        parameters.insert("kty".into(), jwk.key_type().into());

        match Self::build(parameters) {
            Ok(key) => {
                if key.key_type() == jwk.key_type() {
                    Ok(key)
                } else {
                    Err(JsonWebKeyError::KeyType {
                        expected: key.key_type().into(),
                        got: jwk.key_type().into(),
                    })
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Deserialize a concrete key type from a JSON value.
    fn from_value(value: serde_json::Value) -> Result<Self, JsonWebKeyError> {
        let jwk: JsonWebKey = serde_json::from_value(value)?;
        Self::from_jwk(&jwk)
    }

    /// Deserialize a concrete key type from a JSON string.
    fn from_str(s: &str) -> Result<Self, JsonWebKeyError> {
        let value: JsonWebKey = serde_json::from_str(s)?;
        Self::from_jwk(&value)
    }
}

/// Trait for building values derived from a key.
pub trait BuildFromKey<Key: ?Sized> {
    /// Build a value from a key.
    fn derive_from_key(key: &Key) -> Result<Self, JsonWebKeyError>
    where
        Self: Sized;
}

impl<Key> BuildFromKey<Key> for JsonWebKey
where
    Key: SerializePublicJWK + ?Sized,
{
    fn derive_from_key(key: &Key) -> Result<Self, JsonWebKeyError> {
        Ok(JsonWebKey {
            key_type: key.key_type().into(),
            parameters: key.public_parameters().into_iter().collect(),
        })
    }
}

/// JSON Web Key in serialized form.
///
/// This struct just contains the parameters of the JWK.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct JsonWebKey {
    #[serde(rename = "kty")]
    key_type: String,

    #[serde(flatten)]
    parameters: BTreeMap<String, serde_json::Value>,
}

impl JsonWebKey {
    /// Create a new JWK from a key type and parameters.
    pub fn new(key_type: String, parameters: BTreeMap<String, serde_json::Value>) -> Self {
        Self {
            key_type,
            parameters,
        }
    }

    /// Build a JWK from a public key.
    pub fn build_public<K: SerializePublicJWK + ?Sized>(key: &K) -> Self {
        JsonWebKey {
            key_type: key.key_type().into(),
            parameters: key.public_parameters().into_iter().collect(),
        }
    }

    /// Build a JWK from a key.
    pub fn build<K: SerializeJWK + ?Sized>(key: &K) -> Self {
        JsonWebKey {
            key_type: key.key_type().into(),
            parameters: key.parameters().into_iter().collect(),
        }
    }

    /// Get the key type of this JWK.
    pub fn key_type(&self) -> &str {
        &self.key_type
    }

    /// Get the parameters of this JWK.
    pub fn parameters(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.parameters
    }

    /// Deserialize a concrete key type from this JWK.
    pub fn deserialize_key<K: DeserializeJWK>(&self) -> Result<K, JsonWebKeyError> {
        match K::build(self.parameters.clone()) {
            Ok(key) => {
                if key.key_type() == self.key_type {
                    Ok(key)
                } else {
                    Err(JsonWebKeyError::KeyType {
                        expected: self.key_type.clone(),
                        got: key.key_type().into(),
                    })
                }
            }
            Err(e) => Err(e),
        }
    }
}

impl Serialize for JsonWebKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // JWKs must serialize keys in alphabetical order.

        let mut entries = self
            .parameters
            .iter()
            .map(|(key, value)| (key.as_str(), value))
            .collect::<BTreeMap<_, _>>();
        let kty = serde_json::Value::String(self.key_type.clone());
        entries.insert("kty", &kty);

        let mut map = serializer.serialize_map(Some(entries.len()))?;
        for (key, value) in entries {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

/// A computed thumbprint.
#[derive(Debug, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Thumbprint<Digest> {
    thumbprint: String,
    digest: PhantomData<Digest>,
}

impl<Digest> Clone for Thumbprint<Digest> {
    fn clone(&self) -> Self {
        Self {
            thumbprint: self.thumbprint.clone(),
            digest: PhantomData,
        }
    }
}

impl<Digest> Hash for Thumbprint<Digest> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.thumbprint.hash(state);
    }
}

impl<Digest> PartialEq for Thumbprint<Digest> {
    fn eq(&self, other: &Self) -> bool {
        self.thumbprint == other.thumbprint && self.digest == other.digest
    }
}

impl<Digest> Eq for Thumbprint<Digest> {}

impl<Digest> Thumbprint<Digest>
where
    Digest: digest::Digest,
{
    /// Create a new thumbprint from a base64url-encoded digest.
    pub fn new(thumbprint: String) -> Self {
        Self {
            thumbprint,
            digest: PhantomData,
        }
    }

    /// Compute the thumbprint of a JWK.
    pub fn from_jwk(jwk: &JsonWebKey) -> Result<Self, JsonWebKeyError> {
        let thumb = serde_json::to_vec(&jwk)?;

        let mut hasher = Digest::new();
        hasher.update(&thumb);
        let digest = hasher.finalize();
        Ok(Self::new(base64ct::Base64UrlUnpadded::encode_string(
            &digest,
        )))
    }
}

impl<Digest, Key> BuildFromKey<Key> for Thumbprint<Digest>
where
    Key: SerializePublicJWK + ?Sized,
    Digest: digest::Digest,
{
    fn derive_from_key(key: &Key) -> Result<Thumbprint<Digest>, JsonWebKeyError> {
        let jwk = JsonWebKey::derive_from_key(key)?;
        Thumbprint::from_jwk(&jwk)
    }
}

impl<Digest> ser::Serialize for Thumbprint<Digest> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.thumbprint.as_str())
    }
}

struct ThumbprintVisitor<D>(PhantomData<D>);

impl<'de, D> de::Visitor<'de> for ThumbprintVisitor<D>
where
    D: digest::Digest,
{
    type Value = Thumbprint<D>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("thumbprint digest as base64url string")
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Thumbprint::new(v.to_owned()))
    }
}

impl<'de, Digest> de::Deserialize<'de> for Thumbprint<Digest>
where
    Digest: digest::Digest,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(ThumbprintVisitor(PhantomData))
    }
}

impl<Digest> std::fmt::Display for Thumbprint<Digest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.thumbprint)
    }
}

impl<Digest> std::ops::Deref for Thumbprint<Digest> {
    type Target = str;

    fn deref(&self) -> &str {
        &self.thumbprint
    }
}

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
    fn key_type(&self) -> &'static str {
        self.key.key_type()
    }
}

impl<K> SerializeJWK for Restricted<K>
where
    K: SerializeJWK,
{
    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        self.key.parameters()
    }
}

impl<K> SerializePublicJWK for Restricted<K>
where
    K: SerializePublicJWK,
{
    fn public_parameters(&self) -> Vec<(String, serde_json::Value)> {
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

#[cfg(any(feature = "hmac", feature = "rsa", feature = "ecdsa"))]
mod serde_keys {
    use serde::{de, Serialize as _};

    use super::{DeserializeJWK, JsonWebKey, SerializeJWK};

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

/// An identified key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identified<Key> {
    /// The key itself.
    #[serde(flatten)]
    pub key: Key,

    /// The identifier of the key.
    #[serde(rename = "kid")]
    pub id: String,
}

#[cfg(test)]
mod test {

    use super::*;

    use static_assertions as sa;

    sa::assert_obj_safe!(SerializeJWK);

    #[cfg(feature = "rsa")]
    mod rsa {
        use super::super::*;

        use serde_json::json;

        #[test]
        fn rfc7639_example() {
            let key = rsa::PublicKey::from_value(json!({
                  "kty": "RSA",
                  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt
                  VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6
                  4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD
                  W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9
                  1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH
                  aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                  "e": "AQAB",
                  "kid": "2011-04-29"
                 }
            ))
            .unwrap();

            eprintln!(
                "{}",
                serde_json::to_string_pretty(&JsonWebKey::build(&key)).unwrap()
            );

            let thumb: Thumbprint<sha2::Sha256> =
                Thumbprint::from_jwk(&JsonWebKey::build(&key)).unwrap();

            assert_eq!(&*thumb, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
        }

        #[test]
        fn rfc7639_example_web() {
            let _key = PublicWebKey::from_value(json!({
                  "kty": "RSA",
                  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt
                  VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6
                  4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD
                  W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9
                  1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH
                  aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                  "e": "AQAB",
                  "kid": "2011-04-29"
                 }
            ))
            .unwrap();
        }
    }
}
