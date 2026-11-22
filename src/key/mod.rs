//! JSON Web Keys ([RFC 7517][RFC7517])
//!
//! This module implements the JWK format for representing cryptographic keys.
//! For now, it only supports serialization for Keys and Thumbprints.
//!
//! [RFC7517]: https://tools.ietf.org/html/rfc7517

use std::{collections::BTreeMap, fmt, hash::Hash, marker::PhantomData, str::FromStr};

use base64ct::Encoding;
use serde::{
    Deserialize, Serialize, de,
    ser::{self, SerializeMap},
};
use signature::Keypair;
use signature::SignatureEncoding;

mod jwk;
mod jwks;
mod restricted;

#[cfg(test)]
pub(crate) mod fixtures;

#[cfg(all(test, any(feature = "hmac", feature = "rsa", feature = "ecdsa")))]
mod web_key_tests;

use crate::{SignatureBytes, TokenSigner, TokenVerifier, algorithms::AlgorithmIdentifier};

pub use self::jwk::{PrivateWebKey, PublicWebKey, SigningWebKey, VerifyingWebKey};
pub use self::jwks::{JWKSetVerifyError, JWKSetVerifyErrorKind, JwkSet, VerifyJWKSet};
pub use self::restricted::{Restricted, RestrictedAlgorithmError};

/// Error when an algorithm is not supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unsupported algorithm: {0}")]
pub struct UnsupportedAlgorithmError(pub AlgorithmIdentifier);

impl From<AlgorithmIdentifier> for UnsupportedAlgorithmError {
    fn from(algorithm: AlgorithmIdentifier) -> Self {
        Self(algorithm)
    }
}

/// Error when building or deserializing a JWK.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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

    /// Unsupported algorithm error
    #[error("unsupported algorithm: {0:?}")]
    UnsupportedAlgorithm(AlgorithmIdentifier),
}

/// Returns the key type as a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
#[non_exhaustive]
pub enum KeyType {
    /// Octet key type
    Octet,

    /// RSA key type
    Rsa,

    /// Elliptic Curve key type
    EllipticCurve,

    /// Octet Pairs
    OctetPairs,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<KeyType> for String {
    fn from(kt: KeyType) -> Self {
        kt.as_str().to_owned()
    }
}

impl From<KeyType> for serde_json::Value {
    fn from(kt: KeyType) -> Self {
        kt.to_string().into()
    }
}

/// Represents an unknown key type parsing error
#[derive(Debug, Clone, thiserror::Error)]
#[error("unknown key type: {0}")]
pub struct UnknownKeyType(String);

impl FromStr for KeyType {
    type Err = UnknownKeyType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "oct" => Ok(KeyType::Octet),
            "RSA" => Ok(KeyType::Rsa),
            "EC" => Ok(KeyType::EllipticCurve),
            "OKP" => Ok(KeyType::OctetPairs),
            _ => Err(UnknownKeyType(s.to_owned())),
        }
    }
}

impl TryFrom<&str> for KeyType {
    type Error = UnknownKeyType;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for KeyType {
    type Error = UnknownKeyType;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl KeyType {
    /// Returns `true` if the key type is supported by the current build configuration.
    pub fn is_supported(&self) -> bool {
        match self {
            KeyType::Octet => cfg!(feature = "hmac"),
            KeyType::Rsa => cfg!(feature = "rsa"),
            KeyType::EllipticCurve => cfg!(feature = "ecdsa"),
            KeyType::OctetPairs => cfg!(feature = "ed25519"),
        }
    }

    /// Returns the key type as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyType::Octet => "oct",
            KeyType::Rsa => "RSA",
            KeyType::EllipticCurve => "EC",
            KeyType::OctetPairs => "OKP",
        }
    }

    /// Returns `true` if the key type supports the given algorithm.
    pub fn supports_alg(&self, alg: &AlgorithmIdentifier) -> bool {
        match self {
            KeyType::Octet => matches!(
                alg,
                AlgorithmIdentifier::HS256
                    | AlgorithmIdentifier::HS384
                    | AlgorithmIdentifier::HS512
            ),
            KeyType::Rsa => matches!(
                alg,
                AlgorithmIdentifier::RS256
                    | AlgorithmIdentifier::RS384
                    | AlgorithmIdentifier::RS512
                    | AlgorithmIdentifier::PS256
                    | AlgorithmIdentifier::PS384
                    | AlgorithmIdentifier::PS512
            ),
            KeyType::EllipticCurve => matches!(
                alg,
                AlgorithmIdentifier::ES256
                    | AlgorithmIdentifier::ES384
                    | AlgorithmIdentifier::ES512
            ),
            KeyType::OctetPairs => matches!(alg, AlgorithmIdentifier::EdDSA),
        }
    }
}

/// Trait for keys which can be used as a JWK.
pub trait JWKeyType {
    /// The string used to identify the JWK type in the `kty` field.
    const KEY_TYPE: KeyType;
}

impl<T> JWKeyType for &T
where
    T: JWKeyType,
{
    const KEY_TYPE: KeyType = T::KEY_TYPE;
}

/// Trait for keys which can be used as a JWK, automatically implemented for
/// types which implement `JWKeyType`, to make `SerializeJWK` object-safe.
pub trait DynJwkKeyType {
    /// The string used to identify the JWK type in the `kty` field.
    fn key_type(&self) -> KeyType;
}

impl<T> DynJwkKeyType for T
where
    T: JWKeyType,
{
    fn key_type(&self) -> KeyType {
        T::KEY_TYPE
    }
}

/// Trait for types that are not Algorithm-specific, but can be converted into a verifying key for a given algorithm.
pub trait IntoVerifyingKey<S = SignatureBytes>
where
    S: SignatureEncoding,
{
    /// The verifying key type for this algorithm.
    type Key: TokenVerifier<S>;

    /// Returns whether this public key supports the given algorithm
    fn supports_algorithm(&self, algorithm: AlgorithmIdentifier) -> bool;

    /// Converts this public key into a verifying key for the given algorithm
    fn into_verifying_key(
        self,
        algorithm: AlgorithmIdentifier,
    ) -> Result<Self::Key, UnsupportedAlgorithmError>;
}

/// Trait for types that are not Algorithm-specific, but can be converted into a signing key for a given algorithm.
pub trait IntoSigningKey<S = SignatureBytes>
where
    S: SignatureEncoding,
{
    /// The signing key type for this algorithm.
    type Key: TokenSigner<S>;

    /// Returns whether this key supports the given algorithm.
    fn supports_algorithm(&self, algorithm: AlgorithmIdentifier) -> bool;

    /// Converts this key into a signing key for the given algorithm.
    fn into_signing_key(
        self,
        algorithm: AlgorithmIdentifier,
    ) -> Result<Self::Key, UnsupportedAlgorithmError>;
}

/// JWK members which hold secret key material, for any key type.
///
/// These are never printed by the [`Debug`](fmt::Debug) implementation of [`Parameters`].
const SECRET_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// A map of parameters to be serialized in the JWK.
///
/// Parameters can hold private key material. The [`Debug`](fmt::Debug) implementation
/// redacts the members which are secret for any key type (`d`, `p`, `q`, `dp`, `dq`,
/// `qi`, `oth` and `k`).
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Parameters(BTreeMap<String, serde_json::Value>);

impl fmt::Debug for Parameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Redacted<'p>(&'p BTreeMap<String, serde_json::Value>);

        impl fmt::Debug for Redacted<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut map = f.debug_map();
                for (name, value) in self.0 {
                    if SECRET_MEMBERS.contains(&name.as_str()) {
                        map.entry(name, &format_args!("<redacted>"));
                    } else {
                        map.entry(name, value);
                    }
                }
                map.finish()
            }
        }

        f.debug_tuple("Parameters")
            .field(&Redacted(&self.0))
            .finish()
    }
}

impl Parameters {
    /// Returns a new, empty `Parameters` map.
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Returns the number of parameters in the map.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Inserts a parameter into the map.
    pub fn insert<K: Into<String>, V: Into<serde_json::Value>>(&mut self, key: K, value: V) {
        self.0.insert(key.into(), value.into());
    }

    /// Returns a reference to the value for the given key, if it exists.
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.0.get(key)
    }

    /// Removes a parameter from the map, returning the value if it exists.
    pub fn remove(&mut self, key: &str) -> Option<serde_json::Value> {
        self.0.remove(key)
    }

    /// Returns an iterator over the parameters in the map.
    pub fn iter(&self) -> ParametersIter<'_> {
        ParametersIter {
            iter: self.0.iter(),
        }
    }
}

impl FromIterator<(String, serde_json::Value)> for Parameters {
    fn from_iter<T: IntoIterator<Item = (String, serde_json::Value)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl IntoIterator for Parameters {
    type Item = (String, serde_json::Value);
    type IntoIter = std::collections::btree_map::IntoIter<String, serde_json::Value>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Extend<(String, serde_json::Value)> for Parameters {
    fn extend<T: IntoIterator<Item = (String, serde_json::Value)>>(&mut self, iter: T) {
        for (key, value) in iter {
            self.0.insert(key, value);
        }
    }
}

/// Iterator over the parameters in a [`Parameters`] map.
#[derive(Debug, Clone)]
pub struct ParametersIter<'p> {
    iter: std::collections::btree_map::Iter<'p, String, serde_json::Value>,
}

impl<'p> Iterator for ParametersIter<'p> {
    type Item = (&'p str, &'p serde_json::Value);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|(k, v)| (k.as_str(), v))
    }
}

/// Trait for keys which can be serialized as a JWK.
pub trait SerializeJWK: DynJwkKeyType {
    /// Return a list of parameters to be serialized in the JWK.
    fn parameters(&self) -> Parameters;

    /// Serialize this key as a JWK.
    fn to_jwk(&self) -> Result<JsonWebKey, JsonWebKeyError> {
        Ok(JsonWebKey {
            key_type: self.key_type().to_string(),
            parameters: self.parameters(),
        })
    }
}

/// Trait for keys which can be serialized as a public JWK.
pub trait SerializePublicJWK: DynJwkKeyType {
    /// Return a list of parameters to be serialized in the JWK.
    fn public_parameters(&self) -> Parameters;

    /// Serialize this key as a public JWK.
    fn to_public_jwk(&self) -> Result<JsonWebKey, JsonWebKeyError> {
        Ok(JsonWebKey {
            key_type: self.key_type().to_string(),
            parameters: self.public_parameters(),
        })
    }
}

impl<K> SerializePublicJWK for K
where
    K: Keypair + DynJwkKeyType,
    K::VerifyingKey: SerializeJWK,
{
    fn public_parameters(&self) -> Parameters {
        self.verifying_key().parameters()
    }
}

/// Trait for keys which can be deserialized from a JWK.
pub trait DeserializeJWK: DynJwkKeyType + Sized {
    /// From a set of parameters, build a key.
    fn build(parameters: Parameters) -> Result<Self, JsonWebKeyError>;

    /// Build a concrete key type from [`JsonWebKey`].
    fn from_jwk(jwk: &JsonWebKey) -> Result<Self, JsonWebKeyError> {
        let mut parameters = jwk.parameters().clone();
        parameters.insert("kty", jwk.key_type());

        match Self::build(parameters) {
            Ok(key) => {
                if key.key_type().as_str() == jwk.key_type() {
                    Ok(key)
                } else {
                    Err(JsonWebKeyError::KeyType {
                        expected: key.key_type().as_str().into(),
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
        Ok(JsonWebKey::build_public(key))
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
    parameters: Parameters,
}

impl JsonWebKey {
    /// Create a new JWK from a key type and parameters.
    pub fn new(key_type: String, parameters: Parameters) -> Self {
        debug_assert!(
            !parameters.iter().any(|(k, _)| k == "kty"),
            "parameters must not contain 'kty' key"
        );

        Self {
            key_type,
            parameters,
        }
    }

    /// Build a JWK from a public key.
    pub fn build_public<K: SerializePublicJWK + ?Sized>(key: &K) -> Self {
        JsonWebKey {
            key_type: key.key_type().as_str().into(),
            parameters: key
                .public_parameters()
                .into_iter()
                .filter(|(k, _)| k != "kty")
                .collect(),
        }
    }

    /// Build a JWK from a key.
    pub fn build<K: SerializeJWK + ?Sized>(key: &K) -> Self {
        JsonWebKey {
            key_type: key.key_type().as_str().into(),
            parameters: key
                .parameters()
                .into_iter()
                .filter(|(k, _)| k != "kty")
                .collect(),
        }
    }

    /// Get the key type of this JWK.
    pub fn key_type(&self) -> &str {
        &self.key_type
    }

    /// Get the parameters of this JWK.
    pub fn parameters(&self) -> &Parameters {
        &self.parameters
    }

    /// Deserialize a concrete key type from this JWK.
    pub fn deserialize_key<K: DeserializeJWK>(&self) -> Result<K, JsonWebKeyError> {
        let mut entries = self.parameters.clone();
        entries.insert("kty", &*self.key_type);

        match K::build(entries) {
            Ok(key) => {
                if key.key_type().as_str() == self.key_type {
                    Ok(key)
                } else {
                    Err(JsonWebKeyError::KeyType {
                        expected: self.key_type.clone(),
                        got: key.key_type().as_str().into(),
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

        let mut entries = self.parameters.clone();
        entries.insert("kty", &*self.key_type);

        let mut map = serializer.serialize_map(Some(entries.len()))?;
        for (key, value) in entries {
            map.serialize_entry(&key, &value)?;
        }
        map.end()
    }
}

/// The members of a JWK, other than `kty`, which are hashed to compute its thumbprint.
///
/// See [RFC 7638, section 3.2](https://tools.ietf.org/html/rfc7638#section-3.2).
fn thumbprint_members(key_type: &str) -> Option<&'static [&'static str]> {
    match key_type {
        "oct" => Some(&["k"]),
        "RSA" => Some(&["e", "n"]),
        "EC" => Some(&["crv", "x", "y"]),
        "OKP" => Some(&["crv", "x"]),
        _ => None,
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

    /// Compute the thumbprint of a JWK, as defined by [RFC 7638][RFC7638].
    ///
    /// Only the members which are required for the key type are hashed (`k` for
    /// `oct`, `e` and `n` for `RSA`, `crv`, `x` and `y` for `EC`, and `crv` and `x`
    /// for `OKP`), along with `kty`. Any other member, such as `kid`, `alg` or
    /// the private members of a private key, does not affect the thumbprint. A
    /// public key and its private key therefore have the same thumbprint.
    ///
    /// [RFC7638]: https://tools.ietf.org/html/rfc7638
    pub fn from_jwk(jwk: &JsonWebKey) -> Result<Self, JsonWebKeyError> {
        let members = thumbprint_members(jwk.key_type())
            .ok_or_else(|| JsonWebKeyError::UnsupportedKeyType(jwk.key_type().to_owned()))?;

        // A `BTreeMap` serializes its members in lexicographic order, with no
        // whitespace, as the RFC requires.
        let mut required: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
        required.insert("kty", jwk.key_type().into());
        for &name in members {
            let value = jwk
                .parameters()
                .get(name)
                .ok_or(JsonWebKeyError::MissingParameter(name))?;

            if !value.is_string() {
                return Err(JsonWebKeyError::InvalidKey(
                    name,
                    "thumbprint members must be strings".into(),
                ));
            }
            required.insert(name, value.clone());
        }

        let thumb = serde_json::to_vec(&required)?;

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

/// An identified key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identified<Key> {
    /// The key itself.
    #[serde(flatten)]
    pub key: Key,

    /// The identifier of the key.
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none", default)]
    pub id: Option<String>,
}

impl<Key> Identified<Key> {
    /// Creates an unidentified key.
    pub fn unidentified(key: Key) -> Self {
        Self { key, id: None }
    }

    /// Sets the identifier of the key.
    pub fn with_id(self, id: String) -> Self {
        Self {
            id: Some(id),
            ..self
        }
    }

    /// Returns the identifier of the key.
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use static_assertions as sa;

    sa::assert_obj_safe!(SerializeJWK);

    use super::fixtures;
    use crate::algorithms::ALL_ALGORITHMS;
    use serde_json::json;

    const KEY_TYPES: [(KeyType, &str); 4] = [
        (KeyType::Octet, "oct"),
        (KeyType::Rsa, "RSA"),
        (KeyType::EllipticCurve, "EC"),
        (KeyType::OctetPairs, "OKP"),
    ];

    #[test]
    fn key_type_string_forms() {
        for (key_type, name) in KEY_TYPES {
            assert_eq!(key_type.as_str(), name);
            assert_eq!(key_type.to_string(), name);
            assert_eq!(String::from(key_type), name);
            assert_eq!(serde_json::Value::from(key_type), json!(name));

            assert_eq!(name.parse::<KeyType>().unwrap(), key_type);
            assert_eq!(KeyType::try_from(name).unwrap(), key_type);
            assert_eq!(KeyType::try_from(name.to_owned()).unwrap(), key_type);
        }
    }

    #[test]
    fn key_type_serde_roundtrip() {
        for (key_type, name) in KEY_TYPES {
            assert_eq!(serde_json::to_value(key_type).unwrap(), json!(name));
            assert_eq!(
                serde_json::to_string(&key_type).unwrap(),
                format!("\"{name}\"")
            );

            // Borrowed and owned inputs go through different serde paths.
            let from_str: KeyType = serde_json::from_str(&format!("\"{name}\"")).unwrap();
            assert_eq!(from_str, key_type);
            let from_value: KeyType = serde_json::from_value(json!(name)).unwrap();
            assert_eq!(from_value, key_type);
        }
    }

    #[test]
    fn key_type_rejects_unknown_names() {
        for name in ["", "rsa", "ec", "OCT", "okp", "banana", "RSA "] {
            assert!(name.parse::<KeyType>().is_err(), "{name:?}");
            assert!(
                serde_json::from_value::<KeyType>(json!(name)).is_err(),
                "{name:?}"
            );
        }

        assert!(serde_json::from_value::<KeyType>(json!(1)).is_err());
        assert!(serde_json::from_value::<KeyType>(json!(null)).is_err());
    }

    #[test]
    fn key_type_is_supported_follows_features() {
        assert_eq!(KeyType::Octet.is_supported(), cfg!(feature = "hmac"));
        assert_eq!(KeyType::Rsa.is_supported(), cfg!(feature = "rsa"));
        assert_eq!(
            KeyType::EllipticCurve.is_supported(),
            cfg!(feature = "ecdsa")
        );
        assert_eq!(
            KeyType::OctetPairs.is_supported(),
            cfg!(feature = "ed25519")
        );
    }

    #[test]
    fn key_type_supports_the_algorithms_of_its_keys() {
        for f in fixtures::private_keys() {
            let key_type = f.key.key_type();
            assert_eq!(key_type.as_str(), f.kty, "{}", f.label);

            for alg in &f.algorithms {
                assert!(key_type.supports_alg(alg), "{}: {alg:?}", f.label);

                for (other, _) in KEY_TYPES.iter().filter(|(k, _)| *k != key_type) {
                    assert!(
                        !other.supports_alg(alg),
                        "{}: {other:?} should not support {alg:?}",
                        f.label
                    );
                }
            }
        }
    }

    #[test]
    fn no_key_type_supports_none() {
        for (key_type, _) in KEY_TYPES {
            assert!(!key_type.supports_alg(&AlgorithmIdentifier::None));
        }
    }

    #[test]
    fn each_algorithm_has_one_key_type() {
        for alg in ALL_ALGORITHMS
            .iter()
            .filter(|a| **a != AlgorithmIdentifier::None)
        {
            let supporting: Vec<_> = KEY_TYPES
                .iter()
                .filter(|(k, _)| k.supports_alg(alg))
                .collect();
            assert_eq!(supporting.len(), 1, "{alg:?}: {supporting:?}");
        }
    }

    #[test]
    fn parameters_behave_like_a_map() {
        let mut parameters = Parameters::new();
        assert!(parameters.is_empty());

        parameters.insert("b", "two");
        parameters.insert("a", 1);
        parameters.insert(String::from("c"), KeyType::Rsa);
        assert_eq!(parameters.len(), 3);
        assert_eq!(parameters.get("a"), Some(&json!(1)));
        assert_eq!(parameters.get("c"), Some(&json!("RSA")));
        assert_eq!(parameters.get("missing"), None);

        // Inserting replaces.
        parameters.insert("a", "one");
        assert_eq!(parameters.len(), 3);
        assert_eq!(parameters.get("a"), Some(&json!("one")));

        // Iteration is alphabetical.
        let keys: Vec<_> = parameters.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, ["a", "b", "c"]);

        assert_eq!(parameters.remove("b"), Some(json!("two")));
        assert_eq!(parameters.remove("b"), None);
        assert_eq!(parameters.len(), 2);

        parameters.extend([("z".to_owned(), json!(true))]);
        let collected: Parameters = parameters.clone().into_iter().collect();
        assert_eq!(collected, parameters);
    }

    #[test]
    fn parameters_serialize_as_a_plain_object() {
        let mut parameters = Parameters::new();
        parameters.insert("b", "two");
        parameters.insert("a", 1);

        let value = serde_json::to_value(&parameters).unwrap();
        assert_eq!(value, json!({"a": 1, "b": "two"}));

        let back: Parameters = serde_json::from_value(value).unwrap();
        assert_eq!(back, parameters);

        assert!(serde_json::from_value::<Parameters>(json!([1, 2])).is_err());
    }

    #[cfg(any(feature = "hmac", feature = "rsa", feature = "ecdsa"))]
    #[test]
    fn json_web_key_serde_roundtrip() {
        for f in fixtures::private_keys() {
            for (kind, jwk) in [
                ("private", JsonWebKey::build(&f.key)),
                ("public", JsonWebKey::build(&f.public())),
            ] {
                let label = format!("{} {kind}", f.label);
                assert_eq!(jwk.key_type(), f.kty, "{label}");
                assert!(jwk.parameters().get("kty").is_none(), "{label}");

                let rendered = serde_json::to_string(&jwk).unwrap();
                assert_eq!(
                    rendered.matches("\"kty\"").count(),
                    1,
                    "{label}: {rendered}"
                );

                let back: JsonWebKey = serde_json::from_str(&rendered).unwrap();
                assert_eq!(back.key_type(), f.kty, "{label}");
                assert_eq!(back.parameters(), jwk.parameters(), "{label}");
                assert_eq!(serde_json::to_string(&back).unwrap(), rendered, "{label}");
            }
        }
    }

    #[cfg(any(feature = "hmac", feature = "rsa", feature = "ecdsa"))]
    #[test]
    fn json_web_key_build_public_drops_private_members() {
        for f in fixtures::private_keys()
            .into_iter()
            .filter(|f| !f.is_symmetric())
        {
            let jwk = JsonWebKey::build_public(&f.key);

            for member in fixtures::PRIVATE_MEMBERS {
                assert!(
                    jwk.parameters().get(member).is_none(),
                    "{}: {member}",
                    f.label
                );
            }

            // Same thing as building from the public key.
            let from_public = JsonWebKey::build(&f.public());
            assert_eq!(jwk.parameters(), from_public.parameters(), "{}", f.label);
        }
    }

    #[test]
    fn json_web_key_deserialize_key_checks_key_type() {
        for f in fixtures::private_keys() {
            let jwk = JsonWebKey::build(&f.key);

            // The right type works...
            assert!(
                jwk.deserialize_key::<PrivateWebKey>().is_ok(),
                "{}",
                f.label
            );

            // ...but a key type that disagrees with the JWK's `kty` does not.
            #[cfg(feature = "hmac")]
            if f.kty != "oct" {
                assert!(
                    jwk.deserialize_key::<crate::algorithms::hmac::HmacKey>()
                        .is_err(),
                    "{}",
                    f.label
                );
            }
            #[cfg(feature = "rsa")]
            if f.kty != "RSA" {
                assert!(
                    jwk.deserialize_key::<::rsa::PublicKey>().is_err(),
                    "{}",
                    f.label
                );
            }
        }
    }

    #[test]
    fn json_web_key_parses_arbitrary_members() {
        let jwk: JsonWebKey = serde_json::from_value(json!({
            "kty": "oct",
            "k": "AQID",
            "kid": "abc",
            "use": "sig",
            "custom": {"nested": [1, 2, 3]},
        }))
        .unwrap();

        assert_eq!(jwk.key_type(), "oct");
        assert_eq!(jwk.parameters().len(), 4);
        assert_eq!(
            jwk.parameters().get("custom"),
            Some(&json!({"nested": [1, 2, 3]}))
        );

        // Unknown members survive a round trip.
        let back: JsonWebKey = serde_json::from_value(serde_json::to_value(&jwk).unwrap()).unwrap();
        assert_eq!(back.parameters(), jwk.parameters());
    }

    #[test]
    fn json_web_key_requires_kty() {
        assert!(serde_json::from_value::<JsonWebKey>(json!({"k": "AQID"})).is_err());
        assert!(serde_json::from_value::<JsonWebKey>(json!({"kty": 1})).is_err());
    }

    #[test]
    fn parameters_debug_redacts_secret_members() {
        let mut parameters = Parameters::new();
        for member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
            parameters.insert(member, "SECRET-VALUE");
        }
        parameters.insert("n", "PUBLIC-VALUE");
        parameters.insert("kty", "RSA");

        for rendered in [format!("{parameters:?}"), format!("{parameters:#?}")] {
            assert!(!rendered.contains("SECRET-VALUE"), "{rendered}");
            assert_eq!(rendered.matches("<redacted>").count(), 8, "{rendered}");

            // Public members are still useful when debugging.
            assert!(rendered.contains("PUBLIC-VALUE"), "{rendered}");
            assert!(rendered.contains("RSA"), "{rendered}");
        }
    }

    mod thumbprints {
        use super::*;

        use sha2::{Digest, Sha256};

        fn thumbprint(jwk: &JsonWebKey) -> Thumbprint<Sha256> {
            Thumbprint::from_jwk(jwk).unwrap()
        }

        /// The thumbprint of a canonical JSON string.
        fn digest(canonical: &str) -> String {
            base64ct::Base64UrlUnpadded::encode_string(&Sha256::digest(canonical.as_bytes()))
        }

        /// The RSA key from RFC 7638, section 3.1, without line wrapping.
        fn rfc7638_n() -> String {
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt
             VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6
             4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD
             W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9
             1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH
             aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect()
        }

        fn rfc7638_jwk(extra: serde_json::Value) -> JsonWebKey {
            let mut value = json!({"kty": "RSA", "n": rfc7638_n(), "e": "AQAB"});
            value
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            serde_json::from_value(value).unwrap()
        }

        #[test]
        fn rfc7638_example() {
            // RFC 7638 section 3.1 lists the exact octets which are hashed...
            let canonical = format!(r#"{{"e":"AQAB","kty":"RSA","n":"{}"}}"#, rfc7638_n());
            assert_eq!(
                digest(&canonical),
                "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
            );

            // ...and the thumbprint of the key is the digest of those octets.
            let thumb = thumbprint(&rfc7638_jwk(json!({})));
            assert_eq!(&*thumb, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
        }

        #[test]
        fn members_which_are_not_required_are_ignored() {
            let plain = thumbprint(&rfc7638_jwk(json!({})));

            let decorated = rfc7638_jwk(json!({
                "kid": "2011-04-29",
                "alg": "RS256",
                "use": "sig",
                "key_ops": ["verify"],
                "x5c": ["MIIB"],
                "custom": {"nested": true},
            }));
            assert_eq!(thumbprint(&decorated), plain);
        }

        #[test]
        fn required_members_are_hashed_in_lexicographic_order() {
            let jwk: JsonWebKey = serde_json::from_value(json!({
                "y": "y-value", "x": "x-value", "kty": "EC", "crv": "P-256", "kid": "ignored",
            }))
            .unwrap();
            assert_eq!(
                &*thumbprint(&jwk),
                digest(r#"{"crv":"P-256","kty":"EC","x":"x-value","y":"y-value"}"#)
            );

            let jwk: JsonWebKey = serde_json::from_value(json!({
                "kty": "oct", "k": "k-value", "alg": "HS256",
            }))
            .unwrap();
            assert_eq!(&*thumbprint(&jwk), digest(r#"{"k":"k-value","kty":"oct"}"#));

            let jwk: JsonWebKey = serde_json::from_value(json!({
                "kty": "OKP", "x": "x-value", "crv": "Ed25519", "d": "ignored",
            }))
            .unwrap();
            assert_eq!(
                &*thumbprint(&jwk),
                digest(r#"{"crv":"Ed25519","kty":"OKP","x":"x-value"}"#)
            );
        }

        #[cfg(any(feature = "hmac", feature = "rsa", feature = "ecdsa"))]
        #[test]
        fn private_and_public_keys_share_a_thumbprint() {
            for f in fixtures::private_keys() {
                let private = thumbprint(&JsonWebKey::build(&f.key));
                let public = thumbprint(&JsonWebKey::build(&f.public()));
                assert_eq!(private, public, "{}", f.label);

                // Derived from the key directly, too.
                let derived: Thumbprint<Sha256> = Thumbprint::derive_from_key(&f.key).unwrap();
                assert_eq!(derived, public, "{}", f.label);
            }
        }

        #[cfg(any(feature = "hmac", feature = "rsa", feature = "ecdsa"))]
        #[test]
        fn algorithm_specific_keys_share_a_thumbprint() {
            // `alg` is part of the JWK for signing and verifying keys, but not the thumbprint.
            for f in fixtures::private_keys() {
                let expected = thumbprint(&JsonWebKey::build(&f.public()));

                for &alg in &f.algorithms {
                    let signing = f.key.clone().into_signing_key(alg).unwrap();
                    let verifying = f.public().into_verifying_key(alg).unwrap();

                    let label = format!("{} / {alg:?}", f.label);
                    assert_eq!(
                        thumbprint(&JsonWebKey::build(&signing)),
                        expected,
                        "{label}"
                    );
                    assert_eq!(
                        thumbprint(&JsonWebKey::build(&verifying)),
                        expected,
                        "{label}"
                    );
                }
            }
        }

        #[cfg(any(feature = "hmac", feature = "rsa", feature = "ecdsa"))]
        #[test]
        fn different_keys_have_different_thumbprints() {
            let keys = fixtures::private_keys();
            let thumbprints: Vec<_> = keys
                .iter()
                .map(|f| thumbprint(&JsonWebKey::build(&f.public())))
                .collect();

            for (i, a) in thumbprints.iter().enumerate() {
                for b in &thumbprints[i + 1..] {
                    assert_ne!(a, b);
                }
            }
        }

        #[test]
        fn digest_selects_the_thumbprint_length() {
            let jwk = rfc7638_jwk(json!({}));

            // Unpadded base64url of 20, 32 and 48 bytes.
            assert_eq!(Thumbprint::<sha1::Sha1>::from_jwk(&jwk).unwrap().len(), 27);
            assert_eq!(Thumbprint::<Sha256>::from_jwk(&jwk).unwrap().len(), 43);
            assert_eq!(
                Thumbprint::<sha2::Sha384>::from_jwk(&jwk).unwrap().len(),
                64
            );
        }

        #[test]
        fn missing_required_members_are_an_error() {
            for (kty, required) in [
                ("oct", &["k"][..]),
                ("RSA", &["e", "n"][..]),
                ("EC", &["crv", "x", "y"][..]),
                ("OKP", &["crv", "x"][..]),
            ] {
                let mut complete = json!({"kty": kty});
                for member in required {
                    complete[member] = json!("value");
                }

                let jwk: JsonWebKey = serde_json::from_value(complete.clone()).unwrap();
                assert!(Thumbprint::<Sha256>::from_jwk(&jwk).is_ok(), "{kty}");

                for &member in required {
                    let mut value = complete.clone();
                    value.as_object_mut().unwrap().remove(member);
                    let jwk: JsonWebKey = serde_json::from_value(value).unwrap();

                    let err = Thumbprint::<Sha256>::from_jwk(&jwk).unwrap_err();
                    assert!(
                        matches!(err, JsonWebKeyError::MissingParameter(m) if m == member),
                        "{kty} without {member}: {err:?}"
                    );
                }
            }
        }

        #[test]
        fn required_members_must_be_strings() {
            for bad in [json!(1), json!(null), json!(["AQAB"]), json!({"a": 1})] {
                let jwk: JsonWebKey = serde_json::from_value(json!({
                    "kty": "RSA", "n": rfc7638_n(), "e": bad,
                }))
                .unwrap();

                let err = Thumbprint::<Sha256>::from_jwk(&jwk).unwrap_err();
                assert!(
                    matches!(err, JsonWebKeyError::InvalidKey("e", _)),
                    "{bad}: {err:?}"
                );
            }
        }

        #[test]
        fn unknown_key_types_are_an_error() {
            let jwk: JsonWebKey =
                serde_json::from_value(json!({"kty": "banana", "k": "AQID"})).unwrap();

            let err = Thumbprint::<Sha256>::from_jwk(&jwk).unwrap_err();
            assert!(
                matches!(err, JsonWebKeyError::UnsupportedKeyType(ref t) if t == "banana"),
                "{err:?}"
            );
        }
    }

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

        #[test]
        fn rfc7639_example_jwk() {
            let key: JsonWebKey = serde_json::from_value(json!({
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

            let pub_key: PublicWebKey = key.deserialize_key().unwrap();
            assert_eq!(pub_key.key_type(), KeyType::Rsa);
        }
    }
}
