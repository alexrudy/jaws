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
            let key = rsa::RsaPublicKey::from_value(json!({
                  "kty": "RSA",
                  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt
                  VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6
                  4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD
                  W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9
                  1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH
                  aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                  "e": "AQAB",
                  "alg": "RS256",
                  "kid": "2011-04-29"
                 }
            ))
            .unwrap();

            let thumb: Thumbprint<sha2::Sha256> =
                Thumbprint::from_jwk(&JsonWebKey::build(&key)).unwrap();

            assert_eq!(&*thumb, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
        }
    }
}
