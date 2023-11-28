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
use signature::Error as SignatureError;

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

/// Trait for keys which can be deserialized from a JWK.
pub trait DeserializeJWK: JWKeyType {
    /// From a set of parameters, build a key.
    fn build(parameters: BTreeMap<String, serde_json::Value>) -> Result<Self, serde_json::Error>
    where
        Self: Sized;
}

/// Trait for building values derived from a key.
pub trait BuildFromKey<Key: ?Sized> {
    /// Build a value from a key.
    fn build(key: &Key) -> Result<Self, SignatureError>
    where
        Self: Sized;
}

impl<Key> BuildFromKey<Key> for JsonWebKey
where
    Key: SerializeJWK + ?Sized,
{
    fn build(key: &Key) -> Result<Self, SignatureError> {
        Ok(JsonWebKey {
            key_type: key.key_type().into(),
            parameters: key.parameters().into_iter().collect(),
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
    /// Build a JWK from a key.
    pub fn build<K: SerializeJWK + ?Sized>(key: &K) -> Self {
        JsonWebKey {
            key_type: key.key_type().into(),
            parameters: key.parameters().into_iter().collect(),
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

    fn build<K>(key: &K) -> Result<Self, SignatureError>
    where
        K: SerializeJWK + ?Sized,
    {
        let jwk = JsonWebKey::build(key);
        let thumb = serde_json::to_vec(&jwk).map_err(|err| SignatureError::from_source(err))?;

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
    Key: SerializeJWK + ?Sized,
    Digest: digest::Digest,
{
    fn build(key: &Key) -> Result<Thumbprint<Digest>, signature::Error> {
        Thumbprint::build(key).map_err(|err| signature::Error::from_source(err))
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
        write!(f, "{}", self.thumbprint)
    }
}

impl<Digest> std::ops::Deref for Thumbprint<Digest> {
    type Target = str;

    fn deref(&self) -> &str {
        &self.thumbprint
    }
}

#[cfg(all(test, feature = "rsa"))]
pub(crate) mod jwk_reader {
    use base64ct::Encoding;
    use rsa::traits::PrivateKeyParts;

    fn strip_whitespace(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    fn to_biguint(v: &serde_json::Value) -> Option<rsa::BigUint> {
        let val = strip_whitespace(v.as_str()?);
        Some(rsa::BigUint::from_bytes_be(
            base64ct::Base64UrlUnpadded::decode_vec(&val)
                .ok()?
                .as_slice(),
        ))
    }

    pub(crate) fn rsa_pub(key: &serde_json::Value) -> rsa::RsaPublicKey {
        let n = to_biguint(&key["n"]).expect("decode n");
        let e = to_biguint(&key["e"]).expect("decode e");

        rsa::RsaPublicKey::new(n, e).expect("valid key parameters")
    }

    pub(crate) fn rsa(key: &serde_json::Value) -> rsa::RsaPrivateKey {
        let primes = vec![
            to_biguint(&key["p"]).expect("p"),
            to_biguint(&key["q"]).expect("q"),
        ];

        let pkey = rsa::RsaPrivateKey::from_components(
            to_biguint(&key["n"]).expect("n"),
            to_biguint(&key["e"]).expect("e"),
            to_biguint(&key["d"]).expect("d"),
            primes,
        )
        .unwrap();

        assert_eq!(&to_biguint(&key["dp"]).expect("dp"), pkey.dp().unwrap());
        assert_eq!(&to_biguint(&key["dq"]).expect("dq"), pkey.dq().unwrap());

        pkey
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use static_assertions as sa;

    sa::assert_obj_safe!(SerializeJWK);

    #[cfg(all(test, feature = "rsa"))]
    mod rsa {
        use super::super::*;

        use serde_json::json;

        #[cfg(feature = "rsa")]
        #[test]
        fn rfc7639_example() {
            let key = jwk_reader::rsa_pub(&json!({
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
            ));

            let thumb: Thumbprint<sha2::Sha256> = Thumbprint::build(&key).unwrap();

            assert_eq!(&*thumb, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
        }
    }
}
