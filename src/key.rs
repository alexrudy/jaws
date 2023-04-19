//! JSON Web Keys ([RFC 7517][RFC7517])
//!
//! This module implements the JWK format for representing cryptographic keys.
//! For now, it only supports serialization for Keys and Thumbprints.
//!
//! [RFC7517]: https://tools.ietf.org/html/rfc7517

use std::{collections::BTreeMap, marker::PhantomData};

use base64ct::Encoding;
use digest::Digest;
use serde::{ser::SerializeMap, Deserialize, Serialize};

/// Trait for keys which can be used as a JWK.
pub trait JWKeyType {
    /// The string used to identify the JWK type in the `kty` field.
    const KEY_TYPE: &'static str;
}

/// Trait for keys which can be serialized as a JWK.
pub trait SerializeJWK: JWKeyType {
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

/// A JSON Web Key with the original key contained inside.
///
/// The actual key isn't produced until this is serialized.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JsonWebKeyBuilder<K>(K);

impl<K> From<K> for JsonWebKeyBuilder<K> {
    fn from(key: K) -> Self {
        Self(key)
    }
}

impl<Key> Serialize for JsonWebKeyBuilder<Key>
where
    Key: SerializeJWK,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Asseble keys first so that we can order them.
        let mut keys = BTreeMap::new();
        keys.insert(
            "kty".to_owned(),
            serde_json::Value::String(Key::KEY_TYPE.to_owned()),
        );
        for (key, value) in self.0.parameters() {
            keys.insert(key, value);
        }

        // Put them back so we can serialize them in lexical order.
        let mut map = serializer.serialize_map(Some(keys.len()))?;
        for (key, value) in keys {
            map.serialize_entry(&key, &value)?;
        }

        map.end()
    }
}

/// JSON Web Key in serialized form.
///
/// This struct just contains the parameters of the JWK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonWebKey {
    #[serde(rename = "kty")]
    key_type: String,

    #[serde(flatten)]
    parameters: BTreeMap<String, serde_json::Value>,
}

impl<K> From<JsonWebKeyBuilder<K>> for JsonWebKey
where
    K: SerializeJWK,
{
    fn from(key: JsonWebKeyBuilder<K>) -> Self {
        JsonWebKey {
            key_type: K::KEY_TYPE.into(),
            parameters: key.0.parameters().into_iter().collect(),
        }
    }
}

/// A JSON Web Key Thumbprint (RFC 7638) calculator.
///
/// This type contains the raw parts to build a JWK and then digest
/// them to form a thumbprint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Thumbprinter<Digest, Key> {
    digest: PhantomData<Digest>,
    key: JsonWebKeyBuilder<Key>,
}

impl<D, K> Thumbprinter<D, K> {
    /// Create a new JWK Thumbprinter from a key.
    pub fn new(key: K) -> Self {
        Self {
            digest: PhantomData,
            key: JsonWebKeyBuilder::from(key),
        }
    }
}

impl<D, K> Thumbprinter<D, K>
where
    D: Digest,
    K: SerializeJWK,
{
    /// Compute the raw digest of the JWK.
    pub fn digest(&self) -> Vec<u8> {
        let thumb = serde_json::to_vec(&self.key).expect("Valid JSON format");

        let mut hasher = D::new();
        hasher.update(&thumb);
        let digest = hasher.finalize();
        digest.to_vec()
    }

    /// Compute the base64url-encoded digest of the JWK.
    pub fn thumbprint(&self) -> Thumbprint {
        Thumbprint(base64ct::Base64UrlUnpadded::encode_string(&self.digest()))
    }
}

impl<D, K> Serialize for Thumbprinter<D, K>
where
    K: SerializeJWK,
    D: Digest,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.thumbprint())
    }
}

/// A computed thumbprint.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    zeroize::Zeroize,
    zeroize::ZeroizeOnDrop,
)]
pub struct Thumbprint(String);

impl std::ops::Deref for Thumbprint {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
pub(crate) mod jwk_reader {
    use base64ct::Encoding;

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
    use std::ops::Deref;

    use serde_json::json;

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

        let thumb = Thumbprinter::<sha2::Sha256, _>::new(key);

        assert_eq!(
            thumb.thumbprint().deref(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }
}
