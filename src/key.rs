use std::{collections::BTreeMap, marker::PhantomData};

use base64ct::Encoding;
use digest::Digest;
use serde::{ser::SerializeMap, Serialize};

pub trait KeyInfo {
    const KEY_TYPE: &'static str;

    fn parameters(&self) -> Vec<(String, serde_json::Value)>;
}

pub trait DeserializeKey {
    type Key: KeyInfo;

    fn deserialize_key<'de, D>(deserializer: D) -> Result<Self::Key, D::Error>
    where
        D: serde::Deserializer<'de>;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JWK<K>(K);

impl<K> From<K> for JWK<K> {
    fn from(key: K) -> Self {
        Self(key)
    }
}

impl<Key> Serialize for JWK<Key>
where
    Key: KeyInfo,
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Thumbprint<Digest, Key> {
    digest: PhantomData<Digest>,
    key: JWK<Key>,
}

impl<D, K> Thumbprint<D, K> {
    pub fn new(key: K) -> Self {
        Self {
            digest: PhantomData,
            key: JWK::from(key),
        }
    }
}

impl<D, K> Thumbprint<D, K>
where
    D: Digest,
    K: KeyInfo,
{
    pub fn digest(&self) -> Vec<u8> {
        let thumb = serde_json::to_vec(&self.key).expect("Valid JSON format");

        let mut hasher = D::new();
        hasher.update(&thumb);
        let digest = hasher.finalize();
        digest.to_vec()
    }

    pub fn digest_base64(&self) -> String {
        base64ct::Base64UrlUnpadded::encode_string(&self.digest())
    }
}

impl<D, K> Serialize for Thumbprint<D, K>
where
    K: KeyInfo,
    D: Digest,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.digest_base64())
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

        let thumb = Thumbprint::<sha2::Sha256, _>::new(key);

        assert_eq!(
            thumb.digest_base64(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }
}
