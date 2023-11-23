use serde::Serialize;
use sha1::Sha1;
use sha2::Sha256;

use crate::{algorithms::AlgorithmIdentifier, key::SerializeJWK};

use crate::key::{JsonWebKeyBuilder, Thumbprinter};

use super::derive::DerivedKeyValue;
use super::HeaderState;

/// The registered fields of a JOSE header, which are interdependent
/// with the signing key.
#[derive(Debug, Clone, Serialize)]
#[serde(bound(serialize = "Key: SerializeJWK + Clone"))]
pub struct SignedHeader<Key>
where
    Key: SerializeJWK,
{
    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/algorithm.md"))]
    #[serde(rename = "alg")]
    pub(super) algorithm: AlgorithmIdentifier,

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/json_web_key.md"))]
    #[serde(rename = "jwk", skip_serializing_if = "DerivedKeyValue::is_none")]
    pub(super) key: DerivedKeyValue<JsonWebKeyBuilder<Key>, Key>,

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/thumbprint.md"))]
    #[serde(rename = "x5t", skip_serializing_if = "DerivedKeyValue::is_none")]
    pub(super) thumbprint: DerivedKeyValue<Thumbprinter<Sha1, Key>, Key>,

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/thumbprint_sha256.md"))]
    #[serde(rename = "x5t#S256", skip_serializing_if = "DerivedKeyValue::is_none")]
    pub(super) thumbprint_sha256: DerivedKeyValue<Thumbprinter<Sha256, Key>, Key>,
}

impl<Key> HeaderState for SignedHeader<Key>
where
    Key: SerializeJWK + Clone,
{
    fn parameters(&self) -> std::collections::BTreeMap<String, serde_json::Value> {
        let mut data = std::collections::BTreeMap::new();

        data.insert(
            "alg".to_owned(),
            serde_json::to_value(&self.algorithm).unwrap(),
        );

        if let Some(value) = self.key.parameter() {
            data.insert("jwk".to_owned(), value);
        }

        if let Some(value) = self.thumbprint.parameter() {
            data.insert("x5t".to_owned(), value);
        }

        if let Some(value) = self.thumbprint_sha256.parameter() {
            data.insert("x5t#S256".to_owned(), value);
        }

        data
    }
}
