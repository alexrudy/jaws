use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;

use crate::algorithms::AlgorithmIdentifier;

use crate::key::{JsonWebKey, Thumbprint};

use super::HeaderState;

/// The registered fields of a JOSE header, which are interdependent
/// with the signing key, rendered into their typed form.
///
/// This is different from [SignedHeader] in that it contains the actual data,
/// and not thd derivation, so the fields may be in inconsistent states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedHeader {
    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/algorithm.md"))]
    #[serde(rename = "alg")]
    pub(super) algorithm: AlgorithmIdentifier,

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/json_web_key.md"))]
    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    pub(super) key: Option<JsonWebKey>,

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/thumbprint.md"))]
    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    pub(super) thumbprint: Option<Thumbprint<Sha1>>,

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/thumbprint_sha256.md"))]
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub(super) thumbprint_sha256: Option<Thumbprint<Sha256>>,
}

impl HeaderState for RenderedHeader {
    fn parameters(&self) -> std::collections::BTreeMap<String, serde_json::Value> {
        let mut data = std::collections::BTreeMap::new();

        data.insert(
            "alg".to_owned(),
            serde_json::to_value(&self.algorithm).unwrap(),
        );

        if let Some(value) = self.key.as_ref() {
            data.insert("jwk".to_owned(), serde_json::to_value(value).unwrap());
        }

        if let Some(value) = self.thumbprint.as_ref() {
            data.insert("x5t".to_owned(), serde_json::to_value(value).unwrap());
        }

        if let Some(value) = self.thumbprint_sha256.as_ref() {
            data.insert("x5t#S256".to_owned(), serde_json::to_value(value).unwrap());
        }

        data
    }
}
