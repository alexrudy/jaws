use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;
use url::Url;

use crate::algorithms::AlgorithmIdentifier;
use crate::key::{Thumbprint, JWK};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Certificate;

#[derive(Debug, Clone, Default)]
pub struct JOSERegisteredHeaderBuilder {
    pub jwk_set_url: Option<Url>,
    pub r#type: Option<String>,
    pub key: bool,
    pub key_id: Option<String>,
    pub certificate_url: Option<Url>,
    pub certificate_chain: Option<Vec<Certificate>>,
    pub thumbprint: bool,
    pub thumbprint_256: bool,
    pub content_type: Option<String>,
    pub critical: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct JOSEHeaderBuilder<H> {
    pub registered: JOSERegisteredHeaderBuilder,
    pub custom: H,
}

impl JOSEHeaderBuilder<()> {
    pub fn new_registered() -> JOSEHeaderBuilder<()> {
        JOSEHeaderBuilder {
            registered: Default::default(),
            custom: (),
        }
    }
}

impl<H> JOSEHeaderBuilder<H> {
    pub fn new(custom: H) -> Self {
        Self {
            registered: Default::default(),
            custom,
        }
    }

    pub(crate) fn build<A>(self, key: &A::Key) -> JOSEHeader<H, A::Key>
    where
        A: crate::algorithms::SigningAlgorithm,
        A::Key: Clone,
    {
        let registered = JOSERegisteredHeader {
            jwk_set_url: self.registered.jwk_set_url,
            r#type: self.registered.r#type,
            key: if self.registered.key {
                Some(key.clone().into())
            } else {
                None
            },
            key_id: self.registered.key_id,
            certificate_url: self.registered.certificate_url,
            certificate_chain: self.registered.certificate_chain,
            thumbprint: if self.registered.thumbprint {
                Some(Thumbprint::<Sha1, _>::new(key.clone()))
            } else {
                None
            },
            thumbprint_sha256: if self.registered.thumbprint_256 {
                Some(Thumbprint::<Sha256, _>::new(key.clone()))
            } else {
                None
            },
            content_type: self.registered.content_type,
            critical: self.registered.critical,
        };

        JOSEHeader {
            algorithm: A::IDENTIFIER,
            registered,
            header: self.custom,
        }
    }
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(bound = "Key: crate::key::KeyInfo")]
pub struct JOSERegisteredHeader<Key = ()> {
    #[serde(rename = "jku", skip_serializing_if = "Option::is_none")]
    pub jwk_set_url: Option<Url>,

    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,

    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    pub key: Option<JWK<Key>>,

    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    pub certificate_url: Option<Url>,

    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    pub certificate_chain: Option<Vec<Certificate>>,

    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<Thumbprint<Sha1, Key>>,

    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub thumbprint_sha256: Option<Thumbprint<Sha256, Key>>,

    #[serde(rename = "cty", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    #[serde(rename = "crit", skip_serializing_if = "Option::is_none")]
    pub critical: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(bound = "Key: crate::key::KeyInfo, H: Serialize")]
pub struct JOSEHeader<H, Key = ()> {
    #[serde(rename = "alg")]
    pub(crate) algorithm: AlgorithmIdentifier,

    #[serde(flatten)]
    pub registered: JOSERegisteredHeader<Key>,

    #[serde(flatten)]
    pub header: H,
}
