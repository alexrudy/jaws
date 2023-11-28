use std::collections::BTreeMap;

use sha1::Sha1;
use sha2::Sha256;

use crate::key::{JsonWebKey, Thumbprint};

use super::{DeriveFromKey, HeaderState};

/// A builder for the registered JOSE header fields for using JWTs.
///
/// Some fields are set indirectly by the builder, e.g. the `key` field is set
/// to `true` when you'd like to serialize the signing key in the JOSE header
/// as a JSON Web Key (JWK).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnsignedHeader {
    /// Whether to include the signing key in the JOSE header as a JWK.
    ///
    /// See [RenderedHeader::key] for field details.
    pub(super) key: DeriveFromKey<JsonWebKey>,

    /// Whether to include the X.509 certificate thumbprint in the JOSE header with the SHA1 digest.
    ///
    /// See [RenderedHeader::thumbprint] for field details.
    pub(super) thumbprint: DeriveFromKey<Thumbprint<Sha1>>,

    /// Whether to include the X.509 certificate thumbprint in the JOSE header with the SHA256 digest.
    ///
    /// See [RenderedHeader::thumbprint_sha256] for field details.
    pub(super) thumbprint_sha256: DeriveFromKey<Thumbprint<Sha256>>,
}

impl HeaderState for UnsignedHeader {
    fn parameters(
        &self,
    ) -> Result<BTreeMap<std::string::String, serde_json::Value>, serde_json::Error> {
        let mut data = std::collections::BTreeMap::new();

        if let Some(value) = self.key.parameter("jwk")? {
            data.insert("jwk".to_owned(), value);
        }

        if let Some(value) = self.thumbprint.parameter("x5t")? {
            data.insert("x5t".to_owned(), value);
        }

        if let Some(value) = self.thumbprint_sha256.parameter("x5t#S256")? {
            data.insert("x5t#S256".to_owned(), value);
        }

        Ok(data)
    }
}
