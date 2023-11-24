//! JOSE Header implementation ([RFC 7515][rfc7515])
//!
//! The header format for JOSE, a JSON object with both registered and custom fields.
//!
//! This implementation tries to ensure that your fields are consistent, so e.g. it does
//! not allow you to set the algorithm ("alg") header unless you are actually singing the
//! key.
//!
//! [rfc7515]: https://tools.ietf.org/html/rfc7515

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha1::Sha1;
use sha2::Sha256;
use url::Url;

#[cfg(feature = "fmt")]
use crate::base64data::Base64JSON;
use crate::token::TokenVerifyingError;
use crate::{algorithms::AlgorithmIdentifier, key::SerializeJWK};

#[cfg(feature = "fmt")]
use crate::fmt;
use crate::key::{JsonWebKey, Thumbprint};

mod derive;
mod rendered;
mod signed;
mod unsigned;

use self::derive::DerivedKeyValue;
pub use self::derive::KeyDerivation;
pub use self::rendered::RenderedHeader;
pub use self::signed::SignedHeader;
pub use self::unsigned::UnsignedHeader;

/// Stub type to represent an X.509 certificate
///
/// This type should be replaced with a proper representation of an X.509
/// certificate, but that is not yet implemeted for this library.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Certificate;

pub trait HeaderState {
    fn parameters(&self) -> BTreeMap<String, serde_json::Value>;
}

#[derive(Debug, thiserror::Error)]
pub enum HeaderError {
    #[error("Key {0} is reserved for registered headers")]
    ReservedKey(&'static str),

    #[error("invalid header type: {0}")]
    InvalidType(String),

    #[error("unable to serialize header value: {0}")]
    Serde(#[from] serde_json::Error),
}

/// The registered fields of a JOSE header, independent of the signing key.
///
/// This struct represents the registered fields, filled in with a signing
/// key where that is reqiured. This type is used to ensure that fields
/// derived from cryptographic keys are consistent with the keys and algorithms
/// used to sign the entire token. To construct a JOSE header, use the
/// [Header::jwk()] method to set the included JWK, or the [Header::thumbprint()]
/// and [Header::thumbprint_sha256()] methods to set the included X.509 thumbprint.
#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq, Deserialize)]
struct RegisteredHeaderFields {
    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/jwk_set_url.md"))]
    #[serde(rename = "jku", skip_serializing_if = "Option::is_none")]
    jwk_set_url: Option<Url>,

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/type.md"))]
    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    r#type: Option<String>,

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/key_id.md"))]
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/certificate_url.md"))]
    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    pub certificate_url: Option<Url>,

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/certificate_chain.md"))]
    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    certificate_chain: Option<Vec<Certificate>>,

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/content_type.md"))]
    #[serde(rename = "cty", skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/critical.md"))]
    #[serde(rename = "crit", skip_serializing_if = "Option::is_none")]
    critical: Option<Vec<String>>,
}

const REGISTERED_HEADER_KEYS: [&str; 11] = [
    "alg", "jwk", "x5t", "x5t#S256", "jku", "typ", "kid", "x5u", "x5c", "cty", "crit",
];

/// The JOSE Header is a JSON object that represents the cryptographic operations
/// applied to the JWS Protected Header and the JWS Payload and optionally additional
/// properties of the JWS.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct Header<H, State> {
    #[serde(flatten)]
    pub(crate) state: State,

    /// The set of registered header parameters from [JWS][] and [JWA][].
    ///
    /// This does not include the `alg` parameter, which is handled separately.
    ///
    /// [JWA]: https://datatracker.ietf.org/doc/html/rfc7518
    /// [JWS]: https://datatracker.ietf.org/doc/html/rfc7515
    #[serde(flatten)]
    registered: RegisteredHeaderFields,

    /// The set of unregistered header parameters, which are custom provided
    /// by the type parameter H.
    #[serde(flatten)]
    pub custom: H,
}

impl<H, State> Serialize for Header<H, State>
where
    State: HeaderState,
    H: Serialize,
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = self.value().map_err(serde::ser::Error::custom)?;
        value.serialize(serializer)
    }
}

impl<H> Default for Header<H, UnsignedHeader>
where
    H: Default,
{
    fn default() -> Self {
        Self {
            state: UnsignedHeader::default(),
            registered: Default::default(),
            custom: Default::default(),
        }
    }
}

impl<H> Header<H, UnsignedHeader> {
    /// Create a new JOSE header builder with the given custom header.
    pub fn new(custom: H) -> Self {
        Self {
            state: UnsignedHeader::default(),
            registered: Default::default(),
            custom,
        }
    }

    /// Construct the JOSE header from the builder and signing key.
    pub(crate) fn sign<A>(self, key: &A::Key) -> Header<H, SignedHeader<A::Key>>
    where
        A: crate::algorithms::SigningAlgorithm,
        A::Key: Clone,
    {
        let state = SignedHeader {
            algorithm: A::IDENTIFIER,
            key: DerivedKeyValue::derive(self.state.key, key),
            thumbprint: DerivedKeyValue::derive(self.state.thumbprint, key),
            thumbprint_sha256: DerivedKeyValue::derive(self.state.thumbprint_sha256, key),
        };

        Header {
            state,
            registered: self.registered,
            custom: self.custom,
        }
    }

    /// Access the JWK setting for the header.
    pub fn jwk(&mut self) -> &mut KeyDerivation<JsonWebKey> {
        &mut self.state.key
    }

    /// Access the JWK thumbprint setting for the header.
    pub fn thumbprint(&mut self) -> &mut KeyDerivation<Thumbprint<Sha1>> {
        &mut self.state.thumbprint
    }

    /// Access the JWK thumbprint setting for the header.
    pub fn thumbprint_sha256(&mut self) -> &mut KeyDerivation<Thumbprint<Sha256>> {
        &mut self.state.thumbprint_sha256
    }
}

impl<H, Key> Header<H, SignedHeader<Key>>
where
    Key: SerializeJWK,
{
    /// JWK signing algorithm in use.
    pub fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.state.algorithm
    }

    /// Render a signed JWK header into its rendered
    /// form, where the derived fields have been built
    /// as necessary.
    pub fn render(self) -> Header<H, RenderedHeader>
    where
        H: Serialize,
        SignedHeader<Key>: HeaderState,
    {
        let headers = Base64JSON(&self)
            .serialized_bytes()
            .expect("valid header value");

        let state = RenderedHeader {
            raw: headers,
            algorithm: self.state.algorithm,
            key: self.state.key.build(),
            thumbprint: self.state.thumbprint.build(),
            thumbprint_sha256: self.state.thumbprint_sha256.build(),
        };

        Header {
            state,
            registered: self.registered,
            custom: self.custom,
        }
    }
}

impl<H> Header<H, RenderedHeader> {
    pub fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.state.algorithm
    }

    #[allow(unused_variables)]
    pub(crate) fn verify<A>(
        self,
        key: &A::Key,
    ) -> Result<Header<H, SignedHeader<A::Key>>, TokenVerifyingError<A::Error>>
    where
        A: crate::algorithms::VerifyAlgorithm,
    {
        // This may need to only verify that the algorithm header matches the key algorithm.
        if A::IDENTIFIER != self.state.algorithm {
            return Err(TokenVerifyingError::Algorithm(
                A::IDENTIFIER,
                self.state.algorithm,
            ));
        }
        Ok(Header {
            state: SignedHeader {
                algorithm: self.state.algorithm,
                key: DerivedKeyValue::explicit(self.state.key),
                thumbprint: DerivedKeyValue::explicit(self.state.thumbprint),
                thumbprint_sha256: DerivedKeyValue::explicit(self.state.thumbprint_sha256),
            },
            registered: self.registered,
            custom: self.custom,
        })
    }
}

impl<H, State> Header<H, State>
where
    H: Serialize,
    State: HeaderState,
{
    pub(crate) fn value(&self) -> Result<serde_json::Value, HeaderError> {
        // Re-using the parameters map here is important, because it will
        // alphabetize our keys, resulting in a consistent key order in rendered
        // tokens.
        let mut parameters = self.state.parameters();
        let header = serde_json::to_value(&self.registered)?;
        let custom = serde_json::to_value(&self.custom)?;

        match header {
            Value::Object(header) => {
                for (key, value) in header {
                    if parameters.insert(key.clone(), value.clone()).is_some() {
                        panic!("duplicate registered header key: {}", key);
                    }
                }
            }
            Value::Null => {}
            _ => panic!("registered headers are objects"),
        }

        match custom {
            Value::Object(custom) => {
                for (key, value) in custom {
                    if let Some(key) = REGISTERED_HEADER_KEYS.iter().find(|&&k| k == key) {
                        return Err(HeaderError::ReservedKey(key));
                    }
                    if parameters.insert(key.clone(), value.clone()).is_some() {
                        panic!("duplicate custom header key (should have errored as a registered key): {}", key);
                    }
                }
            }
            Value::Null => {}
            _ => panic!("custom headers are objects"),
        };

        let mut map = serde_json::Map::new();
        map.extend(parameters);
        Ok(map.into())
    }
}

#[cfg(feature = "fmt")]
impl<H, State> fmt::JWTFormat for Header<H, State>
where
    H: Serialize,
    State: HeaderState,
{
    fn fmt<W: std::fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> std::fmt::Result {
        let value = self.value().expect("valid header values");

        Base64JSON(value).fmt(f)
    }
}

/// Access to the header fields of a JOSE header.
#[derive(Debug)]
pub struct HeaderAccess<'h, H, State> {
    header: &'h Header<H, State>,
}

impl<'h, H, State> HeaderAccess<'h, H, State> {
    pub(crate) fn new(header: &'h Header<H, State>) -> Self {
        Self { header }
    }

    /// Custom header values. The type of this field is determined by the
    /// type parameter H in the token, and can be used for any arbitrary
    /// JSON values which should be included in the signature.
    ///
    /// Using a custom header value which conflicts with a registered header
    /// value will result in an error when signing the token.
    pub fn custom(&self) -> &H {
        &self.header.custom
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/jwk_set_url.md"))]
    pub fn jwk_set_url(&self) -> Option<&Url> {
        self.header.registered.jwk_set_url.as_ref()
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/type.md"))]
    pub fn r#type(&self) -> Option<&str> {
        self.header.registered.r#type.as_deref()
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/key_id.md"))]
    pub fn key_id(&self) -> Option<&str> {
        self.header.registered.key_id.as_deref()
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/certificate_url.md"))]
    pub fn certificate_url(&self) -> Option<&Url> {
        self.header.registered.certificate_url.as_ref()
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/certificate_chain.md"))]
    pub fn certificate_chain(&self) -> Option<&[Certificate]> {
        self.header.registered.certificate_chain.as_deref()
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/content_type.md"))]
    pub fn content_type(&self) -> Option<&str> {
        self.header.registered.content_type.as_deref()
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/critical.md"))]
    pub fn critical(&self) -> Option<&[String]> {
        self.header.registered.critical.as_deref()
    }
}

impl<'h, H> HeaderAccess<'h, H, UnsignedHeader> {
    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/json_web_key.md"))]
    pub fn key(&self) -> &KeyDerivation<JsonWebKey> {
        &self.header.state.key
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/thumbprint.md"))]
    pub fn thumbprint(&self) -> &KeyDerivation<Thumbprint<Sha1>> {
        &self.header.state.thumbprint
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/thumbprint_sha256.md"))]
    pub fn thumbprint_sha256(&self) -> &KeyDerivation<Thumbprint<Sha256>> {
        &self.header.state.thumbprint_sha256
    }
}

impl<'h, H, K> HeaderAccess<'h, H, SignedHeader<K>>
where
    K: SerializeJWK + Clone,
{
    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/algorithm.md"))]
    pub fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.header.state.algorithm
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/json_web_key.md"))]
    pub fn key(&self) -> Option<JsonWebKey> {
        self.header.state.key.value()
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/thumbprint.md"))]
    pub fn thumbprint(&self) -> Option<Thumbprint<Sha1>> {
        self.header.state.thumbprint.value()
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/thumbprint_sha256.md"))]
    pub fn thumbprint_sha256(&self) -> Option<Thumbprint<Sha256>> {
        self.header.state.thumbprint_sha256.value()
    }
}

impl<'h, H> HeaderAccess<'h, H, RenderedHeader> {
    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/algorithm.md"))]
    pub fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.header.state.algorithm
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/json_web_key.md"))]
    pub fn key(&self) -> Option<&JsonWebKey> {
        self.header.state.key.as_ref()
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/thumbprint.md"))]
    pub fn thumbprint(&self) -> Option<&Thumbprint<Sha1>> {
        self.header.state.thumbprint.as_ref()
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/thumbprint_sha256.md"))]
    pub fn thumbprint_sha256(&self) -> Option<&Thumbprint<Sha256>> {
        self.header.state.thumbprint_sha256.as_ref()
    }
}

#[cfg(feature = "fmt")]
impl<'h, H, State> fmt::JWTFormat for HeaderAccess<'h, H, State>
where
    H: Serialize,
    State: HeaderState,
{
    fn fmt<W: std::fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> std::fmt::Result {
        <Header<H, State> as fmt::JWTFormat>::fmt(self.header, f)
    }
}

/// Mutable access to header fields of a JOSE header.
pub struct HeaderAccessMut<'h, H, State> {
    header: &'h mut Header<H, State>,
}

impl<'h, H, State> HeaderAccessMut<'h, H, State> {
    pub(crate) fn new(header: &'h mut Header<H, State>) -> Self {
        Self { header }
    }

    pub fn custom(&mut self) -> &mut H {
        &mut self.header.custom
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/jwk_set_url.md"))]
    pub fn jwk_set_url(&mut self) -> &mut Option<Url> {
        &mut self.header.registered.jwk_set_url
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/type.md"))]
    pub fn r#type(&mut self) -> &mut Option<String> {
        &mut self.header.registered.r#type
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/key_id.md"))]
    pub fn key_id(&mut self) -> &mut Option<String> {
        &mut self.header.registered.key_id
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/certificate_url.md"))]
    pub fn certificate_url(&mut self) -> &mut Option<Url> {
        &mut self.header.registered.certificate_url
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/certificate_chain.md"))]
    pub fn certificate_chain(&mut self) -> &mut Option<Vec<Certificate>> {
        &mut self.header.registered.certificate_chain
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/content_type.md"))]
    pub fn content_type(&mut self) -> &mut Option<String> {
        &mut self.header.registered.content_type
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/critical.md"))]
    pub fn critical(&mut self) -> &mut Option<Vec<String>> {
        &mut self.header.registered.critical
    }
}

impl<'h, H> HeaderAccessMut<'h, H, UnsignedHeader> {
    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/json_web_key.md"))]
    pub fn key(&mut self) -> &mut KeyDerivation<JsonWebKey> {
        &mut self.header.state.key
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/thumbprint.md"))]
    pub fn thumbprint(&mut self) -> &mut KeyDerivation<Thumbprint<Sha1>> {
        &mut self.header.state.thumbprint
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/thumbprint_sha256.md"))]
    pub fn thumbprint_sha256(&mut self) -> &mut KeyDerivation<Thumbprint<Sha256>> {
        &mut self.header.state.thumbprint_sha256
    }
}

impl<'h, H, K> HeaderAccessMut<'h, H, SignedHeader<K>>
where
    K: SerializeJWK + Clone,
{
    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/algorithm.md"))]
    pub fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.header.state.algorithm
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/json_web_key.md"))]
    pub fn key(&self) -> Option<JsonWebKey> {
        self.header.state.key.value()
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/thumbprint.md"))]
    pub fn thumbprint(&self) -> Option<Thumbprint<Sha1>> {
        self.header.state.thumbprint.value()
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/thumbprint_sha256.md"))]
    pub fn thumbprint_sha256(&self) -> Option<Thumbprint<Sha256>> {
        self.header.state.thumbprint_sha256.value()
    }
}

impl<'h, H> HeaderAccessMut<'h, H, RenderedHeader> {
    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/algorithm.md"))]
    pub fn algorithm(&mut self) -> &mut AlgorithmIdentifier {
        &mut self.header.state.algorithm
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/json_web_key.md"))]
    pub fn key(&mut self) -> &mut Option<JsonWebKey> {
        &mut self.header.state.key
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/thumbprint.md"))]
    pub fn thumbprint(&mut self) -> &mut Option<Thumbprint<Sha1>> {
        &mut self.header.state.thumbprint
    }

    #[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/jose/thumbprint_sha256.md"))]
    pub fn thumbprint_sha256(&mut self) -> &mut Option<Thumbprint<Sha256>> {
        &mut self.header.state.thumbprint_sha256
    }
}

/// Errors returned when verifying a header.
#[derive(Debug, thiserror::Error)]
pub enum VerifyHeaderError {}
