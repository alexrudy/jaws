//! JOSE Header implementation ([RFC 7515][rfc7515])
//!
//! The header format for JOSE, a JSON object with both registered and custom fields.
//!
//! This implementation tries to ensure that your fields are consistent, so e.g. it does
//! not allow you to set the algorithm ("alg") header unless you are actually singing the
//! key.
//!
//! [rfc7515]: https://tools.ietf.org/html/rfc7515

use serde::{ser, Deserialize, Serialize};
use serde_json::{json, Value};
use sha1::Sha1;
use sha2::Sha256;
use url::Url;

use crate::base64data::Base64JSON;
use crate::{algorithms::AlgorithmIdentifier, key::SerializeJWK};

#[cfg(feature = "fmt")]
use crate::fmt;
use crate::key::{JsonWebKey, JsonWebKeyBuilder, KeyDerivedBuilder, Thumbprint, Thumbprinter};

/// Stub type to represent an X.509 certificate
///
/// This type should be replaced with a proper representation of an X.509
/// certificate, but that is not yet implemeted for this library.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Certificate;

/// A builder for the registered JOSE header fields for using JWTs,
/// when those fields are derived from the signing key.
#[derive(Debug, Clone, Default)]
pub enum KeyDerivation<Value> {
    /// Omit this value from the rendered JOSE header.
    #[default]
    Omit,

    /// Derive this value from the signing key used to sign the token.
    Derived,

    /// Provide an explicit value for this field.
    Explicit(Value),
}

impl<Value> KeyDerivation<Value> {
    /// Set this field to be omitteded from the rendered JOSE header.
    pub fn omit(&mut self) {
        *self = Self::Omit;
    }

    /// Set this field to be derived from the signing key.
    pub fn derived(&mut self) {
        *self = Self::Derived;
    }

    /// Set this field to be set explicitly, with a given JSON value.
    pub fn explicit(&mut self, value: Value) {
        *self = Self::Explicit(value);
    }
}

#[cfg(feature = "fmt")]
impl<Value> KeyDerivation<Value>
where
    Value: Serialize,
{
    fn parameter(&self, key: &str) -> Option<serde_json::Value> {
        match self {
            KeyDerivation::Omit => None,
            KeyDerivation::Derived => Some(json!(format!("<{key}>"))),
            KeyDerivation::Explicit(value) => serde_json::to_value(value).ok(),
        }
    }
}

/// A builder for the registered JOSE header fields for using JWTs.
///
/// Some fields are set indirectly by the builder, e.g. the `key` field is set
/// to `true` when you'd like to serialize the signing key in the JOSE header
/// as a JSON Web Key (JWK).
#[derive(Debug, Clone, Default)]
pub struct UnsignedHeader {
    /// Whether to include the signing key in the JOSE header as a JWK.
    ///
    /// See [RenderedHeader::key] for field details.
    pub key: KeyDerivation<JsonWebKey>,

    /// Whether to include the X.509 certificate thumbprint in the JOSE header with the SHA1 digest.
    ///
    /// See [RenderedHeader::thumbprint] for field details.
    pub thumbprint: KeyDerivation<Thumbprint<Sha1>>,

    /// Whether to include the X.509 certificate thumbprint in the JOSE header with the SHA256 digest.
    ///
    /// See [RenderedHeader::thumbprint_sha256] for field details.
    pub thumbprint_sha256: KeyDerivation<Thumbprint<Sha256>>,
}

#[cfg(feature = "fmt")]
impl UnsignedHeader {
    fn parameters(&self) -> serde_json::Value {
        let mut data = json!({});

        if let Some(value) = self.key.parameter("jwk") {
            data["jwk"] = value;
        }

        if let Some(value) = self.thumbprint.parameter("x5t") {
            data["x5t"] = value;
        }

        if let Some(value) = self.thumbprint_sha256.parameter("x5t#S256") {
            data["x5t#S256"] = value;
        }

        data
    }
}

#[cfg(feature = "fmt")]
impl fmt::JWTFormat for UnsignedHeader {
    fn fmt<W: std::fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> std::fmt::Result {
        Base64JSON(&self.parameters()).fmt(f)
    }
}

/// A builder for the registered JOSE header fields for using JWTs.
///
/// Some header values must be set explicitly, while others can
/// be derived from the signing key. This type helps to keep track
/// of that distinction, allowing a field to be marked as derived
/// from the signing key.
#[derive(Debug, Default)]
enum DerivedKeyValue<Builder, Key>
where
    Builder: KeyDerivedBuilder<Key>,
{
    #[default]
    Omit,
    Derived(Key),
    Explicit(Builder::Value),
}

impl<Builder, Key> Clone for DerivedKeyValue<Builder, Key>
where
    Builder: KeyDerivedBuilder<Key>,
    <Builder as KeyDerivedBuilder<Key>>::Value: Clone,
    Key: Clone,
{
    fn clone(&self) -> Self {
        match self {
            Self::Omit => Self::Omit,
            Self::Derived(key) => Self::Derived(key.clone()),
            Self::Explicit(value) => Self::Explicit(value.clone()),
        }
    }
}

impl<Builder, Key> DerivedKeyValue<Builder, Key>
where
    Builder: KeyDerivedBuilder<Key>,
{
    fn is_none(&self) -> bool {
        matches!(self, DerivedKeyValue::Omit)
    }

    fn build(self) -> Option<Builder::Value> {
        match self {
            DerivedKeyValue::Omit => None,
            DerivedKeyValue::Derived(key) => Some(Builder::from(key).build()),
            DerivedKeyValue::Explicit(value) => Some(value),
        }
    }

    fn derive(derivation: KeyDerivation<Builder::Value>, key: &Key) -> Self
    where
        Key: Clone,
    {
        match derivation {
            KeyDerivation::Omit => DerivedKeyValue::Omit,
            KeyDerivation::Derived => DerivedKeyValue::Derived(key.clone()),
            KeyDerivation::Explicit(value) => DerivedKeyValue::Explicit(value),
        }
    }
}

impl<Builder, Key> ser::Serialize for DerivedKeyValue<Builder, Key>
where
    Builder: KeyDerivedBuilder<Key>,
    <Builder as KeyDerivedBuilder<Key>>::Value: Serialize + Clone,
    Key: Clone,
{
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.clone().build().serialize(serializer)
    }
}

#[cfg(feature = "fmt")]
impl<Builder, Key> DerivedKeyValue<Builder, Key>
where
    Builder: KeyDerivedBuilder<Key>,
    <Builder as KeyDerivedBuilder<Key>>::Value: Serialize,
    Key: Clone,
{
    fn parameter(&self) -> Option<serde_json::Value> {
        match self {
            DerivedKeyValue::Omit => None,
            DerivedKeyValue::Derived(key) => Some(
                serde_json::to_value(Builder::from(key.clone()).build())
                    .expect("failed to serialize derived key"),
            ),
            DerivedKeyValue::Explicit(value) => serde_json::to_value(value).ok(),
        }
    }
}

impl<Builder, Key> DerivedKeyValue<Builder, Key>
where
    Builder: KeyDerivedBuilder<Key>,
    <Builder as KeyDerivedBuilder<Key>>::Value: Serialize + Clone,
    Key: Clone,
{
    fn value(&self) -> Option<Builder::Value> {
        match self {
            DerivedKeyValue::Omit => None,
            DerivedKeyValue::Derived(key) => Some(Builder::from(key.clone()).build()),
            DerivedKeyValue::Explicit(value) => Some(value.clone()),
        }
    }
}

/// The registered fields of a JOSE header, which are interdependent
/// with the signing key.
#[derive(Debug, Clone, Serialize)]
#[serde(bound(serialize = "Key: SerializeJWK + Clone"))]
pub struct SignedHeader<Key>
where
    Key: SerializeJWK,
{
    #[doc = include_str!("../docs/jose/algorithm.md")]
    #[serde(rename = "alg")]
    algorithm: AlgorithmIdentifier,

    #[doc = include_str!("../docs/jose/json_web_key.md")]
    #[serde(rename = "jwk", skip_serializing_if = "DerivedKeyValue::is_none")]
    key: DerivedKeyValue<JsonWebKeyBuilder<Key>, Key>,

    #[doc = include_str!("../docs/jose/thumbprint.md")]
    #[serde(rename = "x5t", skip_serializing_if = "DerivedKeyValue::is_none")]
    thumbprint: DerivedKeyValue<Thumbprinter<Sha1, Key>, Key>,

    #[doc = include_str!("../docs/jose/thumbprint_sha256.md")]
    #[serde(rename = "x5t#S256", skip_serializing_if = "DerivedKeyValue::is_none")]
    thumbprint_sha256: DerivedKeyValue<Thumbprinter<Sha256, Key>, Key>,
}

#[cfg(feature = "fmt")]
impl<Key> SignedHeader<Key>
where
    Key: SerializeJWK + Clone,
{
    fn parameters(&self) -> serde_json::Value {
        let mut data = json!({});

        data["alg"] = serde_json::to_value(self.algorithm).unwrap();

        if let Some(value) = self.key.parameter() {
            data["jwk"] = value;
        }

        if let Some(value) = self.thumbprint.parameter() {
            data["x5t"] = value;
        }

        if let Some(value) = self.thumbprint_sha256.parameter() {
            data["x5t#S256"] = value;
        }

        data
    }
}

#[cfg(feature = "fmt")]
impl<Key> fmt::JWTFormat for SignedHeader<Key>
where
    Key: SerializeJWK + Clone,
{
    fn fmt<W: std::fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> std::fmt::Result {
        Base64JSON(&self.parameters()).fmt(f)
    }
}

/// The registered fields of a JOSE header, which are interdependent
/// with the signing key, rendered into their typed form.
///
/// This is different from [SignedHeader] in that it contains the actual data,
/// and not thd derivation, so the fields may be in inconsistent states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedHeader {
    #[doc = include_str!("../docs/jose/algorithm.md")]
    #[serde(rename = "alg")]
    pub algorithm: AlgorithmIdentifier,

    #[doc = include_str!("../docs/jose/json_web_key.md")]
    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    pub key: Option<JsonWebKey>,

    #[doc = include_str!("../docs/jose/thumbprint.md")]
    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<Thumbprint<Sha1>>,

    #[doc = include_str!("../docs/jose/thumbprint_sha256.md")]
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub thumbprint_sha256: Option<Thumbprint<Sha256>>,
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
    #[doc = include_str!("../docs/jose/jwk_set_url.md")]
    #[serde(rename = "jku", skip_serializing_if = "Option::is_none")]
    jwk_set_url: Option<Url>,

    #[doc = include_str!("../docs/jose/type.md")]
    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    r#type: Option<String>,

    #[doc = include_str!("../docs/jose/key_id.md")]
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,

    #[doc = include_str!("../docs/jose/certificate_url.md")]
    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    pub certificate_url: Option<Url>,

    #[doc = include_str!("../docs/jose/certificate_chain.md")]
    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    certificate_chain: Option<Vec<Certificate>>,

    #[doc = include_str!("../docs/jose/content_type.md")]
    #[serde(rename = "cty", skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,

    #[doc = include_str!("../docs/jose/critical.md")]
    #[serde(rename = "crit", skip_serializing_if = "Option::is_none")]
    critical: Option<Vec<String>>,
}

/// The JOSE Header is a JSON object that represents the cryptographic operations
/// applied to the JWS Protected Header and the JWS Payload and optionally additional
/// properties of the JWS.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct Header<H, State> {
    #[serde(flatten)]
    state: State,

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
    pub fn render(self) -> Header<H, RenderedHeader> {
        let state = RenderedHeader {
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
    pub(crate) fn verify<A>(self, key: &A::Key) -> Result<Header<H, SignedHeader<A::Key>>, A::Error>
    where
        A: crate::algorithms::VerifyAlgorithm,
    {
        todo!("verify");
    }
}
#[cfg(feature = "fmt")]
impl<H> Header<H, UnsignedHeader>
where
    H: Serialize,
{
    pub(crate) fn value(&self) -> serde_json::Value {
        let value = self.state.parameters();
        let header = serde_json::to_value(&self.registered).unwrap();
        let custom = serde_json::to_value(&self.custom).unwrap();

        let mut map = serde_json::Map::new();

        match custom {
            Value::Object(custom) => map.extend(custom),
            Value::Null => {}
            _ => panic!("custom headers are objects"),
        };

        let Value::Object(header) = header else {
            panic!("expected header")
        };
        map.extend(header);
        let Value::Object(value) = value else {
            panic!("expected algorithm header")
        };
        map.extend(value);

        map.into()
    }
}

#[cfg(feature = "fmt")]
impl<H> fmt::JWTFormat for Header<H, UnsignedHeader>
where
    H: Serialize,
{
    fn fmt<W: std::fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> std::fmt::Result {
        let value = self.value();

        Base64JSON(value).fmt(f)
    }
}

#[cfg(feature = "fmt")]
impl<H, Key> Header<H, SignedHeader<Key>>
where
    H: Serialize,
    Key: SerializeJWK + Clone,
{
    pub(crate) fn value(&self) -> serde_json::Value {
        let parameters = self.state.parameters();
        let header = serde_json::to_value(&self.registered).unwrap();
        let mut custom = serde_json::to_value(&self.custom).unwrap();

        let map = custom.as_object_mut().unwrap();
        let Value::Object(header) = header else {
            panic!("expected header")
        };

        for (key, value) in header.into_iter() {
            if map.insert(key.clone(), value.clone()).is_some() {
                panic!("duplicate header key: {}", key);
            }
        }

        let Value::Object(parameters) = parameters else {
            panic!("expected algorithm header")
        };
        for (key, value) in parameters {
            if map.insert(key.clone(), value.clone()).is_some() {
                panic!("duplicate header key: {}", key);
            }
        }

        custom
    }
}

#[cfg(feature = "fmt")]
impl<H, Key> fmt::JWTFormat for Header<H, SignedHeader<Key>>
where
    H: Serialize,
    Key: SerializeJWK + Clone,
{
    fn fmt<W: std::fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> std::fmt::Result {
        let value = self.value();

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

    #[doc = include_str!("../docs/jose/jwk_set_url.md")]
    pub fn jwk_set_url(&self) -> Option<&Url> {
        self.header.registered.jwk_set_url.as_ref()
    }

    #[doc = include_str!("../docs/jose/type.md")]
    pub fn r#type(&self) -> Option<&str> {
        self.header.registered.r#type.as_deref()
    }

    #[doc = include_str!("../docs/jose/key_id.md")]
    pub fn key_id(&self) -> Option<&str> {
        self.header.registered.key_id.as_deref()
    }

    #[doc = include_str!("../docs/jose/certificate_url.md")]
    pub fn certificate_url(&self) -> Option<&Url> {
        self.header.registered.certificate_url.as_ref()
    }

    #[doc = include_str!("../docs/jose/certificate_chain.md")]
    pub fn certificate_chain(&self) -> Option<&[Certificate]> {
        self.header.registered.certificate_chain.as_deref()
    }

    #[doc = include_str!("../docs/jose/content_type.md")]
    pub fn content_type(&self) -> Option<&str> {
        self.header.registered.content_type.as_deref()
    }

    #[doc = include_str!("../docs/jose/critical.md")]
    pub fn critical(&self) -> Option<&[String]> {
        self.header.registered.critical.as_deref()
    }
}

impl<'h, H> HeaderAccess<'h, H, UnsignedHeader> {
    #[doc = include_str!("../docs/jose/json_web_key.md")]
    pub fn key(&self) -> &KeyDerivation<JsonWebKey> {
        &self.header.state.key
    }

    #[doc = include_str!("../docs/jose/thumbprint.md")]
    pub fn thumbprint(&self) -> &KeyDerivation<Thumbprint<Sha1>> {
        &self.header.state.thumbprint
    }

    #[doc = include_str!("../docs/jose/thumbprint_sha256.md")]
    pub fn thumbprint_sha256(&self) -> &KeyDerivation<Thumbprint<Sha256>> {
        &self.header.state.thumbprint_sha256
    }
}

impl<'h, H, K> HeaderAccess<'h, H, SignedHeader<K>>
where
    K: SerializeJWK + Clone,
{
    #[doc = include_str!("../docs/jose/algorithm.md")]
    pub fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.header.state.algorithm
    }

    #[doc = include_str!("../docs/jose/json_web_key.md")]
    pub fn key(&self) -> Option<JsonWebKey> {
        self.header.state.key.value()
    }

    #[doc = include_str!("../docs/jose/thumbprint.md")]
    pub fn thumbprint(&self) -> Option<Thumbprint<Sha1>> {
        self.header.state.thumbprint.value()
    }

    #[doc = include_str!("../docs/jose/thumbprint_sha256.md")]
    pub fn thumbprint_sha256(&self) -> Option<Thumbprint<Sha256>> {
        self.header.state.thumbprint_sha256.value()
    }
}

impl<'h, H> HeaderAccess<'h, H, RenderedHeader> {
    #[doc = include_str!("../docs/jose/algorithm.md")]
    pub fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.header.state.algorithm
    }

    #[doc = include_str!("../docs/jose/json_web_key.md")]
    pub fn key(&self) -> Option<&JsonWebKey> {
        self.header.state.key.as_ref()
    }

    #[doc = include_str!("../docs/jose/thumbprint.md")]
    pub fn thumbprint(&self) -> Option<&Thumbprint<Sha1>> {
        self.header.state.thumbprint.as_ref()
    }

    #[doc = include_str!("../docs/jose/thumbprint_sha256.md")]
    pub fn thumbprint_sha256(&self) -> Option<&Thumbprint<Sha256>> {
        self.header.state.thumbprint_sha256.as_ref()
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

    #[doc = include_str!("../docs/jose/jwk_set_url.md")]
    pub fn jwk_set_url(&mut self) -> &mut Option<Url> {
        &mut self.header.registered.jwk_set_url
    }

    #[doc = include_str!("../docs/jose/type.md")]
    pub fn r#type(&mut self) -> &mut Option<String> {
        &mut self.header.registered.r#type
    }

    #[doc = include_str!("../docs/jose/key_id.md")]
    pub fn key_id(&mut self) -> &mut Option<String> {
        &mut self.header.registered.key_id
    }

    #[doc = include_str!("../docs/jose/certificate_url.md")]
    pub fn certificate_url(&mut self) -> &mut Option<Url> {
        &mut self.header.registered.certificate_url
    }

    #[doc = include_str!("../docs/jose/certificate_chain.md")]
    pub fn certificate_chain(&mut self) -> &mut Option<Vec<Certificate>> {
        &mut self.header.registered.certificate_chain
    }

    #[doc = include_str!("../docs/jose/content_type.md")]
    pub fn content_type(&mut self) -> &mut Option<String> {
        &mut self.header.registered.content_type
    }

    #[doc = include_str!("../docs/jose/critical.md")]
    pub fn critical(&mut self) -> &mut Option<Vec<String>> {
        &mut self.header.registered.critical
    }
}

impl<'h, H> HeaderAccessMut<'h, H, UnsignedHeader> {
    #[doc = include_str!("../docs/jose/json_web_key.md")]
    pub fn key(&mut self) -> &mut KeyDerivation<JsonWebKey> {
        &mut self.header.state.key
    }

    #[doc = include_str!("../docs/jose/thumbprint.md")]
    pub fn thumbprint(&mut self) -> &mut KeyDerivation<Thumbprint<Sha1>> {
        &mut self.header.state.thumbprint
    }

    #[doc = include_str!("../docs/jose/thumbprint_sha256.md")]
    pub fn thumbprint_sha256(&mut self) -> &mut KeyDerivation<Thumbprint<Sha256>> {
        &mut self.header.state.thumbprint_sha256
    }
}

impl<'h, H, K> HeaderAccessMut<'h, H, SignedHeader<K>>
where
    K: SerializeJWK + Clone,
{
    #[doc = include_str!("../docs/jose/algorithm.md")]
    pub fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.header.state.algorithm
    }

    #[doc = include_str!("../docs/jose/json_web_key.md")]
    pub fn key(&self) -> Option<JsonWebKey> {
        self.header.state.key.value()
    }

    #[doc = include_str!("../docs/jose/thumbprint.md")]
    pub fn thumbprint(&self) -> Option<Thumbprint<Sha1>> {
        self.header.state.thumbprint.value()
    }

    #[doc = include_str!("../docs/jose/thumbprint_sha256.md")]
    pub fn thumbprint_sha256(&self) -> Option<Thumbprint<Sha256>> {
        self.header.state.thumbprint_sha256.value()
    }
}

impl<'h, H> HeaderAccessMut<'h, H, RenderedHeader> {
    #[doc = include_str!("../docs/jose/algorithm.md")]
    pub fn algorithm(&mut self) -> &mut AlgorithmIdentifier {
        &mut self.header.state.algorithm
    }

    #[doc = include_str!("../docs/jose/json_web_key.md")]
    pub fn key(&mut self) -> &mut Option<JsonWebKey> {
        &mut self.header.state.key
    }

    #[doc = include_str!("../docs/jose/thumbprint.md")]
    pub fn thumbprint(&mut self) -> &mut Option<Thumbprint<Sha1>> {
        &mut self.header.state.thumbprint
    }

    #[doc = include_str!("../docs/jose/thumbprint_sha256.md")]
    pub fn thumbprint_sha256(&mut self) -> &mut Option<Thumbprint<Sha256>> {
        &mut self.header.state.thumbprint_sha256
    }
}

/// Errors returned when verifying a header.
#[derive(Debug, thiserror::Error)]
pub enum VerifyHeaderError {}
