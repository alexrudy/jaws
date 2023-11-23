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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Certificate;

/// A builder for the registered JOSE header fields for using JWTs,
/// when those fields are derived from the signing key.
#[derive(Debug, Clone, Default)]
pub enum KeyDerivation<Value> {
    #[default]
    Omit,
    Derived,
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
pub struct Unsigned {
    /// Whether to include the signing key in the JOSE header as a JWK.
    ///
    /// See [Rendered::key] for field details.
    pub key: KeyDerivation<JsonWebKey>,

    /// Whether to include the X.509 certificate thumbprint in the JOSE header with the SHA1 digest.
    ///
    /// See [Rendered::thumbprint] for field details.
    pub thumbprint: KeyDerivation<Thumbprint<Sha1>>,

    /// Whether to include the X.509 certificate thumbprint in the JOSE header with the SHA256 digest.
    ///
    /// See [Rendered::thumbprint_sha256] for field details.
    pub thumbprint_sha256: KeyDerivation<Thumbprint<Sha256>>,
}

#[cfg(feature = "fmt")]
impl Unsigned {
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
impl fmt::JWTFormat for Unsigned {
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
pub enum DerivedKey<Builder, Key>
where
    Builder: KeyDerivedBuilder<Key>,
{
    #[default]
    Omit,
    Derived(Key),
    Explicit(Builder::Value),
}

impl<Builder, Key> Clone for DerivedKey<Builder, Key>
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

impl<Builder, Key> DerivedKey<Builder, Key>
where
    Builder: KeyDerivedBuilder<Key>,
{
    fn is_none(&self) -> bool {
        matches!(self, DerivedKey::Omit)
    }

    fn build(self) -> Option<Builder::Value> {
        match self {
            DerivedKey::Omit => None,
            DerivedKey::Derived(key) => Some(Builder::from(key).build()),
            DerivedKey::Explicit(value) => Some(value),
        }
    }

    fn derive(derivation: KeyDerivation<Builder::Value>, key: &Key) -> Self
    where
        Key: Clone,
    {
        match derivation {
            KeyDerivation::Omit => DerivedKey::Omit,
            KeyDerivation::Derived => DerivedKey::Derived(key.clone()),
            KeyDerivation::Explicit(value) => DerivedKey::Explicit(value),
        }
    }
}

impl<Builder, Key> ser::Serialize for DerivedKey<Builder, Key>
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
impl<Builder, Key> DerivedKey<Builder, Key>
where
    Builder: KeyDerivedBuilder<Key>,
    <Builder as KeyDerivedBuilder<Key>>::Value: Serialize,
    Key: Clone,
{
    fn parameter(&self) -> Option<serde_json::Value> {
        match self {
            DerivedKey::Omit => None,
            DerivedKey::Derived(key) => Some(
                serde_json::to_value(Builder::from(key.clone()).build())
                    .expect("failed to serialize derived key"),
            ),
            DerivedKey::Explicit(value) => serde_json::to_value(value).ok(),
        }
    }
}

/// The registered fields of a JOSE header, which are interdependent
/// with the signing key.
#[derive(Debug, Clone, Serialize)]
#[serde(bound(serialize = "Key: SerializeJWK + Clone"))]
pub struct Signed<Key>
where
    Key: SerializeJWK,
{
    /// The "alg" (algorithm) Header Parameter identifies the cryptographic
    /// algorithm used to secure the JWS.  The JWS Signature value is not
    /// valid if the "alg" value does not represent a supported algorithm or
    /// if there is not a key for use with that algorithm associated with the
    /// party that digitally signed or MACed the content.  "alg" values
    /// should either be registered in the IANA "JSON Web Signature and
    /// Encryption Algorithms" registry established by [JWA][] or be a value
    /// that contains a Collision-Resistant Name.  The "alg" value is a case-
    /// sensitive ASCII string containing a StringOrURI value.  This Header
    /// Parameter MUST be present and MUST be understood and processed by
    /// implementations.
    ///
    /// A list of defined "alg" values for this use can be found in the IANA
    /// "JSON Web Signature and Encryption Algorithms" registry established
    /// by [JWA][]; the initial contents of this registry are the values
    /// defined in Section 3.1 of [JWA][].
    ///
    /// [JWA]: https://tools.ietf.org/html/rfc7518
    #[serde(rename = "alg")]
    pub algorithm: AlgorithmIdentifier,

    /// The "jwk" (JSON Web Key) Header Parameter is the public key that
    /// corresponds to the key used to digitally sign the JWS.  This key is
    /// represented as a JSON Web Key [JWK][].  Use of this Header Parameter is
    /// OPTIONAL.
    ///
    /// [JWK]: https://tools.ietf.org/html/rfc7517
    #[serde(rename = "jwk", skip_serializing_if = "DerivedKey::is_none")]
    pub key: DerivedKey<JsonWebKeyBuilder<Key>, Key>,

    /// The "x5t" (X.509 certificate SHA-1 thumbprint) Header Parameter is a
    /// base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of the
    /// X.509 certificate ([RFC 5280][RFC5280]) corresponding to the key used to digitally sign
    /// the JWS. Note that certificate thumbprints are also sometimes known as
    /// certificate fingerprints. Use of this Header Parameter is OPTIONAL.
    ///
    /// [RFC5280]: https://tools.ietf.org/html/rfc5280
    #[serde(rename = "x5t", skip_serializing_if = "DerivedKey::is_none")]
    pub thumbprint: DerivedKey<Thumbprinter<Sha1, Key>, Key>,

    /// The "x5t#S256" (X.509 certificate SHA-256 thumbprint) Header Parameter is a
    /// base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of the
    /// X.509 certificate ([RFC 5280][RFC5280]) corresponding to the key used to digitally sign
    /// the JWS. Note that certificate thumbprints are also sometimes known as
    /// certificate fingerprints. Use of this Header Parameter is OPTIONAL.
    ///
    /// [RFC5280]: https://tools.ietf.org/html/rfc5280
    #[serde(rename = "x5t#S256", skip_serializing_if = "DerivedKey::is_none")]
    pub thumbprint_sha256: DerivedKey<Thumbprinter<Sha256, Key>, Key>,
}

#[cfg(feature = "fmt")]
impl<Key> Signed<Key>
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
impl<Key> fmt::JWTFormat for Signed<Key>
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
/// This is different from [Signed] in that it contains the actual data,
/// and not thd derivation, so the fields may be in inconsistent states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rendered {
    /// The "alg" (algorithm) Header Parameter identifies the cryptographic
    /// algorithm used to secure the JWS.  The JWS Signature value is not
    /// valid if the "alg" value does not represent a supported algorithm or
    /// if there is not a key for use with that algorithm associated with the
    /// party that digitally signed or MACed the content.  "alg" values
    /// should either be registered in the IANA "JSON Web Signature and
    /// Encryption Algorithms" registry established by [JWA][] or be a value
    /// that contains a Collision-Resistant Name.  The "alg" value is a case-
    /// sensitive ASCII string containing a StringOrURI value.  This Header
    /// Parameter MUST be present and MUST be understood and processed by
    /// implementations.
    ///
    /// A list of defined "alg" values for this use can be found in the IANA
    /// "JSON Web Signature and Encryption Algorithms" registry established
    /// by [JWA][]; the initial contents of this registry are the values
    /// defined in Section 3.1 of [JWA][].
    ///
    /// [JWA]: https://tools.ietf.org/html/rfc7518
    #[serde(rename = "alg")]
    pub algorithm: AlgorithmIdentifier,

    /// The "jwk" (JSON Web Key) Header Parameter is the public key that
    /// corresponds to the key used to digitally sign the JWS.  This key is
    /// represented as a JSON Web Key [JWK][].  Use of this Header Parameter is
    /// OPTIONAL.
    ///
    /// [JWK]: https://tools.ietf.org/html/rfc7517
    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    pub key: Option<JsonWebKey>,

    /// The "x5t" (X.509 certificate SHA-1 thumbprint) Header Parameter is a
    /// base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of the
    /// X.509 certificate ([RFC 5280][RFC5280]) corresponding to the key used to digitally sign
    /// the JWS. Note that certificate thumbprints are also sometimes known as
    /// certificate fingerprints. Use of this Header Parameter is OPTIONAL.
    ///
    /// [RFC5280]: https://tools.ietf.org/html/rfc5280
    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<Thumbprint<Sha1>>,

    /// The "x5t#S256" (X.509 certificate SHA-256 thumbprint) Header Parameter is a
    /// base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of the
    /// X.509 certificate ([RFC 5280][RFC5280]) corresponding to the key used to digitally sign
    /// the JWS. Note that certificate thumbprints are also sometimes known as
    /// certificate fingerprints. Use of this Header Parameter is OPTIONAL.
    ///
    /// [RFC5280]: https://tools.ietf.org/html/rfc5280
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
pub struct RegisteredHeader {
    /// The "jku" (JWK Set URL) Header Parameter is a URI ([RFC 3986][RFC3986]) that refers to a
    /// resource for a set of JSON-encoded public keys, one of which corresponds to
    /// the key used to digitally sign the JWS. The keys MUST be encoded as a JWK
    /// Set ([JWK][]). The protocol used to acquire the resource MUST provide integrity
    /// protection; an HTTP GET request to retrieve the JWK Set MUST use Transport
    /// Layer Security (TLS) ([RFC 2818][RFC2818]) ([RFC 5246][RFC5246]); and the identity of the server
    /// MUST be validated, as per Section 6 of [RFC 6125][RFC6125]. Also, see Section
    /// 8 on TLS requirements. Use of this Header Parameter is OPTIONAL.
    ///
    /// [JWK]: https://tools.ietf.org/html/rfc7517
    /// [RFC2818]: https://tools.ietf.org/html/rfc2818
    /// [RFC3986]: https://tools.ietf.org/html/rfc3986
    /// [RFC5246]: https://tools.ietf.org/html/rfc5246
    /// [RFC6125]: https://tools.ietf.org/html/rfc6125
    #[serde(rename = "jku", skip_serializing_if = "Option::is_none")]
    pub jwk_set_url: Option<Url>,

    /// The "typ" (type) Header Parameter is used by JWS applications to declare the
    /// media type ([IANA.MediaTypes][]) of this complete JWS. This is intended for use
    /// by the application when more than one kind of object could be present in an
    /// application data structure that can contain a JWS; the application can use this
    /// value to disambiguate among the different kinds of objects that might be
    /// present. It will typically not be used by applications when the kind of object
    /// is already known. This parameter is ignored by JWS implementations; any
    /// processing of this parameter is performed by the JWS application. Use of this
    /// Header Parameter is OPTIONAL.
    ///
    /// Per [RFC 2045][RFC2045], all media type values, subtype values, and parameter names are
    /// case insensitive. However, parameter values are case sensitive unless otherwise
    /// specified for the specific parameter.
    ///
    /// To keep messages compact in common situations, it is RECOMMENDED that producers
    /// omit an "application/" prefix of a media type value in a "typ" Header Parameter
    /// when no other '/' appears in the media type value. A recipient using the media
    /// type value MUST treat it as if "application/" were prepended to any "typ" value
    /// not containing a '/'. For instance, a "typ" value of "example" SHOULD be used
    /// to represent the "application/example" media type, whereas the media type
    /// "application/example;part="1/2"" cannot be shortened to "example;part="1/2"".
    ///
    /// The "typ" value "JOSE" can be used by applications to indicate that this object
    /// is a JWS or JWE using the JWS Compact Serialization or the JWE Compact
    /// Serialization. The "typ" value "JOSE+JSON" can be used by applications to
    /// indicate that this object is a JWS or JWE using the JWS JSON Serialization or
    /// the JWE JSON Serialization. Other type values can also be used by applications.
    ///
    /// [IANA.MediaTypes]: https://www.iana.org/assignments/media-types/media-types.xhtml
    /// [RFC2045]: https://tools.ietf.org/html/rfc2045
    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,

    /// The "kid" (key ID) Header Parameter is a hint indicating which key was used
    /// to secure the [JWS][].  This parameter allows originators to explicitly signal a
    /// change of key to recipients.  The structure of the "kid" value is
    /// unspecified.  Its value MUST be a case-sensitive string.  Use of this Header
    /// Parameter is OPTIONAL.
    ///
    /// When used with a [JWK][], the "kid" value is used to match a [JWK][] "kid" parameter
    /// value.
    ///
    /// [JWK]: https://tools.ietf.org/html/rfc7517
    /// [JWS]: https://datatracker.ietf.org/doc/html/rfc7515

    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    /// The "x5u" (X.509 URL) Header Parameter is a URI ([RFC 3986][RFC3986]) that refers to a
    /// resource for the X.509 public key certificate or certificate chain
    /// ([RFC 5280][RFC5280]) corresponding to the key used to digitally sign the JWS.  The
    /// identified resource MUST provide a representation of the certificate or
    /// certificate chain that conforms to [RFC 5280][RFC5280] in PEM-encoded form,
    /// with each certificate delimited as specified in Section 6.1 of [RFC 4945][RFC4945].
    /// The certificate containing the public key corresponding to the
    /// key used to digitally sign the [JWS][] MUST be the first certificate.  This MAY
    /// be followed by additional certificates, with each subsequent certificate
    /// being the one used to certify the previous one.  The protocol used to
    /// acquire the resource MUST provide integrity protection; an HTTP GET request
    /// to retrieve the certificate MUST use TLS ([RFC 2818][RFC2818]) ([RFC 5246][RFC5246]); and the
    /// identity of the server MUST be validated, as per Section 6 of [RFC 6125][RFC6125].
    /// Also, see Section 8 on TLS requirements.  Use of this Header Parameter is OPTIONAL.
    ///
    /// [JWS]: https://datatracker.ietf.org/doc/html/rfc7515
    /// [RFC2818]: https://tools.ietf.org/html/rfc2818
    /// [RFC3986]: https://tools.ietf.org/html/rfc3986
    /// [RFC4945]: https://tools.ietf.org/html/rfc4945
    /// [RFC5246]: https://tools.ietf.org/html/rfc5246
    /// [RFC5280]: https://tools.ietf.org/html/rfc5280
    /// [RFC6125]: https://tools.ietf.org/html/rfc6125
    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    pub certificate_url: Option<Url>,

    /// The "x5c" (X.509 certificate chain) Header Parameter contains the X.509 public
    /// key certificate or certificate chain ([RFC 5280][RFC5280]) corresponding to the key used
    /// to digitally sign the JWS. The certificate or certificate chain is represented
    /// as a JSON array of certificate value strings. Each string in the array is a
    /// base64-encoded (Section 4 of [RFC 4648][RFC4648] -- not base64url-encoded) DER
    /// ([ITU.X690.2008][]) PKIX certificate value. The certificate containing the public
    /// key corresponding to the key used to digitally sign the JWS MUST be the first
    /// certificate. This MAY be followed by additional certificates, with each
    /// subsequent certificate being the one used to certify the previous one. The
    /// recipient MUST validate the certificate chain according to [RFC 5280][RFC5280]
    /// and consider the certificate or certificate chain to be invalid if any
    /// validation failure occurs. Use of this Header Parameter is OPTIONAL.
    ///
    /// [RFC4648]: https://tools.ietf.org/html/rfc4648
    /// [RFC5280]: https://tools.ietf.org/html/rfc5280
    /// [ITU.X690.2008]: hhttps://www.itu.int/rec/T-REC-X.680-X.693-200811-S/en
    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    pub certificate_chain: Option<Vec<Certificate>>,

    /// The "cty" (content type) Header Parameter is used by JWS applications to
    /// declare the media type ([IANA.MediaTypes][]) of the secured content (the
    /// payload). This is intended for use by the application when more than one kind
    /// of object could be present in the JWS Payload; the application can use this
    /// value to disambiguate among the different kinds of objects that might be
    /// present. It will typically not be used by applications when the kind of object
    /// is already known. This parameter is ignored by JWS implementations; any
    /// processing of this parameter is performed by the JWS application. Use of this
    /// Header Parameter is OPTIONAL.
    ///
    /// Per [RFC 2045][], all media type values, subtype values, and parameter names
    /// are case insensitive. However, parameter values are case sensitive unless
    /// otherwise specified for the specific parameter.
    ///
    /// To keep messages compact in common situations, it is RECOMMENDED that producers
    /// omit an "application/" prefix of a media type value in a "cty" Header Parameter
    /// when no other '/' appears in the media type value. A recipient using the media
    /// type value MUST treat it as if "application/" were prepended to any "cty" value
    /// not containing a '/'. For instance, a "cty" value of "example" SHOULD be used
    /// to represent the "application/example" media type, whereas the media type
    /// "application/example;part="1/2"" cannot be shortened to "example;part="1/2"".
    ///
    /// [IANA.MediaTypes]: https://www.iana.org/assignments/media-types/media-types.xhtml
    /// [RFC2045]: https://tools.ietf.org/html/rfc2045
    #[serde(rename = "cty", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    /// The "crit" (critical) Header Parameter indicates that extensions to this
    /// specification and/or [JWA][] are being used that MUST be understood and
    /// processed. Its value is an array listing the Header Parameter names present in
    /// the JOSE Header that use those extensions. If any of the listed extension
    /// Header Parameters are not understood and supported by the recipient, then the
    /// JWS is invalid. Producers MUST NOT include Header Parameter names defined by
    /// this specification or [JWA][] for use with JWS, duplicate names, or names that
    /// do not occur as Header Parameter names within the JOSE Header in the "crit"
    /// list. Producers MUST NOT use the empty list "[]" as the "crit" value.
    /// Recipients MAY consider the JWS to be invalid if the critical list contains any
    /// Header Parameter names defined by this specification or [JWA][] for use with
    /// JWS or if any other constraints on its use are violated. When used, this Header
    /// Parameter MUST be integrity protected; therefore, it MUST occur only within the
    /// JWS Protected Header. Use of this Header Parameter is OPTIONAL. This Header
    /// Parameter MUST be understood and processed by implementations.
    ///
    /// [JWA]: https://datatracker.ietf.org/doc/html/rfc7518
    #[serde(rename = "crit", skip_serializing_if = "Option::is_none")]
    pub critical: Option<Vec<String>>,
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
    pub registered: RegisteredHeader,

    /// The set of unregistered header parameters, which are custom provided
    /// by the type parameter H.
    #[serde(flatten)]
    pub custom: H,
}

impl<H> Default for Header<H, Unsigned>
where
    H: Default,
{
    fn default() -> Self {
        Self {
            state: Unsigned::default(),
            registered: Default::default(),
            custom: Default::default(),
        }
    }
}

impl<H> Header<H, Unsigned> {
    /// Create a new JOSE header builder with the given custom header.
    pub fn new(custom: H) -> Self {
        Self {
            state: Unsigned::default(),
            registered: Default::default(),
            custom,
        }
    }

    /// Construct the JOSE header from the builder and signing key.
    pub(crate) fn sign<A>(self, key: &A::Key) -> Header<H, Signed<A::Key>>
    where
        A: crate::algorithms::SigningAlgorithm,
        A::Key: Clone,
    {
        let state = Signed {
            algorithm: A::IDENTIFIER,
            key: DerivedKey::derive(self.state.key, key),
            thumbprint: DerivedKey::derive(self.state.thumbprint, key),
            thumbprint_sha256: DerivedKey::derive(self.state.thumbprint_sha256, key),
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

impl<H, Key> Header<H, Signed<Key>>
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
    pub fn render(self) -> Header<H, Rendered> {
        let state = Rendered {
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

impl<H> Header<H, Rendered> {
    pub fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.state.algorithm
    }

    #[allow(unused_variables)]
    pub(crate) fn verify<A>(self, key: &A::Key) -> Result<Header<H, Signed<A::Key>>, A::Error>
    where
        A: crate::algorithms::VerifyAlgorithm,
    {
        todo!("verify");
    }
}
#[cfg(feature = "fmt")]
impl<H> Header<H, Unsigned>
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
impl<H> fmt::JWTFormat for Header<H, Unsigned>
where
    H: Serialize,
{
    fn fmt<W: std::fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> std::fmt::Result {
        let value = self.value();

        Base64JSON(value).fmt(f)
    }
}

#[cfg(feature = "fmt")]
impl<H, Key> Header<H, Signed<Key>>
where
    H: Serialize,
    Key: SerializeJWK + Clone,
{
    pub(crate) fn value(&self) -> serde_json::Value {
        let value = self.state.parameters();
        let header = serde_json::to_value(&self.registered).unwrap();
        let mut custom = serde_json::to_value(&self.custom).unwrap();

        let map = custom.as_object_mut().unwrap();
        let Value::Object(header) = header else {
            panic!("expected header")
        };
        map.extend(header);
        let Value::Object(value) = value else {
            panic!("expected algorithm header")
        };
        map.extend(value);

        custom
    }
}

#[cfg(feature = "fmt")]
impl<H, Key> fmt::JWTFormat for Header<H, Signed<Key>>
where
    H: Serialize,
    Key: SerializeJWK + Clone,
{
    fn fmt<W: std::fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> std::fmt::Result {
        let value = self.value();

        Base64JSON(value).fmt(f)
    }
}

/// Errors returned when verifying a header.
#[derive(Debug, thiserror::Error)]
pub enum VerifyHeaderError {}
