//! JOSE Header implementation (RFC 7515)
//!
//! The header format for JOSE, a JSON object with both registered and custom fields.
//!
//! This implementation tries to ensure that your fields are consistent, so e.g. it does
//! not allow you to set the algorithm ("alg") header unless you are actually singing the
//! key.

use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;
use url::Url;

use crate::algorithms::AlgorithmIdentifier;
use crate::b64data::Base64JSON;
use crate::fmt;
use crate::key::{JsonWebKey, Thumbprint, Thumbprinter, JWK};

/// Stub type to represent an X.509 certificate
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Certificate;

/// A builder for the registered JOSE header fields for using JWKs.
///
/// Some fields are set indirectly by the builder, e.g. the `key` field is set
/// to `true` when you'd like to serialize the signing key in the JOSE header
/// as a JSON Web Key (JWK).
#[derive(Debug, Clone, Default)]
pub struct JOSERegisteredHeaderBuilder {
    /// URL of the JWK Set containing the key used to sign the JWS.
    ///
    /// See [JOSERegisteredHeader::jwk_set_url].
    pub jwk_set_url: Option<Url>,

    /// Message type for this JWT
    ///
    /// See [JOSERegisteredHeader::type].
    pub r#type: Option<String>,

    /// Whether to include the signing key in the JOSE header as a JWK.
    ///
    /// See [JOSERegisteredHeader::key].
    pub key: bool,

    /// Key ID of the signing key.
    ///
    /// See [JOSERegisteredHeader::key_id].
    pub key_id: Option<String>,

    /// URI for the X.509 certificate or certificate chain corresponding to the key used to sign the JWS.
    ///
    /// See [JOSERegisteredHeader::certificate_url].
    pub certificate_url: Option<Url>,

    /// X.509 certificate or certificate chain corresponding to the key used to sign the JWS.
    ///
    /// See [JOSERegisteredHeader::certificate_chain].
    pub certificate_chain: Option<Vec<Certificate>>,

    /// Whether to include the X.509 certificate thumbprint in the JOSE header with the SHA1 digest.
    ///
    /// See [JOSERegisteredHeader::thumbprint].
    pub thumbprint: bool,

    /// Whether to include the X.509 certificate thumbprint in the JOSE header with the SHA256 digest.
    ///
    /// See [JOSERegisteredHeader::thumbprint_sha256].
    pub thumbprint_256: bool,

    /// Content MIME type of the JWT, using the "application/" prefix.
    ///
    /// See [JOSERegisteredHeader::content_type].
    pub content_type: Option<String>,

    /// List of header values which are considered critical to the cryptographic integrity of this
    /// message. By default, for the algorithms implemented in this crate, this is set to the
    /// empty vector. If you are using a custom algorithm, you should set this to the list of
    /// header fields which are critical to the cryptographic integrity of the message.
    ///
    /// See [JOSERegisteredHeader::critical].
    pub critical: Option<Vec<String>>,
}

/// Builder header for JOSE headers.
///
/// Some registered fields depend on the key used to sign the JWT, e.g. "thumbprint".
/// To ensure consistency between the signing key and the JOSE header, the builder
/// takes a key as a parameter to the `build` method, and fills in these fields if they
/// are requested, at that time.
#[derive(Debug, Clone, Default)]
pub struct JOSEHeaderBuilder<H> {
    pub registered: JOSERegisteredHeaderBuilder,
    pub custom: H,
}

impl JOSEHeaderBuilder<()> {
    /// Create a new JOSE header builder with no custom header.
    pub fn new_registered() -> JOSEHeaderBuilder<()> {
        JOSEHeaderBuilder {
            registered: Default::default(),
            custom: (),
        }
    }
}

impl<H> JOSEHeaderBuilder<H> {
    /// Create a new JOSE header builder with the given custom header.
    pub fn new(custom: H) -> Self {
        Self {
            registered: Default::default(),
            custom,
        }
    }

    /// Construct the JOSE header from the builder and signing key.
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
                Some(Thumbprinter::<Sha1, _>::new(key.clone()))
            } else {
                None
            },
            thumbprint_sha256: if self.registered.thumbprint_256 {
                Some(Thumbprinter::<Sha256, _>::new(key.clone()))
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

/// The registered fields of a JOSE header.
///
/// This struct represents the registered fields, filled in with a signing
/// key where that is reqiured. This type is used to ensure that fields
/// derived from cryptographic keys are consistent with the keys and algorithms
/// used to sign the entire token. To construct a JOSE header, use the
/// [JOSEHeaderBuilder] type, which accepts bool for the fields derived from
/// the signing key, and setting such fields to `true` will cause their values
/// to be included in this structure.
#[derive(Debug, Clone, Serialize, Default)]
#[serde(bound = "Key: crate::key::KeyInfo")]
pub struct JOSERegisteredHeader<Key = ()> {
    /// The "jku" (JWK Set URL) Header Parameter is a URI ([RFC3986][]) that refers to a
    /// resource for a set of JSON-encoded public keys, one of which corresponds to
    /// the key used to digitally sign the JWS. The keys MUST be encoded as a JWK
    /// Set ([JWK][]). The protocol used to acquire the resource MUST provide integrity
    /// protection; an HTTP GET request to retrieve the JWK Set MUST use Transport
    /// Layer Security (TLS) ([RFC2818][]) ([RFC5246][]); and the identity of the server
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
    /// Per [RFC2045][], all media type values, subtype values, and parameter names are
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

    /// The "jwk" (JSON Web Key) Header Parameter is the public key that
    /// corresponds to the key used to digitally sign the JWS.  This key is
    /// represented as a JSON Web Key [JWK][].  Use of this Header Parameter is
    /// OPTIONAL.
    ///
    /// [JWK]: https://tools.ietf.org/html/rfc7517
    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    pub key: Option<JWK<Key>>,

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

    /// The "x5u" (X.509 URL) Header Parameter is a URI ([RFC3986][]) that refers to a
    /// resource for the X.509 public key certificate or certificate chain
    /// ([RFC5280][]) corresponding to the key used to digitally sign the JWS.  The
    /// identified resource MUST provide a representation of the certificate or
    /// certificate chain that conforms to [RFC 5280][RFC5280] in PEM-encoded form,
    /// with each certificate delimited as specified in Section 6.1 of [RFC 4945][RFC4945].
    /// The certificate containing the public key corresponding to the
    /// key used to digitally sign the [JWS][] MUST be the first certificate.  This MAY
    /// be followed by additional certificates, with each subsequent certificate
    /// being the one used to certify the previous one.  The protocol used to
    /// acquire the resource MUST provide integrity protection; an HTTP GET request
    /// to retrieve the certificate MUST use TLS ([RFC2818][]) ([RFC5246][]); and the
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
    /// key certificate or certificate chain ([RFC5280][]) corresponding to the key used
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

    /// The "x5t" (X.509 certificate SHA-1 thumbprint) Header Parameter is a
    /// base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of the
    /// X.509 certificate ([RFC5280][]) corresponding to the key used to digitally sign
    /// the JWS. Note that certificate thumbprints are also sometimes known as
    /// certificate fingerprints. Use of this Header Parameter is OPTIONAL.
    ///
    /// [RFC5280]: https://tools.ietf.org/html/rfc5280
    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<Thumbprinter<Sha1, Key>>,

    /// The "x5t#S256" (X.509 certificate SHA-256 thumbprint) Header Parameter is a
    /// base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of the
    /// X.509 certificate ([RFC5280][]) corresponding to the key used to digitally sign
    /// the JWS. Note that certificate thumbprints are also sometimes known as
    /// certificate fingerprints. Use of this Header Parameter is OPTIONAL.
    ///
    /// [RFC5280]: https://tools.ietf.org/html/rfc5280
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub thumbprint_sha256: Option<Thumbprinter<Sha256, Key>>,

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

impl<Key> JOSERegisteredHeader<Key> {
    /// Create a new builder for a JWS Header.
    pub fn builder() -> JOSERegisteredHeaderBuilder {
        JOSERegisteredHeaderBuilder::default()
    }
}

/// The JOSE Header is a JSON object that represents the cryptographic operations
/// applied to the JWS Protected Header and the JWS Payload and optionally additional
/// properties of the JWS.
#[derive(Debug, Clone, Serialize)]
#[serde(bound = "Key: crate::key::KeyInfo, H: Serialize")]
pub struct JOSEHeader<H, Key = ()> {
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
    pub(crate) algorithm: AlgorithmIdentifier,

    /// The set of registered header parameters from [JWS][] and [JWA][].
    ///
    /// This does not include the `alg` parameter, which is handled separately.
    ///
    /// [JWA]: https://datatracker.ietf.org/doc/html/rfc7518
    /// [JWS]: https://datatracker.ietf.org/doc/html/rfc7515
    #[serde(flatten)]
    pub registered: JOSERegisteredHeader<Key>,

    /// The set of unregistered header parameters, which are custom provided
    /// by the type parameter H.
    #[serde(flatten)]
    pub header: H,
}

#[cfg(feature = "fmt")]
impl<H, Key> fmt::JWTFormat for JOSEHeader<H, Key>
where
    H: Serialize,
    Key: crate::key::KeyInfo,
{
    fn fmt<W: std::fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> std::fmt::Result {
        Base64JSON(self).fmt(f)
    }
}

impl<H, Key> JOSEHeader<H, Key> {
    /// Create a new JOSE header with default field values
    /// for registered fields, and a custom header object.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(custom: H) -> JOSEHeaderBuilder<H> {
        JOSEHeaderBuilder::new(custom)
    }
}

impl<H, Key> JOSEHeader<H, Key>
where
    H: Default,
{
    /// Create a new JOSE header with default field values.
    pub fn builder() -> JOSEHeaderBuilder<H> {
        JOSEHeaderBuilder::default()
    }
}

/// The registered fields of a JOSE header, independent of the signing key.
///
/// This struct represents the registered fields, filled in with a signing
/// key where that is reqiured. This type is used to ensure that fields
/// derived from cryptographic keys are consistent with the keys and algorithms
/// used to sign the entire token. To construct a JOSE header, use the
/// [JOSEHeaderBuilder] type, which accepts bool for the fields derived from
/// the signing key, and setting such fields to `true` will cause their values
/// to be included in this structure.
#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq, Deserialize)]
pub struct RegisteredHeader {
    /// The "jku" (JWK Set URL) Header Parameter is a URI ([RFC3986][]) that refers to a
    /// resource for a set of JSON-encoded public keys, one of which corresponds to
    /// the key used to digitally sign the JWS. The keys MUST be encoded as a JWK
    /// Set ([JWK][]). The protocol used to acquire the resource MUST provide integrity
    /// protection; an HTTP GET request to retrieve the JWK Set MUST use Transport
    /// Layer Security (TLS) ([RFC2818][]) ([RFC5246][]); and the identity of the server
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
    /// Per [RFC2045][], all media type values, subtype values, and parameter names are
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

    /// The "jwk" (JSON Web Key) Header Parameter is the public key that
    /// corresponds to the key used to digitally sign the JWS.  This key is
    /// represented as a JSON Web Key [JWK][].  Use of this Header Parameter is
    /// OPTIONAL.
    ///
    /// [JWK]: https://tools.ietf.org/html/rfc7517
    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    pub key: Option<JsonWebKey>,

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

    /// The "x5u" (X.509 URL) Header Parameter is a URI ([RFC3986][]) that refers to a
    /// resource for the X.509 public key certificate or certificate chain
    /// ([RFC5280][]) corresponding to the key used to digitally sign the JWS.  The
    /// identified resource MUST provide a representation of the certificate or
    /// certificate chain that conforms to [RFC 5280][RFC5280] in PEM-encoded form,
    /// with each certificate delimited as specified in Section 6.1 of [RFC 4945][RFC4945].
    /// The certificate containing the public key corresponding to the
    /// key used to digitally sign the [JWS][] MUST be the first certificate.  This MAY
    /// be followed by additional certificates, with each subsequent certificate
    /// being the one used to certify the previous one.  The protocol used to
    /// acquire the resource MUST provide integrity protection; an HTTP GET request
    /// to retrieve the certificate MUST use TLS ([RFC2818][]) ([RFC5246][]); and the
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
    /// key certificate or certificate chain ([RFC5280][]) corresponding to the key used
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

    /// The "x5t" (X.509 certificate SHA-1 thumbprint) Header Parameter is a
    /// base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of the
    /// X.509 certificate ([RFC5280][]) corresponding to the key used to digitally sign
    /// the JWS. Note that certificate thumbprints are also sometimes known as
    /// certificate fingerprints. Use of this Header Parameter is OPTIONAL.
    ///
    /// [RFC5280]: https://tools.ietf.org/html/rfc5280
    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<Thumbprint>,

    /// The "x5t#S256" (X.509 certificate SHA-256 thumbprint) Header Parameter is a
    /// base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of the
    /// X.509 certificate ([RFC5280][]) corresponding to the key used to digitally sign
    /// the JWS. Note that certificate thumbprints are also sometimes known as
    /// certificate fingerprints. Use of this Header Parameter is OPTIONAL.
    ///
    /// [RFC5280]: https://tools.ietf.org/html/rfc5280
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub thumbprint_sha256: Option<Thumbprint>,

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
pub struct Header<H> {
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
    pub(crate) algorithm: AlgorithmIdentifier,

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
    pub header: H,
}
