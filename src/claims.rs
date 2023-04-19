//! Claims for a JWT.
//!
//! Claims are one kind of loosely specified payload for a JWT.
//! The set of registered claims is defined in [RFC 7519][], and can
//! be extended with both public and private claims.
//!
//! [RegisteredClaims] provides a data model for the set of known
//! registered claims, with optional fields. Since some claims can be any
//! JSON value type, the fields are generic over the type of the contents.
//!
//! [Claims] wraps [RegisteredClaims] with a set of custom claims, which
//! can be any struct which implements [serde::Serialize] and produces
//! valid JSON.
//!
//! [RFC 7519]: https://tools.ietf.org/html/rfc7519#section-4
use serde::{Deserialize, Serialize};

#[cfg(feature = "fmt")]
use crate::fmt;

/// The signed header values for the JWS which are common to each
/// request.
///
/// Fields which are `None` are left out of the regsitered header.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegisteredClaims<ISS = String, SUB = String, AUD = String, JTI = String> {
    /// Claim issuer identifies the principal that issued the
    /// JWT.  The processing of this claim is generally application specific.
    /// The "iss" value is a case-sensitive string containing a StringOrURI
    /// value.  Use of this claim is OPTIONAL.
    #[serde(rename = "iss", skip_serializing_if = "Option::is_none")]
    pub issuer: Option<ISS>,

    /// Claim subject identifies the principal that is the
    /// subject of the JWT.  The claims in a JWT are normally statements
    /// about the subject.  The subject value MUST either be scoped to be
    /// locally unique in the context of the issuer or be globally unique.
    /// The processing of this claim is generally application specific.  The
    /// "sub" value is a case-sensitive string containing a StringOrURI
    /// value.  Use of this claim is OPTIONAL.
    #[serde(rename = "sub", skip_serializing_if = "Option::is_none")]
    pub subject: Option<SUB>,

    /// The "aud" (audience) claim identifies the recipients that the JWT is
    /// intended for. Each principal intended to process the JWT MUST identify
    /// itself with a value in the audience claim. If the principal processing
    /// the claim does not identify itself with a value in the "aud" claim when
    /// this claim is present, then the JWT MUST be rejected. In the general
    /// case, the "aud" value is an array of case- sensitive strings, each
    /// containing a StringOrURI value. In the special case when the JWT has one
    /// audience, the "aud" value MAY be a single case-sensitive string containing
    /// a StringOrURI value. The interpretation of audience values is generally
    /// application specific. Use of this claim is OPTIONAL.
    #[serde(rename = "aud", skip_serializing_if = "Option::is_none")]
    pub audience: Option<AUD>,

    /// The "exp" (expiration time) claim identifies the expiration time on or
    /// after which the JWT MUST NOT be accepted for processing. The processing
    /// of the "exp" claim requires that the current date/time MUST be before
    /// the expiration date/time listed in the "exp" claim. Implementers MAY
    /// provide for some small leeway, usually no more than a few minutes, to
    /// account for clock skew. Its value MUST be a number containing a
    /// NumericDate value. Use of this claim is OPTIONAL.
    #[serde(
        rename = "exp",
        skip_serializing_if = "Option::is_none",
        with = "crate::numeric_date"
    )]
    pub expiration: Option<chrono::DateTime<chrono::Utc>>,

    /// The "nbf" (not before) claim identifies the time before which the JWT
    /// MUST NOT be accepted for processing. The processing of the "nbf" claim
    /// requires that the current date/time MUST be after or equal to the
    /// not-before date/time listed in the "nbf" claim. Implementers MAY provide
    /// for some small leeway, usually no more than a few minutes, to account
    /// for clock skew. Its value MUST be a number containing a NumericDate value.
    /// Use of this claim is OPTIONAL.
    #[serde(
        rename = "nbf",
        skip_serializing_if = "Option::is_none",
        with = "crate::numeric_date"
    )]
    pub not_before: Option<chrono::DateTime<chrono::Utc>>,

    /// The "iat" (issued at) claim identifies the time at which the JWT was
    /// issued.  This claim can be used to determine the age of the JWT.  Its
    /// value MUST be a number containing a NumericDate value.  Use of this
    /// claim is OPTIONAL.
    #[serde(
        rename = "iat",
        skip_serializing_if = "Option::is_none",
        with = "crate::numeric_date"
    )]
    pub issued_at: Option<chrono::DateTime<chrono::Utc>>,

    /// The "jti" (JWT ID) claim provides a unique identifier for the JWT. The identifier value MUST be assigned in a manner that ensures that there is a negligible probability that the same value will be accidentally assigned to a different data object; if the application uses multiple issuers, collisions MUST be prevented among values produced by different issuers as well. The "jti" claim can be used to prevent the JWT from being replayed. The "jti" value is a case- sensitive string. Use of this claim is OPTIONAL.
    #[serde(rename = "jti", skip_serializing_if = "Option::is_none")]
    pub token_id: Option<JTI>,
}

#[cfg(feature = "fmt")]
impl<ISS, SUB, AUD, JTI> fmt::JWTFormat for RegisteredClaims<ISS, SUB, AUD, JTI>
where
    ISS: Serialize,
    SUB: Serialize,
    AUD: Serialize,
    JTI: Serialize,
{
    fn fmt<W: fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> fmt::Result {
        f.write_json(&self)
    }
}

/// The claims for the JWS.
///
/// Claims are one kind of loosely specified payload for a JWT.
/// They consist of "registered" header values, specified in RFC 7519,
/// and a set of custom claims, which can be any arbitrary key-value
/// pairs seializable as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, Default)]
pub struct Claims<C, ISS = String, SUB = String, AUD = String, JTI = String> {
    /// Registered claims, which are enumerated specifically. See [RegisteredClaims].
    #[serde(flatten)]
    pub registered: RegisteredClaims<ISS, SUB, AUD, JTI>,

    /// Custom claims, which are any arbitrary JSON objects. Custom claims must implement
    /// `Serialize` to be used to create JWT tokens. `Deserialize` is required to read
    /// custom claims.
    #[serde(flatten)]
    pub claims: C,
}

impl<C, ISS, SUB, AUD, JTI> Claims<C, ISS, SUB, AUD, JTI> {
    /// Create a new set of claims. Claims can also be created by constructing the
    /// struct literal.
    pub fn new(registered: RegisteredClaims<ISS, SUB, AUD, JTI>, claims: C) -> Self {
        Self { registered, claims }
    }
}

impl<T> From<T> for Claims<T> {
    fn from(value: T) -> Self {
        Claims {
            registered: Default::default(),
            claims: value,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    #[test]
    fn claim_iss_integer() {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
        struct CustomClaims {
            foo: String,
        }

        let claims = Claims::new(
            RegisteredClaims::<i32> {
                issuer: Some(123),
                ..Default::default()
            },
            CustomClaims {
                foo: "bar".to_string(),
            },
        );

        let json = serde_json::to_value(claims).unwrap();
        assert_eq!(json, json!({"iss":123,"foo":"bar"}));
    }

    #[test]
    fn claim_nbf() {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
        struct CustomClaims {
            foo: String,
        }

        let claims = Claims::new(
            RegisteredClaims::<i32> {
                not_before: chrono::Utc
                    .with_ymd_and_hms(2023, 4, 18, 21, 54, 39)
                    .single(),
                ..Default::default()
            },
            CustomClaims {
                foo: "bar".to_string(),
            },
        );

        let json = serde_json::to_value(claims).unwrap();
        assert_eq!(json["nbf"].as_u64(), Some(1681854879));
    }
}
