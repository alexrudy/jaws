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

/// Serializer/deserializer for [jiff::Timestamp] values.
///
/// Use via `with = "jaws::claims::jiff_jwt_serde"` on an `Option<Timestamp>` field.
pub mod jiff_jwt_serde {
    use serde::{Deserialize, Serialize, de};

    /// Serializer for [jiff::Timestamp] values as `i64` seconds since the Unix epoch.
    ///
    /// This is the format used in JWT claims.
    pub fn serialize<S>(timestamp: &jiff::Timestamp, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        timestamp.as_second().serialize(serializer)
    }

    /// Deserializer for [jiff::Timestamp] values as `i64` seconds since the Unix epoch.
    ///
    /// This is the format used in JWT claims.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<jiff::Timestamp, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        i64::deserialize(deserializer)
            .and_then(|t| jiff::Timestamp::from_second(t).map_err(|err| de::Error::custom(err)))
    }

    /// Serializer/deserializer for [jiff::Timestamp] values.
    ///
    /// Use via `with = "jaws::claims::jiff_jwt_serde::opt"` on an `Option<Timestamp>` field.
    pub mod opt {
        use serde::{Deserialize, Serialize, de};

        /// Serializer for `Option<jiff::Timestamp>` values as `i64` seconds since the Unix epoch.
        ///
        /// This is the format used in JWT claims.
        pub fn serialize<S>(
            timestamp: &Option<jiff::Timestamp>,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            timestamp.map(|t| t.as_second()).serialize(serializer)
        }

        /// Deserializer for `Option<jiff::Timestamp>` values as `i64` seconds since the Unix epoch.
        ///
        /// This is the format used in JWT claims.
        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<jiff::Timestamp>, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            Option::deserialize(deserializer).and_then(|t: Option<i64>| {
                t.map(|s| jiff::Timestamp::from_second(s))
                    .transpose()
                    .map_err(|err| de::Error::custom(err))
            })
        }
    }
}
/// The signed header values for the JWS which are common to each
/// request.
///
/// Fields which are `None` are left out of the regsitered header.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegisteredClaims<ISS = String, SUB = String, AUD = String, JTI = String> {
    /// Claim issuer identifies the principal that issued the
    /// JWT.  The processing of this claim is generally application specific.
    /// The "iss" value is a case-sensitive string containing a StringOrURI
    /// value.  Use of this claim is OPTIONAL.
    #[serde(default, rename = "iss", skip_serializing_if = "Option::is_none")]
    pub issuer: Option<ISS>,

    /// Claim subject identifies the principal that is the
    /// subject of the JWT.  The claims in a JWT are normally statements
    /// about the subject.  The subject value MUST either be scoped to be
    /// locally unique in the context of the issuer or be globally unique.
    /// The processing of this claim is generally application specific.  The
    /// "sub" value is a case-sensitive string containing a StringOrURI
    /// value.  Use of this claim is OPTIONAL.
    #[serde(default, rename = "sub", skip_serializing_if = "Option::is_none")]
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
    #[serde(default, rename = "aud", skip_serializing_if = "Option::is_none")]
    pub audience: Option<AUD>,

    /// The "exp" (expiration time) claim identifies the expiration time on or
    /// after which the JWT MUST NOT be accepted for processing. The processing
    /// of the "exp" claim requires that the current date/time MUST be before
    /// the expiration date/time listed in the "exp" claim. Implementers MAY
    /// provide for some small leeway, usually no more than a few minutes, to
    /// account for clock skew. Its value MUST be a number containing a
    /// NumericDate value. Use of this claim is OPTIONAL.
    #[serde(
        default,
        rename = "exp",
        skip_serializing_if = "Option::is_none",
        with = "jiff_jwt_serde::opt"
    )]
    pub expiration: Option<jiff::Timestamp>,

    /// The "nbf" (not before) claim identifies the time before which the JWT
    /// MUST NOT be accepted for processing. The processing of the "nbf" claim
    /// requires that the current date/time MUST be after or equal to the
    /// not-before date/time listed in the "nbf" claim. Implementers MAY provide
    /// for some small leeway, usually no more than a few minutes, to account
    /// for clock skew. Its value MUST be a number containing a NumericDate value.
    /// Use of this claim is OPTIONAL.
    #[serde(
        default,
        rename = "nbf",
        skip_serializing_if = "Option::is_none",
        with = "jiff_jwt_serde::opt"
    )]
    pub not_before: Option<jiff::Timestamp>,

    /// The "iat" (issued at) claim identifies the time at which the JWT was
    /// issued.  This claim can be used to determine the age of the JWT.  Its
    /// value MUST be a number containing a NumericDate value.  Use of this
    /// claim is OPTIONAL.
    #[serde(
        default,
        rename = "iat",
        skip_serializing_if = "Option::is_none",
        with = "jiff_jwt_serde::opt"
    )]
    pub issued_at: Option<jiff::Timestamp>,

    /// The "jti" (JWT ID) claim provides a unique identifier for the JWT. The identifier value MUST be assigned in a manner that ensures that there is a negligible probability that the same value will be accidentally assigned to a different data object; if the application uses multiple issuers, collisions MUST be prevented among values produced by different issuers as well. The "jti" claim can be used to prevent the JWT from being replayed. The "jti" value is a case- sensitive string. Use of this claim is OPTIONAL.
    #[serde(default, rename = "jti", skip_serializing_if = "Option::is_none")]
    pub token_id: Option<JTI>,
}

/// Represents errors that can occur during claim validation.
#[derive(Debug, thiserror::Error)]
pub enum ClaimValidationError {
    /// The claims have expired.
    #[error("claims expired at {0}")]
    Expired(jiff::Timestamp),

    /// The claims are not yet valid.
    #[error("claims not yet valid until {0}")]
    NotYetValid(jiff::Timestamp),
}

impl<ISS, SUB, AUD, JTI> RegisteredClaims<ISS, SUB, AUD, JTI> {
    /// Validates the timestamps as of the given time.
    pub fn validate_timestamps_as_of(
        &self,
        now: jiff::Timestamp,
    ) -> Result<(), ClaimValidationError> {
        if let Some(expiration) = &self.expiration {
            if now >= *expiration {
                return Err(ClaimValidationError::Expired(*expiration));
            }
        }
        if let Some(not_before) = &self.not_before {
            if now <= *not_before {
                return Err(ClaimValidationError::NotYetValid(*not_before));
            }
        }
        Ok(())
    }
}

impl<ISS, SUB, AUD, JTI> Default for RegisteredClaims<ISS, SUB, AUD, JTI> {
    fn default() -> Self {
        Self {
            issuer: None,
            subject: None,
            audience: None,
            expiration: None,
            not_before: None,
            issued_at: None,
            token_id: None,
        }
    }
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct Claims<C, ISS = String, SUB = String, AUD = String, JTI = String> {
    /// Registered claims, which are enumerated specifically. See [RegisteredClaims].
    #[serde(default, flatten)]
    pub registered: RegisteredClaims<ISS, SUB, AUD, JTI>,

    /// Custom claims, which are any arbitrary JSON objects. Custom claims must implement
    /// `Serialize` to be used to create JWT tokens. `Deserialize` is required to read
    /// custom claims.
    #[serde(flatten)]
    pub claims: C,
}

impl<C, ISS, SUB, AUD, JTI> Default for Claims<C, ISS, SUB, AUD, JTI>
where
    C: Default,
{
    fn default() -> Self {
        Self {
            registered: Default::default(),
            claims: Default::default(),
        }
    }
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
    use serde_json::json;

    #[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
    struct CustomClaims {
        foo: String,
    }

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
        let claims = Claims::new(
            RegisteredClaims::<()> {
                not_before: "2023-04-18T21:54:39Z"
                    .parse::<jiff::Timestamp>()
                    .map(Into::into)
                    .ok(),
                ..Default::default()
            },
            CustomClaims {
                foo: "bar".to_string(),
            },
        );

        let json = serde_json::to_value(claims).unwrap();
        assert_eq!(json["nbf"].as_i64(), Some(1681854879), "{json:?}");
    }

    #[test]
    fn validate_claim_exp() {
        let claims = RegisteredClaims::<()> {
            expiration: "2023-04-18T21:54:39Z".parse::<jiff::Timestamp>().ok(),
            ..Default::default()
        };

        assert!(
            claims
                .validate_timestamps_as_of(
                    "2023-04-18T21:54:39Z".parse::<jiff::Timestamp>().unwrap()
                )
                .is_err(),
            "Claim expires at boundary"
        );

        assert!(
            claims
                .validate_timestamps_as_of(
                    "2023-04-18T20:54:39Z".parse::<jiff::Timestamp>().unwrap()
                )
                .is_ok(),
            "Claim not expired"
        );

        assert!(
            claims
                .validate_timestamps_as_of(
                    "2023-04-18T22:54:39Z".parse::<jiff::Timestamp>().unwrap()
                )
                .is_err(),
            "Claim expired"
        );
    }

    #[test]
    fn validate_claim_nbf() {
        let claims = RegisteredClaims::<()> {
            not_before: "2023-04-18T21:54:39Z".parse::<jiff::Timestamp>().ok(),
            ..Default::default()
        };

        assert!(
            claims
                .validate_timestamps_as_of(
                    "2023-04-18T20:54:39Z".parse::<jiff::Timestamp>().unwrap()
                )
                .is_err(),
            "Claim not before boundary"
        );

        assert!(
            claims
                .validate_timestamps_as_of(
                    "2023-04-18T21:54:39Z".parse::<jiff::Timestamp>().unwrap()
                )
                .is_err(),
            "Claim not valid on boundary"
        );

        assert!(
            claims
                .validate_timestamps_as_of(
                    "2023-04-18T22:54:39Z".parse::<jiff::Timestamp>().unwrap()
                )
                .is_ok(),
            "Claim not expired"
        );
    }
}
