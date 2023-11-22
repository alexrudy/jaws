//! JSON Web Tokens ([RFC 7519][RFC7519])
//!
//! This module implements the JWS and JWE formats for representing JSON Web Tokens.
//! It is designed to both accept registered headers and claims (see [crate::claims]) as
//! well as custom payloads and entirely custom headers. All registered fields are optional
//! except for the "alg" field in the JOSE header which is required to identify the signing
//! algorithm in use.
//!
//! [RFC7519]: https://tools.ietf.org/html/rfc7519

#[cfg(feature = "fmt")]
use std::fmt::Write;
use std::marker::PhantomData;

use base64ct::Encoding;
use serde::{de, ser, Deserialize, Serialize};

#[cfg(feature = "fmt")]
use crate::fmt;
use crate::{
    algorithms::{AlgorithmIdentifier, SigningAlgorithm},
    base64data::{Base64Data, Base64JSON},
    Header,
};

mod formats;
mod state;

pub use self::formats::{Compact, Flat, TokenFormat, TokenFormattingError};
pub use self::state::{HasSignature, MaybeSigned, Signed, Unsigned, Unverified, Verified};

/// A JWT Playload. Most payloads are JSON objects, which are serialized, and then converted
/// to a base64url string. However, some payloads are empty, and are represented as an empty
/// string, and therefore not base64url encoded.
///
/// It is hard to express this empty type naturally in the Rust type system in a way that interacts
/// well with [serde_json].
#[derive(Debug, Clone)]
pub enum Payload<P> {
    /// A payload which will be serialized as JSON and then base64url encoded.
    Json(Base64JSON<P>),

    /// An empty payload. This is represented as an empty string, and is not base64url encoded.s
    Empty,
}

#[cfg(feature = "fmt")]
impl<P> fmt::JWTFormat for Payload<P>
where
    P: Serialize,
{
    fn fmt<W: fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> fmt::Result {
        match self {
            Payload::Json(data) => <Base64JSON<P> as fmt::JWTFormat>::fmt(data, f),
            Payload::Empty => f.write_str("\"\""),
        }
    }
}

impl<P> Payload<P>
where
    P: Serialize,
{
    fn serialized_value(&self) -> Result<String, serde_json::Error> {
        match self {
            Payload::Json(data) => data.serialized_value(),
            Payload::Empty => Ok("".to_owned()),
        }
    }
}

impl<P> From<P> for Payload<P> {
    fn from(value: P) -> Self {
        Payload::Json(value.into())
    }
}

impl<P> ser::Serialize for Payload<P>
where
    P: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Payload::Json(data) => data.serialize(serializer),
            Payload::Empty => serializer.serialize_str(""),
        }
    }
}

impl<'de, P> de::Deserialize<'de> for Payload<P>
where
    P: for<'d> Deserialize<'d>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PayloadVisitor<P>(PhantomData<P>);

        impl<'de, P> de::Visitor<'de> for PayloadVisitor<P>
        where
            P: de::DeserializeOwned,
        {
            type Value = Payload<P>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a base64url encoded json document")
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.is_empty() {
                    return Ok(Payload::Empty);
                }

                let data = base64ct::Base64UrlUnpadded::decode_vec(v).map_err(|_| {
                    E::invalid_value(de::Unexpected::Str(v), &"invalid base64url encoding")
                })?;

                let data = serde_json::from_slice(&data)
                    .map_err(|err| E::custom(format!("invalid JSON: {err}")))?;
                Ok(Payload::Json(data))
            }
        }

        deserializer.deserialize_str(PayloadVisitor(PhantomData))
    }
}

/// A JSON web token, generic over the signing state, format, and payload.
///
/// Tokens can change state using the `sign`, `verify`, and `unverify` methods.
/// The format can generally not be changed after constructing the token.
///
/// JAWS does not support the general JWS format, only the compact format and
/// the flat format.
///
/// # Examples
///
/// ## Creating a compact token
/// ```
/// use jaws::token::Token;
///
/// let token = Token::compact((), ());
/// ```
///
/// This token will have no payload, and no custom headers, but it is still usable:
/// ```
/// # use jaws::token::Token;
/// # let token = Token::compact((), ());
///
/// use jaws::fmt::JWTFormat;
///
/// println!("{}", token.formatted());
/// ```
///
/// ## Transitioning a token between states
///
/// See [`Token::sign`], [`Token::verify`], and [`Token::unverify`].
///
#[derive(Debug, Clone)]
pub struct Token<P, State: MaybeSigned = Unsigned<()>, Fmt: TokenFormat = Compact> {
    payload: Payload<P>,
    state: State,
    fmt: Fmt,
}

impl<P, State: MaybeSigned, Fmt: TokenFormat> Token<P, State, Fmt> {
    /// Token header values
    ///
    /// # Example: No custom headers, only registered headers.
    ///
    /// ```
    /// use jaws::token::Token;
    ///
    /// let token = Token::compact((), ());
    /// let header = token.header();
    /// assert_eq!(&header.registered.r#type, &None);
    /// ```
    pub fn header(&self) -> &Header<State::Header, State::HeaderState> {
        self.state.header()
    }

    /// Mutable access to Token header values
    pub fn header_mut(&mut self) -> &mut Header<State::Header, State::HeaderState> {
        self.state.header_mut()
    }
}

impl<P, H, Fmt> Token<P, Unsigned<H>, Fmt>
where
    Fmt: TokenFormat,
{
    /// Create a new token with the given header and payload, in a given format.
    ///
    /// See also [`Token::compact`] and [`Token::flat`] to create a token in a specific format.
    pub fn new(header: H, payload: P, fmt: Fmt) -> Self {
        Token {
            payload: Payload::Json(payload.into()),
            state: Unsigned {
                header: Header::new(header),
            },
            fmt,
        }
    }
}

impl<P, H> Token<P, Unsigned<H>, Compact> {
    /// Create a new token with the given header and payload, in the compact format.
    ///
    /// See also [`Token::new`] and [`Token::flat`] to create a token in a specific format.
    ///
    /// The compact format is the format with base64url encoded header and payload, separated
    /// by a dot, and with the signature appended.
    ///
    pub fn compact(header: H, payload: P) -> Token<P, Unsigned<H>, Compact> {
        Token::new(header, payload, Compact::new())
    }
}

impl<P, U, H> Token<P, Unsigned<H>, Flat<U>>
where
    U: Serialize,
{
    /// Create a new token with the given header and payload, in the flat format.
    ///
    /// See also [`Token::new`] and [`Token::compact`] to create a token in a specific format.
    ///
    /// The flat format is the format with a JSON object containing the header, payload, and
    /// signature, all in the same object. It can also include additional JSON data as "unprotected"\
    /// headers, which are not signed and cannot be verified.
    pub fn flat(header: H, unprotected: U, payload: P) -> Token<P, Unsigned<H>, Flat<U>> {
        Token::new(header, payload, Flat::new(unprotected))
    }
}

/// Token serialization and message packing.
impl<P, S, Fmt> Token<P, S, Fmt>
where
    S: MaybeSigned,
    Fmt: TokenFormat,
{
    /// Get the payload and header of the token, serialized in the compact format,
    /// suitable as input into a signature algorithm.
    pub fn message(&self) -> Result<String, serde_json::Error>
    where
        P: Serialize,
        <S as MaybeSigned>::Header: Serialize,
        <S as MaybeSigned>::HeaderState: Serialize,
    {
        let mut msg = String::new();
        let header =
            base64ct::Base64UrlUnpadded::encode_string(&serde_json::to_vec(&self.state.header())?);
        let payload = self.payload.serialized_value()?;
        write!(msg, "{}.{}", header, payload).unwrap();
        Ok(msg)
    }

    /// Get the payload and header of the token, serialized including signature data.
    ///
    /// This method is only available when the token is in a signed state.
    pub fn rendered(&self) -> Result<String, TokenFormattingError>
    where
        P: Serialize,
        S: HasSignature,
        <S as MaybeSigned>::Header: Serialize,
        <S as MaybeSigned>::HeaderState: Serialize,
    {
        let mut msg = String::new();
        self.fmt.render(&mut msg, self)?;
        Ok(msg)
    }
}

impl<H, Fmt, P> Token<P, Unsigned<H>, Fmt>
where
    H: Serialize,
    P: Serialize,
    Fmt: TokenFormat,
{
    /// Sign this token using the given algorithm.
    ///
    /// This method consumes the token and returns a new one with the signature attached.
    /// Once the signature is attached, the internal fields are no longer mutable (as that
    /// would invalidate the signature), but they are still recoverable.
    #[allow(clippy::type_complexity)]
    pub fn sign<A>(
        self,
        algorithm: &A,
    ) -> Result<Token<P, Signed<H, A>, Fmt>, TokenSigningError<A::Error>>
    where
        A: crate::algorithms::SigningAlgorithm,
        A::Key: Clone,
        // A::Signature: Serialize,
    {
        let header = self.state.header.sign::<A>(algorithm.key());
        let headers = Base64JSON(&header).serialized_value()?;
        let payload = self.payload.serialized_value()?;
        let signature = algorithm
            .sign(&headers, &payload)
            .map_err(TokenSigningError::Signing)?;
        Ok(Token {
            payload: self.payload,
            state: Signed { header, signature },
            fmt: self.fmt,
        })
    }
}

impl<H, Fmt, P> Token<P, Unverified<H>, Fmt>
where
    Fmt: TokenFormat,
    H: Serialize,
    P: Serialize,
{
    /// Verify the signature of the token with the given algorithm.
    ///
    /// This method consumes the token and returns a new one with the signature verified.
    ///
    /// The algorithm must be uniquely specified for verification, otherwise the token
    /// could perform a signature downgrade attack.
    #[allow(clippy::type_complexity)]
    pub fn verify<A>(
        self,
        algorithm: A,
    ) -> Result<Token<P, Verified<H, A>, Fmt>, TokenVerifyingError<A::Error>>
    where
        A: crate::algorithms::VerifyAlgorithm,
        A::Key: Clone,
        P: Serialize,
        H: Serialize,
    {
        if A::IDENTIFIER != *self.state.header.algorithm() {
            return Err(TokenVerifyingError::Algorithm(
                A::IDENTIFIER,
                *self.state.header.algorithm(),
            ));
        }

        let signature = &self.state.signature;
        let header = self
            .state
            .header
            .verify::<A>(algorithm.key())
            .map_err(TokenVerifyingError::Verify)?;
        let headers = Base64JSON(&header).serialized_value()?;
        let payload = self.payload.serialized_value()?;
        let signature = algorithm
            .verify(&headers, &payload, signature.as_ref())
            .map_err(TokenVerifyingError::Verify)?;
        Ok(Token {
            payload: self.payload,
            state: Verified { header, signature },
            fmt: self.fmt,
        })
    }
}

impl<P, H, Alg, Fmt> Token<P, Signed<H, Alg>, Fmt>
where
    Fmt: TokenFormat,
    Alg: SigningAlgorithm,
{
    /// Transition the token back into an unverified state.
    ///
    /// This method consumes the token and returns a new one, which still includes the signature
    /// but which is no longer considered verified.
    pub fn unverify(self) -> Token<P, Unverified<H>, Fmt> {
        Token {
            payload: self.payload,
            state: Unverified {
                header: self.state.header.render(),
                signature: Base64Data(self.state.signature.as_ref().to_owned().into()),
            },
            fmt: self.fmt,
        }
    }
}

#[cfg(feature = "fmt")]
impl<P, S, Fmt> fmt::JWTFormat for Token<P, S, Fmt>
where
    S: HasSignature,
    <S as MaybeSigned>::Header: Serialize,
    <S as MaybeSigned>::HeaderState: Serialize,
    P: Serialize,
    Fmt: TokenFormat,
{
    fn fmt<W: std::fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> std::fmt::Result {
        let header = serde_json::to_value(self.state.header()).unwrap();
        let payload = serde_json::to_value(&self.payload).unwrap();
        let signature = serde_json::to_value(Base64Data(self.state.signature())).unwrap();

        let token = serde_json::json!({
            "header": header,
            "payload": payload,
            "signature": signature,
        });

        f.write_str(&token.to_string())
    }
}

#[cfg(feature = "fmt")]
impl<P, H, Fmt> fmt::JWTFormat for Token<P, Unsigned<H>, Fmt>
where
    H: Serialize,
    P: Serialize,
    Fmt: TokenFormat,
{
    fn fmt<W: std::fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> std::fmt::Result {
        let header = self.state.header().value();
        let payload =
            serde_json::to_value(&self.payload).expect("payload should serialize to json:");

        let token = serde_json::json!({
            "header": header,
            "payload": payload,
            "signature": "<signature>",
        });

        f.write_str(&token.to_string())
    }
}

/// An error which occured while verifying a token.
#[derive(Debug, thiserror::Error)]
pub enum TokenVerifyingError<E> {
    /// The verification failed during the cryptographic process, meaning
    /// that the signature was invalid, or the algorithm was invalid.
    #[error("verifying: {0}")]
    Verify(E),

    /// An error occured while re-serailizing the header or payload for
    /// signature verification. This indicates that something is probably
    /// wrong with your custom types.
    #[error("serializing: {0}")]
    Serialization(#[from] serde_json::Error),

    /// The algorithm specified in the header does not match the algorithm
    /// of the verifier.
    #[error("algorithm mismatch: expected {0:?}, got {1:?}")]
    Algorithm(AlgorithmIdentifier, AlgorithmIdentifier),
}

/// An error which occured while verifying a token.
#[derive(Debug, thiserror::Error)]
pub enum TokenSigningError<E> {
    /// The verification failed during the cryptographic process, meaning
    /// that the signature was invalid, or the algorithm was invalid.
    #[error("signing: {0}")]
    Signing(E),

    /// An error occured while serailizing the header or payload for
    /// signature computation. This indicates that something is probably
    /// wrong with your custom types.
    #[error("serializing: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::claims::Claims;

    use base64ct::Encoding;
    use chrono::TimeZone;
    use serde_json::json;
    use sha2::Sha256;

    use crate::key::jwk_reader::rsa;

    fn strip_whitespace(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    fn rfc7515_example_a2_key() -> ::rsa::RsaPrivateKey {
        rsa(&json!( {"kty":"RSA",
              "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx
       HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs
       D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH
       SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV
       MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8
       NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
              "e":"AQAB",
              "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I
       jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0
       BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn
       439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT
       CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh
       BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
              "p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi
       YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG
       BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
              "q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa
       ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA
       -njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
              "dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q
       CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb
       34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
              "dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa
       7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky
       NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
              "qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o
       y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU
       W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
             }
        ))
    }

    #[test]
    fn rfc7515_example_a2() {
        // This test alters the example from RFC 7515, section A.2, since
        // the RFC does not require a specific JSON serialization format,
        // so we use the compact representation without newlines, as opposed
        // to the one presented in the RFC.
        //
        // Link: https://tools.ietf.org/html/rfc7515#appendix-A.2
        //
        // See crate::algorithms::rsa::test::rfc7515_example_A2 for a test
        // which validates the signature against the RFC example.

        let pkey = rfc7515_example_a2_key();

        let custom = json!({
            "http://example.com/is_root": true
        });

        let mut claims = Claims::from(custom);
        claims.registered.issued_at = chrono::Utc.timestamp_opt(1300819380, 0).single();
        claims.registered.issuer = Some("joe".into());

        let token = Token::new((), claims, Compact::new());
        let algorithm: crate::algorithms::rsa::RsaPkcs1v15<Sha256> =
            crate::algorithms::rsa::RsaPkcs1v15::new_with_prefix(pkey);
        let signed = token.sign(&algorithm).unwrap();
        {
            let hdr = base64ct::Base64UrlUnpadded::encode_string(
                &serde_json::to_vec(&signed.state.header()).unwrap(),
            );
            assert_eq!(hdr, "eyJhbGciOiJSUzI1NiJ9")
        }
        {
            let msg = signed.message().unwrap();
            assert_eq!(
                msg,
                strip_whitespace(
                    "eyJhbGciOiJSUzI1NiJ9
            .
            eyJpc3MiOiJqb2UiLCJpYXQiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtc
            GxlLmNvbS9pc19yb290Ijp0cnVlfQ"
                )
            )
        }

        {
            let tkn = signed.rendered().unwrap();
            assert_eq!(
                tkn,
                strip_whitespace(
                    "
            eyJhbGciOiJSUzI1NiJ9
            .
            eyJpc3MiOiJqb2UiLCJpYXQiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtc
            GxlLmNvbS9pc19yb290Ijp0cnVlfQ
            .
            OqzEd_gl5CDmUo9jVwC7yrlKSWUaAQoa2_4JSVzSem5nBjv5mx2PbkEZw
            0qP6karpsUfa0qkNlvtIrdYCWS3GnHff7LBkJkN8tvJgI1zCY2QqIOD0e
            E1yK3AGgxR0yMDHgY9SIFoXi5cK1UHPeiGkU7GlMmZf2zH-YFOQMK7__7
            VdH1y7cap6j3xW4LczctcBjJRFRku7i_gAy9JiR34WsqolbxKOQPIGK8w
            TE3Qo5BhB70IRMJL6O-jqgYVDAl0BrakNKqZtVTLss41ErM5Twyvin740
            UPIE2oHq3cLzCzXcEPEIPqr4_jerU9Wc8vevZ3-wE5czssL6RgtzJjuyw"
                )
            )
        }
    }
}
