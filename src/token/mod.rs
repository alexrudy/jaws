//! JSON Web Tokens ([RFC 7519][RFC7519])
//!
//! This module implements the JWS and JWE formats for representing JSON Web Tokens.
//! It is designed to both accept registered headers and claims (see [crate::claims]) as
//! well as custom payloads and entirely custom headers. All registered fields are optional
//! except for the "alg" field in the JOSE header which is required to identify the signing
//! algorithm in use.
//!
//! [RFC7519]: https://tools.ietf.org/html/rfc7519

use std::marker::PhantomData;
use std::{fmt::Write, str::FromStr};

use base64ct::Encoding;
use bytes::Bytes;
use serde::{
    de::{self, DeserializeOwned},
    ser, Deserialize, Serialize,
};
use signature::SignatureEncoding;

use crate::{
    algorithms::{AlgorithmIdentifier, DynJsonWebAlgorithm},
    base64data::{Base64JSON, Base64Signature, DecodeError},
    jose::{Header, HeaderAccess, HeaderAccessMut, HeaderState},
};
#[cfg(feature = "fmt")]
use crate::{fmt, JWTFormat};

pub mod formats;
mod state;

use self::formats::TokenParseError;
pub use self::formats::{Compact, Flat, FlatUnprotected, TokenFormat, TokenFormattingError};
pub use self::state::{HasSignature, MaybeSigned, Signed, Unsigned, Unverified};

#[allow(deprecated)]
pub use self::state::Verified;

/// A JWT Playload. Most payloads are JSON objects, which are serialized, and then converted
/// to a base64url string. However, some payloads are empty, and are represented as an empty
/// string, and therefore not base64url encoded.
///
/// It is hard to express this empty type naturally in the Rust type system in a way that interacts
/// well with [serde_json].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Payload<P> {
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

    fn serialized_bytes(&self) -> Result<Bytes, serde_json::Error> {
        match self {
            Payload::Json(data) => data.serialized_bytes(),
            Payload::Empty => Ok(Bytes::new()),
        }
    }
}

impl<P> Payload<P>
where
    P: DeserializeOwned,
{
    fn parse(value: &str) -> Result<Self, DecodeError> {
        if value.is_empty() {
            return Ok(Payload::Empty);
        }

        let parsed = Base64JSON::<P>::parse(value)?;
        Ok(Payload::Json(parsed.data.into()))
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
/// A few examples are shown below, but the most powerful examples are shown
/// in the `examples` directory.
///
/// ## Creating a compact token
/// ```
/// use jaws::token::Token;
///
/// let token = Token::compact((), ());
/// ```
///
/// This token will have no payload, and no custom headers.
#[cfg_attr(
    feature = "fmt",
    doc = r#"
To view a debug representation of the token, use the [`fmt::JWTFormat`] trait:

```
# use jaws::token::Token;
# let token = Token::compact((), ());
use jaws::fmt::JWTFormat;

println!("{}", token.formatted());
```
"#
)]
///
/// ## Transitioning a token between states
///
/// Tokens start in either the [`Unsigned`] or [`Unverified`] state. [`Unsigned`] tokens
/// are ones constructed locally, but before a signature has been applied. [`Unverified`]
/// tokens are ones which have been parsed from a string, but which have not yet been
/// checked.
///
#[cfg_attr(
    feature = "rsa",
    doc = r#"
To transition a token from the [`Unsigned`] state to the [`Signed`] state, use the
[`Token::sign`] method:

```rust
# use jaws::token::Token;
# use rand::rand_core::UnwrapErr;
# let mut rng = UnwrapErr(rand::rngs::SysRng);
let key = rsa::pkcs1v15::SigningKey::random(&mut rng, 2048).unwrap();
let token = Token::compact((), ());

// The only way to get a signed token is to sign an Unsigned token!
let signed = token.sign::<rsa::pkcs1v15::SigningKey<sha2::Sha256>, rsa::pkcs1v15::Signature>(&key).unwrap();
println!("Token: {}", signed.rendered().unwrap());
```
Signing often requires specifying the algorithm to use. In the example above, we use
`RS256`, which is the RSA-PKCS1-v1-5 signature algorithm with SHA-256. The algorithm is
specified by constraining the type of `key` when calling [`Token::sign`].

Signed tokens can become unverified ones by discarding the memory of the key used to sign
them. This is done with the [`Token::unverify`] method:

```rust
# use jaws::token::Token;
# use rand::rand_core::UnwrapErr;
# let mut rng = UnwrapErr(rand::rngs::SysRng);
# let key: rsa::pkcs1v15::SigningKey<sha2::Sha256> = rsa::pkcs1v15::SigningKey::random(&mut rng, 2048).unwrap();
# let token = Token::compact((), ());
# let signed = token.sign::<_, rsa::pkcs1v15::Signature>(&key).unwrap();
// We can unverify the token, which discard the memory of the key used to sign it.
let unverified = signed.unverify();

// Unverified tokens still have a signature, but it is no longer considered valid.
println!("Token: {}", unverified.rendered().unwrap());
```

Tokens can also be transitioned from the [`Unverified`] state to the [`Verified`] state
by checking the signature. This is done with the [`Token::verify`] method:

```rust
# use jaws::token::Token;
# use signature::Keypair;
# use rand::rand_core::UnwrapErr;
# let mut rng = UnwrapErr(rand::rngs::SysRng);
# let key: rsa::pkcs1v15::SigningKey<sha2::Sha256> = rsa::pkcs1v15::SigningKey::random(&mut rng, 2048).unwrap();
# let verifying_key = key.verifying_key();
# let token = Token::compact((), ());
# let signed = token.sign::<_, rsa::pkcs1v15::Signature>(&key).unwrap();
# let unverified = signed.unverify();
let verified = unverified.verify::<_, rsa::pkcs1v15::Signature>(&verifying_key).unwrap();
println!("Token: {}", verified.rendered().unwrap());
```

Verification can fail if the signature is invalid, or if the algorithm does not match the
one specified in the header. Since keys are strongly typed, it is not possible to make a
signature substitution attack using a different key type.
"#
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token<P, State: MaybeSigned = Unsigned<()>, Fmt: TokenFormat = Compact> {
    payload: Payload<P>,
    state: State,
    fmt: Fmt,
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

    /// Create an empty token with a given header and format.
    pub fn empty(header: H, fmt: Fmt) -> Self {
        Token {
            payload: Payload::Empty,
            state: Unsigned {
                header: Header::new(header),
            },
            fmt,
        }
    }
}

impl<P, Fmt> Token<P, Unsigned<()>, Fmt>
where
    Fmt: TokenFormat,
{
    /// Create an empty token with no custom header values.
    pub fn blank(fmt: Fmt) -> Self {
        Token {
            payload: Payload::Empty,
            state: Unsigned {
                header: Header::new(()),
            },
            fmt,
        }
    }

    /// Create a token with a given payload and format, but no custom header values.
    pub fn new_with_payload(payload: P, fmt: Fmt) -> Self {
        Token {
            payload: Payload::Json(payload.into()),
            state: Unsigned {
                header: Header::new(()),
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

impl<P, H> Token<P, Unsigned<H>, Flat> {
    /// Create a new token with the given header and payload, in the flat format.
    ///
    /// See also [`Token::new`] and [`Token::compact`] to create a token in a specific format.
    ///
    /// The flat format is the format with a JSON object containing the header, payload, and
    /// signature, all in the same object. It can also include additional JSON data as "unprotected"\
    /// headers, which are not signed and cannot be verified.
    pub fn flat(header: H, payload: P) -> Token<P, Unsigned<H>, Flat> {
        Token::new(header, payload, Flat)
    }
}

impl<P, State: MaybeSigned, Fmt: TokenFormat> Token<P, State, Fmt> {
    /// Access to Token header values.
    ///
    /// All access is read-only, and the header cannot be modified here,
    /// see [`Token::header_mut`] for mutable access.
    ///
    /// Header fields are accessed as methods on [`HeaderAccess`], and
    /// their types will depend on the state of the token. Additionally,
    /// the `alg` field will not be availalbe for unsigned token types.
    ///
    /// # Example: No custom headers, only registered headers.
    ///
    /// ```
    /// use jaws::token::Token;
    ///
    /// let token = Token::compact((), ());
    /// let header = token.header();
    /// assert_eq!(&header.r#type(), &None);
    /// ```
    pub fn header(&'_ self) -> HeaderAccess<'_, State::Header, State::HeaderState> {
        HeaderAccess::new(self.state.header())
    }
}

impl<P, H, Fmt: TokenFormat> Token<P, Unsigned<H>, Fmt> {
    /// Mutable access to Token header values
    pub fn header_mut(&mut self) -> HeaderAccessMut<'_, H, crate::jose::UnsignedHeader> {
        HeaderAccessMut::new(self.state.header_mut())
    }
}

/// Token serialization and message packing.
impl<P, S, Fmt> Token<P, S, Fmt>
where
    S: MaybeSigned,
    Fmt: TokenFormat,
{
    /// Convert this token to a new format
    pub fn into_format<NewFmt>(self) -> Token<P, S, NewFmt>
    where
        NewFmt: TokenFormat + From<Fmt>,
    {
        Token {
            payload: self.payload,
            state: self.state,
            fmt: NewFmt::from(self.fmt),
        }
    }

    /// Get the payload and header of the token, serialized in the compact format,
    /// suitable as input into a signature algorithm.
    pub fn message(&self) -> Result<String, serde_json::Error>
    where
        P: Serialize,
        <S as MaybeSigned>::Header: Serialize,
        <S as MaybeSigned>::HeaderState: Serialize + HeaderState,
    {
        let mut msg = String::new();
        let header =
            base64ct::Base64UrlUnpadded::encode_string(&serde_json::to_vec(self.state.header())?);
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
        <S as MaybeSigned>::HeaderState: HeaderState,
    {
        let mut msg = String::new();
        self.fmt.render(&mut msg, self)?;
        Ok(msg)
    }
}

impl<H, Fmt, P> Token<P, Unsigned<H>, Fmt>
where
    Fmt: TokenFormat,
{
    /// Get the payload of the token.
    pub fn payload(&self) -> Option<&P> {
        match &self.payload {
            Payload::Json(data) => Some(data.as_ref()),
            Payload::Empty => None,
        }
    }

    /// Replace the custom header fields of the token.
    pub fn with_custom_header<H2>(self, header: H2) -> Token<P, Unsigned<H2>, Fmt> {
        Token {
            payload: self.payload,
            state: Unsigned {
                header: self.state.header.with_custom_header(header),
            },
            fmt: self.fmt,
        }
    }
}

impl<H, Fmt, P> Token<P, Unsigned<H>, Fmt>
where
    Fmt: TokenFormat,
{
    /// Sign this token using the given algorithm.
    ///
    /// This method consumes the token and returns a new one with the signature attached.
    /// Once the signature is attached, the internal fields are no longer mutable (as that
    /// would invalidate the signature), but they are still recoverable.
    ///
    /// When using this method, you will need to specify the signature encoding type along
    /// with the algorithm (i.e. both parameters A and S). The algorithm does not uniquely
    /// identify the signature kind, and so it is not possible to infer the signature type
    /// from just the algorithm type. For example, all included algorithms also implement
    /// signing for the [`crate::algorithms::SignatureBytes`] type, which is a raw byte array,
    /// suitable for use with any signature (and appropriate for use when you don't want to
    /// statically specify the signature type, see the dyn-key example).
    ///
    #[cfg_attr(
        feature = "rsa",
        doc = r#"
# Example: Signing with a key

```rust
# use jaws::token::Token;
# use rand::rand_core::UnwrapErr;
# let mut rng = UnwrapErr(rand::rngs::SysRng);
let key = rsa::pkcs1v15::SigningKey::random(&mut rng, 2048).unwrap();
let token = Token::compact((), ());

// The only way to get a signed token is to sign an Unsigned token!
let signed = token.sign::<rsa::pkcs1v15::SigningKey<sha2::Sha256>, rsa::pkcs1v15::Signature>(&key).unwrap();
println!("Token: {}", signed.rendered().unwrap());
```

Signing often requires specifying the algorithm to use. In the example above, we use
`RS256`, which is the RSA-PKCS1-v1-5 signature algorithm with SHA-256. The algorithm is
specified by constraining the type of `key` when calling [`Token::sign`].
    "#
    )]
    #[allow(clippy::type_complexity)]
    pub fn sign<A, S>(
        self,
        algorithm: &A,
    ) -> Result<Token<P, Signed<H, A, S>, Fmt>, TokenSigningError>
    where
        A: crate::algorithms::TokenSigner<S> + ?Sized,
        S: SignatureEncoding,
        P: Serialize,
        H: Serialize,
    {
        let header = self.state.header.into_signed_header(algorithm)?;
        let payload = self.payload.serialized_value()?;
        let signature = algorithm
            .try_sign_token(&header.message()?, &payload)
            .map_err(TokenSigningError::Signing)?;
        Ok(Token {
            payload: self.payload,
            state: Signed {
                header,
                signature,
                _phantom_key: PhantomData,
            },
            fmt: self.fmt,
        })
    }

    /// Sign this token using the given algorithm, and a random number generator.
    #[cfg(feature = "rand")]
    #[allow(clippy::type_complexity)]
    pub fn sign_randomized<A, S>(
        self,
        algorithm: &A,
        rng: &mut impl rand_core::TryCryptoRng,
    ) -> Result<Token<P, Signed<H, A, S>, Fmt>, TokenSigningError>
    where
        A: crate::algorithms::RandomizedTokenSigner<S> + ?Sized,
        S: SignatureEncoding,
        P: Serialize,
        H: Serialize,
    {
        let header = self.state.header.into_signed_header(algorithm)?;
        let payload = self.payload.serialized_value()?;
        let signature = algorithm
            .try_sign_token(&header.message()?, &payload, rng)
            .map_err(TokenSigningError::Signing)?;
        Ok(Token {
            payload: self.payload,
            state: Signed {
                header,
                signature,
                _phantom_key: PhantomData,
            },
            fmt: self.fmt,
        })
    }
}

impl<H, Fmt, P> Token<P, Unverified<H>, Fmt>
where
    Fmt: TokenFormat,
{
    /// Returns `true` if the token can be verified with the given algorithm.
    pub fn can_verify<A>(&self, algorithm: &A) -> bool
    where
        A: crate::algorithms::TokenVerifier + ?Sized,
    {
        algorithm.identifier() == *self.state.header.algorithm()
    }

    /// Verify the signature of the token with the given algorithm.
    ///
    /// This method consumes the token and returns a new one with the signature verified.
    ///
    /// The algorithm must be uniquely specified for verification, otherwise the token
    /// could perform a signature downgrade attack.
    #[allow(clippy::type_complexity)]
    pub fn verify<A, S>(
        self,
        algorithm: &A,
    ) -> Result<Token<P, Signed<H, A, S>, Fmt>, TokenVerifyingError<P, H, Fmt>>
    where
        A: crate::algorithms::TokenVerifier<S> + ?Sized,
        S: SignatureEncoding,
    {
        if algorithm.identifier() != *self.state.header.algorithm() {
            let token_algorithm = *self.state.header.algorithm();
            return Err(TokenVerifyingError::new(
                self,
                TokenVerifyingErrorKind::Algorithm {
                    expected: algorithm.identifier(),
                    actual: token_algorithm,
                },
            ));
        }

        let signature = &self.state.signature;
        let signature = match algorithm.verify_token(
            &self.state.header.state.raw,
            &self.state.payload,
            signature.as_ref(),
        ) {
            Ok(sig) => sig,
            Err(err) => {
                return Err(TokenVerifyingError::new(
                    self,
                    TokenVerifyingErrorKind::Verify(err),
                ))
            }
        };

        let header = self.state.header.into_signed_header::<A, S>(algorithm);

        Ok(Token {
            payload: self.payload,
            state: Signed {
                header,
                signature,
                _phantom_key: PhantomData,
            },
            fmt: self.fmt,
        })
    }
}

impl<P, H, Fmt> FromStr for Token<P, Unverified<H>, Fmt>
where
    P: DeserializeOwned,
    H: DeserializeOwned,
    Fmt: TokenFormat,
{
    type Err = TokenParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Fmt::parse(Bytes::from(s.to_owned()))
    }
}

impl<P, H, Alg, Sig, Fmt> Token<P, Signed<H, Alg, Sig>, Fmt>
where
    Fmt: TokenFormat,
    Alg: DynJsonWebAlgorithm + ?Sized,
    Sig: SignatureEncoding,
    H: Serialize,
    P: Serialize,
{
    /// Transition the token back into an unverified state.
    ///
    /// This method consumes the token and returns a new one, which still includes the signature
    /// but which is no longer considered verified.
    pub fn unverify(self) -> Token<P, Unverified<H>, Fmt> {
        let payload = self
            .payload
            .serialized_bytes()
            .expect("valid payload bytes");
        Token {
            payload: self.payload,
            state: Unverified {
                payload,
                header: self.state.header.into_rendered_header(),
                signature: Base64Signature(self.state.signature.to_bytes().as_ref().into()),
            },
            fmt: self.fmt,
        }
    }
}

impl<H, Fmt, P, Alg, Sig> Token<P, Signed<H, Alg, Sig>, Fmt>
where
    Fmt: TokenFormat,
    Alg: DynJsonWebAlgorithm + ?Sized,
{
    /// Get the payload of the token.
    pub fn payload(&self) -> Option<&P> {
        match &self.payload {
            Payload::Json(data) => Some(data.as_ref()),
            Payload::Empty => None,
        }
    }
}

#[cfg(feature = "fmt")]
impl<P, S, Fmt> fmt::JWTFormat for Token<P, S, Fmt>
where
    S: HasSignature,
    S::Signature: SignatureEncoding,
    <S as MaybeSigned>::Header: Serialize,
    <S as MaybeSigned>::HeaderState: HeaderState,
    P: Serialize,
    Fmt: TokenFormat,
{
    fn fmt<W: std::fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> std::fmt::Result {
        {
            let mut inner = f.indent_skip_first();

            inner.write_str("{\n")?;
            inner.write_str("\"header\": ")?;
            self.state.header().fmt(&mut inner)?;
            inner.write_str(",\n")?;
            inner.write_str("\"payload\": ")?;
            self.payload.fmt(&mut inner)?;
            inner.write_str(",\n")?;
            inner.write_str("\"signature\": ")?;
            JWTFormat::fmt(
                &Base64Signature(self.state.signature().to_bytes().as_ref()),
                &mut inner,
            )?;
        }
        f.write_str("\n}")?;

        Ok(())
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
        {
            let mut inner = f.indent_skip_first();

            inner.write_str("{\n")?;
            inner.write_str("\"header\": ")?;
            self.state.header().fmt(&mut inner)?;
            inner.write_str(",\n")?;
            inner.write_str("\"payload\": ")?;
            self.payload.fmt(&mut inner)?;
            inner.write_str(",\n")?;
            inner.write_str("\"signature\": <signature>")?;
        }
        f.write_str("\n}")?;

        Ok(())
    }
}

/// An error which occured while verifying a token.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[error("{kind}")]
pub struct TokenVerifyingError<P, H, F>
where
    F: TokenFormat,
{
    /// The token which failed to verify.
    pub token: Token<P, Unverified<H>, F>,

    /// The error which occurred during verification.
    #[source]
    pub kind: TokenVerifyingErrorKind,
}

impl<P, H, F> TokenVerifyingError<P, H, F>
where
    F: TokenFormat,
{
    pub(crate) fn new(token: Token<P, Unverified<H>, F>, kind: TokenVerifyingErrorKind) -> Self {
        Self { token, kind }
    }
}

/// An error which occured while verifying a token.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TokenVerifyingErrorKind {
    /// The verification failed during the cryptographic process, meaning
    /// that the signature was invalid, or the algorithm was invalid.
    #[error("verifying: {0}")]
    Verify(#[source] signature::Error),

    /// The algorithm specified in the header does not match the algorithm
    /// of the verifier.
    #[error("algorithm mismatch: expected {expected:?}, got {actual:?}")]
    Algorithm {
        /// The expected algorithm.
        expected: AlgorithmIdentifier,

        /// The actual algorithm for the token
        actual: AlgorithmIdentifier,
    },
}

/// An error which occured while verifying a token.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TokenSigningError {
    /// The verification failed during the cryptographic process, meaning
    /// that the signature was invalid, or the algorithm was invalid.
    #[error("signing: {0}")]
    Signing(#[from] signature::Error),

    /// An error occured while serailizing the header or payload for
    /// signature computation. This indicates that something is probably
    /// wrong with your custom types.
    #[error("serializing: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[cfg(all(test, feature = "rsa"))]
mod test_rsa {
    use super::*;
    use crate::{claims::Claims, key::DeserializeJWK as _};

    use base64ct::Encoding;
    use chrono::TimeZone;
    use serde_json::json;
    use sha2::Sha256;

    use signature::Keypair;

    fn strip_whitespace(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    fn rfc7515_example_a2_key() -> ::rsa::PrivateKey {
        rsa::PrivateKey::from_value(crate::key::fixtures::rfc7515_a2()).unwrap()
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
        let algorithm: rsa::pkcs1v15::SigningKey<Sha256> = rsa::pkcs1v15::SigningKey::new(pkey);
        let signed = token
            .sign::<_, rsa::pkcs1v15::Signature>(&algorithm)
            .unwrap();
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

        let algorithm = algorithm.verifying_key();

        signed
            .unverify()
            .verify::<_, rsa::pkcs1v15::Signature>(&algorithm)
            .unwrap();
    }
}

#[cfg(all(test, feature = "ecdsa", feature = "p256"))]
mod test_ecdsa {
    use super::*;

    use base64ct::Encoding;
    use ecdsa::SigningKey;
    use elliptic_curve::FieldBytes;
    use zeroize::Zeroize;

    fn strip_whitespace(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    fn ecdsa(jwk: &serde_json::Value) -> SigningKey<p256::NistP256> {
        let d_b64 = strip_whitespace(jwk["d"].as_str().unwrap());
        let mut d_bytes = FieldBytes::<p256::NistP256>::default();
        base64ct::Base64UrlUnpadded::decode(&d_b64, &mut d_bytes).unwrap();

        let key = SigningKey::from_slice(&d_bytes).unwrap();
        d_bytes.zeroize();
        key
    }

    #[test]
    fn rfc7515_example_a3() {
        let pkey = &crate::key::fixtures::rfc7515_a3();

        let key = ecdsa(pkey);

        let token = Token::compact((), "This is a signed message");

        let signed = token.sign::<_, ::ecdsa::Signature<_>>(&key).unwrap();

        let verifying_key = key.verifying_key();

        let verified = signed
            .unverify()
            .verify::<_, ::ecdsa::Signature<_>>(verifying_key)
            .unwrap();

        assert_eq!(verified.payload(), Some(&"This is a signed message"));
    }

    #[cfg(feature = "rand")]
    #[test]
    fn rfc7515_example_a3_randomized() {
        let pkey = &crate::key::fixtures::rfc7515_a3();

        let key = ecdsa(pkey);

        let token = Token::compact((), "This is a signed message");

        let signed = token
            .sign_randomized::<_, ::ecdsa::Signature<_>>(&key, &mut rand::rngs::SysRng)
            .unwrap();

        let verifying_key = key.verifying_key();

        let verified = signed
            .unverify()
            .verify::<_, ::ecdsa::Signature<_>>(verifying_key)
            .unwrap();

        assert_eq!(verified.payload(), Some(&"This is a signed message"));
    }
}

#[cfg(all(test, feature = "hmac"))]
mod test_hmac {
    use crate::algorithms::hmac::{DigestSignature, Hmac, HmacKey};

    use super::*;

    use base64ct::Encoding;
    use sha2::Sha256;

    fn strip_whitespace(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    #[test]
    fn rfc7515_example_a1() {
        let pkey = &crate::key::fixtures::rfc7515_a1();

        let key_data = strip_whitespace(pkey["k"].as_str().unwrap());

        let decoded_len = 3 * key_data.len() / 4;

        let mut key = HmacKey::with_capacity(decoded_len);
        key.resize(decoded_len, 0);

        base64ct::Base64UrlUnpadded::decode(&key_data, key.as_mut()).unwrap();

        let algorithm: Hmac<Sha256> = Hmac::new(key);

        let token = Token::compact((), "This is an HMAC'd message");

        let signed = token.sign::<_, DigestSignature<_>>(&algorithm).unwrap();

        let verified = signed
            .unverify()
            .verify::<_, DigestSignature<_>>(&algorithm)
            .unwrap();

        assert_eq!(verified.payload(), Some(&"This is an HMAC'd message"));
    }
}
