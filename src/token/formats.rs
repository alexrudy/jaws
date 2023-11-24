use std::fmt::Write;

use bytes::Bytes;
use serde::de::DeserializeOwned;
use serde::{ser, Deserialize, Serialize};

use super::{HasSignature, MaybeSigned, Unverified};
use super::{Payload, Token};
use crate::algorithms::SignatureBytes;
use crate::base64data::{Base64Data, Base64JSON, DecodeError};
use crate::jose::{HeaderState, RenderedHeader};
use crate::Header;

/// A token format that serializes the token as a compact string.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Compact;

impl Compact {
    /// Creates a new `Compact` token format.
    ///
    /// Since no extra information is needed, the header and payload
    /// are stored in the token itself.
    pub fn new() -> Compact {
        Compact
    }
}

/// A token format that serializes the token as a single JSON object,
/// with the unprotected header as a top-level field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlatUnprotected<U> {
    unprotected: U,
}

impl<U> FlatUnprotected<U> {
    /// Creates a new `Flat` token format with the given unprotected header.
    pub fn new(unprotected: U) -> Self {
        Self { unprotected }
    }

    /// Returns a reference to the unprotected header.
    pub fn unprotected(&self) -> &U {
        &self.unprotected
    }

    /// Returns a mutable reference to the unprotected header.
    pub fn unprotected_mut(&mut self) -> &mut U {
        &mut self.unprotected
    }
}

/// A token format that serializes the token as a single JSON object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flat;

/// Error returned when a token cannot be formatted as a string.
///
/// This error can occur when serializing the header or payload, or
/// when writing to the writer.
#[derive(Debug, thiserror::Error)]
pub enum TokenFormattingError {
    /// An error occured while serailizing the header or payload.
    /// This indicates that something is probably wrong with your
    /// custom header types.
    #[error("serializing: {0}")]
    Serialization(#[from] serde_json::Error),

    /// An error occured while writing to the writer.
    #[error("io: {0}")]
    IO(#[from] std::fmt::Error),
}

/// Error returned when a token cannot be parsed from a string.
///
/// This error can occur when deserializing the header or payload
#[derive(Debug, thiserror::Error)]
pub enum TokenParseError {
    /// Unable to find the header in the raw data.
    #[error("missing header")]
    MissingHeader,

    /// Unable to find the payload in the raw data.
    #[error("missing payload")]
    MissingPayload,

    /// Unable to find the signature in the raw data.
    #[error("missing signature")]
    MissingSignature,

    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    #[error(transparent)]
    Base64(#[from] DecodeError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("unexpected JSON value for {0}: {1}")]
    UnexpectedJSONValue(&'static str, serde_json::Value),
}

/// Trait for token formats, defining how they are serialized.
pub trait TokenFormat {
    /// Render the token to the given writer.
    fn render<S>(
        &self,
        writer: &mut impl Write,
        token: &Token<impl Serialize, S, Self>,
    ) -> Result<(), TokenFormattingError>
    where
        Self: Sized,
        S: HasSignature,
        <S as MaybeSigned>::Header: Serialize,
        <S as MaybeSigned>::HeaderState: HeaderState;

    /// Parse the token from a slice.
    fn parse<P, H>(data: Bytes) -> Result<Token<P, Unverified<H>, Self>, TokenParseError>
    where
        P: DeserializeOwned,
        H: DeserializeOwned,
        Self: Sized;
}

impl TokenFormat for Compact {
    fn render<S>(
        &self,
        writer: &mut impl Write,
        token: &Token<impl Serialize, S, Self>,
    ) -> Result<(), TokenFormattingError>
    where
        Self: Sized,
        S: HasSignature,
        <S as MaybeSigned>::Header: Serialize,
        <S as MaybeSigned>::HeaderState: HeaderState,
    {
        let header = Base64JSON(&token.state.header()).serialized_value()?;
        let payload = token.payload.serialized_value()?;
        let signature = Base64Data(token.state.signature()).serialized_value()?;
        write!(writer, "{}.{}.{}", header, payload, signature)?;
        Ok(())
    }

    fn parse<P, H>(data: Bytes) -> Result<Token<P, Unverified<H>, Self>, TokenParseError>
    where
        P: DeserializeOwned,
        H: DeserializeOwned,
        Self: Sized,
    {
        let mut parts = data.splitn(3, |&b| b == b'.');
        let header = {
            let b64_header =
                std::str::from_utf8(parts.next().ok_or(TokenParseError::MissingHeader)?)?;

            let wrapped_header = Base64JSON::<Header<H, RenderedHeader>>::parse(b64_header)?;
            let mut header = wrapped_header.data;
            header.state.raw = wrapped_header.bytes;
            header
        };

        let (payload, raw_payload) = {
            let b64_payload: &str =
                std::str::from_utf8(parts.next().ok_or(TokenParseError::MissingPayload)?)?;
            let payload: Payload<P> = Payload::parse(b64_payload)?;
            let raw_payload: Vec<u8> = b64_payload.as_bytes().into();
            (payload, raw_payload)
        };

        let signature = {
            let signature = parts.next().ok_or(TokenParseError::MissingSignature)?;
            let signature: Base64Data<SignatureBytes> =
                Base64Data::parse(std::str::from_utf8(signature)?)?;
            signature
        };

        Ok(Token {
            payload,
            state: Unverified {
                header,
                signature,
                payload: raw_payload.into(),
            },
            fmt: Compact,
        })
    }
}

#[derive(Debug, Serialize)]
struct FlatToken<'t, P, U> {
    payload: &'t Payload<P>,
    protected: String,
    unprotected: &'t U,
    signature: String,
}

impl<U> TokenFormat for FlatUnprotected<U>
where
    U: Serialize + DeserializeOwned,
{
    fn render<S>(
        &self,
        writer: &mut impl Write,
        token: &Token<impl Serialize, S, Self>,
    ) -> Result<(), TokenFormattingError>
    where
        Self: Sized,
        S: HasSignature,
        <S as MaybeSigned>::Header: Serialize,
        <S as MaybeSigned>::HeaderState: HeaderState,
    {
        let header = Base64JSON(token.state.header()).serialized_value()?;
        let signature = Base64Data(token.state.signature()).serialized_value()?;

        let flat = FlatToken {
            payload: &token.payload,
            protected: header,
            unprotected: &self.unprotected,
            signature,
        };

        let data = serde_json::to_string(&flat)?;
        write!(writer, "{}", data)?;

        Ok(())
    }

    fn parse<P, H>(data: Bytes) -> Result<Token<P, Unverified<H>, Self>, TokenParseError>
    where
        P: DeserializeOwned,
        H: DeserializeOwned,
        Self: Sized,
    {
        let value: serde_json::Value = serde_json::from_slice(&data)?;
        let serde_json::Value::Object(mut object): serde_json::Value = value else {
            return Err(TokenParseError::UnexpectedJSONValue("token", value));
        };

        let Token { payload, state, .. } = parse_flat_common_values(&mut object)?;

        let unprotected = {
            let unprotected = object
                .remove("unprotected")
                .ok_or(TokenParseError::MissingHeader)?;
            let unprotected: U = serde_json::from_value(unprotected)?;
            unprotected
        };

        Ok(Token {
            payload,
            state,
            fmt: FlatUnprotected { unprotected },
        })
    }
}

impl<P, S, U> Serialize for Token<P, S, FlatUnprotected<U>>
where
    S: HasSignature,
    <S as MaybeSigned>::Header: Serialize,
    <S as MaybeSigned>::HeaderState: HeaderState,
    U: Serialize + DeserializeOwned,
    P: Serialize,
{
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: ser::Serializer,
    {
        let header = Base64JSON(self.state.header())
            .serialized_value()
            .map_err(ser::Error::custom)?;
        let signature = Base64Data(self.state.signature())
            .serialized_value()
            .map_err(ser::Error::custom)?;

        let flat = FlatToken {
            payload: &self.payload,
            protected: header,
            unprotected: &self.fmt.unprotected,
            signature,
        };

        flat.serialize(serializer)
    }
}

#[derive(Debug, Serialize)]
struct FlatSimpleToken<'t, P> {
    payload: &'t Payload<P>,
    protected: String,
    signature: String,
}

impl TokenFormat for Flat {
    fn render<S>(
        &self,
        writer: &mut impl Write,
        token: &Token<impl Serialize, S, Self>,
    ) -> Result<(), TokenFormattingError>
    where
        Self: Sized,
        S: HasSignature,
        <S as MaybeSigned>::Header: Serialize,
        <S as MaybeSigned>::HeaderState: HeaderState,
    {
        let header = Base64JSON(token.state.header()).serialized_value()?;
        let signature = Base64Data(token.state.signature()).serialized_value()?;

        let flat = FlatSimpleToken {
            payload: &token.payload,
            protected: header,
            signature,
        };

        let data = serde_json::to_string(&flat)?;
        write!(writer, "{}", data)?;

        Ok(())
    }

    fn parse<P, H>(data: Bytes) -> Result<Token<P, Unverified<H>, Self>, TokenParseError>
    where
        P: DeserializeOwned,
        H: DeserializeOwned,
        Self: Sized,
    {
        let value: serde_json::Value = serde_json::from_slice(&data)?;
        let serde_json::Value::Object(mut object): serde_json::Value = value else {
            return Err(TokenParseError::UnexpectedJSONValue("token", value));
        };
        parse_flat_common_values(&mut object)
    }
}

fn parse_flat_common_values<P, H>(
    object: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<Token<P, Unverified<H>, Flat>, TokenParseError>
where
    P: DeserializeOwned,
    H: DeserializeOwned,
{
    let header = {
        let protected = object
            .get("protected")
            .ok_or(TokenParseError::MissingHeader)?;
        let protected =
            Base64JSON::<Header<H, RenderedHeader>>::parse(protected.as_str().ok_or_else(
                || TokenParseError::UnexpectedJSONValue("header", protected.clone()),
            )?)?;
        let mut header = protected.data;
        header.state.raw = protected.bytes;
        header
    };

    let (payload, raw_payload) = {
        let value_payload = object
            .remove("payload")
            .ok_or(TokenParseError::MissingPayload)?;
        let b64_payload = value_payload.as_str().ok_or_else(|| {
            TokenParseError::UnexpectedJSONValue("payload", value_payload.clone())
        })?;

        let payload: Payload<P> = Payload::parse(b64_payload)?;
        let raw_payload: Vec<u8> = b64_payload.as_bytes().into();
        (payload, raw_payload)
    };

    let signature = {
        let signature = object
            .remove("signature")
            .ok_or(TokenParseError::MissingSignature)?;
        let signature: Base64Data<SignatureBytes> =
            Base64Data::parse(signature.as_str().ok_or_else(|| {
                TokenParseError::UnexpectedJSONValue("signature", signature.clone())
            })?)?;
        signature
    };

    Ok(Token {
        payload,
        state: Unverified {
            header,
            signature,
            payload: raw_payload.into(),
        },
        fmt: Flat,
    })
}

impl<P, S> Serialize for Token<P, S, Flat>
where
    S: HasSignature,
    <S as MaybeSigned>::Header: Serialize,
    <S as MaybeSigned>::HeaderState: HeaderState,
    P: Serialize,
{
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: ser::Serializer,
    {
        let header = Base64JSON(self.state.header())
            .serialized_value()
            .map_err(ser::Error::custom)?;
        let signature = Base64Data(self.state.signature())
            .serialized_value()
            .map_err(ser::Error::custom)?;

        let flat = FlatSimpleToken {
            payload: &self.payload,
            protected: header,
            signature,
        };

        flat.serialize(serializer)
    }
}
