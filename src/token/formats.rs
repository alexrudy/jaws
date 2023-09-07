use std::fmt::Write;

use serde::{Deserialize, Serialize};

use super::{HasSignature, MaybeSigned};
use super::{Payload, Token};
use crate::base64data::{Base64Data, Base64JSON};

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

/// A token format that serializes the token as a single JSON object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flat<U> {
    unprotected: U,
}

impl<U> Flat<U> {
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
        <S as MaybeSigned>::HeaderState: Serialize;
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
        <S as MaybeSigned>::HeaderState: Serialize,
    {
        let header = Base64JSON(&token.state.header()).serialized_value()?;
        let payload = token.payload.serialized_value()?;
        let signature = Base64Data(token.state.signature()).serialized_value()?;
        write!(writer, "{}.{}.{}", header, payload, signature)?;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct FlatToken<'t, P, U> {
    payload: &'t Payload<P>,
    protected: String,
    unprotected: &'t U,
    signature: String,
}

impl<U> TokenFormat for Flat<U>
where
    U: Serialize,
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
        <S as MaybeSigned>::HeaderState: Serialize,
    {
        let header = Base64JSON(&token.state.header()).serialized_value()?;
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
}
