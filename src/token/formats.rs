use std::fmt::Write;

use serde::{Deserialize, Serialize};

use super::{HasSignature, MaybeSigned};
use super::{Payload, Token};
use crate::base64data::{Base64Data, Base64JSON};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Compact;

impl Compact {
    pub fn new() -> Compact {
        Compact
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flat<U> {
    unprotected: U,
}

impl<U> Flat<U> {
    pub fn new(unprotected: U) -> Self {
        Self { unprotected }
    }
}

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

pub trait TokenFormat {
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
