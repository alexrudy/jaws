//! Base64 Data tools, which interact well with serde and are useful
//! for building data structures for JWTs.

#[cfg(feature = "fmt")]
use std::fmt::Write;

use std::marker::PhantomData;

use base64ct::Encoding;
use bytes::Bytes;
use serde::{
    de::{self, DeserializeOwned},
    ser, Serialize,
};

#[cfg(feature = "fmt")]
use super::fmt::{self, IndentWriter};

/// Error type for decoding base64 data in wrappers.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    /// The data being decoded is not base64
    #[error(transparent)]
    Base64(#[from] base64ct::Error),

    /// The data being decoded is not valid JSON
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// The data being decoded is not valid for another reason.
    #[error("data is not valid: {0}")]
    InvalidData(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Wrapper type for types which implement AsRef<[u8]> to indicate that
/// they should serialize as bytes with a Base64 URL-safe encoding.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Base64Data<T>(pub T);

impl<T> Base64Data<T>
where
    T: AsRef<[u8]>,
{
    pub(crate) fn serialized_value(&self) -> Result<String, serde_json::Error> {
        Ok(base64ct::Base64UrlUnpadded::encode_string(self.0.as_ref()))
    }
}

impl<T> std::fmt::Debug for Base64Data<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Base64Data")
            .field(&self.serialized_value().unwrap())
            .finish()
    }
}

impl<T> From<T> for Base64Data<T> {
    fn from(value: T) -> Self {
        Base64Data(value)
    }
}

impl<T> ser::Serialize for Base64Data<T>
where
    T: AsRef<[u8]>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let target = self
            .serialized_value()
            .map_err(|err| unreachable!("serialization error: {}", err))?;
        serializer.serialize_str(&target)
    }
}

impl<T> AsRef<[u8]> for Base64Data<T>
where
    T: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

struct Base64DataVisitor<T>(PhantomData<T>);

impl<'de, T> de::Visitor<'de> for Base64DataVisitor<T>
where
    T: for<'a> TryFrom<&'a [u8]>,
{
    type Value = Base64Data<T>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("base64url encoded data")
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let data = base64ct::Base64UrlUnpadded::decode_vec(v)
            .map_err(|_| E::invalid_value(de::Unexpected::Str(v), &"invalid base64url encoding"))?;

        let realized = T::try_from(data.as_ref())
            .map_err(|_| E::invalid_value(de::Unexpected::Str(v), &"can't parse internal data"))?;
        Ok(Base64Data(realized))
    }
}

impl<'de, T> de::Deserialize<'de> for Base64Data<T>
where
    T: for<'a> TryFrom<&'a [u8]>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(Base64DataVisitor(PhantomData))
    }
}

#[cfg(feature = "fmt")]
impl<T> fmt::JWTFormat for Base64Data<T>
where
    T: AsRef<[u8]>,
{
    fn fmt<W: fmt::Write>(&self, f: &mut IndentWriter<'_, W>) -> fmt::Result {
        write!(
            f,
            "b64\"{}\"",
            base64ct::Base64UrlUnpadded::encode_string(self.0.as_ref())
        )
    }
}

/// Wrapper type to indicate that the inner type should be serialized
/// as bytes with a Base64 URL-safe encoding.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Base64Signature<T>(pub T);

impl<T> Base64Signature<T>
where
    T: signature::SignatureEncoding,
{
    pub(crate) fn serialized_value(&self) -> Result<String, serde_json::Error> {
        Ok(base64ct::Base64UrlUnpadded::encode_string(
            self.0.to_bytes().as_ref(),
        ))
    }
}

impl<T> std::fmt::Debug for Base64Signature<T>
where
    T: signature::SignatureEncoding,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Base64Signature")
            .field(&self.serialized_value().unwrap())
            .finish()
    }
}

impl<T> Base64Signature<T>
where
    T: TryFrom<Vec<u8>>,
    T::Error: std::error::Error + Send + Sync + 'static,
{
    pub(crate) fn parse(value: &str) -> Result<Self, DecodeError> {
        let data = base64ct::Base64UrlUnpadded::decode_vec(value)?;
        let data = T::try_from(data).map_err(|err| DecodeError::InvalidData(err.into()))?;
        Ok(Base64Signature(data))
    }
}

impl<T> From<T> for Base64Signature<T> {
    fn from(value: T) -> Self {
        Base64Signature(value)
    }
}

impl<T> ser::Serialize for Base64Signature<T>
where
    T: signature::SignatureEncoding,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let target = self
            .serialized_value()
            .map_err(|err| unreachable!("serialization error: {}", err))?;
        serializer.serialize_str(&target)
    }
}

impl<T> AsRef<[u8]> for Base64Signature<T>
where
    T: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

struct Base64SignatureVisitor<T>(PhantomData<T>);

impl<'de, T> de::Visitor<'de> for Base64SignatureVisitor<T>
where
    T: for<'a> TryFrom<&'a [u8]>,
{
    type Value = Base64Signature<T>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("base64url encoded data")
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let data = base64ct::Base64UrlUnpadded::decode_vec(v)
            .map_err(|_| E::invalid_value(de::Unexpected::Str(v), &"invalid base64url encoding"))?;

        let realized = T::try_from(data.as_ref())
            .map_err(|_| E::invalid_value(de::Unexpected::Str(v), &"can't parse internal data"))?;
        Ok(Base64Signature(realized))
    }
}

impl<'de, T> de::Deserialize<'de> for Base64Signature<T>
where
    T: for<'a> TryFrom<&'a [u8]>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(Base64SignatureVisitor(PhantomData))
    }
}

#[cfg(feature = "fmt")]
impl<T> fmt::JWTFormat for Base64Signature<T>
where
    T: AsRef<[u8]>,
{
    fn fmt<W: fmt::Write>(&self, f: &mut IndentWriter<'_, W>) -> fmt::Result {
        write!(
            f,
            "b64\"{}\"",
            base64ct::Base64UrlUnpadded::encode_string(self.0.as_ref())
        )
    }
}

/// Wrapper type to indicate that the inner type should be serialized
/// as JSON and then Base64 URL-safe encoded and serialized as a string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Base64JSON<T>(pub T);

impl<T> Base64JSON<T> {
    /// Create a new Base64JSON wrapper.
    pub fn new(value: T) -> Self {
        Base64JSON(value)
    }

    /// Consume the wrapper and return the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Base64JSON<T>
where
    T: Serialize,
{
    pub(crate) fn serialized_value(&self) -> Result<String, serde_json::Error> {
        let inner = serde_json::to_vec(&self.0)?;
        Ok(base64ct::Base64UrlUnpadded::encode_string(&inner))
    }

    pub(crate) fn serialized_bytes(&self) -> Result<Bytes, serde_json::Error> {
        self.serialized_value().map(Bytes::from)
    }
}

pub(crate) struct ParsedBase64JSON<T> {
    pub(crate) data: T,
    pub(crate) bytes: Bytes,
}

impl<T> Base64JSON<T>
where
    T: DeserializeOwned,
{
    pub(crate) fn parse(raw: &str) -> Result<ParsedBase64JSON<T>, DecodeError>
    where
        T: de::DeserializeOwned,
    {
        let data = base64ct::Base64UrlUnpadded::decode_vec(raw)?;
        let value = serde_json::from_slice(&data)?;
        Ok(ParsedBase64JSON {
            data: value,
            bytes: Bytes::from(raw.to_owned()),
        })
    }
}

impl<T> AsRef<T> for Base64JSON<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T> From<T> for Base64JSON<T> {
    fn from(value: T) -> Self {
        Base64JSON(value)
    }
}

#[cfg(feature = "fmt")]
impl<T> fmt::JWTFormat for Base64JSON<T>
where
    T: Serialize,
{
    fn fmt<W: fmt::Write>(&self, f: &mut IndentWriter<'_, W>) -> fmt::Result {
        write!(f, "base64url(")?;
        f.write_json(&self.0)?;
        f.write_str(")")
    }
}

struct Base64JSONVisitor<T>(PhantomData<T>);

impl<'de, T> de::Visitor<'de> for Base64JSONVisitor<T>
where
    T: de::DeserializeOwned,
{
    type Value = Base64JSON<T>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a base64url encoded json document")
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let data = base64ct::Base64UrlUnpadded::decode_vec(v)
            .map_err(|_| E::invalid_value(de::Unexpected::Str(v), &"invalid base64url encoding"))?;

        let data = serde_json::from_slice(&data)
            .map_err(|err| E::custom(format!("invalid JSON: {err}")))?;
        Ok(Base64JSON(data))
    }
}

impl<'de, T> de::Deserialize<'de> for Base64JSON<T>
where
    T: de::DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(Base64JSONVisitor(PhantomData))
    }
}

impl<T> ser::Serialize for Base64JSON<T>
where
    T: ser::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::Error;
        let inner = self
            .serialized_value()
            .map_err(|err| S::Error::custom(format!("Error producing inner JSON: {err}")))?;
        serializer.serialize_str(&inner)
    }
}

#[cfg(test)]
mod test {
    use serde_json::{json, Value};

    use super::*;
    use crate::algorithms::SignatureBytes;

    #[test]
    fn test_base64_data() {
        let data = Base64Data::from(vec![1, 2, 3, 4]);
        let serialized = serde_json::to_string(&data).unwrap();
        assert_eq!(serialized, r#""AQIDBA""#);
        let deserialized: Base64Data<Vec<u8>> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, data);
    }

    #[test]
    fn test_base64_signature() {
        let data = Base64Signature::from(SignatureBytes::from(vec![1, 2, 3, 4]));
        let serialized = serde_json::to_string(&data).unwrap();
        assert_eq!(serialized, r#""AQIDBA""#);
        let deserialized: Base64Signature<SignatureBytes> =
            serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, data);
    }

    #[test]
    fn test_base64_json() {
        let data = Base64JSON::from(json!({"foo": "bar"}));
        let serialized = serde_json::to_string(&data).unwrap();
        assert_eq!(serialized, r#""eyJmb28iOiJiYXIifQ""#);
        let deserialized: Base64JSON<Value> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, data);
    }
}
