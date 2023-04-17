//! Base64 Data tools, which interact well with serde and are useful
//! for building data structures for JWTs.

#[cfg(feature = "fmt")]
use std::fmt::Write;

use std::marker::PhantomData;

use base64ct::Encoding;
use serde::{de, ser, Serialize};

#[cfg(feature = "fmt")]
use super::fmt::{self, IndentWriter};

/// Wrapper type to indicate that the inner type should be serialized
/// as bytes with a Base64 URL-safe encoding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Base64Data<T>(pub T);

impl<T> Base64Data<T>
where
    T: AsRef<[u8]>,
{
    pub(crate) fn serialized_value(&self) -> Result<String, serde_json::Error> {
        Ok(base64ct::Base64UrlUnpadded::encode_string(self.0.as_ref()))
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

struct Base64Visitor<T>(PhantomData<T>);

impl<'de, T> de::Visitor<'de> for Base64Visitor<T>
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
        deserializer.deserialize_str(Base64Visitor(PhantomData))
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
/// as JSON and then Base64 URL-safe encoded and serialized as a string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Base64JSON<T>(pub T);

impl<T> Base64JSON<T>
where
    T: Serialize,
{
    pub(crate) fn serialized_value(&self) -> Result<String, serde_json::Error> {
        let inner = serde_json::to_vec(&self.0)?;
        Ok(base64ct::Base64UrlUnpadded::encode_string(&inner))
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
