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

impl<T> AsRef<[u8]> for Base64Data<T>
where
    T: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
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

    pub(crate) fn serialized_bytes(&self) -> Result<Box<[u8]>, serde_json::Error> {
        let inner = serde_json::to_vec(&self.0)?;
        Ok(inner.into_boxed_slice())
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

    #[test]
    fn test_base64_data() {
        let data = Base64Data::from(vec![1, 2, 3, 4]);
        let serialized = serde_json::to_string(&data).unwrap();
        assert_eq!(serialized, r#""AQIDBA""#);
        let deserialized: Base64Data<Vec<u8>> = serde_json::from_str(&serialized).unwrap();
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
