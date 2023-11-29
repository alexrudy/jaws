use serde::Serialize;
use serde_json::json;
use signature::Error as SignatureError;

use crate::key::BuildFromKey;

/// A builder for the registered JOSE header fields for using JWTs,
/// when those fields are derived from the signing key.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DeriveFromKey<Value> {
    /// Omit this value from the rendered JOSE header.
    #[default]
    Omit,

    /// Derive this value from the signing key used to sign the token.
    Derived,

    /// Provide an explicit value for this field.
    Explicit(Value),
}

impl<Value> DeriveFromKey<Value> {
    /// Set this field to be omitteded from the rendered JOSE header.
    pub fn omit(&mut self) {
        *self = Self::Omit;
    }

    /// Set this field to be derived from the signing key.
    pub fn derived(&mut self) {
        *self = Self::Derived;
    }

    /// Set this field to be set explicitly, with a given JSON value.
    pub fn explicit(&mut self, value: Value) {
        *self = Self::Explicit(value);
    }
}

impl<Value> DeriveFromKey<Value>
where
    Value: Serialize,
{
    pub(super) fn parameter(
        &self,
        key: &str,
    ) -> Result<Option<serde_json::Value>, serde_json::Error> {
        match self {
            DeriveFromKey::Omit => Ok(None),
            DeriveFromKey::Derived => Ok(Some(json!(format!("<{key}>")))),
            DeriveFromKey::Explicit(value) => Ok(Some(serde_json::to_value(value)?)),
        }
    }
}

impl<Value> DeriveFromKey<Value> {
    pub(super) fn render<K>(self, key: &K) -> Result<Option<Value>, SignatureError>
    where
        Value: BuildFromKey<K>,
        K: ?Sized,
    {
        match self {
            DeriveFromKey::Omit => Ok(None),
            DeriveFromKey::Derived => Ok(Some(
                Value::derive_from_key(key).map_err(SignatureError::from_source)?,
            )),
            DeriveFromKey::Explicit(value) => Ok(Some(value)),
        }
    }
}
