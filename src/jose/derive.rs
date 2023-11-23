use serde::{ser, Serialize};
use serde_json::json;

use crate::key::KeyDerivedBuilder;

/// A builder for the registered JOSE header fields for using JWTs,
/// when those fields are derived from the signing key.
#[derive(Debug, Clone, Default)]
pub enum KeyDerivation<Value> {
    /// Omit this value from the rendered JOSE header.
    #[default]
    Omit,

    /// Derive this value from the signing key used to sign the token.
    Derived,

    /// Provide an explicit value for this field.
    Explicit(Value),
}

impl<Value> KeyDerivation<Value> {
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

#[cfg(feature = "fmt")]
impl<Value> KeyDerivation<Value>
where
    Value: Serialize,
{
    pub(super) fn parameter(&self, key: &str) -> Option<serde_json::Value> {
        match self {
            KeyDerivation::Omit => None,
            KeyDerivation::Derived => Some(json!(format!("<{key}>"))),
            KeyDerivation::Explicit(value) => serde_json::to_value(value).ok(),
        }
    }
}

/// A builder for the registered JOSE header fields for using JWTs.
///
/// Some header values must be set explicitly, while others can
/// be derived from the signing key. This type helps to keep track
/// of that distinction, allowing a field to be marked as derived
/// from the signing key.
#[derive(Debug, Default)]
pub(super) enum DerivedKeyValue<Builder, Key>
where
    Builder: KeyDerivedBuilder<Key>,
{
    #[default]
    Omit,
    Derived(Key),
    Explicit(Builder::Value),
}

impl<Builder, Key> Clone for DerivedKeyValue<Builder, Key>
where
    Builder: KeyDerivedBuilder<Key>,
    <Builder as KeyDerivedBuilder<Key>>::Value: Clone,
    Key: Clone,
{
    fn clone(&self) -> Self {
        match self {
            Self::Omit => Self::Omit,
            Self::Derived(key) => Self::Derived(key.clone()),
            Self::Explicit(value) => Self::Explicit(value.clone()),
        }
    }
}

impl<Builder, Key> DerivedKeyValue<Builder, Key>
where
    Builder: KeyDerivedBuilder<Key>,
{
    pub(super) fn is_none(&self) -> bool {
        matches!(self, DerivedKeyValue::Omit)
    }

    pub(super) fn build(self) -> Option<Builder::Value> {
        match self {
            DerivedKeyValue::Omit => None,
            DerivedKeyValue::Derived(key) => Some(Builder::from(key).build()),
            DerivedKeyValue::Explicit(value) => Some(value),
        }
    }

    pub(super) fn derive(derivation: KeyDerivation<Builder::Value>, key: &Key) -> Self
    where
        Key: Clone,
    {
        match derivation {
            KeyDerivation::Omit => DerivedKeyValue::Omit,
            KeyDerivation::Derived => DerivedKeyValue::Derived(key.clone()),
            KeyDerivation::Explicit(value) => DerivedKeyValue::Explicit(value),
        }
    }
}

impl<Builder, Key> ser::Serialize for DerivedKeyValue<Builder, Key>
where
    Builder: KeyDerivedBuilder<Key>,
    <Builder as KeyDerivedBuilder<Key>>::Value: Serialize + Clone,
    Key: Clone,
{
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.clone().build().serialize(serializer)
    }
}

#[cfg(feature = "fmt")]
impl<Builder, Key> DerivedKeyValue<Builder, Key>
where
    Builder: KeyDerivedBuilder<Key>,
    <Builder as KeyDerivedBuilder<Key>>::Value: Serialize,
    Key: Clone,
{
    pub(super) fn parameter(&self) -> Option<serde_json::Value> {
        match self {
            DerivedKeyValue::Omit => None,
            DerivedKeyValue::Derived(key) => Some(
                serde_json::to_value(Builder::from(key.clone()).build())
                    .expect("failed to serialize derived key"),
            ),
            DerivedKeyValue::Explicit(value) => serde_json::to_value(value).ok(),
        }
    }
}

impl<Builder, Key> DerivedKeyValue<Builder, Key>
where
    Builder: KeyDerivedBuilder<Key>,
    <Builder as KeyDerivedBuilder<Key>>::Value: Serialize + Clone,
    Key: Clone,
{
    pub(super) fn value(&self) -> Option<Builder::Value> {
        match self {
            DerivedKeyValue::Omit => None,
            DerivedKeyValue::Derived(key) => Some(Builder::from(key.clone()).build()),
            DerivedKeyValue::Explicit(value) => Some(value.clone()),
        }
    }
}
