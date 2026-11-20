//! JSON Web Key Set

use std::ops::Deref;

use serde::{Deserialize, Serialize};

use super::Identified;

/// A set of JSON Web Keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet<K> {
    keys: Vec<Identified<K>>,
}

impl<K> FromIterator<Identified<K>> for JwkSet<K> {
    fn from_iter<I: IntoIterator<Item = Identified<K>>>(iter: I) -> Self {
        Self {
            keys: iter.into_iter().collect(),
        }
    }
}

impl<K> From<Vec<Identified<K>>> for JwkSet<K> {
    fn from(keys: Vec<Identified<K>>) -> Self {
        Self { keys }
    }
}

impl<K> Deref for JwkSet<K> {
    type Target = [Identified<K>];

    fn deref(&self) -> &Self::Target {
        &self.keys
    }
}

#[cfg(test)]
#[cfg(feature = "rsa")]
mod tests {
    use super::*;
    use crate::key::{PublicWebKey, VerifyingWebKey};

    #[test]
    fn github() {
        let source = include_str!("../../tests/github.json");
        let jwk_set: JwkSet<PublicWebKey> = serde_json::from_str(source).unwrap();
        assert_eq!(jwk_set.len(), 4);

        let jwk_verifiers: JwkSet<VerifyingWebKey> = serde_json::from_str(source).unwrap();
        assert_eq!(jwk_verifiers.len(), 4);
    }
}
