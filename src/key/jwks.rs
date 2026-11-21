//! JSON Web Key Set

use std::ops::Deref;

use serde::{Deserialize, Serialize};

use super::Identified;

/// A set of JSON Web Keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet<K> {
    keys: Vec<Identified<K>>,
}

impl<K> JwkSet<K> {
    /// Returns the key with the given ID, if one exists.
    pub fn get(&self, id: &str) -> Option<&K> {
        self.keys
            .iter()
            .find(|k| k.id.as_deref() == Some(id))
            .map(|k| &k.key)
    }
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

#[cfg(all(test, any(feature = "hmac", feature = "rsa", feature = "ecdsa")))]
mod roundtrip_tests {
    use super::*;

    use crate::key::fixtures::private_keys;
    use crate::key::{Identified, PrivateWebKey, PublicWebKey, SerializeJWK, VerifyingWebKey};

    use serde_json::{json, Value};

    fn identified<K>(key: K, id: &str) -> Identified<K> {
        Identified {
            key,
            id: Some(id.to_owned()),
        }
    }

    fn count(haystack: &str, member: &str) -> usize {
        haystack.matches(&format!("\"{member}\"")).count()
    }

    #[test]
    fn public_key_set_roundtrip() {
        let fixtures = private_keys();
        let set: JwkSet<PublicWebKey> = fixtures
            .iter()
            .map(|f| identified(f.public(), f.label))
            .collect();
        assert_eq!(set.len(), fixtures.len());

        let rendered = serde_json::to_string(&set).unwrap();
        let value: Value = serde_json::from_str(&rendered).unwrap();
        let entries = value["keys"].as_array().unwrap();
        assert_eq!(entries.len(), fixtures.len());
        for (entry, f) in entries.iter().zip(&fixtures) {
            assert_eq!(entry["kid"], f.label);
            assert_eq!(entry["kty"], f.kty);
        }
        assert_eq!(count(&rendered, "kty"), fixtures.len(), "{rendered}");
        assert_eq!(count(&rendered, "kid"), fixtures.len(), "{rendered}");

        let back: JwkSet<PublicWebKey> = serde_json::from_str(&rendered).unwrap();
        assert_eq!(back.len(), set.len());

        for f in &fixtures {
            let found = back
                .get(f.label)
                .unwrap_or_else(|| panic!("{} not found", f.label));
            assert_eq!(found.parameters(), f.public().parameters(), "{}", f.label);
        }
    }

    #[test]
    fn private_key_set_roundtrip() {
        let fixtures = private_keys();
        let set: JwkSet<PrivateWebKey> = fixtures
            .iter()
            .map(|f| identified(f.key.clone(), f.label))
            .collect();

        let rendered = serde_json::to_string(&set).unwrap();
        assert_eq!(count(&rendered, "kty"), fixtures.len(), "{rendered}");

        let back: JwkSet<PrivateWebKey> = serde_json::from_str(&rendered).unwrap();
        assert_eq!(back.len(), set.len());

        for f in &fixtures {
            let found = back
                .get(f.label)
                .unwrap_or_else(|| panic!("{} not found", f.label));
            assert_eq!(found.parameters(), f.key.parameters(), "{}", f.label);
        }
    }

    #[test]
    fn verifying_key_set_roundtrip() {
        // One verifying key per algorithm, so that each variant is covered.
        let mut ids = Vec::new();
        let mut keys = Vec::new();
        for f in private_keys() {
            for &alg in &f.algorithms {
                ids.push(format!("{}-{alg:?}", f.label));
                keys.push(f.public().into_algorithm(alg).unwrap());
            }
        }

        let set: JwkSet<VerifyingWebKey> = keys
            .iter()
            .zip(&ids)
            .map(|(key, id)| identified(key.clone(), id))
            .collect();

        let rendered = serde_json::to_string(&set).unwrap();
        let back: JwkSet<VerifyingWebKey> = serde_json::from_str(&rendered).unwrap();
        assert_eq!(back.len(), keys.len());

        for (key, id) in keys.iter().zip(&ids) {
            let found = back.get(id).unwrap_or_else(|| panic!("{id} not found"));
            assert_eq!(found.parameters(), key.parameters(), "{id}");
        }
    }

    #[test]
    fn keys_without_an_id() {
        let fixtures = private_keys();
        let set: JwkSet<PublicWebKey> = fixtures
            .iter()
            .map(|f| Identified {
                key: f.public(),
                id: None,
            })
            .collect();

        let rendered = serde_json::to_string(&set).unwrap();
        assert_eq!(count(&rendered, "kid"), 0, "{rendered}");

        let back: JwkSet<PublicWebKey> = serde_json::from_str(&rendered).unwrap();
        assert_eq!(back.len(), fixtures.len());
        assert!(back.iter().all(|k| k.id.is_none()));
        assert!(back.get("anything").is_none());
    }

    #[test]
    fn key_set_preserves_order() {
        let fixtures = private_keys();
        let mut set: Vec<_> = fixtures
            .iter()
            .map(|f| identified(f.public(), f.label))
            .collect();
        set.reverse();
        let set = JwkSet::from(set);

        let back: JwkSet<PublicWebKey> =
            serde_json::from_str(&serde_json::to_string(&set).unwrap()).unwrap();

        let ids: Vec<_> = back.iter().map(|k| k.id.clone().unwrap()).collect();
        let expected: Vec<_> = fixtures.iter().rev().map(|f| f.label.to_owned()).collect();
        assert_eq!(ids, expected);
    }

    #[test]
    fn get_finds_the_first_key_with_an_id() {
        let fixtures = private_keys();
        let Some(first) = fixtures.first() else {
            return;
        };

        let set: JwkSet<PublicWebKey> = fixtures
            .iter()
            .map(|f| identified(f.public(), "same"))
            .collect();

        let found = set.get("same").unwrap();
        assert_eq!(found.parameters(), first.public().parameters());
    }

    #[test]
    fn empty_key_set() {
        let set: JwkSet<PublicWebKey> = serde_json::from_value(json!({"keys": []})).unwrap();
        assert!(set.is_empty());
        assert!(set.get("anything").is_none());

        assert_eq!(serde_json::to_value(&set).unwrap(), json!({"keys": []}));
    }

    #[test]
    fn key_set_requires_keys() {
        assert!(serde_json::from_value::<JwkSet<PublicWebKey>>(json!({})).is_err());
        assert!(serde_json::from_value::<JwkSet<PublicWebKey>>(json!({"keys": 1})).is_err());
        assert!(serde_json::from_value::<JwkSet<PublicWebKey>>(json!([])).is_err());
    }

    #[test]
    fn key_set_rejects_malformed_keys() {
        assert!(
            serde_json::from_value::<JwkSet<PublicWebKey>>(json!({"keys": [{"kid": "x"}]}))
                .is_err()
        );
        assert!(serde_json::from_value::<JwkSet<PublicWebKey>>(
            json!({"keys": [{"kty": "banana", "kid": "x"}]})
        )
        .is_err());
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
