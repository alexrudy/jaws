//! JSON Web Key Set

use std::{borrow::Cow, marker::PhantomData, ops::Deref};

use serde::{Deserialize, Serialize};

use crate::{
    algorithms::AlgorithmIdentifier,
    token::{Signed, TokenFormat, TokenVerifyingError, TokenVerifyingErrorKind, Unverified},
    Token,
};

use super::{Identified, IntoVerifyingKey, Restricted, UnsupportedAlgorithmError};

/// Error when verifying a token using a JWK set.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[error("JWK set verification error: {kind}")]
pub struct JWKSetVerifyError<P, H, F>
where
    F: TokenFormat,
{
    /// The token that failed verification.
    pub token: Token<P, Unverified<H>, F>,

    /// The kind of error that occurred.
    pub kind: JWKSetVerifyErrorKind,
}

impl<P, H, F> JWKSetVerifyError<P, H, F>
where
    F: TokenFormat,
{
    /// Creates a new `JWKSetVerifyError` with the given token and kind.
    pub fn new(token: Token<P, Unverified<H>, F>, kind: JWKSetVerifyErrorKind) -> Self {
        Self { token, kind }
    }
}

/// The kind of error that occurred when verifying a token using a JWK set.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JWKSetVerifyErrorKind {
    /// The key used to verify the token was not found in the JWK set.
    #[error("missing key in JWKS: {0}")]
    MissingKey(String),

    /// The signature failed to verify.
    #[error("verification failed: {0}")]
    Verify(#[from] signature::Error),

    /// The algorithm expected by the key does not match the actual algorithm
    /// used to originally sign the token.
    #[error("algorithm mismatch: expected {expected:?}, got {actual:?}")]
    AlgorithmMismatch {
        /// The algorithm expected by the key.
        expected: AlgorithmIdentifier,

        /// The actual algorithm used to sign the token.
        actual: AlgorithmIdentifier,
    },

    /// The algorithm used to sign the token is not supported.
    #[error(transparent)]
    UnsupportedAlgorithm(#[from] UnsupportedAlgorithmError),

    /// No key was identified in the JWK set.
    #[error("no key identified")]
    NoKeyIdentified,

    /// No key was able to verify the token's signature.
    #[error("no key validated")]
    NoKeyValidated,
}

impl From<TokenVerifyingErrorKind> for JWKSetVerifyErrorKind {
    fn from(value: TokenVerifyingErrorKind) -> Self {
        match value {
            TokenVerifyingErrorKind::Verify(err) => Self::Verify(err),
            TokenVerifyingErrorKind::Algorithm { expected, actual } => {
                Self::AlgorithmMismatch { expected, actual }
            }
        }
    }
}

/// A set of JSON Web Keys.
///
/// This type is a wrapper around a [`Vec`] of [`Identified`] keys.
/// When deserialized, keys that fail to deserialize are skipped,
/// as specified by RFC 7517.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JwkSet<K> {
    /// The keys in the set.
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

    /// Applies [`Restricted`] to each key in the set using the given function, returning a new [`JwkSet`] of [`Restricted`] keys.
    pub fn restrict<F: Fn(K) -> Restricted<K>>(self, func: F) -> JwkSet<Restricted<K>> {
        JwkSet {
            keys: self
                .keys
                .into_iter()
                .map(|k| Identified {
                    key: func(k.key),
                    id: k.id,
                })
                .collect(),
        }
    }
}

/// Trait for verifying JWTs using a JWK set.
pub trait VerifyJWKSet<K>
where
    K: IntoVerifyingKey + Clone,
{
    /// Verify the token using any key in the set, trying to guess the key if no key is identified.
    ///
    /// If a key is identified, it is used to verify the token. If no key is identified, the token is guessed using [`Self::verify_token_guess`].
    fn verify_token_any<P, H, F>(
        &self,
        token: Token<P, Unverified<H>, F>,
    ) -> Result<Token<P, Signed<H, <K as IntoVerifyingKey>::Key>, F>, JWKSetVerifyError<P, H, F>>
    where
        F: TokenFormat + 'static;

    /// Verify the token using any key in the set, returning the verified token if successful.
    ///
    /// This is inherently less secure than [`Self::verify_token`], as it does not require a key to be identified.
    fn verify_token_guess<P, H, F>(
        &self,
        token: Token<P, Unverified<H>, F>,
    ) -> Result<Token<P, Signed<H, <K as IntoVerifyingKey>::Key>, F>, JWKSetVerifyError<P, H, F>>
    where
        F: TokenFormat + 'static;

    /// Verify the token using the identified key in the set, returning the verified token if successful.
    fn verify_token<P, H, F>(
        &self,
        token: Token<P, Unverified<H>, F>,
    ) -> Result<Token<P, Signed<H, <K as IntoVerifyingKey>::Key>, F>, JWKSetVerifyError<P, H, F>>
    where
        F: TokenFormat + 'static;
}

impl<K> VerifyJWKSet<K> for JwkSet<K>
where
    K: IntoVerifyingKey + Clone,
{
    fn verify_token_any<P, H, F>(
        &self,
        token: Token<P, Unverified<H>, F>,
    ) -> Result<Token<P, Signed<H, <K as IntoVerifyingKey>::Key>, F>, JWKSetVerifyError<P, H, F>>
    where
        F: TokenFormat + 'static,
    {
        match self.verify_token(token) {
            Ok(verified) => Ok(verified),
            Err(JWKSetVerifyError { token, kind })
                if matches!(kind, JWKSetVerifyErrorKind::NoKeyIdentified) =>
            {
                self.verify_token_guess(token)
            }
            Err(err) => Err(err),
        }
    }

    fn verify_token_guess<P, H, F>(
        &self,
        mut token: Token<P, Unverified<H>, F>,
    ) -> Result<Token<P, Signed<H, <K as IntoVerifyingKey>::Key>, F>, JWKSetVerifyError<P, H, F>>
    where
        F: TokenFormat + 'static,
    {
        let alg = *token.header().algorithm();
        for key in &self.keys {
            if !key.key.supports_algorithm(alg) {
                continue;
            }
            if let Ok(verifier) = key.key.clone().into_verifying_key(alg) {
                token = match token.verify(&verifier) {
                    Ok(verified) => return Ok(verified),
                    Err(TokenVerifyingError { token, kind }) => {
                        tracing::trace!(kid=%key.id.as_deref().unwrap_or_default(), %alg, "verify error: {kind:?}");
                        token
                    }
                };
            }
        }
        Err(JWKSetVerifyError {
            token,
            kind: JWKSetVerifyErrorKind::NoKeyValidated,
        })
    }

    fn verify_token<P, H, F>(
        &self,
        token: Token<P, Unverified<H>, F>,
    ) -> Result<Token<P, Signed<H, <K as IntoVerifyingKey>::Key>, F>, JWKSetVerifyError<P, H, F>>
    where
        F: TokenFormat + 'static,
    {
        if let Some(kid) = token.header().key_id() {
            let key = match self.get(kid) {
                Some(key) => key,
                None => {
                    let kid = kid.into();
                    return Err(JWKSetVerifyError::new(
                        token,
                        JWKSetVerifyErrorKind::MissingKey(kid),
                    ));
                }
            };

            let algorithm = token.header().algorithm();
            let key = match key.clone().into_verifying_key(*algorithm) {
                Ok(key) => key,
                Err(err) => {
                    return Err(JWKSetVerifyError::new(token, err.into()));
                }
            };

            return match token.verify(&key) {
                Ok(verified) => Ok(verified),
                Err(TokenVerifyingError { token, kind }) => {
                    Err(JWKSetVerifyError::new(token, kind.into()))
                }
            };
        }

        Err(JWKSetVerifyError::new(
            token,
            JWKSetVerifyErrorKind::NoKeyIdentified,
        ))
    }
}

impl<K> Default for JwkSet<K> {
    fn default() -> Self {
        Self { keys: Vec::new() }
    }
}

impl<'de, K> Deserialize<'de> for JwkSet<K>
where
    K: for<'k> Deserialize<'k>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        /// Unit type wrapper for deserializing a sequence of keys
        /// skipping keys that fail to deserialize.
        struct JWKSKeys<K>(Vec<Identified<K>>);

        impl<'de, K> Deserialize<'de> for JWKSKeys<K>
        where
            K: for<'k> Deserialize<'k>,
        {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                /// Visitor for deserializing a sequence of keys
                /// skipping keys that fail to deserialize.
                struct JWKSKeysVisitor<K>(PhantomData<K>);

                impl<'de, K> serde::de::Visitor<'de> for JWKSKeysVisitor<K>
                where
                    K: for<'k> Deserialize<'k>,
                {
                    type Value = JWKSKeys<K>;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str("a list of JWK keys")
                    }

                    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                    where
                        A: serde::de::SeqAccess<'de>,
                    {
                        let mut keys = Vec::new();
                        loop {
                            match seq.next_element() {
                                Ok(Some(key)) => keys.push(key),
                                Ok(None) => break,
                                Err(e) => {
                                    // Ignore unknown/undeserialiable keys according to RFC 7517
                                    tracing::warn!("Skipping failed key in JWKS: {}", e);
                                }
                            }
                        }
                        Ok(JWKSKeys(keys))
                    }
                }

                deserializer.deserialize_seq(JWKSKeysVisitor(PhantomData))
            }
        }

        /// Visit the {'keys':...} structure of a JWKS,
        /// using a [`JWKSKeysVisitor`] to deserialize the sequence of keys.
        struct JWKSVisitor<K>(PhantomData<K>);

        impl<'de, K> serde::de::Visitor<'de> for JWKSVisitor<K>
        where
            K: for<'k> Deserialize<'k>,
        {
            type Value = JwkSet<K>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a JWK set")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                while let Some(key) = map.next_key::<Cow<'de, str>>()? {
                    if key == "keys" {
                        let JWKSKeys(keys) = map.next_value()?;
                        return Ok(JwkSet { keys });
                    }
                }

                Err(serde::de::Error::custom("JWKS must contain a 'keys' field"))
            }
        }

        deserializer.deserialize_struct("JWKSet", &["keys"], JWKSVisitor(PhantomData))
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

impl<K> From<JwkSet<K>> for Vec<Identified<K>> {
    fn from(jwk_set: JwkSet<K>) -> Self {
        jwk_set.keys
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
                keys.push(f.public().into_verifying_key(alg).unwrap());
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
    fn key_set_skips_malformed_keys() {
        assert_eq!(
            serde_json::from_value::<JwkSet<PublicWebKey>>(json!({"keys": [{"kid": "x"}]}))
                .unwrap(),
            JwkSet::default()
        );
        assert_eq!(
            serde_json::from_value::<JwkSet<PublicWebKey>>(
                json!({"keys": [{"kty": "banana", "kid": "x"}]})
            )
            .unwrap(),
            JwkSet::default()
        );
    }
}

#[cfg(all(test, any(feature = "hmac", feature = "rsa", feature = "ecdsa")))]
mod verify_tests {
    use super::*;

    use crate::key::fixtures::{private_keys, Fixture};
    use crate::key::{IntoSigningKey, PublicWebKey};

    type Unverified = Token<(), crate::token::Unverified<()>>;

    /// Algorithms of a fixture which can be signed without an RNG.
    fn algorithms(f: &Fixture) -> Vec<AlgorithmIdentifier> {
        f.algorithms
            .iter()
            .copied()
            .filter(|a| {
                !matches!(
                    a,
                    AlgorithmIdentifier::PS256
                        | AlgorithmIdentifier::PS384
                        | AlgorithmIdentifier::PS512
                )
            })
            .collect()
    }

    fn keyset(fixtures: &[Fixture]) -> JwkSet<PublicWebKey> {
        fixtures
            .iter()
            .map(|f| Identified::unidentified(f.public()).with_id(f.label.to_string()))
            .collect()
    }

    fn token(f: &Fixture, alg: AlgorithmIdentifier, kid: Option<&str>) -> Unverified {
        let mut token = Token::compact((), ());
        if let Some(kid) = kid {
            *token.header_mut().key_id() = Some(kid.to_string());
        }
        let key = f.key.clone().into_signing_key(alg).unwrap();
        token.sign(&key).unwrap().unverify()
    }

    /// Runs `check` for every fixture / algorithm pair, along with a key set holding every fixture.
    fn for_each(check: impl Fn(&Fixture, AlgorithmIdentifier, &JwkSet<PublicWebKey>)) {
        let fixtures = private_keys();
        let set = keyset(&fixtures);
        for f in &fixtures {
            for alg in algorithms(f) {
                check(f, alg, &set);
            }
        }
    }

    #[test]
    fn verify_token_by_kid() {
        for_each(|f, alg, set| {
            let t = token(f, alg, Some(f.label));
            let verified = set
                .verify_token(t)
                .unwrap_or_else(|e| panic!("{} / {alg:?}: {e}", f.label));
            assert_eq!(*verified.header().algorithm(), alg);
        });
    }

    #[test]
    fn verify_token_missing_kid_in_set() {
        for_each(|f, alg, set| {
            let t = token(f, alg, Some("does-not-exist"));
            for result in [set.verify_token(t.clone()), set.verify_token_any(t)] {
                let err = result.err().expect("unknown kid must fail");
                assert!(
                    matches!(&err.kind, JWKSetVerifyErrorKind::MissingKey(k) if k == "does-not-exist"),
                    "{} / {alg:?}: got {:?}",
                    f.label,
                    err.kind
                );
            }
        });
    }

    #[test]
    fn verify_token_without_kid_is_not_identified() {
        for_each(|f, alg, set| {
            let t = token(f, alg, None);
            let err = set.verify_token(t).err().expect("no kid must fail");
            assert!(matches!(err.kind, JWKSetVerifyErrorKind::NoKeyIdentified));
            // The token is handed back to the caller.
            assert_eq!(*err.token.header().algorithm(), alg);
        });
    }

    #[test]
    fn verify_token_with_another_keys_kid_fails() {
        let fixtures = private_keys();
        if fixtures.len() < 2 {
            return;
        }
        let set = keyset(&fixtures);
        let signer = &fixtures[0];
        let other = &fixtures[1];

        for alg in algorithms(signer) {
            let t = token(signer, alg, Some(other.label));
            let err = set.verify_token(t).err().expect("wrong key must fail");
            assert!(
                matches!(
                    err.kind,
                    JWKSetVerifyErrorKind::UnsupportedAlgorithm(_)
                        | JWKSetVerifyErrorKind::Verify(_)
                ),
                "{alg:?}: got {:?}",
                err.kind
            );
        }
    }

    #[test]
    fn verify_token_guess_finds_key() {
        for_each(|f, alg, set| {
            let t = token(f, alg, None);
            assert!(set.verify_token_guess(t).is_ok(), "{} / {alg:?}", f.label);
        });
    }

    #[test]
    fn verify_token_any_falls_back_to_guess() {
        for_each(|f, alg, set| {
            let t = token(f, alg, None);
            assert!(set.verify_token_any(t).is_ok(), "{} / {alg:?}", f.label);
        });
    }

    #[test]
    fn verify_token_any_uses_kid_when_present() {
        for_each(|f, alg, set| {
            let t = token(f, alg, Some(f.label));
            assert!(set.verify_token_any(t).is_ok(), "{} / {alg:?}", f.label);
        });
    }

    #[test]
    fn verify_token_guess_without_matching_key() {
        let fixtures = private_keys();
        for (i, signer) in fixtures.iter().enumerate() {
            let rest: Vec<_> = private_keys()
                .into_iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, f)| f)
                .collect();
            let set = keyset(&rest);

            for alg in algorithms(signer) {
                let t = token(signer, alg, None);
                for result in [set.verify_token_guess(t.clone()), set.verify_token_any(t)] {
                    let err = result.err().expect("no matching key must fail");
                    assert!(
                        matches!(err.kind, JWKSetVerifyErrorKind::NoKeyValidated),
                        "{} / {alg:?}: got {:?}",
                        signer.label,
                        err.kind
                    );
                }
            }
        }
    }

    #[test]
    fn verify_empty_set() {
        let set: JwkSet<PublicWebKey> = JwkSet::default();
        let fixtures = private_keys();
        let f = &fixtures[0];
        let alg = algorithms(f)[0];

        let err = set.verify_token(token(f, alg, Some("a"))).err().unwrap();
        assert!(matches!(err.kind, JWKSetVerifyErrorKind::MissingKey(_)));

        let err = set.verify_token_guess(token(f, alg, None)).err().unwrap();
        assert!(matches!(err.kind, JWKSetVerifyErrorKind::NoKeyValidated));
    }

    #[test]
    fn restrict_preserves_ids() {
        let fixtures = private_keys();
        let set = keyset(&fixtures);
        let restricted = set.restrict(Restricted::all);

        assert_eq!(restricted.len(), fixtures.len());
        for (f, k) in fixtures.iter().zip(restricted.iter()) {
            assert_eq!(k.id(), Some(f.label));
            assert_eq!(
                k.key.allowed_algorithms,
                Restricted::all(()).allowed_algorithms
            );
        }
    }

    #[test]
    fn restricted_set_allows_listed_algorithms() {
        for_each(|f, alg, set| {
            let restricted = Restricted::all(set.clone());

            let by_kid = token(f, alg, Some(f.label));
            assert!(restricted.verify_token(by_kid.clone()).is_ok());
            assert!(restricted.verify_token_any(by_kid).is_ok());

            let guessed = token(f, alg, None);
            assert!(restricted.verify_token_guess(guessed).is_ok());
        });
    }

    #[test]
    fn restricted_set_rejects_unlisted_algorithms() {
        for_each(|f, alg, set| {
            let mut restricted = Restricted::all(set.clone());
            restricted.allowed_algorithms.retain(|&a| a != alg);

            let by_kid = token(f, alg, Some(f.label));
            let guessed = token(f, alg, None);
            let results = [
                restricted.verify_token(by_kid.clone()),
                restricted.verify_token_any(by_kid),
                restricted.verify_token_guess(guessed.clone()),
                restricted.verify_token_any(guessed),
            ];
            for result in results {
                let err = result.err().expect("unlisted algorithm must fail");
                assert!(
                    matches!(&err.kind, JWKSetVerifyErrorKind::UnsupportedAlgorithm(e) if e.0 == alg),
                    "{} / {alg:?}: got {:?}",
                    f.label,
                    err.kind
                );
            }
        });
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
