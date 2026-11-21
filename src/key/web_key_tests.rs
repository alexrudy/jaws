//! Round-trip and JWK tests for the algorithm-independent key types:
//! [`PrivateWebKey`], [`PublicWebKey`], [`SigningWebKey`] and [`VerifyingWebKey`].
//!
//! Every test iterates over [`private_keys`], so each key type that is available
//! with the enabled features is covered by every test.

use serde_json::{json, Value};
use signature::{Keypair, SignatureEncoding};

use crate::algorithms::{
    AlgorithmIdentifier as Alg, DynJsonWebAlgorithm, TokenSigner, TokenVerifier, ALL_ALGORITHMS,
};
use crate::SignatureBytes;

use super::fixtures::{private_keys, HEADER, PAYLOAD, PRIVATE_MEMBERS};
use super::{
    DeserializeJWK, JsonWebKey, JsonWebKeyError, Parameters, PrivateWebKey, PublicWebKey,
    SerializeJWK, SigningWebKey, VerifyingWebKey,
};

fn count(haystack: &str, member: &str) -> usize {
    haystack.matches(&format!("\"{member}\"")).count()
}

fn alg_name(alg: Alg) -> Value {
    serde_json::to_value(alg).unwrap()
}

/// Sign the standard test header and payload with a signing key.
fn sign(key: &SigningWebKey, alg: Alg) -> SignatureBytes {
    #[cfg(feature = "pss")]
    if matches!(alg, Alg::PS256 | Alg::PS384 | Alg::PS512) {
        return crate::algorithms::RandomizedTokenSigner::<SignatureBytes>::try_sign_token(
            key,
            HEADER,
            PAYLOAD,
            &mut rand::rngs::SysRng,
        )
        .expect("randomized signing");
    }
    let _ = alg;

    TokenSigner::<SignatureBytes>::try_sign_token(key, HEADER, PAYLOAD).expect("signing")
}

/// Check that a verifier accepts a good signature, and rejects bad ones.
fn assert_verifies(label: &str, verifier: &impl TokenVerifier<SignatureBytes>, signature: &[u8]) {
    verifier
        .verify_token(HEADER.as_bytes(), PAYLOAD.as_bytes(), signature)
        .unwrap_or_else(|e| panic!("{label}: valid signature rejected: {e}"));

    assert!(
        verifier
            .verify_token(HEADER.as_bytes(), b"dGFtcGVyZWQ", signature)
            .is_err(),
        "{label}: tampered payload was accepted"
    );

    let mut tampered = signature.to_vec();
    tampered[0] ^= 0xff;
    assert!(
        verifier
            .verify_token(HEADER.as_bytes(), PAYLOAD.as_bytes(), &tampered)
            .is_err(),
        "{label}: tampered signature was accepted"
    );
}

// ---------------------------------------------------------------------------
// PrivateWebKey
// ---------------------------------------------------------------------------

#[test]
fn private_web_key_jwk_roundtrip() {
    for f in private_keys() {
        let jwk = JsonWebKey::build(&f.key);
        assert_eq!(jwk.key_type(), f.kty, "{}", f.label);
        assert!(
            jwk.parameters().get("kty").is_none(),
            "{}: kty is stored separately from the parameters",
            f.label
        );

        let from_jwk = PrivateWebKey::from_jwk(&jwk).expect(f.label);
        assert_eq!(from_jwk.parameters(), f.key.parameters(), "{}", f.label);

        let deserialized: PrivateWebKey = jwk.deserialize_key().expect(f.label);
        assert_eq!(deserialized.parameters(), f.key.parameters(), "{}", f.label);

        // Via the default `to_jwk`, too.
        let to_jwk = f.key.to_jwk().unwrap();
        let from_to_jwk = PrivateWebKey::from_jwk(&to_jwk).expect(f.label);
        assert_eq!(from_to_jwk.parameters(), f.key.parameters(), "{}", f.label);
    }
}

#[test]
fn private_web_key_serde_roundtrip() {
    for f in private_keys() {
        let rendered = serde_json::to_string(&f.key).unwrap();
        assert_eq!(count(&rendered, "kty"), 1, "{}: {rendered}", f.label);

        let value: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value["kty"], f.kty, "{}", f.label);

        let from_str: PrivateWebKey = serde_json::from_str(&rendered).expect(f.label);
        assert_eq!(from_str.parameters(), f.key.parameters(), "{}", f.label);

        // `from_value` hands serde owned strings, which exercises different paths
        // than borrowed `from_str`.
        let from_value: PrivateWebKey = serde_json::from_value(value).expect(f.label);
        assert_eq!(from_value.parameters(), f.key.parameters(), "{}", f.label);
    }
}

#[test]
fn private_web_key_parameters_include_kty() {
    for f in private_keys() {
        assert_eq!(
            f.key.parameters().get("kty"),
            Some(&json!(f.kty)),
            "{}",
            f.label
        );
    }
}

#[test]
fn private_web_key_exposes_private_members() {
    for f in private_keys() {
        let params = f.key.parameters();
        match f.kty {
            "oct" => assert!(params.get("k").is_some(), "{}", f.label),
            _ => assert!(params.get("d").is_some(), "{}: missing d", f.label),
        }
    }
}

#[test]
fn debug_output_never_contains_secrets() {
    for f in private_keys() {
        let params = f.key.parameters();
        let secrets: Vec<String> = ["k", "d", "p", "q", "dp", "dq", "qi"]
            .iter()
            .filter_map(|member| Some(params.get(member)?.as_str()?.to_owned()))
            .collect();
        assert!(!secrets.is_empty(), "{}: no secrets to look for", f.label);

        let mut outputs = vec![
            format!("{:?}", f.key),
            format!("{:#?}", f.key),
            format!("{:?}", f.public()),
            format!("{:?}", params),
            format!("{:#?}", JsonWebKey::build(&f.key)),
            format!("{:?}", f.key.to_jwk().unwrap()),
        ];

        for &alg in &f.algorithms {
            let signing = f.key.clone().into_algorithm(alg).unwrap();
            outputs.push(format!("{signing:?}"));
            outputs.push(format!("{:#?}", signing.verifying_key()));
            outputs.push(format!("{:?}", f.public().into_algorithm(alg).unwrap()));
            outputs.push(format!("{:?}", signing.parameters()));
        }

        for output in outputs {
            for secret in &secrets {
                assert!(
                    !output.contains(secret.as_str()),
                    "{}: Debug output contains a secret: {output}",
                    f.label
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PublicWebKey
// ---------------------------------------------------------------------------

#[test]
fn public_web_key_jwk_roundtrip() {
    for f in private_keys() {
        let public = f.public();

        let jwk = JsonWebKey::build(&public);
        assert_eq!(jwk.key_type(), f.kty, "{}", f.label);

        let from_jwk = PublicWebKey::from_jwk(&jwk).expect(f.label);
        assert_eq!(from_jwk.parameters(), public.parameters(), "{}", f.label);

        let deserialized: PublicWebKey = jwk.deserialize_key().expect(f.label);
        assert_eq!(
            deserialized.parameters(),
            public.parameters(),
            "{}",
            f.label
        );
    }
}

#[test]
fn public_web_key_serde_roundtrip() {
    for f in private_keys() {
        let public = f.public();

        let rendered = serde_json::to_string(&public).unwrap();
        assert_eq!(count(&rendered, "kty"), 1, "{}: {rendered}", f.label);

        let value: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value["kty"], f.kty, "{}", f.label);

        let from_str: PublicWebKey = serde_json::from_str(&rendered).expect(f.label);
        assert_eq!(from_str.parameters(), public.parameters(), "{}", f.label);

        let from_value: PublicWebKey = serde_json::from_value(value).expect(f.label);
        assert_eq!(from_value.parameters(), public.parameters(), "{}", f.label);
    }
}

#[test]
fn public_web_key_omits_private_members() {
    for f in private_keys() {
        let public = f.public();
        let rendered = serde_json::to_string(&public).unwrap();

        if f.is_symmetric() {
            // The "public" half of a symmetric key is the key itself.
            assert!(public.parameters().get("k").is_some(), "{}", f.label);
            continue;
        }

        for member in PRIVATE_MEMBERS {
            assert!(
                public.parameters().get(member).is_none(),
                "{}: public key parameters contain private member {member}",
                f.label
            );
            assert_eq!(
                count(&rendered, member),
                0,
                "{}: public key JSON contains private member {member}",
                f.label
            );
        }
    }
}

#[test]
fn public_web_key_parses_from_private_jwk() {
    // A private JWK carries all of the public members, so it can be read as a public key.
    for f in private_keys().into_iter().filter(|f| !f.is_symmetric()) {
        let rendered = serde_json::to_string(&f.key).unwrap();
        let public: PublicWebKey = serde_json::from_str(&rendered).expect(f.label);
        assert_eq!(public.parameters(), f.public().parameters(), "{}", f.label);
    }
}

// ---------------------------------------------------------------------------
// Rejecting bad input
// ---------------------------------------------------------------------------

#[test]
fn missing_kty_is_an_error() {
    assert!(matches!(
        PrivateWebKey::build(Parameters::new()),
        Err(JsonWebKeyError::MissingParameter("kty"))
    ));
    assert!(matches!(
        PublicWebKey::build(Parameters::new()),
        Err(JsonWebKeyError::MissingParameter("kty"))
    ));

    assert!(serde_json::from_value::<PrivateWebKey>(json!({"k": "AQ"})).is_err());
    assert!(serde_json::from_value::<PublicWebKey>(json!({"k": "AQ"})).is_err());
}

#[test]
fn unknown_kty_is_an_error() {
    let mut parameters = Parameters::new();
    parameters.insert("kty", "banana");

    assert!(matches!(
        PrivateWebKey::build(parameters.clone()),
        Err(JsonWebKeyError::UnsupportedKeyType(t)) if t == "banana"
    ));
    assert!(matches!(
        PublicWebKey::build(parameters),
        Err(JsonWebKeyError::UnsupportedKeyType(t)) if t == "banana"
    ));

    assert!(serde_json::from_value::<PrivateWebKey>(json!({"kty": "banana"})).is_err());
    assert!(serde_json::from_value::<PublicWebKey>(json!({"kty": "banana"})).is_err());
}

#[test]
fn mismatched_kty_is_rejected() {
    let keys = private_keys();

    for a in &keys {
        for b in keys.iter().filter(|b| b.kty != a.kty) {
            let label = format!("{} body with {} kty", a.label, b.label);

            let mut private = serde_json::to_value(&a.key).unwrap();
            private["kty"] = json!(b.kty);
            assert!(
                serde_json::from_value::<PrivateWebKey>(private.clone()).is_err(),
                "{label}: private key accepted"
            );
            let jwk: JsonWebKey = serde_json::from_value(private).unwrap();
            assert!(
                PrivateWebKey::from_jwk(&jwk).is_err(),
                "{label}: private jwk accepted"
            );

            let mut public = serde_json::to_value(a.public()).unwrap();
            public["kty"] = json!(b.kty);
            assert!(
                serde_json::from_value::<PublicWebKey>(public.clone()).is_err(),
                "{label}: public key accepted"
            );
            let jwk: JsonWebKey = serde_json::from_value(public).unwrap();
            assert!(
                PublicWebKey::from_jwk(&jwk).is_err(),
                "{label}: public jwk accepted"
            );
        }
    }
}

#[test]
fn mismatched_curve_is_rejected() {
    for f in private_keys().into_iter().filter(|f| f.kty == "EC") {
        for crv in ["P-256", "P-384", "P-521"] {
            let mut private = serde_json::to_value(&f.key).unwrap();
            if private["crv"] == crv {
                continue;
            }
            private["crv"] = json!(crv);
            assert!(
                serde_json::from_value::<PrivateWebKey>(private).is_err(),
                "{}: private key accepted as {crv}",
                f.label
            );

            let mut public = serde_json::to_value(f.public()).unwrap();
            public["crv"] = json!(crv);
            assert!(
                serde_json::from_value::<PublicWebKey>(public).is_err(),
                "{}: public key accepted as {crv}",
                f.label
            );
        }
    }
}

#[test]
fn missing_key_material_is_rejected() {
    for f in private_keys() {
        let required: &[&str] = match f.kty {
            "oct" => &["k"],
            "RSA" => &["n", "e", "d", "p", "q"],
            "EC" => &["crv", "x", "y", "d"],
            other => panic!("unexpected key type {other}"),
        };

        for member in required {
            let mut private = serde_json::to_value(&f.key).unwrap();
            private.as_object_mut().unwrap().remove(*member);
            assert!(
                serde_json::from_value::<PrivateWebKey>(private).is_err(),
                "{}: private key accepted without {member}",
                f.label
            );
        }

        // Public keys need everything except the private members.
        for member in required.iter().filter(|m| !PRIVATE_MEMBERS.contains(m)) {
            let mut public = serde_json::to_value(f.public()).unwrap();
            public.as_object_mut().unwrap().remove(*member);
            assert!(
                serde_json::from_value::<PublicWebKey>(public).is_err(),
                "{}: public key accepted without {member}",
                f.label
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Algorithm support
// ---------------------------------------------------------------------------

#[test]
fn supports_algorithm_matrix() {
    for f in private_keys() {
        let public = f.public();

        for &alg in ALL_ALGORITHMS {
            let expected = f.algorithms.contains(&alg);
            let label = format!("{} / {alg:?}", f.label);

            assert_eq!(
                f.key.supports_algorithm(alg),
                expected,
                "{label}: PrivateWebKey::supports_algorithm"
            );
            assert_eq!(
                public.supports_algorithm(alg),
                expected,
                "{label}: PublicWebKey::supports_algorithm"
            );

            // The "none" algorithm is handled separately: it needs no key.
            if alg == Alg::None {
                continue;
            }

            let signing = f.key.clone().into_algorithm(alg);
            let verifying = public.clone().into_algorithm(alg);

            if expected {
                let signing = signing.unwrap_or_else(|e| panic!("{label}: signing: {e}"));
                assert_eq!(signing.identifier(), alg, "{label}");

                let verifying = verifying.unwrap_or_else(|e| panic!("{label}: verifying: {e}"));
                assert_eq!(verifying.identifier(), alg, "{label}");
            } else {
                assert!(
                    matches!(&signing, Err(JsonWebKeyError::UnsupportedAlgorithm(a)) if *a == alg),
                    "{label}: signing key conversion should be unsupported, got {signing:?}"
                );
                assert!(
                    matches!(&verifying, Err(JsonWebKeyError::UnsupportedAlgorithm(a)) if *a == alg),
                    "{label}: verifying key conversion should be unsupported, got {verifying:?}"
                );
            }
        }
    }
}

#[test]
fn public_keys_never_become_none_verifiers() {
    for f in private_keys() {
        assert!(
            f.public().into_algorithm(Alg::None).is_err(),
            "{}: a public key must not convert to a verifier for `none`",
            f.label
        );
    }
}

// ---------------------------------------------------------------------------
// SigningWebKey / VerifyingWebKey
// ---------------------------------------------------------------------------

#[test]
fn signing_key_roundtrips_to_private_key() {
    for f in private_keys() {
        for &alg in &f.algorithms {
            let label = format!("{} / {alg:?}", f.label);
            let signing = f.key.clone().into_algorithm(alg).expect(&label);

            let private = PrivateWebKey::try_from(signing).expect(&label);
            assert_eq!(private.parameters(), f.key.parameters(), "{label}");
        }
    }
}

#[test]
fn signing_key_parameters_include_alg_and_kty() {
    for f in private_keys() {
        for &alg in &f.algorithms {
            let label = format!("{} / {alg:?}", f.label);
            let signing = f.key.clone().into_algorithm(alg).expect(&label);

            let params = signing.parameters();
            assert_eq!(params.get("alg"), Some(&alg_name(alg)), "{label}");
            assert_eq!(params.get("kty"), Some(&json!(f.kty)), "{label}");

            // The key material should be the same as the unrestricted key's.
            for (name, value) in f.key.parameters().iter() {
                assert_eq!(params.get(name), Some(value), "{label}: {name}");
            }
        }
    }
}

#[test]
fn signing_key_serializes_with_alg_and_kty() {
    for f in private_keys() {
        for &alg in &f.algorithms {
            let label = format!("{} / {alg:?}", f.label);
            let signing = f.key.clone().into_algorithm(alg).expect(&label);

            let rendered = serde_json::to_string(&signing).expect(&label);
            let value: Value = serde_json::from_str(&rendered).unwrap();

            assert_eq!(value["alg"], alg_name(alg), "{label}: {rendered}");
            assert_eq!(value["kty"], f.kty, "{label}: {rendered}");
            assert_eq!(count(&rendered, "kty"), 1, "{label}: {rendered}");
            assert_eq!(count(&rendered, "alg"), 1, "{label}: {rendered}");
        }
    }
}

#[test]
fn sign_and_verify_with_every_algorithm() {
    for f in private_keys() {
        let public = f.public();

        for &alg in &f.algorithms {
            let label = format!("{} / {alg:?}", f.label);

            let signing = f.key.clone().into_algorithm(alg).expect(&label);
            let signature = sign(&signing, alg);
            let signature = signature.to_bytes();
            let signature: &[u8] = signature.as_ref();

            // 1. The verifying half of the signing key.
            let verifying = signing.verifying_key();
            assert_eq!(verifying.identifier(), alg, "{label}");
            assert_verifies(&format!("{label}: verifying_key()"), &verifying, signature);

            // 2. A verifying key built from the public key.
            let from_public = public.clone().into_algorithm(alg).expect(&label);
            assert_verifies(&format!("{label}: from public"), &from_public, signature);

            // 3. A verifying key which has been through JSON.
            let rendered = serde_json::to_string(&from_public).expect(&label);
            let reparsed: VerifyingWebKey = serde_json::from_str(&rendered)
                .unwrap_or_else(|e| panic!("{label}: {e}: {rendered}"));
            assert_eq!(reparsed.identifier(), alg, "{label}");
            assert_verifies(&format!("{label}: reparsed"), &reparsed, signature);

            // 4. A verifying key which has been through a JWK.
            let jwk = JsonWebKey::build(&from_public);
            let from_jwk: VerifyingWebKey =
                serde_json::from_value(serde_json::to_value(&jwk).unwrap())
                    .unwrap_or_else(|e| panic!("{label}: from jwk: {e}"));
            assert_verifies(&format!("{label}: from jwk"), &from_jwk, signature);
        }
    }
}

#[test]
fn verifying_key_rejects_signature_from_another_key() {
    // Two independent sets of keys. Only the EC fixtures are random; the RSA
    // and HMAC fixtures are fixed, so they can't be compared against themselves.
    for (first, second) in private_keys().into_iter().zip(private_keys()) {
        if first.kty != "EC" {
            continue;
        }

        for &alg in &first.algorithms {
            let label = format!("{} / {alg:?}", first.label);
            let signing = first.key.clone().into_algorithm(alg).expect(&label);
            let signature = sign(&signing, alg);
            let signature = signature.to_bytes();
            let signature: &[u8] = signature.as_ref();

            let other = second.public().into_algorithm(alg).expect(&label);
            assert!(
                other
                    .verify_token(HEADER.as_bytes(), PAYLOAD.as_bytes(), signature)
                    .is_err(),
                "{label}: signature verified under a different key"
            );
        }
    }
}

#[test]
fn verifying_key_converts_to_public_key() {
    for f in private_keys() {
        let public = f.public();

        for &alg in &f.algorithms {
            let label = format!("{} / {alg:?}", f.label);
            let verifying = public.clone().into_algorithm(alg).expect(&label);

            let back = PublicWebKey::try_from(verifying).expect(&label);
            assert_eq!(back.parameters(), public.parameters(), "{label}");
        }
    }
}

#[test]
fn verifying_key_serde_has_alg_and_kty() {
    for f in private_keys() {
        for &alg in &f.algorithms {
            let label = format!("{} / {alg:?}", f.label);
            let verifying = f.public().into_algorithm(alg).expect(&label);

            let rendered = serde_json::to_string(&verifying).expect(&label);
            let value: Value = serde_json::from_str(&rendered).unwrap();

            assert_eq!(value["alg"], alg_name(alg), "{label}: {rendered}");
            assert_eq!(value["kty"], f.kty, "{label}: {rendered}");
            assert_eq!(count(&rendered, "kty"), 1, "{label}: {rendered}");
            assert_eq!(count(&rendered, "alg"), 1, "{label}: {rendered}");

            let back: VerifyingWebKey = serde_json::from_value(value).expect(&label);
            assert_eq!(back.parameters(), verifying.parameters(), "{label}");
        }
    }
}

#[test]
fn verifying_key_ignores_extra_jwk_members() {
    // Real-world JWKs carry members like `use`, `kid` and `key_ops`.
    for f in private_keys() {
        for &alg in &f.algorithms {
            let label = format!("{} / {alg:?}", f.label);
            let verifying = f.public().into_algorithm(alg).expect(&label);

            let mut value = serde_json::to_value(&verifying).unwrap();
            let object = value.as_object_mut().unwrap();
            object.insert("use".into(), json!("sig"));
            object.insert("kid".into(), json!("a-key-id"));
            object.insert("key_ops".into(), json!(["verify"]));

            let back: VerifyingWebKey = serde_json::from_value(value)
                .unwrap_or_else(|e| panic!("{label}: extra members rejected: {e}"));
            assert_eq!(back.identifier(), alg, "{label}");
        }
    }
}

#[test]
fn verifying_key_rejects_mismatched_alg() {
    let keys = private_keys();

    for f in &keys {
        let public = f.public();

        // Any algorithm the key does not support must be refused, whatever the
        // key material looks like.
        for &alg in ALL_ALGORITHMS
            .iter()
            .filter(|a| !f.algorithms.contains(a) && **a != Alg::None && **a != Alg::EdDSA)
        {
            // Only algorithms which are compiled in can be present in the enum.
            if !alg.available() {
                continue;
            }

            let label = format!("{} body with alg {alg:?}", f.label);

            let mut value = serde_json::to_value(&public).unwrap();
            value["alg"] = alg_name(alg);
            assert!(
                serde_json::from_value::<VerifyingWebKey>(value).is_err(),
                "{label}: accepted"
            );
        }
    }
}

#[test]
fn verifying_key_rejects_unknown_or_missing_alg() {
    for f in private_keys() {
        let mut unknown = serde_json::to_value(f.public()).unwrap();
        unknown["alg"] = json!("XX999");
        assert!(
            serde_json::from_value::<VerifyingWebKey>(unknown).is_err(),
            "{}: unknown alg accepted",
            f.label
        );

        // No `alg` at all: the tag is required.
        let missing = serde_json::to_value(f.public()).unwrap();
        assert!(
            serde_json::from_value::<VerifyingWebKey>(missing).is_err(),
            "{}: missing alg accepted",
            f.label
        );
    }
}

#[cfg(feature = "none")]
#[test]
fn none_verifying_key_serde() {
    let key: VerifyingWebKey = serde_json::from_value(json!({"alg": "none"})).unwrap();
    assert_eq!(key.identifier(), Alg::None);

    // Only the registered, lower case spelling is accepted.
    assert!(serde_json::from_value::<VerifyingWebKey>(json!({"alg": "None"})).is_err());
    assert!(serde_json::from_value::<VerifyingWebKey>(json!({"alg": "NONE"})).is_err());

    // `none` verifies only the empty signature.
    assert!(key
        .verify_token(HEADER.as_bytes(), PAYLOAD.as_bytes(), b"")
        .is_ok());
    assert!(key
        .verify_token(HEADER.as_bytes(), PAYLOAD.as_bytes(), b"forged")
        .is_err());
}
