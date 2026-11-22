//! Shared key material for tests.
//!
//! Only compiled for tests. Every key type that is available under the enabled
//! features appears in [`private_keys`], along with the set of JWS algorithms
//! that key is expected to support.

// Without any key feature there are no keys to build, and some helpers go unused.
#![cfg_attr(
    not(any(feature = "hmac", feature = "rsa", feature = "ecdsa")),
    allow(dead_code)
)]

use signature::Keypair;

use crate::algorithms::AlgorithmIdentifier as Alg;

use super::{PrivateWebKey, PublicWebKey};

/// A JWS header (base64url) used when signing in tests.
#[cfg(any(feature = "hmac", feature = "rsa", feature = "ecdsa"))]
pub(crate) const HEADER: &str = "eyJhbGciOiJSUzI1NiJ9";

/// A JWS payload (base64url) used when signing in tests.
#[cfg(any(feature = "hmac", feature = "rsa", feature = "ecdsa"))]
pub(crate) const PAYLOAD: &str = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

/// Members of a JWK which only appear in private keys.
pub(crate) const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi"];

/// The JWK from RFC 7515, appendix A.1: an HMAC key.
///
/// The RFC wraps long values across lines. The fixture files hold the values
/// unwrapped, since JSON strings can't contain line breaks.
#[cfg(feature = "hmac")]
pub(crate) fn rfc7515_a1() -> serde_json::Value {
    serde_json::from_str(include_str!("../../tests/fixtures/rfc7515-a1.json")).unwrap()
}

/// The JWK from RFC 7515, appendix A.2: an RSA private key.
#[cfg(feature = "rsa")]
pub(crate) fn rfc7515_a2() -> serde_json::Value {
    serde_json::from_str(include_str!("../../tests/fixtures/rfc7515-a2.json")).unwrap()
}

/// The JWK from RFC 7515, appendix A.3: a P-256 private key.
#[cfg(feature = "p256")]
pub(crate) fn rfc7515_a3() -> serde_json::Value {
    serde_json::from_str(include_str!("../../tests/fixtures/rfc7515-a3.json")).unwrap()
}

/// A key, along with what we expect it to do.
#[derive(Debug, Clone)]
pub(crate) struct Fixture {
    /// Human readable name, for assertion messages.
    pub(crate) label: &'static str,

    /// The expected `kty` value.
    pub(crate) kty: &'static str,

    /// The key itself.
    pub(crate) key: PrivateWebKey,

    /// The algorithms this key is expected to support, given the enabled features.
    pub(crate) algorithms: Vec<Alg>,
}

impl Fixture {
    /// The public half of this fixture.
    pub(crate) fn public(&self) -> PublicWebKey {
        self.key.verifying_key()
    }

    /// Whether this fixture contains secret material even in its public form.
    pub(crate) fn is_symmetric(&self) -> bool {
        self.kty == "oct"
    }
}

#[cfg(feature = "hmac")]
pub(crate) fn hmac_key() -> crate::algorithms::hmac::HmacKey {
    crate::algorithms::hmac::HmacKey::from((0u8..64).map(|b| b.wrapping_mul(3)).collect::<Vec<_>>())
}

/// The RSA key from RFC 7515, Appendix A.2.
#[cfg(feature = "rsa")]
pub(crate) fn rsa_private() -> rsa::PrivateKey {
    use rsa::pkcs8::DecodePrivateKey;

    rsa::PrivateKey::from_pkcs8_pem(include_str!("../../examples/rfc7515a2.pem")).unwrap()
}

#[cfg(feature = "p256")]
pub(crate) fn ec_p256() -> ::ecdsa::SigningKey<p256::NistP256> {
    use ::ecdsa::elliptic_curve::common::Generate;
    ::ecdsa::SigningKey::<p256::NistP256>::try_generate_from_rng(&mut rand::rngs::SysRng).unwrap()
}

#[cfg(feature = "p384")]
pub(crate) fn ec_p384() -> ::ecdsa::SigningKey<p384::NistP384> {
    use ::ecdsa::elliptic_curve::common::Generate;
    ::ecdsa::SigningKey::<p384::NistP384>::try_generate_from_rng(&mut rand::rngs::SysRng).unwrap()
}

#[cfg(feature = "p521")]
pub(crate) fn ec_p521() -> ::ecdsa::SigningKey<p521::NistP521> {
    use ::ecdsa::elliptic_curve::common::Generate;
    ::ecdsa::SigningKey::<p521::NistP521>::try_generate_from_rng(&mut rand::rngs::SysRng).unwrap()
}

/// One private key of every type which is available with the enabled features.
#[allow(unused_mut, clippy::vec_init_then_push)]
pub(crate) fn private_keys() -> Vec<Fixture> {
    let mut keys = Vec::new();

    #[cfg(feature = "hmac")]
    keys.push(Fixture {
        label: "hmac",
        kty: "oct",
        key: hmac_key().into(),
        algorithms: vec![Alg::HS256, Alg::HS384, Alg::HS512],
    });

    #[cfg(feature = "rsa")]
    keys.push(Fixture {
        label: "rsa",
        kty: "RSA",
        key: rsa_private().into(),
        algorithms: vec![
            Alg::RS256,
            Alg::RS384,
            Alg::RS512,
            #[cfg(feature = "pss")]
            Alg::PS256,
            #[cfg(feature = "pss")]
            Alg::PS384,
            #[cfg(feature = "pss")]
            Alg::PS512,
        ],
    });

    #[cfg(feature = "p256")]
    keys.push(Fixture {
        label: "p256",
        kty: "EC",
        key: ec_p256().into(),
        algorithms: vec![Alg::ES256],
    });

    #[cfg(feature = "p384")]
    keys.push(Fixture {
        label: "p384",
        kty: "EC",
        key: ec_p384().into(),
        algorithms: vec![Alg::ES384],
    });

    #[cfg(feature = "p521")]
    keys.push(Fixture {
        label: "p521",
        kty: "EC",
        key: ec_p521().into(),
        algorithms: vec![Alg::ES512],
    });

    keys
}
