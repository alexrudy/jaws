//! HMAC Signing algorithms for use with JWS
//!
//! Based on the [hmac](https://crates.io/crates/hmac) crate.

use std::{marker::PhantomData, ops::Deref};

use base64ct::Encoding;
use digest::Digest;
use hmac::SimpleHmac;
use signature::SignatureEncoding;

use crate::key::{JWKeyType, SerializeJWK};

/// A key used to seed an HMAC signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash, zeroize::Zeroize, zeroize::ZeroizeOnDrop, Default)]
pub struct HmacKey {
    key: Vec<u8>,
}

impl HmacKey {
    /// Create a new HMAC key with the given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            key: Vec::with_capacity(capacity),
        }
    }

    /// Length of the HMAC key.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.key.len()
    }

    /// Resize the HMAC key, filling the rest of the key with a given value.
    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.key.resize(new_len, value);
    }
}

impl<T> From<T> for HmacKey
where
    T: Into<Vec<u8>>,
{
    fn from(key: T) -> Self {
        Self { key: key.into() }
    }
}

impl AsMut<[u8]> for HmacKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.key
    }
}

impl AsRef<[u8]> for HmacKey {
    fn as_ref(&self) -> &[u8] {
        &self.key
    }
}

/// The HMAC algorithm as used when signing a JWS.
///
/// This type exists to associate the original key value with the digest.
/// This is required for verification, and for the `jwk` field in the JWS header,
/// if that field is enabled.
#[derive(Debug, Clone)]
pub struct Hmac<D> {
    key: HmacKey,
    _digest: PhantomData<D>,
}

impl<D> Hmac<D> {
    /// Create a new HMAC digest wrapper with a given signing key.
    ///
    /// Signing keys are arbitrary bytes.
    pub fn new(key: HmacKey) -> Self {
        Self {
            key,
            _digest: PhantomData,
        }
    }

    /// Reference to the HMAC key.
    pub fn key(&self) -> &HmacKey {
        &self.key
    }
}

impl<D> JWKeyType for Hmac<D> {
    const KEY_TYPE: &'static str = "oct";
}

impl<D> SerializeJWK for Hmac<D> {
    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        vec![(
            "k".to_string(),
            serde_json::Value::String(base64ct::Base64UrlUnpadded::encode_string(&self.key.key)),
        )]
    }
}

/// A signature produced by an HMAC algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DigestSignature<D>(digest::Output<SimpleHmac<D>>)
where
    D: Digest + digest::core_api::BlockSizeUser;

impl<D> TryFrom<&[u8]> for DigestSignature<D>
where
    D: Digest + digest::core_api::BlockSizeUser,
{
    type Error = signature::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(
            digest::Output::<SimpleHmac<D>>::from_slice(value).clone(),
        ))
    }
}

impl<D> TryFrom<DigestSignature<D>> for Box<[u8]>
where
    D: Digest + digest::core_api::BlockSizeUser,
{
    type Error = signature::Error;

    fn try_from(value: DigestSignature<D>) -> Result<Self, Self::Error> {
        Ok(value.0.deref().into())
    }
}

impl<D> SignatureEncoding for DigestSignature<D>
where
    D: Digest + digest::core_api::BlockSizeUser + Clone,
{
    type Repr = Box<[u8]>;
}

macro_rules! hmac_algorithm {
    ($alg:ident, $digest:ty) => {
        impl crate::algorithms::JoseAlgorithm for Hmac<$digest> {
            const IDENTIFIER: crate::algorithms::AlgorithmIdentifier =
                crate::algorithms::AlgorithmIdentifier::$alg;
            type Signature = DigestSignature<$digest>;
        }

        impl crate::algorithms::JoseDigestAlgorithm for Hmac<$digest> {
            type Digest = $digest;
        }
    };
}

hmac_algorithm!(HS256, sha2::Sha256);
hmac_algorithm!(HS384, sha2::Sha384);
hmac_algorithm!(HS512, sha2::Sha512);

#[cfg(test)]
mod test {

    use super::*;
    use crate::algorithms::TokenSigner;

    use base64ct::Encoding;
    use serde_json::json;
    use sha2::Sha256;

    fn strip_whitespace(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    #[test]
    fn rfc7515_example_a1_signature() {
        let pkey = &json!({
            "kty":"oct",
            "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75
                aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
        }
        );

        let key_data = strip_whitespace(pkey["k"].as_str().unwrap());

        let decoded_len = 3 * key_data.len() / 4;

        let mut key = HmacKey::with_capacity(decoded_len);
        key.resize(decoded_len, 0);

        base64ct::Base64UrlUnpadded::decode(&key_data, key.as_mut()).unwrap();

        let payload = strip_whitespace(
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
        cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
        );

        let header = strip_whitespace("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");

        let algorithm: Hmac<Sha256> = Hmac::new(key);

        // let signature = algorithm.sign_token(&header, &payload);

        // let sig = base64ct::Base64UrlUnpadded::encode_string(signature.to_bytes().as_ref());

        // assert_eq!(
        //     sig,
        //     strip_whitespace("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        // );
    }
}
