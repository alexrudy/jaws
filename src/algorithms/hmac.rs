//! HMAC Signing algorithms for use with JWS
//!
//! Based on the [hmac](https://crates.io/crates/hmac) crate.

use std::convert::Infallible;

use base64ct::Encoding;
use digest::Mac;
use hmac::SimpleHmac;

use crate::key::KeyInfo;

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

impl KeyInfo for HmacKey {
    const KEY_TYPE: &'static str = "oct";

    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        vec![(
            "k".to_string(),
            serde_json::Value::String(base64ct::Base64UrlUnpadded::encode_string(&self.key)),
        )]
    }
}

/// The HMAC algorithm as used when signing a JWS.
///
/// This type exists to associate the original key value with the digest.
/// This is required for verification, and for the `jwk` field in the JWS header,
/// if that field is enabled.
#[derive(Debug, Clone)]
pub struct Hmac<D>
where
    D: digest::Digest + digest::core_api::BlockSizeUser,
{
    key: HmacKey,
    digest: hmac::SimpleHmac<D>,
}

impl<D> Hmac<D>
where
    D: digest::Digest + digest::core_api::BlockSizeUser,
    hmac::SimpleHmac<D>: Mac,
{
    /// Create a new HMAC digest wrapper with a given signing key.
    ///
    /// Signing keys are arbitrary bytes.
    pub fn new(key: HmacKey) -> Self {
        let digest = SimpleHmac::new_from_slice(key.as_ref()).expect("Valid key");
        Self { key, digest }
    }

    /// Reference to the HMAC key.
    pub fn key(&self) -> &HmacKey {
        &self.key
    }
}

impl super::Algorithm for Hmac<sha2::Sha256> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::HS256;
}

impl super::Algorithm for Hmac<sha2::Sha384> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::HS384;
}

impl super::Algorithm for Hmac<sha2::Sha512> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::HS512;
}

impl<D> super::SigningAlgorithm for Hmac<D>
where
    D: digest::Digest
        + digest::Reset
        + digest::core_api::BlockSizeUser
        + digest::FixedOutput
        + digest::core_api::CoreProxy
        + Clone,
    Hmac<D>: super::Algorithm,
{
    type Error = Infallible;
    type Signature = digest::Output<SimpleHmac<D>>;
    type Key = HmacKey;

    fn sign(&self, header: &str, payload: &str) -> Result<Self::Signature, Self::Error> {
        // Create a new, one-shot digest for this signature.
        let mut digest = self.digest.clone();
        digest.reset();
        let message = format!("{}.{}", header, payload);
        digest.update(message.as_bytes());
        Ok(digest.finalize().into_bytes())
    }

    fn key(&self) -> &Self::Key {
        &self.key
    }
}

#[cfg(test)]
mod test {
    use crate::algorithms::SigningAlgorithm;

    use super::*;

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

        let signature = algorithm.sign(&header, &payload).unwrap();

        let sig = base64ct::Base64UrlUnpadded::encode_string(signature.as_ref());

        assert_eq!(
            sig,
            strip_whitespace("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        );
    }
}
