//! HMAC Signing algorithms for use with JWS
//!
//! Based on the [hmac](https://crates.io/crates/hmac) crate.
//!
//! ## Usage
//!
//! Unlike the other algorithms, HMAC algorithms use special types provided
//! by the JOSE crate. HMAC is not really a "signature" algorithm in a strict sense,
//! as it does not use a private key. Instead, it uses a symmetric key, which is
//! shared between the signer and verifier.
//!
//! The [`HmacKey`] type is used to represent the key. This type is a wrapper around
//! a byte vector, and can be created from any type which can be converted into a
//! byte vector. The [`Hmac`] type is used to represent the algorithm, and is a wrapper
//! which combines the key with the digest algorithm.
//!
//! The [`Hmac`] type implements [`TokenSigner`][crate::algorithms::TokenSigner] and [`TokenVerifier`][crate::algorithms::TokenVerifier], and can be used
//! to sign and verify tokens. Signatures are represented by the [`DigestSignature`] type,
//! which is a wrapper around the [`digest::Output`] type from the [`digest`](https://crates.io/crates/digest)
//! crate, but which provides the appropriate signature encoding behavior.

use std::{collections::BTreeMap, marker::PhantomData, ops::Deref};

use base64ct::Encoding;
use digest::{Digest, Mac};
use hmac::SimpleHmac;
use signature::{Keypair, SignatureEncoding};

use crate::{
    key::{DeserializeJWK, JWKeyType, SerializeJWK},
    SignatureBytes,
};

use super::JsonWebAlgorithm;

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
#[derive(Debug)]
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

impl<D> Clone for Hmac<D> {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            _digest: PhantomData,
        }
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

impl<D> DeserializeJWK for Hmac<D> {
    fn build(
        parameters: BTreeMap<String, serde_json::Value>,
    ) -> Result<Self, crate::key::JsonWebKeyError> {
        let key_data = parameters
            .get("k")
            .ok_or(crate::key::JsonWebKeyError::MissingParameter("k"))?
            .as_str()
            .ok_or(crate::key::JsonWebKeyError::InvalidKey(
                "k",
                "k must be a str".into(),
            ))?;
        let decoded_len = 3 * key_data.len() / 4;

        let mut key = HmacKey::with_capacity(decoded_len);
        key.resize(decoded_len, 0);

        base64ct::Base64UrlUnpadded::decode(key_data, key.as_mut())
            .map_err(|err| crate::key::JsonWebKeyError::InvalidKey("k", err.into()))?;

        Ok(Self::new(key))
    }
}

impl<D> Keypair for Hmac<D> {
    type VerifyingKey = Hmac<D>;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.clone()
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
        impl crate::algorithms::JsonWebAlgorithm for Hmac<$digest> {
            const IDENTIFIER: crate::algorithms::AlgorithmIdentifier =
                crate::algorithms::AlgorithmIdentifier::$alg;
        }
    };
}

hmac_algorithm!(HS256, sha2::Sha256);
hmac_algorithm!(HS384, sha2::Sha384);
hmac_algorithm!(HS512, sha2::Sha512);

impl<D> super::TokenSigner<DigestSignature<D>> for Hmac<D>
where
    Hmac<D>: JsonWebAlgorithm,
    D: Digest + digest::core_api::BlockSizeUser + Clone,
{
    fn try_sign_token(
        &self,
        header: &str,
        payload: &str,
    ) -> Result<DigestSignature<D>, signature::Error> {
        let mut mac: SimpleHmac<D> =
            SimpleHmac::new_from_slice(self.key.as_ref()).expect("Valid key");
        mac.update(header.as_bytes());
        mac.update(b".");
        mac.update(payload.as_bytes());
        Ok(DigestSignature(mac.finalize().into_bytes()))
    }
}

impl<D> super::TokenSigner<SignatureBytes> for Hmac<D>
where
    Hmac<D>: JsonWebAlgorithm,
    D: Digest + digest::core_api::BlockSizeUser + Clone,
{
    fn try_sign_token(
        &self,
        header: &str,
        payload: &str,
    ) -> Result<SignatureBytes, signature::Error> {
        let signature = <Self as super::TokenSigner<DigestSignature<D>>>::try_sign_token(
            self, header, payload,
        )?;
        Ok(signature.to_bytes().as_ref().into())
    }
}

impl<D> super::TokenVerifier<DigestSignature<D>> for Hmac<D>
where
    Hmac<D>: JsonWebAlgorithm,
    D: Digest + digest::core_api::BlockSizeUser + Clone,
{
    fn verify_token(
        &self,
        header: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<DigestSignature<D>, signature::Error> {
        let mut mac: SimpleHmac<D> =
            SimpleHmac::new_from_slice(self.key.as_ref()).expect("Valid key");
        mac.update(header);
        mac.update(b".");
        mac.update(payload);
        mac.clone()
            .verify_slice(signature)
            .map_err(signature::Error::from_source)?;

        Ok(DigestSignature(mac.finalize().into_bytes()))
    }
}

impl<D> super::TokenVerifier<SignatureBytes> for Hmac<D>
where
    Hmac<D>: JsonWebAlgorithm,
    D: Digest + digest::core_api::BlockSizeUser + Clone,
{
    fn verify_token(
        &self,
        header: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<SignatureBytes, signature::Error> {
        let signature = <Self as super::TokenVerifier<DigestSignature<D>>>::verify_token(
            self, header, payload, signature,
        )?;
        Ok(signature.to_bytes().as_ref().into())
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::algorithms::TokenSigner;
    use crate::algorithms::TokenVerifier;

    use base64ct::Encoding;
    use serde_json::json;
    use sha2::Sha256;

    fn strip_whitespace(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    fn jwk() -> serde_json::Value {
        json!({
            "kty":"oct",
            "k":strip_whitespace("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75
                aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
        }
        )
    }

    #[test]
    fn rfc7515_example_a1_signature() {
        let pkey = &jwk();

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

        let signature: DigestSignature<_> = algorithm.sign_token(&header, &payload);

        let sig = base64ct::Base64UrlUnpadded::encode_string(signature.to_bytes().as_ref());

        assert_eq!(
            sig,
            strip_whitespace("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        );

        let _: SignatureBytes = algorithm
            .verify_token(
                &header.as_bytes(),
                &payload.as_bytes(),
                &signature.to_bytes(),
            )
            .unwrap();
    }

    #[test]
    fn rfc7515_example_a1_signature_bytes() {
        let pkey = &jwk();

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

        let signature: SignatureBytes = algorithm.sign_token(&header, &payload);

        let sig = base64ct::Base64UrlUnpadded::encode_string(signature.to_bytes().as_ref());

        assert_eq!(
            sig,
            strip_whitespace("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        );

        let _: SignatureBytes = algorithm
            .verify_token(
                &header.as_bytes(),
                &payload.as_bytes(),
                &signature.to_bytes(),
            )
            .unwrap();
    }

    fn hmac_roundtrip<D, S>(algorithm: &Hmac<D>)
    where
        D: Digest,
        S: SignatureEncoding,
        Hmac<D>: TokenSigner<S> + TokenVerifier<S>,
    {
        let payload = json! {
            {
                "iss": "joe",
                "exp": 1300819380,
                "http://example.com/is_root": true
            }
        };

        let token = crate::Token::compact((), payload);

        let signed = token.sign::<_, S>(algorithm).expect("signing");

        let unverified = signed.unverify();
        unverified.verify::<_, S>(algorithm).expect("verifying");
    }

    macro_rules! hmac_algorithm_test {
        ($name:ident, $digest:ty) => {
            #[test]
            fn $name() {
                let algorithm = Hmac::from_value(jwk()).unwrap();

                hmac_roundtrip::<$digest, DigestSignature<$digest>>(&algorithm);
                hmac_roundtrip::<$digest, SignatureBytes>(&algorithm);
            }
        };
    }

    hmac_algorithm_test!(hs256, sha2::Sha256);
    hmac_algorithm_test!(hs384, sha2::Sha384);
    hmac_algorithm_test!(hs512, sha2::Sha512);
}
