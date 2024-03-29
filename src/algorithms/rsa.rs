//! RSA algorithms
//!
//! # PKCS#1 v1.5 (RS256, RS384, RS512)
//! This algorithm is used to sign and verify JSON Web Tokens using the RSASSA-PKCS1-v1_5.
//! Use [rsa::pkcs1v15::SigningKey] to sign tokens, and [rsa::pkcs1v15::VerifyingKey] to verify tokens.
//!
//! A key of size 2048 bits or larger MUST be used with these algorithms.
//!
//! The RSASSA-PKCS1-v1_5 SHA-256 digital signature is generated as
//! follows: generate a digital signature of the JWS Signing Input using
//! RSASSA-PKCS1-v1_5-SIGN and the SHA-256 hash function with the desired
//! private key.  This is the JWS Signature value.
//!
//! # PSS (PS256, PS384, PS512)
//! This algorithm is used to sign and verify JSON Web Tokens using the RSASSA-PSS.
//!
//! Use [rsa::pss::BlindedSigningKey] to sign tokens, and [rsa::pss::VerifyingKey] to verify tokens.

use base64ct::{Base64UrlUnpadded, Encoding};
use rsa::traits::PrivateKeyParts;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
#[cfg(feature = "rand")]
use signature::RandomizedDigestSigner;

pub use rsa::pkcs1v15;
pub use rsa::pss;

use crate::key::DeserializeJWK;
#[cfg(feature = "rand")]
use crate::SignatureBytes;

impl crate::key::JWKeyType for rsa::RsaPublicKey {
    const KEY_TYPE: &'static str = "RSA";
}

impl crate::key::SerializeJWK for rsa::RsaPublicKey {
    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        let mut params = Vec::with_capacity(2);

        let n = Base64UrlUnpadded::encode_string(&self.n().to_bytes_be());
        params.push(("n".to_owned(), n.into()));
        let e = Base64UrlUnpadded::encode_string(&self.e().to_bytes_be());
        params.push(("e".to_owned(), e.into()));

        params
    }
}

fn strip_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

fn to_biguint(v: &serde_json::Value) -> Option<rsa::BigUint> {
    let val = strip_whitespace(v.as_str()?);
    Some(rsa::BigUint::from_bytes_be(
        base64ct::Base64UrlUnpadded::decode_vec(&val)
            .ok()?
            .as_slice(),
    ))
}

fn rsa_key_parameter(
    parameters: &std::collections::BTreeMap<String, serde_json::Value>,
    name: &'static str,
) -> Result<rsa::BigUint, crate::key::JsonWebKeyError> {
    let val = parameters
        .get(name)
        .ok_or(crate::key::JsonWebKeyError::MissingParameter(name))?;
    to_biguint(val).ok_or(crate::key::JsonWebKeyError::MissingParameter(name))
}

impl crate::key::DeserializeJWK for rsa::RsaPublicKey {
    fn build(
        parameters: std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Result<Self, crate::key::JsonWebKeyError>
    where
        Self: Sized,
    {
        let n = rsa_key_parameter(&parameters, "n")?;
        let e = rsa_key_parameter(&parameters, "e")?;

        rsa::RsaPublicKey::new(n, e)
            .map_err(|error| crate::key::JsonWebKeyError::InvalidKey("RSA", error.into()))
    }
}

impl crate::key::JWKeyType for rsa::RsaPrivateKey {
    const KEY_TYPE: &'static str = "RSA";
}

impl crate::key::SerializeJWK for rsa::RsaPrivateKey {
    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        fn from_biguint(n: &rsa::BigUint) -> String {
            let bytes = n.to_bytes_be();
            Base64UrlUnpadded::encode_string(&bytes)
        }

        let mut params = self.to_public_key().parameters();
        params.push(("d".into(), from_biguint(self.d()).into()));

        let mut additional_params = Vec::new();
        let mut primes = self.primes().iter();

        additional_params.push((
            "p".into(),
            from_biguint(primes.next().expect("At least 1 RSA prime is available")).into(),
        ));
        additional_params.push((
            "q".into(),
            from_biguint(primes.next().expect("At least 2 RSA primes are available")).into(),
        ));

        // We may not have the following parameters if we have not pre-computed their value.
        // If any parameter is missing, we should not include any of them.
        if let Some(dp) = self.dp() {
            additional_params.push(("dp".into(), from_biguint(dp).into()));
        } else {
            additional_params.clear();
        }

        if let Some(dq) = self.dq() {
            additional_params.push(("dq".into(), from_biguint(dq).into()));
        } else {
            additional_params.clear();
        }

        if let Some(qi) = self.qinv() {
            additional_params.push((
                "qi".into(),
                from_biguint(&qi.to_biguint().expect("qinv is positive")).into(),
            ));
        } else {
            additional_params.clear();
        }

        #[allow(unused)]
        for (prime, crt) in primes.zip(self.crt_values().into_iter()) {
            todo!("Support for multiple primes is not yet implemented");
        }

        params.extend(additional_params);

        params
    }
}

impl DeserializeJWK for RsaPrivateKey {
    fn build(
        parameters: std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Result<Self, crate::key::JsonWebKeyError>
    where
        Self: Sized,
    {
        fn validate_key_parameter(
            parameters: &std::collections::BTreeMap<String, serde_json::Value>,
            name: &'static str,
            precomputed: Option<&rsa::BigUint>,
        ) -> Result<(), crate::key::JsonWebKeyError> {
            if let Some(val) = parameters.get(name) {
                let value =
                    to_biguint(val).ok_or(crate::key::JsonWebKeyError::MissingParameter(name))?;

                if let Some(pc_value) = precomputed {
                    if value != *pc_value {
                        return Err(crate::key::JsonWebKeyError::InvalidKey(
                            "RSA",
                            format!("{} does not match precomputed value", name).into(),
                        ));
                    }
                }
            }
            Ok(())
        }

        let primes = vec![
            rsa_key_parameter(&parameters, "p")?,
            rsa_key_parameter(&parameters, "q")?,
        ];

        let n = rsa_key_parameter(&parameters, "n")?;
        let e = rsa_key_parameter(&parameters, "e")?;
        let d = rsa_key_parameter(&parameters, "d")?;

        let key = RsaPrivateKey::from_components(n, e, d, primes)
            .map_err(|error| crate::key::JsonWebKeyError::InvalidKey("RSA", error.into()))?;

        key.validate()
            .map_err(|error| crate::key::JsonWebKeyError::InvalidKey("RSA", error.into()))?;

        validate_key_parameter(&parameters, "dp", key.dp())?;
        validate_key_parameter(&parameters, "dq", key.dq())?;
        validate_key_parameter(
            &parameters,
            "qi",
            key.qinv().and_then(|inv| inv.to_biguint()).as_ref(),
        )?;

        Ok(key)
    }
}

impl<D> crate::key::JWKeyType for rsa::pkcs1v15::SigningKey<D>
where
    D: signature::digest::Digest,
{
    const KEY_TYPE: &'static str = "RSA";
}

impl<D> crate::key::SerializeJWK for rsa::pkcs1v15::SigningKey<D>
where
    D: signature::digest::Digest,
{
    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        self.as_ref().to_public_key().parameters()
    }
}

impl<D> crate::key::JWKeyType for rsa::pkcs1v15::VerifyingKey<D>
where
    D: signature::digest::Digest,
{
    const KEY_TYPE: &'static str = "RSA";
}

impl<D> crate::key::SerializeJWK for rsa::pkcs1v15::VerifyingKey<D>
where
    D: signature::digest::Digest,
{
    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        self.as_ref().parameters()
    }
}

macro_rules! jose_rsa_pkcs1v15_algorithm {
    ($alg:ident, $digest:ty) => {
        $crate::algorithms::jose_algorithm!(
            $alg,
            rsa::pkcs1v15::SigningKey<$digest>,
            rsa::pkcs1v15::VerifyingKey<$digest>,
            $digest,
            rsa::pkcs1v15::Signature
        );
    };
}

jose_rsa_pkcs1v15_algorithm!(RS256, sha2::Sha256);
jose_rsa_pkcs1v15_algorithm!(RS384, sha2::Sha384);
jose_rsa_pkcs1v15_algorithm!(RS512, sha2::Sha512);

impl<D> crate::key::JWKeyType for rsa::pss::BlindedSigningKey<D>
where
    D: signature::digest::Digest,
{
    const KEY_TYPE: &'static str = "RSA";
}

impl<D> crate::key::SerializeJWK for rsa::pss::BlindedSigningKey<D>
where
    D: signature::digest::Digest,
{
    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        self.as_ref().to_public_key().parameters()
    }
}

impl<D> crate::key::JWKeyType for rsa::pss::VerifyingKey<D>
where
    D: signature::digest::Digest,
{
    const KEY_TYPE: &'static str = "RSA";
}

impl<D> crate::key::SerializeJWK for rsa::pss::VerifyingKey<D>
where
    D: signature::digest::Digest,
{
    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        self.as_ref().parameters()
    }
}

#[cfg(feature = "rand")]
impl<D> crate::key::JWKeyType for rsa::pss::SigningKey<D>
where
    D: signature::digest::Digest,
{
    const KEY_TYPE: &'static str = "RSA";
}

#[cfg(feature = "rand")]
macro_rules! rsa_pss_algorithm {
    ($alg:ident, $digest:ty) => {
        impl $crate::algorithms::JsonWebAlgorithm for rsa::pss::SigningKey<$digest> {
            const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::$alg;
        }

        impl $crate::algorithms::JsonWebAlgorithm for rsa::pss::VerifyingKey<$digest> {
            const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::$alg;
        }

        impl signature::RandomizedDigestSigner<$digest, SignatureBytes>
            for rsa::pss::SigningKey<$digest>
        where
            Self: RandomizedDigestSigner<$digest, rsa::pss::Signature>
                + crate::algorithms::DynJsonWebAlgorithm,
        {
            fn try_sign_digest_with_rng(
                &self,
                rng: &mut impl rand_core::CryptoRngCore,
                digest: $digest,
            ) -> Result<SignatureBytes, signature::Error> {
                use signature::SignatureEncoding;

                let signature: rsa::pss::Signature = self.try_sign_digest_with_rng(rng, digest)?;
                Ok(signature.to_bytes().as_ref().into())
            }
        }

        impl signature::DigestVerifier<$digest, SignatureBytes> for rsa::pss::VerifyingKey<$digest>
        where
            Self: signature::DigestVerifier<$digest, rsa::pss::Signature>
                + crate::algorithms::DynJsonWebAlgorithm,
        {
            fn verify_digest(
                &self,
                digest: $digest,
                signature: &SignatureBytes,
            ) -> Result<(), signature::Error> {
                use signature::SignatureEncoding;

                let signature: rsa::pss::Signature = signature
                    .to_bytes()
                    .as_ref()
                    .try_into()
                    .map_err(signature::Error::from_source)?;

                self.verify_digest(digest, &signature)
            }
        }
    };
}

#[cfg(feature = "rand")]
rsa_pss_algorithm!(PS256, sha2::Sha256);
#[cfg(feature = "rand")]
rsa_pss_algorithm!(PS384, sha2::Sha384);
#[cfg(feature = "rand")]
rsa_pss_algorithm!(PS512, sha2::Sha512);

#[cfg(feature = "rand")]
impl<D> crate::key::SerializeJWK for rsa::pss::SigningKey<D>
where
    D: signature::digest::Digest,
{
    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        self.as_ref().to_public_key().parameters()
    }
}

#[cfg(feature = "rand")]
impl<D> crate::key::DeserializeJWK for rsa::pss::SigningKey<D>
where
    D: signature::digest::Digest,
{
    fn build(
        parameters: std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Result<Self, crate::key::JsonWebKeyError>
    where
        Self: Sized,
    {
        let key = rsa::RsaPrivateKey::build(parameters)?;

        Ok(rsa::pss::SigningKey::new(key))
    }
}

#[cfg(feature = "rand")]
impl<S, D> crate::algorithms::RandomizedTokenSigner<S> for rsa::pss::SigningKey<D>
where
    D: signature::digest::Digest,
    S: signature::SignatureEncoding,
    Self: RandomizedDigestSigner<D, S> + crate::algorithms::DynJsonWebAlgorithm,
{
    fn try_sign_token(
        &self,
        header: &str,
        payload: &str,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<S, signature::Error> {
        let mut digest = D::new();
        digest.update(header.as_bytes());
        digest.update(b".");
        digest.update(payload.as_bytes());

        self.try_sign_digest_with_rng(rng, digest)
    }
}

#[cfg(feature = "rand")]
impl<S, D> crate::algorithms::TokenVerifier<S> for rsa::pss::VerifyingKey<D>
where
    D: signature::digest::Digest,
    S: signature::SignatureEncoding,
    for<'a> <S as TryFrom<&'a [u8]>>::Error: std::error::Error + Send + Sync + 'static,
    Self: signature::DigestVerifier<D, S> + crate::algorithms::DynJsonWebAlgorithm,
{
    fn verify_token(
        &self,
        header: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<S, signature::Error> {
        use signature::DigestVerifier;

        let mut digest = D::new();
        digest.update(header);
        digest.update(b".");
        digest.update(payload);

        let signature = signature
            .try_into()
            .map_err(signature::Error::from_source)?;

        self.verify_digest(digest, &signature)?;
        Ok(signature)
    }
}

#[cfg(test)]
mod test {

    use crate::key::DeserializeJWK;
    use crate::SignatureBytes;
    use crate::TokenSigner;

    use base64ct::Encoding as _;
    use serde_json::json;
    use sha2::Sha256;
    use signature::Keypair;
    use signature::SignatureEncoding;

    fn strip_whitespace(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    fn rsa(jwk: serde_json::Value) -> rsa::RsaPrivateKey {
        rsa::RsaPrivateKey::from_value(jwk).unwrap()
    }

    fn jwk() -> serde_json::Value {
        json!( {"kty":"RSA",
              "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx
       HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs
       D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH
       SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV
       MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8
       NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
              "e":"AQAB",
              "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I
       jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0
       BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn
       439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT
       CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh
       BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
              "p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi
       YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG
       BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
              "q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa
       ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA
       -njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
              "dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q
       CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb
       34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
              "dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa
       7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky
       NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
              "qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o
       y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU
       W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
             }
        )
    }

    #[test]
    fn rfc7515_example_a2_signature() {
        let pkey = rsa(jwk());

        let payload = strip_whitespace(
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
        cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
        );

        let header = strip_whitespace("eyJhbGciOiJSUzI1NiJ9");

        let algorithm: rsa::pkcs1v15::SigningKey<Sha256> = rsa::pkcs1v15::SigningKey::new(pkey);

        let signature: rsa::pkcs1v15::Signature = algorithm.sign_token(&header, &payload);

        let sig = base64ct::Base64UrlUnpadded::encode_string(signature.to_bytes().as_ref());

        assert_eq!(
            sig,
            strip_whitespace(
                "
                cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7
                AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4
                BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K
                0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv
                hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB
                p0igcN_IoypGlUPQGe77Rw"
            )
        );
    }

    fn algorithm_roundtrip<S>(
        sign: &impl crate::algorithms::TokenSigner<S>,
        verify: &impl crate::algorithms::TokenVerifier<S>,
    ) where
        S: SignatureEncoding,
    {
        let payload = json! {
            {
                "iss": "joe",
                "exp": 1300819380,
                "http://example.com/is_root": true
            }
        };

        let token = crate::Token::compact((), payload);

        let signed = token.sign::<_, S>(sign).expect("signing");

        let unverified = signed.unverify();
        unverified.verify::<_, S>(verify).expect("verifying");
    }

    macro_rules! rsa_pkcs1v15_algorithm_test {
        ($name:ident, $digest:ty) => {
            #[test]
            fn $name() {
                let pkey = rsa(jwk());

                let algorithm: rsa::pkcs1v15::SigningKey<$digest> =
                    rsa::pkcs1v15::SigningKey::new(pkey);

                algorithm_roundtrip::<rsa::pkcs1v15::Signature>(
                    &algorithm,
                    &algorithm.verifying_key(),
                );
                algorithm_roundtrip::<SignatureBytes>(&algorithm, &algorithm.verifying_key());
            }
        };
    }

    rsa_pkcs1v15_algorithm_test!(rs256_algorithm, sha2::Sha256);
    rsa_pkcs1v15_algorithm_test!(rs384_algorithm, sha2::Sha384);
    rsa_pkcs1v15_algorithm_test!(rs512_algorithm, sha2::Sha512);

    #[cfg(feature = "rand")]
    mod pss {
        use rand_core::OsRng;
        use serde_json::json;
        use signature::Keypair;
        use signature::SignatureEncoding;

        use crate::SignatureBytes;

        fn algorithm_roundtrip<S>(
            sign: &impl crate::algorithms::RandomizedTokenSigner<S>,
            verify: &impl crate::algorithms::TokenVerifier<S>,
        ) where
            S: SignatureEncoding,
        {
            let payload = json! {
                {
                    "iss": "joe",
                    "exp": 1300819380,
                    "http://example.com/is_root": true
                }
            };

            let token = crate::Token::compact((), payload);

            let signed = token
                .sign_randomized::<_, S>(sign, &mut OsRng)
                .expect("signing");

            let unverified = signed.unverify();
            unverified.verify::<_, S>(verify).expect("verifying");
        }

        macro_rules! rsa_pss_algorithm_test {
            ($name:ident, $digest:ty) => {
                #[test]
                fn $name() {
                    let pkey = super::rsa(super::jwk());

                    let algorithm: rsa::pss::SigningKey<$digest> = rsa::pss::SigningKey::new(pkey);

                    algorithm_roundtrip::<rsa::pss::Signature>(
                        &algorithm,
                        &algorithm.verifying_key(),
                    );
                    algorithm_roundtrip::<SignatureBytes>(&algorithm, &algorithm.verifying_key());
                }
            };
        }

        rsa_pss_algorithm_test!(ps256_algorithm, sha2::Sha256);
        rsa_pss_algorithm_test!(ps384_algorithm, sha2::Sha384);
        rsa_pss_algorithm_test!(ps512_algorithm, sha2::Sha512);
    }
}
