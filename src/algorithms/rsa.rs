//! RSA algorithms
//!
//! # PKCS#1 v1.5 (RS256, RS384, RS512)
//! This algorithm is used to sign and verify JSON Web Tokens using the RSASSA-PKCS1-v1_5.
//! A [rsa::pkcs1v15::SigningKey] signing key is used to provide the underlying signature
//! algorithm.
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

use base64ct::{Base64UrlUnpadded, Encoding};
use bytes::BytesMut;
use rsa::rand_core::OsRng;
use rsa::signature::RandomizedSigner;
use rsa::PublicKeyParts;

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

impl crate::key::JWKeyType for rsa::RsaPrivateKey {
    const KEY_TYPE: &'static str = "RSA";
}

impl crate::key::SerializeJWK for rsa::RsaPrivateKey {
    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        self.to_public_key().parameters()
    }
}

/// Alogrithm wrapper for the Digital Signature with RSASSA-PKCS1-v1_5 algorithm.
pub type RsaPkcs1v15<D> = rsa::pkcs1v15::SigningKey<D>;

/// Alogrithm wrapper for the Digital Signature with RSASSA-PKCS1-v1_5 algorithm.
pub type RsaPkcs1v15Verify<D> = rsa::pkcs1v15::VerifyingKey<D>;

impl<D> super::SigningAlgorithm for RsaPkcs1v15<D>
where
    D: digest::Digest,
    RsaPkcs1v15<D>: super::Algorithm<Signature = rsa::pkcs1v15::Signature>,
{
    type Error = signature::Error;
    type Key = rsa::RsaPrivateKey;

    fn sign(&self, header: &str, payload: &str) -> Result<Self::Signature, Self::Error> {
        let message = format!("{}.{}", header, payload);
        self.try_sign_with_rng(&mut OsRng, message.as_bytes())
    }

    fn key(&self) -> &Self::Key {
        self.as_ref()
    }
}

impl<D> super::VerifyAlgorithm for RsaPkcs1v15Verify<D>
where
    D: digest::Digest,
    RsaPkcs1v15Verify<D>: super::Algorithm<Signature = rsa::pkcs1v15::Signature> + Clone,
{
    type Error = signature::Error;

    type Key = rsa::RsaPublicKey;

    fn verify(
        &self,
        header: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<Self::Signature, Self::Error> {
        use rsa::signature::Verifier;
        let signature = rsa::pkcs1v15::Signature::try_from(signature).unwrap();

        let mut message = BytesMut::with_capacity(header.len() + payload.len() + 1);
        message.extend_from_slice(header);
        message.extend_from_slice(b".");
        message.extend_from_slice(payload);

        <Self as Verifier<rsa::pkcs1v15::Signature>>::verify(self, message.as_ref(), &signature)?;
        Ok(signature)
    }

    fn key(&self) -> &Self::Key {
        self.as_ref()
    }
}

impl super::Algorithm for RsaPkcs1v15<sha2::Sha256> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::RS256;
    type Signature = rsa::pkcs1v15::Signature;
}

impl super::Algorithm for RsaPkcs1v15<sha2::Sha384> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::RS384;
    type Signature = rsa::pkcs1v15::Signature;
}

impl super::Algorithm for RsaPkcs1v15<sha2::Sha512> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::RS512;
    type Signature = rsa::pkcs1v15::Signature;
}

impl super::Algorithm for RsaPkcs1v15Verify<sha2::Sha256> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::RS256;
    type Signature = rsa::pkcs1v15::Signature;
}

impl super::Algorithm for RsaPkcs1v15Verify<sha2::Sha384> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::RS384;
    type Signature = rsa::pkcs1v15::Signature;
}

impl super::Algorithm for RsaPkcs1v15Verify<sha2::Sha512> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::RS512;
    type Signature = rsa::pkcs1v15::Signature;
}

/// Algorithm wrapper for RSA-PSS signatures, using [rsa::pss::BlindedSigningKey].
pub type RsaPSSKey<D> = rsa::pss::BlindedSigningKey<D>;

impl<D> super::SigningAlgorithm for RsaPSSKey<D>
where
    D: digest::Digest + digest::FixedOutputReset,
    RsaPSSKey<D>: super::Algorithm<Signature = rsa::pss::Signature>,
{
    type Error = signature::Error;
    type Key = rsa::RsaPrivateKey;

    fn sign(&self, header: &str, payload: &str) -> Result<Self::Signature, Self::Error> {
        let message = format!("{}.{}", header, payload);
        self.try_sign_with_rng(&mut OsRng, message.as_bytes())
    }

    fn key(&self) -> &Self::Key {
        self.as_ref()
    }
}

impl super::Algorithm for RsaPSSKey<sha2::Sha256> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::PS256;
    type Signature = rsa::pss::Signature;
}

impl super::Algorithm for RsaPSSKey<sha2::Sha384> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::PS384;
    type Signature = rsa::pss::Signature;
}

impl super::Algorithm for RsaPSSKey<sha2::Sha512> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::PS512;
    type Signature = rsa::pss::Signature;
}

#[cfg(test)]
mod test {
    use crate::algorithms::SigningAlgorithm;
    use crate::key::jwk_reader::rsa;

    use super::*;

    use base64ct::Encoding;
    use serde_json::json;
    use sha2::Sha256;

    fn strip_whitespace(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    #[test]
    fn rfc7515_example_a2_signature() {
        let pkey = rsa(&json!( {"kty":"RSA",
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
        ));

        let payload = strip_whitespace(
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
        cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
        );

        let header = strip_whitespace("eyJhbGciOiJSUzI1NiJ9");

        let algorithm: RsaPkcs1v15<Sha256> = RsaPkcs1v15::new_with_prefix(pkey);

        let signature = algorithm.sign(&header, &payload).unwrap();

        let sig = base64ct::Base64UrlUnpadded::encode_string(signature.as_ref());

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
}
