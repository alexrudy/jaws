use base64ct::{Base64UrlUnpadded, Encoding};
use rsa::pkcs1v15::SigningKey;
use rsa::rand_core::OsRng;
use rsa::signature::RandomizedSigner;
use rsa::PublicKeyParts;

impl crate::key::KeyInfo for rsa::RsaPublicKey {
    const KEY_TYPE: &'static str = "RSA";

    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        let mut params = Vec::with_capacity(2);

        let n = Base64UrlUnpadded::encode_string(&self.n().to_bytes_be());
        params.push(("n".to_owned(), n.into()));
        let e = Base64UrlUnpadded::encode_string(&self.e().to_bytes_be());
        params.push(("e".to_owned(), e.into()));

        params
    }
}

impl crate::key::KeyInfo for rsa::RsaPrivateKey {
    const KEY_TYPE: &'static str = "RSA";

    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        self.to_public_key().parameters()
    }
}

#[derive(Debug, Clone)]
pub struct Rsa<D>
where
    D: digest::Digest,
{
    key: SigningKey<D>,
}

impl<D> From<rsa::RsaPrivateKey> for Rsa<D>
where
    D: digest::Digest + pkcs8::AssociatedOid,
{
    fn from(key: rsa::RsaPrivateKey) -> Self {
        Self {
            key: SigningKey::new_with_prefix(key),
        }
    }
}

impl super::Algorithm for Rsa<sha2::Sha256> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::RS256;
}

impl super::SigningAlgorithm for Rsa<sha2::Sha256> {
    type Error = signature::Error;
    type Signature = rsa::pkcs1v15::Signature;
    type Key = rsa::RsaPrivateKey;

    fn sign(&self, header: &str, payload: &str) -> Result<Self::Signature, Self::Error> {
        let message = format!("{}.{}", header, payload);
        self.key.try_sign_with_rng(&mut OsRng, message.as_bytes())
    }

    fn key(&self) -> &Self::Key {
        self.key.as_ref()
    }
}

impl super::Algorithm for Rsa<sha2::Sha384> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::RS384;
}

impl super::SigningAlgorithm for Rsa<sha2::Sha384> {
    type Error = signature::Error;
    type Signature = rsa::pkcs1v15::Signature;
    type Key = rsa::RsaPrivateKey;

    fn sign(&self, header: &str, payload: &str) -> Result<Self::Signature, Self::Error> {
        let message = format!("{}.{}", header, payload);
        self.key.try_sign_with_rng(&mut OsRng, message.as_bytes())
    }

    fn key(&self) -> &Self::Key {
        self.key.as_ref()
    }
}

impl super::Algorithm for Rsa<sha2::Sha512> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::RS384;
}

impl super::SigningAlgorithm for Rsa<sha2::Sha512> {
    type Error = signature::Error;
    type Signature = rsa::pkcs1v15::Signature;
    type Key = rsa::RsaPrivateKey;

    fn sign(&self, header: &str, payload: &str) -> Result<Self::Signature, Self::Error> {
        let message = format!("{}.{}", header, payload);
        self.key.try_sign_with_rng(&mut OsRng, message.as_bytes())
    }

    fn key(&self) -> &Self::Key {
        self.key.as_ref()
    }
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

        let algorithm: Rsa<Sha256> = pkey.into();

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
