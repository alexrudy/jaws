#[cfg(feature = "fmt")]
use std::fmt::Write;

use serde::{ser, Serialize};

#[cfg(feature = "fmt")]
use crate::fmt;
use crate::{
    b64data::{Base64Data, Base64JSON},
    jose::{JOSEHeader, JOSEHeaderBuilder},
};

#[derive(Debug, Clone)]
pub enum Payload<P> {
    Json(Base64JSON<P>),
    Empty,
}

#[cfg(feature = "fmt")]
impl<P> fmt::JWTFormat for Payload<P>
where
    P: Serialize,
{
    fn fmt<W: fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> fmt::Result {
        match self {
            Payload::Json(data) => <Base64JSON<P> as fmt::JWTFormat>::fmt(data, f),
            Payload::Empty => f.write_str("\"\""),
        }
    }
}

impl<P> Payload<P>
where
    P: Serialize,
{
    fn serialized_value(&self) -> Result<String, serde_json::Error> {
        match self {
            Payload::Json(data) => data.serialized_value(),
            Payload::Empty => Ok("".to_owned()),
        }
    }
}

impl<P> From<P> for Payload<P> {
    fn from(value: P) -> Self {
        Payload::Json(value.into())
    }
}

impl<P> ser::Serialize for Payload<P>
where
    P: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Payload::Json(data) => data.serialize(serializer),
            Payload::Empty => serializer.serialize_str(""),
        }
    }
}

/// A JWS token wihtout an attached signature
///
/// This token contains just the unsigned parts which are used as the
/// input to the cryptographic signature.
#[derive(Debug, Clone)]
pub struct UnsignedToken<H, P> {
    pub header: JOSEHeaderBuilder<H>,
    payload: Payload<P>,
}

impl<P> UnsignedToken<(), P> {
    pub fn new_registered(payload: P) -> UnsignedToken<(), P> {
        UnsignedToken {
            header: JOSEHeaderBuilder::new_registered(),
            payload: payload.into(),
        }
    }
}

impl<H, P> UnsignedToken<H, P> {
    pub fn new(custom: H, payload: P) -> Self {
        Self {
            header: JOSEHeaderBuilder::new(custom),
            payload: payload.into(),
        }
    }

    pub fn payload(&self) -> Option<&P> {
        match &self.payload {
            Payload::Json(data) => Some(&data.0),
            Payload::Empty => None,
        }
    }

    pub fn header(&self) -> &H {
        &self.header.custom
    }
}

impl<H, P> UnsignedToken<H, P>
where
    H: Serialize,
    P: Serialize,
{
    pub fn sign<A>(self, algorithm: &A) -> Result<SignedToken<H, P, A>, TokenSigningError<A::Error>>
    where
        A: crate::algorithms::SigningAlgorithm,
        A::Key: Clone,
    {
        let headers = self.header.build::<A>(algorithm.key());
        let header = Base64JSON(&headers).serialized_value()?;
        let payload = self.payload.serialized_value()?;
        let signature = algorithm
            .sign(&header, &payload)
            .map_err(TokenSigningError::Signing)?;
        Ok(SignedToken {
            header: headers,
            payload: self.payload,
            signature: signature.into(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TokenSigningError<E> {
    #[error("signing: {0}")]
    Signing(E),

    #[error("serializing: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// A JWT with an attached signature, suitable for serialization.
///
/// Directly serializing this type will produce the JSON form of the JWT.
#[derive(Debug, Clone, Serialize)]
#[serde(bound = "H: Serialize, P: Serialize, A: crate::algorithms::SigningAlgorithm")]
pub struct SignedToken<H, P, A>
where
    A: crate::algorithms::SigningAlgorithm,
{
    #[serde(rename = "protected")]
    header: JOSEHeader<H, A::Key>,
    payload: Payload<P>,
    signature: Base64Data<A::Signature>,
}

impl<H, P, A> SignedToken<H, P, A>
where
    A: crate::algorithms::SigningAlgorithm,
{
    pub fn compact(&self) -> CompactTokenFormatter<'_, H, P, A> {
        CompactTokenFormatter {
            header: &self.header,
            payload: &self.payload,
            signature: &self.signature,
        }
    }

    pub fn message(&self) -> MessageTokenFormatter<'_, H, P, A> {
        MessageTokenFormatter {
            header: &self.header,
            payload: &self.payload,
        }
    }
}

pub struct MessageTokenFormatter<'a, H, P, A>
where
    A: crate::algorithms::SigningAlgorithm,
{
    header: &'a JOSEHeader<H, A::Key>,
    payload: &'a Payload<P>,
}

impl<'a, H, P, A> std::fmt::Display for MessageTokenFormatter<'a, H, P, A>
where
    A: crate::algorithms::SigningAlgorithm,
    H: Serialize,
    P: Serialize,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let header = Base64JSON(&self.header)
            .serialized_value()
            .expect("header can be JSON serialized");
        let payload = self
            .payload
            .serialized_value()
            .expect("payload can be JSON serialized");
        write!(f, "{}.{}", header, payload)
    }
}

/// A JWT with an attached signature in compact Base64URL-encoded format,
/// with '.' delimiters.
#[derive(Debug, Clone)]
pub struct CompactTokenFormatter<'a, H, P, A>
where
    A: crate::algorithms::SigningAlgorithm,
{
    header: &'a JOSEHeader<H, A::Key>,
    payload: &'a Payload<P>,
    signature: &'a Base64Data<A::Signature>,
}

impl<'a, H, P, A> std::fmt::Display for CompactTokenFormatter<'a, H, P, A>
where
    A: crate::algorithms::SigningAlgorithm,
    H: Serialize,
    P: Serialize,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let header = Base64JSON(&self.header)
            .serialized_value()
            .expect("header can be JSON serialized");
        let payload = self
            .payload
            .serialized_value()
            .expect("payload can be JSON serialized");
        let signature = self
            .signature
            .serialized_value()
            .expect("signature is valid base64");
        write!(f, "{}.{}.{}", header, payload, signature)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use base64ct::Encoding;
    use serde_json::json;
    use sha2::Sha256;

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

    #[test]
    #[allow(non_snake_case)]
    fn rfc7515_example_A2() {
        let key = json!( {"kty":"RSA",
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
        );

        let primes = vec![
            to_biguint(&key["p"]).expect("p"),
            to_biguint(&key["q"]).expect("q"),
        ];

        let pkey = rsa::RsaPrivateKey::from_components(
            to_biguint(&key["n"]).expect("n"),
            to_biguint(&key["e"]).expect("e"),
            to_biguint(&key["d"]).expect("d"),
            primes,
        )
        .unwrap();

        assert_eq!(&to_biguint(&key["dp"]).expect("dp"), pkey.dp().unwrap());
        assert_eq!(&to_biguint(&key["dq"]).expect("dq"), pkey.dq().unwrap());

        let payload = json!({
            "iss": "joe",
            "exp": 1300819380,
            "http://example.com/is_root": true
        });

        let token = UnsignedToken::new_registered(payload);

        let algorithm: crate::algorithms::rsa::Rsa<Sha256> = pkey.into();
        let signed = token.sign(&algorithm).unwrap();
        {
            let hdr = base64ct::Base64UrlUnpadded::encode_string(
                &serde_json::to_vec(&signed.header).unwrap(),
            );
            assert_eq!(hdr, "eyJhbGciOiJSUzI1NiJ9")
        }
        {
            let msg = signed.message();
            assert_eq!(
                msg.to_string(),
                strip_whitespace(
                    "eyJhbGciOiJSUzI1NiJ9
            .
            eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb
            290Ijp0cnVlLCJpc3MiOiJqb2UifQ"
                )
            )
        }

        {
            let tkn = signed.compact();
            assert_eq!(
                tkn.to_string(),
                strip_whitespace(
                    "
            eyJhbGciOiJSUzI1NiJ9
            .
            eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb
            290Ijp0cnVlLCJpc3MiOiJqb2UifQ
            .
            NwAkuu3U9lhVJfpX4lCQt3CtDoBAdq8iXX5xbdPsezmbCPyz7VRsIk2Y_
            UTVQHel6PXVFjcGrXI6txw2lMvpLRvwCRcP9YcUVCfvXNFNmTWcBwgkY_
            gA17gSJhOIW_aZGA36dme5TpvhAnodnbpP0T50UnBQSlr1OAtJAQ1Iy9z
            Nens83wr14K7V2bVHj3JbM0PDlQuiAEcQ1M6T5x8le8jLTrI7OKKWakLj
            Kzm8sqeWqTMbLu89T0XPOT3T35G62UAOQsYPZqHxdyJ1KMuovCI1xuHvQ
            3t-Dd_Rrz9uVupwg66eKyYihEVCllMSzZrEknUjaJ4sOcDEX9AMscrZRw"
                )
            )
        }
    }
}
