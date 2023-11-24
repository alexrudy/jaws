//! Elliptic Curve Digital Signature Algorithm (ECDSA) signing algorithms
//!
//! This module provides implementations of the ECDSA signing algorithms for use with JSON Web Tokens.
//!
//! It uses [elliptic_curve::SecretKey] as the base type, and provides implementations of the ECDSA
//! signing algorithms for the following curves:
//! - P-256 (ES256)
//! - P-384 (ES384)
//!
//! # Supported Algorithms
//!
//! - ES256: ECDSA using P-256 and SHA-256
//! - ES384: ECDSA using P-384 and SHA-384
#![cfg_attr(
    all(feature = "p256", feature = "fmt"),
    doc = r#"
# Examples:

Signing with an ECDSA key:

```rust
use serde_json::json;

use elliptic_curve::SecretKey;
use elliptic_curve::FieldBytes;
use base64ct::{Encoding, Base64UrlUnpadded};

use jaws::{Claims, RegisteredClaims, Token};
use jaws::JWTFormat;

// Create a new ECDSA signing key for the P-256 curve
// This is the key used in Appendix A.3 of RFC 7518

let mut key_bytes = FieldBytes::<p256::NistP256>::default();
base64ct::Base64UrlUnpadded::decode("jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI", &mut key_bytes).unwrap();
let key: SecretKey<p256::NistP256> = SecretKey::from_slice(&key_bytes).unwrap();

// Claims can combine registered and custom fields. The claims object
// can be any type which implements [serde::Serialize]
let claims: Claims<serde_json::Value, (), String, (), ()> = Claims {
    registered: RegisteredClaims {
        subject: "1234567890".to_string().into(),
        ..Default::default()
    },
    claims: json!({
        "name": "John Doe",
        "admin": true,
    }),
};

// Create a token with the default headers, and no custom headers.
// The unit type can be used here because it implements [serde::Serialize],
// but a custom type could be passed if we wanted to have custom header
// fields.
let mut token = Token::compact((), claims);
*token.header_mut().r#type() = Some("JWT".to_string());

// Sign the token with the ECDSA key, and print the result.
let signed = token.sign(&key).unwrap();
// Print out the compact form you would use as a token
println!("{}", signed.rendered().unwrap());

// Print out the formatted form useful for debugging
println!("{}", signed.formatted());
```
"#
)]

use std::ops::Add;

use ::ecdsa::{
    der::{MaxOverhead, MaxSize},
    hazmat::SignPrimitive,
    PrimeCurve, SignatureSize,
};
use base64ct::Encoding;
use digest::generic_array::ArrayLength;
use elliptic_curve::{
    ops::Invert,
    sec1::{Coordinates, FromEncodedPoint, ModulusSize, ToEncodedPoint},
    subtle::CtOption,
    AffinePoint, CurveArithmetic, FieldBytesSize, JwkParameters, PublicKey, Scalar,
};

pub use elliptic_curve::SecretKey;

#[cfg(feature = "p256")]
pub use p256::NistP256;

#[cfg(feature = "p384")]
pub use p384::NistP384;

#[cfg(feature = "p521")]
pub use p521::NistP521;

impl<C> crate::key::JWKeyType for PublicKey<C>
where
    C: elliptic_curve::Curve + elliptic_curve::CurveArithmetic,
{
    const KEY_TYPE: &'static str = "EC";
}

impl<C> crate::key::SerializeJWK for PublicKey<C>
where
    C: PrimeCurve + CurveArithmetic + JwkParameters,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        let mut params = Vec::with_capacity(2);

        params.push((
            "crv".to_owned(),
            serde_json::Value::String(C::CRV.to_owned()),
        ));
        let point = self.to_encoded_point(false);
        let Coordinates::Uncompressed { x, y } = point.coordinates() else {
            panic!("can't extract jwk coordinates")
        };

        params.push((
            "x".to_owned(),
            base64ct::Base64UrlUnpadded::encode_string(x).into(),
        ));
        params.push((
            "y".to_owned(),
            base64ct::Base64UrlUnpadded::encode_string(y).into(),
        ));
        params
    }
}

impl<C> crate::key::SerializeJWK for SecretKey<C>
where
    C: PrimeCurve + CurveArithmetic + JwkParameters,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        self.public_key().parameters()
    }
}
impl<C> crate::key::SerializeJWK for ecdsa::SigningKey<C>
where
    C: PrimeCurve + CurveArithmetic + JwkParameters,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        todo!()
    }
}

impl<C> crate::key::JWKeyType for ecdsa::SigningKey<C>
where
    C: PrimeCurve + CurveArithmetic + JwkParameters,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    const KEY_TYPE: &'static str = "EC";
}

impl<C> crate::key::JWKeyType for SecretKey<C>
where
    C: elliptic_curve::Curve,
{
    const KEY_TYPE: &'static str = "EC";
}

#[cfg(feature = "p256")]
impl super::Algorithm for SecretKey<NistP256> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::ES256;
    type Signature = ecdsa::SignatureBytes<NistP256>;
}

#[cfg(feature = "p384")]
impl super::Algorithm for SecretKey<NistP384> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::ES384;
    type Signature = ecdsa::SignatureBytes<NistP384>;
}

#[cfg(feature = "p521")]
impl super::Algorithm for SecretKey<NistP521> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::ES512;
    type Signature = ecdsa::SignatureBytes<NistP521>;
}

impl<C> super::SigningAlgorithm for SecretKey<C>
where
    C: PrimeCurve + CurveArithmetic + JwkParameters + ecdsa::hazmat::DigestPrimitive,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    MaxSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
    SecretKey<C>: super::Algorithm<Signature = ecdsa::SignatureBytes<C>>,
    <FieldBytesSize<C> as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
{
    type Error = ecdsa::Error;
    type Key = SecretKey<C>;

    fn sign(&self, header: &str, payload: &str) -> Result<Self::Signature, Self::Error> {
        let message = format!("{}.{}", header, payload);
        let signature =
            <::ecdsa::SigningKey<C> as signature::Signer<::ecdsa::Signature<C>>>::try_sign(
                &self.into(),
                message.as_bytes(),
            )
            .map(|sig| sig.to_bytes())?;
        Ok(signature)
    }

    fn key(&self) -> &Self::Key {
        self
    }
}

#[cfg(all(test, feature = "p256"))]
mod test {

    use super::*;

    use base64ct::Encoding;
    use elliptic_curve::FieldBytes;
    use serde_json::json;
    use zeroize::Zeroize;

    fn strip_whitespace(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    fn ecdsa(jwk: &serde_json::Value) -> SecretKey<p256::NistP256> {
        let d_b64 = strip_whitespace(jwk["d"].as_str().unwrap());
        let mut d_bytes = FieldBytes::<p256::NistP256>::default();
        base64ct::Base64UrlUnpadded::decode(&d_b64, &mut d_bytes).unwrap();

        let key = SecretKey::from_slice(&d_bytes).unwrap();
        d_bytes.zeroize();
        key
    }

    #[test]
    fn rfc7515_example_a3_signature() {
        let pkey = &json!({
        "kty":"EC",
        "crv":"P-256",
        "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
        });

        let key = ecdsa(pkey);

        let payload = strip_whitespace(
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
            cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
        );

        let header = strip_whitespace("eyJhbGciOiJFUzI1NiJ9");

        let signature = <SecretKey<p256::NistP256> as super::super::SigningAlgorithm>::sign(
            &key, &header, &payload,
        )
        .unwrap();

        let _sig = base64ct::Base64UrlUnpadded::encode_string(signature.as_ref());

        // This won't work because the signature is non-deterministic
        // assert_eq!(
        //     sig,
        //     strip_whitespace(
        //         "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
        //     ),
        //     "signature"
        // );
    }
}
