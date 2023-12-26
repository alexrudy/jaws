//! Elliptic Curve Digital Signature Algorithm (ECDSA) signing algorithms
//!
//! This module provides implementations of the ECDSA signing algorithms for use with JSON Web Tokens.
//!
//! Although the ECDSA algorithm is defined in [RFC7518](https://tools.ietf.org/html/rfc7518), it is defined
//! against the non-deterministic version, which has been shown to have problems with key recovery, and so uses
//! the deterministic version defined in [RFC6979](https://tools.ietf.org/html/rfc6979).
//!
//! This could be changed to use the non-deterministic version specified in [RFC6979](https://tools.ietf.org/html/rfc6979)
//! by requiring an random number generator as an additional parameter to the signing algorithm, but this is not
//! currently easily supported.
//!
//! It uses [ecdsa::SigningKey] and [ecdsa::VerifyingKey] as the key types, and provides implementations of the ECDSA
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

use ecdsa::SigningKey;
use ecdsa::Signature;
use elliptic_curve::FieldBytes;
use base64ct::{Encoding, Base64UrlUnpadded};

use jaws::{Claims, RegisteredClaims, Token};
use jaws::JWTFormat;

// Create a new ECDSA signing key for the P-256 curve
// This is the key used in Appendix A.3 of RFC 7518

let mut key_bytes = FieldBytes::<p256::NistP256>::default();
base64ct::Base64UrlUnpadded::decode("jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI", &mut key_bytes).unwrap();
let key: SigningKey<p256::NistP256> = SigningKey::from_slice(&key_bytes).unwrap();

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
let signed = token.sign::<_, Signature<_>>(&key).unwrap();
// Print out the compact form you would use as a token
println!("{}", signed.rendered().unwrap());

// Print out the formatted form useful for debugging
println!("{}", signed.formatted());
```
"#
)]

use ::ecdsa::{hazmat::SignPrimitive, PrimeCurve, SignatureSize};
pub use ::ecdsa::{SigningKey, VerifyingKey};
use base64ct::Base64UrlUnpadded as Base64Url;
use base64ct::Encoding;
use bytes::Bytes;
use digest::generic_array::{ArrayLength, GenericArray};
#[cfg(feature = "rand")]
use digest::Digest;
use ecdsa::EncodedPoint;
use elliptic_curve::{
    ops::Invert,
    sec1::{Coordinates, FromEncodedPoint, ModulusSize, ToEncodedPoint, ValidatePublicKey},
    subtle::CtOption,
    AffinePoint, Curve, CurveArithmetic, FieldBytes, FieldBytesSize, JwkParameters, PublicKey,
    Scalar, SecretKey,
};

#[cfg(feature = "rand")]
use signature::RandomizedDigestSigner;

#[cfg(feature = "p256")]
pub use p256::NistP256;

#[cfg(feature = "p384")]
pub use p384::NistP384;

#[cfg(feature = "p521")]
pub use p521::NistP521;
use signature::SignatureEncoding;

use crate::key::JsonWebKeyError;

impl<C> From<::ecdsa::Signature<C>> for super::SignatureBytes
where
    C: PrimeCurve,
    ::ecdsa::Signature<C>: SignatureEncoding,
{
    fn from(sig: ::ecdsa::Signature<C>) -> Self {
        Self::from(Bytes::copy_from_slice(sig.to_bytes().as_ref()))
    }
}

impl<C> crate::key::JWKeyType for PublicKey<C>
where
    C: Curve + CurveArithmetic,
{
    const KEY_TYPE: &'static str = "EC";
}

impl<C> crate::key::SerializeJWK for PublicKey<C>
where
    C: PrimeCurve + CurveArithmetic + JwkParameters,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        let mut params = Vec::with_capacity(3);

        params.push((
            "crv".to_owned(),
            serde_json::Value::String(C::CRV.to_owned()),
        ));
        let point = self.to_encoded_point(false);
        let Coordinates::Uncompressed { x, y } = point.coordinates() else {
            panic!("can't extract jwk coordinates from compressed or compact field points")
        };

        params.push(("x".to_owned(), Base64Url::encode_string(x).into()));
        params.push(("y".to_owned(), Base64Url::encode_string(y).into()));
        params
    }
}

impl<C> crate::key::DeserializeJWK for PublicKey<C>
where
    C: Curve + CurveArithmetic + JwkParameters,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn build(
        parameters: std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Result<Self, crate::key::JsonWebKeyError> {
        let crv = parameters
            .get("crv")
            .and_then(|c| c.as_str())
            .ok_or(crate::key::JsonWebKeyError::MissingParameter("crv"))?;

        if crv != C::CRV {
            return Err(crate::key::JsonWebKeyError::InvalidKey(
                "EC",
                format!("got crv {}, expected {}", crv, C::CRV).into(),
            ));
        }

        fn get<C>(
            parameters: &std::collections::BTreeMap<String, serde_json::Value>,
            name: &'static str,
        ) -> Result<GenericArray<u8, <C as Curve>::FieldBytesSize>, crate::key::JsonWebKeyError>
        where
            C: Curve,
        {
            parameters
                .get(name)
                .and_then(|c| c.as_str())
                .ok_or(crate::key::JsonWebKeyError::MissingParameter(name))
                .and_then(|c| {
                    let mut bytes: GenericArray<u8, <C as Curve>::FieldBytesSize> =
                        Default::default();
                    Base64Url::decode(c, bytes.as_mut()).map_err(|error| {
                        crate::key::JsonWebKeyError::InvalidKey(
                            "EC",
                            format!("invalid base64 encoding for {}: {}", name, error).into(),
                        )
                    })?;
                    Ok(bytes)
                })
        }

        let x = get::<C>(&parameters, "x")?;
        let y = get::<C>(&parameters, "y")?;

        let point: EncodedPoint<C> = EncodedPoint::<C>::from_affine_coordinates(&x, &y, false);

        Option::from(Self::from_encoded_point(&point)).ok_or_else(|| {
            crate::key::JsonWebKeyError::InvalidKey(
                "EC",
                String::from("An error occured encoding the EC point").into(),
            )
        })
    }
}

impl<C> crate::key::JWKeyType for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic + JwkParameters,
{
    const KEY_TYPE: &'static str = "EC";
}

impl<C> crate::key::SerializeJWK for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic + JwkParameters,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        PublicKey::from(self).parameters()
    }
}

impl<C> crate::key::DeserializeJWK for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic + JwkParameters,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn build(
        parameters: std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Result<Self, crate::key::JsonWebKeyError> {
        PublicKey::build(parameters).map(Self::from)
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
        let mut parameters = self.public_key().parameters();
        let d = self.to_sec1_der().expect("d is valid sec1 der");
        parameters.push((
            "d".to_owned(),
            base64ct::Base64UrlUnpadded::encode_string(d.as_ref()).into(),
        ));

        parameters
    }
}

impl<C> crate::key::JWKeyType for SecretKey<C>
where
    C: Curve,
{
    const KEY_TYPE: &'static str = "EC";
}

impl<C> crate::key::DeserializeJWK for SecretKey<C>
where
    C: Curve + CurveArithmetic + JwkParameters + ValidatePublicKey,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn build(
        parameters: std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Result<Self, crate::key::JsonWebKeyError> {
        let d = parameters
            .get("d")
            .and_then(|c| c.as_str())
            .ok_or(crate::key::JsonWebKeyError::MissingParameter("d"))?;
        let mut d_bytes = FieldBytes::<C>::default();
        base64ct::Base64UrlUnpadded::decode(d, &mut d_bytes).map_err(|error| {
            crate::key::JsonWebKeyError::InvalidKey(
                "EC",
                format!("invalid base64 encoding for d: {}", error).into(),
            )
        })?;
        let secret_key = SecretKey::from_bytes(&d_bytes).map_err(|error| {
            crate::key::JsonWebKeyError::InvalidKey(
                "EC",
                format!("invalid secret key: {}", error).into(),
            )
        })?;

        let public_key: PublicKey<C> = PublicKey::build(parameters)?;
        C::validate_public_key(&secret_key, &public_key.to_encoded_point(false)).map_err(
            |error: elliptic_curve::Error| JsonWebKeyError::InvalidKey("EC", error.into()),
        )?;

        Ok(secret_key)
    }
}

impl<C> crate::key::JWKeyType for SigningKey<C>
where
    C: PrimeCurve + CurveArithmetic + JwkParameters,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    const KEY_TYPE: &'static str = "EC";
}

impl<C> crate::key::SerializeJWK for SigningKey<C>
where
    C: PrimeCurve + CurveArithmetic + JwkParameters,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        SecretKey::from(self).parameters()
    }
}

impl<C> crate::key::DeserializeJWK for SigningKey<C>
where
    C: PrimeCurve + CurveArithmetic + JwkParameters,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn build(
        parameters: std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Result<Self, crate::key::JsonWebKeyError> {
        SecretKey::build(parameters).map(Self::from)
    }
}

macro_rules! jose_ecdsa_algorithm {
    ($alg:ident, $curve:ty) => {
        $crate::algorithms::jose_algorithm!(
            $alg,
            ecdsa::SigningKey<$curve>,
            ecdsa::VerifyingKey<$curve>,
            <$curve as ::ecdsa::hazmat::DigestPrimitive>::Digest,
            ::ecdsa::Signature<$curve>
        );
    };
}

#[cfg(feature = "rand")]
impl<S, C> crate::algorithms::RandomizedTokenSigner<S> for ecdsa::SigningKey<C>
where
    C: PrimeCurve + CurveArithmetic + JwkParameters + ecdsa::hazmat::DigestPrimitive,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
    S: SignatureEncoding,
    Self: RandomizedDigestSigner<C::Digest, S> + crate::algorithms::DynJsonWebAlgorithm,
{
    fn try_sign_token(
        &self,
        header: &str,
        payload: &str,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<S, signature::Error> {
        let mut digest = C::Digest::new();
        digest.update(header.as_bytes());
        digest.update(b".");
        digest.update(payload.as_bytes());

        self.try_sign_digest_with_rng(rng, digest)
    }
}

#[cfg(feature = "p256")]
jose_ecdsa_algorithm!(ES256, NistP256);

#[cfg(feature = "p384")]
jose_ecdsa_algorithm!(ES384, NistP384);

#[cfg(all(test, feature = "p256"))]
mod test {

    use super::*;
    use crate::{
        algorithms::{TokenSigner, TokenVerifier},
        key::{DeserializeJWK as _, SerializeJWK},
        SignatureBytes,
    };

    use serde_json::json;
    use static_assertions as sa;

    sa::assert_impl_all!(SigningKey<NistP256>: TokenSigner<ecdsa::Signature<NistP256>>, SerializeJWK);
    sa::assert_impl_all!(VerifyingKey<NistP256>: TokenVerifier<ecdsa::Signature<NistP256>>, SerializeJWK);

    fn strip_whitespace(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    #[test]
    fn rfc7515_example_a3_signature() {
        let pkey = json!({
        "kty":"EC",
        "crv":"P-256",
        "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
        });

        let ecpkey: elliptic_curve::JwkEcKey = serde_json::from_value(pkey.clone()).unwrap();
        let key = SigningKey::from_value(pkey).unwrap();

        assert_eq!(ecpkey.to_secret_key::<NistP256>().unwrap(), (&key).into());

        let point: EncodedPoint<NistP256> = key.verifying_key().to_encoded_point(false);
        let ecpoint: EncodedPoint<NistP256> = ecpkey.to_encoded_point::<NistP256>().unwrap();
        assert_eq!(ecpoint, point);

        let payload = strip_whitespace(
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
            cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
        );

        let header = strip_whitespace("eyJhbGciOiJFUzI1NiJ9");

        let signature: ::ecdsa::Signature<NistP256> = key.sign_token(&header, &payload);
        eprintln!("sig: {:?}", signature.to_bytes().as_slice());

        let verify = *key.verifying_key();
        assert_eq!(ecpkey.to_public_key().unwrap(), (&verify).into());

        TokenVerifier::<ecdsa::Signature<NistP256>>::verify_token(
            &verify,
            header.as_bytes(),
            payload.as_bytes(),
            signature.to_bytes().as_slice(),
        )
        .expect("signature verification for internal example failed");

        let signature = SignatureBytes::from_b64url(&strip_whitespace(
            "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
        )).unwrap();

        TokenVerifier::<SignatureBytes>::verify_token(
            &verify,
            header.as_bytes(),
            payload.as_bytes(),
            signature.to_bytes().as_ref(),
        )
        .expect("signature verification for RFC7515a3 example failed");
    }

    macro_rules! ecdsa_algorithm_test {
        ($name:ident, $curve:ty) => {
            #[cfg(feature = "rand")]
            #[test]
            fn $name() {
                let key = SigningKey::<$curve>::random(&mut rand_core::OsRng);
                let verify = *key.verifying_key();

                let payload = json! {
                    {
                        "iss": "joe",
                        "exp": 1300819380,
                        "http://example.com/is_root": true
                    }
                };

                let token = crate::Token::compact((), payload);

                let signed = token
                    .clone()
                    .sign::<_, ecdsa::Signature<$curve>>(&key)
                    .unwrap();
                let unverified = signed.unverify();
                unverified
                    .verify::<_, ecdsa::Signature<$curve>>(&verify)
                    .unwrap();

                let signed = token.clone().sign::<_, SignatureBytes>(&key).unwrap();
                let unverified = signed.unverify();
                unverified.verify::<_, SignatureBytes>(&verify).unwrap();
            }
        };
    }

    #[cfg(feature = "p256")]
    ecdsa_algorithm_test!(p256_roundtrip, NistP256);

    #[cfg(feature = "p384")]
    ecdsa_algorithm_test!(p384_roundtrip, NistP384);
}
