use std::ops::Add;

use base64ct::Encoding;
use digest::generic_array::ArrayLength;
use ecdsa::{
    der::{MaxOverhead, MaxSize},
    hazmat::SignPrimitive,
    PrimeCurve, SignatureSize,
};
use elliptic_curve::{
    ops::Invert,
    sec1::{Coordinates, FromEncodedPoint, ModulusSize, ToEncodedPoint},
    subtle::CtOption,
    AffinePoint, CurveArithmetic, FieldBytesSize, JwkParameters, Scalar, SecretKey,
};

impl<C> crate::key::KeyInfo for SecretKey<C>
where
    C: PrimeCurve + CurveArithmetic + JwkParameters,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    const KEY_TYPE: &'static str = "EC";

    fn parameters(&self) -> Vec<(String, serde_json::Value)> {
        let mut params = Vec::with_capacity(2);

        params.push((
            "crv".to_owned(),
            serde_json::Value::String(C::CRV.to_owned()),
        ));
        let point = self.public_key().to_encoded_point(false);
        let Coordinates::Uncompressed { x, y } = point.coordinates() else {panic!("can't extract jwk coordinates")};

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

impl super::Algorithm for SecretKey<p256::NistP256> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::ES256;
}

impl super::Algorithm for SecretKey<p384::NistP384> {
    const IDENTIFIER: super::AlgorithmIdentifier = super::AlgorithmIdentifier::ES384;
}

impl<C> super::SigningAlgorithm for SecretKey<C>
where
    C: PrimeCurve + CurveArithmetic + JwkParameters + ecdsa::hazmat::DigestPrimitive,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    MaxSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
    SecretKey<C>: super::Algorithm,
    <FieldBytesSize<C> as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
{
    type Error = ecdsa::Error;
    type Signature = ecdsa::SignatureBytes<C>;
    type Key = SecretKey<C>;

    fn sign(&self, header: &str, payload: &str) -> Result<Self::Signature, Self::Error> {
        let message = format!("{}.{}", header, payload);

        <::ecdsa::SigningKey<C> as signature::Signer<::ecdsa::Signature<C>>>::try_sign(
            &self.into(),
            message.as_bytes(),
        )
        .map(|sig| sig.to_bytes())
    }

    fn key(&self) -> &Self::Key {
        self
    }
}
