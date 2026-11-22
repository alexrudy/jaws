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
use pkcs8::AssociatedOid;
use rsa::BoxedUint;
use rsa::PrivateKey;
use rsa::traits::PrivateKeyParts;
use rsa::traits::PublicKeyParts;
#[cfg(feature = "pss")]
use signature::RandomizedDigestSigner;

pub use rsa::pkcs1v15;
pub use rsa::pss;

#[cfg(feature = "pss")]
use crate::SignatureBytes;
use crate::key::DeserializeJWK;
use crate::key::KeyType;
use crate::key::Parameters;

impl crate::key::JWKeyType for rsa::PublicKey {
    const KEY_TYPE: KeyType = KeyType::Rsa;
}

impl crate::key::SerializeJWK for rsa::PublicKey {
    fn parameters(&self) -> Parameters {
        let mut params = Parameters::new();

        let n = Base64UrlUnpadded::encode_string(&self.n().to_be_bytes_trimmed_vartime());
        params.insert("n", n);
        let e = Base64UrlUnpadded::encode_string(&self.e().to_be_bytes_trimmed_vartime());
        params.insert("e", e);

        params
    }
}

fn strip_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

fn to_biguint(v: &serde_json::Value) -> Option<BoxedUint> {
    use crypto_bigint::Encoding;

    let val = strip_whitespace(v.as_str()?);
    Some(BoxedUint::from_be_bytes(
        base64ct::Base64UrlUnpadded::decode_vec(&val).ok()?.into(),
    ))
}

fn rsa_key_parameter(
    parameters: &Parameters,
    name: &'static str,
) -> Result<BoxedUint, crate::key::JsonWebKeyError> {
    let val = parameters
        .get(name)
        .ok_or(crate::key::JsonWebKeyError::MissingParameter(name))?;
    to_biguint(val).ok_or(crate::key::JsonWebKeyError::MissingParameter(name))
}

impl crate::key::DeserializeJWK for rsa::PublicKey {
    fn build(parameters: Parameters) -> Result<Self, crate::key::JsonWebKeyError>
    where
        Self: Sized,
    {
        let n = rsa_key_parameter(&parameters, "n")?;
        let e = rsa_key_parameter(&parameters, "e")?;

        rsa::PublicKey::new(n, e)
            .map_err(|error| crate::key::JsonWebKeyError::InvalidKey("RSA", error.into()))
    }
}

impl crate::key::JWKeyType for rsa::PrivateKey {
    const KEY_TYPE: KeyType = KeyType::Rsa;
}

impl crate::key::SerializeJWK for rsa::PrivateKey {
    fn parameters(&self) -> Parameters {
        fn from_biguint(n: &BoxedUint) -> String {
            let bytes = n.to_be_bytes_trimmed_vartime();
            Base64UrlUnpadded::encode_string(&bytes)
        }

        let mut params = self.to_public_key().parameters();
        params.insert("d", from_biguint(self.d()));

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
            additional_params.push(("qi".into(), from_biguint(&qi.retrieve()).into()));
        } else {
            additional_params.clear();
        }

        #[allow(unused)]
        for (prime, crt) in primes.zip(self.crt_values()) {
            todo!("Support for multiple primes is not yet implemented");
        }

        params.extend(additional_params);

        params
    }
}

impl DeserializeJWK for PrivateKey {
    fn build(parameters: Parameters) -> Result<Self, crate::key::JsonWebKeyError>
    where
        Self: Sized,
    {
        fn validate_key_parameter(
            parameters: &Parameters,
            name: &'static str,
            precomputed: Option<&BoxedUint>,
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

        let key = PrivateKey::from_components(n, e, d, primes)
            .map_err(|error| crate::key::JsonWebKeyError::InvalidKey("RSA", error.into()))?;

        key.validate()
            .map_err(|error| crate::key::JsonWebKeyError::InvalidKey("RSA", error.into()))?;

        validate_key_parameter(&parameters, "dp", key.dp())?;
        validate_key_parameter(&parameters, "dq", key.dq())?;
        validate_key_parameter(
            &parameters,
            "qi",
            key.qinv().map(|inv| inv.retrieve()).as_ref(),
        )?;

        Ok(key)
    }
}

impl<D> crate::key::JWKeyType for rsa::pkcs1v15::SigningKey<D>
where
    D: digest::Digest,
{
    const KEY_TYPE: KeyType = KeyType::Rsa;
}

impl<D> crate::key::SerializeJWK for rsa::pkcs1v15::SigningKey<D>
where
    D: digest::Digest,
{
    fn parameters(&self) -> Parameters {
        self.as_ref().parameters()
    }
}

impl<D> crate::key::DeserializeJWK for rsa::pkcs1v15::SigningKey<D>
where
    D: digest::Digest + AssociatedOid,
{
    fn build(parameters: Parameters) -> Result<Self, crate::key::JsonWebKeyError> {
        rsa::PrivateKey::build(parameters).map(Into::into)
    }
}

impl<D> crate::key::JWKeyType for rsa::pkcs1v15::VerifyingKey<D>
where
    D: digest::Digest,
{
    const KEY_TYPE: KeyType = KeyType::Rsa;
}

impl<D> crate::key::SerializeJWK for rsa::pkcs1v15::VerifyingKey<D>
where
    D: digest::Digest,
{
    fn parameters(&self) -> Parameters {
        self.as_ref().parameters()
    }
}

impl<D> crate::key::DeserializeJWK for rsa::pkcs1v15::VerifyingKey<D>
where
    D: digest::Digest + AssociatedOid,
{
    fn build(parameters: Parameters) -> Result<Self, crate::key::JsonWebKeyError> {
        rsa::PublicKey::build(parameters).map(Into::into)
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

impl<D> crate::key::JWKeyType for rsa::pss::VerifyingKey<D>
where
    D: signature::digest::Digest,
{
    const KEY_TYPE: KeyType = KeyType::Rsa;
}

impl<D> crate::key::SerializeJWK for rsa::pss::VerifyingKey<D>
where
    D: signature::digest::Digest,
{
    fn parameters(&self) -> Parameters {
        self.as_ref().parameters()
    }
}

impl<D> crate::key::DeserializeJWK for rsa::pss::VerifyingKey<D>
where
    D: signature::digest::Digest,
{
    fn build(parameters: Parameters) -> Result<Self, crate::key::JsonWebKeyError> {
        rsa::PublicKey::build(parameters).map(Into::into)
    }
}

#[cfg(feature = "pss")]
impl<D> crate::key::JWKeyType for rsa::pss::SigningKey<D>
where
    D: signature::digest::Digest,
{
    const KEY_TYPE: KeyType = KeyType::Rsa;
}

#[cfg(feature = "pss")]
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
            fn try_sign_digest_with_rng<
                R: rand_core::TryCryptoRng + ?Sized,
                F: Fn(&mut $digest) -> Result<(), ::signature::Error>,
            >(
                &self,
                rng: &mut R,
                f: F,
            ) -> Result<SignatureBytes, signature::Error> {
                use signature::SignatureEncoding;

                let signature: rsa::pss::Signature = self.try_sign_digest_with_rng(rng, f)?;
                Ok(signature.to_bytes().as_ref().into())
            }
        }

        impl signature::DigestVerifier<$digest, SignatureBytes> for rsa::pss::VerifyingKey<$digest>
        where
            Self: signature::DigestVerifier<$digest, rsa::pss::Signature>
                + crate::algorithms::DynJsonWebAlgorithm,
        {
            fn verify_digest<F: Fn(&mut $digest) -> Result<(), ::signature::Error>>(
                &self,
                f: F,
                signature: &SignatureBytes,
            ) -> Result<(), signature::Error> {
                use signature::SignatureEncoding;

                let signature: rsa::pss::Signature = signature
                    .to_bytes()
                    .as_ref()
                    .try_into()
                    .map_err(signature::Error::from_source)?;

                self.verify_digest(f, &signature)
            }
        }
    };
}

#[cfg(feature = "pss")]
rsa_pss_algorithm!(PS256, sha2::Sha256);
#[cfg(feature = "pss")]
rsa_pss_algorithm!(PS384, sha2::Sha384);
#[cfg(feature = "pss")]
rsa_pss_algorithm!(PS512, sha2::Sha512);

#[cfg(feature = "pss")]
impl<D> crate::key::SerializeJWK for rsa::pss::SigningKey<D>
where
    D: signature::digest::Digest,
{
    fn parameters(&self) -> Parameters {
        self.as_ref().parameters()
    }
}

#[cfg(feature = "pss")]
impl<D> crate::key::DeserializeJWK for rsa::pss::SigningKey<D>
where
    D: signature::digest::Digest,
{
    fn build(parameters: Parameters) -> Result<Self, crate::key::JsonWebKeyError>
    where
        Self: Sized,
    {
        let key = rsa::PrivateKey::build(parameters)?;

        Ok(rsa::pss::SigningKey::new(key))
    }
}

#[cfg(feature = "pss")]
impl<S, D> crate::algorithms::RandomizedTokenSigner<S> for rsa::pss::SigningKey<D>
where
    D: digest::Digest + digest::Update,
    S: signature::SignatureEncoding,
    Self: RandomizedDigestSigner<D, S> + crate::algorithms::DynJsonWebAlgorithm,
{
    fn try_sign_token(
        &self,
        header: &str,
        payload: &str,
        rng: &mut impl rand_core::TryCryptoRng,
    ) -> Result<S, signature::Error> {
        self.try_sign_digest_with_rng(rng, |digest| {
            use digest::Update;
            Update::update(digest, header.as_bytes());
            Update::update(digest, b".");
            Update::update(digest, payload.as_bytes());
            Ok(())
        })
    }
}

#[cfg(feature = "pss")]
impl<S, D> crate::algorithms::TokenVerifier<S> for rsa::pss::VerifyingKey<D>
where
    D: digest::Digest + digest::Update,
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

        let signature = signature
            .try_into()
            .map_err(signature::Error::from_source)?;

        self.verify_digest(
            |digest| {
                use digest::Update;
                Update::update(digest, header);
                Update::update(digest, b".");
                Update::update(digest, payload);
                Ok(())
            },
            &signature,
        )?;
        Ok(signature)
    }
}

#[cfg(test)]
mod test {

    use crate::SignatureBytes;
    use crate::TokenSigner;
    use crate::key::DeserializeJWK;
    use crate::key::SerializeJWK;

    use base64ct::Encoding as _;
    use serde_json::json;
    use sha2::Sha256;
    use signature::Keypair;
    use signature::SignatureEncoding;

    fn strip_whitespace(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    fn rsa(jwk: serde_json::Value) -> rsa::PrivateKey {
        rsa::PrivateKey::from_value(jwk).unwrap()
    }

    pub(super) fn jwk() -> serde_json::Value {
        crate::key::fixtures::rfc7515_a2()
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

                let key_r = algorithm.to_jwk().unwrap();
                let key_b = rsa::pkcs1v15::SigningKey::<$digest>::from_jwk(&key_r).unwrap();
                assert_eq!(key_b, algorithm);
            }
        };
    }

    rsa_pkcs1v15_algorithm_test!(rs256_algorithm, sha2::Sha256);
    rsa_pkcs1v15_algorithm_test!(rs384_algorithm, sha2::Sha384);
    rsa_pkcs1v15_algorithm_test!(rs512_algorithm, sha2::Sha512);

    #[cfg(feature = "pss")]
    mod pss {
        use rand::rngs::SysRng;
        use serde_json::json;
        use signature::Keypair;
        use signature::SignatureEncoding;

        use crate::SignatureBytes;
        use crate::key::DeserializeJWK;
        use crate::key::SerializeJWK;

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
                .sign_randomized::<_, S>(sign, &mut SysRng)
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

                    let key_r = algorithm.to_jwk().unwrap();
                    let key_b = rsa::pss::SigningKey::<$digest>::from_jwk(&key_r).unwrap();
                    assert_eq!(key_b, algorithm);
                }
            };
        }

        rsa_pss_algorithm_test!(ps256_algorithm, sha2::Sha256);
        rsa_pss_algorithm_test!(ps384_algorithm, sha2::Sha384);
        rsa_pss_algorithm_test!(ps512_algorithm, sha2::Sha512);
    }
}

#[cfg(all(test, feature = "rsa"))]
mod jwk_tests {
    use super::test::jwk as rfc7515_a2;
    use super::*;

    use crate::key::fixtures;
    use crate::key::{JsonWebKeyError, SerializeJWK};

    use serde_json::{Value, json};
    use signature::Keypair;

    fn without(member: &str) -> Value {
        let mut value = rfc7515_a2();
        value.as_object_mut().unwrap().remove(member);
        value
    }

    fn with(member: &str, replacement: Value) -> Value {
        let mut value = rfc7515_a2();
        value[member] = replacement;
        value
    }

    #[test]
    fn private_key_serializes_unchanged() {
        let key = rsa::PrivateKey::from_value(rfc7515_a2()).unwrap();
        let serialized = key.to_jwk().unwrap();

        assert_eq!(serialized.key_type(), "RSA");

        let mut expected = rfc7515_a2();
        expected.as_object_mut().unwrap().remove("kty");
        assert_eq!(
            serde_json::to_value(serialized.parameters()).unwrap(),
            expected
        );
    }

    #[test]
    fn public_key_serializes_only_n_and_e() {
        let key = rsa::PublicKey::from_value(rfc7515_a2()).unwrap();
        let serialized = key.to_jwk().unwrap();

        let expected = rfc7515_a2();
        assert_eq!(
            serde_json::to_value(serialized.parameters()).unwrap(),
            json!({"n": expected["n"], "e": expected["e"]})
        );
    }

    #[test]
    fn whitespace_within_members_is_ignored() {
        // RFC 7515 wraps long members across lines, so people paste them that way.
        let expected = rsa::PrivateKey::from_value(rfc7515_a2()).unwrap();

        let mut wrapped = rfc7515_a2();
        for member in ["n", "d", "p", "q", "dp", "dq", "qi"] {
            let value = wrapped[member].as_str().unwrap();
            let (head, tail) = value.split_at(value.len() / 2);
            wrapped[member] = json!(format!("{head}\n       {tail}"));
        }

        let key = rsa::PrivateKey::from_value(wrapped).unwrap();
        assert_eq!(key.parameters(), expected.parameters());
    }

    #[test]
    fn private_key_jwk_roundtrip() {
        let key = fixtures::rsa_private();
        let back = rsa::PrivateKey::from_jwk(&key.to_jwk().unwrap()).unwrap();

        assert_eq!(back.parameters(), key.parameters());
        assert_eq!(back.to_public_key(), key.to_public_key());
    }

    #[test]
    fn public_key_jwk_roundtrip() {
        let key = fixtures::rsa_private().to_public_key();
        let back = rsa::PublicKey::from_jwk(&key.to_jwk().unwrap()).unwrap();

        assert_eq!(back, key);
        assert_eq!(back.parameters(), key.parameters());
    }

    #[test]
    fn public_key_reads_private_jwk() {
        let private = fixtures::rsa_private();
        let public = rsa::PublicKey::from_jwk(&private.to_jwk().unwrap()).unwrap();

        assert_eq!(public, private.to_public_key());
    }

    #[test]
    fn private_key_without_crt_parameters_is_accepted() {
        let mut value = rfc7515_a2();
        let object = value.as_object_mut().unwrap();
        for member in ["dp", "dq", "qi"] {
            object.remove(member);
        }

        let key = rsa::PrivateKey::from_value(value).unwrap();
        assert_eq!(key.to_public_key(), fixtures::rsa_private().to_public_key());
        assert_eq!(
            key.parameters().get("d"),
            fixtures::rsa_private().parameters().get("d")
        );
    }

    #[test]
    fn missing_members_are_rejected() {
        for member in ["n", "e", "d", "p", "q"] {
            assert!(
                rsa::PrivateKey::from_value(without(member)).is_err(),
                "private key accepted without {member}"
            );
        }

        for member in ["n", "e"] {
            assert!(
                rsa::PublicKey::from_value(without(member)).is_err(),
                "public key accepted without {member}"
            );
        }
    }

    #[test]
    fn malformed_members_are_rejected() {
        for member in ["n", "e", "d", "p", "q"] {
            for bad in [json!(1), json!(null), json!("!!!"), json!("")] {
                assert!(
                    rsa::PrivateKey::from_value(with(member, bad.clone())).is_err(),
                    "private key accepted {member}={bad}"
                );
            }
        }

        for member in ["n", "e"] {
            for bad in [json!(1), json!(null), json!("!!!"), json!("")] {
                assert!(
                    rsa::PublicKey::from_value(with(member, bad.clone())).is_err(),
                    "public key accepted {member}={bad}"
                );
            }
        }
    }

    #[test]
    fn inconsistent_key_material_is_rejected() {
        let original = rfc7515_a2();

        // Valid base64url integers, but not the right ones.
        for (member, other) in [("d", "e"), ("n", "e"), ("p", "q"), ("q", "p")] {
            let value = with(member, original[other].clone());
            assert!(
                rsa::PrivateKey::from_value(value).is_err(),
                "private key accepted with {member} replaced by {other}"
            );
        }

        // Public exponent of 1.
        assert!(rsa::PublicKey::from_value(with("e", json!("AQ"))).is_err());
    }

    #[test]
    fn inconsistent_crt_parameters_are_rejected() {
        let original = rfc7515_a2();

        for (member, other) in [("dp", "dq"), ("dq", "dp"), ("qi", "dp")] {
            let value = with(member, original[other].clone());
            assert!(
                rsa::PrivateKey::from_value(value).is_err(),
                "private key accepted with {member} replaced by {other}"
            );
        }

        // The primes are interchangeable, but then the CRT parameters are wrong.
        let mut swapped = rfc7515_a2();
        swapped["p"] = original["q"].clone();
        swapped["q"] = original["p"].clone();
        assert!(rsa::PrivateKey::from_value(swapped).is_err());
    }

    #[test]
    fn other_key_types_are_rejected() {
        for kty in ["EC", "oct", "OKP"] {
            let value = with("kty", json!(kty));

            let err = rsa::PrivateKey::from_value(value.clone()).unwrap_err();
            assert!(
                matches!(err, JsonWebKeyError::KeyType { .. }),
                "{kty}: {err:?}"
            );

            let err = rsa::PublicKey::from_value(value).unwrap_err();
            assert!(
                matches!(err, JsonWebKeyError::KeyType { .. }),
                "{kty}: {err:?}"
            );
        }
    }

    #[test]
    fn unrelated_members_are_ignored() {
        let mut value = rfc7515_a2();
        let object = value.as_object_mut().unwrap();
        object.insert("kid".into(), json!("abc"));
        object.insert("use".into(), json!("sig"));
        object.insert("alg".into(), json!("RS256"));
        object.insert("key_ops".into(), json!(["sign"]));

        assert!(rsa::PrivateKey::from_value(value.clone()).is_ok());
        assert!(rsa::PublicKey::from_value(value).is_ok());
    }

    macro_rules! digest_tests {
        ($module:ident, $digest:ty) => {
            mod $module {
                use super::*;

                #[test]
                fn pkcs1v15_jwk_roundtrip() {
                    let signing =
                        rsa::pkcs1v15::SigningKey::<$digest>::new(fixtures::rsa_private());

                    let jwk = signing.to_jwk().unwrap();
                    assert_eq!(jwk.key_type(), "RSA");
                    for member in ["n", "e", "d", "p", "q"] {
                        assert!(jwk.parameters().get(member).is_some(), "{member}");
                    }

                    let back = rsa::pkcs1v15::SigningKey::<$digest>::from_jwk(&jwk).unwrap();
                    assert_eq!(back, signing);
                    assert_eq!(back.parameters(), signing.parameters());

                    let verifying = signing.verifying_key();
                    let jwk = verifying.to_jwk().unwrap();
                    assert_eq!(jwk.parameters().len(), 2, "n and e only");

                    let back = rsa::pkcs1v15::VerifyingKey::<$digest>::from_jwk(&jwk).unwrap();
                    assert_eq!(back, verifying);
                }

                #[cfg(feature = "pss")]
                #[test]
                fn pss_jwk_roundtrip() {
                    let signing = rsa::pss::SigningKey::<$digest>::new(fixtures::rsa_private());

                    let jwk = signing.to_jwk().unwrap();
                    assert_eq!(jwk.key_type(), "RSA");
                    for member in ["n", "e", "d", "p", "q"] {
                        assert!(jwk.parameters().get(member).is_some(), "{member}");
                    }

                    let back = rsa::pss::SigningKey::<$digest>::from_jwk(&jwk).unwrap();
                    assert_eq!(back, signing);
                    assert_eq!(back.parameters(), signing.parameters());

                    let verifying = signing.verifying_key();
                    let jwk = verifying.to_jwk().unwrap();
                    assert_eq!(jwk.parameters().len(), 2, "n and e only");

                    let back = rsa::pss::VerifyingKey::<$digest>::from_jwk(&jwk).unwrap();
                    assert_eq!(back, verifying);
                }

                #[test]
                fn pkcs1v15_and_pss_keys_share_rsa_parameters() {
                    let key = fixtures::rsa_private();
                    let pkcs1v15 = rsa::pkcs1v15::SigningKey::<$digest>::new(key.clone());
                    assert_eq!(pkcs1v15.parameters(), key.parameters());

                    #[cfg(feature = "pss")]
                    {
                        let pss = rsa::pss::SigningKey::<$digest>::new(key.clone());
                        assert_eq!(pss.parameters(), key.parameters());
                    }
                }
            }
        };
    }

    digest_tests!(sha256, sha2::Sha256);
    digest_tests!(sha384, sha2::Sha384);
    digest_tests!(sha512, sha2::Sha512);
}
