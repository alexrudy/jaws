//! Support for the "none" algorithm.

use bytes::Bytes;
use signature::Keypair;

use crate::key::{DynJwkKeyType, KeyType, Parameters, PrivateWebKey, PublicWebKey, SerializeJWK};

use super::{AlgorithmIdentifier, JsonWebAlgorithm, SignatureBytes, TokenSigner, TokenVerifier};

/// Represents the "none" algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoneAlgorithm;

impl JsonWebAlgorithm for NoneAlgorithm {
    const IDENTIFIER: AlgorithmIdentifier = AlgorithmIdentifier::None;
}

impl DynJwkKeyType for NoneAlgorithm {
    fn key_type(&self) -> KeyType {
        panic!("No JWK key type for algorithm 'none'")
    }
}

impl SerializeJWK for NoneAlgorithm {
    fn parameters(&self) -> Parameters {
        panic!("No JWK parameters for algorithm 'none'")
    }
}

impl Keypair for NoneAlgorithm {
    type VerifyingKey = NoneAlgorithm;

    fn verifying_key(&self) -> Self::VerifyingKey {
        *self
    }
}

impl TokenSigner for NoneAlgorithm {
    #[expect(unused_variables)]
    fn try_sign_token(
        &self,
        header: &str,
        payload: &str,
    ) -> Result<super::SignatureBytes, signature::Error> {
        Ok(super::SignatureBytes::from(Bytes::new()))
    }
}

impl TokenVerifier for NoneAlgorithm {
    #[expect(unused_variables)]
    fn verify_token(
        &self,
        header: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<SignatureBytes, signature::Error> {
        if !signature.is_empty() {
            return Err(signature::Error::new());
        }

        Ok(super::SignatureBytes::from(Bytes::new()))
    }
}

impl TryFrom<NoneAlgorithm> for PublicWebKey {
    type Error = crate::key::JsonWebKeyError;

    fn try_from(_: NoneAlgorithm) -> Result<Self, Self::Error> {
        Err(crate::key::JsonWebKeyError::UnsupportedAlgorithm(
            AlgorithmIdentifier::None,
        ))
    }
}

impl TryFrom<NoneAlgorithm> for PrivateWebKey {
    type Error = crate::key::JsonWebKeyError;

    fn try_from(_: NoneAlgorithm) -> Result<Self, Self::Error> {
        Err(crate::key::JsonWebKeyError::UnsupportedAlgorithm(
            AlgorithmIdentifier::None,
        ))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "fmt")]
    use crate::JWTFormat;
    use crate::Token;
    use serde_json::json;
    use signature::SignatureEncoding;

    use super::*;

    #[test]
    fn test_try_sign_token() {
        let header = "eyJhbGciOiJub25lIn0";
        let payload = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

        let algorithm = NoneAlgorithm;
        let result = algorithm.try_sign_token(header, payload);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_bytes(), Bytes::new());

        let result = algorithm.verify_token(header.as_bytes(), payload.as_bytes(), &[]);
        assert!(result.is_ok());

        let non_empty_result = algorithm.verify_token(header.as_bytes(), payload.as_bytes(), &[0]);
        assert!(non_empty_result.is_err());
    }

    #[test]
    fn test_token_verifier() {
        let header = "eyJhbGciOiJub25lIn0";
        let payload = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

        let token: Token<serde_json::Value, crate::token::Unverified<()>> =
            format!("{header}.{payload}.").parse().unwrap();

        #[cfg(feature = "fmt")]
        eprintln!("{}", token.formatted());

        let algorithm = NoneAlgorithm;
        let verified = token.verify(&algorithm).unwrap();

        assert_eq!(
            verified.payload().unwrap(),
            &json!(
                {"iss":"joe",
                      "exp":1300819380,
                      "http://example.com/is_root":true}
            )
        );
    }
}
