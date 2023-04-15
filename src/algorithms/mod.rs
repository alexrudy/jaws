use serde::{Deserialize, Serialize};

use crate::key;

pub mod ecdsa;
pub mod hmac;
pub mod rsa;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum AlgorithmIdentifier {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
    PS256,
    PS384,
    PS512,
    EdDSA,
    #[serde(rename = "none")]
    None,
}

pub trait Algorithm {
    const IDENTIFIER: AlgorithmIdentifier;
}

pub trait SigningAlgorithm: Algorithm {
    type Error;
    type Signature: AsRef<[u8]>;
    type Key: key::KeyInfo;

    fn sign(&self, header: &str, payload: &str) -> Result<Self::Signature, Self::Error>;
    fn key(&self) -> &Self::Key;
}
