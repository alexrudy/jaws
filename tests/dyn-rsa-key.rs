#![allow(dead_code)]

use jaws::algorithms::SignatureBytes;
use jaws::algorithms::TokenSigner;
use jaws::algorithms::TokenVerifier;
use jaws::key::SerializeJWK;
use jaws::token::{Unsigned, Unverified};
use jaws::Compact;
use jaws::JWTFormat;
use jaws::RegisteredClaims;
use rsa::pkcs8::DecodePrivateKey;
use serde_json::json;
use sha2::Sha256;

fn rsa_private() -> rsa::RsaPrivateKey {
    // This key is from RFC 7515, Appendix A.2. Provide your own key instead!
    // The key here is stored as a PKCS#8 PEM file, but you can leverage
    // RustCrypto to load a variety of other formats.
    rsa::RsaPrivateKey::from_pkcs8_pem(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/rfc7515a2.pem"
    )))
    .unwrap()
}

fn rsa_public() -> rsa::RsaPublicKey {
    let key = rsa_private();
    key.to_public_key()
}

trait TokenSigningKey: TokenSigner<SignatureBytes> + SerializeJWK {}

impl<T> TokenSigningKey for T where T: TokenSigner<SignatureBytes> + SerializeJWK {}

fn rsa_signer() -> rsa::pkcs1v15::SigningKey<Sha256> {
    rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_private())
}

fn rsa_verifier() -> rsa::pkcs1v15::VerifyingKey<Sha256> {
    rsa::pkcs1v15::VerifyingKey::new(rsa_public())
}

fn dyn_signer() -> Box<dyn TokenSigningKey> {
    Box::new(rsa_signer())
}

fn dyn_verifier() -> Box<dyn TokenVerifier<SignatureBytes>> {
    Box::new(rsa_verifier())
}

type Claims = jaws::Claims<serde_json::Value, (), String, (), ()>;
type Token<S> = jaws::Token<Claims, S, Compact>;

fn unsigned_token() -> Token<Unsigned<()>> {
    let claims = Claims {
        registered: RegisteredClaims {
            subject: "1234567890".to_string().into(),
            ..Default::default()
        },
        claims: json!({
            "name": "John Doe",
            "admin": true,
        }),
    };

    let mut token = Token::compact((), claims);
    *token.header_mut().r#type() = Some("JWT".to_string());
    token.header_mut().key().derived();
    token
}

fn roundtrip(token: Token<Unverified<()>>) -> Token<Unverified<()>> {
    let rendered = token.rendered().unwrap();
    let parsed: Token<Unverified<()>> = rendered.parse().unwrap();
    assert_eq!(token, parsed);
    parsed
}

#[test]
fn dyn_rsa_verify() {
    let token = unsigned_token();
    println!("=== Unsigned Token ===");
    println!("{}", token.formatted());
    println!(
        "Payload: {}",
        serde_json::to_string_pretty(&token.payload().unwrap()).unwrap()
    );

    let signed = token
        .sign::<_, rsa::pkcs1v15::Signature>(&rsa_signer())
        .unwrap();

    let unverified = roundtrip(signed.unverify());

    println!("=== Unverified Token ===");
    println!("{}", unverified.formatted());

    let verified = unverified
        .verify::<_, rsa::pkcs1v15::Signature>(&rsa_verifier())
        .unwrap();

    let unverified = roundtrip(verified.unverify());

    let verified = unverified
        .verify::<_, SignatureBytes>(dyn_verifier().as_ref())
        .unwrap();

    println!("=== Verified Token ===");
    println!("{}", verified.formatted());
}

#[test]
fn dyn_rsa_sign() {
    let token = unsigned_token();
    println!("=== Unsigned Token ===");
    println!("{}", token.formatted());
    println!(
        "Payload: {}",
        serde_json::to_string_pretty(&token.payload().unwrap()).unwrap()
    );

    let signed = token
        .sign::<_, SignatureBytes>(dyn_signer().as_ref())
        .unwrap();

    let unverified = roundtrip(signed.unverify());

    println!("=== Unverified Token ===");
    println!("{}", unverified.formatted());

    let verified = unverified
        .verify::<_, rsa::pkcs1v15::Signature>(&rsa_verifier())
        .unwrap();

    let unverified = roundtrip(verified.unverify());

    let verified = unverified
        .verify::<_, SignatureBytes>(dyn_verifier().as_ref())
        .unwrap();

    println!("=== Verified Token ===");
    println!("{}", verified.formatted());
}
