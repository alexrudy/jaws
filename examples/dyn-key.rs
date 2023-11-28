use jaws::algorithms::SignatureBytes;
use jaws::algorithms::TokenSigner;
use jaws::algorithms::TokenVerifier;
use jaws::key::SerializeJWK;
use jaws::token::Unverified;
use jaws::Compact;
use jaws::JWTFormat;
use jaws::Token;
use jaws::{Claims, RegisteredClaims};
use rsa::pkcs8::DecodePrivateKey;
use serde_json::json;
use sha2::Sha256;

trait TokenSigningKey: TokenSigner<SignatureBytes> + SerializeJWK {}

impl<T> TokenSigningKey for T where T: TokenSigner<SignatureBytes> + SerializeJWK {}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // This key is from RFC 7515, Appendix A.2. Provide your own key instead!
    // The key here is stored as a PKCS#8 PEM file, but you can leverage
    // RustCrypto to load a variety of other formats.
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/rfc7515a2.pem"
    )))
    .unwrap();
    let verify_key: rsa::pkcs1v15::VerifyingKey<Sha256> =
        rsa::pkcs1v15::VerifyingKey::new(key.to_public_key());
    let verify_alg: Box<dyn TokenVerifier<SignatureBytes>> = Box::new(verify_key.clone());
    let alg: Box<dyn TokenSigningKey> =
        Box::new(rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone()));

    // Claims can combine registered and custom fields. The claims object
    // can be any type which implements [serde::Serialize].
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
    // We can modify the headers freely before signing the JWT. In this case,
    // we provide the `typ` header, which is optional in the JWT spec.
    *token.header_mut().r#type() = Some("JWT".to_string());

    // We can also ask that some fields be derived from the signing key, for example,
    // this will derive the JWK field in the header from the signing key.
    token.header_mut().key().derived();

    println!("=== {} ===", "Initial JWT");

    // Initially the JWT has no defined signature:
    println!("{}", token.formatted());

    // Sign the token with the algorithm, and print the result.
    let signed = token.sign::<_, SignatureBytes>(alg.as_ref()).unwrap();

    let rendered = signed.rendered().unwrap();

    // We can also verify tokens.
    let token: Token<Claims<serde_json::Value>, Unverified<()>, Compact> =
        rendered.parse().unwrap();

    println!("=== {} ===", "Parsed JWT");

    // Unverified tokens can be printed for debugging, but there is deliberately
    // no access to the payload, only to the header fields.
    println!("JWT:");
    println!("{}", token.formatted());

    // We can use the JWK to verify that the token is signed with the correct key.
    let hdr = token.header();
    let jwk = hdr.key().unwrap();
    let key: rsa::pkcs1v15::VerifyingKey<Sha256> = rsa::pkcs1v15::VerifyingKey::new(
        rsa_jwk_reader::rsa_pub(&serde_json::to_value(jwk).unwrap()),
    );

    println!("=== {} === ", "Verification");
    // Check it against the verified key
    token
        .clone()
        .verify::<_, rsa::pkcs1v15::Signature>(&rsa::pkcs1v15::VerifyingKey::<Sha256>::from(
            verify_key,
        ))
        .unwrap();
    println!("Verified with dyn verify key (typed)");

    // Check it against the verified key
    token
        .clone()
        .verify::<_, SignatureBytes>(verify_alg.as_ref())
        .unwrap();
    println!("Verified with dyn verify key");

    // Check it against its own JWT
    token
        .clone()
        .verify::<_, rsa::pkcs1v15::Signature>(&key)
        .unwrap();
    println!("Verified with JWT");

    // We can't access the claims until we verify the token.
    let verified = token
        .verify::<_, SignatureBytes>(verify_alg.as_ref())
        .unwrap();
    println!("Verified with original key");

    println!("=== {} ===", "Verified JWT");
    println!("JWT:");
    println!("{}", verified.formatted());
    println!(
        "Payload: \n{}",
        serde_json::to_string_pretty(&verified.payload()).unwrap()
    );

    Ok(())
}

mod rsa_jwk_reader {
    use base64ct::Encoding;

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

    pub(crate) fn rsa_pub(key: &serde_json::Value) -> rsa::RsaPublicKey {
        let n = to_biguint(&key["n"]).expect("decode n");
        let e = to_biguint(&key["e"]).expect("decode e");

        rsa::RsaPublicKey::new(n, e).expect("valid key parameters")
    }
}