use jaws::algorithms::rsa::RsaPkcs1v15;
use jaws::JWTFormat;
use jaws::UnsignedToken;
use jaws::{Claims, RegisteredClaims};
use rsa::pkcs8::DecodePrivateKey;
use serde_json::json;
use sha2::Sha256;

/// This example is based on the example in RFC 7515, Appendix A.2.
fn main() {
    // This key is from the RFC.
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/rfc7515a2.pem"
    )))
    .unwrap();

    // We will sign the JWT with the RS256 algorithm: RSA with SHA-256.
    let alg = RsaPkcs1v15::<Sha256>::new_with_prefix(key);

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
    let mut token = UnsignedToken::new((), claims);
    token.header.registered.r#type = Some("JWT".to_string());

    // Sign the token with the algorithm, and print the result.
    let signed = token.sign(&alg).unwrap();
    println!("{}", signed.compact());
    println!("{}", signed.formatted());
}
