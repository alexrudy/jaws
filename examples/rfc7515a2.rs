use jaws::Compact;
// JAWS provides JWT format for printing JWTs in a style similar to the example above,
// which is directly inspired by the way the ACME standard shows JWTs.
use jaws::JWTFormat;

// JAWS provides strongly typed support for tokens, so we can only build an UnsignedToken,
// which we can sign to create a SignedToken or a plain Token.
use jaws::Token;

// JAWS provides type-safe support for JWT claims.
use jaws::{Claims, RegisteredClaims};

// We are going to use an RSA private key to sign our JWT, provided by
// the `rsa` crate in the RustCrypto suite.
use rsa::pkcs8::DecodePrivateKey;

// The signing algorithm we will use (`RS256`) relies on the SHA-256 hash
// function, so we get it here from the `sha2` crate in the RustCrypto suite.
use sha2::Sha256;

// JAWS provides thin algorithm wrappers for algorithms which accept
// parameters beyond just the encryption or singing key. For example, the `RS256`
// algorithm accepts a hash function, but is otherwise identical to the other
// `RS*` hash functions.
use jaws::algorithms::rsa::RsaPkcs1v15;

// Using serde_json allows us to quickly construct a serializable payload,
// but applications may want to instead define a struct and use serde to
// derive serialize and deserialize for added type safety.
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // This key is from RFC 7515, Appendix A.2. Provide your own key instead!
    // The key here is stored as a PKCS#8 PEM file, but you can leverage
    // RustCrypto to load a variety of other formats.
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/rfc7515a2.pem"
    )))
    .unwrap();

    // We will sign the JWT with the RS256 algorithm: RSA with SHA-256.
    // RsaPkcs1v15 is really an alias to the digital signature algorithm
    // implementation in the `rsa` crate, but provided in JAWS to make
    // it clear which types are compatible with JWTs.
    let alg = RsaPkcs1v15::<Sha256>::new_with_prefix(key);

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
    let mut token = Token::new((), claims, Compact::default());
    // We can modify the headers freely before signing the JWT. In this case,
    // we provide the `typ` header, which is optional in the JWT spec.
    token.header_mut().registered.r#type = Some("JWT".to_string());

    // Sign the token with the algorithm, and print the result.
    let signed = token.sign(&alg).unwrap();

    // We can't modify the token after signing it (that would change the signature)
    // but we can access fields and read from them:
    println!(
        "Type: {:?}, Algorithm: {:?}",
        signed.header().registered.r#type,
        signed.header().algorithm(),
    );

    println!("Token: {}", signed.rendered().unwrap());
    println!("JWT:");
    println!("{}", signed.formatted());

    Ok(())
}
