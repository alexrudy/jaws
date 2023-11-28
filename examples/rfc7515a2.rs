use jaws::Compact;

// JAWS provides JWT format for printing JWTs in a style similar to the example above,
// which is directly inspired by the way the ACME standard shows JWTs.
use jaws::JWTFormat;

// JAWS provides a single token type which is generic over the state of the token.
// The states are defined in the `state` module, and are used to track the
// signing and verification status.
use jaws::Token;

// The unverified token state, used like `Token<.., Unverified<..>, ..>`.
// It is generic over the type of the custom header parameters.
use jaws::token::Unverified;

// JAWS provides type-safe support for JWT claims.
use jaws::{Claims, RegisteredClaims};

// We are going to use an RSA private key to sign our JWT, provided by
// the `rsa` crate in the RustCrypto suite.
use rsa::pkcs8::DecodePrivateKey;

// The signing algorithm we will use (`RS256`) relies on the SHA-256 hash
// function, so we get it here from the `sha2` crate in the RustCrypto suite.
use sha2::Sha256;

// Using serde_json allows us to quickly construct a serializable payload,
// but applications may want to instead define a struct and use serde to
// derive serialize and deserialize for added type safety.
use serde_json::json;

// Trait to convert a SigningKey into a VerifyingKey.
use signature::Keypair;

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
    let alg = rsa::pkcs1v15::SigningKey::<Sha256>::new(key);

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

    println!("=== Initial JWT ===");

    // Initially the JWT has no defined signature:
    println!("{}", token.formatted());

    // Sign the token with the algorithm, and print the result.
    let signed = token.sign::<_, rsa::pkcs1v15::Signature>(&alg).unwrap();

    println!("=== Signed JWT ===");

    println!("JWT:");
    println!("{}", signed.formatted());
    println!("Token: {}", signed.rendered().unwrap());

    // We can't modify the token after signing it (that would change the signature)
    // but we can access fields and read from them:
    println!(
        "Type: {:?}, Algorithm: {:?}",
        signed.header().r#type(),
        signed.header().algorithm(),
    );

    // We can also verify tokens.
    let token: Token<Claims<serde_json::Value>, Unverified<()>, Compact> =
        signed.rendered().unwrap().parse().unwrap();

    println!("=== Parsed JWT ===");

    // Unverified tokens can be printed for debugging, but there is deliberately
    // no access to the payload, only to the header fields.
    println!("JWT:");
    println!("{}", token.formatted());

    // We can use the JWK to verify that the token is signed with the correct key.
    let hdr = token.header();
    let jwk = hdr.key().unwrap();
    let key = rsa_jwk_reader::rsa_pub(&serde_json::to_value(jwk).unwrap());

    assert_eq!(&key, alg.verifying_key().as_ref());
    println!("=== Verification === ");

    // let alg: rsa::pkcs1v15::VerifyingKey<Sha256> = rsa::pkcs1v15::VerifyingKey::new(key);
    let alg: rsa::pkcs1v15::VerifyingKey<Sha256> = alg.verifying_key();

    // We can't access the claims until we verify the token.
    // let verified = token.verify::<_, rsa::pkcs1v15::Signature>(&alg).unwrap();
    let verified = token
        .verify::<_, jaws::algorithms::SignatureBytes>(&alg)
        .unwrap();

    println!("=== Verified JWT ===");
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
