use jaws::Compact;
use jaws::JWTFormat;
use jaws::Token;
use rsa::pkcs8::DecodePrivateKey;
use serde_json::json;
use sha2::Sha256;

/// Create a JWT suitable as a new-account request in the ACME protocol.
///
/// The resulting JWT should look like this (in the example format from RFC8555):
/// ```
/// POST /acme/new-account HTTP/1.1
/// Host: example.com
/// Content-Type: application/jose+json
///
/// {
///   "protected": base64url({
///     "alg": "RS256",
///     "jwk": {...
///     },
///     "nonce": "6S8IqOGY7eL2lsGoTZYifg",
///     "url": "https://example.com/acme/new-account"
///   }),
///   "payload": base64url({
///     "termsOfServiceAgreed": true,
///     "contact": [
///       "mailto:cert-admin@example.org",
///       "mailto:admin@example.org"
///     ]
///   }),
///   "signature": "RZPOnYoPs1PhjszF...-nh6X1qtOFPB519I"
/// }
/// ```
///
/// For a more detailed explanation, see `rfc7515a2.rs`.
fn main() {
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

    let payload = json!({
      "termsOfServiceAgreed": true,
      "contact": [
        "mailto:cert-admin@example.org",
        "mailto:admin@example.org"
      ]
    });

    let header = json!({
        "nonce": "6S8IqOGY7eL2lsGoTZYifg",
        "url": "https://example.com/acme/new-account"
    });

    // Create a token with the default headers, and no custom headers.
    let mut token = Token::new(payload, header, Compact);
    // Request that the token header include a JWK field.
    token.header_mut().key().derived();

    // Sign the token with the algorithm and key we specified above.
    let signed = token.sign::<_, rsa::pkcs1v15::Signature>(&alg).unwrap();

    // Print the token in the ACME example format.
    println!("{}", signed.formatted());
}
