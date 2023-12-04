use std::fmt;

use base64ct::Encoding;
use bytes::Bytes;

pub use signature::*;

/// A signature which has not been matched to an algorithm or key.
///
/// This is a basic signature `struct` which can be used to store any signature
/// on the heap. It is used to store the signature of a JWT before it is verified,
/// or if a signature has a variable length.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SignatureBytes(Bytes);

impl SignatureBytes {
    /// Create a new signature from a base64url-encoded string.
    pub fn from_b64url(data: &str) -> std::result::Result<Self, base64ct::Error> {
        Ok(Self(Bytes::from(base64ct::Base64UrlUnpadded::decode_vec(
            data,
        )?)))
    }
}

impl fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SignatureBytes")
            .field(&base64ct::Base64UrlUnpadded::encode_string(self.0.as_ref()))
            .finish()
    }
}

impl AsRef<[u8]> for SignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for SignatureBytes {
    fn from(bytes: &[u8]) -> Self {
        SignatureBytes(bytes.to_owned().into())
    }
}

impl From<Bytes> for SignatureBytes {
    fn from(bytes: Bytes) -> Self {
        SignatureBytes(bytes)
    }
}

impl From<SignatureBytes> for Bytes {
    fn from(bytes: SignatureBytes) -> Self {
        bytes.0.clone()
    }
}

impl From<Vec<u8>> for SignatureBytes {
    fn from(bytes: Vec<u8>) -> Self {
        SignatureBytes(bytes.into())
    }
}

impl signature::SignatureEncoding for SignatureBytes {
    type Repr = Bytes;
}

#[cfg(feature = "spki")]
impl spki::SignatureBitStringEncoding for SignatureBytes {
    fn to_bitstring(&self) -> spki::der::Result<spki::der::asn1::BitString> {
        spki::der::asn1::BitString::from_bytes(self.0.as_ref())
    }
}
