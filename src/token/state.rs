use std::marker::PhantomData;

use bytes::Bytes;
use serde::Serialize;
use signature::SignatureEncoding;

use crate::{
    algorithms::{DynJoseAlgorithm, SignatureBytes},
    base64data::Base64Signature,
    jose,
};

/// A trait used to represent the state of a token with respect to
/// its signature.
pub trait MaybeSigned {
    /// The state of the header with respect to its signature.
    ///
    /// When a token is signed, some values of the header may be set
    /// based on the signing key (e.g. algorithm and key id).
    type HeaderState;

    /// The custom header type.
    ///
    /// Usually this will be a type parameter, passed in by the signature
    /// type. It is required here to allow signature-dependent serializing
    /// and deserializing.
    type Header;

    #[doc(hidden)]
    /// Get a reference to the header. The same as [`crate::Token::header`].
    fn header(&self) -> &jose::Header<Self::Header, Self::HeaderState>;

    #[doc(hidden)]
    /// Get a mutable reference to the header. The same as [`crate::Token::header_mut`].
    fn header_mut(&mut self) -> &mut jose::Header<Self::Header, Self::HeaderState>;

    /// Returns true if the token is signed.
    fn is_signed(&self) -> bool;

    /// Returns true if the token is signed and verified.
    fn is_verified(&self) -> bool;
}

/// A trait which marks a token as having a signature.
///
/// Unsigned tokens do not have a signature, and so cannot implement
/// this trait. This trait can be used to restrict tokens only to states
/// where they are signed.
pub trait HasSignature: MaybeSigned {
    /// The type of the signature, which should be representable
    /// as a byte slice.
    type Signature: SignatureEncoding;

    /// Get a reference to the signature.
    fn signature(&self) -> &Self::Signature;
}

/// This JWS token has no attached signature
///
/// This token contains just the unsigned parts which are used as the
/// input to the cryptographic signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsigned<H> {
    pub(super) header: jose::Header<H, jose::UnsignedHeader>,
}

impl<H> MaybeSigned for Unsigned<H> {
    type HeaderState = jose::UnsignedHeader;
    type Header = H;

    fn header(&self) -> &jose::Header<H, Self::HeaderState> {
        &self.header
    }

    fn is_signed(&self) -> bool {
        false
    }

    fn is_verified(&self) -> bool {
        false
    }

    fn header_mut(&mut self) -> &mut jose::Header<Self::Header, Self::HeaderState> {
        &mut self.header
    }
}

/// This JWS has been signed.
///
/// This state is used when this program applied the signature, so we know that the
/// signature is both consistent and valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(bound(serialize = "H: Serialize, Sig: Serialize",))]
pub struct Signed<H, Alg, Sig>
where
    Alg: DynJoseAlgorithm + ?Sized,
{
    pub(super) header: jose::Header<H, jose::SignedHeader>,
    pub(super) signature: Sig,

    #[serde(skip)]
    pub(super) _phantom_key: PhantomData<Alg>,
}

impl<H, Alg, Sig> HasSignature for Signed<H, Alg, Sig>
where
    Alg: DynJoseAlgorithm + ?Sized,
    Sig: SignatureEncoding,
{
    type Signature = Sig;

    fn signature(&self) -> &Self::Signature {
        &self.signature
    }
}

impl<H, Alg, Sig> MaybeSigned for Signed<H, Alg, Sig>
where
    Alg: DynJoseAlgorithm + ?Sized,
{
    type HeaderState = jose::SignedHeader;
    type Header = H;

    fn header(&self) -> &jose::Header<H, Self::HeaderState> {
        &self.header
    }

    fn header_mut(&mut self) -> &mut jose::Header<Self::Header, Self::HeaderState> {
        &mut self.header
    }

    fn is_signed(&self) -> bool {
        true
    }

    fn is_verified(&self) -> bool {
        true
    }
}

/// This JWS has been verified.
///
/// This state is used when this program has verified the signature, so we know that the
/// signature is valid and consistent with the header values. However, we also know that
/// we did not create the token, and modifying it may result in headers which are not
/// consistent with the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(bound(serialize = "H: Serialize, Sig: Serialize",))]
pub struct Verified<H, Alg, Sig>
where
    Alg: DynJoseAlgorithm + ?Sized,
{
    pub(super) header: jose::Header<H, jose::SignedHeader>,
    pub(super) signature: Sig,

    #[serde(skip)]
    pub(super) _phantom_key: PhantomData<Alg>,
}

impl<H, Alg, Sig> MaybeSigned for Verified<H, Alg, Sig>
where
    Alg: DynJoseAlgorithm + ?Sized,
{
    type HeaderState = jose::SignedHeader;
    type Header = H;

    fn header_mut(&mut self) -> &mut jose::Header<Self::Header, Self::HeaderState> {
        &mut self.header
    }

    fn header(&self) -> &jose::Header<H, Self::HeaderState> {
        &self.header
    }

    fn is_signed(&self) -> bool {
        true
    }

    fn is_verified(&self) -> bool {
        true
    }
}

impl<H, Alg, Sig> HasSignature for Verified<H, Alg, Sig>
where
    Alg: DynJoseAlgorithm + ?Sized,
    Sig: SignatureEncoding,
{
    type Signature = Sig;

    fn signature(&self) -> &Self::Signature {
        &self.signature
    }
}

/// This JWS has not been verified. It has a signature, but we have not checked it.
///
/// This state indicates that we have recieved the token from elsewhere, and
/// many fields could be in inconsistnet states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unverified<H> {
    pub(super) payload: Bytes,
    pub(super) header: jose::Header<H, jose::RenderedHeader>,
    pub(super) signature: Base64Signature<SignatureBytes>,
}

impl<H> MaybeSigned for Unverified<H> {
    type HeaderState = jose::RenderedHeader;
    type Header = H;

    fn header_mut(&mut self) -> &mut jose::Header<Self::Header, Self::HeaderState> {
        &mut self.header
    }

    fn header(&self) -> &jose::Header<H, Self::HeaderState> {
        &self.header
    }

    fn is_signed(&self) -> bool {
        true
    }

    fn is_verified(&self) -> bool {
        false
    }
}

impl<H> HasSignature for Unverified<H> {
    type Signature = SignatureBytes;

    fn signature(&self) -> &Self::Signature {
        &self.signature.0
    }
}
