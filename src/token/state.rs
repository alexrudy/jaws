use serde::{Deserialize, Serialize};

use crate::{
    algorithms::{Signature as SignatureBytes, SigningAlgorithm, VerifyAlgorithm},
    base64data::Base64Data,
    jose,
};

pub trait MaybeSigned {
    type HeaderState;
    type Header;

    fn header(&self) -> &jose::Header<Self::Header, Self::HeaderState>;
    fn header_mut(&mut self) -> &mut jose::Header<Self::Header, Self::HeaderState>;
    fn is_signed(&self) -> bool;
    fn is_verified(&self) -> bool;
}

pub trait HasSignature: MaybeSigned {
    type Signature: AsRef<[u8]>;

    fn signature(&self) -> &Self::Signature;
}

/// This JWS token has no attached signature
///
/// This token contains just the unsigned parts which are used as the
/// input to the cryptographic signature.
#[derive(Debug, Clone)]
pub struct Unsigned<H> {
    pub(super) header: jose::Header<H, jose::Unsigned>,
}

impl<H> MaybeSigned for Unsigned<H> {
    type HeaderState = jose::Unsigned;
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

#[derive(Debug, Clone, Serialize)]
#[serde(bound(serialize = "H: Serialize, Alg::Signature: Serialize, Alg::Key: Clone",))]
pub struct Signed<H, Alg>
where
    Alg: SigningAlgorithm,
{
    pub(super) header: jose::Header<H, jose::Signed<Alg::Key>>,
    pub(super) signature: Alg::Signature,
}

impl<H, Alg> HasSignature for Signed<H, Alg>
where
    Alg: SigningAlgorithm,
{
    type Signature = Alg::Signature;

    fn signature(&self) -> &Self::Signature {
        &self.signature
    }
}

impl<H, Alg> MaybeSigned for Signed<H, Alg>
where
    Alg: SigningAlgorithm,
{
    type HeaderState = jose::Signed<Alg::Key>;
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

#[derive(Debug, Clone, Serialize)]
#[serde(bound(serialize = "H: Serialize, Alg::Signature: Serialize, Alg::Key: Clone",))]
pub struct Verified<H, Alg>
where
    Alg: VerifyAlgorithm,
{
    pub(super) header: jose::Header<H, jose::Signed<Alg::Key>>,
    pub(super) signature: Alg::Signature,
}

impl<H, Alg> MaybeSigned for Verified<H, Alg>
where
    Alg: VerifyAlgorithm,
{
    type HeaderState = jose::Signed<Alg::Key>;
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

impl<H, Alg> HasSignature for Verified<H, Alg>
where
    Alg: VerifyAlgorithm,
{
    type Signature = Alg::Signature;

    fn signature(&self) -> &Self::Signature {
        &self.signature
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "H: Serialize",
    deserialize = "H: for<'deh> Deserialize<'deh>"
))]
pub struct Unverified<H> {
    pub(super) header: jose::Header<H, jose::Rendered>,
    pub(super) signature: Base64Data<SignatureBytes>,
}

impl<H> MaybeSigned for Unverified<H> {
    type HeaderState = jose::Rendered;
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
