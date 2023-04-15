pub struct Signature(Vec<u8>);

impl zeroize::Zeroize for Signature {
    fn zeroize(&mut self) {
        for byte in self.0.iter_mut() {
            *byte = 0;
        }
    }
}

impl From<&[u8]> for Signature {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}
