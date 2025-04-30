use std::ops::Deref;

use secp256k1::ThirtyTwoByteHash;

/// Represents a message digest, typically a 32-byte hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Message([u8; 32]);

impl ThirtyTwoByteHash for Message {
    fn into_32(self) -> [u8; 32] {
        self.0
    }
}

impl Message {
    /// Creates a new `Message` from a 32-byte array.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying 32-byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Message {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

impl Deref for Message {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
