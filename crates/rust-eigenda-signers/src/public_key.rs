use ethereum_types::H160;

use crate::secp256k1;
use std::convert::AsRef;
use std::hash::Hash;
use std::ops::Deref;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey(pub secp256k1::PublicKey);

impl From<secp256k1::PublicKey> for PublicKey {
    fn from(key: secp256k1::PublicKey) -> Self {
        PublicKey(key)
    }
}

impl Deref for PublicKey {
    type Target = secp256k1::PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<secp256k1::PublicKey> for PublicKey {
    fn as_ref(&self) -> &secp256k1::PublicKey {
        &self.0
    }
}

impl PublicKey {
    /// Computes the Ethereum address associated with this public key.
    pub fn address(&self) -> H160 {
        let public_key = self.0.serialize_uncompressed();
        // Ethereum address is the last 20 bytes of the Keccak256 hash
        // of the uncompressed public key (excluding the prefix 0x04)
        let hash = keccak256(&public_key[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        address.into()
    }
}

// Helper function to compute Keccak256 hash.
pub(crate) fn keccak256(input: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};

    let mut hasher = Keccak::v256();
    hasher.update(input);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}
