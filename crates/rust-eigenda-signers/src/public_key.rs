use std::fmt::{self, Display};

use ethereum_types::H160;
use thiserror::Error;

/// Represents a secp256k1 public key in uncompressed format (65 bytes, starting with 0x04).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey(secp256k1::PublicKey);

impl From<::secp256k1::PublicKey> for PublicKey {
    fn from(value: ::secp256k1::PublicKey) -> Self {
        Self(value)
    }
}

/// Errors that can occur when parsing a PublicKey.
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("Invalid secp256k1 point")]
    InvalidPoint,
}

impl PublicKey {
    /// Creates a new `PublicKey` from a 65-byte array representing the uncompressed key.
    ///
    /// Validates that the point is a valid secp256k1 public key.
    pub fn new(bytes: [u8; 65]) -> Result<Self, Error> {
        let key = secp256k1::PublicKey::from_slice(&bytes).map_err(|_| Error::InvalidPoint)?;
        Ok(Self(key))
    }

    /// Returns the public key as a 65-byte array (uncompressed format).
    pub fn serialize_uncompressed(&self) -> [u8; 65] {
        self.0.serialize_uncompressed()
    }

    /// Computes the Ethereum address associated with this public key.
    pub fn address(&self) -> H160 {
        // Ethereum address is the last 20 bytes of the Keccak256 hash
        // of the uncompressed public key (excluding the prefix 0x04)
        let hash = keccak256(&self.serialize_uncompressed()[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        address.into()
    }

    pub fn account_id(&self) -> String {
        let hex = hex::encode(self.serialize_uncompressed());

        format!("0x{}", hex)
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.serialize_uncompressed()))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self)
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*; // Import PublicKey, PublicKeyError, etc.

    // Example **valid** uncompressed public key bytes derived from a known private key
    // SK = 1
    const VALID_PK_BYTES: [u8; 65] = [
        0x04, // Prefix
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98, // x
        0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08,
        0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10,
        0xd4, 0xb8, // y
    ];
    const EXPECTED_UNCOMPRESSED_PUB_KEY: &str = "0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    const EXPECTED_ADDRESS: &str = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"; // Address for SK=1

    // Example invalid bytes (correct format, but not on curve - x=1, y=1)
    const INVALID_POINT_BYTES: [u8; 65] = {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x04;
        bytes[32] = 0x01; // x=1
        bytes[64] = 0x01; // y=1 (1*1 != 1*1*1 + 7)
        bytes
    };

    #[test]
    fn test_new_valid() {
        // Given
        let bytes = VALID_PK_BYTES;

        // When
        let pk = PublicKey::new(bytes).expect("bytes to be valid");

        // Then
        assert_eq!(pk.serialize_uncompressed(), bytes);
    }

    #[test]
    fn test_new_invalid_point() {
        // Given
        let bytes = INVALID_POINT_BYTES;

        // When
        let result = PublicKey::new(bytes);

        // Then
        assert!(result.is_err());
    }

    #[test]
    fn test_to_bytes() {
        // Given
        let bytes = VALID_PK_BYTES;
        let pk = PublicKey::new(bytes).unwrap();

        // When
        let retrieved_bytes = pk.serialize_uncompressed();

        // Then
        assert_eq!(retrieved_bytes, bytes);
    }

    #[test]
    fn test_address_calculation() {
        // Given
        let pk = PublicKey::new(VALID_PK_BYTES).unwrap();
        let expected_addr = H160::from_str(EXPECTED_ADDRESS.trim_start_matches("0x")).unwrap();

        // When
        let computed_addr = pk.address();

        // Then
        assert_eq!(computed_addr, expected_addr);
    }

    #[test]
    fn test_debug_format() {
        // Given
        let pk = PublicKey::new(VALID_PK_BYTES).unwrap();
        let expected_debug = format!("PublicKey({EXPECTED_UNCOMPRESSED_PUB_KEY})");

        // When
        let debug_str = format!("{:?}", pk);

        // Then
        assert_eq!(debug_str, expected_debug);
    }

    #[test]
    fn test_account_id_calculation() {
        // Given
        let pk = PublicKey::new(VALID_PK_BYTES).unwrap();
        let expected_account_id = EXPECTED_UNCOMPRESSED_PUB_KEY;

        // When
        let computed_account_id = pk.account_id();

        // Then
        assert_eq!(computed_account_id, expected_account_id);
    }
}
