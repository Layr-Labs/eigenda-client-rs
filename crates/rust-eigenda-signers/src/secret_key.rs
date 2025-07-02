use std::{fmt, str::FromStr};

use secp256k1::SECP256K1;
use thiserror::Error;

use crate::PublicKey;

/// Represents a secret key (a 32-byte scalar).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecretKey(::secp256k1::SecretKey);

impl FromStr for SecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // drop 0x prefix if present
        let s = s.strip_prefix("0x").unwrap_or(s);
        let key = ::secp256k1::SecretKey::from_str(s).map_err(|_| Error::InvalidValue)?;

        Ok(Self(key))
    }
}

/// Errors that can occur when creating a SecretKey.
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("Invalid secret key value (zero or >= curve order)")]
    InvalidValue,
}

impl From<::secp256k1::SecretKey> for crate::SecretKey {
    fn from(value: ::secp256k1::SecretKey) -> Self {
        Self(value)
    }
}

impl From<crate::SecretKey> for ::secp256k1::SecretKey {
    fn from(value: crate::SecretKey) -> Self {
        value.0
    }
}

impl SecretKey {
    /// Creates a new `SecretKey` from a 32-byte array.
    ///
    /// Validates that the bytes represent a valid secp256k1 scalar (non-zero and < curve order `n`).
    pub fn new(bytes: [u8; 32]) -> Result<Self, Error> {
        match secp256k1::SecretKey::from_slice(&bytes) {
            Ok(key) => Ok(Self(key)),
            Err(_) => Err(Error::InvalidValue),
        }
    }

    /// Returns the secret key as a 32-byte array.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.0.secret_bytes()
    }

    pub fn public_key(&self) -> PublicKey {
        let pub_key = secp256k1::PublicKey::from_secret_key(SECP256K1, &self.0);
        pub_key.into()
    }

    pub fn random<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        Self(secp256k1::SecretKey::new(rng))
    }
}

// Implement Debug carefully to avoid leaking the key
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Avoid printing the actual key material
        write!(f, "SecretKey([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::constants::SECRET_KEY_SIZE;

    use super::*;

    // A known valid secret key (scalar = 1)
    const VALID_SK_BYTES: [u8; 32] = {
        let mut bytes = [0u8; SECRET_KEY_SIZE];
        bytes[SECRET_KEY_SIZE - 1] = 1;
        bytes
    };

    // An invalid secret key (scalar = 0)
    const INVALID_SK_BYTES_ZERO: [u8; 32] = [0u8; SECRET_KEY_SIZE];

    // An invalid secret key (scalar = n, the curve order)
    const INVALID_SK_BYTES_ORDER_N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];

    #[test]
    fn test_new_valid() {
        // Given
        let bytes = VALID_SK_BYTES;

        // When
        let sk = SecretKey::new(bytes).expect("Creating with valid bytes failed");

        // Then
        assert_eq!(sk.secret_bytes(), bytes);
    }

    #[test]
    fn test_new_invalid_zero() {
        // Given
        let bytes = INVALID_SK_BYTES_ZERO;

        // When
        let result = SecretKey::new(bytes);

        // Then
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::InvalidValue);
    }

    #[test]
    fn test_new_invalid_order_n() {
        // Given
        let bytes = INVALID_SK_BYTES_ORDER_N;

        // When
        let result = SecretKey::new(bytes);

        // Then
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::InvalidValue);
    }

    #[test]
    fn test_to_bytes() {
        // Given
        let bytes = VALID_SK_BYTES;
        let sk = SecretKey::new(bytes).unwrap();

        // When
        let retrieved_bytes = sk.secret_bytes();

        // Then
        assert_eq!(retrieved_bytes, bytes);
    }

    #[test]
    fn test_debug_format() {
        // Given
        let sk = SecretKey::new(VALID_SK_BYTES).unwrap();
        let expected_debug = "SecretKey([redacted])";

        // When
        let debug_str = format!("{sk:?}");

        // Then
        assert_eq!(debug_str, expected_debug);
    }
}
