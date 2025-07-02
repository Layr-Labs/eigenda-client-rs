use std::{convert::TryFrom, fmt};

use crate::recovery_id::{InvalidRecoveryId, RecoveryId};

/// Represents a recoverable ECDSA signature (r, s, v).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoverableSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: RecoveryId,
}

impl RecoverableSignature {
    /// Encodes the signature into a 65-byte vector [R || S || V], where V is 0 or 1.
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut signature = [0u8; 65];
        signature[0..32].copy_from_slice(&self.r);
        signature[32..64].copy_from_slice(&self.s);
        signature[64] = self.v.to_byte();
        signature
    }

    /// Attempts to parse a `RecoverableSignature` from a 65-byte slice [R || S || V].
    ///
    /// # Errors
    ///
    /// Returns `InvalidRecoveryId` if the recovery ID byte (last byte) is not 0 or 1.
    pub fn from_bytes(bytes: &[u8; 65]) -> Result<Self, InvalidRecoveryId> {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[0..32]);
        s.copy_from_slice(&bytes[32..64]);
        let v_byte = bytes[64];
        let v = RecoveryId::try_from(v_byte)?;
        Ok(Self { r, s, v })
    }
}

impl fmt::Display for RecoverableSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display as hex string [r || s || v]
        write!(f, "0x{}", hex::encode(self.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery_id::RecoveryId;

    #[test]
    fn test_to_bytes_encodes_rsv_correctly() {
        // Given
        let r = sample_r();
        let s = sample_s();
        let v = sample_v1();
        let sig = RecoverableSignature { r, s, v };

        // When
        let bytes = sig.to_bytes();

        // Then
        assert_eq!(bytes.len(), 65, "Encoded length should be 65");
        assert_eq!(&bytes[..32], &r, "R bytes mismatch");
        assert_eq!(&bytes[32..64], &s, "S bytes mismatch");
        assert_eq!(bytes[64], v.to_byte(), "V byte mismatch");
    }

    #[test]
    fn test_from_bytes_parses_valid_bytes_correctly() {
        // Given
        let r = sample_r();
        let s = sample_s();
        let v = sample_v0();
        let original_sig = RecoverableSignature { r, s, v };
        let bytes = original_sig.to_bytes();

        // When
        let parsed_sig =
            RecoverableSignature::from_bytes(&bytes).expect("Parsing valid bytes failed");

        // Then
        assert_eq!(
            parsed_sig, original_sig,
            "Parsed signature does not match original"
        );
    }

    #[test]
    fn test_from_bytes_rejects_invalid_v() {
        // Given
        let r = sample_r();
        let s = sample_s();
        let v = sample_v0(); // A valid v to construct initial bytes
        let sig = RecoverableSignature { r, s, v };
        let mut bytes = sig.to_bytes();
        bytes[64] = 2; // Invalid v value

        // When
        let result = RecoverableSignature::from_bytes(&bytes);

        // Then
        assert!(result.is_err(), "Parsing should fail for invalid v");
        assert_eq!(
            result.unwrap_err(),
            InvalidRecoveryId(2),
            "Error type mismatch"
        );
    }

    #[test]
    fn test_display_formats_as_hex_rsv() {
        // Given
        let r = sample_r();
        let s = sample_s();
        let v = sample_v1();
        let sig = RecoverableSignature { r, s, v };

        // When
        let display_str = format!("{sig}");

        // Then
        assert_eq!(display_str, "0x11000000000000000000000000000000000000000000000000000000000000aa22000000000000000000000000000000000000000000000000000000000000bb01")
    }

    fn sample_r() -> [u8; 32] {
        let mut r = [0u8; 32];
        r[0] = 0x11;
        r[31] = 0xaa;
        r
    }

    fn sample_s() -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = 0x22;
        s[31] = 0xbb;
        s
    }

    fn sample_v0() -> RecoveryId {
        RecoveryId::new(0).unwrap()
    }

    fn sample_v1() -> RecoveryId {
        RecoveryId::new(1).unwrap()
    }
}
