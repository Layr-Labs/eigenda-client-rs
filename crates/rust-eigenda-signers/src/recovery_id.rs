use std::fmt;

/// Represents the recovery ID (v) for an ECDSA signature.
/// It must be either 0 or 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryId(u8);

impl RecoveryId {
    /// Creates a new `RecoveryId` if the provided value is 0 or 1.
    ///
    /// Returns `None` if the value is invalid.
    pub fn new(value: u8) -> Option<Self> {
        if value == 0 || value == 1 {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Attempts to create a `RecoveryId` from an Ethereum-style v value.
    /// Handles values 27, 28, and EIP-155 adjusted values by normalizing them to 0 or 1.
    ///
    /// Returns `None` if the normalized value is not 0 or 1.
    pub fn from_eth_v(v: u64) -> Option<Self> {
        if v == 27 || v == 0 {
            // 0 might be used in some contexts, treat as 0
            Some(Self(0))
        } else if v == 28 || v == 1 {
            // 1 might be used, treat as 1
            Some(Self(1))
        } else if v >= 35 {
            // EIP-155
            // Normalize based on parity: (v - 35) % 2 should be 0 or 1
            let normalized_v = (v - 35) % 2;
            if normalized_v == 0 {
                Some(Self(0))
            } else {
                // normalized_v == 1
                Some(Self(1))
            }
        } else {
            None // Invalid Ethereum v value
        }
    }

    /// Returns the underlying `u8` value (0 or 1).
    pub fn to_byte(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for RecoveryId {
    type Error = InvalidRecoveryId;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(InvalidRecoveryId(value))
    }
}

impl From<RecoveryId> for u8 {
    fn from(id: RecoveryId) -> Self {
        id.to_byte()
    }
}

/// Error returned when attempting to create an invalid `RecoveryId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidRecoveryId(pub u8);

impl fmt::Display for InvalidRecoveryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid recovery ID: {}, must be 0 or 1", self.0)
    }
}

impl std::error::Error for InvalidRecoveryId {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_recovery_id() {
        assert_eq!(RecoveryId::new(0).unwrap().to_byte(), 0);
        assert_eq!(RecoveryId::new(1).unwrap().to_byte(), 1);
        assert_eq!(RecoveryId::try_from(0).unwrap().to_byte(), 0);
        assert_eq!(RecoveryId::try_from(1).unwrap().to_byte(), 1);
    }

    #[test]
    fn test_invalid_recovery_id() {
        assert!(RecoveryId::new(2).is_none());
        assert!(RecoveryId::new(255).is_none());
        assert_eq!(RecoveryId::try_from(2), Err(InvalidRecoveryId(2)));
        assert_eq!(RecoveryId::try_from(255), Err(InvalidRecoveryId(255)));
    }

    #[test]
    fn test_from_eth_v() {
        assert_eq!(RecoveryId::from_eth_v(0), RecoveryId::new(0));
        assert_eq!(RecoveryId::from_eth_v(1), RecoveryId::new(1));
        assert_eq!(RecoveryId::from_eth_v(27), RecoveryId::new(0));
        assert_eq!(RecoveryId::from_eth_v(28), RecoveryId::new(1));
        // EIP-155 examples (chain_id = 1 -> v = 37 or 38)
        assert_eq!(RecoveryId::from_eth_v(37), RecoveryId::new(0));
        assert_eq!(RecoveryId::from_eth_v(38), RecoveryId::new(1));
        // EIP-155 examples (chain_id = 3 -> v = 41 or 42)
        assert_eq!(RecoveryId::from_eth_v(41), RecoveryId::new(0));
        assert_eq!(RecoveryId::from_eth_v(42), RecoveryId::new(1));
        // Invalid values
        assert!(RecoveryId::from_eth_v(2).is_none());
        assert!(RecoveryId::from_eth_v(26).is_none());
        assert!(RecoveryId::from_eth_v(34).is_none());
    }
}
