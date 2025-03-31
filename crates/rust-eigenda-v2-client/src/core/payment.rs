use ethereum_types::Address;
use num_bigint::BigInt;

#[derive(Debug, PartialEq)]
pub struct PaymentMetadata {
    pub account_id: Address,
    pub timestamp: i64,
    pub cumulative_payment: BigInt,
}

/// Contains information about the on-chain state of a reserved payment.
#[derive(Debug, PartialEq)]
pub struct ReservedPayment {
    /// Reserved number of symbols per second.
    pub symbols_per_second: u64,
    /// Reservation activation time.
    pub start_timestamp: u64,
    /// Reservation expiration time.
    pub end_timestamp: u64,

    /// allowed quoroums
    pub quorum_numbers: Vec<u8>,
    /// Ordered mapping of quorum number to payment split; on-chain validation should ensure split <= 100
    pub quorum_splits: Vec<u8>,
}

impl ReservedPayment {
    /// Returns true if the reservation is active at the given timestamp.
    pub fn is_active(&self, current_timestamp: u64) -> bool {
        // TODO: consider using chrono for timestamps.
        self.start_timestamp <= current_timestamp && self.end_timestamp >= current_timestamp
    }
}

#[derive(Debug, PartialEq)]
pub struct OnDemandPayment {
    /// Total amount deposited by the user.
    pub cumulative_payment: BigInt,
}
