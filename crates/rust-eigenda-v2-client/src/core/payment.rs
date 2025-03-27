use ethereum_types::Address;
use num_bigint::BigInt;

#[derive(Debug, PartialEq)]
pub struct PaymentMetadata {
    account_id: Address,
    timestamp: i64,
    cumulative_payment: BigInt,
}

/// Contains information about the on-chain state of a reserved payment.
#[derive(Debug, PartialEq)]
pub struct ReservedPayment {
    /// Reserved number of symbols per second.
    symbols_per_second: u64,
    /// Reservation activation time.
    start_timestamp: u64,
    /// Reservation expiration time.
    end_timestamp: u64,
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
    cumulative_payment: BigInt,
}