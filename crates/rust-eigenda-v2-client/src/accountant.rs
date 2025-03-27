use ethereum_types::Address;
use num_bigint::BigInt;
use crate::core::{ReservedPayment, OnDemandPayment};

#[derive(Debug, PartialEq)]
pub struct PeriodRecord {
    index: u32,
    usage: u64,
}

#[derive(Debug, PartialEq)]
pub struct Accountant {
    // on-chain states
    account_id: Address,
    reservation: ReservedPayment,
    on_demand: OnDemandPayment,
    reservation_window: u64,
    price_per_symbol: u64,
    min_num_symbols: u64,

    // local accounting
    period_records: Vec<PeriodRecord>,
    cumulative_payment: BigInt,

    num_bins: u32,
}