use std::time::Duration;

use crate::{
    core::{OnDemandPayment, PaymentMetadata, ReservedPayment},
    generated::disperser::v2::GetPaymentStateReply,
};
use ark_ff::Zero;
use ethereum_types::Address;
use num_bigint::{BigInt, Sign};

#[derive(Debug, PartialEq, Clone)]
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

impl Accountant {
    /// TODO: add docs
    fn account_blob(
        &mut self,
        timestamp: i64,
        num_symbols: u64,
        quorums: &[u8],
    ) -> Result<PaymentMetadata, String> {
        let cumulative_payment = self.blob_payment_info(num_symbols, quorums, timestamp)?;

        let payment_metadata = PaymentMetadata {
            account_id: self.account_id.clone(),
            timestamp,
            cumulative_payment,
        };

        Ok(payment_metadata)
    }

    // Calculates and records payment information. The accountant
    // will attempt to use the active reservation first and check for quorum settings,
    // then on-demand if the reservation is not available. It takes in a timestamp at
    // the current UNIX time in nanoseconds, and returns a cumulative payment for on-
    // demand payments in units of wei. Both timestamp and cumulative payment are used
    // to create the payment header and signature, with non-zero cumulative payment
    // indicating on-demand payment.
    // These generated values are used to create the payment header and signature, as specified in
    // api/proto/common/v2/common_v2.proto
    fn blob_payment_info(
        &mut self,
        num_symbols: u64,
        quorums: &[u8],
        timestamp: i64,
    ) -> Result<BigInt, String> {
        let current_reservation_period =
            get_reservation_info_by_nanosecond(timestamp, self.reservation_window);
        let symbol_usage = self.symbols_charged(num_symbols);

        let mut relative_period_record = self.relative_period_record(current_reservation_period);

        // first attempt to use the active reservation
        let bin_limit = self.reservation.symbols_per_second * self.reservation_window;
        if relative_period_record.usage <= bin_limit {
            if let Err(_) = quorum_check(quorums, &self.reservation.quorum_numbers) {
                return Ok(BigInt::zero());
            }
            return Ok(BigInt::zero());
        }

        let mut overflow_period_record =
            self.relative_period_record(current_reservation_period + 2);

        // allow one overflow when the overflow bin is empty, the current usage and new length are both less than the limit
        if overflow_period_record.usage.is_zero()
            && relative_period_record.usage - symbol_usage < bin_limit
            && symbol_usage <= bin_limit
        {
            overflow_period_record.usage += relative_period_record.usage - bin_limit;
            if let Err(_) = quorum_check(quorums, &self.reservation.quorum_numbers) {
                return Ok(BigInt::zero());
            }
            return Ok(BigInt::zero());
        }

        // reservation not available, rollback reservation records, attempt on-demand
        //todo: rollback on-demand if disperser respond with some type of rejection?
        relative_period_record.usage -= symbol_usage;
        let increment_required = self.payment_charged(num_symbols);
        self.cumulative_payment += increment_required;

        let required_quorums = vec![0, 1];
        if self.cumulative_payment <= self.on_demand.cumulative_payment {
            if let Err(_) = quorum_check(quorums, &required_quorums) {
                return Ok(BigInt::zero());
            }
            return Ok(self.cumulative_payment.clone());
        }

        Err("neither reservation nor on-demand payment is available".to_string())
    }

    /// Returns the chargeable price for a given data length
    fn payment_charged(&self, num_symbols: u64) -> u64 {
        self.symbols_charged(num_symbols) * self.price_per_symbol
    }

    // Returns the number of symbols charged for a given data length
    // being at least `min_num_symbols` or the nearest rounded-up multiple of `min_num_symbols`.
    fn symbols_charged(&self, num_symbols: u64) -> u64 {
        if num_symbols <= self.min_num_symbols {
            return self.min_num_symbols;
        }
        // Round up to the nearest multiple of `min_num_symbols`
        return round_up_divide(num_symbols, self.min_num_symbols) * self.min_num_symbols;
    }

    fn relative_period_record(&mut self, index: u64) -> PeriodRecord {
        let relative_index = index % (self.num_bins as u64);
        if (self.period_records[relative_index as usize].index as u64) != index {
            self.period_records[relative_index as usize] = PeriodRecord {
                index: index as u32,
                usage: 0,
            };
        }

        self.period_records[relative_index as usize].clone()
    }

    /// Sets the accountant's state from the disperser's response
    /// We require disperser to return a valid set of global parameters, but optional
    /// account level on/off-chain state.
    ///
    /// If on-chain fields are not present, we use dummy values that disable accountant
    /// from using the corresponding payment method.
    /// If off-chain fields are not present, we assume the account has no payment history
    /// and set accoutant state to use initial values.
    pub fn set_payment_state(
        &mut self,
        get_payment_state_reply: &GetPaymentStateReply,
    ) -> Result<(), String> {
        let global_params = get_payment_state_reply
            .payment_global_params
            .as_ref()
            .unwrap();
        self.min_num_symbols = global_params.min_num_symbols.clone();
        self.price_per_symbol = global_params.price_per_symbol.clone();
        self.reservation_window = global_params.reservation_window.clone();

        if get_payment_state_reply
            .onchain_cumulative_payment
            .is_empty()
        {
            self.on_demand = OnDemandPayment {
                cumulative_payment: BigInt::zero(),
            };
        } else {
            let cumulative_payment = BigInt::from_bytes_be(
                Sign::NoSign,
                &get_payment_state_reply.onchain_cumulative_payment,
            );
            self.on_demand = OnDemandPayment { cumulative_payment };
        }

        if get_payment_state_reply.cumulative_payment.is_empty() {
            self.cumulative_payment = BigInt::zero();
        } else {
            let cumulative_payment =
                BigInt::from_bytes_be(Sign::NoSign, &get_payment_state_reply.cumulative_payment);
            self.cumulative_payment = cumulative_payment;
        }

        match get_payment_state_reply.reservation.as_ref() {
            Some(reservation) => {
                self.reservation = ReservedPayment::try_from(reservation.clone())?;
            }
            None => {
                self.reservation = ReservedPayment::default();
            }
        }

        for record in get_payment_state_reply.period_records.iter() {
            self.period_records.push(PeriodRecord {
                index: record.index as u32,
                usage: record.usage,
            });
        }

        Ok(())
    }
}

fn round_up_divide(num: u64, divisor: u64) -> u64 {
    (num + divisor - 1) / divisor
}

fn get_reservation_info_by_nanosecond(timestamp: i64, bin_interval: u64) -> u64 {
    if timestamp < 0 {
        return 0;
    }
    let duration_secs = Duration::from_nanos(timestamp as u64).as_secs();
    reservation_period(duration_secs, bin_interval)
}

// Returns the current reservation period by finding the nearest lower multiple of the bin interval;
// bin interval used by the disperser is publicly recorded on-chain at the payment vault contract
fn reservation_period(timestamp: u64, bin_interval: u64) -> u64 {
    if bin_interval.is_zero() {
        return 0;
    }
    timestamp / bin_interval * bin_interval
}

/// Checks if there are quorum numbers not allowed in the reservation
fn quorum_check(quorum_numbers: &[u8], reservation_quorum_numbers: &[u8]) -> Result<(), String> {
    if quorum_numbers.is_empty() {
        return Err("No quorum numbers provided".to_string());
    }

    for quorum in quorum_numbers {
        if !reservation_quorum_numbers.contains(quorum) {
            return Err("quorum number {quorum} not allowed".to_string());
        }
    }

    Ok(())
}
