#![allow(dead_code)]

use std::collections::BTreeMap;

use super::clearinghouse::{Address, Clearinghouse, SUCCESS_RESULT_TAG};

pub type FirstDexKey = [u8; 32];
pub type FirstDexWeight = u64;

pub const FIRST_DEX_SPLIT_NOT_PROFITABLE: u16 = 91;
pub const FIRST_DEX_AMOUNT_NOT_ABOVE_BASE_SPLIT: u16 = 92;
pub const FIRST_DEX_DISTRIBUTION_MISSING: u16 = 151;
pub const INSUFFICIENT_WITHDRAWABLE_BALANCE: u16 = 51;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FirstDexStakeWeights {
    /// The binary only reads the values and adds them with checked `u64` arithmetic.
    pub weights_by_staker: BTreeMap<Address, FirstDexWeight>,
}

impl FirstDexStakeWeights {
    pub fn total_weight(&self) -> FirstDexWeight {
        self.weights_by_staker
            .values()
            .try_fold(0_u64, |acc, &weight| acc.checked_add(weight))
            .expect("first-dex total weight overflow")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirstDexPayoutEntry {
    /// Nested map at value offset +0x00; its values are summed to decide this entry's share.
    pub stake_weights: FirstDexStakeWeights,
    /// Address copied from value offset +0x18 before calling the balance-credit helper.
    pub beneficiary: Address,
    pub _unknown_field_at_0x2c: [u8; 20],
}

impl Default for FirstDexPayoutEntry {
    fn default() -> Self {
        Self {
            stake_weights: FirstDexStakeWeights::default(),
            beneficiary: [0; 20],
            _unknown_field_at_0x2c: [0; 20],
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FirstDexDistributionSet {
    /// Outer value selected by `active_dex_key` in the recovered helper.
    pub payouts_by_key: BTreeMap<FirstDexKey, FirstDexPayoutEntry>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FirstDexDistributions {
    pub _unknown_field_at_0x00: [u64; 6],
    /// Map keyed by the u64 read from the context at offset +0x48.
    pub by_dex_key: BTreeMap<u64, FirstDexDistributionSet>,
    pub active_dex_key: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct FirstDexResidualSink {
    /// Addresses and floating weights consumed by the downstream class-transfer helper.
    pub weighted_recipients: BTreeMap<Address, f64>,
    pub fallback_recipient: Address,
    pub accumulated_scaled_notional: i64,
    /// Clearinghouse-wide residual scaling factor loaded by the downstream helper before clamping.
    pub residual_scale: f64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FirstDexCappedTransferOutcome {
    pub tag: u16,
    pub excess_above_base_split: i64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FirstDexTransferBudget {
    /// Field read at offset +0x250 by the capped wrapper.
    pub base_first_dex_split: i64,
    /// Field read/written at offset +0x238 by the capped wrapper.
    pub remaining_notional_budget: i64,
}

impl Clearinghouse {
    /// Credits a non-negative delta to a user and mirrors the side effects of the balance helpers:
    /// create the user row if absent, mark it dirty, and maintain the non-zero balance index.
    pub fn credit_first_dex_balance(&mut self, user: Address, amount: i64) {
        assert!(amount >= 0, "first-dex credit amount must be non-negative");
        let state = self.users.entry(user).or_default();
        state.signed_account_value = state
            .signed_account_value
            .checked_add(amount)
            .unwrap_or_else(|| state.signed_account_value.saturating_add(amount));
        self.dirty_users.insert(user);
        self.refresh_first_dex_balance_index(user);
    }

    /// Debits a non-negative delta after the caller has already checked withdrawable balance.
    pub fn debit_first_dex_balance(&mut self, user: Address, amount: i64) {
        assert!(amount >= 0, "first-dex debit amount must be non-negative");
        let state = self.users.entry(user).or_default();
        state.signed_account_value = state
            .signed_account_value
            .checked_sub(amount)
            .unwrap_or_else(|| state.signed_account_value.saturating_sub(amount));
        self.dirty_users.insert(user);
        self.refresh_first_dex_balance_index(user);
    }

    fn refresh_first_dex_balance_index(&mut self, user: Address) {
        let non_zero_balance = self
            .users
            .get(&user)
            .map(|state| state.signed_account_value != 0)
            .unwrap_or(false);
        if non_zero_balance {
            self.active_users_with_positions.insert(user);
        } else {
            self.active_users_with_positions.remove(&user);
        }
    }

    pub fn first_dex_withdrawable_balance(&self, user: &Address) -> i64 {
        let summary = self.aggregate_position_margin_summary(user, false, true);
        summary
            .signed_equity_or_value
            .checked_sub(summary.margin_requirement_sum)
            .unwrap_or_else(|| summary.signed_equity_or_value.saturating_sub(summary.margin_requirement_sum))
            .max(0)
    }

    /// Recovered core helper at 0x370DB70.
    ///
    /// Algorithm evidence:
    /// * negative `amount` panics before any state mutation;
    /// * the selected distribution map is cloned/projected into `(key, total_nested_weight)` pairs;
    /// * zero-weight entries are skipped;
    /// * each credited amount is `trunc(amount as f64 * entry_weight as f64 / total_weight as f64)`;
    /// * rounding residue is routed through the same downstream class-transfer helper used by
    ///   non-first-dex clearinghouse transfers.
    pub fn distribute_first_dex_amount(
        &mut self,
        amount: i64,
        distributions: &FirstDexDistributions,
        residual_sink: &mut FirstDexResidualSink,
    ) -> u16 {
        assert!(amount >= 0, "first-dex distribution amount must be non-negative");

        let Some(set) = distributions.by_dex_key.get(&distributions.active_dex_key) else {
            if amount != 0 {
                self.apply_first_dex_residual(0, amount, residual_sink);
            }
            return FIRST_DEX_DISTRIBUTION_MISSING;
        };

        let mut totals = BTreeMap::new();
        let mut total_weight = 0_u64;
        for (key, entry) in &set.payouts_by_key {
            let weight = entry.stake_weights.total_weight();
            totals.insert(*key, weight);
            total_weight = total_weight
                .checked_add(weight)
                .expect("first-dex aggregate weight overflow");
        }

        let mut residue = amount;
        if total_weight != 0 {
            let denominator = total_weight as f64;
            let amount_f64 = amount as f64;
            for (key, weight) in totals {
                if weight == 0 {
                    continue;
                }
                let share = clamp_f64_to_i64((weight as f64 / denominator) * amount_f64);
                residue = residue
                    .checked_sub(share)
                    .unwrap_or_else(|| residue.saturating_sub(share));

                let entry = set
                    .payouts_by_key
                    .get(&key)
                    .expect("first-dex projected key must exist in original payout map");
                self.credit_first_dex_balance(entry.beneficiary, share);
            }
        }

        if residue != 0 {
            self.apply_first_dex_residual(0, residue, residual_sink);
        }
        SUCCESS_RESULT_TAG
    }

    /// Recovered wrapper at 0x370D980.
    pub fn apply_split_transfer_with_first_dex_fee(
        &mut self,
        source: Address,
        direct_recipient: Address,
        total_amount: i64,
        first_dex_amount: i64,
        distributions: &FirstDexDistributions,
        residual_sink: &mut FirstDexResidualSink,
    ) -> u16 {
        let direct_amount = total_amount.saturating_sub(first_dex_amount);
        if total_amount <= first_dex_amount {
            return FIRST_DEX_SPLIT_NOT_PROFITABLE;
        }
        assert!(total_amount >= 0, "first-dex split transfer amount must be non-negative");

        if self.first_dex_withdrawable_balance(&source) < total_amount {
            return INSUFFICIENT_WITHDRAWABLE_BALANCE;
        }

        self.debit_first_dex_balance(source, total_amount);
        self.credit_first_dex_balance(direct_recipient, direct_amount);
        if first_dex_amount != 0 {
            self.distribute_first_dex_amount(first_dex_amount, distributions, residual_sink);
        }
        SUCCESS_RESULT_TAG
    }

    /// Recovered wrapper at 0x370DA60.
    pub fn apply_capped_first_dex_transfer(
        &mut self,
        source: Address,
        amount: i64,
        budget: &mut FirstDexTransferBudget,
        distributions: &FirstDexDistributions,
        residual_sink: &mut FirstDexResidualSink,
    ) -> FirstDexCappedTransferOutcome {
        let excess = amount.saturating_sub(budget.base_first_dex_split);
        if amount < budget.base_first_dex_split || excess == 0 {
            return FirstDexCappedTransferOutcome {
                tag: FIRST_DEX_AMOUNT_NOT_ABOVE_BASE_SPLIT,
                excess_above_base_split: 0,
            };
        }
        assert!(amount >= 0, "first-dex capped transfer amount must be non-negative");

        if self.first_dex_withdrawable_balance(&source) < amount {
            return FirstDexCappedTransferOutcome {
                tag: INSUFFICIENT_WITHDRAWABLE_BALANCE,
                excess_above_base_split: 0,
            };
        }

        self.debit_first_dex_balance(source, amount);
        self.distribute_first_dex_amount(budget.base_first_dex_split, distributions, residual_sink);
        budget.remaining_notional_budget = budget
            .remaining_notional_budget
            .checked_sub(excess)
            .unwrap_or_else(|| budget.remaining_notional_budget.saturating_sub(excess));

        FirstDexCappedTransferOutcome {
            tag: SUCCESS_RESULT_TAG,
            excess_above_base_split: excess,
        }
    }

    fn apply_first_dex_residual(
        &mut self,
        class_delta: i64,
        amount: i64,
        sink: &mut FirstDexResidualSink,
    ) {
        let combined = class_delta
            .checked_add(amount)
            .unwrap_or_else(|| class_delta.saturating_add(amount));

        let mut residue = amount;
        for (&recipient, &weight) in &sink.weighted_recipients {
            let share = clamp_f64_to_i64((amount as f64) * weight);
            residue = residue
                .checked_sub(share)
                .unwrap_or_else(|| residue.saturating_sub(share));
            self.credit_first_dex_balance(recipient, share);
        }

        self.credit_first_dex_balance(sink.fallback_recipient, residue);
        let scaled = clamp_f64_to_i64((combined as f64) * sink.residual_scale).min(0x147a_e147_ae14_7ae);
        sink.accumulated_scaled_notional = sink
            .accumulated_scaled_notional
            .checked_add(scaled)
            .unwrap_or_else(|| sink.accumulated_scaled_notional.saturating_add(scaled));
    }

}

fn clamp_f64_to_i64(value: f64) -> i64 {
    if value.is_nan() {
        0
    } else if value > i64::MAX as f64 {
        i64::MAX
    } else if value < i64::MIN as f64 {
        i64::MIN
    } else {
        value.trunc() as i64
    }
}

