#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type RawNtl = i64;
pub type RawNtlUnsigned = u64;

pub const RAW_NTL_SCALE: RawNtl = 1_000_000;
pub const RAW_NTL_SCALE_F64: f64 = 1_000_000.0;
pub const MIN_LEADER_EQUITY_NTL: RawNtl = 100_000_000;
pub const MIN_DISTRIBUTION_NTL: RawNtlUnsigned = 10_000_000;
pub const MIN_TOTAL_FRACTION_DENOMINATOR: f64 = 1.0e-15;
pub const MIN_PARTICIPANT_EQUITY_USD: f64 = 1.0e-7;
pub const MIN_WITHDRAW_FRACTION: f64 = 1.0e-8;
pub const MIN_DEPOSIT_FRACTION: f64 = 1.0e-7;
pub const LEADER_FRACTION: f64 = 0.05;
pub const LEADER_MIN_EQUITY_DIVISOR: f64 = 19.0;
pub const SUCCESS_CODE: u16 = 390;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UpdateId {
    pub unix_seconds: i64,
    pub nanos: u32,
}

/// Per-participant value stored in the vault equity BTreeMap.
///
/// Recovered layout: the persistent BTreeMap value is 48 bytes.  Offset +0 is
/// the `f64` share rewritten by the distribution helper.  Offsets +8 and +16
/// are integer accounting fields touched by deposits, withdrawals, and
/// distributions.  New entries copy update metadata into the tail fields.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct VaultEquityRecord {
    pub share: f64,
    pub deposited_ntl: RawNtlUnsigned,
    pub net_ntl: RawNtl,
    pub _unknown_field_at_18: [u8; 12],
    pub last_update_id: UpdateId,
}

impl Default for VaultEquityRecord {
    fn default() -> Self {
        Self {
            share: 0.0,
            deposited_ntl: 0,
            net_ntl: 0,
            _unknown_field_at_18: [0; 12],
            last_update_id: UpdateId::default(),
        }
    }
}

impl VaultEquityRecord {
    #[inline]
    pub fn with_update_id(update_id: UpdateId) -> Self {
        Self {
            last_update_id: update_id,
            ..Self::default()
        }
    }

    #[inline]
    pub fn is_effectively_empty(&self) -> bool {
        self.share < MIN_TOTAL_FRACTION_DENOMINATOR
            && self.deposited_ntl == 0
            && self.net_ntl == 0
    }
}

/// Core vault state recovered from offsets used by the vault helpers.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VaultState {
    /// Offset +0x00.  Version 1 omits the child-vault aggregate pass; version 2+
    /// walks `child_vault_addresses` and includes every child in total NTL.
    pub version: u32,
    /// Offset +0x08/+0x10/+0x18 in the optimized layout.
    pub child_vault_addresses: BTreeSet<Address>,
    /// Offset +0x50/+0x58/+0x60 in the optimized layout.
    pub equity_records: BTreeMap<Address, VaultEquityRecord>,
    /// Offset +0x68. Used to compute distribution/withdrawal retention.
    pub distribution_fee_fraction: f64,
    /// Offset +0x70. Added to the participant update timestamp before allowing
    /// withdrawals.
    pub deposit_lockup_secs: f64,
    /// Offset +0x84: account whose ledger balance belongs to the vault itself.
    pub vault_address: Address,
    /// Offset +0x98: leader/owner account receiving leader-only checks and some
    /// settlement adjustments.
    pub leader_address: Address,
    /// Offset +0xac: set when the recovered distribution path drains total NTL.
    pub closed: bool,
    /// Offset +0xad. Name inferred from deposit gating.
    pub deposits_disabled: bool,
    /// Offset +0xae. Validation returns a liquidation/close hint when this is set.
    pub always_close_on_withdraw: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultError {
    NegativeAggregateRequiresPrivilegedVault = 9,
    TransferZeroTotal = 10,
    ParticipantNotFound = 11,
    WithdrawLockup = 12,
    WithdrawTooMuch = 13,
    InvalidWithdrawFraction = 14,
    LeaderFraction = 15,
    LeaderValueTooSmall = 16,
    DistributionAboveLeaderExcess = 18,
    DistributionBelowMinimum = 19,
    DistributionMustEqualWithdrawable = 20,
    DepositFromWrongAccount = 22,
    DepositsDisabledForLeader = 23,
    InsufficientUserBalance = 44,
    InsufficientVaultBalance = 51,
    TransferWouldBreakMinimum = 272,
}

impl VaultError {
    #[inline]
    pub const fn code(self) -> u16 {
        self as u16
    }
}

pub trait VaultNtlSource {
    /// Recovered helper at 0x3955E80.  The binary computes this from a direct
    /// account balance plus market/oracle-derived components; callers only need
    /// the resulting signed raw NTL.
    fn account_total_ntl(&self, address: &Address) -> RawNtl;

    /// Recovered leader-excess helper caps withdrawal by a positive margin
    /// summary for the vault account.  State implementations that do not expose
    /// margin can return `account_total_ntl(address).max(0)`.
    #[inline]
    fn positive_margin_ntl(&self, address: &Address) -> RawNtl {
        self.account_total_ntl(address).max(0)
    }
}

pub trait VaultLedger: VaultNtlSource {
    fn debit(&mut self, address: &Address, amount: RawNtl) -> bool;
    fn credit(&mut self, address: &Address, amount: RawNtl);
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TransferValidation {
    pub requires_liquidation_check: bool,
    pub effective_fraction: f64,
    pub raw_delta_ntl: RawNtl,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DepositReceipt {
    pub vault_address: Address,
    pub share_fraction: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WithdrawReceipt {
    pub requested_ntl: RawNtl,
    pub fee_ntl: RawNtl,
    pub remaining_user_ntl: RawNtl,
    pub paid_from_vault_ntl: RawNtl,
    pub principal_return_ntl: RawNtl,
    pub participant: Address,
    pub leader_followup: Option<LeaderSettlement>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LeaderSettlement {
    pub fee_ntl: RawNtl,
    pub leader_address: Address,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DistributionReceipt {
    pub participant_deltas: BTreeMap<Address, RawNtl>,
}

impl VaultState {
    #[inline]
    pub fn is_v2_or_later(&self) -> bool {
        self.version >= 2
    }

    pub fn total_vault_ntl<S: VaultNtlSource>(&self, source: &S) -> RawNtl {
        let mut total = source.account_total_ntl(&self.vault_address);
        if self.is_v2_or_later() {
            for child in &self.child_vault_addresses {
                total = total.saturating_add(source.account_total_ntl(child));
            }
        }
        total
    }

    pub fn participant_equity_ntl<S: VaultNtlSource>(
        &self,
        participant: &Address,
        source: &S,
    ) -> RawNtl {
        let Some(record) = self.equity_records.get(participant) else {
            return 0;
        };
        let raw = record.share * self.total_vault_ntl(source) as f64;
        trunc_saturating_i64(raw).max(0)
    }

    pub fn max_withdrawable_ntl_for_depositor<S: VaultNtlSource>(
        &self,
        source: &S,
        depositor: &Address,
    ) -> RawNtl {
        let total = self.total_vault_ntl(source);
        if total <= 0 {
            return 0;
        }

        let Some(record) = self.equity_records.get(depositor) else {
            return 0;
        };

        let mut entitlement = trunc_saturating_i64(total as f64 * record.share);
        if depositor == &self.leader_address {
            let other_equity = total.saturating_sub(entitlement);
            let leader_floor = trunc_saturating_i64(other_equity as f64 / LEADER_MIN_EQUITY_DIVISOR)
                .max(MIN_LEADER_EQUITY_NTL);
            entitlement = entitlement.saturating_sub(leader_floor);
        }

        entitlement
            .max(0)
            .min(source.account_total_ntl(&self.vault_address).max(0))
    }

    pub fn leader_excess_withdrawable_ntl<S: VaultNtlSource>(&self, source: &S) -> RawNtl {
        let Some(record) = self.equity_records.get(&self.leader_address) else {
            return 0;
        };
        if record.share < MIN_TOTAL_FRACTION_DENOMINATOR {
            return 0;
        }

        let threshold = trunc_saturating_i64((100.0 / record.share) * RAW_NTL_SCALE_F64);
        if threshold < 0 {
            return 0;
        }

        let excess = self.total_vault_ntl(source).saturating_sub(threshold).max(0);
        excess.min(source.positive_margin_ntl(&self.vault_address).max(0))
    }

    pub fn update_equity_distribution<S: VaultNtlSource>(
        &mut self,
        participant: Address,
        participant_delta_ntl: RawNtl,
        old_total_ntl: RawNtl,
        update_id: UpdateId,
        source: &S,
    ) {
        let new_total_ntl = old_total_ntl.saturating_add(participant_delta_ntl);
        let denominator = raw_ntl_to_f64(new_total_ntl.max(0));

        let base_total = if participant_delta_ntl > 0 {
            self.total_vault_ntl(source)
        } else {
            old_total_ntl
        };

        let mut equities = BTreeMap::<Address, f64>::new();
        for (address, record) in &self.equity_records {
            equities.insert(*address, raw_ntl_to_f64(base_total) * record.share);
        }

        let participant_entry = equities.entry(participant).or_insert(0.0);
        *participant_entry += raw_ntl_to_f64(participant_delta_ntl);

        for (address, equity) in equities {
            let share = if denominator >= MIN_TOTAL_FRACTION_DENOMINATOR
                && equity >= MIN_PARTICIPANT_EQUITY_USD
            {
                equity / denominator
            } else {
                0.0
            };
            let entry = self
                .equity_records
                .entry(address)
                .or_insert_with(|| VaultEquityRecord::with_update_id(update_id));
            entry.share = share;
            entry.last_update_id = update_id;
        }
    }

    pub fn validate_vault_transfer<S: VaultNtlSource>(
        &self,
        source: &S,
        participant: &Address,
        is_deposit: bool,
        requested_ntl: RawNtlUnsigned,
        now: UpdateId,
        minimum_remaining_ntl: RawNtl,
    ) -> Result<TransferValidation, VaultError> {
        let total = self.total_vault_ntl(source);
        if total <= 0 {
            return Err(VaultError::TransferZeroTotal);
        }

        let Some(record) = self.equity_records.get(participant) else {
            return Err(VaultError::ParticipantNotFound);
        };

        if self.is_v2_or_later()
            && update_before_lockup(record.last_update_id, now, self.deposit_lockup_secs)
        {
            return Err(VaultError::WithdrawLockup);
        }

        let liquidity_cap = self.max_withdrawable_ntl_for_depositor(source, participant);
        let amount_for_fraction = if is_deposit {
            requested_ntl.min(i64::MAX as u64) as RawNtl
        } else {
            liquidity_cap
        };
        let total_usd = raw_ntl_to_f64(total);
        if total_usd < MIN_TOTAL_FRACTION_DENOMINATOR {
            return Err(VaultError::InvalidWithdrawFraction);
        }

        let fraction = raw_ntl_to_f64(amount_for_fraction) / total_usd;
        if !(MIN_WITHDRAW_FRACTION..=record.share).contains(&fraction) {
            return Err(VaultError::InvalidWithdrawFraction);
        }
        if amount_for_fraction > liquidity_cap {
            return Err(VaultError::WithdrawTooMuch);
        }

        if participant == &self.leader_address {
            let remaining_share = record.share - fraction;
            if (1.0 - fraction) * LEADER_FRACTION > remaining_share + MIN_WITHDRAW_FRACTION {
                return Err(VaultError::LeaderFraction);
            }
            let remaining_ntl = trunc_saturating_i64((record.share - fraction) * total as f64);
            if remaining_ntl < MIN_LEADER_EQUITY_NTL {
                return Err(VaultError::LeaderValueTooSmall);
            }
        }

        let raw_delta_ntl = trunc_saturating_i64(total as f64 * fraction);
        if !is_deposit && total.saturating_sub(raw_delta_ntl) < minimum_remaining_ntl {
            return Err(VaultError::TransferWouldBreakMinimum);
        }

        let requires_liquidation_check = !is_deposit
            && self.is_v2_or_later()
            && (raw_delta_ntl > source.account_total_ntl(&self.vault_address)
                || self.always_close_on_withdraw);

        Ok(TransferValidation {
            requires_liquidation_check,
            effective_fraction: if requires_liquidation_check {
                fraction.max(0.2)
            } else {
                fraction
            },
            raw_delta_ntl,
        })
    }

    pub fn apply_vault_deposit<L: VaultLedger>(
        &mut self,
        ledger: &mut L,
        participant: Address,
        deposit_ntl: RawNtl,
        update_id: UpdateId,
        privileged: bool,
    ) -> Result<DepositReceipt, VaultError> {
        if self.total_vault_ntl(ledger) < 0 && !privileged {
            return Err(VaultError::NegativeAggregateRequiresPrivilegedVault);
        }
        if self.version == 1 && participant != self.vault_address {
            return Err(VaultError::DepositFromWrongAccount);
        }
        if !self.deposits_disabled && participant == self.vault_address {
            return Err(VaultError::DepositsDisabledForLeader);
        }
        if deposit_ntl < 0 || !ledger.debit(&participant, deposit_ntl) {
            return Err(VaultError::InsufficientUserBalance);
        }

        ledger.credit(&self.vault_address, deposit_ntl);
        let old_total = self.total_vault_ntl(ledger).saturating_sub(deposit_ntl);
        self.update_equity_distribution(participant, deposit_ntl, old_total, update_id, ledger);

        let record = self.equity_records.entry(participant).or_default();
        record.deposited_ntl = record
            .deposited_ntl
            .saturating_add(deposit_ntl.max(0) as RawNtlUnsigned);
        record.net_ntl = record.net_ntl.saturating_add(deposit_ntl);
        record.last_update_id = update_id;

        Ok(DepositReceipt {
            vault_address: self.vault_address,
            share_fraction: record.share,
        })
    }

    pub fn apply_vault_withdraw<L: VaultLedger>(
        &mut self,
        ledger: &mut L,
        participant: Address,
        requested_ntl: RawNtl,
        update_id: UpdateId,
        requested_fraction: f64,
    ) -> Result<WithdrawReceipt, VaultError> {
        let old_total = self.total_vault_ntl(ledger);
        let record = self
            .equity_records
            .get(&participant)
            .copied()
            .ok_or(VaultError::ParticipantNotFound)?;
        if record.deposited_ntl > i64::MAX as u64 {
            return Err(VaultError::InvalidWithdrawFraction);
        }
        if record.share < MIN_TOTAL_FRACTION_DENOMINATOR {
            return Err(VaultError::InvalidWithdrawFraction);
        }

        let account_available = ledger.account_total_ntl(&self.vault_address).max(0);
        let raw_requested_from_fraction = trunc_saturating_i64(requested_fraction * old_total as f64);
        let paid_from_vault = requested_ntl.min(account_available).min(raw_requested_from_fraction).max(0);
        if paid_from_vault <= 0 {
            return Err(VaultError::WithdrawTooMuch);
        }
        if !ledger.debit(&self.vault_address, paid_from_vault) {
            return Err(VaultError::InsufficientVaultBalance);
        }

        let participant_available = trunc_saturating_i64(record.deposited_ntl as f64 * requested_fraction / record.share)
            .max(0);
        let fee_ntl = trunc_saturating_i64((paid_from_vault.saturating_sub(participant_available)) as f64 * self.distribution_fee_fraction).max(0);
        let principal_return = paid_from_vault.saturating_sub(fee_ntl).max(0);
        ledger.credit(&participant, principal_return);
        if fee_ntl > 0 {
            ledger.credit(&self.leader_address, fee_ntl);
        }

        self.update_equity_distribution(participant, -paid_from_vault, old_total, update_id, ledger);
        if let Some(current) = self.equity_records.get_mut(&participant) {
            current.deposited_ntl = current.deposited_ntl.saturating_sub(participant_available as u64);
            current.net_ntl = current.net_ntl.saturating_sub(paid_from_vault);
            current.last_update_id = update_id;
        }

        let remaining_user_ntl = requested_ntl.saturating_sub(paid_from_vault);
        Ok(WithdrawReceipt {
            requested_ntl,
            fee_ntl,
            remaining_user_ntl,
            paid_from_vault_ntl: paid_from_vault,
            principal_return_ntl: principal_return,
            participant,
            leader_followup: (fee_ntl > 0).then_some(LeaderSettlement {
                fee_ntl,
                leader_address: self.leader_address,
            }),
        })
    }

    pub fn apply_distribution<L: VaultLedger>(
        &mut self,
        ledger: &mut L,
        leader_excess_mode: bool,
        requested_ntl: RawNtlUnsigned,
        update_id: UpdateId,
    ) -> Result<DistributionReceipt, VaultError> {
        let total = self.total_vault_ntl(ledger);
        let amount = if leader_excess_mode {
            if requested_ntl < MIN_DISTRIBUTION_NTL {
                return Err(VaultError::DistributionBelowMinimum);
            }
            let cap = self.leader_excess_withdrawable_ntl(ledger);
            let requested = requested_ntl.min(i64::MAX as u64) as RawNtl;
            if requested > cap {
                return Err(VaultError::DistributionAboveLeaderExcess);
            }
            requested
        } else {
            let cap = self.max_withdrawable_ntl_for_depositor(ledger, &self.vault_address);
            if requested_ntl.min(i64::MAX as u64) as RawNtl != cap {
                return Err(VaultError::DistributionMustEqualWithdrawable);
            }
            cap
        };

        if total <= 0 || amount <= 0 {
            return Err(VaultError::DistributionAboveLeaderExcess);
        }
        if amount > ledger.account_total_ntl(&self.vault_address).max(0)
            || !ledger.debit(&self.vault_address, amount)
        {
            return Err(VaultError::InsufficientVaultBalance);
        }

        let total_f = total as f64;
        let mut distributed = BTreeMap::new();
        let mut distributed_sum = 0_i64;
        let leader_key = self.leader_address;

        for (address, record) in self.equity_records.iter_mut() {
            if record.share < MIN_TOTAL_FRACTION_DENOMINATOR {
                continue;
            }
            let mut participant_amount = trunc_saturating_i64(record.share * amount as f64).max(0);
            let fee = if *address == leader_key {
                0
            } else {
                let gross = trunc_saturating_i64(record.share * total_f).max(0);
                let principal = record.deposited_ntl.min(gross as u64) as i64;
                let profit = gross.saturating_sub(principal).max(0);
                trunc_saturating_i64(profit as f64 * self.distribution_fee_fraction).max(0)
            };
            participant_amount = participant_amount.saturating_sub(fee).max(0);
            if participant_amount == 0 {
                continue;
            }
            ledger.credit(address, participant_amount);
            if fee > 0 {
                ledger.credit(&leader_key, fee);
            }
            record.net_ntl = record.net_ntl.saturating_add(participant_amount);
            record.last_update_id = update_id;
            distributed_sum = distributed_sum.saturating_add(participant_amount);
            distributed.insert(*address, participant_amount);
        }

        let residual = amount.saturating_sub(distributed_sum);
        if residual > 0 {
            ledger.credit(&leader_key, residual);
            distributed
                .entry(leader_key)
                .and_modify(|v| *v = v.saturating_add(residual))
                .or_insert(residual);
        }

        if self.total_vault_ntl(ledger) == 0 {
            self.closed = true;
        }

        Ok(DistributionReceipt {
            participant_deltas: distributed,
        })
    }
}

#[inline]
pub fn raw_ntl_to_f64(value: RawNtl) -> f64 {
    value as f64 / RAW_NTL_SCALE_F64
}

#[inline]
pub fn trunc_saturating_i64(value: f64) -> RawNtl {
    if !value.is_finite() {
        0
    } else if value > i64::MAX as f64 {
        i64::MAX
    } else if value < i64::MIN as f64 {
        i64::MIN
    } else {
        value as RawNtl
    }
}

#[inline]
fn update_before_lockup(last: UpdateId, now: UpdateId, lockup_secs: f64) -> bool {
    let locked_until = last.unix_seconds as f64 + lockup_secs;
    let now_seconds = now.unix_seconds as f64 + f64::from(now.nanos) / 1_000_000_000.0;
    now_seconds < locked_until
}
