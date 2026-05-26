#![allow(dead_code)]

use std::collections::BTreeMap;

pub type Address = [u8; 20];
pub type AssetId = u64;
pub type DexId = u64;
pub type RawNtl = u64;
pub type FeeUnits = u64;
pub type DayBucket = u32;

pub const ASSETS_PER_DEX: u64 = 10_000;
pub const FEE_RATE_DENOMINATOR: u64 = 10_000;
pub const FEE_SCALE_FOR_NON_FULL_RATE_ASSETS: f64 = 0.1;
pub const FEE_COMPONENT_SCALE: u64 = 100;

/// Largest notional the optimized code sends through the floating-rate multiply.
pub const MAX_PRE_RATE_NOTIONAL: u64 = 0x028f_5c28_f5c2_8f5c;
/// Largest absolute rate product retained before converting back to a positive fee.
pub const MAX_POST_RATE_PRODUCT: u64 = 0x0014_7ae1_47ae_147a;

#[derive(Clone, Debug, Default)]
pub struct PerpFeeState {
    pub dex: DexId,
    pub fee_trial_enabled: bool,
    pub current_day_bucket: u64,
    pub base_fee_rate: f64,
    pub assets: Vec<PerpFeeAsset>,
    pub users: BTreeMap<Address, UserFeeState>,
    pub day_totals: BTreeMap<DayBucket, FeePair>,
    pub external_volume_by_user: BTreeMap<Address, BTreeMap<u64, FeeUnits>>,
    pub active_fee_accounts: BTreeMap<Address, ()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerpFeeAsset {
    /// Byte `asset + 0x29`: when false, the notional multiplier is reduced by 10x.
    pub full_rate_fees: bool,
}

impl Default for PerpFeeAsset {
    fn default() -> Self {
        Self { full_rate_fees: true }
    }
}

#[derive(Clone, Debug, Default)]
pub struct FeeRuntimeConfig {
    /// Loaded from the runtime context when the fee-trial flag is active.
    pub fee_trial_multiplier: f64,
    pub split_state: BuilderVaultSplitState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerpFundingAndVolumeUpdate {
    pub asset: AssetId,
    pub raw_notional: i64,
    pub day_bucket: DayBucket,
    pub account_side_tag: u8,
    pub sides: [TradeSideFeeInfo; 2],
}

impl PerpFundingAndVolumeUpdate {
    #[inline]
    pub fn side(&self, side: TradeSide) -> &TradeSideFeeInfo {
        &self.sides[side.index()]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TradeSide {
    First,
    Second,
}

impl TradeSide {
    #[inline]
    pub const fn index(self) -> usize {
        match self {
            Self::First => 0,
            Self::Second => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TradeSideFeeInfo {
    pub user: Address,
    /// Discriminant loaded from the side record. `2` skips the builder/vault split path.
    pub fee_mode: u64,
    /// Present when `fee_mode & 1 != 0`; the amount is scaled by 100 before splitting.
    pub primary_recipient: Option<FeeRecipientAmount>,
    /// Present when the second side-level option discriminant is `1`.
    pub secondary_recipient: Option<FeeRecipientAmount>,
    pub gross_component: RawNtl,
    pub rebate_component: RawNtl,
    pub protocol_component: RawNtl,
}

impl Default for TradeSideFeeInfo {
    fn default() -> Self {
        Self {
            user: [0; 20],
            fee_mode: 2,
            primary_recipient: None,
            secondary_recipient: None,
            gross_component: 0,
            rebate_component: 0,
            protocol_component: 0,
        }
    }
}

impl TradeSideFeeInfo {
    #[inline]
    pub const fn has_split_components(self) -> bool {
        self.fee_mode != 2
    }

    #[inline]
    pub const fn primary_component_enabled(self) -> bool {
        (self.fee_mode & 1) != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeeRecipientAmount {
    pub recipient: Address,
    pub amount: RawNtl,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FeePair {
    pub first_side: FeeUnits,
    pub matching_side: FeeUnits,
}

impl FeePair {
    #[inline]
    pub fn add_for_match(&mut self, matching_side: bool, amount: FeeUnits) {
        if matching_side {
            self.matching_side = saturating_add_after_diagnostic(self.matching_side, amount);
        } else {
            self.first_side = saturating_add_after_diagnostic(self.first_side, amount);
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct UserFeeState {
    pub has_active_fee_account: bool,
    pub paid_scaled_fee_units: FeeUnits,
    pub paid_unscaled_fee_units: FeeUnits,
    pub by_day: BTreeMap<DayBucket, FeePair>,
}

#[derive(Clone, Debug, Default)]
pub struct BuilderVaultSplitState {
    pub per_user: BTreeMap<Address, UserSplitTotals>,
    pub per_recipient: BTreeMap<Address, BTreeMap<Address, FeeUnits>>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UserSplitTotals {
    pub builder_paid_100x: FeeUnits,
    pub net_after_rebate_100x: FeeUnits,
    pub gross_paid_100x: FeeUnits,
    pub secondary_paid_100x: FeeUnits,
    pub protocol_component_100x: FeeUnits,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BuilderVaultSplit {
    pub primary: Option<FeeRecipientAmount>,
    pub secondary: Option<FeeRecipientAmount>,
    pub gross_100x: FeeUnits,
    pub rebate_100x: FeeUnits,
    pub protocol_100x: FeeUnits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyFeeError {
    AssetDexMismatch,
    AssetOutOfBounds,
    NegativeNotional,
    ComponentScaleOverflow,
}

/// Applies the recovered perp trade/funding fee update for one side of a two-sided trade.
///
/// Formula recovered from the optimized arithmetic:
///
/// - split `asset` as `dex = asset / 10_000`, `local_asset = asset % 10_000`;
/// - choose multiplier `fee_trial_multiplier` only when the per-dex fee-trial byte is set;
/// - multiply the multiplier by `0.1` when the asset byte at `+0x29` is clear;
/// - convert `raw_notional * multiplier` through Rust's saturating float-to-int path;
/// - multiply by the per-dex fee rate only below `0x28f5c28f5c28f5c`, clamp the product to
///   `0x147ae147ae147ae`, then divide by `10_000`.
pub fn apply_perp_funding_and_volume_update(
    state: &mut PerpFeeState,
    update: &PerpFundingAndVolumeUpdate,
    selected_side: TradeSide,
    runtime: &mut FeeRuntimeConfig,
) -> Result<(), ApplyFeeError> {
    let dex = update.asset / ASSETS_PER_DEX;
    if dex != state.dex {
        return Err(ApplyFeeError::AssetDexMismatch);
    }
    let local_asset = update.asset % ASSETS_PER_DEX;
    let Some(asset) = state.assets.get(local_asset as usize) else {
        return Err(ApplyFeeError::AssetOutOfBounds);
    };
    if update.raw_notional < 0 {
        return Err(ApplyFeeError::NegativeNotional);
    }

    let participant = update.side(selected_side);
    let multiplier = fee_notional_multiplier(state.fee_trial_enabled, runtime.fee_trial_multiplier, *asset);
    let scaled_notional = clamp_nonnegative_float_to_u64((update.raw_notional as f64) * multiplier);
    let scaled_fee_units = fee_units_for_notional(scaled_notional, state.base_fee_rate);
    let unscaled_fee_units = fee_units_for_notional(update.raw_notional as u64, state.base_fee_rate);

    if participant.has_split_components() {
        add_external_volume(&mut state.external_volume_by_user, participant.user, state.current_day_bucket, scaled_fee_units);
        let split = split_from_trade_side(participant)?;
        apply_builder_vault_fee_split(&mut runtime.split_state, participant.user, &split);
    }

    let user = state.users.entry(participant.user).or_default();
    user.paid_scaled_fee_units = saturating_add_after_diagnostic(user.paid_scaled_fee_units, scaled_fee_units);
    user.paid_unscaled_fee_units = saturating_add_after_diagnostic(user.paid_unscaled_fee_units, unscaled_fee_units);
    user.by_day
        .entry(update.day_bucket)
        .or_default()
        .add_for_match(update.account_side_tag == selected_side.index() as u8, scaled_fee_units);

    if user.has_active_fee_account {
        state.active_fee_accounts.entry(participant.user).or_insert(());
    } else {
        state.active_fee_accounts.remove(&participant.user);
    }

    if selected_side == TradeSide::Second {
        let totals = state.day_totals.entry(update.day_bucket).or_default();
        totals.first_side = saturating_add_after_diagnostic(totals.first_side, scaled_fee_units);
        totals.matching_side = saturating_add_after_diagnostic(totals.matching_side, unscaled_fee_units);
    }

    Ok(())
}

#[inline]
pub fn fee_notional_multiplier(fee_trial_enabled: bool, fee_trial_multiplier: f64, asset: PerpFeeAsset) -> f64 {
    let mut multiplier = if fee_trial_enabled { fee_trial_multiplier } else { 1.0 };
    if !asset.full_rate_fees {
        multiplier *= FEE_SCALE_FOR_NON_FULL_RATE_ASSETS;
    }
    multiplier
}

#[inline]
pub fn fee_units_for_notional(notional: RawNtl, fee_rate: f64) -> FeeUnits {
    let rated = if notional <= MAX_PRE_RATE_NOTIONAL {
        clamp_rate_product((notional as f64) * fee_rate)
    } else {
        notional
    };
    rated / FEE_RATE_DENOMINATOR
}

pub fn split_from_trade_side(side: &TradeSideFeeInfo) -> Result<BuilderVaultSplit, ApplyFeeError> {
    let primary = if side.primary_component_enabled() {
        side.primary_recipient
    } else {
        None
    };
    let secondary = side.secondary_recipient;
    Ok(BuilderVaultSplit {
        primary: scale_recipient_amount(primary)?,
        secondary: scale_recipient_amount(secondary)?,
        gross_100x: checked_100x(side.gross_component)?,
        rebate_100x: checked_100x(side.rebate_component)?,
        protocol_100x: checked_100x(side.protocol_component)?,
    })
}

pub fn apply_builder_vault_fee_split(state: &mut BuilderVaultSplitState, user: Address, split: &BuilderVaultSplit) {
    let mut primary_credit = None;
    let mut secondary_credit = None;

    {
        let totals = state.per_user.entry(user).or_default();
        totals.protocol_component_100x = saturating_add_after_diagnostic(totals.protocol_component_100x, split.protocol_100x);

        if let Some(primary) = split.primary {
            if let Some(net) = split
                .gross_100x
                .checked_sub(split.rebate_100x)
                .and_then(|remaining| remaining.checked_sub(split.protocol_100x))
            {
                totals.net_after_rebate_100x = saturating_add_after_diagnostic(totals.net_after_rebate_100x, net);
            }
            totals.builder_paid_100x = saturating_add_after_diagnostic(totals.builder_paid_100x, primary.amount);
            primary_credit = Some(primary);
        }

        if let Some(secondary) = split.secondary {
            totals.secondary_paid_100x = saturating_add_after_diagnostic(totals.secondary_paid_100x, secondary.amount);
            secondary_credit = Some(secondary);
        }
    }

    if let Some(primary) = primary_credit {
        add_recipient_amount(state, primary.recipient, user, primary.amount);
    }
    if let Some(secondary) = secondary_credit {
        add_recipient_amount(state, secondary.recipient, user, secondary.amount);
    }
}

#[inline]
fn add_external_volume(
    by_user: &mut BTreeMap<Address, BTreeMap<u64, FeeUnits>>,
    user: Address,
    day: u64,
    amount: FeeUnits,
) {
    let entry = by_user.entry(user).or_default().entry(day).or_default();
    *entry = saturating_add_after_diagnostic(*entry, amount);
}

#[inline]
fn add_recipient_amount(state: &mut BuilderVaultSplitState, recipient: Address, user: Address, amount: FeeUnits) {
    let entry = state.per_recipient.entry(recipient).or_default().entry(user).or_default();
    *entry = saturating_add_after_diagnostic(*entry, amount);
}

#[inline]
fn scale_recipient_amount(value: Option<FeeRecipientAmount>) -> Result<Option<FeeRecipientAmount>, ApplyFeeError> {
    match value {
        Some(value) => Ok(Some(FeeRecipientAmount { recipient: value.recipient, amount: checked_100x(value.amount)? })),
        None => Ok(None),
    }
}

#[inline]
fn checked_100x(value: u64) -> Result<u64, ApplyFeeError> {
    value.checked_mul(FEE_COMPONENT_SCALE).ok_or(ApplyFeeError::ComponentScaleOverflow)
}

#[inline]
pub fn saturating_add_after_diagnostic(current: u64, delta: u64) -> u64 {
    current.saturating_add(delta)
}

pub fn clamp_rate_product(value: f64) -> u64 {
    let signed = clamp_float_to_i64(value);
    if signed <= 0 {
        return 0;
    }
    (signed as u64).min(MAX_POST_RATE_PRODUCT)
}

pub fn clamp_nonnegative_float_to_u64(value: f64) -> u64 {
    let signed = clamp_float_to_i64(value);
    if signed <= 0 { 0 } else { signed as u64 }
}

pub fn clamp_float_to_i64(value: f64) -> i64 {
    if !value.is_finite() {
        return 0;
    }
    if value < i64::MIN as f64 {
        i64::MIN
    } else if value > i64::MAX as f64 {
        i64::MAX
    } else {
        value.trunc() as i64
    }
}
