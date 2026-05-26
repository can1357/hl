#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type AssetId = u64;
pub type RawPx = i64;
pub type RawNtl = u64;
pub type SignedNtl = i64;

pub const ASSETS_PER_DEX: AssetId = 10_000;
pub const BUILTIN_MARGIN_TABLE_CUTOFF: u32 = 50;
pub const ADL_MIN_FACTOR: f64 = 0.00000001;
pub const DELISTED_CLOSE_MIN_RATIO: f64 = 0.5;
pub const DELISTED_CLOSE_MAX_RATIO: f64 = 1.0;

pub const RESULT_INVALID_DELISTED_CLOSE_RATIO: u16 = 67;
pub const RESULT_INSUFFICIENT_AVAILABLE_MARGIN: u16 = 75;
pub const RESULT_MARGIN_WOULD_BE_NEGATIVE: u16 = 76;
pub const RESULT_SIGNED_POSITION_OVERFLOW: u16 = 190;
pub const RESULT_ACCOUNT_VALUE_OVERFLOW: u16 = 191;
pub const RESULT_NOT_DELISTED: u16 = 313;
pub const RESULT_SUCCESS: u16 = 390;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PositionMarginMode {
    NoRequirement = 0,
    SimpleMaxLeverage = 1,
    Initial = 2,
    Maintenance = 3,
    CappedLeverage = 4,
}

impl PositionMarginMode {
    pub fn from_storage(value: u8) -> Self {
        match value {
            0 => Self::NoRequirement,
            1 => Self::SimpleMaxLeverage,
            2 => Self::Initial,
            3 => Self::Maintenance,
            4 => Self::CappedLeverage,
            _ => Self::NoRequirement,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TradingStatus {
    Active = 0,
    ReduceOnly = 1,
    Delisted = 2,
    Disabled = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MarginTier {
    pub lower_bound: RawNtl,
    pub prior_contribution: RawNtl,
    pub max_leverage: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarginTable {
    pub tiers: Vec<MarginTier>,
}

impl MarginTable {
    pub fn single_tier(max_leverage: u32) -> Self {
        Self {
            tiers: vec![MarginTier {
                lower_bound: 0,
                prior_contribution: 0,
                max_leverage: max_leverage as u8,
            }],
        }
    }

    pub fn tier_for_notional(&self, notional: RawNtl) -> &MarginTier {
        let mut selected = &self.tiers[0];
        for tier in &self.tiers[1..] {
            if notional < tier.lower_bound {
                break;
            }
            selected = tier;
        }
        selected
    }

    /// Mode-2 helper: `notional / (2 * leverage) - prior_contribution`, saturating at zero.
    pub fn initial_requirement(&self, notional: RawNtl) -> RawNtl {
        let tier = self.tier_for_notional(notional);
        let divisor = 2 * u64::from(tier.max_leverage.max(1));
        (notional / divisor).saturating_sub(tier.prior_contribution)
    }

    /// Mode-3 helper: `(2 * notional - 4 * leverage * prior_contribution) / (6 * leverage)`.
    pub fn maintenance_requirement(&self, notional: RawNtl) -> RawNtl {
        let tier = self.tier_for_notional(notional);
        let leverage = u64::from(tier.max_leverage.max(1));
        let lhs = notional.saturating_mul(2);
        let rhs = tier.prior_contribution.saturating_mul(4 * leverage);
        lhs.saturating_sub(rhs) / (6 * leverage)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MarginTablesView {
    pub custom_margin_tables: BTreeMap<u32, MarginTable>,
}

impl MarginTablesView {
    pub fn margin_table_for_selector(&self, selector: u32) -> MarginTable {
        if selector < BUILTIN_MARGIN_TABLE_CUTOFF {
            return MarginTable::single_tier(selector);
        }
        self.custom_margin_tables
            .get(&selector)
            .cloned()
            .unwrap_or_else(|| panic!("missing margin table"))
    }
}

/// The 64-byte value stored in the user's per-asset position tree.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct PositionRecord {
    /// Offset +0x00. Zero is cross margin; nonzero is treated as isolated by margin helpers.
    pub margin_mode_or_isolated: u32,
    /// Offset +0x04. Used directly by simple leverage and capped leverage modes.
    pub max_leverage: u32,
    /// Offset +0x08. Isolated margin balance, also used by delisted-close margin transfers.
    pub margin_raw: SignedNtl,
    /// Offset +0x10. Positive is long, negative is short.
    pub szi: i64,
    pub _unknown_field_at_0x18: [u8; 24],
    /// Offset +0x30. The ADL path requires this to be nonnegative and uses it as the PnL denominator.
    pub cumulative_funding_raw: SignedNtl,
    /// Offset +0x38. Selects either a built-in leverage table or a custom margin table.
    pub margin_table_id: u32,
    pub _unknown_field_at_0x3c: u32,
}

impl PositionRecord {
    pub fn cross(max_leverage: u32, margin_table_id: u32) -> Self {
        Self {
            max_leverage,
            margin_table_id,
            ..Self::default()
        }
    }

    pub fn isolated(max_leverage: u32, margin_table_id: u32, margin_raw: SignedNtl) -> Self {
        Self {
            margin_mode_or_isolated: 1,
            max_leverage,
            margin_raw,
            margin_table_id,
            ..Self::default()
        }
    }

    #[inline]
    pub fn is_isolated(self) -> bool {
        (self.margin_mode_or_isolated as u8) != 0
    }

    #[inline]
    pub fn is_cross(self) -> bool {
        !self.is_isolated()
    }

    #[inline]
    pub fn side_matches(self, is_long: bool) -> bool {
        self.szi != 0 && ((self.szi > 0) == is_long)
    }

    pub fn signed_notional(self, oracle_px_raw: RawPx) -> SignedNtl {
        checked_signed_notional(self.szi, oracle_px_raw)
    }

    pub fn abs_notional(self, oracle_px_raw: RawPx) -> RawNtl {
        self.signed_notional(oracle_px_raw).unsigned_abs()
    }

    pub fn isolated_equity(self, oracle_px_raw: RawPx) -> SignedNtl {
        self.margin_raw
            .saturating_add(self.signed_notional(oracle_px_raw))
    }

    pub fn adl_profit_fraction(self, oracle_px_raw: RawPx, is_long: bool) -> f64 {
        if self.cumulative_funding_raw < 0 {
            panic!("called `Result::unwrap()` on an `Err` value");
        }
        let signed_notional = self.signed_notional(oracle_px_raw);
        let reference = self.cumulative_funding_raw;
        let side_reference = if is_long { reference } else { -reference };
        let pnl = signed_notional.saturating_sub(side_reference);
        if pnl > 0 && reference != 0 {
            ((pnl as f64) / (reference as f64)).max(ADL_MIN_FACTOR)
        } else {
            ADL_MIN_FACTOR
        }
    }

    pub fn apply_margin_delta(&mut self, delta: SignedNtl) -> Result<(), u16> {
        self.margin_raw = self
            .margin_raw
            .checked_add(delta)
            .ok_or(RESULT_SIGNED_POSITION_OVERFLOW)?;
        Ok(())
    }

    pub fn apply_size_delta(&mut self, delta: i64) -> Result<(), u16> {
        self.szi = self.szi.checked_add(delta).ok_or(RESULT_SIGNED_POSITION_OVERFLOW)?;
        Ok(())
    }

    pub fn apply_size_and_margin_delta(&mut self, size_delta: i64, margin_delta: SignedNtl) -> Result<(), u16> {
        let mut next = *self;
        next.apply_margin_delta(margin_delta)?;
        next.apply_size_delta(size_delta)?;
        *self = next;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MarginSummary {
    pub active: bool,
    pub signed_margin_after: SignedNtl,
    pub effective_margin: RawNtl,
    pub notional: RawNtl,
    pub previous_margin: SignedNtl,
    pub computed_requirement: RawNtl,
}

impl MarginSummary {
    pub fn surplus(self) -> SignedNtl {
        self.signed_margin_after
            .saturating_sub(self.computed_requirement.min(i64::MAX as u64) as i64)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AggregateMarginSummary {
    pub signed_equity_or_value: SignedNtl,
    pub margin_requirement_sum: RawNtl,
    pub abs_notional_sum: RawNtl,
    pub isolated_margin_sum: SignedNtl,
}

impl AggregateMarginSummary {
    pub fn surplus(self) -> SignedNtl {
        self.signed_equity_or_value
            .saturating_sub(self.margin_requirement_sum.min(i64::MAX as u64) as i64)
    }
}

#[derive(Clone, Debug, Default)]
pub struct UserPositionSet {
    /// The B-tree wrapper's first word is the account-level signed value before per-position sums.
    pub signed_account_value: SignedNtl,
    pub positions_by_asset: BTreeMap<AssetId, PositionRecord>,
}

impl UserPositionSet {
    pub fn compute_adl_candidate_score(
        &self,
        asset: AssetId,
        is_long: bool,
        oracle_prices: &OraclePrices,
        tables: &MarginTablesView,
        user: Address,
        cap_leverage: u8,
    ) -> Option<AdlCandidate> {
        let position = self.positions_by_asset.get(&asset)?;
        if !position.side_matches(is_long) {
            return None;
        }

        let oracle_px = oracle_prices.price_for_asset(asset);
        let margin = compute_margin_requirement_by_mode(
            position,
            oracle_px,
            PositionMarginMode::Initial,
            cap_leverage,
            tables,
        );

        let effective_leverage = if position.is_cross() {
            let aggregate = aggregate_position_margin_summary(
                self,
                false,
                PositionMarginMode::SimpleMaxLeverage,
                cap_leverage,
                oracle_prices,
                tables,
            );
            if margin.active {
                panic!("internal error: entered unreachable code: Position must be cross");
            }
            if aggregate.signed_equity_or_value > 0 {
                (margin.notional as f64) / (aggregate.signed_equity_or_value as f64)
            } else {
                0.0
            }
        } else {
            let equity = position.isolated_equity(oracle_px);
            if equity > 0 {
                (position.abs_notional(oracle_px) as f64) / (equity as f64)
            } else {
                0.0
            }
        };

        let profit_fraction = position.adl_profit_fraction(oracle_px, is_long);
        Some(AdlCandidate {
            score: effective_leverage.max(ADL_MIN_FACTOR) * profit_fraction,
            user,
        })
    }

    pub fn margin_surplus_for_asset_or_account(
        &self,
        asset: AssetId,
        single_asset: bool,
        mode: PositionMarginMode,
        cap_leverage: u8,
        oracle_prices: &OraclePrices,
        tables: &MarginTablesView,
    ) -> SignedNtl {
        if single_asset {
            let Some(position) = self.positions_by_asset.get(&asset) else {
                return 0;
            };
            let summary = compute_margin_requirement_by_mode(
                position,
                oracle_prices.price_for_asset(asset),
                mode,
                cap_leverage,
                tables,
            );
            if !summary.active {
                panic!("internal error: expected isolated position");
            }
            summary.surplus()
        } else {
            aggregate_position_margin_summary(self, false, mode, cap_leverage, oracle_prices, tables).surplus()
        }
    }

    pub fn liquidation_shortfall(
        &self,
        asset: AssetId,
        single_asset: bool,
        mode: PositionMarginMode,
        cap_leverage: u8,
        oracle_prices: &OraclePrices,
        tables: &MarginTablesView,
    ) -> RawNtl {
        let surplus = self.margin_surplus_for_asset_or_account(
            asset,
            single_asset,
            mode,
            cap_leverage,
            oracle_prices,
            tables,
        );
        if surplus < 0 {
            surplus.unsigned_abs()
        } else {
            0
        }
    }

    pub fn apply_user_asset_position_delta(
        &mut self,
        asset: AssetId,
        delta: SignedNtl,
        status: TradingStatus,
        oracle_prices: &OraclePrices,
        tables: &MarginTablesView,
        cap_leverage: u8,
    ) -> u16 {
        if delta == 0 {
            return 73;
        }
        if delta < 0 && status == TradingStatus::Delisted {
            return 78;
        }
        let Some(existing) = self.positions_by_asset.get(&asset).copied() else {
            return 72;
        };
        if delta > existing.szi.unsigned_abs().min(i64::MAX as u64) as i64 {
            return RESULT_INSUFFICIENT_AVAILABLE_MARGIN;
        }

        let mut next = existing;
        if next.apply_size_and_margin_delta(delta, delta).is_err() {
            return RESULT_SIGNED_POSITION_OVERFLOW;
        }
        if delta < 0 {
            let margin = compute_margin_requirement_by_mode(
                &next,
                oracle_prices.price_for_asset(asset),
                PositionMarginMode::CappedLeverage,
                cap_leverage,
                tables,
            );
            if margin.surplus() < 0 {
                return RESULT_MARGIN_WOULD_BE_NEGATIVE;
            }
        }
        self.positions_by_asset.insert(asset, next);
        RESULT_SUCCESS
    }

    pub fn close_delisted_asset_to_margin_ratio(
        &mut self,
        asset: AssetId,
        ratio: f64,
        status: TradingStatus,
        oracle_prices: &OraclePrices,
    ) -> u16 {
        if !(DELISTED_CLOSE_MIN_RATIO..=DELISTED_CLOSE_MAX_RATIO).contains(&ratio) {
            return RESULT_INVALID_DELISTED_CLOSE_RATIO;
        }
        if status != TradingStatus::Delisted {
            return RESULT_NOT_DELISTED;
        }
        let Some(position) = self.positions_by_asset.get_mut(&asset) else {
            return RESULT_SUCCESS;
        };
        if !position.is_isolated() {
            return RESULT_SUCCESS;
        }

        let signed_notional = position.signed_notional(oracle_prices.price_for_asset(asset));
        let equity = position.margin_raw.saturating_add(signed_notional);
        let required_equity = f64_to_i64_saturating((signed_notional.unsigned_abs() as f64) / ratio);
        let delta = match required_equity.checked_sub(equity) {
            Some(delta) => delta,
            None => return RESULT_ACCOUNT_VALUE_OVERFLOW,
        };
        if delta > 0 {
            if self.signed_account_value < delta {
                return RESULT_INSUFFICIENT_AVAILABLE_MARGIN;
            }
            self.signed_account_value = self.signed_account_value.saturating_sub(delta);
            position.margin_raw = position.margin_raw.saturating_add(delta);
        }
        RESULT_SUCCESS
    }
}

#[derive(Clone, Debug, Default)]
pub struct OraclePrices {
    /// Rows have 96-byte stride in the binary; the raw price is read from row offset +0x20.
    pub rows: Vec<RawPx>,
}

impl OraclePrices {
    pub fn price_for_asset(&self, asset: AssetId) -> RawPx {
        let local = (asset % ASSETS_PER_DEX) as usize;
        self.rows[local]
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AdlCandidate {
    pub score: f64,
    pub user: Address,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiquidationCandidate {
    pub user: Address,
    pub asset: AssetId,
    pub side_is_long: bool,
    pub shortfall: RawNtl,
    pub abs_position_size: u64,
}

#[derive(Clone, Debug, Default)]
pub struct PositionUniverse {
    pub users: BTreeMap<Address, UserPositionSet>,
}

impl PositionUniverse {
    pub fn collect_liquidation_candidates(
        &self,
        asset: AssetId,
        single_asset: bool,
        mode: PositionMarginMode,
        cap_leverage: u8,
        oracle_prices: &OraclePrices,
        tables: &MarginTablesView,
        excluded_users: &BTreeSet<Address>,
    ) -> Vec<LiquidationCandidate> {
        let mut out = Vec::new();
        for (user, positions) in &self.users {
            if excluded_users.contains(user) {
                continue;
            }
            let shortfall = positions.liquidation_shortfall(
                asset,
                single_asset,
                mode,
                cap_leverage,
                oracle_prices,
                tables,
            );
            if shortfall == 0 {
                continue;
            }
            let Some(position) = positions.positions_by_asset.get(&asset) else {
                continue;
            };
            if position.szi == 0 {
                continue;
            }
            out.push(LiquidationCandidate {
                user: *user,
                asset,
                side_is_long: position.szi > 0,
                shortfall,
                abs_position_size: position.szi.unsigned_abs(),
            });
        }
        out
    }
}

pub fn compute_margin_requirement_by_mode(
    position: &PositionRecord,
    oracle_px_raw: RawPx,
    mode: PositionMarginMode,
    cap_leverage: u8,
    tables: &MarginTablesView,
) -> MarginSummary {
    let signed_notional = position.signed_notional(oracle_px_raw);
    let notional = signed_notional.unsigned_abs();
    let computed_requirement = match mode {
        PositionMarginMode::NoRequirement => 0,
        PositionMarginMode::SimpleMaxLeverage => div_by_leverage(notional, position.max_leverage),
        PositionMarginMode::Initial => tables
            .margin_table_for_selector(position.margin_table_id)
            .initial_requirement(notional),
        PositionMarginMode::Maintenance => tables
            .margin_table_for_selector(position.margin_table_id)
            .maintenance_requirement(notional),
        PositionMarginMode::CappedLeverage => {
            let capped = position.max_leverage.min(u32::from(cap_leverage));
            div_by_leverage(notional, capped)
        }
    };

    if position.is_cross() {
        return MarginSummary {
            active: false,
            signed_margin_after: signed_notional,
            effective_margin: computed_requirement,
            notional,
            previous_margin: 0,
            computed_requirement: 0,
        };
    }

    let signed_margin_after = position.margin_raw.saturating_add(signed_notional);
    MarginSummary {
        active: true,
        signed_margin_after,
        effective_margin: signed_margin_after.max(0) as RawNtl,
        notional,
        previous_margin: position.margin_raw,
        computed_requirement,
    }
}

pub fn aggregate_position_margin_summary(
    positions: &UserPositionSet,
    include_isolated: bool,
    mode: PositionMarginMode,
    cap_leverage: u8,
    oracle_prices: &OraclePrices,
    tables: &MarginTablesView,
) -> AggregateMarginSummary {
    let mut out = AggregateMarginSummary {
        signed_equity_or_value: positions.signed_account_value,
        ..AggregateMarginSummary::default()
    };

    for (&asset, position) in &positions.positions_by_asset {
        if !include_isolated && position.is_isolated() {
            continue;
        }
        let margin = compute_margin_requirement_by_mode(
            position,
            oracle_prices.price_for_asset(asset),
            mode,
            cap_leverage,
            tables,
        );
        out.signed_equity_or_value = out
            .signed_equity_or_value
            .saturating_add(margin.signed_margin_after);
        out.margin_requirement_sum = out.margin_requirement_sum.saturating_add(margin.effective_margin);
        out.abs_notional_sum = out.abs_notional_sum.saturating_add(margin.notional);
        if margin.active {
            out.isolated_margin_sum = out.isolated_margin_sum.saturating_add(margin.previous_margin);
        }
    }

    out
}

#[inline]
pub fn checked_signed_notional(szi: i64, oracle_px_raw: RawPx) -> SignedNtl {
    if oracle_px_raw < 0 {
        panic!("negative oracle price");
    }
    szi.checked_mul(oracle_px_raw).unwrap_or_else(|| panic!("position notional overflow"))
}

#[inline]
fn div_by_leverage(notional: RawNtl, leverage: u32) -> RawNtl {
    let leverage = u64::from(leverage.max(1));
    notional / leverage
}

#[inline]
fn f64_to_i64_saturating(value: f64) -> i64 {
    if value.is_nan() {
        0
    } else if value >= i64::MAX as f64 {
        i64::MAX
    } else if value <= i64::MIN as f64 {
        i64::MIN
    } else {
        value as i64
    }
}
