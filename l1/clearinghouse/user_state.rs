#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type AssetId = u64;
pub type RawPx = i64;
pub type RawNtl = u64;
pub type SignedNtl = i64;

pub const ASSETS_PER_DEX: AssetId = 10_000;
pub const BUILTIN_MARGIN_TABLE_CUTOFF: u32 = 50;

pub const RESULT_INVALID_MAX_LEVERAGE: u16 = 67;
pub const RESULT_ONLY_ISOLATED_ASSET: u16 = 68;
pub const RESULT_LEVERAGE_MODE_MISMATCH: u16 = 69;
pub const RESULT_MISSING_USER_FOR_POSITION_DELTA: u16 = 72;
pub const RESULT_ZERO_POSITION_DELTA: u16 = 73;
pub const RESULT_MISSING_ASSET_CONTEXT: u16 = 74;
pub const RESULT_INSUFFICIENT_AVAILABLE_MARGIN: u16 = 75;
pub const RESULT_MARGIN_WOULD_BE_NEGATIVE: u16 = 76;
pub const RESULT_NON_NORMAL_POSITION_CONTEXT: u16 = 77;
pub const RESULT_DELISTED_ASSET_CANNOT_BE_REDUCED_HERE: u16 = 78;
pub const RESULT_MARGIN_TABLE_WOULD_INCREASE_REQUIREMENT: u16 = 79;
pub const RESULT_MAX_LEVERAGE_TOO_HIGH_FOR_TABLE: u16 = 80;
pub const RESULT_SIGNED_POSITION_OVERFLOW: u16 = 190;
pub const RESULT_ACCOUNT_VALUE_OVERFLOW: u16 = 191;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TradingStatus {
    Active = 0,
    ReduceOnly = 1,
    Delisted = 2,
    Disabled = 3,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct PositionRecord {
    /// +0x00. Zero is cross margin; nonzero is isolated margin.
    pub margin_mode_or_isolated: u32,
    /// +0x04. User-selected leverage cap.
    pub max_leverage: u32,
    /// +0x08. Isolated margin balance. Cross positions leave this at zero.
    pub margin_raw: SignedNtl,
    /// +0x10. Signed position size; positive is long, negative is short.
    pub szi: i64,
    pub _unknown_field_at_0x18: [u8; 24],
    /// +0x30. Funding basis used by ADL/profit calculations in adjacent position helpers.
    pub cumulative_funding_raw: SignedNtl,
    /// +0x38. Built-in margin table id below 50; otherwise key into custom tables.
    pub margin_table_id: u32,
    pub _unknown_field_at_0x3c: u32,
}

impl PositionRecord {
    #[inline]
    pub fn is_isolated(self) -> bool {
        (self.margin_mode_or_isolated as u8) != 0
    }

    #[inline]
    pub fn is_cross(self) -> bool {
        !self.is_isolated()
    }

    #[inline]
    pub fn signed_notional(self, oracle_px_raw: RawPx) -> SignedNtl {
        checked_signed_notional(self.szi, oracle_px_raw)
    }

    #[inline]
    pub fn abs_notional(self, oracle_px_raw: RawPx) -> RawNtl {
        self.signed_notional(oracle_px_raw).unsigned_abs()
    }

    pub fn with_margin_delta(mut self, delta: SignedNtl) -> Result<Self, u16> {
        self.margin_raw = self
            .margin_raw
            .checked_add(delta)
            .ok_or(RESULT_SIGNED_POSITION_OVERFLOW)?;
        Ok(self)
    }

    pub fn with_size_delta(mut self, delta: i64) -> Result<Self, u16> {
        self.szi = self.szi.checked_add(delta).ok_or(RESULT_SIGNED_POSITION_OVERFLOW)?;
        Ok(self)
    }
}

#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct UserState {
    /// +0x00. Cross-margin cash/account value. Isolated margin transfers subtract from here.
    pub signed_account_value: SignedNtl,
    /// +0x08. BTreeMap entries have u64 asset keys and 64-byte PositionRecord values.
    pub positions_by_asset: BTreeMap<AssetId, PositionRecord>,
    /// +0x20. Maintained by update paths from old/new signed size; zero removes the user from the active set.
    pub open_position_count: u64,
    /// +0x28. [INFERENCE] Per-asset margin/cache tree copied with user state during position updates.
    pub cached_margin_by_asset: BTreeMap<AssetId, SignedNtl>,
    /// +0x40. [INFERENCE] Secondary per-asset cache; exact source name was not present in strings.
    pub _unknown_field_at_0x40: BTreeMap<AssetId, SignedNtl>,
    /// +0x58. [INFERENCE] Tertiary per-asset cache; exact source name was not present in strings.
    pub _unknown_field_at_0x58: BTreeMap<AssetId, SignedNtl>,
}

impl UserState {
    #[inline]
    pub fn position(&self, asset: AssetId) -> Option<&PositionRecord> {
        self.positions_by_asset.get(&asset)
    }

    #[inline]
    pub fn position_mut(&mut self, asset: AssetId) -> Option<&mut PositionRecord> {
        self.positions_by_asset.get_mut(&asset)
    }

    pub fn refresh_open_position_count(&mut self) -> u64 {
        self.open_position_count = self
            .positions_by_asset
            .values()
            .filter(|position| position.szi != 0)
            .count() as u64;
        self.open_position_count
    }

    pub fn apply_open_position_count_delta(&mut self, old_szi: i64, new_szi: i64) {
        match (old_szi == 0, new_szi == 0) {
            (true, false) => self.open_position_count = self.open_position_count.saturating_add(1),
            (false, true) => self.open_position_count = self.open_position_count.saturating_sub(1),
            _ => {}
        }
    }

    pub fn aggregate_position_margin_summary(
        &self,
        include_isolated: bool,
        mode: PositionMarginMode,
        cap_leverage: u8,
        oracle_prices: &OraclePrices,
        tables: &MarginTablesView,
    ) -> AggregateMarginSummary {
        let mut out = AggregateMarginSummary {
            signed_equity_or_value: self.signed_account_value,
            ..AggregateMarginSummary::default()
        };

        for (&asset, position) in &self.positions_by_asset {
            if !include_isolated && position.is_isolated() {
                continue;
            }

            let summary = compute_margin_requirement_by_mode(
                position,
                oracle_prices.price_for_asset(asset),
                mode,
                cap_leverage,
                tables,
            );

            out.signed_equity_or_value = out
                .signed_equity_or_value
                .saturating_add(summary.signed_margin_after);
            out.margin_requirement_sum = out
                .margin_requirement_sum
                .saturating_add(summary.effective_margin);
            out.abs_notional_sum = out.abs_notional_sum.saturating_add(summary.notional);
            if summary.active {
                out.isolated_margin_sum = out
                    .isolated_margin_sum
                    .saturating_add(summary.previous_margin);
            }
        }

        out
    }

    /// Recovered core helper at 0x37d77e0.
    ///
    /// `isolated = true` computes one asset's isolated surplus. `isolated = false` computes
    /// the cross-account surplus over all non-isolated positions.
    pub fn margin_delta_for_asset(
        &self,
        isolated: bool,
        asset: AssetId,
        mode: PositionMarginMode,
        cap_leverage: u8,
        oracle_prices: &OraclePrices,
        tables: &MarginTablesView,
    ) -> SignedNtl {
        if isolated {
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
                panic!("internal error: entered unreachable code");
            }
            return summary
                .signed_margin_after
                .saturating_sub(summary.computed_requirement.min(i64::MAX as u64) as i64);
        }

        let aggregate = self.aggregate_position_margin_summary(false, mode, cap_leverage, oracle_prices, tables);
        if aggregate.margin_requirement_sum > i64::MAX as u64 {
            panic!("called `Result::unwrap()` on an `Err` value");
        }
        aggregate
            .signed_equity_or_value
            .saturating_sub(aggregate.margin_requirement_sum as i64)
    }

    pub fn available_margin_after_reserved(
        &self,
        reserved_ntl: RawNtl,
        oracle_prices: &OraclePrices,
        tables: &MarginTablesView,
        cap_leverage: u8,
    ) -> RawNtl {
        let margin = self.margin_delta_for_asset(
            false,
            0,
            PositionMarginMode::CappedLeverage,
            cap_leverage,
            oracle_prices,
            tables,
        );
        (margin.max(0) as RawNtl).saturating_sub(reserved_ntl)
    }

    /// Transfer margin between cross account value and an isolated position.
    /// Positive `delta` moves cross account value into isolated margin; negative withdraws it.
    pub fn apply_isolated_margin_delta(
        &mut self,
        asset: AssetId,
        delta: SignedNtl,
        status: TradingStatus,
        oracle_prices: &OraclePrices,
        tables: &MarginTablesView,
        cap_leverage: u8,
    ) -> u16 {
        if delta == 0 {
            return RESULT_ZERO_POSITION_DELTA;
        }
        if delta < 0 && status == TradingStatus::Delisted {
            return RESULT_DELISTED_ASSET_CANNOT_BE_REDUCED_HERE;
        }
        if delta > self.signed_account_value {
            return RESULT_INSUFFICIENT_AVAILABLE_MARGIN;
        }

        let Some(existing) = self.positions_by_asset.get(&asset).copied() else {
            return RESULT_MISSING_USER_FOR_POSITION_DELTA;
        };
        if !existing.is_isolated() {
            return RESULT_NON_NORMAL_POSITION_CONTEXT;
        }

        let next = match existing.with_margin_delta(delta) {
            Ok(next) => next,
            Err(tag) => return tag,
        };

        if delta < 0 {
            let summary = compute_margin_requirement_by_mode(
                &next,
                oracle_prices.price_for_asset(asset),
                PositionMarginMode::CappedLeverage,
                cap_leverage,
                tables,
            );
            if summary
                .signed_margin_after
                .saturating_sub(summary.computed_requirement.min(i64::MAX as u64) as i64)
                < 0
            {
                return RESULT_MARGIN_WOULD_BE_NEGATIVE;
            }
        }

        let Some(next_account_value) = self.signed_account_value.checked_sub(delta) else {
            return RESULT_ACCOUNT_VALUE_OVERFLOW;
        };
        self.signed_account_value = next_account_value;
        self.positions_by_asset.insert(asset, next);
        RESULT_SUCCESS
    }

    /// Update leverage and cross/isolated mode for an existing or new per-asset position.
    pub fn set_leverage_mode(
        &mut self,
        asset: AssetId,
        isolated: bool,
        leverage: u32,
        asset_max_leverage: u8,
        margin_table_id: u32,
        oracle_prices: &OraclePrices,
        tables: &MarginTablesView,
        cap_leverage: u8,
    ) -> u16 {
        if leverage > u32::from(asset_max_leverage) {
            return RESULT_INVALID_MAX_LEVERAGE;
        }

        let mut next = self.positions_by_asset.get(&asset).copied().unwrap_or_default();
        let old = next;
        if next.szi != 0 && next.is_isolated() != isolated {
            return RESULT_LEVERAGE_MODE_MISMATCH;
        }

        next.margin_mode_or_isolated = u32::from(isolated);
        next.max_leverage = leverage;
        next.margin_table_id = margin_table_id;

        if old.margin_table_id != margin_table_id
            && self.margin_delta_with_position_override(
                asset,
                next,
                isolated,
                PositionMarginMode::Initial,
                cap_leverage,
                oracle_prices,
                tables,
            ) < 0
        {
            return RESULT_MARGIN_TABLE_WOULD_INCREASE_REQUIREMENT;
        }

        if leverage < old.max_leverage
            && self.margin_delta_with_position_override(
                asset,
                next,
                isolated,
                PositionMarginMode::SimpleMaxLeverage,
                cap_leverage,
                oracle_prices,
                tables,
            ) < 0
        {
            return RESULT_MARGIN_WOULD_BE_NEGATIVE;
        }

        self.positions_by_asset.insert(asset, next);
        RESULT_SUCCESS
    }

    fn margin_delta_with_position_override(
        &self,
        asset: AssetId,
        position: PositionRecord,
        isolated: bool,
        mode: PositionMarginMode,
        cap_leverage: u8,
        oracle_prices: &OraclePrices,
        tables: &MarginTablesView,
    ) -> SignedNtl {
        if isolated {
            let summary = compute_margin_requirement_by_mode(
                &position,
                oracle_prices.price_for_asset(asset),
                mode,
                cap_leverage,
                tables,
            );
            return summary
                .signed_margin_after
                .saturating_sub(summary.computed_requirement.min(i64::MAX as u64) as i64);
        }

        let mut aggregate = AggregateMarginSummary {
            signed_equity_or_value: self.signed_account_value,
            ..AggregateMarginSummary::default()
        };
        for (&entry_asset, entry_position) in &self.positions_by_asset {
            let position = if entry_asset == asset { &position } else { entry_position };
            if position.is_isolated() {
                continue;
            }
            let summary = compute_margin_requirement_by_mode(
                position,
                oracle_prices.price_for_asset(entry_asset),
                mode,
                cap_leverage,
                tables,
            );
            aggregate.signed_equity_or_value = aggregate
                .signed_equity_or_value
                .saturating_add(summary.signed_margin_after);
            aggregate.margin_requirement_sum = aggregate
                .margin_requirement_sum
                .saturating_add(summary.effective_margin);
        }
        aggregate
            .signed_equity_or_value
            .saturating_sub(aggregate.margin_requirement_sum.min(i64::MAX as u64) as i64)
    }

    pub fn collect_negative_margin_assets(
        &self,
        user: Address,
        mode: PositionMarginMode,
        cap_leverage: u8,
        oracle_prices: &OraclePrices,
        tables: &MarginTablesView,
    ) -> Vec<NegativeMarginEntry> {
        let mut out = Vec::new();
        let account_delta = self.margin_delta_for_asset(false, 0, mode, cap_leverage, oracle_prices, tables);
        if account_delta < 0 {
            out.push(NegativeMarginEntry {
                kind: NegativeMarginKind::Account,
                asset: None,
                delta: account_delta,
                user,
            });
        }

        for (&asset, position) in &self.positions_by_asset {
            if !position.is_isolated() {
                continue;
            }
            let delta = self.margin_delta_for_asset(true, asset, mode, cap_leverage, oracle_prices, tables);
            if delta < 0 {
                out.push(NegativeMarginEntry {
                    kind: NegativeMarginKind::IsolatedAsset,
                    asset: Some(asset),
                    delta,
                    user,
                });
            }
        }
        out
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AggregateMarginSummary {
    pub signed_equity_or_value: SignedNtl,
    pub margin_requirement_sum: RawNtl,
    pub abs_notional_sum: RawNtl,
    pub isolated_margin_sum: SignedNtl,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegativeMarginKind {
    Account,
    IsolatedAsset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NegativeMarginEntry {
    pub kind: NegativeMarginKind,
    pub asset: Option<AssetId>,
    pub delta: SignedNtl,
    pub user: Address,
}

#[derive(Clone, Debug, Default)]
pub struct ActiveUsersWithPositions {
    pub users: BTreeSet<Address>,
}

impl ActiveUsersWithPositions {
    pub fn refresh_user(&mut self, user: Address, previous_count: u64, state: &UserState) {
        match (previous_count == 0, state.open_position_count == 0) {
            (true, false) => {
                self.users.insert(user);
            }
            (false, true) => {
                self.users.remove(&user);
            }
            _ => {}
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct OraclePrices {
    /// The binary indexes `rows[asset % 10000]` and reads the signed raw price at row offset +0x20.
    pub rows: Vec<OracleAssetRow>,
}

impl OraclePrices {
    pub fn price_for_asset(&self, asset: AssetId) -> RawPx {
        let local = (asset % ASSETS_PER_DEX) as usize;
        self.rows[local].signed_px_raw
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct OracleAssetRow {
    pub _unknown_field_at_0x00: [u64; 4],
    pub signed_px_raw: RawPx,
    pub _unknown_field_at_0x28: [u64; 7],
}

#[derive(Clone, Debug, Default)]
pub struct MarginTablesView {
    pub custom_margin_tables: BTreeMap<u32, MarginTable>,
}

impl MarginTablesView {
    pub fn margin_table_for_selector(&self, selector: u32) -> MarginTable {
        if selector < BUILTIN_MARGIN_TABLE_CUTOFF {
            return MarginTable::single_tier(selector as u8);
        }
        self.custom_margin_tables
            .get(&selector)
            .cloned()
            .unwrap_or_else(|| panic!("called `Option::unwrap()` on a `None` value"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarginTable {
    pub tiers: Vec<MarginTier>,
}

impl MarginTable {
    pub fn single_tier(max_leverage: u8) -> Self {
        Self {
            tiers: vec![MarginTier {
                lower_bound: 0,
                prior_contribution: 0,
                max_leverage: max_leverage.max(1),
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

    /// Initial-margin tier helper recovered as `notional / (2 * leverage) - prior_contribution`.
    pub fn ntl_div_2x_leverage_minus_prior_contribution(&self, notional: RawNtl) -> RawNtl {
        let tier = self.tier_for_notional(notional);
        let divisor = 2 * u64::from(tier.max_leverage.max(1));
        (notional / divisor).saturating_sub(tier.prior_contribution)
    }

    /// Maintenance-margin tier helper recovered as `(2 * notional - 4 * leverage * prior) / (6 * leverage)`.
    pub fn margin_after_tier_offset_div_6x_leverage(&self, notional: RawNtl) -> RawNtl {
        let tier = self.tier_for_notional(notional);
        let leverage = u64::from(tier.max_leverage.max(1));
        let lhs = notional.saturating_mul(2);
        let rhs = tier.prior_contribution.saturating_mul(4 * leverage);
        lhs.saturating_sub(rhs) / (6 * leverage)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MarginTier {
    pub lower_bound: RawNtl,
    pub prior_contribution: RawNtl,
    pub max_leverage: u8,
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
            .ntl_div_2x_leverage_minus_prior_contribution(notional),
        PositionMarginMode::Maintenance => tables
            .margin_table_for_selector(position.margin_table_id)
            .margin_after_tier_offset_div_6x_leverage(notional),
        PositionMarginMode::CappedLeverage => {
            div_by_leverage(notional, position.max_leverage.min(u32::from(cap_leverage)))
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

#[inline]
pub fn checked_signed_notional(szi: i64, oracle_px_raw: RawPx) -> SignedNtl {
    if oracle_px_raw < 0 {
        panic!("negative oracle price");
    }
    szi.checked_mul(oracle_px_raw)
        .unwrap_or_else(|| panic!("position notional overflow"))
}

#[inline]
fn div_by_leverage(notional: RawNtl, leverage: u32) -> RawNtl {
    notional / u64::from(leverage.max(1))
}
