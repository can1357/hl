#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};

pub type Address = [u8; 20];
pub type AssetId = u64;
pub type DexId = u64;

pub const ASSETS_PER_DEX: AssetId = 10_000;
pub const SUCCESS_RESULT_TAG: u16 = 390;
pub const OPEN_INTEREST_CAP_LOG_TOPIC: &str = "open interest cap";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ClearinghouseResultTag {
    MissingUserForPositionDelta = 72,
    ZeroPositionDelta = 73,
    MissingAssetContext = 74,
    PositionDeltaTooLarge = 75,
    MarginWouldBeNegative = 76,
    NonNormalPositionContext = 77,
    DelistedAssetCannotBeReducedHere = 78,
    SignedPositionOverflow = 190,
    AccountValueOverflow = 191,
    Success = SUCCESS_RESULT_TAG,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TradingStatus {
    #[default]
    Active,
    ReduceOnly,
    Delisted,
    Disabled,
    Unknown(u8),
}

impl TradingStatus {
    fn from_storage_byte(value: u8) -> Self {
        match value {
            0 => Self::Active,
            1 => Self::ReduceOnly,
            2 => Self::Delisted,
            3 => Self::Disabled,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PositionContextKind {
    Empty,
    #[default]
    Normal,
    Unknown(u32),
}

impl PositionContextKind {
    fn from_storage(value: u32) -> Self {
        match value {
            0 => Self::Empty,
            1 => Self::Normal,
            other => Self::Unknown(other),
        }
    }

    fn as_storage(self) -> u32 {
        match self {
            Self::Empty => 0,
            Self::Normal => 1,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct AssetMeta48 {
    pub name_index_or_tag: u64,
    pub max_leverage: u32,
    pub sz_decimals: u32,
    pub margin_table_or_oi_unit: u32,
    pub _unknown_field_at_0x1c: u32,
    pub only_isolated_or_status: u8,
    pub _unknown_field_at_0x29: [u8; 7],
    pub _unknown_field_at_0x30: u64,
}

impl AssetMeta48 {
    pub fn trading_status(&self) -> TradingStatus {
        TradingStatus::from_storage_byte(self.only_isolated_or_status)
    }
}

#[derive(Clone, Debug, Default)]
pub struct AssetRow96 {
    pub _unknown_field_at_0x00: [u64; 4],
    /// Signed raw oracle/mark price read at row +0x20 by the OI-cap and fill paths.
    pub signed_px_raw: i64,
    pub _unknown_field_at_0x28: [u64; 7],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PositionContext {
    /// Storage tag at +0x00. Normal active contexts use tag 1.
    pub kind: PositionContextKind,
    /// Asset-specific unit/table copied from asset metadata at +0x18.
    pub oi_unit: u32,
    /// Signed account/margin accumulator used by margin checks.
    pub signed_margin_or_basis: i64,
    /// Signed size: positive long, negative short.
    pub signed_sz: i64,
    pub aux_20: i64,
    pub aux_28: i64,
    /// Absolute notional/open-interest scalar maintained from size and price.
    pub abs_open_notional: u64,
    pub aux_38: u64,
}

impl PositionContext {
    pub fn new_normal(oi_unit: u32) -> Self {
        Self {
            kind: PositionContextKind::Normal,
            oi_unit,
            ..Self::default()
        }
    }

    pub fn is_normal(self) -> bool {
        self.kind == PositionContextKind::Normal
    }

    pub fn abs_sz(self) -> u64 {
        self.signed_sz.unsigned_abs()
    }

    pub fn recompute_abs_open_notional(&mut self, px: u64) -> Result<(), ClearinghouseResultTag> {
        self.abs_open_notional = if self.signed_sz == 0 || px == 0 {
            0
        } else {
            self.abs_sz()
                .checked_mul(px)
                .filter(|value| *value <= i64::MAX as u64 - 1)
                .ok_or(ClearinghouseResultTag::AccountValueOverflow)?
        };
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct UserState {
    /// Aggregate signed scalar updated when a user position is adjusted.
    pub signed_account_value: i64,
    pub positions: BTreeMap<AssetId, PositionContext>,
    pub open_position_count: u64,
    pub _unknown_field_at_0x28: BTreeMap<AssetId, i64>,
    pub _unknown_field_at_0x30: BTreeMap<AssetId, i64>,
    pub _unknown_field_at_0x38: BTreeMap<AssetId, i64>,
}

impl UserState {
    fn refresh_open_position_count(&mut self) -> (u64, u64) {
        let old = self.open_position_count;
        self.open_position_count = self.positions.values().filter(|ctx| ctx.signed_sz != 0).count() as u64;
        (old, self.open_position_count)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AggregateMarginSummary {
    pub signed_equity_or_value: i64,
    pub margin_requirement_sum: i64,
    pub abs_notional_sum: u64,
    pub isolated_margin_sum: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PositionUpdateSide {
    pub kind: PositionContextKind,
    pub signed_sz_before: i64,
    pub user: Address,
    pub user_tag: u32,
    pub px_raw: u64,
    pub asset: AssetId,
    pub sz_delta_abs: u64,
    pub notional_delta: u64,
    pub is_buy_or_long: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedFillRecord {
    pub sequence: i64,
    pub user: Address,
    pub asset: AssetId,
    pub closed_sz: u64,
    pub notional: u64,
    pub was_long: bool,
    pub before: PositionContext,
    pub after: PositionContext,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ApplyTradeResult {
    pub tag: u16,
    pub before: PositionContext,
    pub after: PositionContext,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OiCapHit {
    pub asset: AssetId,
    pub sz: u64,
    pub scaled_delta_minus_notional: i64,
    pub notional: i64,
}

pub struct OiCapContext<'a> {
    pub clearinghouse: &'a Clearinghouse,
    pub denominator: &'a u64,
    pub _unknown_field_at_0x10: &'a u64,
    pub scale: &'a i64,
    pub remaining_budget: &'a mut i64,
}

#[derive(Clone, Debug, Default)]
pub struct OpenInterestCapLog {
    pub asset: AssetId,
    pub requested_delta: i64,
    pub current_open_interest: u64,
    pub cap: u64,
    pub oracle_px: i64,
    pub message: String,
}

#[derive(Clone, Debug, Default)]
pub struct Clearinghouse {
    /// +0x00: Vec-like asset metadata table; item stride 48 in the binary.
    pub asset_meta: Vec<AssetMeta48>,
    /// +0x30: DEX id; encoded perp asset ids are `dex_id * 10000 + local`.
    pub dex_id: DexId,
    /// +0x68: Vec-like asset/oracle rows; item stride 96 in the binary.
    pub asset_rows: Vec<AssetRow96>,
    /// +0xF8: SwissTable keyed by 20-byte user address.
    pub users: HashMap<Address, UserState>,
    /// +0x128: per-user/per-asset index refreshed when the position OI unit changes.
    pub active_position_oi_units: HashMap<(Address, AssetId), u32>,
    /// +0x158: users whose per-user open-position count is nonzero.
    pub active_users_with_positions: BTreeSet<Address>,
    /// +0x170: aggregate absolute open interest by encoded asset id.
    pub open_interest_by_asset: BTreeMap<AssetId, u64>,
    /// Streaming OI cap table read by the retain predicate before logging violations.
    pub open_interest_cap_by_asset: BTreeMap<AssetId, u64>,
    /// +0x188: dirty/touched user set inserted before mutating a position.
    pub dirty_users: BTreeSet<Address>,
    /// +0x1B8 in mode-3 paths: cumulative notional by asset.
    pub cumulative_notional_by_asset: BTreeMap<AssetId, i64>,
    pub timestamp_or_sequence_a: u64,
    pub timestamp_or_sequence_b: u64,
    /// Mode byte: value 3 enables extra aggregate-notional accounting and skips timestamp copyback.
    pub mode: u8,
    /// +0x248: mutable budget/threshold used by liquidation and OI-cap collection.
    pub oi_cap_budget: u64,
}

impl Clearinghouse {
    pub fn new(dex_id: DexId) -> Self {
        Self {
            dex_id,
            ..Self::default()
        }
    }

    pub fn encoded_asset(&self, local: usize) -> AssetId {
        self.dex_id * ASSETS_PER_DEX + local as AssetId
    }

    pub fn split_asset_id(&self, asset: AssetId) -> Result<usize, ClearinghouseResultTag> {
        let dex = asset / ASSETS_PER_DEX;
        let local = (asset % ASSETS_PER_DEX) as usize;
        if dex == self.dex_id && local < self.asset_meta.len() {
            Ok(local)
        } else {
            panic!("BUG: clearinghouse asset id out of range")
        }
    }

    pub fn asset_meta(&self, asset: AssetId) -> &AssetMeta48 {
        let local = self.split_asset_id(asset).expect("asset id checked by split_asset_id");
        &self.asset_meta[local]
    }

    pub fn asset_row(&self, asset: AssetId) -> &AssetRow96 {
        let local = (asset % ASSETS_PER_DEX) as usize;
        self.asset_rows.get(local).expect("asset row index out of range")
    }

    pub fn oracle_px_raw(&self, asset: AssetId) -> i64 {
        self.asset_row(asset).signed_px_raw
    }

    pub fn user_state(&self, user: &Address) -> Option<&UserState> {
        self.users.get(user)
    }

    pub fn user_state_mut(&mut self, user: &Address) -> Option<&mut UserState> {
        self.users.get_mut(user)
    }

    pub fn get_or_insert_user(&mut self, user: Address) -> &mut UserState {
        self.users.entry(user).or_default()
    }

    pub fn asset_oracle_context(&self, asset: AssetId) -> PositionContext {
        let meta = self.asset_meta(asset);
        PositionContext::new_normal(meta.margin_table_or_oi_unit)
    }

    pub fn get_or_insert_asset_oracle_context(
        &mut self,
        user: Address,
        asset: AssetId,
    ) -> &mut PositionContext {
        let oi_unit = self.asset_meta(asset).margin_table_or_oi_unit;
        self.dirty_users.insert(user);
        self.users
            .entry(user)
            .or_default()
            .positions
            .entry(asset)
            .or_insert_with(|| PositionContext::new_normal(oi_unit))
    }

    pub fn aggregate_position_margin_summary(
        &self,
        user: &Address,
        include_isolated: bool,
        include_cross: bool,
    ) -> AggregateMarginSummary {
        let mut summary = AggregateMarginSummary::default();
        let Some(state) = self.users.get(user) else {
            return summary;
        };

        summary.signed_equity_or_value = state.signed_account_value;
        for (&asset, ctx) in &state.positions {
            if !ctx.is_normal() || ctx.signed_sz == 0 {
                continue;
            }
            let only_isolated = self.asset_meta(asset).only_isolated_or_status != 0;
            if (only_isolated && !include_isolated) || (!only_isolated && !include_cross) {
                continue;
            }
            summary.abs_notional_sum = summary.abs_notional_sum.saturating_add(ctx.abs_open_notional);
            let margin = self.margin_delta_for_asset(ctx, asset, 2).max(0);
            summary.margin_requirement_sum = summary.margin_requirement_sum.saturating_add(margin);
            if only_isolated {
                summary.isolated_margin_sum = summary.isolated_margin_sum.saturating_add(margin);
            }
        }
        summary
    }

    pub fn margin_delta_for_asset(&self, ctx: &PositionContext, asset: AssetId, mode: u8) -> i64 {
        let px = self.oracle_px_raw(asset);
        if px <= 0 || ctx.signed_sz == 0 {
            return 0;
        }
        let notional = (ctx.signed_sz.unsigned_abs() as i128) * (px as i128);
        let leverage = self.asset_meta(asset).max_leverage.max(1) as i128;
        let base = (notional / leverage).min(i64::MAX as i128) as i64;
        match mode {
            1 => base,
            2 => base.saturating_sub(ctx.signed_margin_or_basis.max(0)),
            3 | 4 => base.saturating_add(ctx.aux_20),
            _ => base,
        }
    }

    fn refresh_user_activity_after_position_change(&mut self, user: Address) {
        let Some(state) = self.users.get_mut(&user) else {
            self.active_users_with_positions.remove(&user);
            return;
        };
        let (_old, new) = state.refresh_open_position_count();
        if new == 0 {
            self.active_users_with_positions.remove(&user);
        } else {
            self.active_users_with_positions.insert(user);
        }
    }

    fn rescale_position_oi_unit(&mut self, user: Address, asset: AssetId, oi_unit: u32) {
        if oi_unit == 0 {
            self.active_position_oi_units.remove(&(user, asset));
        } else {
            self.active_position_oi_units.insert((user, asset), oi_unit);
        }
    }

    pub fn update_open_interest_by_slot(&mut self, asset: AssetId, old_abs_sz: i64, new_abs_sz: i64) {
        let old = old_abs_sz.unsigned_abs();
        let new = new_abs_sz.unsigned_abs();
        let entry = self.open_interest_by_asset.entry(asset).or_insert(0);
        *entry = entry.saturating_sub(old).saturating_add(new);
        if *entry == 0 {
            self.open_interest_by_asset.remove(&asset);
        }
    }

    pub fn apply_trade_or_fill_update(
        &mut self,
        asset: AssetId,
        px_raw: i64,
        signed_sz_delta: i64,
        user: Address,
        side_notional_hint: i64,
    ) -> ApplyTradeResult {
        let before_summary = self.aggregate_position_margin_summary(&user, false, true);
        let withdrawable = before_summary
            .signed_equity_or_value
            .saturating_sub(before_summary.margin_requirement_sum)
            .max(0);
        let user_available_after_reserved = self
            .users
            .get(&user)
            .map(|state| state.signed_account_value.saturating_sub(withdrawable))
            .unwrap_or_default();

        let before = *self.get_or_insert_asset_oracle_context(user, asset);
        let mut after = before;
        if !after.is_normal() {
            return ApplyTradeResult { tag: 77, before, after };
        }

        let old_sz = after.signed_sz;
        let old_oi_unit = after.oi_unit;
        match old_sz.checked_add(signed_sz_delta) {
            Some(next) => after.signed_sz = next,
            None => return ApplyTradeResult { tag: 190, before, after },
        }

        let px = if px_raw <= 0 { 0 } else { px_raw as u64 };
        if after.signed_sz == 0 || old_sz.signum() != after.signed_sz.signum() {
            after.aux_20 = 0;
            after.aux_28 = 0;
        }
        if let Err(tag) = after.recompute_abs_open_notional(px) {
            return ApplyTradeResult { tag: tag as u16, before, after };
        }
        after.signed_margin_or_basis = user_available_after_reserved.saturating_add(side_notional_hint);

        let new_oi_unit = after.oi_unit;
        *self.get_or_insert_asset_oracle_context(user, asset) = after;
        self.update_open_interest_by_slot(asset, before.signed_sz, after.signed_sz);
        if old_oi_unit != new_oi_unit {
            self.rescale_position_oi_unit(user, asset, new_oi_unit);
        }
        self.refresh_user_activity_after_position_change(user);

        if self.mode == 3 {
            let abs_change = after.abs_open_notional as i64 - before.abs_open_notional as i64;
            let entry = self.cumulative_notional_by_asset.entry(asset).or_insert(0);
            *entry = entry.saturating_add(abs_change);
        }

        ApplyTradeResult { tag: SUCCESS_RESULT_TAG, before, after }
    }

    pub fn apply_user_asset_position_delta(
        &mut self,
        user: Address,
        asset: AssetId,
        delta: i64,
    ) -> ClearinghouseResultTag {
        if !self.users.contains_key(&user) {
            return ClearinghouseResultTag::MissingUserForPositionDelta;
        }
        if delta == 0 {
            return ClearinghouseResultTag::ZeroPositionDelta;
        }
        if delta < 0 && self.asset_meta(asset).trading_status() == TradingStatus::Delisted {
            return ClearinghouseResultTag::DelistedAssetCannotBeReducedHere;
        }

        let available = self
            .users
            .get(&user)
            .and_then(|state| state.positions.get(&asset))
            .map(|ctx| ctx.signed_sz.unsigned_abs() as i64)
            .unwrap_or_default();
        if delta > available {
            return ClearinghouseResultTag::PositionDeltaTooLarge;
        }

        let old = *self.get_or_insert_asset_oracle_context(user, asset);
        if old.kind == PositionContextKind::Empty {
            return ClearinghouseResultTag::MissingAssetContext;
        }
        if !old.is_normal() {
            return ClearinghouseResultTag::NonNormalPositionContext;
        }

        let mut next = old;
        next.signed_margin_or_basis = match next.signed_margin_or_basis.checked_add(delta) {
            Some(value) => value,
            None => return ClearinghouseResultTag::SignedPositionOverflow,
        };
        next.signed_sz = match next.signed_sz.checked_add(delta) {
            Some(value) => value,
            None => return ClearinghouseResultTag::SignedPositionOverflow,
        };

        if delta < 0 && self.margin_delta_for_asset(&next, asset, 4) < 0 {
            return ClearinghouseResultTag::MarginWouldBeNegative;
        }

        let old_oi_unit = old.oi_unit;
        let new_oi_unit = next.oi_unit;
        *self.get_or_insert_asset_oracle_context(user, asset) = next;
        self.update_open_interest_by_slot(asset, old.signed_sz, next.signed_sz);
        if old_oi_unit != new_oi_unit {
            self.rescale_position_oi_unit(user, asset, new_oi_unit);
        }
        self.refresh_user_activity_after_position_change(user);
        ClearinghouseResultTag::Success
    }

    pub fn apply_position_update_for_asset_side(&mut self, side: &PositionUpdateSide, is_second_side: bool) {
        if side.kind != PositionContextKind::Normal {
            return;
        }

        let old = *self.get_or_insert_asset_oracle_context(side.user, side.asset);
        let old_oi_unit = old.oi_unit;
        let mut next = old;
        let signed_delta = if is_second_side {
            -(side.sz_delta_abs as i64)
        } else {
            side.sz_delta_abs as i64
        };
        next.signed_sz = next.signed_sz.saturating_add(signed_delta);

        if next.signed_sz == 0 {
            next.abs_open_notional = 0;
        } else if old.signed_sz != 0 && old.signed_sz.signum() == next.signed_sz.signum() {
            next.abs_open_notional = next
                .abs_open_notional
                .saturating_add(side.notional_delta);
        } else {
            next.abs_open_notional = next
                .signed_sz
                .unsigned_abs()
                .saturating_mul(side.px_raw)
                .min(i64::MAX as u64 - 1);
        }

        let new_oi_unit = next.oi_unit;
        *self.get_or_insert_asset_oracle_context(side.user, side.asset) = next;
        self.update_open_interest_by_slot(side.asset, old.signed_sz, next.signed_sz);
        if old_oi_unit != new_oi_unit {
            self.rescale_position_oi_unit(side.user, side.asset, new_oi_unit);
        }
        self.refresh_user_activity_after_position_change(side.user);
    }

    pub fn flatten_asset_positions_for_book(
        &mut self,
        asset: AssetId,
        px_raw: i64,
        timestamp_source: (u64, u64),
    ) -> Vec<GeneratedFillRecord> {
        let mut out = Vec::new();
        let users: Vec<Address> = self.users.keys().copied().collect();
        let mut sequence = timestamp_source.0 as i64;

        for user in users {
            let Some(position) = self.users.get(&user).and_then(|state| state.positions.get(&asset)).copied() else {
                continue;
            };
            if position.signed_sz == 0 {
                continue;
            }

            let signed_close = position.signed_sz.saturating_neg();
            let close_abs = signed_close.unsigned_abs();
            let result = self.apply_trade_or_fill_update(asset, px_raw, signed_close, user, 0);
            if result.tag != SUCCESS_RESULT_TAG {
                panic!("called `Result::unwrap()` on an `Err` value");
            }

            sequence = sequence.saturating_add(1);
            let notional = close_abs
                .checked_mul(px_raw.max(0) as u64)
                .filter(|value| *value <= i64::MAX as u64 - 1)
                .expect("BUG: fill notional overflow");
            out.push(GeneratedFillRecord {
                sequence,
                user,
                asset,
                closed_sz: close_abs,
                notional,
                was_long: position.signed_sz > 0,
                before: result.before,
                after: result.after,
            });
        }

        if self.mode != 3 {
            self.timestamp_or_sequence_a = timestamp_source.0;
            self.timestamp_or_sequence_b = timestamp_source.1;
        }
        out
    }

    pub fn collect_perps_at_open_interest_cap(
        &self,
        denominator: &u64,
        scale: &i64,
        remaining_budget: &mut i64,
    ) -> Vec<OiCapHit> {
        let mut hits = Vec::new();
        if *denominator == 0 {
            return hits;
        }

        let mut ctx = OiCapContext {
            clearinghouse: self,
            denominator,
            _unknown_field_at_0x10: denominator,
            scale,
            remaining_budget,
        };

        for (&asset, &sz) in &self.open_interest_by_asset {
            if sz == 0 {
                continue;
            }
            let entry = PositionLikeEntry { kind: 0, sz };
            if let Some(hit) = take_open_interest_cap_adjustment(&mut ctx, asset, &entry) {
                hits.push(hit);
            }
        }
        hits
    }

    pub fn retain_if_under_open_interest_cap(
        &self,
        asset: AssetId,
        requested_delta: i64,
        logs: &mut Vec<OpenInterestCapLog>,
        cap_side_enabled: bool,
    ) -> bool {
        let current = self.open_interest_by_asset.get(&asset).copied().unwrap_or_default();
        let cap = self.open_interest_cap_by_asset.get(&asset).copied().unwrap_or_default();
        let requested_abs = requested_delta.unsigned_abs();
        let exceeds = cap_side_enabled && cap != 0 && current.saturating_add(requested_abs) > cap;
        if exceeds {
            logs.push(OpenInterestCapLog {
                asset,
                requested_delta,
                current_open_interest: current,
                cap,
                oracle_px: self.oracle_px_raw(asset),
                message: format_open_interest_cap_error(asset, requested_delta, current, cap),
            });
        }
        !exceeds
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PositionLikeEntry {
    pub kind: u32,
    pub sz: u64,
}

pub fn take_open_interest_cap_adjustment(
    ctx: &mut OiCapContext<'_>,
    asset: AssetId,
    entry: &PositionLikeEntry,
) -> Option<OiCapHit> {
    let local = (asset % ASSETS_PER_DEX) as usize;
    let px = ctx.clearinghouse.asset_rows.get(local)?.signed_px_raw;
    if px < 0 {
        panic!("BUG: OI notional overflow");
    }
    let notional = entry
        .sz
        .checked_mul(px as u64)
        .filter(|value| *value <= i64::MAX as u64)
        .map(|value| value as i64)
        .expect("BUG: OI notional overflow");

    if *ctx.denominator == 0 {
        return None;
    }

    let scaled = ((*ctx.scale as f64) * ((notional.unsigned_abs() as f64) / (*ctx.denominator as f64)))
        .clamp(i64::MIN as f64, i64::MAX as f64) as i64;
    let scaled_delta_minus_notional = scaled.saturating_sub(notional);
    *ctx.remaining_budget = ctx.remaining_budget.saturating_sub(scaled);

    Some(OiCapHit {
        asset,
        sz: entry.sz,
        scaled_delta_minus_notional,
        notional,
    })
}

pub fn format_open_interest_cap_error(
    asset: AssetId,
    requested_delta: i64,
    current_open_interest: u64,
    cap: u64,
) -> String {
    format!(
        "{}: asset={} requested_delta={} current_open_interest={} cap={}",
        OPEN_INTEREST_CAP_LOG_TOPIC, asset, requested_delta, current_open_interest, cap
    )
}
