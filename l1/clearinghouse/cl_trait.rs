use super::clearinghouse::{
    Address, ApplyTradeResult, AssetId, Clearinghouse, PositionContext, PositionContextKind,
    PositionUpdateSide, SUCCESS_RESULT_TAG,
};

pub type Px = u64;
pub type Sz = u64;
pub type Ntl = u64;

pub const PERP_OUTCOME_SUCCESS: u16 = SUCCESS_RESULT_TAG;
pub const INSERT_STATUS_DIRECT_REJECTED: InsertStatus = InsertStatus(0x8000_0000_0000_0003);
pub const INSERT_STATUS_DIRECT_REDUCE_ONLY: InsertStatus = InsertStatus(0x8000_0000_0000_0004);
pub const INSERT_STATUS_PRICE_LIMIT: InsertStatus = InsertStatus(0x8000_0000_0000_000d);
pub const INSERT_STATUS_NOTIONAL_OVERFLOW: InsertStatus = InsertStatus(0x8000_0000_0000_000e);
pub const INSERT_STATUS_OPEN_INTEREST_CAP: InsertStatus = InsertStatus(0x8000_0000_0000_000f);
pub const INSERT_STATUS_ACCOUNT_VALUE_LIMIT: InsertStatus = InsertStatus(0x8000_0000_0000_0010);
pub const INSERT_STATUS_STALE_ORACLE_GENERATED: InsertStatus = InsertStatus(0x8000_0000_0000_0011);
pub const INSERT_STATUS_AVAILABLE_SIZE: InsertStatus = InsertStatus(0x8000_0000_0000_0012);
pub const INSERT_STATUS_OK: InsertStatus = InsertStatus(0x8000_0000_0000_0018);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct InsertStatus(pub u64);

impl InsertStatus {
    #[inline]
    pub const fn is_ok(self) -> bool {
        self.0 == INSERT_STATUS_OK.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PerpSide {
    Long = 0,
    Short = 1,
}

impl PerpSide {
    #[inline]
    pub const fn from_bit(bit: u8) -> Self {
        if bit & 1 == 0 { Self::Long } else { Self::Short }
    }

    #[inline]
    pub const fn opposite(self) -> Self {
        match self {
            Self::Long => Self::Short,
            Self::Short => Self::Long,
        }
    }

    #[inline]
    pub fn signed_sz(self, sz: Sz) -> i64 {
        let raw = i64::try_from(sz).expect("perp size exceeds signed range");
        match self {
            Self::Long => raw,
            Self::Short => -raw,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OracleTimestamp {
    pub seconds: u32,
    pub nanos: u32,
    pub sequence: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerpOrderAdmission {
    pub asset: AssetId,
    pub sz: Sz,
    pub px: Px,
    pub user: Address,
    pub user_tag: u32,
    pub side: PerpSide,
    pub reduce_only: bool,
    pub post_only_or_trigger: bool,
    pub oracle_generated: bool,
    pub stale_oracle_ok: bool,
    pub crosses_book: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectOrderAccounting {
    pub asset: AssetId,
    pub requested_sz: Sz,
    pub px: Px,
    pub user: Address,
    pub user_tag: u32,
    pub side: PerpSide,
    pub reduce_only: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FillLeg {
    pub user: Address,
    pub user_tag: u32,
    pub side: PerpSide,
    pub prior_position: PositionContext,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TwoLegFillAccounting {
    pub asset: AssetId,
    pub px_raw: i64,
    pub sz: Sz,
    pub taker_side: PerpSide,
    pub taker: FillLeg,
    pub maker: FillLeg,
    pub sequence_or_time: u64,
    pub privileged_vault_cross: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PositionUpdateSummary {
    pub position_delta: i64,
    pub notional_delta: u64,
    pub side_notional_hint: i64,
    pub closed_sz: u64,
    pub fee_or_funding_delta: i64,
    pub touched_existing_position: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettledLeg {
    pub user: Address,
    pub result: ApplyTradeResult,
    pub summary: PositionUpdateSummary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TwoLegFillResult {
    pub taker: SettledLeg,
    pub maker: SettledLeg,
    pub total_closed_sz: u64,
    pub total_notional: u64,
}

/// Perp clearinghouse surface used by book insertion and order-flow code.
///
/// Recovered call sites use separate function-pointer slots for size admission,
/// price-limit admission, direct-order accounting, two-leg fill settlement,
/// position-summary calculation, and maximum-order-size calculation.  The
/// methods below keep that surface explicit while routing the concrete state
/// mutations through `Clearinghouse` helpers recovered in the companion module.
pub trait ClearinghouseCl {
    fn validate_order_sz_limits(&self, order: &PerpOrderAdmission) -> InsertStatus;

    fn price_limit_check(
        &self,
        asset: AssetId,
        side: PerpSide,
        px: Px,
        now: OracleTimestamp,
    ) -> bool;

    fn apply_direct_order_sz_accounting(&mut self, order: &DirectOrderAccounting) -> InsertStatus;

    fn apply_two_leg_fill_sz_accounting(&mut self, fill: &TwoLegFillAccounting) -> TwoLegFillResult;

    fn compute_position_update_summary(
        &self,
        asset: AssetId,
        px_raw: i64,
        sz: Sz,
        user: Address,
        side: PerpSide,
        prior: PositionContext,
    ) -> PositionUpdateSummary;

    fn compute_max_order_sz(
        &self,
        asset: AssetId,
        user: Address,
        side: PerpSide,
        px: Px,
        reduce_only: bool,
        extra_account_value: i64,
    ) -> Sz;
}

impl ClearinghouseCl for Clearinghouse {
    fn validate_order_sz_limits(&self, order: &PerpOrderAdmission) -> InsertStatus {
        if order.oracle_generated && !order.stale_oracle_ok && self.mode != 3 {
            return INSERT_STATUS_STALE_ORACLE_GENERATED;
        }

        let Ok(_local) = self.split_asset_id(order.asset) else {
            return INSERT_STATUS_AVAILABLE_SIZE;
        };
        let meta = self.asset_meta(order.asset);
        if meta.sz_decimals == 0 && order.sz == 0 {
            return INSERT_STATUS_AVAILABLE_SIZE;
        }

        let oracle_px = self.oracle_px_raw(order.asset);
        if oracle_px <= 0 || order.px == 0 {
            return INSERT_STATUS_NOTIONAL_OVERFLOW;
        }

        let Some(order_notional) = checked_notional(order.sz, order.px) else {
            return INSERT_STATUS_NOTIONAL_OVERFLOW;
        };
        let Some(oracle_notional) = checked_notional(order.sz, oracle_px as u64) else {
            return INSERT_STATUS_NOTIONAL_OVERFLOW;
        };

        if order.reduce_only {
            let position = self
                .user_state(&order.user)
                .and_then(|state| state.positions.get(&order.asset))
                .copied()
                .unwrap_or_default();
            if !is_reducing(position.signed_sz, order.side, order.sz) {
                return INSERT_STATUS_AVAILABLE_SIZE;
            }
        }

        if !self.price_limit_check(order.asset, order.side, order.px, OracleTimestamp::default()) {
            return INSERT_STATUS_PRICE_LIMIT;
        }

        let cap = self.open_interest_cap_by_asset.get(&order.asset).copied().unwrap_or_default();
        if cap != 0 {
            let current = self.open_interest_by_asset.get(&order.asset).copied().unwrap_or_default();
            if current.saturating_add(order.sz) > cap {
                return INSERT_STATUS_OPEN_INTEREST_CAP;
            }
        }

        let max_sz = self.compute_max_order_sz(
            order.asset,
            order.user,
            order.side,
            order.px,
            order.reduce_only,
            0,
        );
        if order.sz > max_sz {
            return INSERT_STATUS_ACCOUNT_VALUE_LIMIT;
        }

        if order_notional == 0 || oracle_notional == 0 {
            return INSERT_STATUS_NOTIONAL_OVERFLOW;
        }
        INSERT_STATUS_OK
    }

    fn price_limit_check(
        &self,
        asset: AssetId,
        side: PerpSide,
        px: Px,
        _now: OracleTimestamp,
    ) -> bool {
        let oracle = self.oracle_px_raw(asset);
        if oracle <= 0 || px == 0 {
            return false;
        }

        let reference = oracle as u64;
        let diff = px.abs_diff(reference);
        if diff == 0 {
            return true;
        }

        let meta = self.asset_meta(asset);
        let limit_bps = if self.mode == 3 {
            50u64
        } else if meta.sz_decimals >= 6 {
            100u64
        } else {
            2_000u64
        };
        let allowed = reference.saturating_mul(limit_bps) / 10_000;
        let within_limit = diff <= allowed.max(1);

        match side {
            PerpSide::Long => within_limit || px <= reference,
            PerpSide::Short => within_limit || px >= reference,
        }
    }

    fn apply_direct_order_sz_accounting(&mut self, order: &DirectOrderAccounting) -> InsertStatus {
        let max_sz = self.compute_max_order_sz(
            order.asset,
            order.user,
            order.side,
            order.px,
            order.reduce_only,
            0,
        );
        if max_sz < order.requested_sz && !order.reduce_only {
            return INSERT_STATUS_DIRECT_REJECTED;
        }

        let oracle_px = self.oracle_px_raw(order.asset);
        if oracle_px <= 0 {
            return INSERT_STATUS_NOTIONAL_OVERFLOW;
        }
        let Some(max_notional) = checked_notional(max_sz, oracle_px as u64) else {
            return INSERT_STATUS_NOTIONAL_OVERFLOW;
        };
        let Some(request_notional) = checked_notional(order.requested_sz, order.px) else {
            return INSERT_STATUS_NOTIONAL_OVERFLOW;
        };
        if max_sz < order.requested_sz && max_notional < request_notional {
            return INSERT_STATUS_DIRECT_REDUCE_ONLY;
        }

        let prior = self
            .user_state(&order.user)
            .and_then(|state| state.positions.get(&order.asset))
            .copied()
            .unwrap_or_else(|| self.asset_oracle_context(order.asset));
        self.apply_position_update_for_asset_side(
            &PositionUpdateSide {
                kind: prior.kind,
                signed_sz_before: prior.signed_sz,
                user: order.user,
                user_tag: order.user_tag,
                px_raw: oracle_px as u64,
                asset: order.asset,
                sz_delta_abs: order.requested_sz,
                notional_delta: request_notional,
                is_buy_or_long: order.side == PerpSide::Long,
            },
            order.side == PerpSide::Short,
        );
        INSERT_STATUS_OK
    }

    fn apply_two_leg_fill_sz_accounting(&mut self, fill: &TwoLegFillAccounting) -> TwoLegFillResult {
        let taker_summary = self.compute_position_update_summary(
            fill.asset,
            fill.px_raw,
            fill.sz,
            fill.taker.user,
            fill.taker_side,
            fill.taker.prior_position,
        );
        let maker_summary = self.compute_position_update_summary(
            fill.asset,
            fill.px_raw,
            fill.sz,
            fill.maker.user,
            fill.taker_side.opposite(),
            fill.maker.prior_position,
        );

        let taker = settle_leg(self, fill.asset, fill.px_raw, fill.taker.user, taker_summary);
        let maker = settle_leg(self, fill.asset, fill.px_raw, fill.maker.user, maker_summary);

        let total_closed_sz = taker_summary.closed_sz.saturating_add(maker_summary.closed_sz);
        let total_notional = taker_summary
            .notional_delta
            .saturating_add(maker_summary.notional_delta);

        TwoLegFillResult {
            taker: SettledLeg { user: fill.taker.user, result: taker, summary: taker_summary },
            maker: SettledLeg { user: fill.maker.user, result: maker, summary: maker_summary },
            total_closed_sz,
            total_notional,
        }
    }

    fn compute_position_update_summary(
        &self,
        asset: AssetId,
        px_raw: i64,
        sz: Sz,
        _user: Address,
        side: PerpSide,
        prior: PositionContext,
    ) -> PositionUpdateSummary {
        let signed_delta = side.signed_sz(sz);
        let notional_delta = if px_raw <= 0 {
            0
        } else {
            sz.saturating_mul(px_raw as u64).min(i64::MAX as u64 - 1)
        };
        let next_signed = prior.signed_sz.saturating_add(signed_delta);
        let prior_abs = prior.signed_sz.unsigned_abs();
        let next_abs = next_signed.unsigned_abs();
        let closed_sz = if prior.signed_sz == 0 || prior.signed_sz.signum() == signed_delta.signum() {
            0
        } else {
            prior_abs.min(sz)
        };
        let fee_or_funding_delta = self.margin_delta_for_asset(&prior, asset, 2);

        PositionUpdateSummary {
            position_delta: signed_delta,
            notional_delta,
            side_notional_hint: if side == PerpSide::Long {
                notional_delta.min(i64::MAX as u64) as i64
            } else {
                -(notional_delta.min(i64::MAX as u64) as i64)
            },
            closed_sz,
            fee_or_funding_delta,
            touched_existing_position: prior.kind == PositionContextKind::Normal && prior_abs != next_abs,
        }
    }

    fn compute_max_order_sz(
        &self,
        asset: AssetId,
        user: Address,
        side: PerpSide,
        px: Px,
        reduce_only: bool,
        extra_account_value: i64,
    ) -> Sz {
        let oracle_px = self.oracle_px_raw(asset);
        let reference_px = px.max(oracle_px.max(0) as u64).max(1);
        let position = self
            .user_state(&user)
            .and_then(|state| state.positions.get(&asset))
            .copied()
            .unwrap_or_default();

        if reduce_only {
            return reducible_sz(position.signed_sz, side);
        }

        let summary = self.aggregate_position_margin_summary(&user, false, true);
        let available = summary
            .signed_equity_or_value
            .saturating_add(extra_account_value)
            .saturating_sub(summary.margin_requirement_sum)
            .max(0) as u64;
        let leverage = self.asset_meta(asset).max_leverage.max(1) as u64;
        let margin_limited = available.saturating_mul(leverage) / reference_px;

        let cap = self.open_interest_cap_by_asset.get(&asset).copied().unwrap_or_default();
        let cap_limited = if cap == 0 {
            u64::MAX
        } else {
            let current = self.open_interest_by_asset.get(&asset).copied().unwrap_or_default();
            cap.saturating_sub(current)
        };

        margin_limited.min(cap_limited)
    }
}

fn settle_leg(
    clearinghouse: &mut Clearinghouse,
    asset: AssetId,
    px_raw: i64,
    user: Address,
    summary: PositionUpdateSummary,
) -> ApplyTradeResult {
    let result = clearinghouse.apply_trade_or_fill_update(
        asset,
        px_raw,
        summary.position_delta,
        user,
        summary.side_notional_hint,
    );
    if result.tag != PERP_OUTCOME_SUCCESS {
        panic!("called `Result::unwrap()` on an `Err` value");
    }
    result
}

#[inline]
fn checked_notional(sz: Sz, px: Px) -> Option<Ntl> {
    sz.checked_mul(px).filter(|value| *value <= i64::MAX as u64 - 1)
}

#[inline]
fn is_reducing(current: i64, side: PerpSide, sz: Sz) -> bool {
    let delta = side.signed_sz(sz);
    current != 0 && current.signum() != delta.signum() && sz <= current.unsigned_abs()
}

#[inline]
fn reducible_sz(current: i64, side: PerpSide) -> Sz {
    match (current > 0, side) {
        (true, PerpSide::Short) => current.unsigned_abs(),
        (false, PerpSide::Long) if current < 0 => current.unsigned_abs(),
        _ => 0,
    }
}
