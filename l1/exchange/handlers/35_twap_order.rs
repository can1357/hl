//! Recovered `twapOrder` handler.
//!
//! Entry in the user-action manifest points at
//! `l1_perp_dex__sub_place_trigger_order_across_dex` (`0x2722790`). The shared
//! helper reuses the trigger-order asset-routing and risk validators, then wraps
//! them with TWAP-specific duration, per-user-capacity, and scheduling logic.
//!
//! Binary evidence used here:
//! - `0x2722790` `l1_perp_dex__sub_place_trigger_order_across_dex`
//! - `0x24F7390` `l1_perp_meta__validate_trigger_order_risk`
//! - `0x24F7BD0` spot/non-perp TWAP validation helper
//! - `0x230B0E0` spot amount / decimal-alignment helper
//! - `0x26D1CF0` spot reduce-only / spendable-balance helper

#![allow(dead_code)]

use std::collections::BTreeMap;

pub type Address20 = [u8; 20];
pub type RawSize = u64;
pub type GlobalAsset = u64;
pub type OrderId = u64;
pub type TimestampMillis = u64;

pub const STATUS_OK: u16 = 390;
pub const STATUS_INVALID_TWAP_DURATION: u16 = 203;
pub const STATUS_MAX_N_TWAPS_EXCEEDED: u16 = 204;
pub const STATUS_TWAP_REDUCE_ONLY: u16 = 205;
pub const STATUS_TWAP_WIRE_NTL_TOO_SMALL: u16 = 207;
pub const STATUS_TWAP_WIRE_NTL_TOO_LARGE: u16 = 208;
pub const STATUS_SPOT_TWAP_WIRE_NTL_TOO_SMALL: u16 = 209;
pub const STATUS_SPOT_TWAP_WIRE_NTL_TOO_LARGE: u16 = 210;
pub const STATUS_GRID_SIZE_MISMATCH: u16 = 102;
pub const STATUS_SIZE_ZERO: u16 = 94;
pub const STATUS_NOTIONAL_OVERFLOW: u16 = 105;
pub const STATUS_SPOT_ASSET_HALTED: u16 = 113;
pub const STATUS_SPOT_REDUCE_ONLY_REQUIRES_FLAG: u16 = 244;
pub const STATUS_SPOT_OPEN_ORDER_CONFLICT: u16 = 380;
pub const STATUS_SPOT_STATE_REJECTED: u16 = 381;
pub const STATUS_UNKNOWN_SPOT_ASSET: u16 = 383;
pub const STATUS_UNKNOWN_DEX: u16 = 321;
pub const STATUS_CROSS_DEX_DISABLED: u16 = 249;
pub const STATUS_TRADING_GUARD: u16 = 116;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TwapOrderAction {
    pub twap: TwapWire,
}

/// Internal handler-facing form of the nested `twap` payload.
///
/// The public JSON codec uses a decimal string for `s`; by the time the handler
/// runs the size has already been parsed into the exchange's integer wire unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TwapWire {
    pub asset: u32,
    pub is_buy: bool,
    pub raw_size: RawSize,
    pub reduce_only: bool,
    pub minutes: u64,
    pub randomize: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutedAsset {
    Perp {
        dex_index: u64,
        global_asset: GlobalAsset,
        sz_divisor: u64,
    },
    Spot {
        dex_index: u64,
        spot_asset: u64,
        lot_sz_divisor: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TwapSide {
    Buy,
    Sell,
}

impl From<bool> for TwapSide {
    fn from(is_buy: bool) -> Self {
        if is_buy { Self::Buy } else { Self::Sell }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TwapOrderError {
    InvalidDuration { minutes: u64 },
    MaxNTwapsExceeded,
    GridSizeMismatch,
    SizeZero,
    NotionalOverflow,
    TwapReduceOnly,
    TwapWireNtlTooSmall { min_notional_usd: f64 },
    TwapWireNtlTooLarge { max_notional_usd: f64 },
    SpotTwapWireNtlTooSmall {
        asset_name: &'static str,
        min_base_amount: f64,
    },
    SpotTwapWireNtlTooLarge {
        asset_name: &'static str,
        max_notional_usd: f64,
    },
    SpotAssetHalted,
    SpotReduceOnlyRequiresFlag,
    SpotOpenOrderConflict,
    SpotStateRejected { aux_code: u8 },
    UnknownSpotAsset,
    UnknownDex,
    CrossDexDisabled,
    TradingGuard { aux_code: u8 },
    OtherStatus { status: u16 },
}

impl TwapOrderError {
    pub const fn status(self) -> u16 {
        match self {
            Self::InvalidDuration { .. } => STATUS_INVALID_TWAP_DURATION,
            Self::MaxNTwapsExceeded => STATUS_MAX_N_TWAPS_EXCEEDED,
            Self::GridSizeMismatch => STATUS_GRID_SIZE_MISMATCH,
            Self::SizeZero => STATUS_SIZE_ZERO,
            Self::NotionalOverflow => STATUS_NOTIONAL_OVERFLOW,
            Self::TwapReduceOnly => STATUS_TWAP_REDUCE_ONLY,
            Self::TwapWireNtlTooSmall { .. } => STATUS_TWAP_WIRE_NTL_TOO_SMALL,
            Self::TwapWireNtlTooLarge { .. } => STATUS_TWAP_WIRE_NTL_TOO_LARGE,
            Self::SpotTwapWireNtlTooSmall { .. } => STATUS_SPOT_TWAP_WIRE_NTL_TOO_SMALL,
            Self::SpotTwapWireNtlTooLarge { .. } => STATUS_SPOT_TWAP_WIRE_NTL_TOO_LARGE,
            Self::SpotAssetHalted => STATUS_SPOT_ASSET_HALTED,
            Self::SpotReduceOnlyRequiresFlag => STATUS_SPOT_REDUCE_ONLY_REQUIRES_FLAG,
            Self::SpotOpenOrderConflict => STATUS_SPOT_OPEN_ORDER_CONFLICT,
            Self::SpotStateRejected { .. } => STATUS_SPOT_STATE_REJECTED,
            Self::UnknownSpotAsset => STATUS_UNKNOWN_SPOT_ASSET,
            Self::UnknownDex => STATUS_UNKNOWN_DEX,
            Self::CrossDexDisabled => STATUS_CROSS_DEX_DISABLED,
            Self::TradingGuard { .. } => STATUS_TRADING_GUARD,
            Self::OtherStatus { status } => status,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrontendTwapOrderUpdate {
    pub asset: GlobalAsset,
    pub size: u64,
    pub duration_secs: u64,
    pub start_time_ms: TimestampMillis,
    pub side: TwapSide,
    pub reduce_only: bool,
    pub randomize: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TwapScheduleEntry {
    pub order_id: OrderId,
    pub target_size: u64,
    pub duration_secs: u64,
    pub start_time_ms: TimestampMillis,
    pub side: TwapSide,
    pub reduce_only: bool,
    pub randomize: bool,
    pub next_slice_after_ms: TimestampMillis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TwapPlacement {
    pub order_id: OrderId,
    pub route: RoutedAsset,
    pub frontend_update: FrontendTwapOrderUpdate,
    pub schedule_entry: TwapScheduleEntry,
}

#[derive(Clone, Debug, Default)]
pub struct TwapOrderState {
    pub next_order_id: OrderId,
    pub max_open_twaps_per_user: u64,
    pub now_ms: TimestampMillis,
    pub open_twaps_per_user: BTreeMap<Address20, u64>,
    pub schedules_by_user: BTreeMap<Address20, BTreeMap<OrderId, TwapScheduleEntry>>,
    pub frontend_updates: Vec<FrontendTwapOrderUpdate>,
}

impl TwapOrderState {
    /// Recovered shape of `l1_perp_dex__sub_place_trigger_order_across_dex`.
    ///
    /// Handler flow:
    /// 1. classify the encoded wire asset into the perp or spot path;
    /// 2. run the shared trigger-order validator for that path;
    /// 3. enforce TWAP-specific duration and active-count limits;
    /// 4. allocate the next TWAP/order id;
    /// 5. enqueue a per-user schedule entry that first fires one second later;
    /// 6. append the frontend/order-history update payload.
    pub fn apply_twap_order_recovered(
        &mut self,
        user: Address20,
        action: TwapOrderAction,
        classifier: &impl TwapAssetClassifier,
        limits: &impl TwapRiskValidator,
    ) -> Result<TwapPlacement, TwapOrderError> {
        validate_duration_guard(action.twap.minutes)?;

        let route = classifier.classify(action.twap.asset)?;
        let normalized_size = match route {
            RoutedAsset::Perp { sz_divisor, .. } => normalize_size(action.twap.raw_size, sz_divisor)?,
            RoutedAsset::Spot { lot_sz_divisor, .. } => normalize_size(action.twap.raw_size, lot_sz_divisor)?,
        };

        match route {
            RoutedAsset::Perp { global_asset, .. } => {
                limits.validate_perp(user, action.twap, global_asset, normalized_size)?;
            }
            RoutedAsset::Spot { spot_asset, .. } => {
                limits.validate_spot(user, action.twap, spot_asset, normalized_size)?;
            }
        }

        let open = self.open_twaps_per_user.get(&user).copied().unwrap_or(0);
        if open >= self.max_open_twaps_per_user {
            return Err(TwapOrderError::MaxNTwapsExceeded);
        }

        let order_id = self.next_order_id;
        self.next_order_id = self.next_order_id.saturating_add(1);
        *self.open_twaps_per_user.entry(user).or_default() += 1;

        let duration_secs = action.twap.minutes.saturating_mul(60);
        let frontend_update = FrontendTwapOrderUpdate {
            asset: route.global_asset_key(),
            size: normalized_size,
            duration_secs,
            start_time_ms: self.now_ms,
            side: action.twap.is_buy.into(),
            reduce_only: action.twap.reduce_only,
            randomize: action.twap.randomize,
        };
        let schedule_entry = TwapScheduleEntry {
            order_id,
            target_size: normalized_size,
            duration_secs,
            start_time_ms: self.now_ms,
            side: action.twap.is_buy.into(),
            reduce_only: action.twap.reduce_only,
            randomize: action.twap.randomize,
            next_slice_after_ms: self.now_ms.saturating_add(1_000),
        };

        self.schedules_by_user
            .entry(user)
            .or_default()
            .insert(order_id, schedule_entry);
        self.frontend_updates.push(frontend_update);

        Ok(TwapPlacement {
            order_id,
            route,
            frontend_update,
            schedule_entry,
        })
    }
}

pub trait TwapAssetClassifier {
    fn classify(&self, wire_asset: u32) -> Result<RoutedAsset, TwapOrderError>;
}

/// Narrow interface for the shared validators the TWAP wrapper reuses.
///
/// Perp path (`0x24F7390`) reuses trigger-order risk checks, then adds TWAP-only:
/// - duration guard;
/// - aggregate active-TWAP count across the user's main/per-dex trees;
/// - minimum notional derived from `minutes * 10`;
/// - maximum impact-notional cap;
/// - final trading/timing guard (`sub_275FA60`).
///
/// Spot path (`0x24F7BD0`) reuses the same wrapper structure, but its helper also
/// checks lot divisibility, spot-asset liveness, reduce-only balance/position
/// rules, and a hard top-end notional cap of `5_000_000` quote units.
pub trait TwapRiskValidator {
    fn validate_perp(
        &self,
        user: Address20,
        twap: TwapWire,
        global_asset: GlobalAsset,
        normalized_size: u64,
    ) -> Result<(), TwapOrderError>;

    fn validate_spot(
        &self,
        user: Address20,
        twap: TwapWire,
        spot_asset: u64,
        normalized_size: u64,
    ) -> Result<(), TwapOrderError>;
}

impl RoutedAsset {
    #[inline]
    pub const fn global_asset_key(self) -> u64 {
        match self {
            Self::Perp { global_asset, .. } => global_asset,
            Self::Spot { spot_asset, .. } => spot_asset,
        }
    }
}

#[inline]
pub fn normalize_size(raw_size: RawSize, divisor: u64) -> Result<u64, TwapOrderError> {
    if raw_size == 0 {
        return Err(TwapOrderError::SizeZero);
    }
    if divisor == 0 || raw_size % divisor != 0 {
        return Err(TwapOrderError::GridSizeMismatch);
    }
    Ok(raw_size / divisor)
}

/// Exact first guard recovered from both the perp and spot TWAP helpers.
///
/// The machine code rejects durations in the range `5..=1440` and accepts `0..=4`
/// plus `>= 1441`. That shape is unusual; this source keeps the binary behavior
/// rather than normalizing it into a cleaner policy.
#[inline]
pub fn validate_duration_guard(minutes: u64) -> Result<(), TwapOrderError> {
    if (5..=1440).contains(&minutes) {
        return Err(TwapOrderError::InvalidDuration { minutes });
    }
    Ok(())
}
