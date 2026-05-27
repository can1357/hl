#![allow(dead_code)]

use std::collections::BTreeMap;

pub type Address = [u8; 20];
pub type AssetId = u64;
pub type DexId = u64;
pub type RawPx = i64;
pub type SignedNtl = i64;

pub const TOP_UP_ISOLATED_ONLY_MARGIN_HANDLER_EA: u64 = 0x21E2_EE0;
pub const TOP_UP_ISOLATED_ONLY_MARGIN_CORE_EA: u64 = 0x3709_560;

pub const WRAPPER_TAG_APPLIED: u8 = 13;
pub const WRAPPER_TAG_REJECTED: u8 = 14;

pub const STATUS_SUCCESS: u16 = 390;
pub const STATUS_PERP_ASSET_REQUIRED: u16 = 350;
pub const STATUS_INPUT_TOO_LONG: u16 = 323;
/// Raw status emitted after a successful decimal parse when the follow-on
/// float conversion/normalization helper rejects the value.
pub const STATUS_LEVERAGE_CONVERSION_FAILED: u16 = 171;
pub const STATUS_INVALID_DELISTED_CLOSE_LEVERAGE: u16 = 67;
pub const STATUS_INSUFFICIENT_AVAILABLE_MARGIN: u16 = 75;
pub const STATUS_ACCOUNT_VALUE_OVERFLOW: u16 = 191;
pub const STATUS_ASSET_NOT_DELISTED: u16 = 313;

pub const MAX_LEVERAGE_TEXT_LEN: usize = 100;
pub const MIN_TARGET_LEVERAGE: f64 = 0.5;
pub const MAX_TARGET_LEVERAGE: f64 = 1.0;
pub const ASSETS_PER_DEX: AssetId = 10_000;

/// Payload shape recovered from `sub_21E2EE0`.
///
/// The wrapper classifies `asset` from payload offset `+0x18` and parses the
/// string-or-float field stored at payload `+0x08/+0x10`. Protocol metadata and
/// the old serializer recovery both point to the API name `leverage`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TopUpIsolatedOnlyMarginAction {
    pub leverage_text: String,
    pub asset: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutedAsset {
    Perp {
        global_asset: AssetId,
        dex_id: DexId,
        local_asset: u32,
    },
    Spot,
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
    /// Zero means cross margin; any nonzero value is treated as isolated.
    pub margin_mode_or_isolated: u32,
    pub max_leverage: u32,
    pub margin_raw: SignedNtl,
    pub szi: i64,
}

impl PositionRecord {
    #[inline]
    pub const fn is_isolated(self) -> bool {
        (self.margin_mode_or_isolated as u8) != 0
    }

    #[inline]
    pub fn signed_notional(self, oracle_px_raw: RawPx) -> SignedNtl {
        checked_signed_notional(self.szi, oracle_px_raw)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UserPositions {
    /// Cross-margin account value funding isolated top-ups.
    pub signed_account_value: SignedNtl,
    pub positions_by_asset: BTreeMap<AssetId, PositionRecord>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OraclePrices {
    pub rows: Vec<RawPx>,
}

impl OraclePrices {
    #[inline]
    pub fn price_for_asset(&self, asset: AssetId) -> RawPx {
        self.rows[(asset % ASSETS_PER_DEX) as usize]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecimalParseFailure {
    pub status: u16,
}

pub trait TopUpIsolatedOnlyMarginParser {
    /// Mirrors `l1_qtys_mod__parse_decimal_from_str_or_float` plus the follow-on
    /// conversion helper at `0x4EAD680`.
    fn parse_target_leverage(&self, text: &[u8]) -> Result<f64, DecimalParseFailure>;
}

pub trait TopUpIsolatedOnlyMarginEngine {
    fn classify_wire_asset(&self, raw_asset: u32) -> Result<RoutedAsset, u16>;
    fn close_delisted_asset_to_leverage(
        &mut self,
        user: Address,
        asset: AssetId,
        dex_id: DexId,
        target_leverage: f64,
    ) -> u16;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TopUpIsolatedOnlyMarginResult {
    pub tag: u8,
    pub status: u16,
    pub asset: Option<AssetId>,
    pub dex_id: Option<DexId>,
}

impl TopUpIsolatedOnlyMarginResult {
    #[inline]
    pub const fn success(asset: AssetId, dex_id: DexId) -> Self {
        Self {
            tag: WRAPPER_TAG_APPLIED,
            status: STATUS_SUCCESS,
            asset: Some(asset),
            dex_id: Some(dex_id),
        }
    }

    #[inline]
    pub const fn from_status(status: u16, asset: AssetId, dex_id: DexId) -> Self {
        Self {
            tag: if status == STATUS_SUCCESS {
                WRAPPER_TAG_APPLIED
            } else {
                WRAPPER_TAG_REJECTED
            },
            status,
            asset: Some(asset),
            dex_id: Some(dex_id),
        }
    }

    #[inline]
    pub const fn rejected(status: u16) -> Self {
        Self {
            tag: WRAPPER_TAG_REJECTED,
            status,
            asset: None,
            dex_id: None,
        }
    }
}

/// Recovered wrapper flow from `sub_21E2EE0`.
///
/// Order matters:
/// 1. classify the wire asset first;
/// 2. reject spot assets with `350`;
/// 3. reject `leverage` inputs longer than 100 bytes with `323`;
/// 4. parse the decimal/string-or-float payload into an `f64`, bubbling helper
///    errors unchanged;
/// 5. dispatch into the per-dex delisted-position helper at `0x3709560`.
///
/// The generic exchange nonce gate already ran in `impl_execute_action` before
/// this handler is reached.
pub fn apply_top_up_isolated_only_margin<E, P>(
    engine: &mut E,
    parser: &P,
    user: Address,
    action: &TopUpIsolatedOnlyMarginAction,
) -> TopUpIsolatedOnlyMarginResult
where
    E: TopUpIsolatedOnlyMarginEngine,
    P: TopUpIsolatedOnlyMarginParser,
{
    let routed = match engine.classify_wire_asset(action.asset) {
        Ok(routed) => routed,
        Err(status) => return TopUpIsolatedOnlyMarginResult::rejected(status),
    };

    let (asset, dex_id) = match routed {
        RoutedAsset::Perp {
            global_asset,
            dex_id,
            ..
        } => (global_asset, dex_id),
        RoutedAsset::Spot => return TopUpIsolatedOnlyMarginResult::rejected(STATUS_PERP_ASSET_REQUIRED),
    };

    let text = action.leverage_text.as_bytes();
    if text.len() > MAX_LEVERAGE_TEXT_LEN {
        return TopUpIsolatedOnlyMarginResult::rejected(STATUS_INPUT_TOO_LONG);
    }

    let target_leverage = match parser.parse_target_leverage(text) {
        Ok(value) => value,
        Err(failure) => return TopUpIsolatedOnlyMarginResult::rejected(failure.status),
    };

    TopUpIsolatedOnlyMarginResult::from_status(
        engine.close_delisted_asset_to_leverage(user, asset, dex_id, target_leverage),
        asset,
        dex_id,
    )
}

/// State mutation recovered from `0x3709560` together with the matching position
/// logic in `recon/l1/src/clearinghouse/position.rs`.
///
/// Notable behavior:
/// - only delisted assets are eligible (`313` otherwise);
/// - missing users, missing positions, or cross-margin positions are treated as
///   a successful no-op;
/// - `target_leverage` must land in the inclusive `[0.5, 1.0]` interval;
/// - only positive top-ups are ever applied; if the position already has enough
///   equity for the requested leverage, nothing changes and the helper succeeds;
/// - any added isolated margin is funded by subtracting the same amount from the
///   user's cross-margin account value.
pub fn close_delisted_asset_to_leverage(
    positions: &mut UserPositions,
    asset: AssetId,
    target_leverage: f64,
    status: TradingStatus,
    oracle_prices: &OraclePrices,
) -> u16 {
    if !target_leverage.is_finite() || !(MIN_TARGET_LEVERAGE..=MAX_TARGET_LEVERAGE).contains(&target_leverage) {
        return STATUS_INVALID_DELISTED_CLOSE_LEVERAGE;
    }
    if status != TradingStatus::Delisted {
        return STATUS_ASSET_NOT_DELISTED;
    }

    let Some(position) = positions.positions_by_asset.get_mut(&asset) else {
        return STATUS_SUCCESS;
    };
    if !position.is_isolated() {
        return STATUS_SUCCESS;
    }

    let signed_notional = position.signed_notional(oracle_prices.price_for_asset(asset));
    let equity = position.margin_raw.saturating_add(signed_notional);
    let required_equity = f64_to_i64_saturating((signed_notional.unsigned_abs() as f64) / target_leverage);
    let Some(delta) = required_equity.checked_sub(equity) else {
        return STATUS_ACCOUNT_VALUE_OVERFLOW;
    };

    if delta > 0 {
        if positions.signed_account_value < delta {
            return STATUS_INSUFFICIENT_AVAILABLE_MARGIN;
        }
        positions.signed_account_value = positions.signed_account_value.saturating_sub(delta);
        position.margin_raw = position.margin_raw.saturating_add(delta);
    }

    STATUS_SUCCESS
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
pub fn f64_to_i64_saturating(value: f64) -> i64 {
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
