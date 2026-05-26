//! Frontend/API position types.
//!
//! The serializer emits decimal `f64` values through `Display`, so the public
//! JSON shape carries these numeric fields as strings. Field order below follows
//! the recovered serializer order.

use std::borrow::Cow;

pub const ASSET_POSITION_SERDE_FIELDS: [&str; 2] = ["type", "position"];
pub const POSITION_SERDE_FIELDS: [&str; 11] = [
    "coin",
    "szi",
    "leverage",
    "entryPx",
    "positionValue",
    "unrealizedPnl",
    "returnOnEquity",
    "liquidationPx",
    "marginUsed",
    "maxLeverage",
    "cumFunding",
];
pub const LEVERAGE_SERDE_FIELDS: [&str; 3] = ["type", "value", "rawUsd"];
pub const CUM_FUNDING_SERDE_FIELDS: [&str; 3] = ["allTime", "sinceOpen", "sinceChange"];

/// API wrapper for a one-way perp position.
#[derive(Clone, Debug, PartialEq)]
pub struct FAssetPosition {
    /// Serialized key: `type`; serialized value: `oneWay`.
    pub r#type: FAssetPositionType,
    pub position: Position,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FAssetPositionType {
    OneWay,
}

impl FAssetPositionType {
    #[inline]
    pub const fn as_api_str(self) -> &'static str {
        match self {
            Self::OneWay => "oneWay",
        }
    }
}

impl FAssetPosition {
    #[inline]
    pub fn one_way(position: Position) -> Self {
        Self { r#type: FAssetPositionType::OneWay, position }
    }
}

/// Frontend position body nested under `FAssetPosition.position`.
#[derive(Clone, Debug, PartialEq)]
pub struct Position {
    pub coin: String,
    /// Serialized key: `szi`; decimal string.
    pub szi: f64,
    pub leverage: Leverage,
    /// Serialized key: `entryPx`; null when no entry notional is available.
    pub entry_px: Option<f64>,
    /// Serialized key: `positionValue`; decimal string.
    pub position_value: f64,
    /// Serialized key: `unrealizedPnl`; decimal string.
    pub unrealized_pnl: f64,
    /// Serialized key: `returnOnEquity`; decimal string.
    pub return_on_equity: f64,
    /// Serialized key: `liquidationPx`; null when no liquidation price is found.
    pub liquidation_px: Option<f64>,
    /// Serialized key: `marginUsed`; decimal string.
    pub margin_used: f64,
    /// Serialized key: `maxLeverage`.
    pub max_leverage: u8,
    /// Serialized key: `cumFunding`.
    pub cum_funding: CumFunding,
}

/// Frontend leverage object. Cross positions omit `rawUsd`; isolated positions
/// include it as a decimal string.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Leverage {
    Cross { value: u32 },
    Isolated { value: u32, raw_usd: f64 },
}

impl Leverage {
    #[inline]
    pub const fn cross(value: u32) -> Self {
        Self::Cross { value }
    }

    #[inline]
    pub const fn isolated(value: u32, raw_usd: f64) -> Self {
        Self::Isolated { value, raw_usd }
    }

    #[inline]
    pub const fn as_api_type(self) -> &'static str {
        match self {
            Self::Cross { .. } => "cross",
            Self::Isolated { .. } => "isolated",
        }
    }

    #[inline]
    pub const fn value(self) -> u32 {
        match self {
            Self::Cross { value } | Self::Isolated { value, .. } => value,
        }
    }

    #[inline]
    pub const fn raw_usd(self) -> Option<f64> {
        match self {
            Self::Cross { .. } => None,
            Self::Isolated { raw_usd, .. } => Some(raw_usd),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CumFunding {
    /// Serialized key: `allTime`; decimal string.
    pub all_time: f64,
    /// Serialized key: `sinceOpen`; decimal string.
    pub since_open: f64,
    /// Serialized key: `sinceChange`; decimal string.
    pub since_change: f64,
}

/// Raw values consumed by the recovered frontend conversion.
///
/// Fixed-point conventions recovered from the conversion:
/// - USD/notional/funding values are scaled by 1e6.
/// - `signed_size_lots` is converted with `size_scale`.
/// - entry price uses integer division of `entry_notional_raw / abs(size_lots)`
///   and then `price_scale`.
#[derive(Clone, Debug, PartialEq)]
pub struct RecoveredPositionInput<'a> {
    pub coin: Cow<'a, str>,
    pub signed_size_lots: i64,
    pub size_scale: f64,
    pub price_scale: f64,
    pub entry_notional_raw: u64,
    pub mark_notional_raw: i64,
    pub margin_used_raw: i64,
    pub leverage: LeverageKind,
    pub leverage_value: u32,
    pub isolated_raw_usd: i64,
    pub max_leverage: u8,
    pub cum_funding_all_time_raw: i32,
    pub cum_funding_since_open_raw: i32,
    pub cum_funding_since_change_raw: i32,
    pub liquidation_px: Option<f64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeverageKind {
    Cross,
    Isolated,
}

impl Position {
    /// Convert recovered clearinghouse values into the frontend position shape.
    #[inline]
    pub fn from_recovered(input: RecoveredPositionInput<'_>) -> Self {
        let abs_size_lots = input.signed_size_lots.unsigned_abs();
        let signed_entry_notional_raw = if input.signed_size_lots >= 0 {
            input.entry_notional_raw as i128
        } else {
            -(input.entry_notional_raw as i128)
        };
        let unrealized_raw = input.mark_notional_raw as i128 - signed_entry_notional_raw;

        let entry_px = if input.entry_notional_raw != 0
            && abs_size_lots != 0
            && abs_size_lots <= input.entry_notional_raw
        {
            Some((input.entry_notional_raw / abs_size_lots) as f64 / input.price_scale)
        } else {
            None
        };

        let leverage = match input.leverage {
            LeverageKind::Cross => Leverage::Cross { value: input.leverage_value },
            LeverageKind::Isolated => Leverage::Isolated {
                value: input.leverage_value,
                raw_usd: usd_1e6(input.isolated_raw_usd),
            },
        };

        let return_on_equity = if input.entry_notional_raw == 0 {
            0.0
        } else {
            (input.leverage_value as f64) * (unrealized_raw as f64) / (input.entry_notional_raw as f64)
        };

        Self {
            coin: input.coin.into_owned(),
            szi: (input.signed_size_lots as f64) / input.size_scale,
            leverage,
            entry_px,
            position_value: usd_1e6(input.mark_notional_raw.unsigned_abs() as i64),
            unrealized_pnl: (unrealized_raw as f64) / 1_000_000.0,
            return_on_equity,
            liquidation_px: input.liquidation_px,
            margin_used: usd_1e6(input.margin_used_raw),
            max_leverage: input.max_leverage,
            cum_funding: CumFunding {
                all_time: usd_1e6(input.cum_funding_all_time_raw as i64),
                since_open: usd_1e6(input.cum_funding_since_open_raw as i64),
                since_change: usd_1e6(input.cum_funding_since_change_raw as i64),
            },
        }
    }

    #[inline]
    pub fn into_asset_position(self) -> FAssetPosition {
        FAssetPosition::one_way(self)
    }
}

/// Mirror of the recovered collector: zero-size internal positions are skipped
/// before frontend records are produced.
#[inline]
pub fn collect_asset_positions<'a, I>(positions: I) -> Vec<FAssetPosition>
where
    I: IntoIterator<Item = RecoveredPositionInput<'a>>,
{
    positions
        .into_iter()
        .filter(|position| position.signed_size_lots != 0)
        .map(Position::from_recovered)
        .map(FAssetPosition::one_way)
        .collect()
}

/// The JSON encoder formats frontend decimals by `Display` and writes them as
/// strings, not as JSON numbers.
#[inline]
pub fn frontend_decimal_to_api_string(value: f64) -> String {
    value.to_string()
}

#[inline]
pub fn optional_frontend_decimal_to_api_string(value: Option<f64>) -> Option<String> {
    value.map(frontend_decimal_to_api_string)
}

#[inline]
fn usd_1e6(raw: i64) -> f64 {
    (raw as f64) / 1_000_000.0
}
