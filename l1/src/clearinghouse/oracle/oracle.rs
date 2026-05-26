#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type AssetId = u64;
pub type DexId = u64;
pub type RawPx = u64;
pub type TimeMillis = u64;
pub type TimeSeconds = i64;

pub const ASSETS_PER_DEX: AssetId = 10_000;
pub const MAX_SUPPORTED_SZ_DECIMALS: u8 = 6;
pub const MAX_CONTEXT_LEVERAGE: u32 = 20;
pub const DEFAULT_CONTEXT_LEVERAGE: u32 = 3;
pub const NORMAL_PRICE_LIMIT_DISTANCE: f64 = 0.20;
pub const HIP3_DEFAULT_LOWER_PRICE_RATIO: f64 = 0.50;
pub const HIP3_DEFAULT_UPPER_PRICE_RATIO: f64 = 2.00;
pub const STALE_ORACLE_REPRICE_SECONDS: TimeSeconds = 1_800;
pub const SUCCESS_RESULT_TAG: u16 = 390;

const DISPLAY_SCALE: [f64; 8] = [
    1.0,
    10.0,
    100.0,
    1_000.0,
    10_000.0,
    100_000.0,
    1_000_000.0,
    10_000_000.0,
];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct AssetKey {
    pub asset: AssetId,
    pub is_external_perp: bool,
}

impl AssetKey {
    pub fn local(asset: AssetId) -> Self {
        Self {
            asset,
            is_external_perp: false,
        }
    }

    pub fn external(asset: AssetId) -> Self {
        Self {
            asset,
            is_external_perp: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleError {
    MissingReferenceOracle,
    PriceMovedTooFarFromReferenceOracle,
    OraclePriceMustBePositive,
    OraclePriceUpdateTooOften,
    UnexpectedOraclePriceLength { got: usize, expected: usize },
    InvalidAssetId { asset: AssetId },
    UnsupportedDecimals { decimals: u8 },
    NonFinitePrice,
    PriceTooFarFromOracle,
    UnauthorizedOracleUpdater,
    ArithmeticOverflow,
}

impl OracleError {
    pub fn as_recovered_str(self) -> &'static str {
        match self {
            Self::MissingReferenceOracle => "Missing reference oracle",
            Self::PriceMovedTooFarFromReferenceOracle => "Price moved too far from reference oracle",
            Self::OraclePriceMustBePositive => "Oracle price must be positive",
            Self::OraclePriceUpdateTooOften => "Oracle price update too often",
            Self::UnexpectedOraclePriceLength { .. } => "Unexpected length of prices to set in oracle",
            Self::InvalidAssetId { .. } => "invalid asset id",
            Self::UnsupportedDecimals { .. } => "unsupported oracle px decimals",
            Self::NonFinitePrice => "oracle price is not finite",
            Self::PriceTooFarFromOracle => "Price too far from oracle",
            Self::UnauthorizedOracleUpdater => "unauthorized oracle updater",
            Self::ArithmeticOverflow => "oracle arithmetic overflow",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OracleKindEntry {
    /// Serialized as key `p`.
    pub p: RawPx,
    /// Serialized as key `d`.
    pub d: RawPx,
    /// Serialized as key `u`; omitted by the compact serializer when it is the default sentinel.
    pub u: TimeMillis,
}

impl OracleKindEntry {
    pub fn new(p: RawPx, d: RawPx, u: TimeMillis) -> Result<Self, OracleError> {
        if p == 0 || d == 0 {
            return Err(OracleError::OraclePriceMustBePositive);
        }
        Ok(Self { p, d, u })
    }

    pub fn is_compact(self) -> bool {
        self.u == 0
    }

    pub fn display_price(self, decimals: u8) -> Result<f64, OracleError> {
        raw_px_to_display(self.p, decimals)
    }
}

/// Three 32-byte oracle-kind entries are serialized as `OraclePx`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OraclePx {
    pub entries: [OracleKindEntry; 3],
}

impl OraclePx {
    pub fn primary(self) -> OracleKindEntry {
        self.entries[0]
    }

    pub fn mark(self) -> OracleKindEntry {
        self.entries[1]
    }

    pub fn external(self) -> OracleKindEntry {
        self.entries[2]
    }

    pub fn all_positive(self) -> bool {
        self.entries.iter().all(|entry| entry.p > 0 && entry.d > 0)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OracleKindMap(pub Vec<[OracleKindEntry; 3]>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ReferenceOracleMode {
    E = 0,
    A = 1,
    D = 2,
}

impl Default for ReferenceOracleMode {
    fn default() -> Self {
        Self::E
    }
}

impl ReferenceOracleMode {
    pub fn from_storage(value: u8) -> Self {
        match value {
            0 => Self::E,
            1 => Self::A,
            _ => Self::D,
        }
    }

    pub fn wire_str(self) -> &'static str {
        match self {
            Self::E => "e",
            Self::A => "a",
            Self::D => "d",
        }
    }

    pub fn bypasses_reference_check(self) -> bool {
        !matches!(self, Self::E)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ReferenceOracleConfig {
    /// First field read as f64 by the distance check: max `abs(new/reference - 1)`.
    pub max_signed_distance: f64,
    /// Serialized as `r` in one recovered view. The exact source name is not recovered.
    pub r: f64,
    /// Serialized as `n` in one recovered view.
    pub n: u64,
    pub mode: ReferenceOracleMode,
}

impl ReferenceOracleConfig {
    pub fn reference_checks_enabled(self) -> bool {
        !self.mode.bypasses_reference_check()
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReferenceOracleConfigs {
    /// Serialized as `o`.
    pub overrides: OracleKindMap,
    /// Serialized as `d`.
    pub default: ReferenceOracleConfig,
}

impl ReferenceOracleConfigs {
    pub fn config_for_asset(&self, _asset: AssetId) -> ReferenceOracleConfig {
        // [INFERENCE] The binary has an OracleKindMap override table; unresolved map-key shape is kept outside
        // the default path here, but the default config behavior is recovered.
        self.default
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct MedianStreamTracker {
    pub samples: Vec<(TimeMillis, RawPx)>,
}

impl MedianStreamTracker {
    pub fn push(&mut self, time: TimeMillis, px: RawPx) {
        self.samples.push((time, px));
    }

    pub fn median(&self) -> Option<RawPx> {
        if self.samples.is_empty() {
            return None;
        }
        let mut values: Vec<RawPx> = self.samples.iter().map(|(_, px)| *px).collect();
        values.sort_unstable();
        Some(values[values.len() / 2])
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReferenceOracle {
    pub m: MedianStreamTracker,
    pub n: MedianStreamTracker,
    pub r: ReferenceOracleConfigs,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ErrDurGuard {
    pub last_error_time: Option<TimeMillis>,
    pub suppressed_count: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Oracle {
    /// Serialized as `pxs2`; each row carries primary, mark, and external oracle-kind entries.
    pub pxs2: Vec<OraclePx>,
    /// Serialized as `r`.
    pub reference: ReferenceOracle,
    /// Serialized as `err_dur_guard`.
    pub err_dur_guard: ErrDurGuard,
    pub last_update_millis: Option<TimeMillis>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct OracleSnapshot {
    pub oracle: Oracle,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AssetMeta {
    pub sz_decimals: u8,
    pub max_leverage: u32,
    pub delisted: bool,
    pub only_isolated: bool,
    pub margin_table_id: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AssetOracleContext {
    pub asset: AssetId,
    pub leverage: u32,
    pub margin_table_id: u32,
    pub delisted: bool,
    pub signed_position_sz: i64,
    pub signed_margin: i64,
    pub open_interest_ntl: u64,
}

impl AssetOracleContext {
    pub fn from_meta(asset: AssetId, meta: AssetMeta) -> Self {
        let leverage = if meta.max_leverage == 0 {
            DEFAULT_CONTEXT_LEVERAGE
        } else {
            meta.max_leverage.min(MAX_CONTEXT_LEVERAGE)
        };
        Self {
            asset,
            leverage,
            margin_table_id: meta.margin_table_id,
            delisted: meta.delisted,
            signed_position_sz: 0,
            signed_margin: 0,
            open_interest_ntl: 0,
        }
    }

    pub fn recompute_open_interest(&mut self, px: RawPx) -> Result<(), OracleError> {
        let abs_sz = checked_abs_i64(self.signed_position_sz)?;
        self.open_interest_ntl = abs_sz.checked_mul(px).ok_or(OracleError::ArithmeticOverflow)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DexOraclePriceMaps {
    pub oracle: BTreeMap<String, f64>,
    pub mark: BTreeMap<String, f64>,
    pub external: BTreeMap<String, f64>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PerpAssetRow {
    pub name: String,
    pub sz_decimals: u8,
    pub oracle_px: RawPx,
    pub mark_px: RawPx,
    pub external_px: RawPx,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct OracleUpdateConfig {
    pub min_update_interval_millis: TimeMillis,
    pub reference: ReferenceOracleConfig,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ValidatorL1UpdateReferenceOracleAction {
    /// Serialized as `oraclePxs` in action/API views.
    pub oracle_pxs: Vec<RawPx>,
    /// Serialized as `markPxs`.
    pub mark_pxs: Vec<Option<RawPx>>,
    /// Serialized as `externalPerpPxs` in the validator update path.
    pub external_perp_pxs: Vec<ExternalPerpPx>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExternalPerpPx {
    pub asset: AssetId,
    pub px: RawPx,
    pub flags: u16,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Hip3SetOracleAction {
    pub oracle_pxs: Vec<RawPx>,
    pub mark_pxs: Vec<Option<RawPx>>,
    pub external_perp_pxs: Vec<ExternalPerpPx>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ClearinghouseOracleDomain {
    pub dex: DexId,
    pub oracle_updater: Address,
    pub assets: Vec<AssetMeta>,
    pub rows: Vec<PerpAssetRow>,
    pub oracle: Oracle,
    pub contexts: BTreeMap<AssetKey, AssetOracleContext>,
    pub override_max_signed_distances_from_oracle: BTreeMap<AssetId, f64>,
    pub isolated_oracle: BTreeMap<AssetId, f64>,
    pub external_perp_pxs: BTreeMap<AssetId, ExternalPerpPx>,
}

impl ClearinghouseOracleDomain {
    pub fn set_oracle_prices(
        &mut self,
        now: TimeMillis,
        prices: &[RawPx],
        config: OracleUpdateConfig,
    ) -> Result<(), OracleError> {
        if prices.len() != self.rows.len() {
            return Err(OracleError::UnexpectedOraclePriceLength {
                got: prices.len(),
                expected: self.rows.len(),
            });
        }
        if let Some(last) = self.oracle.last_update_millis {
            if now.saturating_sub(last) < config.min_update_interval_millis {
                return Err(OracleError::OraclePriceUpdateTooOften);
            }
        }

        for (local, px) in prices.iter().copied().enumerate() {
            validate_positive_price(px)?;
            let asset = encode_asset_id(self.dex, local as AssetId)?;
            let reference_px = self.oracle.reference.m.median();
            check_reference_oracle_price_move(
                asset,
                ReferenceSourceKind::Primary,
                ReferenceSourceKind::Primary,
                px,
                reference_px,
                config.reference,
            )?;
            self.rows[local].oracle_px = px;
            let context = self.get_or_insert_asset_context(asset, local)?;
            context.recompute_open_interest(px)?;
        }

        self.oracle.last_update_millis = Some(now);
        Ok(())
    }

    pub fn apply_hip3_set_oracle(
        &mut self,
        sender: Address,
        now: TimeMillis,
        action: Hip3SetOracleAction,
        config: OracleUpdateConfig,
    ) -> Result<(), OracleError> {
        if sender != self.oracle_updater {
            return Err(OracleError::UnauthorizedOracleUpdater);
        }
        self.set_oracle_prices(now, &action.oracle_pxs, config)?;
        if action.mark_pxs.len() != self.rows.len() {
            return Err(OracleError::UnexpectedOraclePriceLength {
                got: action.mark_pxs.len(),
                expected: self.rows.len(),
            });
        }
        for (local, maybe_px) in action.mark_pxs.into_iter().enumerate() {
            if let Some(px) = maybe_px {
                validate_positive_price(px)?;
                self.rows[local].mark_px = px;
            }
        }
        for external in action.external_perp_pxs {
            validate_positive_price(external.px)?;
            self.external_perp_pxs.insert(external.asset, external);
        }
        Ok(())
    }

    pub fn build_price_maps(&self) -> Result<DexOraclePriceMaps, OracleError> {
        build_dex_oracle_price_maps(self.dex, &self.rows)
    }

    pub fn asset_oracle_mark_pair(&self, asset: AssetId) -> Result<(Option<f64>, Option<f64>), OracleError> {
        let (_, local) = split_asset_id(asset);
        let row = self.rows.get(local as usize).ok_or(OracleError::InvalidAssetId { asset })?;
        let mark = raw_px_to_display(row.mark_px, row.sz_decimals).ok();
        let oracle = raw_px_to_display(row.oracle_px, row.sz_decimals).ok();
        Ok((oracle, mark))
    }

    pub fn get_or_insert_asset_context(
        &mut self,
        asset: AssetId,
        local: usize,
    ) -> Result<&mut AssetOracleContext, OracleError> {
        let meta = *self.assets.get(local).ok_or(OracleError::InvalidAssetId { asset })?;
        Ok(self
            .contexts
            .entry(AssetKey::local(asset))
            .or_insert_with(|| AssetOracleContext::from_meta(asset, meta)))
    }

    pub fn price_limit_check(
        &self,
        asset: AssetId,
        order_px: RawPx,
        is_bid: bool,
        hip3: bool,
    ) -> Result<(), OracleError> {
        let (_, local) = split_asset_id(asset);
        let row = self.rows.get(local as usize).ok_or(OracleError::InvalidAssetId { asset })?;
        let anchor_raw = if row.mark_px != 0 { row.mark_px } else { row.oracle_px };
        validate_positive_price(anchor_raw)?;
        validate_positive_price(order_px)?;
        let anchor = raw_px_to_display(anchor_raw, row.sz_decimals)?;
        let order = raw_px_to_display(order_px, row.sz_decimals)?;

        let (lower, upper) = if hip3 {
            (HIP3_DEFAULT_LOWER_PRICE_RATIO, HIP3_DEFAULT_UPPER_PRICE_RATIO)
        } else {
            let dist = self
                .override_max_signed_distances_from_oracle
                .get(&asset)
                .copied()
                .unwrap_or(NORMAL_PRICE_LIMIT_DISTANCE);
            (1.0 - dist, 1.0 + dist)
        };
        let limit = if is_bid { anchor * upper } else { anchor * lower };
        if (is_bid && order <= limit) || (!is_bid && order >= limit) {
            Ok(())
        } else {
            Err(OracleError::PriceTooFarFromOracle)
        }
    }

    pub fn stale_assets(&self, now_seconds: TimeSeconds) -> BTreeSet<AssetId> {
        let mut stale = BTreeSet::new();
        for (local, px) in self.oracle.pxs2.iter().enumerate() {
            let last_update_seconds = (px.primary().u / 1_000) as TimeSeconds;
            if now_seconds.saturating_sub(last_update_seconds) >= STALE_ORACLE_REPRICE_SECONDS {
                let _ = stale.insert(encode_asset_id(self.dex, local as AssetId).unwrap_or(local as AssetId));
            }
        }
        stale
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ReferenceSourceKind {
    Primary = 0,
    Mark = 1,
    External = 2,
    Native = 3,
}

impl ReferenceSourceKind {
    fn storage_byte(self) -> u8 {
        self as u8
    }
}

pub fn validate_positive_price(px: RawPx) -> Result<(), OracleError> {
    if px == 0 {
        Err(OracleError::OraclePriceMustBePositive)
    } else {
        Ok(())
    }
}

pub fn encode_asset_id(dex: DexId, local: AssetId) -> Result<AssetId, OracleError> {
    dex.checked_mul(ASSETS_PER_DEX)
        .and_then(|base| base.checked_add(local))
        .ok_or(OracleError::ArithmeticOverflow)
}

pub fn split_asset_id(asset: AssetId) -> (DexId, AssetId) {
    (asset / ASSETS_PER_DEX, asset % ASSETS_PER_DEX)
}

pub fn raw_px_to_display(px: RawPx, sz_decimals: u8) -> Result<f64, OracleError> {
    validate_positive_price(px)?;
    if sz_decimals > MAX_SUPPORTED_SZ_DECIMALS {
        return Err(OracleError::UnsupportedDecimals { decimals: sz_decimals });
    }
    let scale_index = (MAX_SUPPORTED_SZ_DECIMALS - sz_decimals) as usize;
    let value = px as f64 / DISPLAY_SCALE[scale_index];
    if value.is_finite() {
        Ok(value)
    } else {
        Err(OracleError::NonFinitePrice)
    }
}

pub fn check_reference_oracle_price_move(
    asset: AssetId,
    oracle_source: ReferenceSourceKind,
    market_source: ReferenceSourceKind,
    new_px: RawPx,
    reference_px: Option<RawPx>,
    config: ReferenceOracleConfig,
) -> Result<(), OracleError> {
    if config.mode.bypasses_reference_check() {
        return Ok(());
    }

    let Some(reference_px) = reference_px else {
        if reference_missing_is_allowed(asset, oracle_source, market_source) {
            return Ok(());
        }
        return Err(OracleError::MissingReferenceOracle);
    };

    validate_positive_price(new_px)?;
    validate_positive_price(reference_px)?;
    let new_px = new_px as f64;
    let reference_px = reference_px as f64;
    let move_ratio = (new_px / reference_px - 1.0).abs();
    if move_ratio <= config.max_signed_distance {
        Ok(())
    } else {
        Err(OracleError::PriceMovedTooFarFromReferenceOracle)
    }
}

fn reference_missing_is_allowed(
    asset: AssetId,
    oracle_source: ReferenceSourceKind,
    market_source: ReferenceSourceKind,
) -> bool {
    if oracle_source.storage_byte() < 2 || market_source.storage_byte() < 2 {
        return false;
    }
    match oracle_source {
        ReferenceSourceKind::Native => matches!(asset, 152 | 159),
        _ => matches!(asset, 125 | 135),
    }
}

pub fn build_dex_oracle_price_maps(
    dex: DexId,
    rows: &[PerpAssetRow],
) -> Result<DexOraclePriceMaps, OracleError> {
    let mut maps = DexOraclePriceMaps::default();
    let base = dex.checked_mul(ASSETS_PER_DEX).ok_or(OracleError::ArithmeticOverflow)?;
    for (local, row) in rows.iter().enumerate() {
        let local = local as AssetId;
        let asset = base.checked_add(local).ok_or(OracleError::ArithmeticOverflow)?;
        let key = if row.name.is_empty() {
            wire_asset_key(asset)
        } else {
            row.name.clone()
        };
        let oracle_px = raw_px_to_display(row.oracle_px, row.sz_decimals)?;
        let mark_px = raw_px_to_display(row.mark_px, row.sz_decimals)?;
        let external_px = raw_px_to_display(row.external_px, row.sz_decimals)?;
        maps.oracle.insert(key.clone(), oracle_px);
        maps.mark.insert(key.clone(), mark_px);
        maps.external.insert(key, external_px);
    }
    Ok(maps)
}

pub fn record_median_reference_oracle_px(
    oracle: &mut Oracle,
    now: TimeMillis,
    asset: AssetId,
    px: OraclePx,
) {
    let config = oracle.reference.r.config_for_asset(asset);
    let primary = px.primary().p;
    let mark = px.mark().p;
    let external = px.external().p;
    oracle.reference.m.push(now, primary);
    oracle.reference.n.push(now, mark);
    if config.mode == ReferenceOracleMode::D || reference_missing_is_allowed(asset, ReferenceSourceKind::Native, ReferenceSourceKind::External) {
        oracle.reference.m.push(now, external);
    }
}

pub fn apply_trade_or_fill_update(
    context: &mut AssetOracleContext,
    signed_fill_sz: i64,
    fill_px: RawPx,
) -> Result<u16, OracleError> {
    context.signed_position_sz = context
        .signed_position_sz
        .checked_add(signed_fill_sz)
        .ok_or(OracleError::ArithmeticOverflow)?;
    context.recompute_open_interest(fill_px)?;
    Ok(SUCCESS_RESULT_TAG)
}

pub fn liquidation_shortfall_to_size(shortfall_ntl: i64, px: RawPx) -> Result<u64, OracleError> {
    if shortfall_ntl >= 0 {
        return Ok(0);
    }
    validate_positive_price(px)?;
    let shortfall = checked_abs_i64(shortfall_ntl)?;
    Ok(shortfall / px + u64::from(shortfall % px != 0))
}

pub fn margin_delta_for_asset(
    context: Option<&AssetOracleContext>,
    px: RawPx,
    use_maintenance: bool,
) -> Result<i64, OracleError> {
    validate_positive_price(px)?;
    let Some(context) = context else {
        return Ok(0);
    };
    let abs_sz = checked_abs_i64(context.signed_position_sz)?;
    let notional = abs_sz.checked_mul(px).ok_or(OracleError::ArithmeticOverflow)?;
    let leverage = if use_maintenance {
        context.leverage.max(1) as u64 * 2
    } else {
        context.leverage.max(1) as u64
    };
    let requirement = (notional / leverage) as i64;
    Ok(context.signed_margin.saturating_sub(requirement))
}

pub fn update_scaled_volume_prices(
    rows: &[PerpAssetRow],
    external: &[ExternalPerpPx],
) -> Result<BTreeMap<AssetId, f64>, OracleError> {
    let mut out = BTreeMap::new();
    for (asset, row) in rows.iter().enumerate() {
        let px = if row.oracle_px != 0 { row.oracle_px } else { row.mark_px };
        out.insert(asset as AssetId, raw_px_to_display(px, row.sz_decimals)?);
    }
    for ext in external {
        validate_positive_price(ext.px)?;
        out.insert(ext.asset, ext.px as f64);
    }
    Ok(out)
}

pub fn collect_oracle_px_diagnostics(
    rows: &[PerpAssetRow],
    oracle: &Oracle,
) -> Vec<String> {
    let mut out = Vec::new();
    if rows.len() != oracle.pxs2.len() {
        out.push("unexpected length".to_owned());
    }
    for (local, row) in rows.iter().enumerate() {
        if row.mark_px == 0 {
            out.push(format!("{}: missing mark px", row.name));
        }
        if row.oracle_px == 0 {
            out.push(format!("{}: missing oracle px", row.name));
        }
        if oracle
            .pxs2
            .get(local)
            .map(|px| px.primary().p == 0)
            .unwrap_or(true)
        {
            out.push(format!("{}: missing median", row.name));
        }
    }
    out
}

pub fn oracle_entry_serialized_len(entry: OracleKindEntry) -> usize {
    if entry.is_compact() { 2 } else { 3 }
}

pub fn reference_oracle_mode_from_wire(s: &str) -> Option<ReferenceOracleMode> {
    match s {
        "e" | "E" => Some(ReferenceOracleMode::E),
        "a" | "A" => Some(ReferenceOracleMode::A),
        "d" | "D" => Some(ReferenceOracleMode::D),
        _ => None,
    }
}

fn wire_asset_key(asset: AssetId) -> String {
    if asset <= 9_999 {
        asset.to_string()
    } else if asset <= 99_999_999 {
        (asset + 100_000).to_string()
    } else {
        "-1".to_owned()
    }
}

fn checked_abs_i64(value: i64) -> Result<u64, OracleError> {
    value
        .checked_abs()
        .map(|abs| abs as u64)
        .ok_or(OracleError::ArithmeticOverflow)
}
