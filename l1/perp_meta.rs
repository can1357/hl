use std::collections::{BTreeMap, BTreeSet};

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};

pub type Address = [u8; 20];
pub type AssetId = u64;
pub type Coin = String;
pub type Dex = u64;
pub type Token = u32;

pub const ASSETS_PER_DEX: u64 = 10_000;
pub const MAX_SZ_DECIMALS: u8 = 6;
pub const PX_DECIMALS: u8 = 6;
pub const BUILTIN_MARGIN_TABLE_CUTOFF: u32 = 50;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PerpMetaResponse {
    pub universe: Vec<PerpAssetMeta>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub margin_tables: Vec<RawMarginTable>,
    pub collateral_token: Token,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PerpAssetMeta {
    pub name: Coin,
    pub sz_decimals: u32,
    pub max_leverage: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_isolated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub margin_table_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_delisted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub margin_mode: Option<MarginMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub growth_mode: Option<GrowthMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_growth_mode_change_time: Option<u64>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TradingStatus {
    Active,
    ReduceOnly,
    Delisted,
    Disabled,
}

impl Default for TradingStatus {
    fn default() -> Self {
        Self::Active
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MarginMode {
    Cross,
    Isolated,
    InitialTable,
    MaintenanceTable,
    CappedLeverage,
}

impl Default for MarginMode {
    fn default() -> Self {
        Self::Cross
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GrowthMode {
    Normal,
    AllowHip3,
    Frozen,
}

impl Default for GrowthMode {
    fn default() -> Self {
        Self::Normal
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PerpUniverseAsset {
    pub name: Coin,
    pub sz_decimals: u8,
    pub max_leverage: u32,
    pub margin_table_id: Option<u32>,
    #[serde(default)]
    pub only_isolated: bool,
    #[serde(default)]
    pub trading_status: TradingStatus,
    #[serde(default)]
    pub margin_mode: MarginMode,
    #[serde(default)]
    pub growth_mode: GrowthMode,
    #[serde(default)]
    pub last_growth_mode_change_time: Option<u64>,
    #[serde(default)]
    pub base_perp_id: Option<u32>,
}

impl Serialize for PerpUniverseAsset {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Recovered serializer order: szDecimals, name, maxLeverage,
        // marginTableId; optional mode fields are emitted only when non-default.
        let mut len = 4;
        len += usize::from(self.only_isolated);
        len += usize::from(self.trading_status == TradingStatus::Delisted);
        len += usize::from(self.margin_mode != MarginMode::Cross);
        len += usize::from(self.growth_mode != GrowthMode::Normal);
        len += usize::from(self.last_growth_mode_change_time.is_some());

        let mut st = serializer.serialize_struct("PerpUniverseAsset", len)?;
        st.serialize_field("szDecimals", &(self.sz_decimals as u32))?;
        st.serialize_field("name", &self.name)?;
        st.serialize_field("maxLeverage", &self.max_leverage)?;
        st.serialize_field("marginTableId", &self.margin_table_id)?;
        if self.only_isolated {
            st.serialize_field("onlyIsolated", &true)?;
        }
        if self.trading_status == TradingStatus::Delisted {
            st.serialize_field("isDelisted", &true)?;
        }
        if self.margin_mode != MarginMode::Cross {
            st.serialize_field("marginMode", &self.margin_mode)?;
        }
        if self.growth_mode != GrowthMode::Normal {
            st.serialize_field("growthMode", &self.growth_mode)?;
        }
        if let Some(t) = self.last_growth_mode_change_time {
            st.serialize_field("lastGrowthModeChangeTime", &t)?;
        }
        st.end()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawMarginTable {
    pub description: String,
    pub margin_tiers: Vec<RawMarginTier>,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawMarginTier {
    pub lower_bound: u64,
    pub max_leverage: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MarginTable {
    pub description: String,
    pub margin_tiers: Vec<MarginTier>,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MarginTier {
    pub lower_bound_ntl: u64,
    pub max_leverage: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetCtx {
    pub day_ntl_vlm: String,
    pub funding: String,
    pub impact_pxs: Option<[String; 2]>,
    pub mark_px: String,
    pub mid_px: Option<String>,
    pub open_interest: String,
    pub oracle_px: String,
    pub premium: String,
    pub prev_day_px: String,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct OracleMarkPair {
    pub oracle_px_raw: Option<u64>,
    pub mark_px_raw: Option<u64>,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct PerpAssetStats {
    pub day_ntl_vlm_raw: u64,
    pub funding_raw: i64,
    pub open_interest_raw: u64,
    pub oracle_px_raw: u64,
    pub mark_px_raw: u64,
    pub mid_px_raw: Option<u64>,
    pub prev_day_px_raw: u64,
    pub impact_pxs_raw: Option<[u64; 2]>,
}

#[derive(Clone, Debug, Default)]
pub struct PerpMeta {
    pub dex: Dex,
    pub universe: Vec<PerpUniverseAsset>,
    pub margin_tables: BTreeMap<u32, MarginTable>,
    pub collateral_token: Token,
    pub asset_to_streaming_oi_cap: BTreeMap<AssetId, u64>,
    pub active_users_with_positions: BTreeSet<Address>,
    pub max_users_with_positions: Option<usize>,
    pub funding_multiplier_by_asset: BTreeMap<AssetId, i64>,
    pub funding_interest_rate_by_asset: BTreeMap<AssetId, i64>,
}

impl PerpMeta {
    pub fn new(dex: Dex, collateral_token: Token) -> Self {
        Self {
            dex,
            collateral_token,
            ..Self::default()
        }
    }

    pub fn split_asset_id(&self, asset_id: AssetId) -> Result<(Dex, usize), PerpMetaError> {
        let dex = asset_id / ASSETS_PER_DEX;
        let local = (asset_id % ASSETS_PER_DEX) as usize;
        if dex != self.dex || local >= self.universe.len() {
            return Err(PerpMetaError::InvalidAsset(asset_id));
        }
        Ok((dex, local))
    }

    pub fn asset(&self, asset_id: AssetId) -> Result<&PerpUniverseAsset, PerpMetaError> {
        let (_, local) = self.split_asset_id(asset_id)?;
        Ok(&self.universe[local])
    }

    pub fn asset_mut(&mut self, asset_id: AssetId) -> Result<&mut PerpUniverseAsset, PerpMetaError> {
        let (_, local) = self.split_asset_id(asset_id)?;
        Ok(&mut self.universe[local])
    }

    pub fn to_response(&self) -> PerpMetaResponse {
        let universe = self
            .universe
            .iter()
            .map(PerpUniverseAsset::to_api_meta)
            .collect();
        let margin_tables = self
            .margin_tables
            .values()
            .map(MarginTable::to_raw)
            .collect();
        PerpMetaResponse {
            universe,
            margin_tables,
            collateral_token: self.collateral_token,
        }
    }

    pub fn register_asset(&mut self, asset: PerpUniverseAsset) -> Result<AssetId, PerpMetaError> {
        asset.validate()?;
        let local = self.universe.len();
        if local >= ASSETS_PER_DEX as usize {
            return Err(PerpMetaError::NoFreeAssetSlot);
        }
        self.universe.push(asset);
        Ok(self.dex * ASSETS_PER_DEX + local as u64)
    }

    pub fn find_available_asset_slot(&self) -> Option<AssetId> {
        self.universe
            .iter()
            .position(|asset| asset.trading_status == TradingStatus::Active && asset.base_perp_id.is_none())
            .map(|local| self.dex * ASSETS_PER_DEX + local as u64)
    }

    pub fn set_asset_max_leverage(
        &mut self,
        asset_id: AssetId,
        max_leverage: u32,
        margin_table_id: Option<u32>,
    ) -> Result<(), PerpMetaError> {
        validate_leverage(max_leverage)?;
        if let Some(table_id) = margin_table_id {
            self.margin_table_for_selector(max_leverage, table_id)?;
        }
        let asset = self.asset_mut(asset_id)?;
        asset.max_leverage = max_leverage;
        asset.margin_table_id = margin_table_id;
        Ok(())
    }

    pub fn close_delisted_asset_to_margin_ratio(
        &self,
        asset_id: AssetId,
        ratio: f64,
        position_abs_raw: i64,
    ) -> Result<i64, PerpMetaError> {
        let asset = self.asset(asset_id)?;
        if asset.trading_status != TradingStatus::Delisted {
            return Ok(0);
        }
        if !(0.5..=1.0).contains(&ratio) {
            return Err(PerpMetaError::InvalidCloseRatio);
        }
        Ok(((position_abs_raw as f64) * ratio).ceil() as i64)
    }

    pub fn raw_px_to_display_px(&self, asset_id: AssetId, raw_px: u64) -> Result<f64, PerpMetaError> {
        let asset = self.asset(asset_id)?;
        asset.check_sz_decimals()?;
        Ok(raw_px as f64 / pow10_u64((PX_DECIMALS - asset.sz_decimals) as u32) as f64)
    }

    pub fn raw_sz_to_display_sz(&self, asset_id: AssetId, raw_sz: u64) -> Result<f64, PerpMetaError> {
        if raw_sz == 0 {
            return Ok(0.0);
        }
        let asset = self.asset(asset_id)?;
        asset.check_sz_decimals()?;
        Ok(raw_sz as f64 / pow10_u64(asset.sz_decimals as u32) as f64)
    }

    pub fn display_px_string(&self, asset_id: AssetId, raw_px: u64) -> Result<String, PerpMetaError> {
        let asset = self.asset(asset_id)?;
        asset.check_sz_decimals()?;
        Ok(format_fixed_u64(raw_px, (PX_DECIMALS - asset.sz_decimals) as u32))
    }

    pub fn display_sz_string(&self, asset_id: AssetId, raw_sz: u64) -> Result<String, PerpMetaError> {
        let asset = self.asset(asset_id)?;
        asset.check_sz_decimals()?;
        Ok(format_fixed_u64(raw_sz, asset.sz_decimals as u32))
    }

    pub fn size_increment_for_asset(
        &self,
        asset_id: AssetId,
        raw_notional: u64,
    ) -> Result<u64, PerpMetaError> {
        let asset = self.asset(asset_id)?;
        asset.check_sz_decimals()?;
        let dynamic = dynamic_size_increment(raw_notional);
        let decimal_cap = pow10_u64((PX_DECIMALS - asset.sz_decimals) as u32);
        Ok(dynamic.min(decimal_cap))
    }

    pub fn compute_asset_tick_size(&self, asset_id: AssetId, raw_px: u64) -> Result<u64, PerpMetaError> {
        let asset = self.asset(asset_id)?;
        asset.check_sz_decimals()?;
        let decimal_cap = pow10_u64((PX_DECIMALS - asset.sz_decimals) as u32);
        Ok(price_magnitude_tick(raw_px).min(decimal_cap))
    }

    pub fn validate_raw_size_granularity(
        &self,
        asset_id: AssetId,
        wire: WireSize,
    ) -> Result<NormalizedOrderSize, ValidationError> {
        if wire.kind == 2 {
            return Ok(NormalizedOrderSize {
                lots: wire.raw,
                flags: wire.flags,
                kind: wire.kind,
            });
        }
        let asset = self.asset(asset_id).map_err(ValidationError::from)?;
        asset.check_sz_decimals().map_err(ValidationError::from)?;
        let unit = pow10_u64(asset.sz_decimals as u32 + 2);
        if wire.raw < unit || wire.raw % unit != 0 {
            return Err(ValidationError::code(101));
        }
        Ok(NormalizedOrderSize {
            lots: wire.raw / unit,
            flags: wire.flags,
            kind: wire.kind,
        })
    }

    pub fn validate_open_interest_caps(
        &self,
        user: Address,
        asset_id: AssetId,
        normalized_size: u64,
        is_buy: bool,
        account_allows_trade: bool,
    ) -> Result<(), ValidationError> {
        if !is_buy && normalized_size == 0 {
            return Err(ValidationError::code(94));
        }
        if self.asset_to_streaming_oi_cap.contains_key(&asset_id) {
            return Err(ValidationError::code(113));
        }
        let asset = self.asset(asset_id).map_err(ValidationError::from)?;
        if !account_allows_trade && asset.trading_status == TradingStatus::Active {
            return Err(ValidationError::code(196));
        }
        if let Some(limit) = self.max_users_with_positions {
            if !self.active_users_with_positions.contains(&user)
                && self.active_users_with_positions.len() >= limit
            {
                return Err(ValidationError::code(353));
            }
        }
        Ok(())
    }

    pub fn max_leverage_for_margin_table(
        &self,
        max_leverage: u32,
        margin_table_id: Option<u32>,
        notional: u64,
    ) -> Result<u32, PerpMetaError> {
        let table = self.margin_table_for_selector(max_leverage, margin_table_id.unwrap_or(max_leverage))?;
        Ok(table.max_leverage_for_notional(notional))
    }

    pub fn compute_margin_requirement_by_mode(
        &self,
        input: PositionMarginInput,
    ) -> Result<MarginRequirement, PerpMetaError> {
        if input.price_raw < 0 || input.abs_size_raw < 0 {
            return Err(PerpMetaError::NegativeMarginInput);
        }
        let notional = checked_i64_product_abs(input.price_raw, input.abs_size_raw)?;
        let leverage = match input.mode {
            MarginMode::Cross => 0,
            MarginMode::Isolated => input.max_leverage,
            MarginMode::InitialTable => self.max_leverage_for_margin_table(
                input.max_leverage,
                input.margin_table_id,
                notional,
            )?,
            MarginMode::MaintenanceTable => self
                .margin_table_for_selector(input.max_leverage, input.margin_table_id.unwrap_or(input.max_leverage))?
                .maintenance_leverage_for_notional(notional),
            MarginMode::CappedLeverage => input.max_leverage.min(input.cap_leverage.unwrap_or(input.max_leverage)),
        };
        let margin = if leverage == 0 { 0 } else { notional / leverage as u64 };
        let signed_equity_after = input.existing_margin_raw.saturating_add(input.position_delta_raw);
        Ok(MarginRequirement {
            active: input.has_position,
            signed_equity_after,
            required_margin: if input.has_position { margin } else { 0 },
            notional,
            previous_margin: input.existing_margin_raw,
            applied_leverage: leverage,
        })
    }

    pub fn impact_pxs_to_display_pair(
        &self,
        asset_id: AssetId,
        raw: [u64; 2],
    ) -> Result<[f64; 2], PerpMetaError> {
        let first = if raw[0] == 0 { 0.0 } else { self.raw_px_to_display_px(asset_id, raw[0])? };
        let second = if raw[1] == 0 { 0.0 } else { self.raw_px_to_display_px(asset_id, raw[1])? };
        Ok([first, second])
    }

    pub fn compute_premium_and_impact_pxs(
        &self,
        asset_id: AssetId,
        oracle_px_raw: u64,
        impact_bid_raw: u64,
        impact_ask_raw: u64,
        divide_premium_by_100: bool,
    ) -> Result<PremiumImpact, PerpMetaError> {
        let oracle = self.raw_px_to_display_px(asset_id, oracle_px_raw)?;
        let bid = self.raw_px_to_display_px(asset_id, impact_bid_raw)?;
        let ask = self.raw_px_to_display_px(asset_id, impact_ask_raw)?;
        let mut premium = if oracle == 0.0 { 0.0 } else { ((bid + ask) * 0.5 - oracle) / oracle };
        premium = premium.clamp(-0.5, 0.5);
        if divide_premium_by_100 {
            premium /= 100.0;
        }
        Ok(PremiumImpact {
            premium,
            impact_pxs: [bid, ask],
        })
    }

    pub fn active_asset_ctx(
        &self,
        asset_id: AssetId,
        stats: PerpAssetStats,
    ) -> Result<AssetCtx, PerpMetaError> {
        let impact_pxs = match stats.impact_pxs_raw {
            Some(raw) => Some([
                self.display_px_string(asset_id, raw[0])?,
                self.display_px_string(asset_id, raw[1])?,
            ]),
            None => None,
        };
        let premium = if stats.oracle_px_raw == 0 {
            String::from("0")
        } else {
            let mark = self.raw_px_to_display_px(asset_id, stats.mark_px_raw)?;
            let oracle = self.raw_px_to_display_px(asset_id, stats.oracle_px_raw)?;
            format_decimal_f64(((mark - oracle) / oracle).clamp(-0.5, 0.5), 8)
        };
        Ok(AssetCtx {
            day_ntl_vlm: format_fixed_u64(stats.day_ntl_vlm_raw, 6),
            funding: format_fixed_i64(stats.funding_raw, 6),
            impact_pxs,
            mark_px: self.display_px_string(asset_id, stats.mark_px_raw)?,
            mid_px: stats
                .mid_px_raw
                .map(|raw| self.display_px_string(asset_id, raw))
                .transpose()?,
            open_interest: self.display_sz_string(asset_id, stats.open_interest_raw)?,
            oracle_px: self.display_px_string(asset_id, stats.oracle_px_raw)?,
            premium,
            prev_day_px: self.display_px_string(asset_id, stats.prev_day_px_raw)?,
        })
    }

    fn margin_table_for_selector(&self, max_leverage: u32, selector: u32) -> Result<MarginTable, PerpMetaError> {
        if selector < BUILTIN_MARGIN_TABLE_CUTOFF {
            validate_leverage(max_leverage)?;
            return Ok(MarginTable::single_tier(format!("{}x", max_leverage), max_leverage));
        }
        self.margin_tables
            .get(&selector)
            .cloned()
            .ok_or(PerpMetaError::MissingMarginTable(selector))
    }
}

impl PerpUniverseAsset {
    pub fn validate(&self) -> Result<(), PerpMetaError> {
        self.check_sz_decimals()?;
        validate_leverage(self.max_leverage)?;
        if self.only_isolated && self.margin_mode == MarginMode::Cross {
            return Err(PerpMetaError::OnlyIsolatedAssetCannotUseCross);
        }
        Ok(())
    }

    pub fn check_sz_decimals(&self) -> Result<(), PerpMetaError> {
        if self.sz_decimals > MAX_SZ_DECIMALS {
            return Err(PerpMetaError::InvalidSizeDecimals(self.sz_decimals));
        }
        Ok(())
    }

    pub fn to_api_meta(&self) -> PerpAssetMeta {
        PerpAssetMeta {
            name: self.name.clone(),
            sz_decimals: self.sz_decimals as u32,
            max_leverage: self.max_leverage,
            only_isolated: self.only_isolated.then_some(true),
            margin_table_id: self.margin_table_id,
            is_delisted: (self.trading_status == TradingStatus::Delisted).then_some(true),
            margin_mode: (self.margin_mode != MarginMode::Cross).then_some(self.margin_mode),
            growth_mode: (self.growth_mode != GrowthMode::Normal).then_some(self.growth_mode),
            last_growth_mode_change_time: self.last_growth_mode_change_time,
        }
    }
}

impl MarginTable {
    pub fn single_tier(description: String, max_leverage: u32) -> Self {
        Self {
            description,
            margin_tiers: vec![MarginTier {
                lower_bound_ntl: 0,
                max_leverage,
            }],
        }
    }

    pub fn validate(&self) -> Result<(), PerpMetaError> {
        if self.margin_tiers.is_empty() {
            return Err(PerpMetaError::EmptyMarginTable);
        }
        let mut last_lower = None;
        for tier in &self.margin_tiers {
            validate_leverage(tier.max_leverage)?;
            if let Some(last) = last_lower {
                if tier.lower_bound_ntl <= last {
                    return Err(PerpMetaError::UnsortedMarginTable);
                }
            }
            last_lower = Some(tier.lower_bound_ntl);
        }
        Ok(())
    }

    pub fn max_leverage_for_notional(&self, notional: u64) -> u32 {
        self.tier_for_notional(notional).max_leverage
    }

    pub fn maintenance_leverage_for_notional(&self, notional: u64) -> u32 {
        self.tier_for_notional(notional).max_leverage
    }

    pub fn to_raw(&self) -> RawMarginTable {
        RawMarginTable {
            description: self.description.clone(),
            margin_tiers: self
                .margin_tiers
                .iter()
                .map(|tier| RawMarginTier {
                    lower_bound: tier.lower_bound_ntl,
                    max_leverage: tier.max_leverage,
                })
                .collect(),
        }
    }

    fn tier_for_notional(&self, notional: u64) -> MarginTier {
        let mut selected = self.margin_tiers[0];
        for tier in &self.margin_tiers {
            if tier.lower_bound_ntl > notional {
                break;
            }
            selected = *tier;
        }
        selected
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WireSize {
    pub raw: u64,
    pub flags: u8,
    pub kind: u8,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NormalizedOrderSize {
    pub lots: u64,
    pub flags: u8,
    pub kind: u8,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PositionMarginInput {
    pub has_position: bool,
    pub existing_margin_raw: i64,
    pub price_raw: i64,
    pub abs_size_raw: i64,
    pub mode: MarginMode,
    pub max_leverage: u32,
    pub margin_table_id: Option<u32>,
    pub cap_leverage: Option<u32>,
    pub position_delta_raw: i64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MarginRequirement {
    pub active: bool,
    pub signed_equity_after: i64,
    pub required_margin: u64,
    pub notional: u64,
    pub previous_margin: i64,
    pub applied_leverage: u32,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct PremiumImpact {
    pub premium: f64,
    pub impact_pxs: [f64; 2],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PerpMetaError {
    InvalidAsset(AssetId),
    InvalidSizeDecimals(u8),
    InvalidLeverage(u32),
    MissingMarginTable(u32),
    EmptyMarginTable,
    UnsortedMarginTable,
    OnlyIsolatedAssetCannotUseCross,
    NegativeMarginInput,
    NotionalOverflow,
    InvalidCloseRatio,
    NoFreeAssetSlot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationError {
    pub code: u16,
    pub source: Option<PerpMetaError>,
}

impl ValidationError {
    pub fn code(code: u16) -> Self {
        Self { code, source: None }
    }
}

impl From<PerpMetaError> for ValidationError {
    fn from(source: PerpMetaError) -> Self {
        Self {
            code: 390,
            source: Some(source),
        }
    }
}

fn validate_leverage(max_leverage: u32) -> Result<(), PerpMetaError> {
    if max_leverage == 0 {
        return Err(PerpMetaError::InvalidLeverage(max_leverage));
    }
    Ok(())
}

fn checked_i64_product_abs(a: i64, b: i64) -> Result<u64, PerpMetaError> {
    let product = a.checked_mul(b).ok_or(PerpMetaError::NotionalOverflow)?;
    if product == i64::MIN {
        return Err(PerpMetaError::NotionalOverflow);
    }
    Ok(product.unsigned_abs())
}

fn dynamic_size_increment(raw_notional: u64) -> u64 {
    match raw_notional {
        0..=99_999 => 1,
        100_000..=999_999 => 10,
        1_000_000..=9_999_999 => 100,
        10_000_000..=99_999_999 => 1_000,
        100_000_000..=999_999_999 => 10_000,
        1_000_000_000..=9_999_999_999 => 100_000,
        10_000_000_000..=99_999_999_999 => 1_000_000,
        100_000_000_000..=999_999_999_999 => 10_000_000,
        1_000_000_000_000..=9_999_999_999_999 => 100_000_000,
        10_000_000_000_000..=99_999_999_999_999 => 1_000_000_000,
        100_000_000_000_000..=999_999_999_999_999 => 10_000_000_000,
        1_000_000_000_000_000..=9_999_999_999_999_999 => 100_000_000_000,
        _ => 1_000_000_000_000,
    }
}

fn price_magnitude_tick(raw_px: u64) -> u64 {
    match raw_px {
        0..=999_999 => 1,
        1_000_000..=9_999_999 => 10,
        10_000_000..=99_999_999 => 100,
        100_000_000..=999_999_999 => 1_000,
        1_000_000_000..=9_999_999_999 => 10_000,
        _ => 100_000,
    }
}

fn pow10_u64(exp: u32) -> u64 {
    let mut value = 1_u64;
    for _ in 0..exp {
        value *= 10;
    }
    value
}

fn format_fixed_u64(value: u64, decimals: u32) -> String {
    if decimals == 0 {
        return value.to_string();
    }
    let scale = pow10_u64(decimals);
    let whole = value / scale;
    let frac = value % scale;
    if frac == 0 {
        return whole.to_string();
    }
    let mut frac_text = format!("{:0width$}", frac, width = decimals as usize);
    while frac_text.ends_with('0') {
        frac_text.pop();
    }
    format!("{whole}.{frac_text}")
}

fn format_fixed_i64(value: i64, decimals: u32) -> String {
    if value < 0 {
        let magnitude = value.unsigned_abs();
        format!("-{}", format_fixed_u64(magnitude, decimals))
    } else {
        format_fixed_u64(value as u64, decimals)
    }
}

fn format_decimal_f64(value: f64, decimals: usize) -> String {
    let mut out = format!("{value:.decimals$}");
    while out.contains('.') && out.ends_with('0') {
        out.pop();
    }
    if out.ends_with('.') {
        out.pop();
    }
    out
}
