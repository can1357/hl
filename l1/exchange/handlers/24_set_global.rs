use std::collections::BTreeMap;

pub type Address = [u8; 20];
pub type AssetId = u64;

pub const STATUS_SUCCESS: u16 = 390;
pub const STATUS_UNKNOWN_ASSET_KEY: u16 = 100;
pub const STATUS_NON_POSITIVE_PRICE: u16 = 119;
pub const STATUS_UNAUTHORIZED_ORACLE_UPDATER: u16 = 148;
pub const STATUS_UNKNOWN_DEX: u16 = 321;
pub const STATUS_BOUNDS: u16 = 323;

pub const MAX_WIRE_ITEMS: usize = 10_000;
pub const MAX_WIRE_STRING_BYTES: usize = 100;
pub const RECENT_RESULT_RETENTION_CAP: usize = 100;
pub const RECENT_RESULT_RETENTION_WINDOW_SECS: i64 = 300;

#[derive(Clone, Debug, PartialEq)]
pub enum DecimalWireValue {
    Str(String),
    Float(f64),
}

impl DecimalWireValue {
    #[inline]
    pub fn parse_positive_f64(&self) -> Result<f64, SetGlobalError> {
        let parsed = match self {
            Self::Str(raw) => raw
                .parse::<f64>()
                .map_err(|_| SetGlobalError::InvalidPriceEncoding)?,
            Self::Float(value) => *value,
        };
        if parsed.is_finite() && parsed > 0.0 {
            Ok(parsed)
        } else {
            Err(SetGlobalError::NonPositivePrice)
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReferenceOracleUpdate {
    pub asset_key: String,
    pub px: DecimalWireValue,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExternalPerpPxUpdate {
    pub asset_key: String,
    pub px: DecimalWireValue,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SetGlobalAction {
    pub pxs: Vec<ReferenceOracleUpdate>,
    pub usdt_usdc_px: Option<DecimalWireValue>,
    pub native_px: Option<DecimalWireValue>,
    pub external_perp_pxs: Vec<ExternalPerpPxUpdate>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct OracleAssetRegistry {
    pub asset_key_to_id: BTreeMap<String, AssetId>,
}

impl OracleAssetRegistry {
    #[inline]
    pub fn resolve_asset_key(&self, asset_key: &str) -> Result<AssetId, SetGlobalError> {
        self.asset_key_to_id
            .get(asset_key)
            .copied()
            .ok_or_else(|| SetGlobalError::UnknownAssetKey(asset_key.to_owned()))
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct OracleUpdateBatch {
    pub reference_oracle_pxs: BTreeMap<AssetId, f64>,
    pub external_perp_pxs: BTreeMap<AssetId, f64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerDexTimestepOutcome {
    pub applied_reference_updates: usize,
    pub applied_external_updates: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecentOracleResult {
    pub unix_day: i32,
    pub seconds_into_day: u32,
    pub nanos: u32,
    pub heap_len: usize,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DexZeroOracleState {
    pub oracle_updater_signers: Vec<Address>,
    pub usdt_usdc_px: Option<f64>,
    pub native_px: Option<f64>,
    pub recent_results: Vec<RecentOracleResult>,
}

impl DexZeroOracleState {
    #[inline]
    fn signer_allowed(&self, sender: &Address) -> bool {
        self.oracle_updater_signers.iter().any(|candidate| candidate == sender)
    }

    fn retain_recent_results(&mut self, now: RecentOracleResult) {
        self.recent_results.retain(|entry| {
            let current = (now.unix_day as i64) * 86_400 + now.seconds_into_day as i64;
            let candidate = (entry.unix_day as i64) * 86_400 + entry.seconds_into_day as i64;
            candidate + RECENT_RESULT_RETENTION_WINDOW_SECS >= current
        });
        while self.recent_results.len() > RECENT_RESULT_RETENTION_CAP {
            self.recent_results.remove(0);
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ExchangeState {
    pub asset_registry: OracleAssetRegistry,
    pub dex0: Option<DexZeroOracleState>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SetGlobalApplyOk {
    pub status: u16,
    pub per_dex_timestep: PerDexTimestepOutcome,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SetGlobalError {
    UnknownDex,
    UnauthorizedOracleUpdater,
    Bounds,
    UnknownAssetKey(String),
    InvalidPriceEncoding,
    NonPositivePrice,
    PerDexTimestepRejected,
}

impl SetGlobalError {
    #[inline]
    pub fn status(&self) -> u16 {
        match self {
            Self::UnknownDex => STATUS_UNKNOWN_DEX,
            Self::UnauthorizedOracleUpdater => STATUS_UNAUTHORIZED_ORACLE_UPDATER,
            Self::Bounds => STATUS_BOUNDS,
            Self::UnknownAssetKey(_) => STATUS_UNKNOWN_ASSET_KEY,
            Self::InvalidPriceEncoding | Self::NonPositivePrice => STATUS_NON_POSITIVE_PRICE,
            Self::PerDexTimestepRejected => STATUS_NON_POSITIVE_PRICE,
        }
    }
}

pub trait PerDexOracleEngine {
    fn process_per_dex_timestep(
        &mut self,
        updates: &OracleUpdateBatch,
    ) -> Result<PerDexTimestepOutcome, SetGlobalError>;
}

#[inline]
pub fn apply_set_global<E: PerDexOracleEngine>(
    exchange_state: &mut ExchangeState,
    oracle_engine: &mut E,
    sender: Address,
    action: &SetGlobalAction,
    now: RecentOracleResult,
) -> Result<SetGlobalApplyOk, SetGlobalError> {
    let dex0 = exchange_state.dex0.as_mut().ok_or(SetGlobalError::UnknownDex)?;
    if !dex0.signer_allowed(&sender) {
        return Err(SetGlobalError::UnauthorizedOracleUpdater);
    }

    let external_perp_pxs = parse_external_perp_pxs(&exchange_state.asset_registry, &action.external_perp_pxs)?;
    let reference_oracle_pxs = parse_reference_oracle_pxs(&exchange_state.asset_registry, &action.pxs)?;

    let per_dex_timestep = oracle_engine.process_per_dex_timestep(
        &OracleUpdateBatch {
            reference_oracle_pxs,
            external_perp_pxs,
        },
    )?;

    if let Some(px) = action.usdt_usdc_px.as_ref() {
        dex0.usdt_usdc_px = Some(px.parse_positive_f64()?);
    }
    if let Some(px) = action.native_px.as_ref() {
        dex0.native_px = Some(px.parse_positive_f64()?);
    }

    dex0.recent_results.push(now);
    dex0.retain_recent_results(now);

    Ok(SetGlobalApplyOk {
        status: STATUS_SUCCESS,
        per_dex_timestep,
    })
}

fn parse_external_perp_pxs(
    registry: &OracleAssetRegistry,
    updates: &[ExternalPerpPxUpdate],
) -> Result<BTreeMap<AssetId, f64>, SetGlobalError> {
    if updates.len() > MAX_WIRE_ITEMS {
        return Err(SetGlobalError::Bounds);
    }

    let mut out = BTreeMap::new();
    for update in updates {
        if update.asset_key.len() > MAX_WIRE_STRING_BYTES {
            return Err(SetGlobalError::Bounds);
        }
        let asset = registry.resolve_asset_key(&update.asset_key)?;
        let px = update.px.parse_positive_f64()?;
        out.insert(asset, px);
    }
    Ok(out)
}

fn parse_reference_oracle_pxs(
    registry: &OracleAssetRegistry,
    updates: &[ReferenceOracleUpdate],
) -> Result<BTreeMap<AssetId, f64>, SetGlobalError> {
    if updates.len() > MAX_WIRE_ITEMS {
        return Err(SetGlobalError::Bounds);
    }

    let mut out = BTreeMap::new();
    for update in updates {
        if update.asset_key.len() > MAX_WIRE_STRING_BYTES {
            return Err(SetGlobalError::Bounds);
        }
        let asset = registry.resolve_asset_key(&update.asset_key)?;
        let px = update.px.parse_positive_f64()?;
        out.insert(asset, px);
    }
    Ok(out)
}
