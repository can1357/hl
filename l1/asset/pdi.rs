use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

pub const PDI_ASSETS_PER_DEX: u64 = 10_000;
pub const MAX_PDI_RANGE_LEN: usize = 10_000;
pub const MAX_ASSET_PREFIX_BYTES: usize = 100;
pub const MAX_ANNOTATION_NAME_BYTES: usize = 15;
pub const MAX_ANNOTATION_TEXT_BYTES: usize = 400;
pub const EXTERNAL_PERP_ORACLE_OFFSET: u64 = 100_000;
pub const SUCCESS_STATUS: u16 = 390;

#[repr(transparent)]
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DexId(pub u64);

#[repr(transparent)]
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LocalAssetIndex(pub u64);

#[repr(transparent)]
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Pdi(pub u64);

impl Pdi {
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn dex_id(self) -> DexId {
        DexId(self.0 / PDI_ASSETS_PER_DEX)
    }

    #[inline]
    pub const fn local_index(self) -> LocalAssetIndex {
        LocalAssetIndex(self.0 % PDI_ASSETS_PER_DEX)
    }

    #[inline]
    pub fn from_parts(dex_id: DexId, local: LocalAssetIndex) -> Option<Self> {
        if local.0 >= PDI_ASSETS_PER_DEX {
            return None;
        }
        Some(Self(dex_id.0.checked_mul(PDI_ASSETS_PER_DEX)?.checked_add(local.0)?))
    }

    #[inline]
    pub fn from_api_asset_id(asset: u64) -> Option<Self> {
        if asset < PDI_ASSETS_PER_DEX {
            Some(Self(asset))
        } else if asset >= EXTERNAL_PERP_ORACLE_OFFSET {
            Some(Self(asset - EXTERNAL_PERP_ORACLE_OFFSET))
        } else {
            None
        }
    }

    #[inline]
    pub fn api_asset_id(self) -> Option<u64> {
        if self.0 < PDI_ASSETS_PER_DEX {
            Some(self.0)
        } else {
            self.0.checked_add(EXTERNAL_PERP_ORACLE_OFFSET)
        }
    }

    #[inline]
    pub fn external_oracle_asset_id(self) -> Option<u64> {
        self.0.checked_add(EXTERNAL_PERP_ORACLE_OFFSET)
    }
}

impl fmt::Debug for Pdi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The recovered formatter paths are transparent through the numeric newtype;
        // serde wrong-type diagnostics use the string "tuple struct Pdi".
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Display for Pdi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl From<Pdi> for u64 {
    #[inline]
    fn from(value: Pdi) -> Self {
        value.0
    }
}

impl FromStr for Pdi {
    type Err = PdiParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw = s.parse::<u64>().map_err(|_| PdiParseError::InvalidNumber)?;
        Ok(Self(raw))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PdiParseError {
    InvalidNumber,
    PrefixTooLong { len: usize },
    UnknownDex,
    UnknownAsset(String),
    MixedDexIds,
    LocalAssetOutOfRange { local: u64 },
    PackedOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdiStatus {
    UnknownCoin = 100,
    ExplicitMessage = 224,
    DisableUnauthorized = 227,
    Unauthorized = 228,
    InvalidFeeScale = 229,
    FeeScaleGrowthModeBlocked = 230,
    MixedDexIds = 232,
    UnknownDex = 321,
    Bounds = 323,
    BadDexStatus = 354,
    UserPrecondition = 355,
    Ok = 390,
}

impl PdiStatus {
    #[inline]
    pub const fn code(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum PdiError {
    Status(PdiStatus),
    Message { status: PdiStatus, message: String },
    UnknownAsset { asset: String },
    Parse(PdiParseError),
}

impl From<PdiParseError> for PdiError {
    fn from(value: PdiParseError) -> Self {
        match value {
            PdiParseError::UnknownDex => Self::Status(PdiStatus::UnknownDex),
            PdiParseError::UnknownAsset(asset) => Self::UnknownAsset { asset },
            PdiParseError::MixedDexIds => Self::Status(PdiStatus::MixedDexIds),
            PdiParseError::PrefixTooLong { .. } | PdiParseError::LocalAssetOutOfRange { .. } => {
                Self::Status(PdiStatus::Bounds)
            }
            PdiParseError::PackedOverflow => Self::Parse(PdiParseError::PackedOverflow),
            PdiParseError::InvalidNumber => Self::Parse(PdiParseError::InvalidNumber),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PdiAssetKey<'a> {
    pub dex_prefix: Option<&'a str>,
    pub asset: &'a str,
}

impl<'a> PdiAssetKey<'a> {
    pub fn parse(input: &'a str) -> Result<Self, PdiParseError> {
        if input.len() > MAX_ASSET_PREFIX_BYTES {
            return Err(PdiParseError::PrefixTooLong { len: input.len() });
        }
        if let Some((dex, asset)) = input.split_once("::") {
            if dex.len() > MAX_ASSET_PREFIX_BYTES || asset.len() > MAX_ASSET_PREFIX_BYTES {
                return Err(PdiParseError::PrefixTooLong { len: input.len() });
            }
            Ok(Self { dex_prefix: Some(dex), asset })
        } else {
            Ok(Self { dex_prefix: None, asset: input })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PdiAssetRange {
    pub dex_id: DexId,
    pub start: LocalAssetIndex,
    pub end: LocalAssetIndex,
}

impl PdiAssetRange {
    #[inline]
    pub fn len(self) -> usize {
        self.end.0.saturating_sub(self.start.0) as usize
    }

    #[inline]
    pub fn is_empty(self) -> bool {
        self.start.0 >= self.end.0
    }

    pub fn checked(self) -> Result<Self, PdiParseError> {
        if self.start.0 > PDI_ASSETS_PER_DEX {
            return Err(PdiParseError::LocalAssetOutOfRange { local: self.start.0 });
        }
        if self.end.0 > PDI_ASSETS_PER_DEX {
            return Err(PdiParseError::LocalAssetOutOfRange { local: self.end.0 });
        }
        Ok(self)
    }

    pub fn iter(self) -> PdiAssetRangeIter {
        PdiAssetRangeIter { range: self, next: self.start.0 }
    }

    pub fn packed_asset_ids(self) -> Result<Vec<Pdi>, PdiParseError> {
        self.checked()?;
        let mut out = Vec::with_capacity(self.len());
        for pdi in self.iter() {
            out.push(pdi?);
        }
        Ok(out)
    }

    pub fn zero_pdi_rows(self) -> Result<Vec<ZeroPdiRow>, PdiParseError> {
        self.checked()?;
        let mut out = Vec::with_capacity(self.len());
        for pdi in self.iter() {
            out.push(ZeroPdiRow { pdi: pdi?, size: 0, reserved: 0 });
        }
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PdiAssetRangeIter {
    range: PdiAssetRange,
    next: u64,
}

impl Iterator for PdiAssetRangeIter {
    type Item = Result<Pdi, PdiParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.range.end.0 {
            return None;
        }
        let local = LocalAssetIndex(self.next);
        self.next += 1;
        Some(Pdi::from_parts(self.range.dex_id, local).ok_or(PdiParseError::PackedOverflow))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ZeroPdiRow {
    pub pdi: Pdi,
    pub size: i64,
    pub reserved: i64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Decimal128(pub i128);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AssetMetricTriplet {
    pub oracle_px: Option<Decimal128>,
    pub mark_px: Option<Decimal128>,
    pub external_perp_px: Option<Decimal128>,
}

#[derive(Clone, Debug, Default)]
pub struct ExternalPerpPxMaps {
    pub oracle_px: BTreeMap<Pdi, Decimal128>,
    pub mark_px: BTreeMap<Pdi, Decimal128>,
    pub external_perp_px: BTreeMap<Pdi, Decimal128>,
}

impl ExternalPerpPxMaps {
    #[inline]
    pub fn lookup_triplet(&self, pdi: Pdi) -> AssetMetricTriplet {
        AssetMetricTriplet {
            oracle_px: self.oracle_px.get(&pdi).copied(),
            mark_px: self.mark_px.get(&pdi).copied(),
            external_perp_px: self.external_perp_px.get(&pdi).copied(),
        }
    }

    pub fn rows_from_range(&self, range: PdiAssetRange) -> Result<Vec<AssetMetricTriplet>, PdiParseError> {
        range.checked()?;
        let mut rows = Vec::with_capacity(range.len());
        for pdi in range.iter() {
            rows.push(self.lookup_triplet(pdi?));
        }
        Ok(rows)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DexStatus {
    Active,
    Disabling,
    DisabledByValidators,
    Deleted,
}

impl DexStatus {
    #[inline]
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Active),
            1 => Some(Self::Disabling),
            2 => Some(Self::DisabledByValidators),
            3 => Some(Self::Deleted),
            _ => None,
        }
    }

    #[inline]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::Disabling => 1,
            Self::DisabledByValidators => 2,
            Self::Deleted => 3,
        }
    }

    #[inline]
    pub const fn is_lookup_visible(self) -> bool {
        !matches!(self, Self::Deleted)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Address(pub [u8; 20]);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct NaiveDateTime12 {
    pub seconds: i64,
    pub nanos: u32,
}

impl NaiveDateTime12 {
    #[inline]
    pub fn checked_add_seconds_f64(self, seconds: f64) -> Option<Self> {
        if !seconds.is_finite() || seconds < i64::MIN as f64 || seconds > i64::MAX as f64 {
            return None;
        }
        Some(Self { seconds: self.seconds.checked_add(seconds as i64)?, nanos: self.nanos })
    }
}

#[derive(Clone, Debug, Default)]
pub struct PerpAnnotation {
    pub category: String,
    pub description: String,
    pub display_name: String,
    pub keywords: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct PdiAssetInfo {
    pub name: String,
    pub pdi: Pdi,
    pub source_local_index: LocalAssetIndex,
    pub is_halted: bool,
    pub growth_mode_allowed: bool,
    pub funding_multiplier: Option<f64>,
    pub funding_interest_rate: Option<f64>,
    pub open_interest_cap: Option<f64>,
    pub annotation: Option<PerpAnnotation>,
}

#[derive(Clone, Debug, Default)]
pub struct PerpDexAuthority {
    pub deployer: Address,
    pub permissions: BTreeSet<(u8, Address)>,
}

#[derive(Clone, Debug)]
pub struct PerpDexEntry {
    pub dex_id: DexId,
    pub name: String,
    pub status: DexStatus,
    pub assets: Vec<PdiAssetInfo>,
    pub authority: PerpDexAuthority,
    pub fee_scale: f64,
    pub last_fee_scale_update: NaiveDateTime12,
}

impl Default for PerpDexEntry {
    fn default() -> Self {
        Self {
            dex_id: DexId(0),
            name: String::new(),
            status: DexStatus::Active,
            assets: Vec::new(),
            authority: PerpDexAuthority::default(),
            fee_scale: 1.0,
            last_fee_scale_update: NaiveDateTime12::default(),
        }
    }
}

impl PerpDexEntry {
    pub fn range(&self) -> PdiAssetRange {
        PdiAssetRange {
            dex_id: self.dex_id,
            start: LocalAssetIndex(0),
            end: LocalAssetIndex(self.assets.len() as u64),
        }
    }

    pub fn parse_oracle_asset_key(&self, asset_name: &str) -> Result<Pdi, PdiError> {
        for (local, asset) in self.assets.iter().enumerate() {
            if asset.name.len() == asset_name.len() && asset.name.as_bytes() == asset_name.as_bytes() {
                let local = LocalAssetIndex(local as u64);
                return Pdi::from_parts(self.dex_id, local)
                    .ok_or(PdiError::Parse(PdiParseError::PackedOverflow));
            }
        }
        Err(PdiError::UnknownAsset { asset: asset_name.to_owned() })
    }

    pub fn append_pdi_asset_infos(&self, range: PdiAssetRange) -> Result<Vec<PdiAssetInfo>, PdiError> {
        let mut out = Vec::with_capacity(range.checked()?.len());
        for pdi in range.iter() {
            let pdi = pdi?;
            let local = pdi.local_index().0 as usize;
            let Some(asset) = self.assets.get(local) else {
                return Err(PdiError::Status(PdiStatus::Bounds));
            };
            let mut cloned = asset.clone();
            cloned.pdi = pdi;
            cloned.source_local_index = LocalAssetIndex(local as u64);
            out.push(cloned);
        }
        Ok(out)
    }

    pub fn collect_stale_oracle_asset_names(&self, eligible: &BTreeSet<Pdi>, range: PdiAssetRange) -> Result<Vec<String>, PdiError> {
        let mut out = Vec::new();
        for pdi in range.iter() {
            let pdi = pdi?;
            if eligible.contains(&pdi) {
                if let Some(asset) = self.assets.get(pdi.local_index().0 as usize) {
                    out.push(asset.name.clone());
                }
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Default)]
pub struct PdiRegistry {
    pub dexes: Vec<PerpDexEntry>,
}

impl PdiRegistry {
    pub fn find_by_dex_name_or_first(&self, name: &str) -> Result<&PerpDexEntry, PdiError> {
        if name.len() > MAX_ASSET_PREFIX_BYTES {
            return Err(PdiError::Status(PdiStatus::Bounds));
        }
        if name.is_empty() {
            return self.dexes.iter().find(|dex| dex.status.is_lookup_visible()).ok_or(PdiError::Status(PdiStatus::UnknownDex));
        }
        self.dexes
            .iter()
            .find(|dex| dex.status.is_lookup_visible() && dex.name.len() == name.len() && dex.name.as_bytes() == name.as_bytes())
            .ok_or(PdiError::Status(PdiStatus::UnknownDex))
    }

    pub fn find_by_dex_name_or_first_mut(&mut self, name: &str) -> Result<&mut PerpDexEntry, PdiError> {
        if name.len() > MAX_ASSET_PREFIX_BYTES {
            return Err(PdiError::Status(PdiStatus::Bounds));
        }
        if name.is_empty() {
            return self.dexes.iter_mut().find(|dex| dex.status.is_lookup_visible()).ok_or(PdiError::Status(PdiStatus::UnknownDex));
        }
        self.dexes
            .iter_mut()
            .find(|dex| dex.status.is_lookup_visible() && dex.name.len() == name.len() && dex.name.as_bytes() == name.as_bytes())
            .ok_or(PdiError::Status(PdiStatus::UnknownDex))
    }

    pub fn resolve_asset_prefix(&self, key: &str) -> Result<(&PerpDexEntry, &str), PdiError> {
        let parsed = PdiAssetKey::parse(key)?;
        let dex = self.find_by_dex_name_or_first(parsed.dex_prefix.unwrap_or(""))?;
        Ok((dex, parsed.asset))
    }

    pub fn parse_prefixed_asset_key(&self, key: &str) -> Result<Pdi, PdiError> {
        let (dex, asset) = self.resolve_asset_prefix(key)?;
        dex.parse_oracle_asset_key(asset)
    }

    pub fn resolve_asset_prefixes_same_dex<'a, I>(&self, keys: I) -> Result<(DexId, Vec<Pdi>), PdiError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut dex_id = None;
        let mut out = Vec::new();
        for key in keys {
            let (dex, asset) = self.resolve_asset_prefix(key)?;
            if let Some(first) = dex_id {
                if first != dex.dex_id {
                    return Err(PdiError::Status(PdiStatus::MixedDexIds));
                }
            } else {
                dex_id = Some(dex.dex_id);
            }
            out.push(dex.parse_oracle_asset_key(asset)?);
        }
        Ok((dex_id.unwrap_or(DexId(0)), out))
    }

    pub fn collect_funding_values_by_asset(&self, default_value: f64) -> BTreeMap<Pdi, f64> {
        let mut out = BTreeMap::new();
        for dex in self.dexes.iter().filter(|dex| dex.status.is_lookup_visible()) {
            for asset in &dex.assets {
                let value = asset.funding_multiplier.unwrap_or(default_value);
                out.insert(asset.pdi, value);
            }
        }
        out
    }
}

#[derive(Clone, Debug, Default)]
pub struct PdiSizeState {
    pub dex_id: DexId,
    pub sizes_by_local_asset: Vec<i64>,
    pub multiplier_by_pdi: BTreeMap<Pdi, i64>,
}

impl PdiSizeState {
    pub fn try_fold_size_products(&self, range: PdiAssetRange, acc: i64, override_one: Option<(Pdi, i64)>) -> Option<i64> {
        let mut sum = acc;
        for pdi in range.iter() {
            let pdi = pdi.ok()?;
            let local = pdi.local_index().0 as usize;
            let mut size = *self.sizes_by_local_asset.get(local)?;
            if let Some((override_pdi, override_size)) = override_one {
                if override_pdi == pdi && override_size != 0 {
                    size = override_size;
                }
            }
            if size < 0 {
                return None;
            }
            let product = match self.multiplier_by_pdi.get(&pdi) {
                Some(multiplier) => multiplier.checked_mul(size)?,
                None => 0,
            };
            sum = sum.checked_add(product)?;
        }
        Some(sum)
    }

    pub fn try_fold_size_products_with_map(&self, range: PdiAssetRange, acc: i64, overrides: &BTreeMap<Pdi, i64>) -> Option<i64> {
        let mut sum = acc;
        for pdi in range.iter() {
            let pdi = pdi.ok()?;
            let local = pdi.local_index().0 as usize;
            let size = overrides.get(&pdi).copied().unwrap_or(*self.sizes_by_local_asset.get(local)?);
            if size < 0 {
                return None;
            }
            let product = match self.multiplier_by_pdi.get(&pdi) {
                Some(multiplier) => multiplier.checked_mul(size)?,
                None => 0,
            };
            sum = sum.checked_add(product)?;
        }
        Some(sum)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdiActionKind {
    RegisterAsset = 0,
    RegisterAsset2 = 1,
    ProcessPerDexTimestep = 2,
    ToggleAsset = 3,
    UpdateMarginTable = 4,
    SetUserDexFlag = 5,
    ApplyAssetModeFlags = 6,
    ValidateMarginModeChanges = 7,
    SetFundingMultiplier = 8,
    SetFundingInterestRate = 9,
    SetStaleOracleAssets = 10,
    ApplyMarginModeChanges = 11,
    SetFeeScale = 12,
    AssetsAtOpenInterestCap = 13,
    DisableDex = 14,
    SetPerpAnnotation = 15,
}

impl PdiActionKind {
    pub fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::RegisterAsset),
            1 => Some(Self::RegisterAsset2),
            2 => Some(Self::ProcessPerDexTimestep),
            3 => Some(Self::ToggleAsset),
            4 => Some(Self::UpdateMarginTable),
            5 => Some(Self::SetUserDexFlag),
            6 => Some(Self::ApplyAssetModeFlags),
            7 => Some(Self::ValidateMarginModeChanges),
            8 => Some(Self::SetFundingMultiplier),
            9 => Some(Self::SetFundingInterestRate),
            10 => Some(Self::SetStaleOracleAssets),
            11 => Some(Self::ApplyMarginModeChanges),
            12 => Some(Self::SetFeeScale),
            13 => Some(Self::AssetsAtOpenInterestCap),
            14 => Some(Self::DisableDex),
            15 => Some(Self::SetPerpAnnotation),
            _ => None,
        }
    }

    pub const fn authority_op(self) -> u8 {
        match self {
            Self::RegisterAsset | Self::RegisterAsset2 => 0,
            Self::ProcessPerDexTimestep => 1,
            Self::ToggleAsset => 4,
            Self::UpdateMarginTable => 2,
            Self::SetUserDexFlag => 3,
            Self::ApplyAssetModeFlags => 5,
            Self::ValidateMarginModeChanges => 6,
            Self::SetFundingMultiplier => 7,
            Self::SetFundingInterestRate => 11,
            Self::SetStaleOracleAssets => 14,
            Self::ApplyMarginModeChanges => 8,
            Self::SetFeeScale => 9,
            Self::AssetsAtOpenInterestCap => 10,
            Self::DisableDex => 12,
            Self::SetPerpAnnotation => 13,
        }
    }
}

#[derive(Clone, Debug)]
pub enum PdiAction {
    RegisterAsset { dex_name: String },
    RegisterAsset2 { dex_name: String },
    ProcessPerDexTimestep { dex_name: String },
    ToggleAsset { asset: String, enabled: bool },
    UpdateMarginTable { dex_name: String },
    SetUserDexFlag { dex_name: String, user: Address },
    ApplyAssetModeFlags { assets: Vec<String> },
    ValidateMarginModeChanges { assets: Vec<String> },
    SetFundingMultiplier { entries: BTreeMap<String, f64> },
    SetFundingInterestRate { entries: BTreeMap<String, f64> },
    SetStaleOracleAssets { dex_name: String, assets: Vec<String> },
    ApplyMarginModeChanges { assets: Vec<String> },
    SetFeeScale { dex_name: String, fee_scale: f64 },
    AssetsAtOpenInterestCap { assets: Vec<String> },
    DisableDex { dex_name: String },
    SetPerpAnnotation { asset: String, annotation: PerpAnnotation },
}

impl PdiAction {
    pub fn kind(&self) -> PdiActionKind {
        match self {
            Self::RegisterAsset { .. } => PdiActionKind::RegisterAsset,
            Self::RegisterAsset2 { .. } => PdiActionKind::RegisterAsset2,
            Self::ProcessPerDexTimestep { .. } => PdiActionKind::ProcessPerDexTimestep,
            Self::ToggleAsset { .. } => PdiActionKind::ToggleAsset,
            Self::UpdateMarginTable { .. } => PdiActionKind::UpdateMarginTable,
            Self::SetUserDexFlag { .. } => PdiActionKind::SetUserDexFlag,
            Self::ApplyAssetModeFlags { .. } => PdiActionKind::ApplyAssetModeFlags,
            Self::ValidateMarginModeChanges { .. } => PdiActionKind::ValidateMarginModeChanges,
            Self::SetFundingMultiplier { .. } => PdiActionKind::SetFundingMultiplier,
            Self::SetFundingInterestRate { .. } => PdiActionKind::SetFundingInterestRate,
            Self::SetStaleOracleAssets { .. } => PdiActionKind::SetStaleOracleAssets,
            Self::ApplyMarginModeChanges { .. } => PdiActionKind::ApplyMarginModeChanges,
            Self::SetFeeScale { .. } => PdiActionKind::SetFeeScale,
            Self::AssetsAtOpenInterestCap { .. } => PdiActionKind::AssetsAtOpenInterestCap,
            Self::DisableDex { .. } => PdiActionKind::DisableDex,
            Self::SetPerpAnnotation { .. } => PdiActionKind::SetPerpAnnotation,
        }
    }

    pub fn primary_dex_name(&self) -> Option<&str> {
        match self {
            Self::RegisterAsset { dex_name }
            | Self::RegisterAsset2 { dex_name }
            | Self::ProcessPerDexTimestep { dex_name }
            | Self::UpdateMarginTable { dex_name }
            | Self::SetUserDexFlag { dex_name, .. }
            | Self::SetStaleOracleAssets { dex_name, .. }
            | Self::SetFeeScale { dex_name, .. }
            | Self::DisableDex { dex_name } => Some(dex_name),
            Self::ToggleAsset { asset, .. } | Self::SetPerpAnnotation { asset, .. } => PdiAssetKey::parse(asset).ok().and_then(|key| key.dex_prefix),
            Self::ApplyAssetModeFlags { .. }
            | Self::ValidateMarginModeChanges { .. }
            | Self::SetFundingMultiplier { .. }
            | Self::SetFundingInterestRate { .. }
            | Self::ApplyMarginModeChanges { .. }
            | Self::AssetsAtOpenInterestCap { .. } => None,
        }
    }
}

pub trait PerpDexMutationSink {
    fn apply_pdi_action(&mut self, dex: DexId, action: PdiAction, resolved_assets: Vec<Pdi>) -> Result<(), PdiError>;
}

pub fn validate_perp_dex_action_authority(dex: &PerpDexEntry, op: u8, caller: Address) -> Result<(), PdiError> {
    if dex.status == DexStatus::Deleted {
        return Err(PdiError::Status(if op == PdiActionKind::DisableDex.authority_op() {
            PdiStatus::DisableUnauthorized
        } else {
            PdiStatus::Unauthorized
        }));
    }
    if caller == dex.authority.deployer || dex.authority.permissions.contains(&(op, caller)) {
        return Ok(());
    }
    Err(PdiError::Status(if op == PdiActionKind::DisableDex.authority_op() {
        PdiStatus::DisableUnauthorized
    } else {
        PdiStatus::Unauthorized
    }))
}

pub fn apply_fee_scale_update(
    dex: &mut PerpDexEntry,
    mode_tag: u8,
    now: NaiveDateTime12,
    fee_scale: f64,
) -> Result<(), PdiError> {
    if !(0.0..=3.0).contains(&fee_scale) {
        return Err(PdiError::Message { status: PdiStatus::InvalidFeeScale, message: "fee scale must be between 0 and 3".to_owned() });
    }
    if dex.status == DexStatus::Deleted {
        return Err(PdiError::Status(PdiStatus::DisableUnauthorized));
    }

    let cooldown_secs = if mode_tag == 3 { 60.0 } else { 2_592_000.0 };
    if let Some(next_allowed) = dex.last_fee_scale_update.checked_add_seconds_f64(cooldown_secs) {
        if now < next_allowed {
            return Err(PdiError::Message {
                status: PdiStatus::ExplicitMessage,
                message: "can only change fee scale once every 30.0 days".to_owned(),
            });
        }
    }

    if fee_scale > 1.0 && dex.assets.iter().any(|asset| !asset.growth_mode_allowed) {
        return Err(PdiError::Status(PdiStatus::FeeScaleGrowthModeBlocked));
    }

    if dex.fee_scale != fee_scale {
        dex.fee_scale = fee_scale;
        dex.last_fee_scale_update = now;
    }
    Ok(())
}

pub fn apply_perp_dex_action_adapter<S: PerpDexMutationSink>(
    registry: &mut PdiRegistry,
    sink: &mut S,
    caller: Address,
    mode_tag: u8,
    now: NaiveDateTime12,
    action: PdiAction,
) -> Result<(), PdiError> {
    let kind = action.kind();
    let op = kind.authority_op();

    let dex_id = resolve_action_dex_id(registry, &action)?;
    let dex = registry.dexes.iter().find(|dex| dex.dex_id == dex_id).ok_or(PdiError::Status(PdiStatus::UnknownDex))?;
    if dex.status != DexStatus::Active && dex.status != DexStatus::Deleted {
        return Err(PdiError::Status(PdiStatus::BadDexStatus));
    }
    validate_perp_dex_action_authority(dex, op, caller)?;

    match &action {
        PdiAction::SetFeeScale { dex_name, fee_scale } => {
            let dex = registry.find_by_dex_name_or_first_mut(dex_name)?;
            return apply_fee_scale_update(dex, mode_tag, now, *fee_scale);
        }
        PdiAction::DisableDex { dex_name } => {
            let dex = registry.find_by_dex_name_or_first_mut(dex_name)?;
            return match dex.status {
                DexStatus::Active | DexStatus::Disabling => {
                    if dex.assets.iter().any(|asset| !asset.is_halted) {
                        Err(PdiError::Message {
                            status: PdiStatus::ExplicitMessage,
                            message: "all assets must be halted before disabling dex".to_owned(),
                        })
                    } else {
                        dex.status = DexStatus::Disabling;
                        Ok(())
                    }
                }
                DexStatus::DisabledByValidators => Err(PdiError::Message {
                    status: PdiStatus::ExplicitMessage,
                    message: "already disabled by validators".to_owned(),
                }),
                DexStatus::Deleted => Err(PdiError::Status(PdiStatus::UnknownDex)),
            };
        }
        PdiAction::SetFundingMultiplier { entries } => {
            if entries.len() > MAX_PDI_RANGE_LEN {
                return Err(PdiError::Status(PdiStatus::Bounds));
            }
            for value in entries.values() {
                if !(0.0..=10.0).contains(value) {
                    return Err(PdiError::Message { status: PdiStatus::ExplicitMessage, message: "Invalid funding multiplier".to_owned() });
                }
            }
        }
        PdiAction::SetFundingInterestRate { entries } => {
            if entries.len() > MAX_PDI_RANGE_LEN {
                return Err(PdiError::Status(PdiStatus::Bounds));
            }
            for value in entries.values() {
                if value.abs() > 0.01 {
                    return Err(PdiError::Message { status: PdiStatus::ExplicitMessage, message: "Invalid funding interest rate".to_owned() });
                }
            }
        }
        PdiAction::SetPerpAnnotation { annotation, .. } => {
            if annotation.display_name.len() > MAX_ANNOTATION_NAME_BYTES
                || annotation.category.len() > MAX_ANNOTATION_NAME_BYTES
                || annotation.description.len() > MAX_ANNOTATION_TEXT_BYTES
            {
                return Err(PdiError::Status(PdiStatus::Bounds));
            }
        }
        _ => {}
    }

    let assets = resolve_action_assets(registry, &action)?;
    sink.apply_pdi_action(dex_id, action, assets)
}

fn resolve_action_dex_id(registry: &PdiRegistry, action: &PdiAction) -> Result<DexId, PdiError> {
    if let Some(dex_name) = action.primary_dex_name() {
        return Ok(registry.find_by_dex_name_or_first(dex_name)?.dex_id);
    }
    let keys = action_asset_keys(action);
    if keys.is_empty() {
        return Ok(registry.find_by_dex_name_or_first("")?.dex_id);
    }
    let (dex, _) = registry.resolve_asset_prefixes_same_dex(keys.iter().copied())?;
    Ok(dex)
}

fn resolve_action_assets(registry: &PdiRegistry, action: &PdiAction) -> Result<Vec<Pdi>, PdiError> {
    let keys = action_asset_keys(action);
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let (_, assets) = registry.resolve_asset_prefixes_same_dex(keys.iter().copied())?;
    Ok(assets)
}

fn action_asset_keys(action: &PdiAction) -> Vec<&str> {
    match action {
        PdiAction::ToggleAsset { asset, .. } | PdiAction::SetPerpAnnotation { asset, .. } => vec![asset.as_str()],
        PdiAction::ApplyAssetModeFlags { assets }
        | PdiAction::ValidateMarginModeChanges { assets }
        | PdiAction::SetStaleOracleAssets { assets, .. }
        | PdiAction::ApplyMarginModeChanges { assets }
        | PdiAction::AssetsAtOpenInterestCap { assets } => assets.iter().map(String::as_str).collect(),
        PdiAction::SetFundingMultiplier { entries } | PdiAction::SetFundingInterestRate { entries } => entries.keys().map(String::as_str).collect(),
        PdiAction::RegisterAsset { .. }
        | PdiAction::RegisterAsset2 { .. }
        | PdiAction::ProcessPerDexTimestep { .. }
        | PdiAction::UpdateMarginTable { .. }
        | PdiAction::SetUserDexFlag { .. }
        | PdiAction::SetFeeScale { .. }
        | PdiAction::DisableDex { .. } => Vec::new(),
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Pdi {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Pdi {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PdiVisitor;

        impl<'de> serde::de::Visitor<'de> for PdiVisitor {
            type Value = Pdi;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("tuple struct Pdi")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Pdi(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value < 0 {
                    return Err(E::custom("negative Pdi"));
                }
                Ok(Pdi(value as u64))
            }
        }

        deserializer.deserialize_newtype_struct("Pdi", PdiVisitor)
    }
}
