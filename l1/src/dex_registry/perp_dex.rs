use std::collections::{BTreeMap, BTreeSet};

pub const ENCODED_PERP_DEX_STRIDE: usize = 10_000;
pub const MAX_PERP_DEXS: usize = 2_000;
pub const MAX_PERP_ASSETS_PER_DEX: usize = 10_000;
pub const DEX_NAME_MIN_BYTES: usize = 2;
pub const DEX_NAME_MAX_BYTES: usize = 4;
pub const DEX_FULL_NAME_MAX_BYTES: usize = 50;
pub const DEX_FULL_NAME_RAW_CAP_BYTES: usize = 100;
pub const FUNDING_MULTIPLIER_MIN: f64 = 0.0;
pub const FUNDING_MULTIPLIER_MAX: f64 = 10.0;
pub const FUNDING_INTEREST_RATE_ABS_MAX: f64 = 0.01;
pub const PERP_DEX_FIELDS_WITHOUT_ANNOTATIONS: [&str; 3] = ["books", "funding_tracker", "twap_tracker"];
pub const PERP_DEX_FIELDS_WITH_ANNOTATIONS: [&str; 4] = [
    "books",
    "funding_tracker",
    "twap_tracker",
    "perp_to_annotation",
];
pub const PERP_ANNOTATION_FIELDS: [&str; 5] = [
    "last_update_time",
    "category",
    "description",
    "display_name",
    "keywords",
];


pub const RESERVED_CANONICAL_DEX_NAMES: [&str; 14] = [
    "nyse", "cme", "hl", "hyp", "hkex", "lse", "krx", "sgx", "cboe", "ice", "usd", "eth", "btc", "sol",
];

pub const MAINNET_PERP_AWS_NAMES: [AwsName; 18] = [
    AwsName::FBinPerp,
    AwsName::FBinPerp2,
    AwsName::FOkexPerp,
    AwsName::FHuobiPerp,
    AwsName::FHlPerp,
    AwsName::GaHlPerp,
    AwsName::GaHlPerp2,
    AwsName::GaHlPerp3,
    AwsName::GbHlPerp,
    AwsName::GbHlPerp2,
    AwsName::GbHlPerp3,
    AwsName::GcHlPerp,
    AwsName::GcHlPerp2,
    AwsName::GdHlPerp,
    AwsName::GdHlPerp2,
    AwsName::GsHlPerp,
    AwsName::EaHlPerp,
    AwsName::EbHlPerp,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwsName {
    FBinPerp,
    FBinPerp2,
    FOkexPerp,
    FHuobiPerp,
    FHlPerp,
    GaHlPerp,
    GaHlPerp2,
    GaHlPerp3,
    GbHlPerp,
    GbHlPerp2,
    GbHlPerp3,
    GcHlPerp,
    GcHlPerp2,
    GdHlPerp,
    GdHlPerp2,
    GsHlPerp,
    EaHlPerp,
    EbHlPerp,
}

impl AwsName {
    pub fn id(self) -> u8 {
        match self {
            AwsName::FBinPerp => 45,
            AwsName::FBinPerp2 => 46,
            AwsName::FOkexPerp => 49,
            AwsName::FHuobiPerp => 55,
            AwsName::FHlPerp => 62,
            AwsName::GaHlPerp => 63,
            AwsName::GaHlPerp2 => 64,
            AwsName::GaHlPerp3 => 65,
            AwsName::GbHlPerp => 66,
            AwsName::GbHlPerp2 => 67,
            AwsName::GbHlPerp3 => 68,
            AwsName::GcHlPerp => 69,
            AwsName::GcHlPerp2 => 70,
            AwsName::GdHlPerp => 71,
            AwsName::GdHlPerp2 => 72,
            AwsName::GsHlPerp => 73,
            AwsName::EaHlPerp => 74,
            AwsName::EbHlPerp => 75,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AwsName::FBinPerp => "FBinPerp",
            AwsName::FBinPerp2 => "FBinPerp2",
            AwsName::FOkexPerp => "FOkexPerp",
            AwsName::FHuobiPerp => "FHuobiPerp",
            AwsName::FHlPerp => "FHlPerp",
            AwsName::GaHlPerp => "GaHlPerp",
            AwsName::GaHlPerp2 => "GaHlPerp2",
            AwsName::GaHlPerp3 => "GaHlPerp3",
            AwsName::GbHlPerp => "GbHlPerp",
            AwsName::GbHlPerp2 => "GbHlPerp2",
            AwsName::GbHlPerp3 => "GbHlPerp3",
            AwsName::GcHlPerp => "GcHlPerp",
            AwsName::GcHlPerp2 => "GcHlPerp2",
            AwsName::GdHlPerp => "GdHlPerp",
            AwsName::GdHlPerp2 => "GdHlPerp2",
            AwsName::GsHlPerp => "GsHlPerp",
            AwsName::EaHlPerp => "EaHlPerp",
            AwsName::EbHlPerp => "EbHlPerp",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Address(pub [u8; 20]);

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct RecoveredTime {
    pub day: u32,
    pub seconds: u32,
    pub subsecond: u32,
}

impl RecoveredTime {
    #[inline]
    pub fn seconds_since_epoch_day_zero(self) -> u64 {
        u64::from(self.day) * 86_400 + u64::from(self.seconds)
    }

    #[inline]
    pub fn is_at_least_one_day_after(self, older: Self) -> bool {
        self.seconds_since_epoch_day_zero() >= older.seconds_since_epoch_day_zero().saturating_add(86_400)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerpAssetId(pub usize);

impl PerpAssetId {
    #[inline]
    pub fn dex_index(self) -> usize {
        self.0 / ENCODED_PERP_DEX_STRIDE
    }

    #[inline]
    pub fn local_index(self) -> usize {
        self.0 % ENCODED_PERP_DEX_STRIDE
    }

    #[inline]
    pub fn from_parts(dex_index: usize, local_index: usize) -> Self {
        Self(dex_index * ENCODED_PERP_DEX_STRIDE + local_index)
    }

    #[inline]
    pub fn api_asset_id(self) -> i64 {
        if self.0 <= 9_999 {
            self.0 as i64
        } else if self.0 <= 99_899_999 {
            (self.0 + 100_000) as i64
        } else {
            -1
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Books {
    pub assets_with_live_books: BTreeSet<usize>,
}

#[derive(Clone, Debug, Default)]
pub struct FundingTracker {
    pub last_sample_time: RecoveredTime,
}

#[derive(Clone, Debug, Default)]
pub struct TwapTracker {
    pub pending_order_count: usize,
}

#[derive(Clone, Debug)]
pub struct PerpDex {
    pub books: Books,
    pub funding_tracker: FundingTracker,
    pub twap_tracker: TwapTracker,
    pub perp_to_annotation: BTreeMap<usize, PerpAnnotation>,
}

impl PerpDex {
    pub fn empty() -> Self {
        Self {
            books: Books::default(),
            funding_tracker: FundingTracker::default(),
            twap_tracker: TwapTracker::default(),
            perp_to_annotation: BTreeMap::new(),
        }
    }

    #[inline]
    pub fn annotation(&self, asset: PerpAssetId) -> Option<&PerpAnnotation> {
        self.perp_to_annotation.get(&asset.0)
    }
    #[inline]
    pub fn recovered_serde_fields(&self) -> &'static [&'static str] {
        if self.perp_to_annotation.is_empty() {
            &PERP_DEX_FIELDS_WITHOUT_ANNOTATIONS
        } else {
            &PERP_DEX_FIELDS_WITH_ANNOTATIONS
        }
    }


    pub fn set_annotation(
        &mut self,
        asset: PerpAssetId,
        now: RecoveredTime,
        category: String,
        description: String,
        display_name: Option<String>,
        keywords: Vec<String>,
    ) -> Result<(), PerpDexError> {
        if let Some(existing) = self.perp_to_annotation.get(&asset.0) {
            if !now.is_at_least_one_day_after(existing.last_update_time) {
                return Err(PerpDexError::Message("can only change perp annotation once per day"));
            }
        }

        self.perp_to_annotation.insert(
            asset.0,
            PerpAnnotation {
                last_update_time: now,
                category,
                description,
                display_name,
                keywords,
            },
        );
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct PerpAnnotation {
    pub last_update_time: RecoveredTime,
    pub category: String,
    pub description: String,
    pub display_name: Option<String>,
    pub keywords: Vec<String>,
}
impl PerpAnnotation {
    #[inline]
    pub fn recovered_serde_fields() -> &'static [&'static str] {
        &PERP_ANNOTATION_FIELDS
    }
}

#[derive(Clone, Debug, Default)]
pub struct PerpDexs(pub Vec<PerpDexRecord>);

impl PerpDexs {
    #[inline]
    pub fn active(&self) -> impl Iterator<Item = (usize, &PerpDexRecord)> {
        self.0.iter().enumerate().filter(|(_, record)| record.status != DexStatus::Deleted)
    }

    pub fn find_by_name_or_first(&self, name: &str) -> Result<(usize, &PerpDexRecord), PerpDexError> {
        if name.is_empty() {
            return self.active().next().ok_or(PerpDexError::InvalidPerpDex);
        }

        self.active()
            .find(|(_, record)| record.name == name)
            .ok_or(PerpDexError::InvalidPerpDex)
    }
}

#[derive(Clone, Debug)]
pub struct PerpDexRecord {
    pub name: String,
    pub full_name: String,
    pub deployer: Address,
    pub collateral_asset: usize,
    pub fee_recipient: Option<Address>,
    pub status: DexStatus,
    pub dex: PerpDex,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DexStatus {
    Active,
    Locked,
    Disabled,
    Deleted,
}

#[derive(Clone, Debug, Default)]
pub struct PerpAssetInfo {
    pub assets: Vec<PerpAssetMeta>,
    pub hl_only_perps: BTreeSet<usize>,
    pub perp_to_funding_multiplier: BTreeMap<usize, f64>,
    pub perp_to_funding_interest_rate: BTreeMap<usize, f64>,
    pub oi_sz_cap_per_perp: BTreeMap<usize, f64>,
    pub perp_to_annotation: BTreeMap<usize, PerpAnnotation>,
}

impl PerpAssetInfo {
    #[inline]
    pub fn get(&self, local_asset: usize) -> Result<&PerpAssetMeta, PerpDexError> {
        self.assets.get(local_asset).ok_or(PerpDexError::InvalidPerpDex)
    }

    #[inline]
    pub fn get_mut(&mut self, local_asset: usize) -> Result<&mut PerpAssetMeta, PerpDexError> {
        self.assets.get_mut(local_asset).ok_or(PerpDexError::InvalidPerpDex)
    }

    pub fn push_asset(&mut self, asset: PerpAssetMeta) -> Result<usize, PerpDexError> {
        if self.assets.len() >= MAX_PERP_ASSETS_PER_DEX {
            return Err(PerpDexError::PerpAssetIndexOverflow);
        }
        let local_index = self.assets.len();
        self.assets.push(asset);
        Ok(local_index)
    }
}

#[derive(Clone, Debug)]
pub struct PerpAssetMeta {
    pub name: String,
    pub sz_decimals: u8,
    pub max_leverage: u32,
    pub only_isolated: bool,
    pub margin_table_id: u32,
    pub deployer: Address,
}

#[derive(Clone, Debug)]
pub struct PerpAssetView {
    pub encoded_asset: PerpAssetId,
    pub dex_name: String,
    pub meta: PerpAssetMeta,
    pub funding_multiplier: Option<f64>,
    pub funding_interest_rate: Option<f64>,
    pub oi_sz_cap: Option<f64>,
}

#[derive(Clone, Debug, Default)]
pub struct DexRegistry {
    pub perp_dexs: PerpDexs,
    pub perp_asset_infos: Vec<PerpAssetInfo>,
    pub allowed_collateral_assets: BTreeSet<usize>,
}

impl DexRegistry {
    pub fn validate_new_dex(
        &self,
        deployer: Address,
        name: &str,
        full_name: &str,
        collateral_asset: usize,
    ) -> Result<(), PerpDexError> {
        if self.perp_dexs.0.len() >= MAX_PERP_DEXS {
            return Err(PerpDexError::Message("too many perp DEXs"));
        }

        if self.perp_dexs.active().any(|(_, record)| record.deployer == deployer) {
            return Err(PerpDexError::Message("can deploy at most one DEX"));
        }

        if full_name.len() > DEX_FULL_NAME_RAW_CAP_BYTES {
            return Err(PerpDexError::FullNameTooLong);
        }

        if !self.allowed_collateral_assets.contains(&collateral_asset) {
            return Err(PerpDexError::Message("Collateral asset not supported"));
        }

        validate_dex_name(name)?;
        validate_full_name(full_name)?;

        if self.perp_dexs.active().any(|(_, record)| record.name == name) || name == "spot" {
            return Err(PerpDexError::Message("duplicate perp DEX name"));
        }

        if self.perp_asset_infos.len() != self.perp_dexs.0.len() {
            return Err(PerpDexError::Message("unexpected"));
        }

        Ok(())
    }

    pub fn deploy_perp_dex(
        &mut self,
        deployer: Address,
        name: String,
        full_name: String,
        collateral_asset: usize,
        fee_recipient: Option<Address>,
    ) -> Result<usize, PerpDexError> {
        self.validate_new_dex(deployer, &name, &full_name, collateral_asset)?;
        let index = self.perp_dexs.0.len();
        self.perp_asset_infos.push(PerpAssetInfo::default());
        self.perp_dexs.0.push(PerpDexRecord {
            name,
            full_name,
            deployer,
            collateral_asset,
            fee_recipient,
            status: DexStatus::Active,
            dex: PerpDex::empty(),
        });
        Ok(index)
    }

    pub fn drop_last_if_empty(&mut self, dex_index: usize) -> Result<bool, PerpDexError> {
        let is_last_dex = dex_index + 1 == self.perp_dexs.0.len();
        let is_last_asset_info = dex_index + 1 == self.perp_asset_infos.len();
        if !is_last_dex || !is_last_asset_info {
            return Ok(false);
        }

        let record = self.perp_dexs.0.get(dex_index).ok_or(PerpDexError::InvalidPerpDex)?;
        let asset_info = self.perp_asset_infos.get(dex_index).ok_or(PerpDexError::InvalidPerpDex)?;
        if record.dex.books.assets_with_live_books.is_empty() && asset_info.assets.is_empty() {
            self.perp_dexs.0.pop();
            self.perp_asset_infos.pop();
            return Ok(true);
        }
        Ok(false)
    }

    pub fn dex_record(&self, dex_index: usize) -> Result<&PerpDexRecord, PerpDexError> {
        self.perp_dexs.0.get(dex_index).ok_or(PerpDexError::InvalidPerpDex)
    }

    pub fn dex_record_mut(&mut self, dex_index: usize) -> Result<&mut PerpDexRecord, PerpDexError> {
        self.perp_dexs.0.get_mut(dex_index).ok_or(PerpDexError::InvalidPerpDex)
    }

    pub fn asset_info(&self, dex_index: usize) -> Result<&PerpAssetInfo, PerpDexError> {
        self.perp_asset_infos.get(dex_index).ok_or(PerpDexError::InvalidPerpDex)
    }

    pub fn asset_info_mut(&mut self, dex_index: usize) -> Result<&mut PerpAssetInfo, PerpDexError> {
        self.perp_asset_infos.get_mut(dex_index).ok_or(PerpDexError::InvalidPerpDex)
    }

    pub fn asset_meta_by_encoded_asset(&self, asset: PerpAssetId) -> Result<&PerpAssetMeta, PerpDexError> {
        let dex_index = asset.dex_index();
        let local_index = asset.local_index();
        self.asset_info(dex_index)?.get(local_index)
    }

    pub fn perp_annotation_for_asset(&self, asset: PerpAssetId) -> Result<Option<&PerpAnnotation>, PerpDexError> {
        let dex_index = asset.dex_index();
        let local_index = asset.local_index();
        let info = self.asset_info(dex_index)?;
        if local_index >= info.assets.len() {
            return Err(PerpDexError::InvalidPerpDex);
        }
        Ok(info.perp_to_annotation.get(&asset.0).or_else(|| {
            self.perp_dexs.0.get(dex_index).and_then(|record| record.dex.perp_to_annotation.get(&asset.0))
        }))
    }

    pub fn validate_add_perp_asset(
        &self,
        dex_index: usize,
        request: &PerpAssetDeployRequest,
    ) -> Result<(), PerpDexError> {
        let dex = self.dex_record(dex_index)?;
        if dex.status == DexStatus::Deleted {
            return Err(PerpDexError::InvalidPerpDex);
        }

        let info = self.asset_info(dex_index)?;
        if info.assets.len() >= MAX_PERP_ASSETS_PER_DEX {
            return Err(PerpDexError::Message("Too many assets in perp dex"));
        }
        if request.cross_margin && !request.only_isolated {
            return Err(PerpDexError::Message("cross margin not supported"));
        }
        if request.name.len() > DEX_FULL_NAME_RAW_CAP_BYTES {
            return Err(PerpDexError::FullNameTooLong);
        }
        if !request.name.starts_with(&dex.name) {
            return Err(PerpDexError::InvalidPerpDex);
        }

        let suffix = &request.name[dex.name.len()..];
        if suffix.is_empty() || suffix.len() >= 10 {
            return Err(PerpDexError::Message("asset name suffix must be between 1 and 9 characters"));
        }
        if !suffix.bytes().all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit()) {
            return Err(PerpDexError::Message("asset name only accepts upper case characters and digits"));
        }

        Ok(())
    }

    pub fn add_perp_asset(
        &mut self,
        dex_index: usize,
        request: PerpAssetDeployRequest,
    ) -> Result<PerpAssetId, PerpDexError> {
        self.validate_add_perp_asset(dex_index, &request)?;
        let meta = PerpAssetMeta {
            name: request.name,
            sz_decimals: request.sz_decimals,
            max_leverage: request.max_leverage,
            only_isolated: request.only_isolated,
            margin_table_id: request.margin_table_id,
            deployer: request.deployer,
        };
        let local_index = self.asset_info_mut(dex_index)?.push_asset(meta)?;
        Ok(PerpAssetId::from_parts(dex_index, local_index))
    }

    pub fn sorted_perp_asset_infos_for_dex(&self, dex_index: usize, limit: usize) -> Result<Vec<PerpAssetView>, PerpDexError> {
        let record = self.dex_record(dex_index)?;
        let info = self.asset_info(dex_index)?;
        let take = if limit == 0 { usize::MAX } else { limit };
        let mut out = Vec::new();
        for (local_index, meta) in info.assets.iter().enumerate().take(take) {
            out.push(PerpAssetView {
                encoded_asset: PerpAssetId::from_parts(dex_index, local_index),
                dex_name: record.name.clone(),
                meta: meta.clone(),
                funding_multiplier: info.perp_to_funding_multiplier.get(&local_index).copied(),
                funding_interest_rate: info.perp_to_funding_interest_rate.get(&local_index).copied(),
                oi_sz_cap: info.oi_sz_cap_per_perp.get(&local_index).copied(),
            });
        }
        out.reverse();
        Ok(out)
    }

    pub fn set_funding_multiplier(&mut self, asset: PerpAssetId, value: f64) -> Result<(), PerpDexError> {
        if !(FUNDING_MULTIPLIER_MIN..=FUNDING_MULTIPLIER_MAX).contains(&value) {
            return Err(PerpDexError::Message("Invalid funding multiplier"));
        }
        self.asset_meta_by_encoded_asset(asset)?;
        self.asset_info_mut(asset.dex_index())?
            .perp_to_funding_multiplier
            .insert(asset.local_index(), value);
        Ok(())
    }

    pub fn set_funding_interest_rate(&mut self, asset: PerpAssetId, value: f64) -> Result<(), PerpDexError> {
        if value.abs() > FUNDING_INTEREST_RATE_ABS_MAX {
            return Err(PerpDexError::Message("Invalid funding interest rate"));
        }
        self.asset_meta_by_encoded_asset(asset)?;
        self.asset_info_mut(asset.dex_index())?
            .perp_to_funding_interest_rate
            .insert(asset.local_index(), value);
        Ok(())
    }

    pub fn set_perp_annotation(
        &mut self,
        asset: PerpAssetId,
        now: RecoveredTime,
        category: String,
        description: String,
        display_name: Option<String>,
        keywords: Vec<String>,
    ) -> Result<(), PerpDexError> {
        self.asset_meta_by_encoded_asset(asset)?;
        let info = self.asset_info_mut(asset.dex_index())?;
        if let Some(existing) = info.perp_to_annotation.get(&asset.0) {
            if !now.is_at_least_one_day_after(existing.last_update_time) {
                return Err(PerpDexError::Message("can only change perp annotation once per day"));
            }
        }
        info.perp_to_annotation.insert(
            asset.0,
            PerpAnnotation {
                last_update_time: now,
                category,
                description,
                display_name,
                keywords,
            },
        );
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct PerpAssetDeployRequest {
    pub name: String,
    pub sz_decimals: u8,
    pub max_leverage: u32,
    pub margin_table_id: u32,
    pub only_isolated: bool,
    pub cross_margin: bool,
    pub deployer: Address,
}

pub fn validate_dex_name(name: &str) -> Result<(), PerpDexError> {
    if !(DEX_NAME_MIN_BYTES..=DEX_NAME_MAX_BYTES).contains(&name.len()) {
        return Err(PerpDexError::DexNameLength);
    }
    if RESERVED_CANONICAL_DEX_NAMES.contains(&name) {
        return Err(PerpDexError::Message("cannot use canonical name"));
    }
    if has_non_lower_ascii(name) {
        return Err(PerpDexError::Message("dex name only accepts lower case characters"));
    }
    Ok(())
}

pub fn validate_full_name(full_name: &str) -> Result<(), PerpDexError> {
    if full_name.is_empty() || full_name.len() > DEX_FULL_NAME_MAX_BYTES {
        return Err(PerpDexError::FullNameTooLong);
    }
    Ok(())
}

#[inline]
pub fn has_non_lower_ascii(input: &str) -> bool {
    input.chars().any(|ch| !matches!(ch, 'a'..='z'))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PerpDexError {
    Message(&'static str),
    InvalidPerpDex,
    PerpAssetIndexOverflow,
    DexNameLength,
    FullNameTooLong,
    UnsupportedCollateral,
    InvalidFeeRecipient,
}

impl PerpDexError {
    pub fn code(self) -> u16 {
        match self {
            PerpDexError::Message(_) => 224,
            PerpDexError::PerpAssetIndexOverflow => 320,
            PerpDexError::InvalidPerpDex => 321,
            PerpDexError::FullNameTooLong => 323,
            PerpDexError::UnsupportedCollateral => 234,
            PerpDexError::InvalidFeeRecipient => 355,
            PerpDexError::DexNameLength => 224,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            PerpDexError::Message(message) => message,
            PerpDexError::InvalidPerpDex => "Invalid perp DEX",
            PerpDexError::PerpAssetIndexOverflow => "Too many assets in perp dex",
            PerpDexError::DexNameLength => "Perp DEX name must be between 2 and 4 characters long",
            PerpDexError::FullNameTooLong => "Perp DEX full name can be at most 50 characters long",
            PerpDexError::UnsupportedCollateral => "Collateral asset not supported",
            PerpDexError::InvalidFeeRecipient => "Invalid perp DEX fee recipient",
        }
    }
}
