use core::fmt;
use std::collections::BTreeSet;

use super::perp_dex::{Dex, PerpDex};

pub type DexId = usize;
pub type GlobalAssetId = u64;
pub type LocalAssetId = usize;
pub type SpotUniverseId = usize;

pub const PERP_ASSET_STRIDE: GlobalAssetId = 10_000;
pub const LEGACY_SPOT_WIRE_OFFSET: u32 = 10_000;
pub const NON_MAIN_PERP_WIRE_OFFSET: u32 = 100_000;
pub const EXTENDED_SPOT_WIRE_OFFSET: u64 = 100_000_000;
pub const MAX_PERP_DEXS: usize = 2_000;
pub const MAX_PERP_DEX_NAME_LEN: usize = 4;
pub const MIN_PERP_DEX_NAME_LEN: usize = 2;
pub const MAX_PERP_DEX_FULL_NAME_LEN: usize = 50;

const RESERVED_PERP_DEX_NAMES: &[&str] = &[
    "nyse", "cme", "hl", "hyp", "hkex", "lse", "krx", "sgx", "cboe", "ice", "usd", "eth", "btc",
    "sol",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryError {
    UnknownDex,
    InvalidPerpAsset { normalized: GlobalAssetId },
    UnknownSpotAsset,
    CrossDexDisabled,
    CrossDexRoutingDenied,
    TooManyPerpDexs,
    CollateralAssetNotSupported,
    NameLength,
    NameNotLowercaseAscii,
    FullNameTooLong,
    CanonicalName,
    DuplicateName,
    DeployLimit,
    UnexpectedRegistryShape,
}

impl RegistryError {
    pub const fn code(self) -> u16 {
        match self {
            Self::UnknownDex => 321,
            Self::InvalidPerpAsset { .. } => 96,
            Self::UnknownSpotAsset => 383,
            Self::CrossDexDisabled => 249,
            Self::CrossDexRoutingDenied => 368,
            Self::CollateralAssetNotSupported => 234,
            Self::TooManyPerpDexs
            | Self::NameLength
            | Self::NameNotLowercaseAscii
            | Self::FullNameTooLong
            | Self::CanonicalName
            | Self::DuplicateName
            | Self::DeployLimit
            | Self::UnexpectedRegistryShape => 224,
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::UnknownDex => "unknown DEX",
            Self::InvalidPerpAsset { .. } => "invalid perp asset",
            Self::UnknownSpotAsset => "unknown spot asset",
            Self::CrossDexDisabled => "cross-DEX routing disabled",
            Self::CrossDexRoutingDenied => "cross-DEX routing denied",
            Self::TooManyPerpDexs => "too many perp DEXs",
            Self::CollateralAssetNotSupported => "Collateral asset not supported",
            Self::NameLength => "Perp DEX name must be between 2 and 4 characters long",
            Self::NameNotLowercaseAscii => "Perp DEX name only accepts lower case characters",
            Self::FullNameTooLong => "Perp DEX full name can be at most 50 characters long",
            Self::CanonicalName => "cannot use canonical name",
            Self::DuplicateName => "duplicate perp DEX name",
            Self::DeployLimit => "can deploy at most one DEX",
            Self::UnexpectedRegistryShape => "unexpected",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClearinghouseStatus {
    Active,
    Paused,
    Closing,
    Removed,
    Unknown(u8),
}

impl ClearinghouseStatus {
    pub const fn from_byte(value: u8) -> Self {
        match value {
            0 => Self::Active,
            1 => Self::Paused,
            2 => Self::Closing,
            3 => Self::Removed,
            other => Self::Unknown(other),
        }
    }

    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::Paused => 1,
            Self::Closing => 2,
            Self::Removed => 3,
            Self::Unknown(value) => value,
        }
    }

    pub const fn participates_in_lookup(self) -> bool {
        !matches!(self, Self::Removed)
    }
}

#[derive(Clone, Debug, Default)]
pub struct PerDexAux {
    pub asset_states: Vec<PerAssetState>,
    pub pending_assets: Vec<GlobalAssetId>,
    pub empty_marker: usize,
}

impl PerDexAux {
    pub fn is_empty(&self) -> bool {
        self.asset_states.is_empty() && self.pending_assets.is_empty() && self.empty_marker == 0
    }
}

#[derive(Clone, Debug, Default)]
pub struct PerAssetState {
    pub open_interest: u64,
    pub max_leverage: u32,
    pub flags: u8,
}

#[derive(Clone, Debug)]
pub struct Clearinghouse {
    pub dex_id: DexId,
    pub dex: PerpDex,
    pub asset_count: usize,
    pub settlement_asset: GlobalAssetId,
    pub status: ClearinghouseStatus,
    pub empty_trailing_state: usize,
}

impl Clearinghouse {
    pub fn name(&self) -> &str {
        self.dex.name.as_str()
    }

    pub fn full_name(&self) -> &str {
        self.dex.full_name.as_str()
    }

    pub fn is_active_for_lookup(&self) -> bool {
        self.status.participates_in_lookup()
    }

    pub fn has_local_asset(&self, local: LocalAssetId) -> bool {
        local < self.asset_count
    }

    pub fn global_asset_id(&self, local: LocalAssetId) -> GlobalAssetId {
        self.dex_id as GlobalAssetId * PERP_ASSET_STRIDE + local as GlobalAssetId
    }

    pub fn is_empty(&self) -> bool {
        self.asset_count == 0 && self.empty_trailing_state == 0
    }
}

#[derive(Clone, Default)]
pub struct Clearinghouses(pub Vec<PerDexAux>, pub Vec<Clearinghouse>);

impl fmt::Debug for Clearinghouses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Clearinghouses").field(&self.0).field(&self.1).finish()
    }
}

impl Clearinghouses {
    pub fn new(aux: Vec<PerDexAux>, clearinghouses: Vec<Clearinghouse>) -> Self {
        Self(aux, clearinghouses)
    }

    pub fn len(&self) -> usize {
        self.1.len()
    }

    pub fn is_empty(&self) -> bool {
        self.1.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Clearinghouse> {
        self.1.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Clearinghouse> {
        self.1.iter_mut()
    }

    pub fn get(&self, dex_id: DexId) -> Option<&Clearinghouse> {
        self.1.get(dex_id)
    }

    pub fn get_mut(&mut self, dex_id: DexId) -> Option<&mut Clearinghouse> {
        self.1.get_mut(dex_id)
    }

    pub fn index(&self, dex_id: DexId) -> &Clearinghouse {
        self.get(dex_id).expect("called `Result::unwrap()` on an `Err` value")
    }

    pub fn index_mut(&mut self, dex_id: DexId) -> &mut Clearinghouse {
        self.get_mut(dex_id).expect("called `Result::unwrap()` on an `Err` value")
    }

    pub fn aux(&self, dex_id: DexId) -> &PerDexAux {
        self.0.get(dex_id).expect("called `Result::unwrap()` on an `Err` value")
    }

    pub fn find_by_dex_name_or_first(&self, name: &str) -> Result<&Clearinghouse, RegistryError> {
        if name.is_empty() {
            return Ok(self.1.first().expect("called `Result::unwrap()` on an `Err` value"));
        }

        self.1
            .iter()
            .find(|clearinghouse| clearinghouse.is_active_for_lookup() && clearinghouse.name().as_bytes() == name.as_bytes())
            .ok_or(RegistryError::UnknownDex)
    }

    pub fn find_by_dex_name_or_first_mut(&mut self, name: &str) -> Result<&mut Clearinghouse, RegistryError> {
        if name.is_empty() {
            return Ok(self.1.first_mut().expect("called `Result::unwrap()` on an `Err` value"));
        }

        self.1
            .iter_mut()
            .find(|clearinghouse| clearinghouse.is_active_for_lookup() && clearinghouse.name().as_bytes() == name.as_bytes())
            .ok_or(RegistryError::UnknownDex)
    }

    pub fn find_by_asset_prefix(&self, asset: &str) -> Result<&Clearinghouse, RegistryError> {
        self.find_by_dex_name_or_first(first_colon_prefix(asset))
    }

    pub fn find_by_asset_prefix_mut(&mut self, asset: &str) -> Result<&mut Clearinghouse, RegistryError> {
        self.find_by_dex_name_or_first_mut(first_colon_prefix(asset))
    }

    pub fn dex_name_to_optional_index(&self, name: &str) -> Result<Option<DexId>, RegistryError> {
        if name == "spot" {
            return Ok(None);
        }
        Ok(Some(self.find_by_dex_name_or_first(name)?.dex_id))
    }

    pub fn resolve_asset_name<'a, R>(
        &'a self,
        resolver: &R,
        asset_name: &'a str,
    ) -> Result<R::Output, RegistryError>
    where
        R: AssetNameResolver<'a>,
    {
        let clearinghouse = self.find_by_asset_prefix(asset_name)?;
        resolver.resolve_in_clearinghouse(asset_name, clearinghouse)
    }

    pub fn get_by_global_asset(&self, global_asset: GlobalAssetId) -> &Clearinghouse {
        self.index(dex_id_from_global_asset(global_asset))
    }

    pub fn validate_global_perp_asset(&self, global_asset: GlobalAssetId) -> Result<(DexId, LocalAssetId), RegistryError> {
        let dex_id = dex_id_from_global_asset(global_asset);
        let local = local_asset_from_global_asset(global_asset);
        let clearinghouse = self.get(dex_id).ok_or(RegistryError::InvalidPerpAsset {
            normalized: global_asset,
        })?;
        if clearinghouse.has_local_asset(local) {
            Ok((dex_id, local))
        } else {
            Err(RegistryError::InvalidPerpAsset {
                normalized: global_asset,
            })
        }
    }

    pub fn drop_last_if_empty(&mut self, dex_id: DexId) {
        if dex_id + 1 != self.0.len() || dex_id + 1 != self.1.len() {
            return;
        }
        if !self.0[dex_id].is_empty() || !self.1[dex_id].is_empty() {
            return;
        }
        self.0.pop();
        self.1.pop();
    }

    pub fn try_deploy_perp_dex(
        &mut self,
        request: DeployPerpDexRequest,
        supported_collateral_assets: &BTreeSet<u32>,
    ) -> Result<DexId, RegistryError> {
        if self.0.len() > MAX_PERP_DEXS - 1 {
            return Err(RegistryError::TooManyPerpDexs);
        }
        if self.0.len() != self.1.len() {
            return Err(RegistryError::UnexpectedRegistryShape);
        }
        if !supported_collateral_assets.contains(&request.collateral_asset) {
            return Err(RegistryError::CollateralAssetNotSupported);
        }
        if self
            .1
            .iter()
            .any(|clearinghouse| clearinghouse.is_active_for_lookup() && clearinghouse.dex.deployer == Some(request.deployer))
        {
            return Err(RegistryError::DeployLimit);
        }

        validate_perp_dex_name(request.name.as_str())?;
        validate_perp_dex_full_name(request.full_name.as_str())?;
        if self.find_by_dex_name_or_first(request.name.as_str()).is_ok() || request.name.as_str() == "spot" {
            return Err(RegistryError::DuplicateName);
        }

        let dex_id = self.0.len();
        self.0.push(PerDexAux::default());
        self.1.push(Clearinghouse {
            dex_id,
            dex: PerpDex {
                name: request.name,
                full_name: request.full_name,
                deployer: Some(request.deployer),
                oracle_pxs: Default::default(),
            },
            asset_count: 0,
            settlement_asset: 0,
            status: ClearinghouseStatus::Active,
            empty_trailing_state: 0,
        });
        Ok(dex_id)
    }
}

#[derive(Clone, Debug)]
pub struct DeployPerpDexRequest {
    pub name: Dex,
    pub full_name: String,
    pub deployer: Address,
    pub collateral_asset: u32,
}

pub type Address = [u8; 20];

pub trait AssetNameResolver<'a> {
    type Output;

    fn resolve_in_clearinghouse(
        &self,
        full_asset_name: &'a str,
        clearinghouse: &'a Clearinghouse,
    ) -> Result<Self::Output, RegistryError>;
}

pub fn validate_perp_dex_name(name: &str) -> Result<(), RegistryError> {
    if !(MIN_PERP_DEX_NAME_LEN..=MAX_PERP_DEX_NAME_LEN).contains(&name.len()) {
        return Err(RegistryError::NameLength);
    }
    if RESERVED_PERP_DEX_NAMES.iter().any(|reserved| name == *reserved) {
        return Err(RegistryError::CanonicalName);
    }
    if name.bytes().any(|byte| !byte.is_ascii_lowercase()) {
        return Err(RegistryError::NameNotLowercaseAscii);
    }
    Ok(())
}

pub fn validate_perp_dex_full_name(full_name: &str) -> Result<(), RegistryError> {
    if full_name.len() > MAX_PERP_DEX_FULL_NAME_LEN {
        return Err(RegistryError::FullNameTooLong);
    }
    Ok(())
}

pub const fn dex_id_from_global_asset(asset: GlobalAssetId) -> DexId {
    (asset / PERP_ASSET_STRIDE) as DexId
}

pub const fn local_asset_from_global_asset(asset: GlobalAssetId) -> LocalAssetId {
    (asset % PERP_ASSET_STRIDE) as LocalAssetId
}

pub const fn global_asset_id(dex_id: DexId, local_asset: LocalAssetId) -> GlobalAssetId {
    dex_id as GlobalAssetId * PERP_ASSET_STRIDE + local_asset as GlobalAssetId
}

fn first_colon_prefix(value: &str) -> &str {
    match value.as_bytes().iter().position(|byte| *byte == b':') {
        Some(index) => &value[..index],
        None => "",
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutedAsset {
    Perp {
        global_asset: GlobalAssetId,
        dex_id: DexId,
        local_asset: LocalAssetId,
    },
    Spot {
        spot_universe_id: SpotUniverseId,
    },
}

pub trait SpotAssetCodec {
    fn decode_spot_wire_id_exact(&self, raw: u64) -> Option<SpotUniverseId>;
    fn encode_spot_wire_id(&self, spot_universe_id: SpotUniverseId) -> Option<u64>;
}

pub fn classify_wire_asset_id<S: SpotAssetCodec>(
    raw: u32,
    clearinghouses: &Clearinghouses,
    spot_codec: &S,
) -> Result<RoutedAsset, RegistryError> {
    let raw64 = raw as u64;
    if raw <= 99_999_999 {
        if raw >= LEGACY_SPOT_WIRE_OFFSET && raw < 110_000 {
            let normalized_spot = raw64 - LEGACY_SPOT_WIRE_OFFSET as u64;
            return spot_codec
                .decode_spot_wire_id_exact(normalized_spot)
                .map(|spot_universe_id| RoutedAsset::Spot { spot_universe_id })
                .ok_or(RegistryError::UnknownSpotAsset);
        }

        let normalized = if raw >= 110_000 {
            raw64 - NON_MAIN_PERP_WIRE_OFFSET as u64
        } else {
            raw64
        };
        let (dex_id, local_asset) = clearinghouses.validate_global_perp_asset(normalized)?;
        return Ok(RoutedAsset::Perp {
            global_asset: normalized,
            dex_id,
            local_asset,
        });
    }

    spot_codec
        .decode_spot_wire_id_exact(raw64)
        .map(|spot_universe_id| RoutedAsset::Spot { spot_universe_id })
        .ok_or(RegistryError::UnknownSpotAsset)
}

pub fn encode_wire_asset_id<S: SpotAssetCodec>(asset: RoutedAsset, spot_codec: &S) -> Option<u32> {
    match asset {
        RoutedAsset::Perp { global_asset, .. } => {
            let raw = if global_asset < PERP_ASSET_STRIDE {
                global_asset
            } else {
                global_asset.checked_add(NON_MAIN_PERP_WIRE_OFFSET as u64)?
            };
            (raw <= 99_999_999).then_some(raw as u32)
        }
        RoutedAsset::Spot { spot_universe_id } => {
            let encoded = spot_codec.encode_spot_wire_id(spot_universe_id)?;
            let raw = if encoded < EXTENDED_SPOT_WIRE_OFFSET {
                encoded.checked_add(LEGACY_SPOT_WIRE_OFFSET as u64)?
            } else {
                encoded
            };
            u32::try_from(raw).ok()
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClearinghouseSide {
    Primary,
    Secondary,
}

#[derive(Clone, Debug)]
pub struct RegistrySet {
    pub side: ClearinghouseSide,
    pub clearinghouses: Clearinghouses,
    pub cross_dex_enabled: bool,
    pub spot_routing_disabled: bool,
}

impl RegistrySet {
    pub fn get_by_global_asset(&self, global_asset: GlobalAssetId) -> &Clearinghouse {
        self.clearinghouses.get_by_global_asset(global_asset)
    }

    pub fn classify<S: SpotAssetCodec>(&self, raw: u32, spot_codec: &S) -> Result<RoutedAsset, RegistryError> {
        classify_wire_asset_id(raw, &self.clearinghouses, spot_codec)
    }

    pub fn route_asset_action(
        &self,
        user_status: UserDexRoutingStatus,
        global_asset: GlobalAssetId,
        permissions: DexRoutingPermissions,
    ) -> Result<RoutePlan, RegistryError> {
        let dex_id = dex_id_from_global_asset(global_asset);
        let clearinghouse = self.clearinghouses.index(dex_id);

        if user_status.force_direct()
            || self.spot_routing_disabled
            || !self.cross_dex_enabled
            || global_asset < PERP_ASSET_STRIDE
        {
            return Ok(RoutePlan::Direct { dex_id, global_asset });
        }

        if !permissions.can_enter && !permissions.can_exit {
            return Err(RegistryError::CrossDexRoutingDenied);
        }

        Ok(RoutePlan::CrossDex {
            dex_id,
            global_asset,
            settlement_asset: clearinghouse.settlement_asset,
            pre_settle: permissions.can_enter,
            post_settle: permissions.can_exit,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserDexRoutingStatus {
    Disabled,
    DirectOnly,
    AbstractionIfEnabled,
    Permissioned,
    Privileged,
    Unknown(u8),
}

impl UserDexRoutingStatus {
    pub const fn from_byte(value: u8) -> Self {
        match value {
            0 => Self::Disabled,
            1 => Self::DirectOnly,
            2 => Self::AbstractionIfEnabled,
            3 => Self::Permissioned,
            4 => Self::Privileged,
            other => Self::Unknown(other),
        }
    }

    pub const fn force_direct(self) -> bool {
        matches!(self, Self::Disabled | Self::DirectOnly)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DexRoutingPermissions {
    pub can_enter: bool,
    pub can_exit: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutePlan {
    Direct {
        dex_id: DexId,
        global_asset: GlobalAssetId,
    },
    CrossDex {
        dex_id: DexId,
        global_asset: GlobalAssetId,
        settlement_asset: GlobalAssetId,
        pre_settle: bool,
        post_settle: bool,
    },
}

pub const PRIMARY_REGISTRY_FIELD_TAGS: &[&str] = &["ctx", "cls", "scl", "ftr", "ust"];
pub const SECONDARY_REGISTRY_FIELD_TAGS: &[&str] = PRIMARY_REGISTRY_FIELD_TAGS;
pub const REGISTRY_TRAILING_FIELD_TAGS: &[&str] = &[
    "chn", "pdl", "uar", "blp", "qus", "ctr", "uac", "vlt", "hcm", "pmu",
];

pub fn registry_human_readable_field_tags() -> impl Iterator<Item = &'static str> {
    PRIMARY_REGISTRY_FIELD_TAGS
        .iter()
        .copied()
        .chain(REGISTRY_TRAILING_FIELD_TAGS.iter().copied())
}
