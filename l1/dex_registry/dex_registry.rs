use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub type Address = [u8; 20];
pub type AssetKey = [u8; 20];
pub type LocalAssetIndex = u64;
pub type DexIndex = u64;
pub type EncodedAssetId = u64;

const ASSETS_PER_DEX: u64 = 10_000;
const MAX_DEX_COUNT: usize = 2_000;
const MAX_FULL_NAME_BYTES: usize = 50;
const HIP3_STATUS_REFRESH_SECS: i64 = 10 * 24 * 60 * 60;
const ANNOTATION_UPDATE_MIN_SECS: i64 = 24 * 60 * 60;
const FUNDING_MULTIPLIER_MIN: f64 = 0.0;
const FUNDING_MULTIPLIER_MAX: f64 = 10.0;
const FUNDING_INTEREST_ABS_MAX: f64 = 0.01;
const SUCCESS_RESULT_TAG: u16 = 390;

const RESERVED_DEX_NAMES: &[&str] = &[
    "nyse", "cme", "hl", "hyp", "hkex", "lse", "krx", "sgx", "cboe", "ice", "usd", "eth", "btc", "sol",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NaiveDateTime12 {
    pub seconds: i64,
    pub nanos: u32,
}
impl Default for NaiveDateTime12 {
    fn default() -> Self {
        Self { seconds: 0, nanos: 0 }
    }
}


impl NaiveDateTime12 {
    #[inline]
    pub fn checked_add_seconds(self, seconds: i64) -> Option<Self> {
        Some(Self { seconds: self.seconds.checked_add(seconds)?, nanos: self.nanos })
    }

    #[inline]
    pub fn older_or_equal(self, other: Self) -> bool {
        self.seconds < other.seconds || (self.seconds == other.seconds && self.nanos <= other.nanos)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    LengthMismatch,
    DexNameLen,
    DexNameNotLowerAscii,
    DexNameReserved,
    DexNameDuplicate,
    FullNameTooLong,
    TooManyDexs,
    ActiveDexForDeployer,
    DexNotFound,
    LocalAssetOutOfRange,
    EncodedAssetOverflow,
    InvalidAssetSuffix,
    CrossMarginAsset,
    FundingMultiplierOutOfRange,
    FundingInterestOutOfRange,
    AnnotationUpdatedTooRecently,
    DeletedDex,
    TimeOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DexStatus {
    Live,
    Locked,
    Delisted,
    Deleted,
}
impl Default for DexStatus {
    fn default() -> Self {
        Self::Live
    }
}

impl DexStatus {
    #[inline]
    pub fn is_active(self) -> bool {
        // The binary consistently skips entries whose status/tag byte is 3.
        self != Self::Deleted
    }
}

#[derive(Clone, Debug)]
pub struct PerpDexRecord {
    pub name: String,
    pub full_name: String,
    pub deployer: Address,
    pub collateral_asset: u32,
    pub fee_recipient: Address,
    pub status: DexStatus,
    pub dex: DexIndex,
}

#[derive(Clone, Debug)]
pub struct PerpAnnotation {
    pub last_update_time: NaiveDateTime12,
    pub category: String,
    pub description: String,
    pub display_name: String,
    pub keywords: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PerpAssetInfo {
    pub assets: Vec<String>,
    pub hl_only_perps: BTreeSet<LocalAssetIndex>,
    pub perp_to_funding_multiplier: BTreeMap<LocalAssetIndex, f64>,
    pub perp_to_funding_interest_rate: BTreeMap<LocalAssetIndex, f64>,
    pub oi_sz_cap_per_perp: BTreeMap<LocalAssetIndex, f64>,
    pub perp_to_annotation: BTreeMap<LocalAssetIndex, PerpAnnotation>,
}

impl Default for PerpAssetInfo {
    fn default() -> Self {
        Self {
            assets: Vec::new(),
            hl_only_perps: BTreeSet::new(),
            perp_to_funding_multiplier: BTreeMap::new(),
            perp_to_funding_interest_rate: BTreeMap::new(),
            oi_sz_cap_per_perp: BTreeMap::new(),
            perp_to_annotation: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct PerpDex {
    pub dex_index: DexIndex,
    pub asset_count: u64,
    pub hip3_asset_key: AssetKey,
    pub hip3_assets: BTreeSet<EncodedAssetId>,
    pub active_order_count: u64,
    pub target_order_count: u64,
    pub books: BTreeMap<LocalAssetIndex, BookState>,
    pub funding_tracker: FundingTracker,
    pub twap_tracker: TwapTracker,
    pub perp_to_annotation: BTreeMap<LocalAssetIndex, PerpAnnotation>,
}

#[derive(Clone, Debug, Default)]
pub struct BookState {
    pub live_orders: u64,
    pub empty_levels: u64,
}

#[derive(Clone, Debug, Default)]
pub struct FundingTracker {
    pub pending_by_asset: BTreeMap<EncodedAssetId, f64>,
}

#[derive(Clone, Debug, Default)]
pub struct TwapTracker {
    pub pending_updates: usize,
}

#[derive(Clone, Debug, Default)]
pub struct Clearinghouse {
    pub dex_index: DexIndex,
    pub status: DexStatus,
    pub last_hip3_status_refresh: NaiveDateTime12,
    pub oracle_prices: BTreeMap<EncodedAssetId, f64>,
    pub hip3_asset_keys: BTreeSet<AssetKey>,
    pub funding_accumulator: BTreeMap<EncodedAssetId, f64>,
    pub users_with_activity: BTreeSet<Address>,
}

#[derive(Clone, Debug, Default)]
pub struct RegistrySnapshot {
    pub pair_hash: [u8; 32],
    pub side_hash: [u8; 32],
    pub dex_count: usize,
    pub clearinghouse_count: usize,
}

#[derive(Clone, Debug)]
pub struct BookStatsTiming<T> {
    pub value: T,
    pub guard_wait_secs: f64,
    pub inner_secs: f64,
}

#[derive(Clone, Debug, Default)]
pub struct DexRegistry {
    pub now: NaiveDateTime12,
    pub mode_tag: u8,
    pub perp_dexs: Vec<PerpDex>,
    pub clearinghouses: Vec<Clearinghouse>,
    pub dex_records: Vec<PerpDexRecord>,
    pub asset_infos: Vec<PerpAssetInfo>,
    pub global_hip3_asset_keys: BTreeSet<AssetKey>,
    pub deleted_hip3_asset_keys: BTreeSet<AssetKey>,
    pub state_hash_history: BTreeMap<u64, RegistrySnapshot>,
}

impl DexRegistry {
    #[inline]
    pub fn check_parallel_lengths(&self) -> Result<(), RegistryError> {
        if self.perp_dexs.len() == self.clearinghouses.len() {
            Ok(())
        } else {
            Err(RegistryError::LengthMismatch)
        }
    }

    pub fn pair_iter(&self) -> Result<impl Iterator<Item = (&PerpDex, &Clearinghouse)>, RegistryError> {
        self.check_parallel_lengths()?;
        Ok(self.perp_dexs.iter().zip(self.clearinghouses.iter()))
    }

    pub fn pair_iter_mut(&mut self) -> Result<impl Iterator<Item = (&mut PerpDex, &mut Clearinghouse)>, RegistryError> {
        if self.perp_dexs.len() != self.clearinghouses.len() {
            return Err(RegistryError::LengthMismatch);
        }
        Ok(self.perp_dexs.iter_mut().zip(self.clearinghouses.iter_mut()))
    }

    pub fn validate_new_dex(&self, name: &str, full_name: &str, deployer: Address) -> Result<(), RegistryError> {
        validate_dex_name(name)?;
        if full_name.len() > MAX_FULL_NAME_BYTES {
            return Err(RegistryError::FullNameTooLong);
        }
        if self.dex_records.len() >= MAX_DEX_COUNT {
            return Err(RegistryError::TooManyDexs);
        }
        if self.dex_records.iter().any(|record| record.name == name) || name == "spot" {
            return Err(RegistryError::DexNameDuplicate);
        }
        if self.dex_records.iter().any(|record| record.deployer == deployer && record.status.is_active()) {
            return Err(RegistryError::ActiveDexForDeployer);
        }
        Ok(())
    }

    pub fn deploy_perp_dex(
        &mut self,
        name: String,
        full_name: String,
        deployer: Address,
        collateral_asset: u32,
        fee_recipient: Address,
    ) -> Result<DexIndex, RegistryError> {
        self.validate_new_dex(&name, &full_name, deployer)?;
        let dex = self.dex_records.len() as DexIndex;
        self.dex_records.push(PerpDexRecord {
            name,
            full_name,
            deployer,
            collateral_asset,
            fee_recipient,
            status: DexStatus::Live,
            dex,
        });
        self.perp_dexs.push(PerpDex { dex_index: dex, ..PerpDex::default() });
        self.clearinghouses.push(Clearinghouse { dex_index: dex, ..Clearinghouse::default() });
        self.asset_infos.push(PerpAssetInfo::default());
        Ok(dex)
    }

    pub fn drop_last_if_empty(&mut self) -> bool {
        let Some(perp_dex) = self.perp_dexs.last() else { return false; };
        let Some(clearinghouse) = self.clearinghouses.last() else { return false; };
        if perp_dex.asset_count != 0 || !perp_dex.books.is_empty() || !clearinghouse.users_with_activity.is_empty() {
            return false;
        }
        self.perp_dexs.pop();
        self.clearinghouses.pop();
        self.asset_infos.pop();
        self.dex_records.pop();
        true
    }

    #[inline]
    pub fn dex_record(&self, dex: DexIndex) -> Result<&PerpDexRecord, RegistryError> {
        self.dex_records.get(dex as usize).ok_or(RegistryError::DexNotFound)
    }

    #[inline]
    pub fn dex_record_mut(&mut self, dex: DexIndex) -> Result<&mut PerpDexRecord, RegistryError> {
        self.dex_records.get_mut(dex as usize).ok_or(RegistryError::DexNotFound)
    }

    #[inline]
    pub fn asset_info(&self, dex: DexIndex) -> Result<&PerpAssetInfo, RegistryError> {
        self.asset_infos.get(dex as usize).ok_or(RegistryError::DexNotFound)
    }

    #[inline]
    pub fn asset_info_mut(&mut self, dex: DexIndex) -> Result<&mut PerpAssetInfo, RegistryError> {
        self.asset_infos.get_mut(dex as usize).ok_or(RegistryError::DexNotFound)
    }

    pub fn asset_meta_by_encoded_asset(&self, asset: EncodedAssetId) -> Result<(&PerpDexRecord, &str), RegistryError> {
        let id = PerpAssetId::from_encoded(asset);
        let info = self.asset_info(id.dex_index)?;
        let asset_name = info.assets.get(id.local_index as usize).ok_or(RegistryError::LocalAssetOutOfRange)?;
        Ok((self.dex_record(id.dex_index)?, asset_name.as_str()))
    }

    pub fn perp_annotation_for_asset(&self, asset: EncodedAssetId) -> Option<&PerpAnnotation> {
        let id = PerpAssetId::from_encoded(asset);
        self.asset_infos
            .get(id.dex_index as usize)
            .and_then(|info| info.perp_to_annotation.get(&id.local_index))
    }

    pub fn validate_add_perp_asset(&self, dex: DexIndex, asset_name: &str, cross_margin: bool) -> Result<(), RegistryError> {
        if cross_margin {
            return Err(RegistryError::CrossMarginAsset);
        }
        let info = self.asset_info(dex)?;
        if info.assets.len() >= ASSETS_PER_DEX as usize {
            return Err(RegistryError::LocalAssetOutOfRange);
        }
        validate_asset_suffix(asset_name)?;
        Ok(())
    }

    pub fn add_perp_asset(&mut self, dex: DexIndex, asset_name: String, cross_margin: bool) -> Result<EncodedAssetId, RegistryError> {
        self.validate_add_perp_asset(dex, &asset_name, cross_margin)?;
        let local = self.asset_info(dex)?.assets.len() as LocalAssetIndex;
        self.asset_info_mut(dex)?.assets.push(asset_name);
        if let Some(perp_dex) = self.perp_dexs.get_mut(dex as usize) {
            perp_dex.asset_count = perp_dex.asset_count.saturating_add(1);
        }
        encode_asset_id(dex, local)
    }

    pub fn sorted_perp_asset_infos_for_dex(&self, dex: DexIndex) -> Result<Vec<(EncodedAssetId, &str)>, RegistryError> {
        let info = self.asset_info(dex)?;
        let mut out = Vec::with_capacity(info.assets.len());
        for (local, name) in info.assets.iter().enumerate() {
            out.push((encode_asset_id(dex, local as u64)?, name.as_str()));
        }
        out.sort_unstable_by_key(|(asset, _)| *asset);
        Ok(out)
    }

    pub fn set_funding_multiplier(
        &mut self,
        asset: EncodedAssetId,
        multiplier: f64,
    ) -> Result<(), RegistryError> {
        if !(FUNDING_MULTIPLIER_MIN..=FUNDING_MULTIPLIER_MAX).contains(&multiplier) {
            return Err(RegistryError::FundingMultiplierOutOfRange);
        }
        let id = PerpAssetId::from_encoded(asset);
        self.asset_info_mut(id.dex_index)?.perp_to_funding_multiplier.insert(id.local_index, multiplier);
        Ok(())
    }

    pub fn set_funding_interest_rate(
        &mut self,
        asset: EncodedAssetId,
        interest_rate: f64,
    ) -> Result<(), RegistryError> {
        if interest_rate.abs() > FUNDING_INTEREST_ABS_MAX {
            return Err(RegistryError::FundingInterestOutOfRange);
        }
        let id = PerpAssetId::from_encoded(asset);
        self.asset_info_mut(id.dex_index)?.perp_to_funding_interest_rate.insert(id.local_index, interest_rate);
        Ok(())
    }

    pub fn set_perp_annotation(
        &mut self,
        asset: EncodedAssetId,
        annotation: PerpAnnotation,
    ) -> Result<(), RegistryError> {
        let id = PerpAssetId::from_encoded(asset);
        if let Some(old) = self.asset_info(id.dex_index)?.perp_to_annotation.get(&id.local_index) {
            let next_allowed = old
                .last_update_time
                .checked_add_seconds(ANNOTATION_UPDATE_MIN_SECS)
                .ok_or(RegistryError::TimeOverflow)?;
            if !next_allowed.older_or_equal(annotation.last_update_time) {
                return Err(RegistryError::AnnotationUpdatedTooRecently);
            }
        }
        self.asset_info_mut(id.dex_index)?.perp_to_annotation.insert(id.local_index, annotation);
        Ok(())
    }

    pub fn collect_funding_values_by_asset(&self) -> Result<BTreeMap<EncodedAssetId, f64>, RegistryError> {
        let mut values = BTreeMap::new();
        for (perp_dex, clearinghouse) in self.pair_iter()? {
            for local in 0..perp_dex.asset_count {
                let encoded = encode_asset_id(perp_dex.dex_index, local)?;
                let price = clearinghouse.oracle_prices.get(&encoded).copied().unwrap_or(0.0);
                values.insert(encoded, price);
            }
        }
        Ok(values)
    }

    pub fn distribute_funding_guarded(&mut self, is_due: bool) -> Result<(), RegistryError> {
        if !is_due {
            return Ok(());
        }
        let funding_values = self.collect_funding_values_by_asset()?;
        for (perp_dex, clearinghouse) in self.pair_iter_mut()? {
            for (asset, price) in &funding_values {
                if *asset / ASSETS_PER_DEX == perp_dex.dex_index {
                    clearinghouse.funding_accumulator.insert(*asset, *price);
                    perp_dex.funding_tracker.pending_by_asset.insert(*asset, *price);
                }
            }
        }
        Ok(())
    }

    pub fn refresh_hip3_status_guarded(&mut self, now: NaiveDateTime12) -> Result<Vec<GuardOutcome>, RegistryError> {
        let mut due = Vec::new();
        for (dex_index, (perp_dex, clearinghouse)) in self.pair_iter()?.enumerate() {
            if !clearinghouse.status.is_active() {
                continue;
            }
            let refresh_at = clearinghouse
                .last_hip3_status_refresh
                .checked_add_seconds(HIP3_STATUS_REFRESH_SECS)
                .ok_or(RegistryError::TimeOverflow)?;
            if refresh_at.older_or_equal(now) || perp_dex.active_order_count != perp_dex.target_order_count {
                due.push(dex_index);
            }
        }

        let mut outcomes = Vec::new();
        for dex_index in due {
            let outcome = self.refresh_one_hip3_status(dex_index as DexIndex)?;
            if outcome.tag != SUCCESS_RESULT_TAG {
                outcomes.push(outcome);
            }
        }
        Ok(outcomes)
    }

    pub fn contains_hip3_asset_key(&self, key: &AssetKey) -> Result<bool, RegistryError> {
        for (perp_dex, clearinghouse) in self.pair_iter()? {
            if &perp_dex.hip3_asset_key == key || clearinghouse.hip3_asset_keys.contains(key) {
                return Ok(true);
            }
        }
        Ok(self.global_hip3_asset_keys.contains(key) || self.deleted_hip3_asset_keys.contains(key))
    }

    pub fn state_hash_snapshot(&self) -> Result<RegistrySnapshot, RegistryError> {
        self.check_parallel_lengths()?;
        let mut pair_hash = [0u8; 32];
        let mut side_hash = [0u8; 32];
        for (idx, (perp_dex, clearinghouse)) in self.perp_dexs.iter().zip(&self.clearinghouses).enumerate() {
            mix_u64(&mut pair_hash, idx as u64);
            mix_u64(&mut pair_hash, perp_dex.dex_index);
            mix_u64(&mut pair_hash, perp_dex.asset_count);
            mix_u64(&mut pair_hash, clearinghouse.dex_index);
            mix_u64(&mut pair_hash, clearinghouse.funding_accumulator.len() as u64);
        }
        mix_u64(&mut side_hash, self.dex_records.len() as u64);
        mix_u64(&mut side_hash, self.asset_infos.len() as u64);
        mix_u64(&mut side_hash, self.mode_tag as u64);
        Ok(RegistrySnapshot {
            pair_hash,
            side_hash,
            dex_count: self.perp_dexs.len(),
            clearinghouse_count: self.clearinghouses.len(),
        })
    }

    pub fn collect_book_stats_timed(&self) -> Result<BookStatsTiming<Vec<(DexIndex, usize)>>, RegistryError> {
        let mut value = Vec::new();
        for (perp_dex, clearinghouse) in self.pair_iter()? {
            if clearinghouse.status.is_active() {
                value.push((perp_dex.dex_index, perp_dex.books.len()));
            }
        }
        Ok(BookStatsTiming { value, guard_wait_secs: 0.0, inner_secs: 0.0 })
    }

    pub fn end_block_update(&mut self, previous_time: NaiveDateTime12, now: NaiveDateTime12) -> Result<Vec<GuardOutcome>, RegistryError> {
        self.now = now;
        let mut outcomes = Vec::new();
        let funding_due = previous_time.seconds / 1_000 != now.seconds / 1_000;
        self.distribute_funding_guarded(funding_due)?;
        self.update_mark_prices_and_action_delay();
        outcomes.extend(self.refresh_hip3_status_guarded(now)?);
        for (_, clearinghouse) in self.pair_iter_mut()? {
            if clearinghouse.status == DexStatus::Deleted {
                clearinghouse.users_with_activity.clear();
            }
        }
        Ok(outcomes)
    }

    fn refresh_one_hip3_status(&mut self, dex: DexIndex) -> Result<GuardOutcome, RegistryError> {
        let Some((perp_dex, clearinghouse)) = self.perp_dexs.get_mut(dex as usize).zip(self.clearinghouses.get_mut(dex as usize)) else {
            return Err(RegistryError::DexNotFound);
        };
        perp_dex.target_order_count = perp_dex.active_order_count;
        clearinghouse.last_hip3_status_refresh = self.now;
        Ok(GuardOutcome { tag: SUCCESS_RESULT_TAG, dex })
    }

    fn update_mark_prices_and_action_delay(&mut self) {
        for perp_dex in &mut self.perp_dexs {
            for book in perp_dex.books.values_mut() {
                if book.empty_levels > book.live_orders {
                    book.empty_levels = book.live_orders;
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerpAssetId {
    pub dex_index: DexIndex,
    pub local_index: LocalAssetIndex,
}

impl PerpAssetId {
    #[inline]
    pub fn from_encoded(encoded: EncodedAssetId) -> Self {
        Self { dex_index: encoded / ASSETS_PER_DEX, local_index: encoded % ASSETS_PER_DEX }
    }

    #[inline]
    pub fn from_parts(dex_index: DexIndex, local_index: LocalAssetIndex) -> Result<Self, RegistryError> {
        if local_index >= ASSETS_PER_DEX {
            return Err(RegistryError::LocalAssetOutOfRange);
        }
        encode_asset_id(dex_index, local_index)?;
        Ok(Self { dex_index, local_index })
    }

    #[inline]
    pub fn api_asset_id(self) -> Result<EncodedAssetId, RegistryError> {
        encode_asset_id(self.dex_index, self.local_index)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardOutcome {
    pub tag: u16,
    pub dex: DexIndex,
}

pub fn encode_asset_id(dex_index: DexIndex, local_index: LocalAssetIndex) -> Result<EncodedAssetId, RegistryError> {
    if local_index >= ASSETS_PER_DEX {
        return Err(RegistryError::LocalAssetOutOfRange);
    }
    dex_index
        .checked_mul(ASSETS_PER_DEX)
        .and_then(|base| base.checked_add(local_index))
        .ok_or(RegistryError::EncodedAssetOverflow)
}

pub fn validate_dex_name(name: &str) -> Result<(), RegistryError> {
    if !(2..=4).contains(&name.len()) {
        return Err(RegistryError::DexNameLen);
    }
    if has_non_lower_ascii(name) {
        return Err(RegistryError::DexNameNotLowerAscii);
    }
    if RESERVED_DEX_NAMES.contains(&name) {
        return Err(RegistryError::DexNameReserved);
    }
    Ok(())
}

#[inline]
pub fn has_non_lower_ascii(value: &str) -> bool {
    value.bytes().any(|byte| !byte.is_ascii_lowercase())
}

pub fn validate_asset_suffix(asset: &str) -> Result<(), RegistryError> {
    if asset.is_empty() || asset.len() > 9 {
        return Err(RegistryError::InvalidAssetSuffix);
    }
    if asset.bytes().any(|byte| !byte.is_ascii_uppercase() && !byte.is_ascii_digit()) {
        return Err(RegistryError::InvalidAssetSuffix);
    }
    Ok(())
}

pub fn find_dex_by_name_or_first<'a>(records: &'a [PerpDexRecord], dex: Option<&str>) -> Option<&'a PerpDexRecord> {
    match dex {
        Some(name) => records.iter().find(|record| record.name == name && record.status.is_active()),
        None => records.iter().find(|record| record.status.is_active()),
    }
}

fn mix_u64(hash: &mut [u8; 32], value: u64) {
    let bytes = value.to_le_bytes();
    for (idx, byte) in bytes.iter().enumerate() {
        let slot = idx % hash.len();
        hash[slot] = hash[slot].wrapping_mul(31).wrapping_add(*byte);
        hash[(slot + 13) % 32] ^= byte.rotate_left((idx & 7) as u32);
    }
}

#[allow(dead_code)]
fn collect_active_deployers(records: &[PerpDexRecord]) -> HashSet<Address> {
    records
        .iter()
        .filter(|record| record.status.is_active())
        .map(|record| record.deployer)
        .collect()
}

#[allow(dead_code)]
fn funding_values_to_hash_map(values: &BTreeMap<EncodedAssetId, f64>) -> HashMap<EncodedAssetId, f64> {
    values.iter().map(|(asset, price)| (*asset, *price)).collect()
}
