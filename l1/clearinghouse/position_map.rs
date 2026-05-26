#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type AssetId = u64;
pub type RawPx = i64;
pub type SignedNtl = i64;

pub const ASSETS_PER_DEX: AssetId = 10_000;
pub const POSITION_MAP_STATUS_OK: u64 = 1;
pub const POSITION_MAP_STATUS_MISSING_USER: u64 = 2;

/// 64-byte per-asset position value stored in the user's ordered position tree.
///
/// The recovered iterator reads keys in ascending `u64` order and values with a
/// 64-byte stride. Offsets +0x00, +0x08, +0x10, +0x18, +0x20, +0x28, +0x38 are
/// used directly by the liquidation/index path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct PositionRecord {
    /// Zero for cross margin; one is the isolated-margin branch observed in the binary.
    pub margin_mode_or_isolated: u32,
    pub max_leverage: u32,
    /// Isolated margin balance. The liquidation collector subtracts from this field for
    /// isolated positions instead of subtracting from the account-level scalar.
    pub margin_raw: SignedNtl,
    /// Signed size; positive long, negative short. Zero positions remain stored until a
    /// caller prunes them from the map.
    pub szi: i64,
    /// Funding/PnL accumulator updated with the same signed delta as the next two fields.
    pub accumulator_a: SignedNtl,
    pub accumulator_b: SignedNtl,
    pub accumulator_c: SignedNtl,
    /// ADL and margin-table code in adjacent reconstruction reads this as the denominator.
    pub cumulative_funding_raw: SignedNtl,
    pub margin_table_id: u32,
    pub flags_or_mode: u32,
}

impl PositionRecord {
    #[inline]
    pub fn is_isolated(self) -> bool {
        self.margin_mode_or_isolated == 1
    }

    #[inline]
    pub fn is_open(self) -> bool {
        self.szi != 0
    }

    #[inline]
    pub fn abs_size(self) -> u64 {
        self.szi.unsigned_abs()
    }

    fn apply_liquidation_delta(&mut self, account_value: &mut SignedNtl, delta: SignedNtl) {
        if self.is_isolated() {
            self.margin_raw = self.margin_raw.saturating_sub(delta);
        } else {
            *account_value = account_value.saturating_sub(delta);
        }

        self.accumulator_a = self.accumulator_a.saturating_add(delta);
        self.accumulator_b = self.accumulator_b.saturating_add(delta);
        self.accumulator_c = self.accumulator_c.saturating_add(delta);
    }
}

/// Wrapper around the per-user BTreeMap recovered from the B-tree node walk.
///
/// The first word passed with the iterator is an account-level signed scalar, followed
/// by a `BTreeMap<u64, PositionRecord>`. The binary walks the map in sorted asset order
/// and uses `asset % 10_000` to address per-dex oracle rows.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PositionMap {
    pub signed_account_value: SignedNtl,
    pub positions_by_asset: BTreeMap<AssetId, PositionRecord>,
}

impl PositionMap {
    #[inline]
    pub fn new(signed_account_value: SignedNtl) -> Self {
        Self {
            signed_account_value,
            positions_by_asset: BTreeMap::new(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.positions_by_asset.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.positions_by_asset.is_empty()
    }

    #[inline]
    pub fn contains_asset(&self, asset: AssetId) -> bool {
        self.positions_by_asset.contains_key(&asset)
    }

    #[inline]
    pub fn get(&self, asset: AssetId) -> Option<&PositionRecord> {
        self.positions_by_asset.get(&asset)
    }

    #[inline]
    pub fn get_mut(&mut self, asset: AssetId) -> Option<&mut PositionRecord> {
        self.positions_by_asset.get_mut(&asset)
    }

    #[inline]
    pub fn insert(&mut self, asset: AssetId, position: PositionRecord) -> Option<PositionRecord> {
        self.positions_by_asset.insert(asset, position)
    }

    #[inline]
    pub fn remove(&mut self, asset: AssetId) -> Option<PositionRecord> {
        self.positions_by_asset.remove(&asset)
    }

    #[inline]
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&AssetId, &PositionRecord)> {
        self.positions_by_asset.iter()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> impl DoubleEndedIterator<Item = (&AssetId, &mut PositionRecord)> {
        self.positions_by_asset.iter_mut()
    }

    pub fn open_position_count(&self) -> usize {
        self.positions_by_asset
            .values()
            .filter(|position| position.is_open())
            .count()
    }

    pub fn retain_open_positions(&mut self) {
        self.positions_by_asset.retain(|_, position| position.is_open());
    }

    pub fn local_asset_index(asset: AssetId, oracle_row_count: usize) -> usize {
        let local = (asset % ASSETS_PER_DEX) as usize;
        assert!(local < oracle_row_count);
        local
    }

    pub fn collect_liquidation_summary(
        &mut self,
        user: Address,
        user_tag: u32,
        known_users: &BTreeSet<Address>,
        oracle_px_by_local_asset: &[RawPx],
        liquidation_factor_by_asset: &BTreeMap<AssetId, f64>,
        mutate_positions: bool,
        aux_user_meta: u64,
    ) -> PositionMapLiquidationSummary {
        if !known_users.contains(&user) {
            return PositionMapLiquidationSummary::missing_user(user, user_tag);
        }

        let mut contributions = Vec::new();
        let mut selected_asset = 0;
        let mut selected_abs_notional = 0;
        let mut total_signed_delta = 0i64;

        for (&asset, position) in self.positions_by_asset.iter_mut() {
            let Some(&factor) = liquidation_factor_by_asset.get(&asset) else {
                continue;
            };
            if factor == 0.0 || position.szi == 0 {
                continue;
            }

            let local = Self::local_asset_index(asset, oracle_px_by_local_asset.len());
            let oracle_px = oracle_px_by_local_asset[local];
            if oracle_px < 0 {
                panic!("oracle price must be nonnegative");
            }

            let raw_notional = position
                .abs_size()
                .checked_mul(oracle_px as u64)
                .expect("position notional overflow");
            let delta = f64_to_i64_saturating((raw_notional as f64) * factor);
            if delta == 0 {
                continue;
            }

            if mutate_positions {
                position.apply_liquidation_delta(&mut self.signed_account_value, delta);
            }

            let signed_delta = delta.saturating_neg();
            total_signed_delta = total_signed_delta.saturating_add(signed_delta);
            if raw_notional > selected_abs_notional {
                selected_abs_notional = raw_notional;
                selected_asset = asset;
            }

            contributions.push(PositionMapLiquidationContribution {
                asset,
                signed_delta,
                size_abs: position.abs_size(),
                liquidation_factor: factor,
                raw_notional,
                user,
                user_tag,
                mutate_positions,
                aux_user_meta,
            });
        }

        PositionMapLiquidationSummary {
            user,
            user_tag,
            contributions,
            total_signed_delta,
            status: POSITION_MAP_STATUS_OK,
            selected_asset,
            selected_abs_notional,
            selected_user: user,
            selected_user_tag: user_tag,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PositionMapIndex {
    pub users: BTreeMap<Address, PositionMap>,
    pub active_users: BTreeSet<Address>,
    pub active_by_asset: BTreeMap<AssetId, BTreeSet<Address>>,
}

impl PositionMapIndex {
    pub fn get_or_default_mut(&mut self, user: Address) -> &mut PositionMap {
        self.users.entry(user).or_default()
    }

    pub fn refresh_user(&mut self, user: Address) {
        for users in self.active_by_asset.values_mut() {
            users.remove(&user);
        }

        let Some(map) = self.users.get(&user) else {
            self.active_users.remove(&user);
            return;
        };

        let mut has_open = false;
        for (&asset, position) in map.iter() {
            if position.is_open() {
                has_open = true;
                self.active_by_asset.entry(asset).or_default().insert(user);
            }
        }

        if has_open {
            self.active_users.insert(user);
        } else {
            self.active_users.remove(&user);
        }
    }

    pub fn upsert_position(&mut self, user: Address, asset: AssetId, position: PositionRecord) {
        self.get_or_default_mut(user).insert(asset, position);
        self.refresh_user(user);
    }

    pub fn remove_flat_position(&mut self, user: Address, asset: AssetId) -> Option<PositionRecord> {
        let map = self.users.get_mut(&user)?;
        let position = map.get(asset).copied()?;
        if position.is_open() {
            return None;
        }
        let removed = map.remove(asset);
        self.refresh_user(user);
        removed
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PositionMapLiquidationContribution {
    pub asset: AssetId,
    pub signed_delta: SignedNtl,
    pub size_abs: u64,
    pub liquidation_factor: f64,
    pub raw_notional: u64,
    pub user: Address,
    pub user_tag: u32,
    pub mutate_positions: bool,
    pub aux_user_meta: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PositionMapLiquidationSummary {
    pub user: Address,
    pub user_tag: u32,
    pub contributions: Vec<PositionMapLiquidationContribution>,
    pub total_signed_delta: SignedNtl,
    pub status: u64,
    pub selected_asset: AssetId,
    pub selected_abs_notional: u64,
    pub selected_user: Address,
    pub selected_user_tag: u32,
}

impl PositionMapLiquidationSummary {
    pub fn missing_user(user: Address, user_tag: u32) -> Self {
        Self {
            user,
            user_tag,
            status: POSITION_MAP_STATUS_MISSING_USER,
            ..Self::default()
        }
    }

    #[inline]
    pub fn has_candidates(&self) -> bool {
        !self.contributions.is_empty()
    }
}

fn f64_to_i64_saturating(value: f64) -> i64 {
    if !value.is_finite() {
        return 0;
    }
    if value >= i64::MAX as f64 {
        i64::MAX
    } else if value <= i64::MIN as f64 {
        i64::MIN
    } else {
        value as i64
    }
}
