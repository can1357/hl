#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::collections::hash_map::{Entry, Iter, IterMut};

use super::position::{
    aggregate_position_margin_summary, AdlCandidate, Address, AggregateMarginSummary, AssetId,
    MarginTablesView, OraclePrices, PositionMarginMode, RawNtl, UserPositionSet,
};

/// User-position collection owned by a clearinghouse.
///
/// The recovered layout is load-bearing for callers that borrow the collection as a single state
/// object: `users` is the SwissTable at +0x00, `active_users_with_positions` is the BTreeSet at
/// +0x60, and the ADL collection mode byte is read at +0xA8.
#[derive(Clone, Debug, Default)]
pub struct UserStates {
    pub users: HashMap<Address, UserPositionSet>,
    pub active_position_oi_units: HashMap<(Address, AssetId), u32>,
    pub active_users_with_positions: BTreeSet<Address>,
    pub open_interest_by_asset: BTreeMap<AssetId, RawNtl>,
    pub dirty_users: BTreeSet<Address>,
    /// When set, the ADL collector scans `users` and reorders through a BTreeMap. Otherwise it
    /// iterates `active_users_with_positions` directly and skips stale entries missing from `users`.
    pub use_full_user_scan_for_adl: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdlSideRequest {
    pub asset: AssetId,
    pub is_long: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AdlSideCandidates {
    pub asset: AssetId,
    pub is_long: bool,
    pub candidates: Vec<AdlCandidate>,
}

impl UserStates {
    pub fn new(use_full_user_scan_for_adl: bool) -> Self {
        Self {
            use_full_user_scan_for_adl,
            ..Self::default()
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.users.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    #[inline]
    pub fn contains_user(&self, user: &Address) -> bool {
        self.users.contains_key(user)
    }

    #[inline]
    pub fn user_state(&self, user: &Address) -> Option<&UserPositionSet> {
        self.users.get(user)
    }

    #[inline]
    pub fn user_state_mut(&mut self, user: &Address) -> Option<&mut UserPositionSet> {
        self.users.get_mut(user)
    }

    #[inline]
    pub fn user_entry(&mut self, user: Address) -> Entry<'_, Address, UserPositionSet> {
        self.users.entry(user)
    }

    #[inline]
    pub fn get_or_insert_user(&mut self, user: Address) -> &mut UserPositionSet {
        self.users.entry(user).or_default()
    }

    #[inline]
    pub fn iter(&self) -> Iter<'_, Address, UserPositionSet> {
        self.users.iter()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_, Address, UserPositionSet> {
        self.users.iter_mut()
    }

    #[inline]
    pub fn active_users(&self) -> impl Iterator<Item = &Address> {
        self.active_users_with_positions.iter()
    }

    #[inline]
    pub fn mark_dirty(&mut self, user: Address) {
        self.dirty_users.insert(user);
    }

    pub fn take_dirty_users(&mut self) -> BTreeSet<Address> {
        std::mem::take(&mut self.dirty_users)
    }

    /// Returns a mutable user position set and records that the user was touched before mutation.
    pub fn get_or_insert_user_for_position_mutation(&mut self, user: Address) -> &mut UserPositionSet {
        self.dirty_users.insert(user);
        self.users.entry(user).or_default()
    }

    /// Recomputes the active-user index after a position update.
    ///
    /// The binary stores only users with at least one nonzero position in the BTreeSet used by the
    /// default ADL path. Missing users and users whose positions have all gone to zero are removed.
    pub fn refresh_user_activity_after_position_change(&mut self, user: Address) -> (bool, bool) {
        let was_active = self.active_users_with_positions.contains(&user);
        let is_active = self
            .users
            .get(&user)
            .is_some_and(|state| state.positions_by_asset.values().any(|position| position.szi != 0));

        if is_active {
            self.active_users_with_positions.insert(user);
        } else {
            self.active_users_with_positions.remove(&user);
        }

        (was_active, is_active)
    }

    /// Maintains the per-user/per-asset open-interest unit side index.
    pub fn rescale_position_oi_unit(&mut self, user: Address, asset: AssetId, oi_unit: u32) {
        if oi_unit == 0 {
            self.active_position_oi_units.remove(&(user, asset));
        } else {
            self.active_position_oi_units.insert((user, asset), oi_unit);
        }
    }

    /// Applies an absolute-size replacement to the aggregate open-interest map.
    pub fn update_open_interest_by_slot(&mut self, asset: AssetId, old_abs_sz: i64, new_abs_sz: i64) {
        let old = old_abs_sz.unsigned_abs();
        let new = new_abs_sz.unsigned_abs();
        let entry = self.open_interest_by_asset.entry(asset).or_insert(0);
        *entry = entry.saturating_sub(old).saturating_add(new);
        if *entry == 0 {
            self.open_interest_by_asset.remove(&asset);
        }
    }

    pub fn aggregate_margin_summary_for_user(
        &self,
        user: &Address,
        include_isolated: bool,
        mode: PositionMarginMode,
        cap_leverage: u8,
        oracle_prices: &OraclePrices,
        tables: &MarginTablesView,
    ) -> AggregateMarginSummary {
        self.users.get(user).map_or_else(AggregateMarginSummary::default, |positions| {
            aggregate_position_margin_summary(
                positions,
                include_isolated,
                mode,
                cap_leverage,
                oracle_prices,
                tables,
            )
        })
    }

    pub fn collect_adl_candidates_for_sides(
        &self,
        requests: &[AdlSideRequest],
        oracle_prices: &OraclePrices,
        tables: &MarginTablesView,
        cap_leverage: u8,
    ) -> Vec<AdlSideCandidates> {
        let mut out = Vec::with_capacity(requests.len());
        for request in requests {
            out.push(self.collect_adl_candidates_for_side(*request, oracle_prices, tables, cap_leverage));
        }
        out
    }

    pub fn collect_adl_candidates_for_side(
        &self,
        request: AdlSideRequest,
        oracle_prices: &OraclePrices,
        tables: &MarginTablesView,
        cap_leverage: u8,
    ) -> AdlSideCandidates {
        let candidates = if self.use_full_user_scan_for_adl {
            self.collect_adl_candidates_from_all_users(request, oracle_prices, tables, cap_leverage)
        } else {
            self.collect_adl_candidates_from_active_users(request, oracle_prices, tables, cap_leverage)
        };

        AdlSideCandidates {
            asset: request.asset,
            is_long: request.is_long,
            candidates,
        }
    }

    fn collect_adl_candidates_from_active_users(
        &self,
        request: AdlSideRequest,
        oracle_prices: &OraclePrices,
        tables: &MarginTablesView,
        cap_leverage: u8,
    ) -> Vec<AdlCandidate> {
        let mut out = Vec::new();
        for user in &self.active_users_with_positions {
            let Some(positions) = self.users.get(user) else {
                continue;
            };
            if let Some(candidate) = positions.compute_adl_candidate_score(
                request.asset,
                request.is_long,
                oracle_prices,
                tables,
                *user,
                cap_leverage,
            ) {
                out.push(candidate);
            }
        }
        out
    }

    fn collect_adl_candidates_from_all_users(
        &self,
        request: AdlSideRequest,
        oracle_prices: &OraclePrices,
        tables: &MarginTablesView,
        cap_leverage: u8,
    ) -> Vec<AdlCandidate> {
        let mut ordered = BTreeMap::new();
        for (user, positions) in &self.users {
            if let Some(candidate) = positions.compute_adl_candidate_score(
                request.asset,
                request.is_long,
                oracle_prices,
                tables,
                *user,
                cap_leverage,
            ) {
                ordered.insert(*user, candidate);
            }
        }
        ordered.into_values().collect()
    }
}
