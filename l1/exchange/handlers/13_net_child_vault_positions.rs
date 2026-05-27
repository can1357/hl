//! NetChildVaultPositions action handler.
//!
//! Handler EA: `0x27E8CB0`
//! Core helper: `sub_26F6C30`
//!
//! Recovered shape:
//! - the caller address is the parent vault key;
//! - the payload carries `child_vault_addresses` plus a wire-asset list;
//! - assets are classified, normalized to perp global assets, deduplicated, and
//!   then netted across the supplied child vault set.

use std::collections::BTreeSet;

pub type Address = [u8; 20];
pub type AssetId = u64;

pub const STATUS_OK: u16 = 390;
pub const STATUS_DEX_NOT_READY: u16 = 97;
pub const STATUS_UNKNOWN_PARENT_VAULT: u16 = 7;
pub const STATUS_PARENT_VAULT_NOT_CHILD_NETTING_CAPABLE: u16 = 24;
pub const STATUS_UNKNOWN_CHILD_VAULT: u16 = 27;
pub const STATUS_SPOT_ASSET_NOT_ALLOWED: u16 = 350;
pub const STATUS_UNKNOWN_DEX: u16 = 321;
pub const STATUS_TOO_MANY_ASSETS: u16 = 323;
pub const FEATURE_READY: u8 = 3;
pub const MAX_ASSET_CAPACITY: usize = 10_000;
pub const CHILD_NETTING_MIN_VAULT_VERSION: u32 = 2;
pub const PERP_ASSET_STRIDE: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetChildVaultPositionsAction {
    pub child_vault_addresses: Vec<Address>,
    pub assets: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultState {
    /// Version gate recovered from `*((_DWORD *)v11 - 4) >= 2` in `sub_26F6C30`.
    pub version: u32,
    /// The helper walks this tree and rejects any payload child that is not already linked.
    pub child_vault_addresses: BTreeSet<Address>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutedAsset {
    Perp { global_asset: AssetId, dex_id: usize },
    Spot { universe: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NormalizedPerpAsset {
    pub raw_wire_asset: u32,
    pub global_asset: AssetId,
    pub dex_id: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PositionUpdateSide {
    pub user: Address,
    pub asset: AssetId,
    pub sz_delta_abs: u64,
    pub notional_delta: u64,
    pub px_raw: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerpFundingAndVolumeUpdate {
    pub asset: AssetId,
    pub raw_notional: i64,
    pub day_bucket: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PositionStorageUpdate {
    /// Opaque rewritten position row. `sub_24FB610` rebuilds this and persists it through `sub_23D9D40`.
    pub encoded_row: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PositionNetCandidate {
    pub funding_update: PerpFundingAndVolumeUpdate,
    pub position_update: PositionUpdateSide,
    pub is_second_side: bool,
    pub storage_update: PositionStorageUpdate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChildVaultNettingOutcome {
    pub parent_vault: Address,
    pub requested_children: Vec<Address>,
    pub unique_perp_assets: Vec<NormalizedPerpAsset>,
    pub applied_candidates: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetChildVaultPositionsError {
    TooManyAssets { capacity: usize },
    AssetClassification { raw_wire_asset: u32, status: u16 },
    SpotAssetNotAllowed { raw_wire_asset: u32 },
    DexNotReady { global_asset: AssetId, dex_id: usize },
    UnknownParentVault { parent_vault: Address },
    ParentVaultNotChildNettingCapable { parent_vault: Address, version: u32 },
    UnknownChildVault { parent_vault: Address, child_vault: Address },
}

impl NetChildVaultPositionsError {
    pub const fn status(&self) -> u16 {
        match self {
            Self::TooManyAssets { .. } => STATUS_TOO_MANY_ASSETS,
            Self::AssetClassification { status, .. } => *status,
            Self::SpotAssetNotAllowed { .. } => STATUS_SPOT_ASSET_NOT_ALLOWED,
            Self::DexNotReady { .. } => STATUS_DEX_NOT_READY,
            Self::UnknownParentVault { .. } => STATUS_UNKNOWN_PARENT_VAULT,
            Self::ParentVaultNotChildNettingCapable { .. } => STATUS_PARENT_VAULT_NOT_CHILD_NETTING_CAPABLE,
            Self::UnknownChildVault { .. } => STATUS_UNKNOWN_CHILD_VAULT,
        }
    }
}

/// Narrow interface to the state touched by `0x27E8CB0` and `sub_26F6C30`.
///
/// The binary path does three things once validation passes:
/// 1. scans the requested children for liquidation-style position candidates on each asset;
/// 2. applies perp funding/volume updates for every candidate;
/// 3. applies the resulting position delta and writes the rebuilt row back into the dex table.
pub trait NetChildVaultRuntime {
    fn classify_wire_asset_id(&self, raw_wire_asset: u32) -> Result<RoutedAsset, u16>;
    fn dex_feature_tier(&self, dex_id: usize) -> Option<u8>;
    fn vault(&self, address: &Address) -> Option<&VaultState>;
    fn scan_child_vault_candidates_for_asset(
        &mut self,
        parent_vault: &Address,
        child_vaults: &[Address],
        asset: NormalizedPerpAsset,
    ) -> Vec<PositionNetCandidate>;
    fn apply_perp_funding_and_volume_update(&mut self, update: &PerpFundingAndVolumeUpdate);
    fn apply_position_update_for_asset_side(&mut self, side: &PositionUpdateSide, is_second_side: bool);
    fn persist_position_storage_update(&mut self, asset: NormalizedPerpAsset, storage: PositionStorageUpdate);
}

/// Reconstructed handler for `NetChildVaultPositions`.
///
/// Validation and apply flow recovered from `0x27E8CB0`:
///
/// 1. Reject asset vectors whose backing capacity exceeds `10_000`.
/// 2. For each wire asset:
///    - classify through the clearinghouse registry;
///    - reject spot assets (`350`);
///    - compute `dex_id = global_asset / 10_000`;
///    - require the per-dex feature byte to be `3`;
///    - insert the normalized perp asset into a `BTreeSet`, so duplicates are ignored.
/// 3. Resolve the caller address as the parent vault.
/// 4. Require vault version `>= 2`; older vaults do not expose the child-vault tree used here.
/// 5. If the payload names children, every entry must already be linked beneath that parent.
/// 6. For every unique asset, scan the requested child vaults for candidate position rows,
///    then apply funding/volume updates, apply the position delta, and persist the rebuilt row.
///
/// The handler treats an empty child list as a valid no-op scan input.
pub fn net_child_vault_positions<R: NetChildVaultRuntime>(
    runtime: &mut R,
    parent_vault: Address,
    action: &NetChildVaultPositionsAction,
) -> Result<ChildVaultNettingOutcome, NetChildVaultPositionsError> {
    if action.assets.capacity() > MAX_ASSET_CAPACITY {
        return Err(NetChildVaultPositionsError::TooManyAssets {
            capacity: action.assets.capacity(),
        });
    }

    let mut unique_assets = BTreeSet::new();
    for &raw_wire_asset in &action.assets {
        let routed = runtime
            .classify_wire_asset_id(raw_wire_asset)
            .map_err(|status| NetChildVaultPositionsError::AssetClassification {
                raw_wire_asset,
                status,
            })?;

        let RoutedAsset::Perp { global_asset, dex_id } = routed else {
            return Err(NetChildVaultPositionsError::SpotAssetNotAllowed { raw_wire_asset });
        };

        let Some(feature_tier) = runtime.dex_feature_tier(dex_id) else {
            return Err(NetChildVaultPositionsError::AssetClassification {
                raw_wire_asset,
                status: STATUS_UNKNOWN_DEX,
            });
        };
        if feature_tier != FEATURE_READY {
            return Err(NetChildVaultPositionsError::DexNotReady { global_asset, dex_id });
        }

        unique_assets.insert(NormalizedPerpAsset {
            raw_wire_asset,
            global_asset,
            dex_id,
        });
    }

    let parent = runtime
        .vault(&parent_vault)
        .ok_or(NetChildVaultPositionsError::UnknownParentVault { parent_vault })?;
    if parent.version < CHILD_NETTING_MIN_VAULT_VERSION {
        return Err(NetChildVaultPositionsError::ParentVaultNotChildNettingCapable {
            parent_vault,
            version: parent.version,
        });
    }

    for &child_vault in &action.child_vault_addresses {
        if !parent.child_vault_addresses.contains(&child_vault) {
            return Err(NetChildVaultPositionsError::UnknownChildVault {
                parent_vault,
                child_vault,
            });
        }
    }

    let unique_perp_assets: Vec<_> = unique_assets.into_iter().collect();
    let mut applied_candidates = 0usize;
    for asset in unique_perp_assets.iter().copied() {
        let candidates = runtime.scan_child_vault_candidates_for_asset(
            &parent_vault,
            &action.child_vault_addresses,
            asset,
        );
        for candidate in candidates {
            runtime.apply_perp_funding_and_volume_update(&candidate.funding_update);
            runtime.apply_position_update_for_asset_side(&candidate.position_update, candidate.is_second_side);
            runtime.persist_position_storage_update(asset, candidate.storage_update);
            applied_candidates += 1;
        }
    }

    Ok(ChildVaultNettingOutcome {
        parent_vault,
        requested_children: action.child_vault_addresses.clone(),
        unique_perp_assets,
        applied_candidates,
    })
}
