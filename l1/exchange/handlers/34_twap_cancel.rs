//! Recovered `twapCancel` handler (`UserActionTag::TwapCancel`, idx 34).
//!
//! Grounding:
//! - dispatcher arm `sub_22C4630` at `0x22C4630`
//! - wire-asset classifier `l1_dex_registry_clearinghouses__classify_wire_asset_id`
//!   at `0x3C0CC70`
//! - shared TWAP removal helper at `0x2724580`
//!
//! The generic signer-scoped nonce gate runs before the execute-action switch, so
//! this handler has no local nonce/replay logic of its own.

#![allow(dead_code)]

pub type Address = [u8; 20];
pub type WireAssetId = u32;
pub type GlobalAssetId = u64;
pub type SpotAssetId = u64;
pub type DexId = u64;
pub type TwapId = u64;

pub const STATUS_OK: u16 = 390;
/// Returned directly from `classify_wire_asset_id(...)` when the routed perp DEX
/// does not exist.
pub const STATUS_UNKNOWN_DEX: u16 = 321;
/// Exact inline guard in `sub_22C4630`: reject `twap_id >= 0xCCCCCCCCCCCCCCCu`.
pub const STATUS_TWAP_ID_OVERFLOW: u16 = 319;
/// Branch-local gate when the spot-TWAP store/feature is disabled.
pub const STATUS_SPOT_TWAP_BRANCH_DISABLED: u16 = 249;
/// [INFERENCE] `0x2724580` returns `206` whenever the user tree is missing the
/// requested TWAP entry or the removed row is already in tombstone state `2`.
pub const STATUS_MISSING_TWAP: u16 = 206;

pub const OUTCOME_TAG_SUCCESS: u8 = 5;
pub const OUTCOME_TAG_ERROR: u8 = 14;
pub const TWAP_DEX_STRIDE: u64 = 10_000;
pub const TWAP_ID_OVERFLOW_THRESHOLD: u64 = 0x0CCC_CCCC_CCCC_CCCC;

/// Lowered in-memory asset-index view consumed by `sub_22C4630`.
///
/// The raw action serializer documents an `AssetIndex` object, but the handler
/// itself only reads the 32-bit wire asset at offset `+8`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TwapCancelAssetIndex {
    pub _opaque_prefix: u64,
    pub raw_wire_asset: WireAssetId,
    pub _opaque_suffix: u32,
}

/// Lowered handler-local view of the action payload.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TwapCancelAction {
    pub twap_id: TwapId,
    pub asset: TwapCancelAssetIndex,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutedAsset {
    Perp {
        global_asset: GlobalAssetId,
    },
    Spot {
        spot_asset: SpotAssetId,
    },
}

impl RoutedAsset {
    #[inline]
    pub const fn inferred_dex_id(self) -> Option<DexId> {
        match self {
            Self::Perp { global_asset } => Some(global_asset / TWAP_DEX_STRIDE),
            Self::Spot { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TwapCancelError {
    AssetClassification { status: u16 },
    TwapIdOverflow { twap_id: TwapId },
    SpotBranchDisabled,
    MissingTwap,
    UnknownStatus(u16),
}

impl TwapCancelError {
    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::AssetClassification { status } => status,
            Self::TwapIdOverflow { .. } => STATUS_TWAP_ID_OVERFLOW,
            Self::SpotBranchDisabled => STATUS_SPOT_TWAP_BRANCH_DISABLED,
            Self::MissingTwap => STATUS_MISSING_TWAP,
            Self::UnknownStatus(status) => status,
        }
    }

    #[inline]
    pub const fn from_status(status: u16) -> Self {
        match status {
            STATUS_SPOT_TWAP_BRANCH_DISABLED => Self::SpotBranchDisabled,
            STATUS_MISSING_TWAP => Self::MissingTwap,
            other => Self::UnknownStatus(other),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TwapCancelSuccess {
    pub twap_id: TwapId,
    pub route: RoutedAsset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TwapCancelOutcome {
    Success(TwapCancelSuccess),
    Error(TwapCancelError),
}

impl TwapCancelOutcome {
    #[inline]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Success(_) => OUTCOME_TAG_SUCCESS,
            Self::Error(_) => OUTCOME_TAG_ERROR,
        }
    }

    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::Success(_) => STATUS_OK,
            Self::Error(error) => error.status(),
        }
    }
}

/// Minimal exchange surface exercised by `0x22C4630 -> 0x2724580`.
///
/// Exact helper behavior per branch:
///
/// - classify the raw wire asset;
/// - reject oversized `twap_id` before any state mutation;
/// - for perp routes, derive `dex_id = global_asset / 10_000`, look up the
///   caller's TWAP tree inside that DEX, erase `twap_id`, compact the user tree
///   when it becomes empty, emit a perp frontend-order update, and persist the
///   rewritten row through the `sub_24FB610` path;
/// - for spot routes, first require the exchange gate at `state + 15048` to be
///   enabled, then erase `twap_id` from the global spot-TWAP tree, compact empty
///   user state, emit the spot frontend update, and persist through `sub_24FC8A0`.
///
/// Both branches treat a missing entry and a removed row already marked with
/// lifecycle byte `2` as the same `206` error.
pub trait TwapCancelEngine {
    fn classify_wire_asset(&self, raw_wire_asset: WireAssetId) -> Result<RoutedAsset, u16>;
    fn spot_twap_branch_enabled(&self) -> bool;

    fn cancel_perp_twap(&mut self, user: Address, dex_id: DexId, twap_id: TwapId) -> Result<(), u16>;
    fn cancel_spot_twap(&mut self, user: Address, twap_id: TwapId) -> Result<(), u16>;
}

#[inline]
pub fn apply_twap_cancel<E: TwapCancelEngine>(
    engine: &mut E,
    user: Address,
    action: &TwapCancelAction,
) -> TwapCancelOutcome {
    let route = match engine.classify_wire_asset(action.asset.raw_wire_asset) {
        Ok(route) => route,
        Err(status) => return TwapCancelOutcome::Error(TwapCancelError::AssetClassification { status }),
    };

    if action.twap_id >= TWAP_ID_OVERFLOW_THRESHOLD {
        return TwapCancelOutcome::Error(TwapCancelError::TwapIdOverflow {
            twap_id: action.twap_id,
        });
    }

    let status = match route {
        RoutedAsset::Perp { .. } => {
            let dex_id = route.inferred_dex_id().expect("perp route must produce dex id");
            engine.cancel_perp_twap(user, dex_id, action.twap_id)
        }
        RoutedAsset::Spot { .. } => {
            if !engine.spot_twap_branch_enabled() {
                return TwapCancelOutcome::Error(TwapCancelError::SpotBranchDisabled);
            }
            engine.cancel_spot_twap(user, action.twap_id)
        }
    };

    match status {
        Ok(()) => TwapCancelOutcome::Success(TwapCancelSuccess {
            twap_id: action.twap_id,
            route,
        }),
        Err(status) => TwapCancelOutcome::Error(TwapCancelError::from_status(status)),
    }
}
