#![allow(dead_code)]

pub type Address = [u8; 20];
pub type AssetId = u64;
pub type DexId = u64;
pub type SpotUniverseId = u64;

pub const UPDATE_ISOLATED_MARGIN_HANDLER_EA: u64 = 0x21E2_B60;
pub const UPDATE_ISOLATED_MARGIN_CORE_EA: u64 = 0x2722_010;

pub const WRAPPER_TAG_APPLIED: u8 = 13;
pub const WRAPPER_TAG_REJECTED: u8 = 14;
pub const STATUS_SUCCESS: u16 = 390;
pub const STATUS_PERP_ASSET_REQUIRED: u16 = 350;
pub const STATUS_NTLI_ABS_OVERFLOW: u16 = 319;
pub const STATUS_REQUIRED_ROUTING_SET_MISS: u16 = 368;
pub const STATUS_UNKNOWN_DEX: u16 = 321;

/// Generic clearinghouse result tags surfaced by `apply_user_asset_position_delta`.
/// The protocol error table gives these action-local names such as
/// `UpdateIsolatedMarginUnknownUser`, `UpdateIsolatedMarginZeroNtli`,
/// `UpdateIsolatedMarginEmptyPosition`, and so on.
pub const STATUS_MISSING_USER_FOR_POSITION_DELTA: u16 = 72;
pub const STATUS_ZERO_POSITION_DELTA: u16 = 73;
pub const STATUS_MISSING_ASSET_CONTEXT: u16 = 74;
pub const STATUS_POSITION_DELTA_TOO_LARGE: u16 = 75;
pub const STATUS_MARGIN_WOULD_BE_NEGATIVE: u16 = 76;
pub const STATUS_NON_NORMAL_POSITION_CONTEXT: u16 = 77;
pub const STATUS_DELISTED_ASSET_CANNOT_BE_REDUCED_HERE: u16 = 78;
pub const STATUS_SIGNED_POSITION_OVERFLOW: u16 = 190;

/// The wrapper rejects when `abs(ntli)` reaches this threshold before the routed
/// helper runs.  The compare in `sub_21E2B60` is against `0x0CCC_CCCC_CCCC_CCCC`.
pub const NTLI_ABS_LIMIT_EXCLUSIVE: u64 = u64::MAX / 20;
pub const PERP_ASSET_STRIDE: AssetId = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct UpdateIsolatedMarginAction {
    /// API-facing wire asset id.  `sub_21E2B60` immediately classifies it through
    /// `l1_dex_registry_clearinghouses__classify_wire_asset_id` and rejects spot ids.
    pub asset: u32,
    /// Signed isolated-margin delta in the handler's ntl-like lot units.
    pub ntli: i64,
    /// Present in the serialized action (`"isBuy"`) but not consumed by the apply path
    /// recovered here.
    pub is_buy: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutedAsset {
    Perp {
        global_asset: AssetId,
        dex_id: DexId,
        local_asset: u32,
    },
    Spot {
        spot_universe_id: SpotUniverseId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserClass {
    SpotOnly,
    Legacy,
    AbstractionOptIn,
    DexUser,
    PrivilegedDexUser,
    Other(u8),
}

impl UserClass {
    #[inline]
    pub const fn status_byte(self) -> u8 {
        match self {
            Self::SpotOnly => 0,
            Self::Legacy => 1,
            Self::AbstractionOptIn => 2,
            Self::DexUser => 3,
            Self::PrivilegedDexUser => 4,
            Self::Other(byte) => byte,
        }
    }

    #[inline]
    pub const fn is_privileged(self) -> bool {
        self.status_byte() >= 4
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpdateIsolatedMarginResult {
    pub tag: u8,
    pub status: u16,
    pub asset: Option<AssetId>,
    pub settlement_asset: Option<AssetId>,
    pub routed: bool,
    pub privileged_route: bool,
}

impl UpdateIsolatedMarginResult {
    #[inline]
    pub const fn from_status(
        status: u16,
        asset: AssetId,
        settlement_asset: Option<AssetId>,
        routed: bool,
        privileged_route: bool,
    ) -> Self {
        Self {
            tag: if status == STATUS_SUCCESS {
                WRAPPER_TAG_APPLIED
            } else {
                WRAPPER_TAG_REJECTED
            },
            status,
            asset: Some(asset),
            settlement_asset,
            routed,
            privileged_route,
        }
    }

    #[inline]
    pub const fn rejected(status: u16) -> Self {
        Self {
            tag: WRAPPER_TAG_REJECTED,
            status,
            asset: None,
            settlement_asset: None,
            routed: false,
            privileged_route: false,
        }
    }
}

/// Minimal state interface needed by the recovered handler.
///
/// The routing branch is the same abstraction gate recovered in
/// `recon/l1/src/exchange/impl_abstraction.rs::route_dex_action`, specialized to an
/// `AssetPositionDelta` request whose direct mutation is the clearinghouse helper
/// `apply_user_asset_position_delta(user, asset, ntli)`.
pub trait UpdateIsolatedMarginEngine {
    fn classify_wire_asset(&self, raw_asset: u32) -> Result<RoutedAsset, u16>;
    fn user_class(&self, user: Address) -> UserClass;

    fn disable_low_class_direct_path(&self) -> bool;
    fn disable_privileged_direct_path(&self) -> bool;
    fn dex_abstraction_enabled(&self) -> bool;

    fn settlement_asset(&self, dex_id: DexId) -> Result<AssetId, u16>;

    /// Mirrors the status-2 preflight settlement helper call.
    fn pre_settlement_recheck(&mut self, user: Address, settlement_asset: AssetId, enter_as_spot: bool) -> u16;

    /// Mirrors the post-mutation settlement helper call used by status-2 and status-3
    /// routed users.
    fn post_settlement_recheck(
        &mut self,
        user: Address,
        settlement_asset: AssetId,
        dex_id: DexId,
        exit_via_spot: bool,
    ) -> u16;

    /// Mirrors the dual required-set membership test.  On success this MUST also bump
    /// the per-user accepted counter and the global routed-action counter.
    fn accept_routed_margin_delta(&mut self, user: Address) -> bool;

    /// Mirrors the routed pre-mutation helper (`sub_272FE00`).
    fn pre_routed_margin_delta(
        &mut self,
        user: Address,
        settlement_asset: AssetId,
        dex_id: DexId,
        privileged: bool,
    );

    /// Mirrors the privileged finalize helper (`sub_272F880`).
    fn finalize_privileged_margin_delta(&mut self, user: Address, settlement_asset: AssetId, dex_id: DexId);

    /// Direct clearinghouse mutation: `apply_user_asset_position_delta(user, asset, ntli)`.
    fn apply_asset_position_delta(&mut self, user: Address, asset: AssetId, delta: i64) -> u16;
}

/// Recovered apply wrapper for `UpdateIsolatedMargin`.
///
/// High-confidence flow from `sub_21E2B60` + `sub_2722010`:
/// 1. Classify the API wire asset and reject non-perp assets with `350`.
/// 2. Reject oversized `abs(ntli)` before any state mutation with `319`.
/// 3. Route through the same abstraction gate used by other perp asset actions:
///    - classes 0/1 are always direct;
///    - class 2 can run a pre/post settlement rebalance around the direct mutation;
///    - classes 3/4 require membership in one of the routed-user acceptance sets.
/// 4. The direct mutation is the clearinghouse helper
///    `apply_user_asset_position_delta(user, asset, ntli)`.
/// 5. Privileged routed users run a post-apply privileged finalize helper instead of the
///    normal settlement recheck.
///
/// The generic user-action nonce gate runs before dispatch enters this handler; there is
/// no handler-local nonce check here.
pub fn apply_update_isolated_margin<E: UpdateIsolatedMarginEngine>(
    engine: &mut E,
    user: Address,
    action: &UpdateIsolatedMarginAction,
) -> UpdateIsolatedMarginResult {
    let routed = match engine.classify_wire_asset(action.asset) {
        Ok(routed) => routed,
        Err(status) => return UpdateIsolatedMarginResult::rejected(status),
    };

    let (asset, dex_id) = match routed {
        RoutedAsset::Perp {
            global_asset,
            dex_id,
            ..
        } => (global_asset, dex_id),
        RoutedAsset::Spot { .. } => return UpdateIsolatedMarginResult::rejected(STATUS_PERP_ASSET_REQUIRED),
    };

    let delta_abs = action.ntli.unsigned_abs();
    if delta_abs >= NTLI_ABS_LIMIT_EXCLUSIVE {
        return UpdateIsolatedMarginResult::rejected(STATUS_NTLI_ABS_OVERFLOW);
    }

    let class = engine.user_class(user);
    let status = class.status_byte();
    let direct = status < 2
        || (status < 4 && engine.disable_low_class_direct_path())
        || (status >= 4 && engine.disable_privileged_direct_path())
        || (status == 2 && (!engine.dex_abstraction_enabled() || asset < PERP_ASSET_STRIDE));

    if direct {
        return UpdateIsolatedMarginResult::from_status(
            engine.apply_asset_position_delta(user, asset, action.ntli),
            asset,
            None,
            false,
            false,
        );
    }

    if status == 2 {
        let settlement_asset = match engine.settlement_asset(dex_id) {
            Ok(asset) => asset,
            Err(code) => return UpdateIsolatedMarginResult::rejected(code),
        };
        let enter_as_spot = settlement_asset == 0;

        let pre = engine.pre_settlement_recheck(user, settlement_asset, enter_as_spot);
        if pre != STATUS_SUCCESS {
            return UpdateIsolatedMarginResult::from_status(pre, asset, Some(settlement_asset), true, false);
        }

        let apply = engine.apply_asset_position_delta(user, asset, action.ntli);
        if engine.dex_abstraction_enabled() {
            let post = engine.post_settlement_recheck(user, settlement_asset, dex_id, enter_as_spot);
            if post != STATUS_SUCCESS {
                return UpdateIsolatedMarginResult::from_status(post, asset, Some(settlement_asset), true, false);
            }
        }

        return UpdateIsolatedMarginResult::from_status(apply, asset, Some(settlement_asset), true, false);
    }

    if !engine.accept_routed_margin_delta(user) {
        return UpdateIsolatedMarginResult::from_status(STATUS_REQUIRED_ROUTING_SET_MISS, asset, None, true, class.is_privileged());
    }

    let settlement_asset = match engine.settlement_asset(dex_id) {
        Ok(asset) => asset,
        Err(code) => return UpdateIsolatedMarginResult::rejected(code),
    };

    engine.pre_routed_margin_delta(user, settlement_asset, dex_id, class.is_privileged());
    let apply = engine.apply_asset_position_delta(user, asset, action.ntli);

    if class.is_privileged() {
        engine.finalize_privileged_margin_delta(user, settlement_asset, dex_id);
        return UpdateIsolatedMarginResult::from_status(apply, asset, Some(settlement_asset), true, true);
    }

    let post = engine.post_settlement_recheck(user, settlement_asset, dex_id, false);
    if post != STATUS_SUCCESS {
        return UpdateIsolatedMarginResult::from_status(post, asset, Some(settlement_asset), true, false);
    }

    UpdateIsolatedMarginResult::from_status(apply, asset, Some(settlement_asset), true, false)
}
