#![allow(dead_code)]

pub type Address = [u8; 20];
pub type AssetId = u64;
pub type DexId = u64;

pub const UPDATE_LEVERAGE_HANDLER_EA: u64 = 0x21E0_B70;
pub const UPDATE_LEVERAGE_APPLY_EA: u64 = 0x2721_860;
pub const SET_USER_ASSET_LEVERAGE_MODE_EA: u64 = 0x3709_8A0;

pub const WRAPPER_TAG_APPLIED: u8 = 13;
pub const WRAPPER_TAG_REJECTED: u8 = 14;

pub const STATUS_SUCCESS: u16 = 390;
pub const STATUS_PERP_ASSET_REQUIRED: u16 = 350;
pub const STATUS_REQUIRED_ROUTING_SET_MISS: u16 = 368;

/// `l1_perp_meta__set_user_asset_leverage_mode` rejects these compact result tags.
pub const STATUS_INVALID_MAX_LEVERAGE: u16 = 67;
pub const STATUS_CROSS_MARGIN_NOT_ALLOWED: u16 = 68;
pub const STATUS_LEVERAGE_TYPE_OPEN_POSITION: u16 = 69;
pub const STATUS_CROSS_LEVERAGE_DECREASE_INSUFFICIENT_MARGIN: u16 = 70;
pub const STATUS_ISOLATED_LEVERAGE_DECREASE_INSUFFICIENT_MARGIN: u16 = 71;
pub const STATUS_MARGIN_TABLE_WOULD_INCREASE_REQUIREMENT: u16 = 79;
pub const STATUS_MAX_LEVERAGE_TOO_BIG_FOR_POSITION: u16 = 80;

pub const PERP_ASSET_STRIDE: AssetId = 10_000;

/// Recovered in-memory payload layout consumed by `0x21E0B70`.
///
/// The public API names this action `updateLeverage` with fields `asset`,
/// `isCross`, and `leverage`, but the normalized struct reaching the handler is
/// laid out as `leverage @ +0x00`, `asset @ +0x04`, `is_cross @ +0x08`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct UpdateLeverageAction {
    pub leverage: u32,
    pub asset: u32,
    pub is_cross: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutedAsset {
    Perp {
        global_asset: AssetId,
        dex_id: DexId,
        local_asset: u32,
    },
    Spot {
        spot_universe_id: u64,
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
pub struct UpdateLeverageResult {
    pub tag: u8,
    pub status: u16,
    pub asset: Option<AssetId>,
    pub dex_id: Option<DexId>,
    pub settlement_asset: Option<AssetId>,
    pub routed: bool,
    pub privileged_route: bool,
    pub is_cross: bool,
    pub leverage: u32,
}

impl UpdateLeverageResult {
    #[inline]
    pub const fn from_status(
        status: u16,
        asset: AssetId,
        dex_id: DexId,
        settlement_asset: Option<AssetId>,
        routed: bool,
        privileged_route: bool,
        is_cross: bool,
        leverage: u32,
    ) -> Self {
        Self {
            tag: if status == STATUS_SUCCESS {
                WRAPPER_TAG_APPLIED
            } else {
                WRAPPER_TAG_REJECTED
            },
            status,
            asset: Some(asset),
            dex_id: Some(dex_id),
            settlement_asset,
            routed,
            privileged_route,
            is_cross,
            leverage,
        }
    }

    #[inline]
    pub const fn rejected(status: u16, is_cross: bool, leverage: u32) -> Self {
        Self {
            tag: WRAPPER_TAG_REJECTED,
            status,
            asset: None,
            dex_id: None,
            settlement_asset: None,
            routed: false,
            privileged_route: false,
            is_cross,
            leverage,
        }
    }
}

pub trait UpdateLeverageEngine {
    fn classify_wire_asset(&self, raw_asset: u32) -> Result<RoutedAsset, u16>;
    fn user_class(&self, user: Address) -> UserClass;

    /// Mirrors the feature bit at exchange offset `+1457`.
    ///
    /// When enabled, class-2 and class-3 users stay on the direct path instead of
    /// going through the routed cross-DEX machinery.
    fn low_class_direct_path_enabled(&self) -> bool;

    /// Mirrors the feature bit at exchange offset `+1456`.
    ///
    /// When enabled, class-4+ users bypass the routed cross-DEX machinery and go
    /// straight to `set_user_asset_leverage_mode`.
    fn privileged_direct_path_enabled(&self) -> bool;

    /// Mirrors exchange byte `+15051`.  Class-2 users only enter the cross-DEX
    /// abstraction path when this is enabled and the asset is not on the first DEX.
    fn dex_abstraction_enabled(&self) -> bool;

    /// Resolve the collateral/settlement asset attached to a DEX.
    fn settlement_asset(&self, dex_id: DexId) -> AssetId;

    /// Best-effort settlement rebalance used around class-2 cross-DEX leverage
    /// changes and after non-privileged routed updates.  The binary logs failures
    /// from this helper but still returns the leverage-update status.
    fn best_effort_cross_dex_rebalance(
        &mut self,
        user: Address,
        settlement_asset: AssetId,
        dex_id: DexId,
        exit_via_spot: bool,
    );

    /// Pre-hook used only for class-3/class-4 routed users before the leverage
    /// mutation runs.
    fn pre_routed_leverage_update(
        &mut self,
        user: Address,
        settlement_asset: AssetId,
        dex_id: DexId,
        privileged: bool,
    );

    /// Membership test against the two recovered routed-user acceptance sets.
    /// A successful check MUST also bump the per-user accepted counter and the
    /// global routed-action counter, matching `0x2721860`.
    fn accept_routed_leverage_update(&mut self, user: Address) -> bool;

    /// Class-4 routed users finalize through a distinct privileged helper instead
    /// of the normal best-effort rebalance.
    fn finalize_privileged_leverage_update(
        &mut self,
        user: Address,
        settlement_asset: AssetId,
        dex_id: DexId,
    );

    /// Final state mutation: update or create the user's per-asset position record.
    ///
    /// Recovered effects from `l1_perp_meta__set_user_asset_leverage_mode`:
    /// - reject cross mode on isolated-only assets with `68`;
    /// - cap requested leverage against asset/table limits with `67` or `80`;
    /// - reject changing cross/isolated mode while a non-flat position exists with `69`;
    /// - reject leverage/table changes that would under-collateralize the user with `70`,
    ///   `71`, or `79`;
    /// - on success, insert/update the per-asset position record, refresh oracle-context
    ///   metadata, and update the open-interest / active-user indexes.
    fn set_user_asset_leverage_mode(
        &mut self,
        user: Address,
        asset: AssetId,
        is_cross: bool,
        leverage: u32,
    ) -> u16;
}

/// Recovered apply flow from `l1_exchange_impl_execute_action__update_leverage`
/// (`0x21E0B70`) and `l1_exchange_impl_execute_action__update_leverage_apply`
/// (`0x2721860`).
///
/// Ordering matters:
/// 1. classify the wire asset and reject spot ids with `350`;
/// 2. choose one of three execution modes based on user class and feature bits:
///    - direct mutation for class `< 2`, for classes forced direct by feature flags,
///      and for class `2` main-dex assets or when DEX abstraction is disabled;
///    - class `2` cross-DEX route: best-effort settlement rebalance, leverage update,
///      then another best-effort rebalance;
///    - class `3`/`4` routed path: require membership in one of the routed-user sets,
///      run the routed pre-hook, apply the leverage change, then either finalize the
///      privileged route or run the normal best-effort rebalance;
/// 3. return wrapper tag `13` only when the leverage update itself returns `390`.
///
/// The generic signed-action nonce gate already ran in `impl_execute_action` before
/// this handler is entered.
pub fn apply_update_leverage<E: UpdateLeverageEngine>(
    engine: &mut E,
    user: Address,
    action: &UpdateLeverageAction,
) -> UpdateLeverageResult {
    let routed = match engine.classify_wire_asset(action.asset) {
        Ok(routed) => routed,
        Err(status) => return UpdateLeverageResult::rejected(status, action.is_cross, action.leverage),
    };

    let (asset, dex_id) = match routed {
        RoutedAsset::Perp {
            global_asset,
            dex_id,
            ..
        } => (global_asset, dex_id),
        RoutedAsset::Spot { .. } => {
            return UpdateLeverageResult::rejected(
                STATUS_PERP_ASSET_REQUIRED,
                action.is_cross,
                action.leverage,
            )
        }
    };

    let class = engine.user_class(user);
    let status = class.status_byte();
    let direct = status < 2
        || (status < 4 && engine.low_class_direct_path_enabled())
        || (status >= 4 && engine.privileged_direct_path_enabled())
        || (status == 2 && (!engine.dex_abstraction_enabled() || asset < PERP_ASSET_STRIDE));

    if direct {
        return UpdateLeverageResult::from_status(
            engine.set_user_asset_leverage_mode(user, asset, action.is_cross, action.leverage),
            asset,
            dex_id,
            None,
            false,
            false,
            action.is_cross,
            action.leverage,
        );
    }

    if status == 2 {
        let settlement_asset = engine.settlement_asset(dex_id);
        let exit_via_spot = settlement_asset == 0;

        engine.best_effort_cross_dex_rebalance(user, settlement_asset, dex_id, exit_via_spot);
        let apply = engine.set_user_asset_leverage_mode(user, asset, action.is_cross, action.leverage);
        engine.best_effort_cross_dex_rebalance(user, settlement_asset, dex_id, exit_via_spot);

        return UpdateLeverageResult::from_status(
            apply,
            asset,
            dex_id,
            Some(settlement_asset),
            true,
            false,
            action.is_cross,
            action.leverage,
        );
    }

    if !engine.accept_routed_leverage_update(user) {
        return UpdateLeverageResult::from_status(
            STATUS_REQUIRED_ROUTING_SET_MISS,
            asset,
            dex_id,
            None,
            true,
            class.is_privileged(),
            action.is_cross,
            action.leverage,
        );
    }

    let settlement_asset = engine.settlement_asset(dex_id);
    engine.pre_routed_leverage_update(user, settlement_asset, dex_id, class.is_privileged());

    let apply = engine.set_user_asset_leverage_mode(user, asset, action.is_cross, action.leverage);
    if class.is_privileged() {
        engine.finalize_privileged_leverage_update(user, settlement_asset, dex_id);
        return UpdateLeverageResult::from_status(
            apply,
            asset,
            dex_id,
            Some(settlement_asset),
            true,
            true,
            action.is_cross,
            action.leverage,
        );
    }

    engine.best_effort_cross_dex_rebalance(user, settlement_asset, dex_id, false);
    UpdateLeverageResult::from_status(
        apply,
        asset,
        dex_id,
        Some(settlement_asset),
        true,
        false,
        action.is_cross,
        action.leverage,
    )
}
