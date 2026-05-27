#![allow(dead_code)]

pub type Address = [u8; 20];
pub type AssetId = u64;

pub const SYSTEM_BOLE_HANDLER_EA: u64 = 0x1F69_020;
pub const SYSTEM_BOLE_CORE_EA: u64 = 0x2764_D60;
pub const WRAPPER_TAG_APPLIED: u8 = 13;
pub const WRAPPER_TAG_REJECTED: u8 = 14;

pub const STATUS_SUCCESS: u16 = 390;
pub const STATUS_OWNER_MISMATCH: u16 = 21;
pub const STATUS_DIRECT_IMPL_REJECTED_WITH_SUBCODE: u16 = 225;
pub const STATUS_DIRECT_IMPL_MISSING_FOLLOWUP: u16 = 226;
pub const STATUS_UNKNOWN_COLLATERAL: u16 = 234;
pub const STATUS_AMOUNT_OVERFLOW: u16 = 319;
pub const STATUS_ZERO_EXACT_AMOUNT: u16 = 348;
pub const STATUS_REQUIRED_ROUTING_SET_MISS: u16 = 368;
pub const STATUS_PRIVILEGED_DIRECT_PATH_REQUIRED: u16 = 371;

/// The exact-amount arm rejects when the raw quantity is greater than
/// `0x0CCC_CCCC_CCCC_CCCB`; this mirrors the guard in `sub_1F69020`.
pub const MAX_EXACT_AMOUNT: u64 = 0x0CCC_CCCC_CCCC_CCCB;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemBoleAmount {
    /// `word0 == 0` in the recovered 25-byte payload.  The core helper treats this as
    /// the special non-exact mode and ignores the numeric quantity field.
    Special,
    /// `word0 != 0`, `word1 != 0`, and `word1 <= MAX_EXACT_AMOUNT`.
    Exact(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemBoleOp {
    /// `op & 1 == 0`, increasing lane 0.
    Lane0Increase,
    /// `op & 1 == 1`, increasing lane 1.
    Lane1Increase,
    /// `op & 1 == 0`, decreasing lane 0.
    Lane0Decrease,
    /// `op & 1 == 1`, decreasing lane 1.
    Lane1Decrease,
    Recovered(u8),
}

impl SystemBoleOp {
    #[inline]
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Lane0Increase,
            1 => Self::Lane1Increase,
            2 => Self::Lane0Decrease,
            3 => Self::Lane1Decrease,
            other => Self::Recovered(other),
        }
    }

    #[inline]
    pub const fn raw(self) -> u8 {
        match self {
            Self::Lane0Increase => 0,
            Self::Lane1Increase => 1,
            Self::Lane0Decrease => 2,
            Self::Lane1Decrease => 3,
            Self::Recovered(other) => other,
        }
    }

    #[inline]
    pub const fn uses_lane1(self) -> bool {
        (self.raw() & 1) != 0
    }

    #[inline]
    pub const fn decreases(self) -> bool {
        matches!(self.raw(), 2 | 3)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemBoleAction {
    pub amount: SystemBoleAmount,
    pub asset: AssetId,
    pub op: SystemBoleOp,
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
pub struct SystemBoleResult {
    pub tag: u8,
    pub status: u16,
    pub routed: bool,
    pub privileged_route: bool,
    pub asset: Option<AssetId>,
}

impl SystemBoleResult {
    #[inline]
    pub const fn applied() -> Self {
        Self {
            tag: WRAPPER_TAG_APPLIED,
            status: STATUS_SUCCESS,
            routed: false,
            privileged_route: false,
            asset: None,
        }
    }

    #[inline]
    pub const fn rejected(status: u16, asset: Option<AssetId>, routed: bool, privileged_route: bool) -> Self {
        Self {
            tag: WRAPPER_TAG_REJECTED,
            status,
            routed,
            privileged_route,
            asset,
        }
    }
}

/// Minimal abstraction over the state touched by `sub_2764D60`.
///
/// High-confidence recovery points:
/// - the wrapper validates `asset < asset_count`, exact amounts are non-zero and below
///   `MAX_EXACT_AMOUNT`, then calls the shared BOLE helper;
/// - privileged users (`class >= 4`) are rejected with `371` unless the exchange-wide
///   privileged-direct bit is set;
/// - class-3 and class-4 users may be routed through the same acceptance-set path used
///   by other abstraction-gated exchange actions, producing `368` on a set miss;
/// - all other classes stay on the direct helper path.
pub trait SystemBoleEngine {
    fn asset_count(&self) -> u64;
    fn user_class(&self, user: Address) -> UserClass;

    /// Mirrors the class-4 gate checked before any user normalization or asset lookup.
    fn allow_privileged_direct_path(&self) -> bool;
    /// Mirrors the class-3 routing branch bit tested inside `sub_2764D60`.
    fn allow_class3_direct_path(&self) -> bool;

    /// Mirrors the `sub_373C9C0(...) == 10` preflight.  Any non-`Ok(())` value is
    /// surfaced as status `225` by the binary.
    fn normalize_user_for_bole(&self, user: Address) -> Result<(), u8>;

    /// Mirrors the collateral-id tree lookup rooted at `exchange + 1384`.
    fn asset_exists(&self, asset: AssetId) -> bool;

    /// Mirrors the optional per-user entry lookup rooted at `exchange + 2256`.
    ///
    /// When an entry exists, lane-1 operations (`raw op 1/3`) are only allowed if the
    /// entry flag is set and the asset id is zero; otherwise the helper returns `21`.
    fn user_lane1_gate_flag(&self, user: Address) -> Option<bool>;

    /// MUST mirror the dual routed-user set membership test and the counter bumps that
    /// happen on success.
    fn accept_routed_bole(&mut self, user: Address, asset: AssetId) -> bool;

    /// Mirrors the routed pre-mutation helper (`sub_272FE00`).
    fn pre_routed_bole(&mut self, user: Address, asset: AssetId, privileged: bool);

    /// Core BOLE mutation performed by the direct helper `sub_2732AE0`.
    fn apply_core_bole(&mut self, user: Address, action: SystemBoleAction) -> u16;

    /// Mirrors the privileged finalize helper (`sub_272F880`).
    fn finalize_privileged_bole(&mut self, user: Address, asset: AssetId);

    /// Mirrors the non-privileged follow-up transfer/reconciliation helper
    /// `l1_qtys_impl_ntl__sub_compute_and_apply_cross_asset_ntl_transfer(...)`.
    fn apply_cross_asset_followup(&mut self, user: Address, asset: AssetId, action: SystemBoleAction) -> u16;
}

#[inline]
pub fn apply_system_bole<E: SystemBoleEngine>(
    engine: &mut E,
    user: Address,
    action: SystemBoleAction,
) -> SystemBoleResult {
    if action.asset >= engine.asset_count() {
        return SystemBoleResult::rejected(STATUS_UNKNOWN_COLLATERAL, Some(action.asset), false, false);
    }

    if let SystemBoleAmount::Exact(amount) = action.amount {
        if amount > MAX_EXACT_AMOUNT {
            return SystemBoleResult::rejected(STATUS_AMOUNT_OVERFLOW, Some(action.asset), false, false);
        }
        if amount == 0 {
            return SystemBoleResult::rejected(STATUS_ZERO_EXACT_AMOUNT, Some(action.asset), false, false);
        }
    }

    let class = engine.user_class(user);
    if class.is_privileged() && !engine.allow_privileged_direct_path() {
        return SystemBoleResult::rejected(
            STATUS_PRIVILEGED_DIRECT_PATH_REQUIRED,
            Some(action.asset),
            false,
            true,
        );
    }

    if engine.normalize_user_for_bole(user).is_err() {
        return SystemBoleResult::rejected(
            STATUS_DIRECT_IMPL_REJECTED_WITH_SUBCODE,
            Some(action.asset),
            false,
            class.is_privileged(),
        );
    }
    if !engine.asset_exists(action.asset) {
        return SystemBoleResult::rejected(
            STATUS_DIRECT_IMPL_REJECTED_WITH_SUBCODE,
            Some(action.asset),
            false,
            class.is_privileged(),
        );
    }

    if action.op.uses_lane1()
        && matches!(engine.user_lane1_gate_flag(user), Some(flag) if !(flag && action.asset == 0))
    {
        return SystemBoleResult::rejected(STATUS_OWNER_MISMATCH, Some(action.asset), false, class.is_privileged());
    }

    let routed = match class.status_byte() {
        0..=2 => false,
        3 => !engine.allow_class3_direct_path(),
        _ => !engine.allow_privileged_direct_path(),
    };

    if !routed {
        let status = engine.apply_core_bole(user, action);
        return if status == STATUS_SUCCESS {
            SystemBoleResult::applied()
        } else {
            SystemBoleResult::rejected(status, Some(action.asset), false, class.is_privileged())
        };
    }

    if !engine.accept_routed_bole(user, action.asset) {
        return SystemBoleResult::rejected(
            STATUS_REQUIRED_ROUTING_SET_MISS,
            Some(action.asset),
            true,
            class.is_privileged(),
        );
    }

    engine.pre_routed_bole(user, action.asset, class.is_privileged());
    let status = engine.apply_core_bole(user, action);
    if class.is_privileged() {
        engine.finalize_privileged_bole(user, action.asset);
    } else {
        let followup = engine.apply_cross_asset_followup(user, action.asset, action);
        if followup == STATUS_DIRECT_IMPL_MISSING_FOLLOWUP && status == STATUS_SUCCESS {
            return SystemBoleResult::rejected(followup, Some(action.asset), true, false);
        }
    }

    if status == STATUS_SUCCESS {
        SystemBoleResult {
            tag: WRAPPER_TAG_APPLIED,
            status,
            routed: true,
            privileged_route: class.is_privileged(),
            asset: Some(action.asset),
        }
    } else {
        SystemBoleResult::rejected(status, Some(action.asset), true, class.is_privileged())
    }
}
