#![allow(dead_code)]

use core::convert::TryFrom;

pub type Address = [u8; 20];
pub type Nonce = u64;
pub type TimestampMillis = u64;
pub type Usd = u64;
pub type RouteKey = u64;

pub const WITHDRAW3_HANDLER_EA: u64 = 0x1F67_810;
pub const WITHDRAW3_STATE_HELPER_EA: u64 = 0x2732_530;
pub const WITHDRAW3_CORE_HELPER_EA: u64 = 0x2734_200;
pub const WITHDRAW3_NONCE_SCALE: u64 = 1_000;
pub const MAX_WIRE_STRING_LEN: usize = 100;

pub const WRAPPER_TAG_APPLIED: u8 = 13;
pub const WRAPPER_TAG_REJECTED: u8 = 14;

pub const STATUS_OK: u16 = 390;
pub const STATUS_REQUIRED_SET_MISS: u16 = 368;
pub const STATUS_STRING_TOO_LONG: u16 = 323;
pub const STATUS_NONCE_ALREADY_USED: u16 = 90;
pub const STATUS_INVALID_DESTINATION: u16 = 182;
pub const STATUS_NONCE_ARITHMETIC: u16 = 198;
/// [INFERENCE] `sub_3C097B0` returns `48` when the parsed decimal quantizes to zero.
pub const STATUS_ZERO_USD: u16 = 48;
/// [INFERENCE] `sub_2734200` returns `39` when the quantized withdrawal exceeds the
/// first clearinghouse bridge limit loaded from `exchange[844]`.
pub const STATUS_USD_ABOVE_BRIDGE_LIMIT: u16 = 39;
/// [INFERENCE] `sub_2734200` returns `40` on the follow-on bridge accounting overflow
/// guard around the first clearinghouse bridge bucket.
pub const STATUS_BRIDGE_BUCKET_OVERFLOW: u16 = 40;
/// [INFERENCE] The leading guard in `sub_2734200` returns `117` before any string
/// parsing when the exchange-level timing/window predicate fails.
pub const STATUS_ENVIRONMENT_WINDOW_REJECTED: u16 = 117;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Withdraw3Action {
    /// API field `destination`.
    pub destination: String,
    /// API field `usd`.
    pub usd: String,
    /// API field `nonce`. The shared signed-action nonce path consumes this first,
    /// then the handler reuses it for the local monotonic replay slot.
    pub nonce: Nonce,
    /// Serialized and signed upstream, but not consumed directly by the apply core.
    pub signature_chain_id: [u8; 32],
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
pub struct Withdraw3RoutingConfig {
    /// `exchange[1457] & 1` in `l1_action_withdraw3__apply_state_main`.
    pub allow_class2_direct_path: bool,
    /// `exchange[1456] & 1` in `l1_action_withdraw3__apply_state_main`.
    pub allow_privileged_direct_path: bool,
    /// `exchange[15051] == 1` in the class-2 mirror branch.
    pub class2_mirror_enabled: bool,
    /// `*a6 >= 2` gate in the class-2 mirror branch.
    pub routed_count: u64,
    /// `a5` / table-derived route key used by the routed helpers.
    pub route_key: RouteKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Withdraw3Phase {
    Direct,
    /// User class 2 special path: run the settlement/NTL helper before the core,
    /// then optionally repeat the mirrored helper after the core succeeds.
    Class2Mirrored { route_key: RouteKey },
    /// Required-set path used for class-3 users and for privileged users when the
    /// direct path feature bit is disabled.
    Routed {
        route_key: RouteKey,
        privileged_finalize: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Withdraw3Applied {
    pub destination: Address,
    pub usd: Usd,
    pub nonce_ms: TimestampMillis,
    pub phase: Withdraw3Phase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Withdraw3Result {
    pub tag: u8,
    pub status: u16,
    pub applied: Option<Withdraw3Applied>,
}

impl Withdraw3Result {
    #[inline]
    pub const fn ok(applied: Withdraw3Applied) -> Self {
        Self {
            tag: WRAPPER_TAG_APPLIED,
            status: STATUS_OK,
            applied: Some(applied),
        }
    }

    #[inline]
    pub const fn rejected(status: u16) -> Self {
        Self {
            tag: WRAPPER_TAG_REJECTED,
            status,
            applied: None,
        }
    }
}

pub trait Withdraw3Engine {
    fn user_class(&self, user: Address) -> UserClass;
    fn routing_config(&self) -> Withdraw3RoutingConfig;

    /// Mirrors the leading non-string guard in `sub_2734200` that can return `117`.
    fn validate_environment_window(&self, user: Address) -> Result<(), u16>;

    fn last_withdraw3_nonce_ms(&self, user: Address) -> Option<TimestampMillis>;
    fn parse_withdraw_usd(&self, usd: &str) -> Result<Usd, u16>;
    fn parse_destination(&self, destination: &str) -> Result<Address, u16>;
    fn max_bridge_withdraw_usd(&self) -> Usd;
    fn apply_first_dex_withdrawal(&mut self, user: Address, usd: Usd) -> Result<(), u16>;
    fn record_withdrawal_signature_and_debit(
        &mut self,
        user: Address,
        destination: Address,
        usd: Usd,
        nonce_ms: TimestampMillis,
    );
    fn remember_withdraw3_nonce(&mut self, user: Address, nonce_ms: TimestampMillis);
    fn clear_withdraw3_pending_flag(&mut self, user: Address);
    fn add_user_ntl_volume_scaled(&mut self, user: Address, delta: i64);

    /// Mirrors the dual membership check in `l1_action_withdraw3__apply_state_main`.
    /// On success this MUST also bump the per-user/global routed-withdraw counters.
    fn accept_routed_withdraw(&mut self, user: Address) -> bool;

    /// Mirrors `sub_272FE00`.
    fn prepare_routed_withdraw(&mut self, user: Address, route_key: RouteKey, privileged_user: bool);
    /// Mirrors `sub_272F880`.
    fn finalize_privileged_routed_withdraw(&mut self, user: Address, route_key: RouteKey);
    /// Mirrors `l1_qtys_impl_ntl__sub_compute_and_apply_cross_asset_ntl_transfer`.
    fn reconcile_routed_withdraw(&mut self, user: Address, route_key: RouteKey) -> Result<(), u16>;
}

#[inline]
pub fn classify_withdraw3_phase(class: UserClass, cfg: Withdraw3RoutingConfig) -> Withdraw3Phase {
    match class {
        UserClass::SpotOnly | UserClass::Legacy => Withdraw3Phase::Direct,
        UserClass::AbstractionOptIn => {
            if cfg.allow_class2_direct_path {
                Withdraw3Phase::Direct
            } else if cfg.class2_mirror_enabled && cfg.routed_count >= 2 {
                Withdraw3Phase::Class2Mirrored {
                    route_key: cfg.route_key,
                }
            } else {
                Withdraw3Phase::Direct
            }
        }
        UserClass::DexUser => Withdraw3Phase::Routed {
            route_key: cfg.route_key,
            privileged_finalize: false,
        },
        UserClass::PrivilegedDexUser | UserClass::Other(4..=u8::MAX) => {
            if cfg.allow_privileged_direct_path {
                Withdraw3Phase::Direct
            } else {
                Withdraw3Phase::Routed {
                    route_key: cfg.route_key,
                    privileged_finalize: true,
                }
            }
        }
        UserClass::Other(_) => Withdraw3Phase::Direct,
    }
}

/// Reconstructs `l1_action_withdraw3__apply_wrapper_main` +
/// `l1_action_withdraw3__apply_state_main` + `sub_2734200`.
///
/// Shared signer-domain validation has already happened when this runs:
/// - the normal exchange nonce set has reserved `action.nonce`, and
/// - the signature/chain-id checks already accepted the signed action envelope.
///
/// This handler then adds its own per-user monotonic nonce slot, parses the wire
/// strings, debits the first clearinghouse, records the Bridge2 withdrawal keyed by
/// `(user, nonce_ms)`, and finally writes the new local nonce back into the user
/// account record.
pub fn apply_withdraw3<E: Withdraw3Engine>(
    engine: &mut E,
    user: Address,
    action: &Withdraw3Action,
) -> Withdraw3Result {
    let phase = classify_withdraw3_phase(engine.user_class(user), engine.routing_config());

    match phase {
        Withdraw3Phase::Direct => apply_withdraw3_core(engine, user, action, phase),
        Withdraw3Phase::Class2Mirrored { route_key } => {
            if let Err(status) = engine.reconcile_routed_withdraw(user, route_key) {
                return Withdraw3Result::rejected(status);
            }

            let result = apply_withdraw3_core(engine, user, action, phase);
            if result.status != STATUS_OK {
                return result;
            }

            if let Err(status) = engine.reconcile_routed_withdraw(user, route_key) {
                return Withdraw3Result::rejected(status);
            }
            result
        }
        Withdraw3Phase::Routed {
            route_key,
            privileged_finalize,
        } => {
            if !engine.accept_routed_withdraw(user) {
                return Withdraw3Result::rejected(STATUS_REQUIRED_SET_MISS);
            }

            engine.prepare_routed_withdraw(user, route_key, privileged_finalize);
            let result = apply_withdraw3_core(engine, user, action, phase);
            if result.status != STATUS_OK {
                return result;
            }

            if privileged_finalize {
                engine.finalize_privileged_routed_withdraw(user, route_key);
                result
            } else {
                match engine.reconcile_routed_withdraw(user, route_key) {
                    Ok(()) => result,
                    Err(status) => Withdraw3Result::rejected(status),
                }
            }
        }
    }
}

fn apply_withdraw3_core<E: Withdraw3Engine>(
    engine: &mut E,
    user: Address,
    action: &Withdraw3Action,
    phase: Withdraw3Phase,
) -> Withdraw3Result {
    if action.destination.len() > MAX_WIRE_STRING_LEN || action.usd.len() > MAX_WIRE_STRING_LEN {
        return Withdraw3Result::rejected(STATUS_STRING_TOO_LONG);
    }

    if let Err(status) = engine.validate_environment_window(user) {
        return Withdraw3Result::rejected(status);
    }

    let nonce_ms = match action.nonce.checked_mul(WITHDRAW3_NONCE_SCALE) {
        Some(nonce_ms) => nonce_ms,
        None => return Withdraw3Result::rejected(STATUS_NONCE_ARITHMETIC),
    };

    if let Some(stored_ms) = engine.last_withdraw3_nonce_ms(user) {
        if nonce_ms <= stored_ms {
            return Withdraw3Result::rejected(STATUS_NONCE_ALREADY_USED);
        }
    }

    let usd = match engine.parse_withdraw_usd(&action.usd) {
        Ok(usd) => usd,
        Err(status) => return Withdraw3Result::rejected(status),
    };

    if usd == 0 {
        return Withdraw3Result::rejected(STATUS_ZERO_USD);
    }
    if usd > engine.max_bridge_withdraw_usd() {
        return Withdraw3Result::rejected(STATUS_USD_ABOVE_BRIDGE_LIMIT);
    }

    let destination = match engine.parse_destination(&action.destination) {
        Ok(destination) => destination,
        Err(_) => return Withdraw3Result::rejected(STATUS_INVALID_DESTINATION),
    };

    if let Err(status) = engine.apply_first_dex_withdrawal(user, usd) {
        return Withdraw3Result::rejected(status);
    }

    engine.record_withdrawal_signature_and_debit(user, destination, usd, nonce_ms);
    engine.remember_withdraw3_nonce(user, nonce_ms);
    engine.clear_withdraw3_pending_flag(user);
    let Some(volume_delta) = i64::try_from(usd).ok().and_then(|usd| usd.checked_neg()) else {
        return Withdraw3Result::rejected(STATUS_BRIDGE_BUCKET_OVERFLOW);
    };
    engine.add_user_ntl_volume_scaled(user, volume_delta);

    Withdraw3Result::ok(Withdraw3Applied {
        destination,
        usd,
        nonce_ms,
        phase,
    })
}
