#![allow(dead_code)]

pub type Address = [u8; 20];

pub const STATUS_SUCCESS: u16 = 390;
pub const STATUS_RESTRICTED_USER: u16 = 28;
pub const STATUS_SPOT_DISABLED: u16 = 249;
pub const STATUS_ALREADY_OPTED_OUT: u16 = 306;
pub const STATUS_NOT_OPTED_OUT: u16 = 307;

/// Recovered `spotUser` payload.
///
/// Current binary evidence only shows one inner variant:
/// `toggleSpotDusting { optOut: bool }`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpotUserAction {
    ToggleSpotDusting(ToggleSpotDustingAction),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToggleSpotDustingAction {
    /// `true` inserts the caller into the exchange state's opt-out set.
    /// `false` removes the caller from that set.
    pub opt_out: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpotUserOutcome {
    pub status: u16,
    pub opt_out_after: bool,
    pub changed: bool,
}

pub trait SpotUserRuntime {
    /// Guards a small immutable user set checked before the feature flag.
    /// The exact product name of this restriction was not recovered, but matching
    /// users are rejected with status 28 and the handler performs no mutation.
    fn is_restricted_user(&self, user: Address) -> bool;

    /// Mirrors the byte gate at `exchange_state + 15048`.
    fn spot_dusting_enabled(&self) -> bool;

    /// True when `user` is already present in the mutable opt-out set rooted at
    /// `exchange_state + 1080`.
    fn is_opted_out_of_spot_dusting(&self, user: Address) -> bool;

    fn insert_spot_dusting_opt_out(&mut self, user: Address);
    fn remove_spot_dusting_opt_out(&mut self, user: Address);
}

/// Recovered from `sub_21CFEC0`.
///
/// Apply flow:
/// 1. reject users present in a precomputed restriction set with status 28;
/// 2. reject globally-disabled spot dusting with status 249;
/// 3. for `opt_out = true`, insert the user into the opt-out set unless already
///    present, in which case return status 306;
/// 4. for `opt_out = false`, remove the user from the opt-out set unless absent,
///    in which case return status 307.
///
/// The binary copies only the 20-byte user key into both set lookups, so the
/// handler mutates per-user membership only; no balances or spot positions are
/// touched here.
pub fn apply_spot_user<R: SpotUserRuntime>(
    runtime: &mut R,
    user: Address,
    action: SpotUserAction,
) -> SpotUserOutcome {
    let SpotUserAction::ToggleSpotDusting(action) = action;

    if runtime.is_restricted_user(user) {
        return SpotUserOutcome {
            status: STATUS_RESTRICTED_USER,
            opt_out_after: runtime.is_opted_out_of_spot_dusting(user),
            changed: false,
        };
    }

    if !runtime.spot_dusting_enabled() {
        return SpotUserOutcome {
            status: STATUS_SPOT_DISABLED,
            opt_out_after: runtime.is_opted_out_of_spot_dusting(user),
            changed: false,
        };
    }

    let was_opted_out = runtime.is_opted_out_of_spot_dusting(user);
    match (action.opt_out, was_opted_out) {
        (true, true) => SpotUserOutcome {
            status: STATUS_ALREADY_OPTED_OUT,
            opt_out_after: true,
            changed: false,
        },
        (true, false) => {
            runtime.insert_spot_dusting_opt_out(user);
            SpotUserOutcome {
                status: STATUS_SUCCESS,
                opt_out_after: true,
                changed: true,
            }
        }
        (false, true) => {
            runtime.remove_spot_dusting_opt_out(user);
            SpotUserOutcome {
                status: STATUS_SUCCESS,
                opt_out_after: false,
                changed: true,
            }
        }
        (false, false) => SpotUserOutcome {
            status: STATUS_NOT_OPTED_OUT,
            opt_out_after: false,
            changed: false,
        },
    }
}
