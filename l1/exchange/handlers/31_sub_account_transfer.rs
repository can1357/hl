#![allow(dead_code)]

pub type Address = [u8; 20];
pub type RawUsd = u64;

pub const HANDLER_EA: u64 = 0x1E60_D00;
pub const TRANSFER_HELPER_EA: u64 = 0x2714_8E0;
pub const USER_ACCOUNT_LOOKUP_EA: u64 = 0x2755_400;

pub const OUTCOME_TAG_SUCCESS: u8 = 13;
pub const OUTCOME_TAG_ERROR: u8 = 14;

pub const STATUS_OK: u16 = 390;
pub const STATUS_ZERO_USD: u16 = 49;
pub const STATUS_INSUFFICIENT_WITHDRAWABLE: u16 = 51;
pub const STATUS_SUB_ACCOUNT_TRANSFER_NOT_ALLOWED: u16 = 218;
pub const STATUS_FEATURE_GATE_REJECTED: u16 = 367;
pub const STATUS_AMOUNT_OVERFLOW: u16 = 319;

pub const RAW_USD_OVERFLOW_CUTOFF: RawUsd = 0x0CCC_CCCC_CCCC_CCCC;
pub const USER_ACCOUNT_TRANSFER_UNIT_DIVISOR: RawUsd = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubAccountTransferAction {
    pub usd: RawUsd,
    pub sub_account_user: Address,
    pub is_deposit: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferFeatureGate {
    /// Observed at `exchange + 91 * 16 + 1`.
    pub allow_kind3_users: bool,
    /// Observed at `exchange + 91 * 16 + 0`.
    pub allow_kind4_plus_users: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Deposit,
    Withdraw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedSubAccountTransfer {
    pub from: Address,
    pub to: Address,
    pub master: Address,
    pub sub_account_user: Address,
    pub usd: RawUsd,
    pub direction: TransferDirection,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SubAccountTransferEvent {
    pub from: Address,
    pub to: Address,
    pub master: Address,
    pub sub_account_user: Address,
    pub usd: RawUsd,
    /// The helper materializes `usd as f64 / 1_000_000.0` into the emitted event payload.
    pub event_usd: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubAccountTransferError {
    FeatureGateRejected,
    ZeroUsd,
    /// The recovered helper collapses both "unknown sub-account" and "belongs to a
    /// different master" into status `218`.
    SubAccountTransferNotAllowed {
        master: Address,
        sub_account_user: Address,
    },
    InsufficientWithdrawable {
        from: Address,
        requested_usd: RawUsd,
    },
    AmountOverflow {
        requested_usd: RawUsd,
    },
    Unknown(u16),
}

impl SubAccountTransferError {
    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::FeatureGateRejected => STATUS_FEATURE_GATE_REJECTED,
            Self::ZeroUsd => STATUS_ZERO_USD,
            Self::SubAccountTransferNotAllowed { .. } => STATUS_SUB_ACCOUNT_TRANSFER_NOT_ALLOWED,
            Self::InsufficientWithdrawable { .. } => STATUS_INSUFFICIENT_WITHDRAWABLE,
            Self::AmountOverflow { .. } => STATUS_AMOUNT_OVERFLOW,
            Self::Unknown(status) => status,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BaseActionOutcome {
    Success(ResolvedSubAccountTransfer),
    Error {
        status: u16,
        error: SubAccountTransferError,
    },
}

impl BaseActionOutcome {
    #[inline]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Success(..) => OUTCOME_TAG_SUCCESS,
            Self::Error { .. } => OUTCOME_TAG_ERROR,
        }
    }
}

pub trait SubAccountTransferState {
    /// Mirrors the byte read from `sub_2755400(exchange, user) + 60`.
    fn user_gate_kind(&self, user: &Address) -> u8;

    /// Mirrors the two gate bytes the wrapper reads from the exchange object.
    fn transfer_feature_gate(&self) -> TransferFeatureGate;

    /// Returns `Some(master)` only when `sub_account_user` is a registered sub-account.
    fn lookup_sub_account_master(&self, sub_account_user: &Address) -> Option<Address>;

    /// Mirrors `l1_user_state__available_margin_after_reserved(...)` for the debited leg.
    fn available_margin_after_reserved(&self, user: &Address) -> RawUsd;

    /// Mirrors `sub_370A3D0(...)` on the debited leg.
    fn debit_ntl(&mut self, user: Address, usd: RawUsd);

    /// Mirrors `sub_36FF4F0(...)` on the credited leg.
    fn credit_ntl(&mut self, user: Address, usd: RawUsd);

    /// Mirrors the two saturating decrements on `get_or_create_user_account(from)`.
    fn debit_user_transfer_units(&mut self, user: Address, units: u64);

    /// Mirrors the two saturating increments on `get_or_create_user_account(to)`.
    fn credit_user_transfer_units(&mut self, user: Address, units: u64);

    /// Mirrors the event push via `sub_3576710(...)`.
    fn emit_transfer_event(&mut self, event: SubAccountTransferEvent);
}

#[inline]
pub const fn user_is_transfer_gated(raw_kind: u8, gate: TransferFeatureGate) -> bool {
    if raw_kind > 3 {
        gate.allow_kind4_plus_users
    } else if raw_kind == 3 {
        gate.allow_kind3_users
    } else {
        true
    }
}

#[inline]
pub const fn resolve_direction(is_deposit: bool) -> TransferDirection {
    if is_deposit {
        TransferDirection::Deposit
    } else {
        TransferDirection::Withdraw
    }
}

#[inline]
pub const fn resolve_legs(
    master: Address,
    sub_account_user: Address,
    is_deposit: bool,
) -> (Address, Address, TransferDirection) {
    if is_deposit {
        (master, sub_account_user, TransferDirection::Deposit)
    } else {
        (sub_account_user, master, TransferDirection::Withdraw)
    }
}

/// Reconstructs `sub_1E60D00` and its helper `l1_qtys_impl_ntl__transfer_user_ntl`.
///
/// Observed flow:
/// 1. Read the signer/master account gate kind through `sub_2755400(exchange, master)`.
/// 2. Reject with `367` unless the exchange-level gate bits allow that kind.
/// 3. Repeat the same gate check for `action.sub_account_user`.
/// 4. Reject `usd == 0` with `49`.
/// 5. Reject `usd >= 0x0CCC_CCCC_CCCC_CCCC` with `319` before touching balances.
/// 6. Resolve transfer legs from `is_deposit`:
///    - deposit: master -> sub-account
///    - withdraw: sub-account -> master
/// 7. Verify `sub_account_to_master[sub_account_user] == master`; any miss or mismatch returns `218`.
/// 8. Check `available_margin_after_reserved(from) >= usd`; otherwise return `51`.
/// 9. Debit the sender NTL bucket, credit the receiver NTL bucket, emit one transfer event,
///    and mirror `usd / 10_000` into two per-user account counters on each side.
/// 10. Map helper status `390` to outer outcome tag `13`; every non-`390` status becomes tag `14`.
pub fn apply_sub_account_transfer<S>(
    state: &mut S,
    master: Address,
    action: SubAccountTransferAction,
) -> BaseActionOutcome
where
    S: SubAccountTransferState,
{
    let gate = state.transfer_feature_gate();
    if !user_is_transfer_gated(state.user_gate_kind(&master), gate)
        || !user_is_transfer_gated(state.user_gate_kind(&action.sub_account_user), gate)
    {
        return BaseActionOutcome::Error {
            status: STATUS_FEATURE_GATE_REJECTED,
            error: SubAccountTransferError::FeatureGateRejected,
        };
    }

    match execute_sub_account_transfer(state, master, action) {
        Ok(applied) => BaseActionOutcome::Success(applied),
        Err(error) => BaseActionOutcome::Error {
            status: error.status(),
            error,
        },
    }
}

pub fn execute_sub_account_transfer<S>(
    state: &mut S,
    master: Address,
    action: SubAccountTransferAction,
) -> Result<ResolvedSubAccountTransfer, SubAccountTransferError>
where
    S: SubAccountTransferState,
{
    if action.usd >= RAW_USD_OVERFLOW_CUTOFF {
        return Err(SubAccountTransferError::AmountOverflow {
            requested_usd: action.usd,
        });
    }
    if action.usd == 0 {
        return Err(SubAccountTransferError::ZeroUsd);
    }

    let (from, to, direction) = resolve_legs(master, action.sub_account_user, action.is_deposit);
    match state.lookup_sub_account_master(&action.sub_account_user) {
        Some(mapped_master) if mapped_master == master => {}
        _ => {
            return Err(SubAccountTransferError::SubAccountTransferNotAllowed {
                master,
                sub_account_user: action.sub_account_user,
            });
        }
    }

    if state.available_margin_after_reserved(&from) < action.usd {
        return Err(SubAccountTransferError::InsufficientWithdrawable {
            from,
            requested_usd: action.usd,
        });
    }

    state.debit_ntl(from, action.usd);
    state.credit_ntl(to, action.usd);

    let user_transfer_units = action.usd / USER_ACCOUNT_TRANSFER_UNIT_DIVISOR;
    state.debit_user_transfer_units(from, user_transfer_units);
    state.credit_user_transfer_units(to, user_transfer_units);

    state.emit_transfer_event(SubAccountTransferEvent {
        from,
        to,
        master,
        sub_account_user: action.sub_account_user,
        usd: action.usd,
        event_usd: action.usd as f64 / 1_000_000.0,
    });

    Ok(ResolvedSubAccountTransfer {
        from,
        to,
        master,
        sub_account_user: action.sub_account_user,
        usd: action.usd,
        direction,
    })
}
