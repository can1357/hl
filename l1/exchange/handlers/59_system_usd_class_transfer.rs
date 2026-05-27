#![allow(dead_code)]

pub type Address = [u8; 20];
pub type RawUsd = i64;

pub const HANDLER_EA: u64 = 0x1E64_530;
pub const APPLY_WRAPPER_EA: u64 = 0x2717_CF0;
pub const APPLY_CORE_EA: u64 = 0x270F_6F0;
pub const USER_ACCOUNT_LOOKUP_EA: u64 = 0x2755_400;

pub const OUTCOME_TAG_SUCCESS: u8 = 13;
pub const OUTCOME_TAG_ERROR: u8 = 14;

pub const STATUS_OK: u16 = 390;
pub const STATUS_INSUFFICIENT_BALANCE: u16 = 247;
pub const STATUS_WITHDRAWABLE_LIMIT: u16 = 51;
pub const STATUS_OWNER_MISMATCH: u16 = 21;
pub const STATUS_UNKNOWN_TRANSFER_CLASS: u16 = 249;
pub const STATUS_FEATURE_GATE_REJECTED: u16 = 367;
pub const STATUS_AMOUNT_OVERFLOW: u16 = 319;

/// `sub_1E64530` rejects `amount >= 0x0CCC_CCCC_CCCC_CCCC` before casting into the
/// signed notional helper.
pub const RAW_USD_OVERFLOW_CUTOFF: u64 = 0x0CCC_CCCC_CCCC_CCCC;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemUsdClassTransferAction {
    pub amount: u64,
    pub to_perp: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferFeatureGate {
    /// Observed at `exchange + 91 * 16 + 1`.
    pub allow_kind3_users: bool,
    /// Observed at `exchange + 91 * 16 + 0`.
    pub allow_kind4_plus_users: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AccountClassTransferEvent {
    pub user: Address,
    pub usd: RawUsd,
    pub to_perp: bool,
    /// `sub_2717CF0` converts the raw amount to `f64 / 1e6` before emitting the ledger event.
    pub event_usd: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemUsdClassTransferError {
    AmountOverflow { requested_amount: u64 },
    FeatureGateRejected,
    Core(u16),
}

impl SystemUsdClassTransferError {
    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::AmountOverflow { .. } => STATUS_AMOUNT_OVERFLOW,
            Self::FeatureGateRejected => STATUS_FEATURE_GATE_REJECTED,
            Self::Core(status) => status,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BaseActionOutcome {
    Success(AccountClassTransferEvent),
    Error {
        status: u16,
        error: SystemUsdClassTransferError,
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

pub trait SystemUsdClassTransferState {
    /// Mirrors `sub_2755400(exchange, user) + 60`.
    fn user_gate_kind(&self, user: &Address) -> u8;

    /// Mirrors the two feature bytes read from the exchange object.
    fn transfer_feature_gate(&self) -> TransferFeatureGate;

    /// Wraps the shared class-transfer path at `0x2717CF0` / `0x270F6F0`.
    ///
    /// Grounded downstream statuses include:
    /// - `249`: transfer class disabled on the exchange object;
    /// - `247`: insufficient source balance in the chosen class;
    /// - `51`: withdrawable-limit failure on perp -> cross releases;
    /// - `21`: user/account ownership mismatch inside the asset-class tables.
    fn apply_account_class_transfer_core(
        &mut self,
        user: Address,
        usd: RawUsd,
        to_perp: bool,
    ) -> Result<AccountClassTransferEvent, u16>;
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

/// Reconstructs `sub_1E64530`.
///
/// Observed wrapper flow:
/// 1. Treat the payload as `{ amount: u64, to_perp: bool }`.
/// 2. Reject `amount >= RAW_USD_OVERFLOW_CUTOFF` with outer tag `14` and status `319`.
/// 3. Look up `sub_2755400(exchange, user) + 60` and apply the same class gate as the
///    user-signed `UsdClassTransfer` path:
///    - kind `3` requires `exchange[91][1]`;
///    - kinds `>= 4` require `exchange[91][0]`;
///    - all lower kinds bypass the gate.
/// 4. Forward `(user, amount as i64, to_perp)` into the shared class-transfer helper.
/// 5. Return outer tag `13` only when the helper reports `390`; otherwise copy the helper
///    payload/status into the outer tag `14` error path unchanged.
///
/// Unlike the user action, this system variant performs no string parsing, sub-account
/// authorization, nonce handling, or signature-chain verification in the handler body.
pub fn apply_system_usd_class_transfer<S>(
    state: &mut S,
    user: Address,
    action: &SystemUsdClassTransferAction,
) -> BaseActionOutcome
where
    S: SystemUsdClassTransferState,
{
    if action.amount >= RAW_USD_OVERFLOW_CUTOFF {
        let error = SystemUsdClassTransferError::AmountOverflow {
            requested_amount: action.amount,
        };
        return BaseActionOutcome::Error {
            status: error.status(),
            error,
        };
    }

    let gate = state.transfer_feature_gate();
    if !user_is_transfer_gated(state.user_gate_kind(&user), gate) {
        return BaseActionOutcome::Error {
            status: STATUS_FEATURE_GATE_REJECTED,
            error: SystemUsdClassTransferError::FeatureGateRejected,
        };
    }

    match state.apply_account_class_transfer_core(user, action.amount as RawUsd, action.to_perp) {
        Ok(event) => BaseActionOutcome::Success(event),
        Err(status) => BaseActionOutcome::Error {
            status,
            error: SystemUsdClassTransferError::Core(status),
        },
    }
}
