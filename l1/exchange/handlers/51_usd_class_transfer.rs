#![allow(dead_code)]

use std::convert::TryFrom;

pub type Address = [u8; 20];
pub type RawUsd = i64;
pub type SignatureChainIdent = u64;

pub const HANDLER_EA: u64 = 0x1E60_850;
pub const PARSE_USD_FIELD_EA: u64 = 0x3980_A60;
pub const AUTHORIZE_SUBACCOUNT_EA: u64 = 0x2714_F80;
pub const APPLY_WRAPPER_EA: u64 = 0x2717_CF0;
pub const APPLY_CORE_EA: u64 = 0x270F_6F0;
pub const USER_ACCOUNT_LOOKUP_EA: u64 = 0x2755_400;

pub const OUTCOME_TAG_SUCCESS: u8 = 13;
pub const OUTCOME_TAG_ERROR: u8 = 14;

pub const STATUS_OK: u16 = 390;
pub const STATUS_INVALID_SUBACCOUNT_ADDRESS: u16 = 182;
pub const STATUS_SUBACCOUNT_NOT_REGISTERED_OR_UNAUTHORIZED: u16 = 220;
pub const STATUS_UNKNOWN_TRANSFER_CLASS: u16 = 249;
pub const STATUS_INSUFFICIENT_BALANCE: u16 = 247;
pub const STATUS_WITHDRAWABLE_LIMIT: u16 = 51;
pub const STATUS_FEATURE_GATE_REJECTED: u16 = 367;
pub const STATUS_STRING_TOO_LONG: u16 = 323;
pub const STATUS_MALFORMED_USD_STRING: u16 = 305;
pub const STATUS_AMOUNT_OVERFLOW: u16 = 319;

pub const MAX_WIRE_STRING_LEN: usize = 100;
pub const RAW_USD_OVERFLOW_CUTOFF: RawUsd = 0x0CCC_CCCC_CCCC_CCCC_u64 as i64;
pub const SUBACCOUNT_SENTINEL: &str = "subaccount:";
pub const USD_SCALE: RawUsd = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsdClassTransferAction {
    /// Handler-local payload field read through `sub_3980A60`.
    ///
    /// Observed wire format:
    /// - plain user transfer: `<usd>`
    /// - master-authorized sub-account transfer: `<usd>subaccount:<0x-address>`
    pub usd: String,
    pub to_perp: bool,
    /// The shared signed-action path consumes nonce/signature material before this wrapper runs.
    pub nonce: u64,
    pub signature_chain_idents: Vec<SignatureChainIdent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferFeatureGate {
    /// Observed at `exchange + 91 * 16 + 1`.
    pub allow_kind3_users: bool,
    /// Observed at `exchange + 91 * 16 + 0`.
    pub allow_kind4_plus_users: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedUsdField {
    pub usd: RawUsd,
    pub target_user: Address,
    pub used_subaccount_suffix: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AccountClassTransferEvent {
    pub user: Address,
    pub usd: RawUsd,
    pub to_perp: bool,
    /// `sub_2717CF0` converts this to `f64` for the emitted event payload.
    pub event_usd: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsdClassTransferError {
    StringTooLong,
    MalformedUsdString,
    InvalidSubaccountAddress,
    UnauthorizedSubaccount {
        signer: Address,
        requested_subaccount: Address,
    },
    FeatureGateRejected,
    AmountOverflow {
        requested_usd: RawUsd,
    },
    Core(u16),
}

impl UsdClassTransferError {
    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::StringTooLong => STATUS_STRING_TOO_LONG,
            Self::MalformedUsdString => STATUS_MALFORMED_USD_STRING,
            Self::InvalidSubaccountAddress => STATUS_INVALID_SUBACCOUNT_ADDRESS,
            Self::UnauthorizedSubaccount { .. } => STATUS_SUBACCOUNT_NOT_REGISTERED_OR_UNAUTHORIZED,
            Self::FeatureGateRejected => STATUS_FEATURE_GATE_REJECTED,
            Self::AmountOverflow { .. } => STATUS_AMOUNT_OVERFLOW,
            Self::Core(status) => status,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BaseActionOutcome {
    Success(AccountClassTransferEvent),
    Error {
        status: u16,
        error: UsdClassTransferError,
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

pub trait UsdClassTransferState {
    /// Mirrors `sub_2755400(exchange, user) + 60`.
    fn user_gate_kind(&self, user: &Address) -> u8;

    /// Mirrors the two feature bytes the wrapper reads from the exchange object.
    fn transfer_feature_gate(&self) -> TransferFeatureGate;

    /// Returns `Some(master)` only when `user` is a registered sub-account.
    fn lookup_sub_account_master(&self, user: &Address) -> Option<Address>;

    /// Wraps the downstream shared transfer path at `0x2717CF0` / `0x270F6F0`.
    ///
    /// That path performs the actual class-to-class balance move, auxiliary user-account
    /// counter updates, and event emission. Observed status returns include `249`, `247`,
    /// `51`, and `21` in addition to `390`.
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

/// Reconstructs `l1_exchange_impl_execute_action__usd_class_transfer`.
///
/// Observed wrapper flow:
/// 1. Reject `action.usd.len() >= 101` with `323`.
/// 2. Parse `action.usd` with `sub_3980A60`:
///    - plain decimal text transfers the signer account;
///    - `<usd>subaccount:<addr>` retargets the transfer to a signer-owned sub-account;
///    - malformed split shapes return `305`;
///    - invalid suffix address returns `182`.
/// 3. When a `subaccount:` suffix is present, authorize it with `sub_2714F80`; failures return `220`.
/// 4. Apply the standard account-kind gate to the effective target user with `sub_2755400` and
///    exchange feature bytes `exchange[91][1]` / `exchange[91][0]`; gate failures return `367`.
/// 5. Forward `(effective_user, parsed_usd, to_perp)` into the shared USD-class transfer core.
/// 6. On success return outer tag `13`; any non-`390` status returns outer tag `14` unchanged.
///
/// The shared core performs the actual cross/perp rebalance:
/// - `to_perp = true`: debit the user's spot/cross USD bucket and credit the perp-margin bucket.
/// - `to_perp = false`: debit perp margin and credit the spot/cross USD bucket.
/// - The helper also mirrors the move into auxiliary per-user counters and emits an
///   `accountClassTransfer` ledger/event record.
pub fn apply_usd_class_transfer<S>(
    state: &mut S,
    signer: Address,
    action: &UsdClassTransferAction,
) -> BaseActionOutcome
where
    S: UsdClassTransferState,
{
    let parsed = match parse_usd_field(state, signer, &action.usd) {
        Ok(parsed) => parsed,
        Err(error) => {
            return BaseActionOutcome::Error {
                status: error.status(),
                error,
            };
        }
    };

    let gate = state.transfer_feature_gate();
    if !user_is_transfer_gated(state.user_gate_kind(&parsed.target_user), gate) {
        return BaseActionOutcome::Error {
            status: STATUS_FEATURE_GATE_REJECTED,
            error: UsdClassTransferError::FeatureGateRejected,
        };
    }

    if parsed.usd >= RAW_USD_OVERFLOW_CUTOFF {
        return BaseActionOutcome::Error {
            status: STATUS_AMOUNT_OVERFLOW,
            error: UsdClassTransferError::AmountOverflow {
                requested_usd: parsed.usd,
            },
        };
    }

    match state.apply_account_class_transfer_core(parsed.target_user, parsed.usd, action.to_perp) {
        Ok(event) => BaseActionOutcome::Success(event),
        Err(status) => BaseActionOutcome::Error {
            status,
            error: UsdClassTransferError::Core(status),
        },
    }
}

pub fn parse_usd_field<S>(
    state: &S,
    signer: Address,
    raw: &str,
) -> Result<ParsedUsdField, UsdClassTransferError>
where
    S: UsdClassTransferState,
{
    if raw.len() > MAX_WIRE_STRING_LEN {
        return Err(UsdClassTransferError::StringTooLong);
    }

    let mut parts = raw.split(SUBACCOUNT_SENTINEL);
    let usd_part = parts.next().ok_or(UsdClassTransferError::MalformedUsdString)?;
    let suffix = parts.next();
    if parts.next().is_some() {
        return Err(UsdClassTransferError::MalformedUsdString);
    }

    let usd = parse_scaled_usd_1e6(usd_part)?;

    let Some(subaccount_text) = suffix else {
        return Ok(ParsedUsdField {
            usd,
            target_user: signer,
            used_subaccount_suffix: false,
        });
    };

    let requested_subaccount = parse_address(subaccount_text)
        .ok_or(UsdClassTransferError::InvalidSubaccountAddress)?;
    match state.lookup_sub_account_master(&requested_subaccount) {
        Some(master) if master == signer => Ok(ParsedUsdField {
            usd,
            target_user: requested_subaccount,
            used_subaccount_suffix: true,
        }),
        _ => Err(UsdClassTransferError::UnauthorizedSubaccount {
            signer,
            requested_subaccount,
        }),
    }
}

fn parse_scaled_usd_1e6(raw: &str) -> Result<RawUsd, UsdClassTransferError> {
    if raw.is_empty() {
        return Err(UsdClassTransferError::MalformedUsdString);
    }

    let (negative, digits) = match raw.as_bytes()[0] {
        b'-' => (true, &raw[1..]),
        b'+' => (false, &raw[1..]),
        _ => (false, raw),
    };
    if digits.is_empty() {
        return Err(UsdClassTransferError::MalformedUsdString);
    }

    let (whole, frac) = match digits.split_once('.') {
        Some((whole, frac)) => (whole, frac),
        None => (digits, ""),
    };
    if whole.is_empty() && frac.is_empty() {
        return Err(UsdClassTransferError::MalformedUsdString);
    }
    if !whole.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return Err(UsdClassTransferError::MalformedUsdString);
    }
    if frac.len() > 6 {
        return Err(UsdClassTransferError::MalformedUsdString);
    }

    let whole = if whole.is_empty() {
        0_i128
    } else {
        whole
            .parse::<i128>()
            .map_err(|_| UsdClassTransferError::MalformedUsdString)?
    };
    let mut frac_scaled = if frac.is_empty() {
        0_i128
    } else {
        frac.parse::<i128>()
            .map_err(|_| UsdClassTransferError::MalformedUsdString)?
    };
    for _ in frac.len()..6 {
        frac_scaled *= 10;
    }

    let scaled = whole
        .checked_mul(USD_SCALE as i128)
        .and_then(|lhs| lhs.checked_add(frac_scaled))
        .ok_or(UsdClassTransferError::AmountOverflow {
            requested_usd: RAW_USD_OVERFLOW_CUTOFF,
        })?;
    let scaled = if negative { -scaled } else { scaled };
    i64::try_from(scaled).map_err(|_| UsdClassTransferError::AmountOverflow {
        requested_usd: RAW_USD_OVERFLOW_CUTOFF,
    })
}

fn parse_address(raw: &str) -> Option<Address> {
    let hex = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")).unwrap_or(raw);
    if hex.len() != 40 {
        return None;
    }

    let mut out = [0_u8; 20];
    for (idx, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        out[idx] = (decode_hex_nybble(chunk[0])? << 4) | decode_hex_nybble(chunk[1])?;
    }
    Some(out)
}

const fn decode_hex_nybble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
