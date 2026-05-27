#![allow(dead_code)]

use std::collections::BTreeMap;

pub type Address = [u8; 20];
pub type Nonce = u64;
pub type FeeRateMillis = u64;
pub type SignedAccountValue = i64;

pub const OUTER_OK_TAG: u8 = 13;
pub const OUTER_ERR_TAG: u8 = 14;
pub const STATUS_OK: u16 = 390;
pub const STATUS_ACCOUNT_VALUE_TOO_SMALL: u16 = 295;
pub const STATUS_INVALID_FEE_RATE: u16 = 298;
pub const STATUS_TOO_MANY_APPROVED_BUILDERS: u16 = 299;
pub const STATUS_RAW_FEE_OVERFLOW: u16 = 319;
pub const STATUS_BOUNDS: u16 = 323;

/// `sub_2758330` rejects non-zero approvals unless the caller's aggregate margin
/// summary reports `signed_equity_or_value > 99_999_999`.
pub const MIN_SIGNED_ACCOUNT_VALUE_EXCLUSIVE_RAW: SignedAccountValue = 99_999_999;

/// `sub_37459E0` only inserts when the per-user builder-fee container's tracked
/// count is `<= 10`; larger pre-existing states reject with status `299`.
pub const MAX_TRACKED_BUILDER_FEES_BEFORE_INSERT: usize = 10;

/// Recovered wire payload for user action tag `54` handled by `sub_1E60A90`.
///
/// The generic exchange nonce validator runs before dispatch, so the local
/// handler never rereads or reserves `nonce`; it only consumes `builder` and the
/// fee-rate string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApproveBuilderFeeAction {
    pub builder: Address,
    pub max_fee_rate: String,
    pub nonce: Nonce,
}

/// Shared system-side form used by tag `70` (`sub_1E64620`), which bypasses the
/// string parser and feeds the scaled raw value directly into the same apply
/// helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemApproveBuilderFeeAction {
    pub builder: Address,
    pub max_fee_rate_millis: FeeRateMillis,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExchangeState {
    /// Rooted under the user-account table reached from `exchange_state + 1488`.
    pub users: BTreeMap<Address, UserAccountState>,
}

impl ExchangeState {
    #[inline]
    pub fn max_builder_fee(&self, user: &Address, builder: &Address) -> FeeRateMillis {
        self.users
            .get(user)
            .and_then(|account| account.max_builder_fee_by_builder.get(builder).copied())
            .unwrap_or(0)
    }

    fn user_account_mut(&mut self, user: Address) -> &mut UserAccountState {
        self.users.entry(user).or_default()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UserAccountState {
    /// `aggregate_position_margin_summary(..., false, true).signed_equity_or_value`
    /// as consumed by `sub_2758330`.
    pub signed_equity_or_value: SignedAccountValue,
    /// Per-builder fee approvals read by the order builder-approval path and the
    /// `maxBuilderFee` info-server route.
    pub max_builder_fee_by_builder: BTreeMap<Address, FeeRateMillis>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApproveBuilderFeeError {
    AccountValueTooSmall,
    InvalidFeeRate,
    TooManyApprovedBuilders,
    RawFeeOverflow,
    Bounds,
}

impl ApproveBuilderFeeError {
    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::AccountValueTooSmall => STATUS_ACCOUNT_VALUE_TOO_SMALL,
            Self::InvalidFeeRate => STATUS_INVALID_FEE_RATE,
            Self::TooManyApprovedBuilders => STATUS_TOO_MANY_APPROVED_BUILDERS,
            Self::RawFeeOverflow => STATUS_RAW_FEE_OVERFLOW,
            Self::Bounds => STATUS_BOUNDS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApproveBuilderFeeResult {
    Applied,
    Rejected(ApproveBuilderFeeError),
}

impl ApproveBuilderFeeResult {
    #[inline]
    pub const fn outer_tag(self) -> u8 {
        match self {
            Self::Applied => OUTER_OK_TAG,
            Self::Rejected(_) => OUTER_ERR_TAG,
        }
    }

    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::Applied => STATUS_OK,
            Self::Rejected(error) => error.status(),
        }
    }
}

pub fn apply_approve_builder_fee(
    state: &mut ExchangeState,
    user: Address,
    action: &ApproveBuilderFeeAction,
) -> ApproveBuilderFeeResult {
    let max_fee_rate_millis = match parse_builder_fee_rate(&action.max_fee_rate) {
        Ok(value) => value,
        Err(error) => return ApproveBuilderFeeResult::Rejected(error),
    };

    apply_approve_builder_fee_raw(state, user, action.builder, max_fee_rate_millis)
}

pub fn apply_system_approve_builder_fee(
    state: &mut ExchangeState,
    user: Address,
    action: SystemApproveBuilderFeeAction,
) -> ApproveBuilderFeeResult {
    if action.max_fee_rate_millis >= 0x0CCC_CCCC_CCCC_CCCC {
        return ApproveBuilderFeeResult::Rejected(ApproveBuilderFeeError::RawFeeOverflow);
    }
    apply_approve_builder_fee_raw(state, user, action.builder, action.max_fee_rate_millis)
}

pub fn apply_approve_builder_fee_raw(
    state: &mut ExchangeState,
    user: Address,
    builder: Address,
    max_fee_rate_millis: FeeRateMillis,
) -> ApproveBuilderFeeResult {
    if max_fee_rate_millis != 0 {
        let signed_equity_or_value = state
            .users
            .get(&user)
            .map(|account| account.signed_equity_or_value)
            .unwrap_or_default();
        if signed_equity_or_value <= MIN_SIGNED_ACCOUNT_VALUE_EXCLUSIVE_RAW {
            return ApproveBuilderFeeResult::Rejected(ApproveBuilderFeeError::AccountValueTooSmall);
        }
    }

    let account = state.user_account_mut(user);
    if max_fee_rate_millis == 0 {
        account.max_builder_fee_by_builder.remove(&builder);
        return ApproveBuilderFeeResult::Applied;
    }

    if account.max_builder_fee_by_builder.len() > MAX_TRACKED_BUILDER_FEES_BEFORE_INSERT {
        return ApproveBuilderFeeResult::Rejected(ApproveBuilderFeeError::TooManyApprovedBuilders);
    }

    account
        .max_builder_fee_by_builder
        .insert(builder, max_fee_rate_millis);
    ApproveBuilderFeeResult::Applied
}

/// Mirrors `sub_3364CD0`:
/// - reject strings of length `>= 101` before parsing;
/// - require a trailing `%`;
/// - parse the decimal body and scale it by `10^3` with no fractional remainder
///   left after scaling.
pub fn parse_builder_fee_rate(input: &str) -> Result<FeeRateMillis, ApproveBuilderFeeError> {
    if input.len() >= 101 {
        return Err(ApproveBuilderFeeError::Bounds);
    }

    let body = input
        .strip_suffix('%')
        .ok_or(ApproveBuilderFeeError::InvalidFeeRate)?;

    parse_unsigned_decimal_millis(body).map_err(|_| ApproveBuilderFeeError::InvalidFeeRate)
}

fn parse_unsigned_decimal_millis(input: &str) -> Result<FeeRateMillis, ()> {
    if input.is_empty() || input.starts_with('+') || input.starts_with('-') {
        return Err(());
    }

    let mut whole: u64 = 0;
    let mut frac: u64 = 0;
    let mut frac_digits = 0u8;
    let mut seen_digit = false;
    let mut seen_dot = false;

    for byte in input.bytes() {
        match byte {
            b'0'..=b'9' => {
                seen_digit = true;
                let digit = (byte - b'0') as u64;
                if seen_dot {
                    if frac_digits >= 3 {
                        return Err(());
                    }
                    frac = frac.checked_mul(10).and_then(|v| v.checked_add(digit)).ok_or(())?;
                    frac_digits += 1;
                } else {
                    whole = whole.checked_mul(10).and_then(|v| v.checked_add(digit)).ok_or(())?;
                }
            }
            b'.' if !seen_dot => seen_dot = true,
            _ => return Err(()),
        }
    }

    if !seen_digit {
        return Err(());
    }

    let scale_missing = 3u32 - frac_digits as u32;
    let scaled_whole = whole.checked_mul(1_000).ok_or(())?;
    let scaled_frac = frac.checked_mul(10u64.pow(scale_missing)).ok_or(())?;
    scaled_whole.checked_add(scaled_frac).ok_or(())
}
