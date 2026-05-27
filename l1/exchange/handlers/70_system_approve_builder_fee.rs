#![allow(dead_code)]

use std::collections::BTreeMap;

pub type Address = [u8; 20];
pub type FeeRateMillis = u64;
pub type SignedAccountValue = i64;

pub const SYSTEM_APPROVE_BUILDER_FEE_HANDLER_EA: u64 = 0x1E64_620;
pub const SHARED_APPLY_HELPER_EA: u64 = 0x2758_330;
pub const APPLY_MAP_HELPER_EA: u64 = 0x3745_9E0;

pub const WRAPPER_TAG_APPLIED: u8 = 13;
pub const WRAPPER_TAG_REJECTED: u8 = 14;

pub const STATUS_APPLIED: u16 = 390;
pub const STATUS_ACCOUNT_VALUE_TOO_SMALL: u16 = 295;
pub const STATUS_TOO_MANY_APPROVED_BUILDERS: u16 = 299;
pub const STATUS_RAW_FEE_OVERFLOW: u16 = 319;

/// `sub_2758330` only allows non-zero builder-fee approvals when the caller's
/// aggregate position-margin summary reports a signed equity/value strictly
/// above this threshold.
pub const MIN_SIGNED_ACCOUNT_VALUE_EXCLUSIVE_RAW: SignedAccountValue = 99_999_999;

/// `sub_37459E0` rejects insertion when the per-user builder-fee container's
/// tracked count is already greater than ten.
pub const MAX_TRACKED_BUILDER_FEES_BEFORE_INSERT: usize = 10;

/// `sub_1E64620` consumes a compact 28-byte payload:
/// - `+0x00`: raw max fee rate already scaled to millis-of-a-percent;
/// - `+0x08`: builder address bytes;
/// - `+0x18`: trailing builder-address word.
///
/// Unlike the user-signed tag-54 path, there is no embedded nonce or fee-rate
/// string parsing here. The wrapper forwards the raw integer directly into the
/// shared apply helper at `0x2758330`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemApproveBuilderFeeAction {
    pub builder: Address,
    pub max_fee_rate_millis: FeeRateMillis,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExchangeState {
    /// Rooted under `exchange + 1488`; each user owns a small per-builder fee map.
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

    #[inline]
    fn user_account_mut(&mut self, user: Address) -> &mut UserAccountState {
        self.users.entry(user).or_default()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UserAccountState {
    /// `l1_position__aggregate_position_margin_summary(..., true, true)` field
    /// consumed by `sub_2758330` before it touches the fee-approval map.
    pub signed_equity_or_value: SignedAccountValue,
    /// Builder address -> approved maximum fee rate, in millis-of-a-percent.
    pub max_builder_fee_by_builder: BTreeMap<Address, FeeRateMillis>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemApproveBuilderFeeError {
    AccountValueTooSmall,
    TooManyApprovedBuilders,
    RawFeeOverflow,
}

impl SystemApproveBuilderFeeError {
    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::AccountValueTooSmall => STATUS_ACCOUNT_VALUE_TOO_SMALL,
            Self::TooManyApprovedBuilders => STATUS_TOO_MANY_APPROVED_BUILDERS,
            Self::RawFeeOverflow => STATUS_RAW_FEE_OVERFLOW,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemApproveBuilderFeeResult {
    Applied,
    Rejected(SystemApproveBuilderFeeError),
}

impl SystemApproveBuilderFeeResult {
    #[inline]
    pub const fn outer_tag(self) -> u8 {
        match self {
            Self::Applied => WRAPPER_TAG_APPLIED,
            Self::Rejected(_) => WRAPPER_TAG_REJECTED,
        }
    }

    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::Applied => STATUS_APPLIED,
            Self::Rejected(error) => error.status(),
        }
    }
}

/// Recovered model of `sub_1E64620` + `sub_2758330` + `sub_37459E0`.
///
/// Validation / mutation order is exact:
/// 1. Reject raw fee values `>= 0x0CCC_CCCC_CCCC_CCCC` with status `319`.
/// 2. For non-zero approvals, compute the caller margin summary and reject when
///    `signed_equity_or_value <= 99_999_999` with status `295`.
/// 3. A zero fee removes any existing builder approval and succeeds.
/// 4. Otherwise reject when the tracked builder-fee count is already `> 10`.
/// 5. Insert or overwrite `builder -> max_fee_rate_millis` and return `390`.
pub fn apply_system_approve_builder_fee(
    state: &mut ExchangeState,
    user: Address,
    action: SystemApproveBuilderFeeAction,
) -> SystemApproveBuilderFeeResult {
    if action.max_fee_rate_millis >= 0x0CCC_CCCC_CCCC_CCCC {
        return SystemApproveBuilderFeeResult::Rejected(SystemApproveBuilderFeeError::RawFeeOverflow);
    }

    apply_system_approve_builder_fee_raw(state, user, action.builder, action.max_fee_rate_millis)
}

pub fn apply_system_approve_builder_fee_raw(
    state: &mut ExchangeState,
    user: Address,
    builder: Address,
    max_fee_rate_millis: FeeRateMillis,
) -> SystemApproveBuilderFeeResult {
    if max_fee_rate_millis != 0 {
        let signed_equity_or_value = state
            .users
            .get(&user)
            .map(|account| account.signed_equity_or_value)
            .unwrap_or_default();
        if signed_equity_or_value <= MIN_SIGNED_ACCOUNT_VALUE_EXCLUSIVE_RAW {
            return SystemApproveBuilderFeeResult::Rejected(
                SystemApproveBuilderFeeError::AccountValueTooSmall,
            );
        }
    }

    let account = state.user_account_mut(user);
    if max_fee_rate_millis == 0 {
        account.max_builder_fee_by_builder.remove(&builder);
        return SystemApproveBuilderFeeResult::Applied;
    }

    if account.max_builder_fee_by_builder.len() > MAX_TRACKED_BUILDER_FEES_BEFORE_INSERT {
        return SystemApproveBuilderFeeResult::Rejected(
            SystemApproveBuilderFeeError::TooManyApprovedBuilders,
        );
    }

    account
        .max_builder_fee_by_builder
        .insert(builder, max_fee_rate_millis);
    SystemApproveBuilderFeeResult::Applied
}
