#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type Wei = u64;
pub type TimestampMillis = u64;

pub const OUTER_OK_TAG: u8 = 13;
pub const OUTER_ERR_TAG: u8 = 14;

pub const STATUS_OK: u16 = 390;
pub const STATUS_AMOUNT_OVERFLOW_GUARD: u16 = 319;
pub const STATUS_STAKING_DISABLED: u16 = 251;
pub const STATUS_DELEGATE_AMOUNT_ZERO: u16 = 50;
pub const STATUS_MISSING_VALIDATOR: u16 = 145;
pub const STATUS_MISSING_EPOCH_STATE: u16 = 151;
pub const STATUS_DELEGATE_INSUFFICIENT_BALANCE: u16 = 252;
pub const STATUS_DELEGATE_VALIDATOR_DISABLED: u16 = 253;
pub const STATUS_UNDELEGATE_INSUFFICIENT_BALANCE: u16 = 254;
pub const STATUS_UNDELEGATE_LOCKED: u16 = 255;
pub const STATUS_SELF_DELEGATION_INSUFFICIENT: u16 = 304;
/// [INFERENCE] The epoch/live-delegation helpers saturating-trap on arithmetic
/// overflow and surface the same error family used by other staking quantity
/// mutations.
pub const STATUS_STAKING_ARITHMETIC_OVERFLOW: u16 = 190;

/// Raw deserialization carries `wei` as a decimal string plus signature-domain
/// fields (`signatureChainId`, `hyperliquidChain`, `nonce`).  By the time the
/// concrete handler at `0x1E5FA70` runs, the only payload members it reads are
/// the parsed `wei`, the 20-byte validator address, and `isUndelegate`; the
/// shared signed-action/nonce gate has already consumed the rest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenDelegateAction {
    pub signature_chain_id: u64,
    pub nonce: u64,
    pub hyperliquid_chain: String,
    pub validator: Address,
    pub wei: Wei,
    pub is_undelegate: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DelegationLot {
    pub wei: Wei,
    /// `true` maps to status `255`: "Cannot undelegate during lockup period after
    /// delegating or voting."
    pub undelegations_blocked: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EpochDelegation {
    pub wei: Wei,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ValidatorProfile {
    pub delegations_disabled: bool,
    pub registered: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SelfDelegationLock {
    pub unlock_at_ms: Option<TimestampMillis>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TokenDelegateState {
    pub now_ms: TimestampMillis,
    pub long_term_staking_allowed: bool,
    pub self_delegation_requirement: Wei,
    pub foundation_validator_addresses: BTreeSet<Address>,
    pub validator_profiles: BTreeMap<Address, ValidatorProfile>,
    pub available_balances: BTreeMap<Address, Wei>,
    /// Live delegations keyed by `(delegator, validator)`.
    pub live_delegations: BTreeMap<(Address, Address), DelegationLot>,
    /// Current-epoch delegation snapshot keyed by `(validator, delegator)`.
    pub epoch_delegations: BTreeMap<(Address, Address), EpochDelegation>,
    /// [INFERENCE] The delegate path nets the caller's liquid balance against one
    /// additional per-user reserved bucket before checking status `252`.
    pub reserved_balances: BTreeMap<Address, Wei>,
    /// Only meaningful for `delegator == validator`.
    pub self_delegation_locks: BTreeMap<Address, SelfDelegationLock>,
}

impl TokenDelegateState {
    #[inline]
    pub fn spendable_balance(&self, user: &Address) -> Wei {
        let available = self.available_balances.get(user).copied().unwrap_or(0);
        let reserved = self.reserved_balances.get(user).copied().unwrap_or(0);
        available.saturating_sub(reserved)
    }

    #[inline]
    fn validator_profile(&self, validator: &Address) -> Result<ValidatorProfile, TokenDelegateError> {
        self.validator_profiles
            .get(validator)
            .copied()
            .ok_or(TokenDelegateError::MissingValidator)
    }

    #[inline]
    fn epoch_delegation_mut(
        &mut self,
        validator: Address,
        delegator: Address,
    ) -> Result<&mut EpochDelegation, TokenDelegateError> {
        self.epoch_delegations
            .get_mut(&(validator, delegator))
            .ok_or(TokenDelegateError::MissingEpochState)
    }

    #[inline]
    fn live_delegation_mut(&mut self, delegator: Address, validator: Address) -> &mut DelegationLot {
        self.live_delegations.entry((delegator, validator)).or_default()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenDelegateError {
    AmountOverflowGuard { wei: Wei },
    StakingDisabled,
    DelegateAmountZero,
    MissingValidator,
    MissingEpochState,
    DelegateInsufficientBalance,
    DelegateValidatorDisabled,
    UndelegateInsufficientBalance,
    UndelegateLocked,
    SelfDelegationInsufficient,
    ArithmeticOverflow,
}

impl TokenDelegateError {
    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::AmountOverflowGuard { .. } => STATUS_AMOUNT_OVERFLOW_GUARD,
            Self::StakingDisabled => STATUS_STAKING_DISABLED,
            Self::DelegateAmountZero => STATUS_DELEGATE_AMOUNT_ZERO,
            Self::MissingValidator => STATUS_MISSING_VALIDATOR,
            Self::MissingEpochState => STATUS_MISSING_EPOCH_STATE,
            Self::DelegateInsufficientBalance => STATUS_DELEGATE_INSUFFICIENT_BALANCE,
            Self::DelegateValidatorDisabled => STATUS_DELEGATE_VALIDATOR_DISABLED,
            Self::UndelegateInsufficientBalance => STATUS_UNDELEGATE_INSUFFICIENT_BALANCE,
            Self::UndelegateLocked => STATUS_UNDELEGATE_LOCKED,
            Self::SelfDelegationInsufficient => STATUS_SELF_DELEGATION_INSUFFICIENT,
            Self::ArithmeticOverflow => STATUS_STAKING_ARITHMETIC_OVERFLOW,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenDelegateResult {
    Applied,
    Rejected(TokenDelegateError),
}

impl TokenDelegateResult {
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

/// Source-level reconstruction of `sub_1E5FA70` + `sub_2757FE0`.
///
/// Observed order:
/// 1. Reject absurdly large parsed `wei` before any staking lookups (`319`).
/// 2. Require long-term staking to be enabled (`251`).
/// 3. Require `wei != 0` (`50`).
/// 4. Require the validator record and current epoch delegation snapshot (`145`, `151`).
/// 5. Branch on `is_undelegate`:
///    - delegate: reject disabled validators (`253`), reject insufficient liquid
///      balance (`252`), then add the amount to both live and current-epoch state;
///    - undelegate: reject missing/short/blocked delegation lots (`254`, `255`),
///      enforce the self-delegation floor (`304`), then subtract from both state
///      views.
///
/// [INFERENCE] The binary keeps a few extra side tables in sync as it mutates the
/// two core delegation maps: self-delegation lock timestamps, aggregate delegated
/// totals, and one validator-status flag used when a validator's own delegation
/// changes across a threshold.
pub fn apply_token_delegate(
    state: &mut TokenDelegateState,
    delegator: Address,
    action: &TokenDelegateAction,
) -> TokenDelegateResult {
    match try_apply_token_delegate(state, delegator, action) {
        Ok(()) => TokenDelegateResult::Applied,
        Err(error) => TokenDelegateResult::Rejected(error),
    }
}

fn try_apply_token_delegate(
    state: &mut TokenDelegateState,
    delegator: Address,
    action: &TokenDelegateAction,
) -> Result<(), TokenDelegateError> {
    if action.wei >= 0x0CCC_CCCC_CCCC_CCCC {
        return Err(TokenDelegateError::AmountOverflowGuard { wei: action.wei });
    }
    if !state.long_term_staking_allowed {
        return Err(TokenDelegateError::StakingDisabled);
    }
    if action.wei == 0 {
        return Err(TokenDelegateError::DelegateAmountZero);
    }

    let validator = action.validator;
    let profile = state.validator_profile(&validator)?;
    let _ = state.epoch_delegation_mut(validator, delegator)?;

    if action.is_undelegate {
        apply_undelegate(state, delegator, validator, profile, action.wei)
    } else {
        apply_delegate(state, delegator, validator, profile, action.wei)
    }
}

fn apply_delegate(
    state: &mut TokenDelegateState,
    delegator: Address,
    validator: Address,
    profile: ValidatorProfile,
    wei: Wei,
) -> Result<(), TokenDelegateError> {
    if profile.delegations_disabled {
        return Err(TokenDelegateError::DelegateValidatorDisabled);
    }
    if state.spendable_balance(&delegator) < wei {
        return Err(TokenDelegateError::DelegateInsufficientBalance);
    }

    let epoch = state.epoch_delegation_mut(validator, delegator)?;
    epoch.wei = epoch
        .wei
        .checked_add(wei)
        .ok_or(TokenDelegateError::ArithmeticOverflow)?;

    let live = state.live_delegation_mut(delegator, validator);
    live.wei = live
        .wei
        .checked_add(wei)
        .ok_or(TokenDelegateError::ArithmeticOverflow)?;

    if delegator == validator && !state.foundation_validator_addresses.contains(&validator) {
        let lock = state.self_delegation_locks.entry(validator).or_default();
        let one_year_ms = 31_557_600_000_u64;
        let extended = state.now_ms.saturating_add(one_year_ms);
        lock.unlock_at_ms = Some(lock.unlock_at_ms.map_or(extended, |current| current.max(extended)));
    }

    Ok(())
}

fn apply_undelegate(
    state: &mut TokenDelegateState,
    delegator: Address,
    validator: Address,
    profile: ValidatorProfile,
    wei: Wei,
) -> Result<(), TokenDelegateError> {
    let current_live = state
        .live_delegations
        .get(&(delegator, validator))
        .copied()
        .ok_or(TokenDelegateError::UndelegateInsufficientBalance)?;
    if current_live.undelegations_blocked {
        return Err(TokenDelegateError::UndelegateLocked);
    }
    if current_live.wei < wei {
        return Err(TokenDelegateError::UndelegateInsufficientBalance);
    }

    if delegator == validator && profile.registered {
        if !state.foundation_validator_addresses.contains(&validator) {
            if state
                .self_delegation_locks
                .get(&validator)
                .and_then(|lock| lock.unlock_at_ms)
                .is_some_and(|unlock_at_ms| state.now_ms < unlock_at_ms)
            {
                return Err(TokenDelegateError::UndelegateLocked);
            }
        }

        let remaining = current_live.wei - wei;
        if remaining != 0 && remaining < state.self_delegation_requirement {
            return Err(TokenDelegateError::SelfDelegationInsufficient);
        }
    }

    let epoch = state.epoch_delegation_mut(validator, delegator)?;
    epoch.wei = epoch
        .wei
        .checked_sub(wei)
        .ok_or(TokenDelegateError::UndelegateInsufficientBalance)?;

    let live = state.live_delegation_mut(delegator, validator);
    live.wei = live
        .wei
        .checked_sub(wei)
        .ok_or(TokenDelegateError::UndelegateInsufficientBalance)?;
    if live.wei == 0 {
        state.live_delegations.remove(&(delegator, validator));
    }

    Ok(())
}
