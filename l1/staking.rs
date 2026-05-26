use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type Wei = u64;
pub type Epoch = u64;

pub const STAKING_OK_TAG: u16 = 390;
pub const EPOCH_STATE_DOES_NOT_EXIST_TAG: u16 = 151;
pub const INVALID_VALIDATOR_SET_TAG: u16 = 53;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delegation {
    pub validator: Address,
    pub wei: Wei,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Delegations {
    pub delegations: BTreeMap<Address, Wei>,
    pub delegations_blocked: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EpochDelegation {
    pub total_delegated: Wei,
    pub delegator_to_epoch_delegation: BTreeMap<Address, Wei>,
    pub delegations_blocked: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenDelegateAction {
    pub signature_chain_id: u64,
    pub nonce: u64,
    pub hyperliquid_chain: String,
    pub validator: Address,
    pub wei: Wei,
    pub is_undelegate: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimRewardsAction;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CWithdrawAction {
    pub destination: Address,
    pub wei: Wei,
    pub usd: u64,
    pub builder: Option<Address>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CUserModifyAction {
    pub extend_long_term_staking: bool,
    pub profile: Option<CUserProfile>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CUserProfile {
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkStakingUserAction {
    pub staking_user: Address,
    pub trading_user: Address,
    pub nonce: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CStakingAction {
    TokenDelegate(TokenDelegateAction),
    ClaimRewards(ClaimRewardsAction),
    CWithdraw(CWithdrawAction),
    CUserModify(CUserModifyAction),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CValidatorProfile {
    pub node_ip: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub commission_bps: u16,
    pub delegations_disabled: bool,
    pub signer: Address,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CValidatorAction {
    Register {
        profile: CValidatorProfile,
        initial_wei: Wei,
        disable_delegations: bool,
    },
    ChangeProfile(CValidatorProfile),
    Unregister,
}

/// Compact validator record used by validator-set votes.
///
/// The recovered insert comparator orders the raw 48-byte record as:
/// `total_delegated`, then the first 20-byte address, then the second 20-byte
/// address. The caller byte-compares two ordered `BTreeSet`s of this record.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatorProfile {
    pub total_delegated: Wei,
    pub validator: Address,
    pub signer: Address,
}

impl Ord for ValidatorProfile {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.total_delegated
            .cmp(&other.total_delegated)
            .then_with(|| self.validator.cmp(&other.validator))
            .then_with(|| self.signer.cmp(&other.signer))
    }
}

impl PartialOrd for ValidatorProfile {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EpochValidatorState {
    pub delegator_balances: BTreeMap<Address, Wei>,
    pub validator: Address,
    pub signer: Address,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StakingEpochState {
    pub validators: BTreeSet<EpochValidatorState>,
}

impl Ord for EpochValidatorState {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.validator
            .cmp(&other.validator)
            .then_with(|| self.signer.cmp(&other.signer))
            .then_with(|| self.delegator_balances.cmp(&other.delegator_balances))
    }
}

impl PartialOrd for EpochValidatorState {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WithdrawalRequest {
    pub destination: Address,
    pub wei: Wei,
    pub unlock_epoch: Epoch,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RewardState {
    pub unclaimed_rewards: BTreeMap<Address, Wei>,
    pub claimed_rewards: BTreeMap<Address, Wei>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CStaking {
    pub user_to_delegations: BTreeMap<Address, Delegations>,
    pub validator_to_profile: BTreeMap<Address, CValidatorProfile>,
    pub validator_to_epoch_delegation: BTreeMap<Address, EpochDelegation>,
    pub delegator_to_epoch_delegation: BTreeMap<Address, EpochDelegation>,
    pub epoch_states: BTreeMap<Epoch, StakingEpochState>,
    pub rewards: RewardState,
    pub pending_withdrawals: BTreeMap<Address, Vec<WithdrawalRequest>>,
    pub self_delegation_requirement: Wei,
    pub total_delegated: Wei,
    pub staking_epoch_duration_seconds: u64,
    pub long_term_staking_allowed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StakingError {
    EpochStateDoesNotExist,
    InvalidValidatorSet,
    DelegateAmountCannotBeZero,
    DelegateInsufficientBalance,
    DelegateValidatorDisabled,
    UndelegateInsufficientBalance,
    UndelegateLocked,
    CWithdrawInsufficientBalance,
    CStakingTooManyWithdrawals,
    UnregisterCValidatorWithDelegations,
    SelfDelegationInsufficient,
    ArithmeticOverflow,
}

impl StakingError {
    #[inline]
    pub const fn tag(&self) -> u16 {
        match self {
            StakingError::EpochStateDoesNotExist => EPOCH_STATE_DOES_NOT_EXIST_TAG,
            StakingError::InvalidValidatorSet => INVALID_VALIDATOR_SET_TAG,
            _ => 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorProfilesAtEpoch {
    pub profiles: BTreeSet<ValidatorProfile>,
    pub epoch: Epoch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForceIncreaseEpochProfiles {
    pub profiles: BTreeSet<ValidatorProfile>,
    pub epoch: Epoch,
}

impl CStaking {
    /// Recovered from the staking assertion `profiles.insert(validator_profile)`.
    ///
    /// The binary performs an exact `BTreeMap` lookup by epoch, iterates that
    /// epoch's validator entries, sums every delegator balance for each
    /// validator with checked `u64` addition, then inserts the resulting
    /// 48-byte `ValidatorProfile` into a `BTreeSet`. A duplicate profile is an
    /// internal invariant violation in the recovered code.
    #[inline]
    pub fn validator_profiles_at_epoch(
        &self,
        epoch: Epoch,
    ) -> Result<ValidatorProfilesAtEpoch, StakingError> {
        let state = self
            .epoch_states
            .get(&epoch)
            .ok_or(StakingError::EpochStateDoesNotExist)?;

        let mut profiles = BTreeSet::new();
        for validator_state in &state.validators {
            let mut total_delegated = 0_u64;
            for wei in validator_state.delegator_balances.values() {
                total_delegated = total_delegated
                    .checked_add(*wei)
                    .ok_or(StakingError::ArithmeticOverflow)?;
            }

            let validator_profile = ValidatorProfile {
                total_delegated,
                validator: validator_state.validator,
                signer: validator_state.signer,
            };
            assert!(profiles.insert(validator_profile));
        }

        Ok(ValidatorProfilesAtEpoch { profiles, epoch })
    }

    /// Recomputes the validator profile set for the action epoch and compares
    /// it to the supplied profile set in lock-step sorted order.
    #[inline]
    pub fn validate_force_epoch_validator_profiles(
        &self,
        expected: &ForceIncreaseEpochProfiles,
    ) -> Result<(), StakingError> {
        let actual = self.validator_profiles_at_epoch(expected.epoch)?;
        if actual.profiles.len() != expected.profiles.len() {
            return Err(StakingError::InvalidValidatorSet);
        }

        let mut actual_iter = actual.profiles.iter();
        let mut expected_iter = expected.profiles.iter();
        loop {
            match (actual_iter.next(), expected_iter.next()) {
                (None, None) => break,
                (Some(actual_profile), Some(expected_profile)) if actual_profile == expected_profile => {}
                _ => return Err(StakingError::InvalidValidatorSet),
            }
        }

        if actual.epoch == expected.epoch {
            Ok(())
        } else {
            Err(StakingError::InvalidValidatorSet)
        }
    }

    pub fn apply_token_delegate(
        &mut self,
        delegator: Address,
        action: &TokenDelegateAction,
        available_balance: Wei,
    ) -> Result<(), StakingError> {
        if action.wei == 0 {
            return Err(StakingError::DelegateAmountCannotBeZero);
        }

        if action.is_undelegate {
            self.undelegate(delegator, action.validator, action.wei)
        } else {
            if available_balance < action.wei {
                return Err(StakingError::DelegateInsufficientBalance);
            }
            if self
                .validator_to_profile
                .get(&action.validator)
                .map(|profile| profile.delegations_disabled)
                .unwrap_or(false)
            {
                return Err(StakingError::DelegateValidatorDisabled);
            }
            self.delegate(delegator, action.validator, action.wei)
        }
    }

    #[inline]
    pub fn delegate(
        &mut self,
        delegator: Address,
        validator: Address,
        wei: Wei,
    ) -> Result<(), StakingError> {
        let delegations = self.user_to_delegations.entry(delegator).or_default();
        let current = delegations.delegations.entry(validator).or_insert(0);
        *current = current
            .checked_add(wei)
            .ok_or(StakingError::ArithmeticOverflow)?;
        self.total_delegated = self
            .total_delegated
            .checked_add(wei)
            .ok_or(StakingError::ArithmeticOverflow)?;
        Ok(())
    }

    #[inline]
    pub fn undelegate(
        &mut self,
        delegator: Address,
        validator: Address,
        wei: Wei,
    ) -> Result<(), StakingError> {
        let delegations = self
            .user_to_delegations
            .get_mut(&delegator)
            .ok_or(StakingError::UndelegateInsufficientBalance)?;
        if delegations.delegations_blocked {
            return Err(StakingError::UndelegateLocked);
        }

        let current = delegations
            .delegations
            .get_mut(&validator)
            .ok_or(StakingError::UndelegateInsufficientBalance)?;
        if *current < wei {
            return Err(StakingError::UndelegateInsufficientBalance);
        }
        *current -= wei;
        if *current == 0 {
            delegations.delegations.remove(&validator);
        }
        self.total_delegated = self
            .total_delegated
            .checked_sub(wei)
            .ok_or(StakingError::UndelegateInsufficientBalance)?;
        Ok(())
    }

    #[inline]
    pub fn claim_rewards(&mut self, user: Address) -> Wei {
        let reward = self.rewards.unclaimed_rewards.remove(&user).unwrap_or(0);
        let claimed = self.rewards.claimed_rewards.entry(user).or_insert(0);
        *claimed = claimed.saturating_add(reward);
        reward
    }

    #[inline]
    pub fn unregister_validator(&self, validator: Address) -> Result<(), StakingError> {
        let has_delegations = self
            .user_to_delegations
            .values()
            .any(|delegations| delegations.delegations.get(&validator).copied().unwrap_or(0) != 0);
        if has_delegations {
            return Err(StakingError::UnregisterCValidatorWithDelegations);
        }
        Ok(())
    }
}
