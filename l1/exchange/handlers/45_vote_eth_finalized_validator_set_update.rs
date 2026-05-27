#![allow(dead_code)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type Epoch = u64;
pub type Wei = u64;
pub type BlockNumber = u64;
pub type ValidatorVoteKey = [u8; 32];

pub const STATUS_OK: u16 = 390;
pub const STATUS_INVALID_VALIDATOR_SET: u16 = 53;
pub const STATUS_MISSING_EPOCH_STATE: u16 = 151;
pub const STATUS_OVERFLOW_GUARD: u16 = 319;
pub const MAX_TRACKED_FINALIZED_VALIDATOR_SET_VOTES: usize = 100;
pub const OVERFLOW_GUARD_U64: u64 = 0x0CCC_CCCC_CCCC_CCCC;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EthEventId {
    pub block_number: BlockNumber,
    pub log_index: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatorProfile {
    pub total_delegated: Wei,
    pub validator: Address,
    pub signer: Address,
}

impl Ord for ValidatorProfile {
    fn cmp(&self, other: &Self) -> Ordering {
        self.total_delegated
            .cmp(&other.total_delegated)
            .then_with(|| self.validator.cmp(&other.validator))
            .then_with(|| self.signer.cmp(&other.signer))
    }
}

impl PartialOrd for ValidatorProfile {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForceIncreaseEpochProfiles {
    pub profiles: BTreeSet<ValidatorProfile>,
    pub epoch: Epoch,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EpochValidatorState {
    pub delegator_balances: BTreeMap<Address, Wei>,
    pub validator: Address,
    pub signer: Address,
}

impl Ord for EpochValidatorState {
    fn cmp(&self, other: &Self) -> Ordering {
        self.validator
            .cmp(&other.validator)
            .then_with(|| self.signer.cmp(&other.signer))
            .then_with(|| self.delegator_balances.cmp(&other.delegator_balances))
    }
}

impl PartialOrd for EpochValidatorState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StakingEpochState {
    pub validators: BTreeSet<EpochValidatorState>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CStakingPartial {
    pub epoch_states: BTreeMap<Epoch, StakingEpochState>,
    /// Recovered read/write at staking offset `+72`.
    pub current_epoch: Epoch,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidatorSetSignatures {
    pub signers: BTreeSet<Address>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidatorSetFinalizedVotes {
    /// [INFERENCE] `sub_374F930` copies a 32-byte token out of the shared preflight
    /// helper and stores it in the finalized-vote bucket before calling the quorum
    /// helper. The concrete token format is left opaque here.
    pub voters: BTreeSet<ValidatorVoteKey>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Bridge2 {
    pub validator_set_signatures: BTreeMap<EthEventId, ValidatorSetSignatures>,
    pub validator_set_finalized_votes: BTreeMap<EthEventId, ValidatorSetFinalizedVotes>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExchangeState {
    pub bridge2: Bridge2,
    pub staking: CStakingPartial,
    /// [INFERENCE] Quorum finalization writes the winning epoch into a second side
    /// table adjacent to `validator_set_finalized_votes` after advancing
    /// `staking.current_epoch`. The binary write site is concrete; the exact table
    /// semantics outside this handler are not.
    pub validator_set_update_epoch_marker: BTreeSet<Epoch>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteEthFinalizedValidatorSetUpdateAction {
    /// [INFERENCE] Protocol notes call this field `header`; the recovered apply path
    /// treats it as the key for the bridge2 validator-set vote tables.
    pub header: EthEventId,
    pub validator_set: ForceIncreaseEpochProfiles,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoteEthFinalizedValidatorSetUpdateError {
    SharedPreflight(u16),
    InvalidValidatorSet,
    MissingEpochState,
    OverflowGuard,
}

impl VoteEthFinalizedValidatorSetUpdateError {
    pub const fn status(self) -> u16 {
        match self {
            Self::SharedPreflight(status) => status,
            Self::InvalidValidatorSet => STATUS_INVALID_VALIDATOR_SET,
            Self::MissingEpochState => STATUS_MISSING_EPOCH_STATE,
            Self::OverflowGuard => STATUS_OVERFLOW_GUARD,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VoteEthFinalizedValidatorSetUpdateOutcome {
    pub status: u16,
    pub finalized: bool,
    pub epoch_advanced: bool,
}

impl VoteEthFinalizedValidatorSetUpdateOutcome {
    pub const fn ok(finalized: bool, epoch_advanced: bool) -> Self {
        Self {
            status: STATUS_OK,
            finalized,
            epoch_advanced,
        }
    }

    pub const fn err(error: VoteEthFinalizedValidatorSetUpdateError) -> Self {
        Self {
            status: error.status(),
            finalized: false,
            epoch_advanced: false,
        }
    }
}

/// Shared helper contract recovered around `base_iter__cham_iterator_unique_elem`
/// and `sub_3940D60`.
pub trait VoteEthFinalizedValidatorSetUpdateSupport {
    fn preflight_vote(
        &self,
        bridge2: &Bridge2,
        staking: &CStakingPartial,
        header: &EthEventId,
        current_epoch: Epoch,
    ) -> Result<ValidatorVoteKey, u16>;

    fn quorum_reached(
        &self,
        bridge2: &Bridge2,
        staking: &CStakingPartial,
        header: &EthEventId,
        voters: &BTreeSet<ValidatorVoteKey>,
    ) -> bool;
}

impl CStakingPartial {
    pub fn validator_profiles_at_epoch(
        &self,
        epoch: Epoch,
    ) -> Result<ForceIncreaseEpochProfiles, VoteEthFinalizedValidatorSetUpdateError> {
        let state = self
            .epoch_states
            .get(&epoch)
            .ok_or(VoteEthFinalizedValidatorSetUpdateError::MissingEpochState)?;

        let mut profiles = BTreeSet::new();
        for validator_state in &state.validators {
            let total_delegated = validator_state
                .delegator_balances
                .values()
                .copied()
                .fold(0_u64, u64::saturating_add);
            assert!(profiles.insert(ValidatorProfile {
                total_delegated,
                validator: validator_state.validator,
                signer: validator_state.signer,
            }));
        }

        Ok(ForceIncreaseEpochProfiles { profiles, epoch })
    }

    pub fn validate_force_epoch_validator_profiles(
        &self,
        expected: &ForceIncreaseEpochProfiles,
    ) -> Result<(), VoteEthFinalizedValidatorSetUpdateError> {
        let actual = self.validator_profiles_at_epoch(expected.epoch)?;
        if actual != *expected {
            return Err(VoteEthFinalizedValidatorSetUpdateError::InvalidValidatorSet);
        }
        Ok(())
    }
}

#[inline]
pub fn validate_validator_set_bounds(
    validator_set: &ForceIncreaseEpochProfiles,
) -> Result<(), VoteEthFinalizedValidatorSetUpdateError> {
    if validator_set.epoch >= OVERFLOW_GUARD_U64 {
        return Err(VoteEthFinalizedValidatorSetUpdateError::OverflowGuard);
    }
    if validator_set
        .profiles
        .iter()
        .any(|profile| profile.total_delegated >= OVERFLOW_GUARD_U64)
    {
        return Err(VoteEthFinalizedValidatorSetUpdateError::OverflowGuard);
    }
    Ok(())
}

#[inline]
pub fn prune_oldest_validator_set_finalized_votes(bridge2: &mut Bridge2) {
    while bridge2.validator_set_finalized_votes.len() > MAX_TRACKED_FINALIZED_VALIDATOR_SET_VOTES {
        let oldest = *bridge2
            .validator_set_finalized_votes
            .keys()
            .next()
            .expect("validator_set_finalized_votes is non-empty");
        bridge2.validator_set_finalized_votes.remove(&oldest);
    }
}

/// Recovered handler for `0x1E64CB0` / `sub_374F930`.
///
/// Grounded flow:
/// 1. Run the shared validator-vote preflight against the action header and the
///    current staking epoch; any failure status is forwarded unchanged.
/// 2. Apply the local overflow guard used by `sub_37A1230` to the submitted
///    validator-set epoch and each validator `total_delegated` value.
/// 3. Recompute the validator profiles for `action.validator_set.epoch` and require
///    an exact match (`53` on mismatch, `151` when the epoch snapshot is missing).
/// 4. If the vote targets an epoch that is not newer than `staking.current_epoch`,
///    return success without mutating bridge2.
/// 5. Otherwise upsert `bridge2.validator_set_finalized_votes[action.header]`, add
///    the preflight vote key, and prune the oldest buckets until at most 100 remain.
/// 6. Once the quorum helper says the finalized-vote bucket is complete, advance
///    `staking.current_epoch` to the voted epoch and record the epoch in the
///    auxiliary marker table.
pub fn apply_vote_eth_finalized_validator_set_update<S>(
    state: &mut ExchangeState,
    action: &VoteEthFinalizedValidatorSetUpdateAction,
    support: &S,
) -> VoteEthFinalizedValidatorSetUpdateOutcome
where
    S: VoteEthFinalizedValidatorSetUpdateSupport,
{
    let current_epoch = state.staking.current_epoch;
    let vote_key = match support.preflight_vote(
        &state.bridge2,
        &state.staking,
        &action.header,
        current_epoch,
    ) {
        Ok(vote_key) => vote_key,
        Err(status) => {
            return VoteEthFinalizedValidatorSetUpdateOutcome::err(
                VoteEthFinalizedValidatorSetUpdateError::SharedPreflight(status),
            )
        }
    };

    if let Err(error) = validate_validator_set_bounds(&action.validator_set) {
        return VoteEthFinalizedValidatorSetUpdateOutcome::err(error);
    }
    if let Err(error) = state
        .staking
        .validate_force_epoch_validator_profiles(&action.validator_set)
    {
        return VoteEthFinalizedValidatorSetUpdateOutcome::err(error);
    }

    if action.validator_set.epoch <= current_epoch {
        return VoteEthFinalizedValidatorSetUpdateOutcome::ok(false, false);
    }

    let (inserted, voters_snapshot) = {
        let vote_bucket = state
            .bridge2
            .validator_set_finalized_votes
            .entry(action.header)
            .or_default();
        let inserted = vote_bucket.voters.insert(vote_key);
        (inserted, vote_bucket.voters.clone())
    };
    let finalized = inserted
        && support.quorum_reached(
            &state.bridge2,
            &state.staking,
            &action.header,
            &voters_snapshot,
        );
    prune_oldest_validator_set_finalized_votes(&mut state.bridge2);

    if !finalized {
        return VoteEthFinalizedValidatorSetUpdateOutcome::ok(false, false);
    }

    state.staking.current_epoch = action.validator_set.epoch;
    state
        .validator_set_update_epoch_marker
        .insert(action.validator_set.epoch);
    VoteEthFinalizedValidatorSetUpdateOutcome::ok(true, true)
}
