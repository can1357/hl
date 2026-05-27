#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type TimestampSeconds = u64;
pub type ValidatorSetId = [u8; 32];

pub const STATUS_OK: u16 = 390;
pub const STATUS_CALLER_NOT_ALLOWED: u16 = 148;
pub const STATUS_MISSING_VALIDATOR_SET: u16 = 145;
pub const STATUS_INVALID_VALIDATOR_SET: u16 = 53;
pub const STATUS_TOO_MANY_PENDING_VALIDATOR_L1_VOTES: u16 = 54;

pub const MAX_PENDING_VALIDATOR_L1_VOTES_PER_ACTION: usize = 49;
pub const VALIDATOR_L1_VOTE_TTL_SECS: TimestampSeconds = 7 * 24 * 60 * 60;

/// Recovered wrapper for `sub_22CDB40`.
///
/// The binary does not apply the nested governance payload immediately. Instead it:
/// 1. requires validator-mode auth and a validator signer that is present in the
///    current validator-vote registry,
/// 2. estimates how many concrete vote records the payload would fan out into and
///    rejects overly large batches with `54`,
/// 3. records the caller in the `l1_vote_tracker` bucket for the current validator
///    set snapshot, and
/// 4. only once the tracker reaches quorum, forwards the payload into the shared
///    `VoteGlobal` apply path (`sub_2387390`).
///
/// The downstream apply helper reuses the same payload family as `VoteGlobalAction`.
/// High-confidence side effects recovered from `sub_2387390`:
/// - some variants resolve asset or dex names before delegating into the global
///   governance executor,
/// - quote-token votes flip the aligned quote-token enable bit directly,
/// - clearinghouse enable/disable votes update a per-dex state byte and may cancel
///   every open order for the affected dex when disabling,
/// - several larger variants are forwarded wholesale into existing `VoteGlobal`
///   helpers after quorum is reached.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorL1VoteEnvelope<P> {
    pub caller: Address,
    pub validator_mode: bool,
    pub payload: P,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidatorMembership {
    pub signer: Address,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidatorVoteSet {
    pub id: ValidatorSetId,
    pub voters: BTreeSet<Address>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingValidatorL1Vote<P> {
    pub payload: P,
    pub validator_set_id: ValidatorSetId,
    pub voters: BTreeSet<Address>,
    pub expires_at: TimestampSeconds,
    pub applied: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Exchange<P> {
    /// VoteGlobal raw tag `0x53` toggles this path.  The recovered wrapper still
    /// enforces validator-mode auth even when the flag is enabled.
    pub validator_l1_vote_enabled: bool,
    /// Validator signer registry consulted before any tracker mutation.
    pub validator_membership: BTreeMap<Address, ValidatorMembership>,
    /// Snapshot used to scope vote trackers and quorum checks.
    pub current_validator_set: Option<ValidatorVoteSet>,
    /// `l1_vote_tracker` state keyed by the nested payload.
    pub pending_validator_l1_votes: BTreeMap<P, PendingValidatorL1Vote<P>>,
    pub now_unix_seconds: TimestampSeconds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidatorL1VoteError {
    CallerNotAllowed,
    MissingValidatorSet,
    InvalidValidatorSet,
    TooManyPendingValidatorL1Votes,
    NestedApply(u16),
}

impl ValidatorL1VoteError {
    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::CallerNotAllowed => STATUS_CALLER_NOT_ALLOWED,
            Self::MissingValidatorSet => STATUS_MISSING_VALIDATOR_SET,
            Self::InvalidValidatorSet => STATUS_INVALID_VALIDATOR_SET,
            Self::TooManyPendingValidatorL1Votes => STATUS_TOO_MANY_PENDING_VALIDATOR_L1_VOTES,
            Self::NestedApply(status) => status,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatorL1VoteOutcome {
    pub status: u16,
    /// Set once the pending vote tracker says this submission finalized the vote.
    pub finalized: bool,
    /// Set once the downstream `VoteGlobal` mutation actually ran.
    pub applied: bool,
}

impl ValidatorL1VoteOutcome {
    #[inline]
    pub const fn ok(finalized: bool, applied: bool) -> Self {
        Self {
            status: STATUS_OK,
            finalized,
            applied,
        }
    }

    #[inline]
    pub const fn err(error: ValidatorL1VoteError) -> Self {
        Self {
            status: error.status(),
            finalized: false,
            applied: false,
        }
    }
}

/// Minimal contract recovered from the validator-vote wrapper.
///
/// The wrapper itself knows how to gate validators, bound fan-out, persist pending
/// vote records, and detect finalization.  Payload-specific quorum semantics and the
/// final `VoteGlobal` mutation stay in the executor so the generic tracker remains
/// faithful to the binary split between `sub_3949140` and `sub_2387390`.
pub trait ValidatorL1VoteExecutor<P> {
    fn pending_item_count(&self, exchange: &Exchange<P>, payload: &P) -> usize;

    fn quorum_reached(&self, validator_set: &ValidatorVoteSet, voters: &BTreeSet<Address>) -> bool;

    fn apply_finalized_vote(&self, exchange: &mut Exchange<P>, payload: &P) -> Result<(), u16>;
}

pub fn apply_validator_l1_vote<P, E>(
    exchange: &mut Exchange<P>,
    envelope: &ValidatorL1VoteEnvelope<P>,
    executor: &E,
) -> ValidatorL1VoteOutcome
where
    P: Clone + Ord,
    E: ValidatorL1VoteExecutor<P>,
{
    if !exchange.validator_l1_vote_enabled || !envelope.validator_mode {
        return ValidatorL1VoteOutcome::err(ValidatorL1VoteError::CallerNotAllowed);
    }
    if !exchange.validator_membership.contains_key(&envelope.caller) {
        return ValidatorL1VoteOutcome::err(ValidatorL1VoteError::CallerNotAllowed);
    }

    let validator_set = match exchange.current_validator_set.clone() {
        Some(set) => set,
        None => return ValidatorL1VoteOutcome::err(ValidatorL1VoteError::MissingValidatorSet),
    };
    if !validator_set.voters.contains(&envelope.caller) {
        return ValidatorL1VoteOutcome::err(ValidatorL1VoteError::InvalidValidatorSet);
    }

    let pending_item_count = executor.pending_item_count(exchange, &envelope.payload);
    if pending_item_count > MAX_PENDING_VALIDATOR_L1_VOTES_PER_ACTION {
        return ValidatorL1VoteOutcome::err(ValidatorL1VoteError::TooManyPendingValidatorL1Votes);
    }

    prune_expired_validator_l1_votes(exchange);

    let key = envelope.payload.clone();
    let expires_at = exchange
        .now_unix_seconds
        .saturating_add(VALIDATOR_L1_VOTE_TTL_SECS);

    let (finalized, inserted, payload_to_apply) = {
        let entry = exchange
            .pending_validator_l1_votes
            .entry(key)
            .or_insert_with(|| PendingValidatorL1Vote {
                payload: envelope.payload.clone(),
                validator_set_id: validator_set.id,
                voters: BTreeSet::new(),
                expires_at,
                applied: false,
            });

        if entry.validator_set_id != validator_set.id {
            *entry = PendingValidatorL1Vote {
                payload: envelope.payload.clone(),
                validator_set_id: validator_set.id,
                voters: BTreeSet::new(),
                expires_at,
                applied: false,
            };
        }

        entry.expires_at = expires_at;
        if entry.applied {
            return ValidatorL1VoteOutcome::ok(true, false);
        }

        let inserted = entry.voters.insert(envelope.caller);
        let finalized = inserted && executor.quorum_reached(&validator_set, &entry.voters);
        let payload_to_apply = finalized.then(|| entry.payload.clone());
        (finalized, inserted, payload_to_apply)
    };

    if !inserted {
        return ValidatorL1VoteOutcome::ok(false, false);
    }
    if !finalized {
        return ValidatorL1VoteOutcome::ok(false, false);
    }

    let payload_to_apply = payload_to_apply.expect("finalized vote must have a payload clone");
    if let Err(status) = executor.apply_finalized_vote(exchange, &payload_to_apply) {
        return ValidatorL1VoteOutcome::err(ValidatorL1VoteError::NestedApply(status));
    }

    if let Some(entry) = exchange.pending_validator_l1_votes.get_mut(&envelope.payload) {
        entry.applied = true;
    }

    ValidatorL1VoteOutcome::ok(true, true)
}

#[inline]
pub fn prune_expired_validator_l1_votes<P>(exchange: &mut Exchange<P>)
where
    P: Ord,
{
    let now = exchange.now_unix_seconds;
    exchange
        .pending_validator_l1_votes
        .retain(|_, vote| vote.expires_at >= now && !vote.applied);
}
