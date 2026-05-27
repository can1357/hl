#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type Epoch = u64;
pub type Wei = u64;

pub const STATUS_OK: u16 = 390;
pub const STATUS_BAD_SIGNATURE: u16 = 122;
pub const STATUS_UNKNOWN_VALIDATOR_SLOT: u16 = 148;
pub const STATUS_MISSING_EPOCH_STATE: u16 = 151;
pub const STATUS_EPOCH_GATE_CLOSED: u16 = 152;
pub const STATUS_INSUFFICIENT_QUORUM: u16 = 153;
pub const STATUS_DUPLICATE_FINALIZATION: u16 = 154;
pub const STATUS_SIGNER_MISMATCH: u16 = 287;
pub const STATUS_EPOCH_OVERFLOW: u16 = 319;
pub const STATUS_EPOCH_OUT_OF_RANGE: u16 = 323;

pub const L1_ACTION_CHAIN_ID: u64 = 1337;
pub const MAINNET_CHAIN_DISCRIMINANT: u8 = 3;
pub const MAX_EPOCH_VALUE: u64 = 10_000;
pub const MAX_CACHED_FORCE_EPOCHS: usize = 1_000;

/// Exact 32-byte key used by the recovered handler for both quorum accounting and
/// per-signature validator lookup.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct ValidatorSlotKey(pub [u8; 32]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForceIncreaseEpochSignature {
    pub slot_key: ValidatorSlotKey,
    pub signature: Vec<u8>,
}

/// The serializer string says `ForceIncreaseEpochAction` has three fields.
///
/// The handler only interprets the first trailing word as the requested epoch.
/// The second trailing word is included in the signed preimage but is otherwise
/// opaque to the apply path recovered here.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ForceIncreaseEpochSignedFields {
    pub epoch: Epoch,
    pub trailing_word: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ForceIncreaseEpochAction {
    pub signatures: Vec<ForceIncreaseEpochSignature>,
    pub signed_fields: ForceIncreaseEpochSignedFields,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PackedDateTime {
    pub unix_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochValidatorMember {
    pub slot_key: ValidatorSlotKey,
    pub signer: Address,
    pub delegated_wei: Wei,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StakingEpochState {
    pub validators_by_slot: BTreeMap<ValidatorSlotKey, EpochValidatorMember>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ForceEpochState {
    /// Epoch length divisor used by the gate helper.
    pub epoch_duration_seconds: u64,
    /// Last wall-clock snapshot persisted after a successful force.
    pub last_force_time: PackedDateTime,
    /// Recovered mode word checked by the gate helper; mode `3` bypasses the
    /// initial bootstrap restriction.
    pub mode: u64,
    /// Last epoch forced during bootstrap mode.
    pub bootstrap_forced_epoch: Epoch,
    /// Lowest epoch still accepted by the gate helper.
    pub next_allowed_epoch: Epoch,
    /// Active epoch snapshots keyed by epoch.
    pub epoch_states: BTreeMap<Epoch, StakingEpochState>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Exchange {
    /// Byte at recovered offset `+0x8f2`; mainnet uses `3`, which signs with
    /// source byte `b'a'`. Other observed values sign with `b'b'`.
    pub chain_discriminant: u8,
    /// State at recovered offset `+0x3840`.
    pub force_epoch_state: ForceEpochState,
    /// Secondary finalization table touched after a successful force at recovered
    /// offset `+0x3438`.
    pub finalized_force_epochs: BTreeSet<Epoch>,
    /// Current block time used by the gate helper.
    pub now: PackedDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForceIncreaseEpochError {
    BadSignature,
    UnknownValidatorSlot,
    MissingEpochState,
    EpochGateClosed,
    InsufficientQuorum,
    DuplicateFinalization,
    SignerMismatch,
    EpochOverflow,
    EpochOutOfRange,
}

impl ForceIncreaseEpochError {
    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::BadSignature => STATUS_BAD_SIGNATURE,
            Self::UnknownValidatorSlot => STATUS_UNKNOWN_VALIDATOR_SLOT,
            Self::MissingEpochState => STATUS_MISSING_EPOCH_STATE,
            Self::EpochGateClosed => STATUS_EPOCH_GATE_CLOSED,
            Self::InsufficientQuorum => STATUS_INSUFFICIENT_QUORUM,
            Self::DuplicateFinalization => STATUS_DUPLICATE_FINALIZATION,
            Self::SignerMismatch => STATUS_SIGNER_MISMATCH,
            Self::EpochOverflow => STATUS_EPOCH_OVERFLOW,
            Self::EpochOutOfRange => STATUS_EPOCH_OUT_OF_RANGE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForceIncreaseEpochOutcome {
    pub status: u16,
}

impl ForceIncreaseEpochOutcome {
    #[inline]
    pub const fn ok() -> Self {
        Self { status: STATUS_OK }
    }

    #[inline]
    pub const fn err(error: ForceIncreaseEpochError) -> Self {
        Self {
            status: error.status(),
        }
    }
}

/// Recovered apply wrapper for `sub_21E0A00`.
///
/// High-confidence flow:
/// 1. Load the requested epoch from the first word of the signed tail.
/// 2. Look up the staking epoch snapshot and reject `151` if missing.
/// 3. Reject out-of-range/overflowing epoch values before any signature work.
/// 4. Require the submitted validator slots to represent strictly more than
///    two-thirds of the delegated stake of the target epoch.
/// 5. Run the epoch-transition gate; this can reject stale or premature forces
///    with `152`.
/// 6. Verify every submitted signature against the signable payload
///    `("forceIncreaseEpoch", signed_fields, source_byte, 1337)` and ensure the
///    recovered signer matches the signer recorded in the epoch snapshot.
/// 7. Advance `next_allowed_epoch`, persist the new wall-clock snapshot, prune old
///    cached epoch entries once the rolling window exceeds 1000, and insert the
///    finalized epoch into the side table (duplicate insert => `154`).
pub fn force_increase_epoch(
    exchange: &mut Exchange,
    action: &ForceIncreaseEpochAction,
    crypto: &impl ForceEpochCrypto,
) -> ForceIncreaseEpochOutcome {
    let epoch = action.signed_fields.epoch;

    let epoch_state = match exchange.force_epoch_state.epoch_states.get(&epoch) {
        Some(epoch_state) => epoch_state.clone(),
        None => return ForceIncreaseEpochOutcome::err(ForceIncreaseEpochError::MissingEpochState),
    };

    if epoch > MAX_EPOCH_VALUE {
        return ForceIncreaseEpochOutcome::err(ForceIncreaseEpochError::EpochOutOfRange);
    }
    if epoch.checked_add(1).is_none() {
        return ForceIncreaseEpochOutcome::err(ForceIncreaseEpochError::EpochOverflow);
    }

    if !has_supermajority_quorum(&epoch_state, &action.signatures) {
        return ForceIncreaseEpochOutcome::err(ForceIncreaseEpochError::InsufficientQuorum);
    }

    if let Err(error) = gate_and_rotate_force_epoch_state(&mut exchange.force_epoch_state, exchange.now, exchange.chain_discriminant, epoch) {
        return ForceIncreaseEpochOutcome::err(error);
    }

    let signable = build_force_epoch_signable_bytes(action.signed_fields, exchange.chain_discriminant);
    for submitted in &action.signatures {
        let member = match epoch_state.validators_by_slot.get(&submitted.slot_key) {
            Some(member) => member,
            None => return ForceIncreaseEpochOutcome::err(ForceIncreaseEpochError::UnknownValidatorSlot),
        };

        let recovered = match crypto.recover_force_epoch_signer(&signable, &submitted.signature) {
            Some(recovered) => recovered,
            None => return ForceIncreaseEpochOutcome::err(ForceIncreaseEpochError::BadSignature),
        };

        if recovered != member.signer {
            return ForceIncreaseEpochOutcome::err(ForceIncreaseEpochError::SignerMismatch);
        }
    }

    if has_active_force_epoch_cache(&exchange.force_epoch_state)
        && !exchange.finalized_force_epochs.insert(epoch)
    {
        return ForceIncreaseEpochOutcome::err(ForceIncreaseEpochError::DuplicateFinalization);
    }

    prune_cached_epochs(&mut exchange.force_epoch_state);
    ForceIncreaseEpochOutcome::ok()
}

#[inline]
pub fn has_supermajority_quorum(
    epoch_state: &StakingEpochState,
    submitted: &[ForceIncreaseEpochSignature],
) -> bool {
    let total_weight = epoch_state
        .validators_by_slot
        .values()
        .fold(0_u64, |acc, member| acc.saturating_add(member.delegated_wei));

    let submitted_slots: BTreeSet<_> = submitted.iter().map(|entry| entry.slot_key).collect();
    let signed_weight = submitted_slots
        .into_iter()
        .filter_map(|slot| epoch_state.validators_by_slot.get(&slot))
        .fold(0_u64, |acc, member| acc.saturating_add(member.delegated_wei));

    (signed_weight as u128) * 3 > (total_weight as u128) * 2
}

/// Recovered gate from `sub_33696B0`.
///
/// The helper keeps a rolling lower bound (`next_allowed_epoch`) and compares the
/// requested epoch against the current wall-clock epoch bucket. On the very first
/// force it permits a bootstrap override when either the chain byte is nonzero or
/// the internal mode word equals `3`; afterward the request must move the system
/// forward.
pub fn gate_and_rotate_force_epoch_state(
    state: &mut ForceEpochState,
    now: PackedDateTime,
    chain_discriminant: u8,
    requested_epoch: Epoch,
) -> Result<(), ForceIncreaseEpochError> {
    if requested_epoch < state.next_allowed_epoch {
        return Err(ForceIncreaseEpochError::EpochGateClosed);
    }

    let Some(current_wall_clock_epoch) = current_epoch_bucket(state.epoch_duration_seconds, now) else {
        return Err(ForceIncreaseEpochError::EpochGateClosed);
    };

    let bootstrap_override = state.bootstrap_forced_epoch == 0
        && (chain_discriminant != 0 || state.mode == 3);
    if !bootstrap_override && requested_epoch <= current_wall_clock_epoch {
        return Err(ForceIncreaseEpochError::EpochGateClosed);
    }

    if bootstrap_override {
        state.bootstrap_forced_epoch = state.next_allowed_epoch;
    }
    state.next_allowed_epoch = requested_epoch.saturating_add(1);
    state.last_force_time = now;
    Ok(())
}

#[inline]
pub fn current_epoch_bucket(epoch_duration_seconds: u64, now: PackedDateTime) -> Option<Epoch> {
    if epoch_duration_seconds == 0 {
        return None;
    }
    Some(now.unix_seconds / epoch_duration_seconds)
}
#[inline]
pub fn has_active_force_epoch_cache(state: &ForceEpochState) -> bool {
    !state.epoch_states.is_empty()
}


#[inline]
pub fn prune_cached_epochs(state: &mut ForceEpochState) {
    while state.epoch_states.len() > MAX_CACHED_FORCE_EPOCHS {
        let Some(oldest) = state.epoch_states.keys().next().copied() else {
            break;
        };
        state.epoch_states.remove(&oldest);
    }
}

#[inline]
pub fn build_force_epoch_signable_bytes(
    fields: ForceIncreaseEpochSignedFields,
    chain_discriminant: u8,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(18 + 16 + 1 + 8);
    out.extend_from_slice(b"forceIncreaseEpoch");
    out.extend_from_slice(&fields.epoch.to_le_bytes());
    out.extend_from_slice(&fields.trailing_word.to_le_bytes());
    out.push(if chain_discriminant == MAINNET_CHAIN_DISCRIMINANT {
        b'a'
    } else {
        b'b'
    });
    out.extend_from_slice(&L1_ACTION_CHAIN_ID.to_le_bytes());
    out
}

pub trait ForceEpochCrypto {
    fn recover_force_epoch_signer(&self, signable: &[u8], signature: &[u8]) -> Option<Address>;
}
