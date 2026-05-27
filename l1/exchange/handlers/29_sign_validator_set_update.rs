#![allow(dead_code)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type B256 = [u8; 32];
pub type Epoch = u64;
pub type Wei = u64;
pub type SignatureBytes = Vec<u8>;

pub const STATUS_OK: u16 = 390;
pub const STATUS_INVALID_VALIDATOR_SET: u16 = 53;
pub const STATUS_INVALID_OR_INACTIVE_SIGNER: u16 = 148;
pub const STATUS_MISSING_EPOCH_STATE: u16 = 151;
pub const STATUS_BAD_SIGNATURE: u16 = 122;
pub const STATUS_SIGNER_MISMATCH: u16 = 287;

pub const BRIDGE_ACTION_TAG: u8 = b'a';
pub const MAINNET_BRIDGE_CHAIN_ID: u64 = 42_161;
pub const TESTNET_BRIDGE_CHAIN_ID: u64 = 421_614;
pub const MAX_TRACKED_VALIDATOR_SET_UPDATES: usize = 100;

/// Compact validator record compared byte-for-byte against the staking snapshot.
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignValidatorSetUpdateAction {
    pub validator_set: ForceIncreaseEpochProfiles,
    /// [INFERENCE] The handler passes the serialized signature blob directly into
    /// the generic bridge-request signer recovery path.
    pub signature: SignatureBytes,
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
pub struct CStakingPartial {
    /// Active validator signer lookup used before any validator-set hashing or
    /// signature recovery.
    pub active_validator_signers: BTreeSet<Address>,
    pub epoch_states: BTreeMap<Epoch, StakingEpochState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeRequest {
    pub tag: u8,
    pub payload_hash: B256,
    pub chain_id: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PendingValidatorSetUpdate {
    pub validator_set: ForceIncreaseEpochProfiles,
    /// [INFERENCE] `sub_3945250` maintains a signer-indexed signature tracker for
    /// each epoch and prunes the oldest epochs once the map grows past 100.
    pub hot_user_to_signature: BTreeMap<Address, SignatureBytes>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExchangeState {
    /// Recovered byte at exchange offset `+2290`; mainnet uses `3` and signs for
    /// Arbitrum One (`42161`), while the alternate lane signs for `421614`.
    pub chain_discriminant: u8,
    pub staking: CStakingPartial,
    pub pending_validator_set_updates: BTreeMap<Epoch, PendingValidatorSetUpdate>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignValidatorSetUpdateError {
    InvalidValidatorSet,
    InvalidOrInactiveSigner,
    MissingEpochState,
    BadSignature,
    SignerMismatch,
}

impl SignValidatorSetUpdateError {
    pub const fn status(self) -> u16 {
        match self {
            Self::InvalidValidatorSet => STATUS_INVALID_VALIDATOR_SET,
            Self::InvalidOrInactiveSigner => STATUS_INVALID_OR_INACTIVE_SIGNER,
            Self::MissingEpochState => STATUS_MISSING_EPOCH_STATE,
            Self::BadSignature => STATUS_BAD_SIGNATURE,
            Self::SignerMismatch => STATUS_SIGNER_MISMATCH,
        }
    }
}

pub trait SignValidatorSetUpdateCrypto {
    fn hash_validator_set(&self, validator_set: &ForceIncreaseEpochProfiles) -> B256;
    fn recover_bridge_request_signer(
        &self,
        request: &BridgeRequest,
        signature: &[u8],
    ) -> Option<Address>;
}

impl CStakingPartial {
    pub fn validator_profiles_at_epoch(
        &self,
        epoch: Epoch,
    ) -> Result<ForceIncreaseEpochProfiles, SignValidatorSetUpdateError> {
        let state = self
            .epoch_states
            .get(&epoch)
            .ok_or(SignValidatorSetUpdateError::MissingEpochState)?;

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
}

#[inline]
pub const fn bridge_chain_id(chain_discriminant: u8) -> u64 {
    if chain_discriminant == 3 {
        MAINNET_BRIDGE_CHAIN_ID
    } else {
        TESTNET_BRIDGE_CHAIN_ID
    }
}

#[inline]
pub fn build_validator_set_update_bridge_request<C: SignValidatorSetUpdateCrypto>(
    crypto: &C,
    chain_discriminant: u8,
    validator_set: &ForceIncreaseEpochProfiles,
) -> BridgeRequest {
    BridgeRequest {
        tag: BRIDGE_ACTION_TAG,
        payload_hash: crypto.hash_validator_set(validator_set),
        chain_id: bridge_chain_id(chain_discriminant),
    }
}

/// Recovered handler logic for `sub_1E642E0` / `sub_374E620`.
///
/// The apply path is:
/// 1. Require the outer signer to be an active validator signer.
/// 2. Recompute the validator-profile set for `action.validator_set.epoch` and
///    require an exact match (`53` on any mismatch).
/// 3. Build the canonical bridge signable request with tag `b'a'` and chain id
///    `42161` on mainnet (`chain_discriminant == 3`) or `421614` otherwise.
/// 4. Recover the signer from `action.signature`; invalid recovery returns `122`
///    and a recovered address mismatch returns `287`.
/// 5. Upsert the `(epoch -> validator_set + hot_user_to_signature)` tracker and
///    prune the oldest epochs until at most 100 remain.
pub fn apply_sign_validator_set_update<C: SignValidatorSetUpdateCrypto>(
    state: &mut ExchangeState,
    signer: Address,
    action: &SignValidatorSetUpdateAction,
    crypto: &C,
) -> Result<(), SignValidatorSetUpdateError> {
    if !state.staking.active_validator_signers.contains(&signer) {
        return Err(SignValidatorSetUpdateError::InvalidOrInactiveSigner);
    }

    let actual = state
        .staking
        .validator_profiles_at_epoch(action.validator_set.epoch)?;
    if actual != action.validator_set {
        return Err(SignValidatorSetUpdateError::InvalidValidatorSet);
    }

    let request = build_validator_set_update_bridge_request(
        crypto,
        state.chain_discriminant,
        &action.validator_set,
    );
    let recovered = crypto
        .recover_bridge_request_signer(&request, &action.signature)
        .ok_or(SignValidatorSetUpdateError::BadSignature)?;
    if recovered != signer {
        return Err(SignValidatorSetUpdateError::SignerMismatch);
    }

    let tracker = state
        .pending_validator_set_updates
        .entry(action.validator_set.epoch)
        .or_insert_with(|| PendingValidatorSetUpdate {
            validator_set: action.validator_set.clone(),
            hot_user_to_signature: BTreeMap::new(),
        });

    if tracker.validator_set != action.validator_set {
        tracker.validator_set = action.validator_set.clone();
        tracker.hot_user_to_signature.clear();
    }
    tracker
        .hot_user_to_signature
        .insert(signer, action.signature.clone());

    while state.pending_validator_set_updates.len() > MAX_TRACKED_VALIDATOR_SET_UPDATES {
        let oldest_epoch = *state
            .pending_validator_set_updates
            .keys()
            .next()
            .expect("non-empty validator-set tracker");
        state.pending_validator_set_updates.remove(&oldest_epoch);
    }

    Ok(())
}
