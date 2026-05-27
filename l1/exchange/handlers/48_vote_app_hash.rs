#![allow(dead_code)]

use std::collections::BTreeMap;

pub type Address = [u8; 20];
pub type AppHash = [u8; 32];
pub type BlockHeight = u64;
pub type SignatureBytes = Vec<u8>;

pub const STATUS_OK: u16 = 390;
pub const STATUS_SIGNER_CONTEXT_MISSING: u16 = 151;
pub const STATUS_SIGNER_CONTEXT_NOT_FOUND: u16 = 42;
pub const STATUS_BAD_SIGNATURE: u16 = 122;
pub const STATUS_SIGNER_MISMATCH: u16 = 287;
pub const STATUS_HEIGHT_OVERFLOW: u16 = 319;

pub const HEIGHT_SERIALIZATION_LIMIT_EXCLUSIVE: u64 = 0x0CCC_CCCC_CCCC_CCCC;
pub const VOTE_RETENTION_HEIGHT_DELTA: u64 = 50_000;

/// Recovered from `protocol/l1_action_payloads.md` and the wrapper at
/// `sub_1E5F5D0`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteAppHashAction {
    pub app_hash: AppHash,
    pub height: BlockHeight,
    pub signature: SignatureBytes,
}

/// `sub_33690C0` resolves a unique 32-byte record for the current hot signer out
/// of the live validator/app-hash context before the vote tracker mutates.
///
/// [INFERENCE] The binary treats this as an opaque signer identity / quorum slot;
/// the exact source-level meaning is not recoverable from the wrapper alone, but
/// it is stable enough to key replacement votes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SignerVoteKey(pub [u8; 32]);

/// Tracker entry recovered from `struct QuorumAppHash` and the `sub_3946A80`
/// mutation path.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct QuorumAppHash {
    pub app_hash: AppHash,
    pub hot_user_to_signature: BTreeMap<Address, SignatureBytes>,
}

/// Per-target-height vote window.
///
/// [INFERENCE] `sub_3946A80` maintains both a signer-key -> app-hash index and an
/// app-hash -> signature bucket map so a signer can replace an earlier vote for
/// the same target height without being counted twice.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AppHashVoteWindow {
    pub signer_votes: BTreeMap<SignerVoteKey, AppHash>,
    pub app_hash_to_votes: BTreeMap<AppHash, QuorumAppHash>,
    pub finalized: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExchangeState {
    /// [INFERENCE] Outer key passed into `sub_33690C0`; it selects the current
    /// signer-resolution snapshot used before any vote mutation.
    pub current_signer_context_height: BlockHeight,
    /// Snapshot-scoped signer lookup consulted by `resolve_signer_vote_key`.
    pub signer_context: BTreeMap<BlockHeight, BTreeMap<Address, SignerVoteKey>>,
    /// Vote tracker keyed by the target app-hash height from the payload.
    pub app_hash_votes: BTreeMap<BlockHeight, AppHashVoteWindow>,
    /// Highest target height accepted so far; `sub_336A4E0` prunes anything more
    /// than 50_000 heights behind this watermark.
    pub max_tracked_vote_height: BlockHeight,
    /// Materialized handoff queue consumed later by the ABCI/execution layer.
    pub emitted_handoffs: Vec<AppHashHandoff>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppHashHandoff {
    pub height: BlockHeight,
    pub app_hash: AppHash,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoteAppHashError {
    SignerContextMissing,
    SignerContextNotFound,
    BadSignature,
    SignerMismatch,
    HeightOverflow,
}

impl VoteAppHashError {
    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::SignerContextMissing => STATUS_SIGNER_CONTEXT_MISSING,
            Self::SignerContextNotFound => STATUS_SIGNER_CONTEXT_NOT_FOUND,
            Self::BadSignature => STATUS_BAD_SIGNATURE,
            Self::SignerMismatch => STATUS_SIGNER_MISMATCH,
            Self::HeightOverflow => STATUS_HEIGHT_OVERFLOW,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoteAppHashFinalizeMode {
    RecordedOnly,
    FinalizedNow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VoteAppHashOutcome {
    pub status: u16,
    /// Mirrors the success byte returned by `sub_336A4E0`: `false` means the vote
    /// was accepted but did not finalize an app-hash handoff; `true` means the
    /// handoff record was materialized immediately.
    pub finalized_now: bool,
}

impl VoteAppHashOutcome {
    #[inline]
    pub const fn ok(mode: VoteAppHashFinalizeMode) -> Self {
        Self {
            status: STATUS_OK,
            finalized_now: matches!(mode, VoteAppHashFinalizeMode::FinalizedNow),
        }
    }

    #[inline]
    pub const fn err(error: VoteAppHashError) -> Self {
        Self {
            status: error.status(),
            finalized_now: false,
        }
    }
}

/// Minimal cryptographic contract recovered from `sub_1E5F5D0`:
/// 1. serialize the canonical `(height, app_hash)` signable message,
/// 2. keccak it via `l1_utils__keccak_rmp_u64_h256_hex`,
/// 3. recover an address from `action.signature`.
pub trait VoteAppHashCrypto {
    fn recover_vote_app_hash_signer(
        &self,
        height: BlockHeight,
        app_hash: &AppHash,
        signature: &[u8],
    ) -> Option<Address>;
}

/// Exact high-level flow recovered from `sub_1E5F5D0` + `sub_336A4E0`:
/// 1. reject heights at or above `0x0CCC_CCCC_CCCC_CCCC` with `319`;
/// 2. recover the signing address from the canonical `(height, app_hash)` hash,
///    returning `122` on failure and `287` on signer mismatch;
/// 3. resolve the caller's current 32-byte signer slot from the live signer
///    context (`151` if the outer snapshot is missing, `42` if the signer is not
///    present in that snapshot);
/// 4. upsert the `(target_height, app_hash)` quorum bucket, replacing any older
///    vote from the same signer slot for that target height;
/// 5. if the updated bucket crosses quorum, emit a finalized app-hash handoff and
///    prune windows older than `max_height - 50_000`; otherwise return success
///    with `finalized_now = false`.
pub fn apply_vote_app_hash<C, Q>(
    state: &mut ExchangeState,
    signer: Address,
    action: &VoteAppHashAction,
    crypto: &C,
    quorum: &Q,
) -> VoteAppHashOutcome
where
    C: VoteAppHashCrypto,
    Q: AppHashVoteQuorum,
{
    if action.height >= HEIGHT_SERIALIZATION_LIMIT_EXCLUSIVE {
        return VoteAppHashOutcome::err(VoteAppHashError::HeightOverflow);
    }

    let recovered = match crypto.recover_vote_app_hash_signer(action.height, &action.app_hash, &action.signature) {
        Some(recovered) => recovered,
        None => return VoteAppHashOutcome::err(VoteAppHashError::BadSignature),
    };
    if recovered != signer {
        return VoteAppHashOutcome::err(VoteAppHashError::SignerMismatch);
    }

    let signer_key = match resolve_signer_vote_key(state, signer) {
        Ok(key) => key,
        Err(error) => return VoteAppHashOutcome::err(error),
    };

    let finalized = record_app_hash_vote(state, signer_key, signer, action, quorum);
    VoteAppHashOutcome::ok(if finalized {
        VoteAppHashFinalizeMode::FinalizedNow
    } else {
        VoteAppHashFinalizeMode::RecordedOnly
    })
}

#[inline]
pub fn resolve_signer_vote_key(
    state: &ExchangeState,
    signer: Address,
) -> Result<SignerVoteKey, VoteAppHashError> {
    let snapshot = state
        .signer_context
        .get(&state.current_signer_context_height)
        .ok_or(VoteAppHashError::SignerContextMissing)?;
    snapshot
        .get(&signer)
        .copied()
        .ok_or(VoteAppHashError::SignerContextNotFound)
}

pub trait AppHashVoteQuorum {
    fn quorum_reached(&self, votes: &QuorumAppHash) -> bool;
}

pub fn record_app_hash_vote<Q>(
    state: &mut ExchangeState,
    signer_key: SignerVoteKey,
    signer: Address,
    action: &VoteAppHashAction,
    quorum: &Q,
) -> bool
where
    Q: AppHashVoteQuorum,
{
    let window = state.app_hash_votes.entry(action.height).or_default();

    if let Some(previous_app_hash) = window.signer_votes.insert(signer_key, action.app_hash) {
        if previous_app_hash != action.app_hash {
            let should_remove = if let Some(previous_bucket) = window.app_hash_to_votes.get_mut(&previous_app_hash) {
                previous_bucket.hot_user_to_signature.remove(&signer);
                previous_bucket.hot_user_to_signature.is_empty()
            } else {
                false
            };
            if should_remove {
                window.app_hash_to_votes.remove(&previous_app_hash);
            }
        }
    }

    let bucket = window
        .app_hash_to_votes
        .entry(action.app_hash)
        .or_insert_with(|| QuorumAppHash {
            app_hash: action.app_hash,
            hot_user_to_signature: BTreeMap::new(),
        });
    bucket
        .hot_user_to_signature
        .insert(signer, action.signature.clone());

    if window.finalized || !quorum.quorum_reached(bucket) {
        return false;
    }

    window.finalized = true;
    state.max_tracked_vote_height = state.max_tracked_vote_height.max(action.height);
    state.emitted_handoffs.push(AppHashHandoff {
        height: action.height,
        app_hash: action.app_hash,
    });
    prune_old_vote_windows(state);
    true
}

pub fn prune_old_vote_windows(state: &mut ExchangeState) {
    let floor = state
        .max_tracked_vote_height
        .saturating_sub(VOTE_RETENTION_HEIGHT_DELTA);
    state.app_hash_votes.retain(|height, _| *height >= floor);
}
