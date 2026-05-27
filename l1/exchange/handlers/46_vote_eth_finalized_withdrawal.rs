#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type B256 = [u8; 32];
pub type Nonce = u64;
pub type TimestampMillis = u64;
pub type Usd = u64;

pub const STATUS_OK: u16 = 390;
pub const STATUS_PENDING_WITHDRAWAL_MISSING_OR_MISMATCHED: u16 = 144;
pub const STATUS_AMOUNT_OVERFLOW: u16 = 319;
pub const MAX_TRACKED_FINALIZED_WITHDRAWALS: usize = 100;
pub const USD_SCALE: f64 = 1_000_000.0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VoteEthFinalizedWithdrawalAction {
    pub eth_tx_hash: B256,
    pub nonce: Nonce,
    pub usd: Usd,
    pub user: Address,
    pub destination: Address,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UserAndNonce {
    pub nonce: Nonce,
    pub user: Address,
}

impl UserAndNonce {
    pub const fn new(nonce: Nonce, user: Address) -> Self {
        Self { nonce, user }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Withdrawal {
    pub usd: Usd,
    pub destination: Address,
}

impl Withdrawal {
    pub const fn new(usd: Usd, destination: Address) -> Self {
        Self { usd, destination }
    }
}

/// The binary threads a 32-byte validator-derived record through the vote tracker.
/// [INFERENCE] It is richer than a raw signer address, so the reconstruction keeps
/// the opaque bytes instead of pretending it is just `Address`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ValidatorVoteKey(pub [u8; 32]);

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FinalizedWithdrawalCandidateVotes {
    pub voters: BTreeSet<ValidatorVoteKey>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PendingFinalizedWithdrawalVotes {
    /// The vote map is keyed by the raw 32-byte finalized Ethereum transaction hash.
    pub by_eth_tx_hash: BTreeMap<B256, FinalizedWithdrawalCandidateVotes>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Bridge2 {
    pub withdrawal_signatures: BTreeMap<UserAndNonce, Withdrawal>,
    pub withdrawal_finalized_votes: BTreeMap<UserAndNonce, PendingFinalizedWithdrawalVotes>,
    pub finished_withdrawal_to_time: BTreeMap<UserAndNonce, TimestampMillis>,
    pub bal: Usd,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExchangeState {
    /// Active validator lookup consumed by the shared `base_iter__cham_iterator_unique_elem`
    /// preflight before the handler touches bridge state.
    pub active_validator_votes: BTreeMap<Address, ValidatorVoteKey>,
    pub bridge2: Bridge2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizedWithdrawalEvent {
    pub usd: f64,
    pub nonce: Nonce,
    pub bridge_balance_usd: f64,
    pub user: Address,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VoteEthFinalizedWithdrawalOutcome {
    pub finalized: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoteEthFinalizedWithdrawalError {
    AmountOverflow { usd: Usd },
    ValidatorLookup { status: u16 },
    PendingWithdrawalMissingOrMismatched,
}

impl VoteEthFinalizedWithdrawalError {
    pub const fn status(self) -> u16 {
        match self {
            Self::AmountOverflow { .. } => STATUS_AMOUNT_OVERFLOW,
            Self::ValidatorLookup { status } => status,
            Self::PendingWithdrawalMissingOrMismatched => STATUS_PENDING_WITHDRAWAL_MISSING_OR_MISMATCHED,
        }
    }
}

pub trait VoteEthFinalizedWithdrawalQuorum {
    fn validator_vote_key(&self, state: &ExchangeState, signer: Address) -> Result<ValidatorVoteKey, u16>;
    fn vote_reaches_finality(&self, voters: &BTreeSet<ValidatorVoteKey>) -> bool;
}

pub trait VoteEthFinalizedWithdrawalTelemetry {
    fn emit_finalized_withdrawal(&mut self, event: FinalizedWithdrawalEvent);
}

#[derive(Default)]
pub struct NoopTelemetry;

impl VoteEthFinalizedWithdrawalTelemetry for NoopTelemetry {
    fn emit_finalized_withdrawal(&mut self, _event: FinalizedWithdrawalEvent) {}
}

impl Bridge2 {
    #[inline]
    pub fn pending_withdrawal_matches(&self, key: UserAndNonce, withdrawal: Withdrawal) -> bool {
        self.withdrawal_signatures.get(&key).copied() == Some(withdrawal)
    }

    pub fn record_finalized_vote<Q: VoteEthFinalizedWithdrawalQuorum>(
        &mut self,
        key: UserAndNonce,
        eth_tx_hash: B256,
        voter: ValidatorVoteKey,
        quorum: &Q,
    ) -> bool {
        let pending = self.withdrawal_finalized_votes.entry(key).or_default();
        let candidate = pending.by_eth_tx_hash.entry(eth_tx_hash).or_default();
        candidate.voters.insert(voter);
        let finalized = quorum.vote_reaches_finality(&candidate.voters);

        while self.withdrawal_finalized_votes.len() > MAX_TRACKED_FINALIZED_WITHDRAWALS {
            let oldest = self
                .withdrawal_finalized_votes
                .keys()
                .next()
                .copied()
                .expect("vote tracker is non-empty while pruning");
            self.withdrawal_finalized_votes.remove(&oldest);
        }

        finalized
    }

    pub fn finalize_withdrawal(&mut self, key: UserAndNonce, now_ms: TimestampMillis) {
        self.finished_withdrawal_to_time.insert(key, now_ms);
        self.withdrawal_signatures.remove(&key);
        self.withdrawal_finalized_votes.remove(&key);
    }
}

/// Recovered handler logic for `0x27177C0` / `0x374F5B0`.
///
/// Grounded control flow:
/// 1. Reject `action.usd >= 0xCCCCCCCCCCCCCCCC` with compact status `319`.
/// 2. Resolve the outer signer through the shared validator lookup used by the
///    ETH bridge vote handlers; any non-`390` preflight status bubbles out.
/// 3. Build `UserAndNonce { user, nonce }` and require an exact pending
///    `Withdrawal { usd, destination }` match in bridge2, otherwise return `144`.
/// 4. Upsert the finalized-vote tracker for that `(user, nonce)` key, keyed again
///    by the raw `eth_tx_hash`, and add the validator-derived vote record.
/// 5. Cap the tracker at 100 keyed withdrawals.
/// 6. When quorum reports finality, move the key into
///    `finished_withdrawal_to_time`, remove both the pending withdrawal and the
///    finalized-vote tracker entry, then emit a compact event containing
///    `(usd / 1e6, nonce, bridge_balance / 1e6, user)`.
pub fn apply_vote_eth_finalized_withdrawal<
    Q: VoteEthFinalizedWithdrawalQuorum,
    T: VoteEthFinalizedWithdrawalTelemetry,
>(
    state: &mut ExchangeState,
    signer: Address,
    action: &VoteEthFinalizedWithdrawalAction,
    now_ms: TimestampMillis,
    quorum: &Q,
    telemetry: &mut T,
) -> Result<VoteEthFinalizedWithdrawalOutcome, VoteEthFinalizedWithdrawalError> {
    if action.usd >= 0xCCCC_CCCC_CCCC_CCCC {
        return Err(VoteEthFinalizedWithdrawalError::AmountOverflow { usd: action.usd });
    }

    let validator_vote_key = quorum
        .validator_vote_key(state, signer)
        .map_err(|status| VoteEthFinalizedWithdrawalError::ValidatorLookup { status })?;

    let key = UserAndNonce::new(action.nonce, action.user);
    let withdrawal = Withdrawal::new(action.usd, action.destination);
    if !state.bridge2.pending_withdrawal_matches(key, withdrawal) {
        return Err(VoteEthFinalizedWithdrawalError::PendingWithdrawalMissingOrMismatched);
    }

    let finalized = state
        .bridge2
        .record_finalized_vote(key, action.eth_tx_hash, validator_vote_key, quorum);

    if finalized {
        state.bridge2.finalize_withdrawal(key, now_ms);
        telemetry.emit_finalized_withdrawal(FinalizedWithdrawalEvent {
            usd: action.usd as f64 / USD_SCALE,
            nonce: action.nonce,
            bridge_balance_usd: state.bridge2.bal as f64 / USD_SCALE,
            user: action.user,
        });
    }

    Ok(VoteEthFinalizedWithdrawalOutcome { finalized })
}
