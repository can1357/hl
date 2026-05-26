//! Reconstruction of `/home/ubuntu/hl/code_Mainnet/node/src/consensus/state.rs`.
//!
//! Seed EAs from `path_to_funcs.json`: `0x44AB970`, `0x2043F70`, `0x22BF220`,
//! `0x44A8420`, `0x44AB560`, `0x44ADFA0`, `0x44B3200`.
//!
//! Confidence: medium for the state container and transition invariants, lower for
//! exact field offsets while the shared IDA server is queue-full.  Local evidence
//! used here:
//! - `0x44A8420` constructs a large state object, copies a 0x138-byte input block,
//!   then initializes maps/queues/timer handles through offsets ending near `+0xb04`.
//! - `0x44AB560` registers a client block, compares QC tuples, emits the `: Bad QCs:`
//!   formatting path on mismatch, appends a 0x168-byte record, and calls the
//!   validator/round notifier at `0x44B6670`.
//! - `0x44AB970` and `0x44ADFA0` are mempool-owned; state calls the reconstructed
//!   `consensus::mempool` API rather than inlining their block/tx indexes.
//! - `0x2043F70` and `0x22BF220` are timer/async glue; state exposes semantic round
//!   hooks while `timer.rs` owns sleep handles and elapsed/backoff bookkeeping.
//! - `0x44B3200` belongs to validator-set/round snapshot coordination; this file
//!   delegates active-stake and quorum work to `validator_set.rs`.
//!
//! IDA updates applied in this worker: none observed.  Small IDA calls to status,
//! decompile, and disassembly timed out while central auto-analysis was running.
//!
//! IDA-PENDING:
//! - Rename `0x44A8420` -> `node_consensus_state__new`; add source-path header
//!   comment and apply `hl_node_consensus_ConsensusState` once the layout is firm.
//! - Rename `0x44AB560` -> `node_consensus_state__register_client_block`; comment the
//!   `: Bad QCs:` branch and the 0x168-byte client-block append.
//! - Confirm `0x44B6670` as `node_consensus_state__notify_round_registered` or move it
//!   to `validator_set.rs` if xrefs show validator ownership.
//! - Leave `0x44AB970` / `0x44ADFA0` named in `mempool.rs`, `0x2043F70` / `0x22BF220`
//!   named in `timer.rs`, and `0x44B3200` named in `validator_set.rs` after direct xrefs.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use super::mempool::{
    poll_mempool, BlockContext, BlockVerifier, BlocksAndTxsResponse, ExternalTx, Mempool,
    MempoolEvent, MempoolHandoff, MempoolPollInput, SignedBlock as MempoolSignedBlock,
};
use super::types::{
    BlockHash, ClientBlock, ConsensusBlock, ConsensusRpcError, QuorumCertificate, Round, Signed,
    SignedTimeout, TimeoutCertificate, TxHash, ValidatorIndex,
};
use super::validator_set::{
    RoundValidatorSetHistory, ValidatorSetDelta, ValidatorSetError,
    ValidatorSetSnapshot as ActiveValidatorSet,
};

pub const STATE_CONSTRUCTOR_EA: u64 = 0x44A8420;
pub const REGISTER_CLIENT_BLOCK_EA: u64 = 0x44AB560;
pub const MEMPOOL_VERIFY_BLOCK_EA: u64 = 0x44AB970;
pub const MEMPOOL_POLL_EA: u64 = 0x44ADFA0;
pub const VALIDATOR_ROUND_HELPER_EA: u64 = 0x44B3200;
pub const TIMER_POLL_SEED_0_EA: u64 = 0x2043F70;
pub const TIMER_POLL_SEED_1_EA: u64 = 0x22BF220;

pub const RECOVERED_STATE_SIZE_UPPER_BOUND: usize = 0xb08;
pub const CLIENT_BLOCK_RECORD_SIZE: usize = 0x168;
pub const DEFAULT_BLOCK_RETENTION: usize = 10_000;
pub const DEFAULT_TIMEOUT_RETENTION: usize = 10_000;
pub const DEFAULT_MISSED_ROUND_BACKOFF: Duration = Duration::from_millis(200);

#[derive(Clone, Debug)]
pub struct ConsensusStateConfig {
    pub home_validator: ValidatorIndex,
    pub start_round: Round,
    pub block_retention: usize,
    pub timeout_retention: usize,
    pub missed_round_backoff: Duration,
}

impl ConsensusStateConfig {
    pub fn mainnet(home_validator: ValidatorIndex) -> Self {
        Self {
            home_validator,
            start_round: 0,
            block_retention: DEFAULT_BLOCK_RETENTION,
            timeout_retention: DEFAULT_TIMEOUT_RETENTION,
            missed_round_backoff: DEFAULT_MISSED_ROUND_BACKOFF,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsensusStatus {
    Constructing,
    Bootstrapping,
    Active,
    WaitingForTimeout,
    Exiting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnownBlock {
    pub block_hash: BlockHash,
    pub signed_block: Signed<ConsensusBlock>,
    pub registered_at: Option<Instant>,
    pub committed: bool,
}

impl KnownBlock {
    fn round(&self) -> Round {
        self.signed_block.content.round
    }

    fn tx_hashes(&self) -> &[TxHash] {
        &self.signed_block.content.tx_hashes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredClientBlock {
    pub block: ClientBlock,
    pub registered_at: Option<Instant>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoundAdvanceReason {
    RegisteredBlock { block_hash: BlockHash, round: Round },
    TimeoutCertificate { round: Round },
    LocalTimer { round: Round },
    ValidatorSetChanged { round: Round },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateEvent {
    Constructed { start_round: Round },
    RegisteredBlock { block_hash: BlockHash, round: Round },
    RegisteredClientBlock { block_hash: BlockHash, round: Round },
    CommittedBlock { block_hash: BlockHash, round: Round },
    RoundAdvanced { from: Round, to: Round, reason: RoundAdvanceReason },
    TimeoutRecorded { round: Round, validator: ValidatorIndex },
    TimeoutCertificateBuilt { round: Round, voters: usize },
    ValidatorSetUpdated { round: Round, active_validators: usize },
    Mempool(MempoolEvent),
    BadQcs { block_qc_round: Round, commit_qc_round: Round },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockTransition {
    pub inserted: bool,
    pub committed_round: Option<Round>,
    pub advanced_to: Round,
}

#[derive(Debug)]
pub struct ConsensusState {
    /// Constructor seed `0x44A8420`: home validator and initial round are copied out
    /// of the input/config record before state maps are allocated.
    pub config: ConsensusStateConfig,
    pub status: ConsensusStatus,

    /// Validator snapshots are delegated to `validator_set.rs`; seed `0x44B3200`
    /// is treated as validator-set/round-history ownership unless direct xrefs
    /// later prove this file owns that helper.
    pub validators: RoundValidatorSetHistory,

    pub current_round: Round,
    pub highest_seen_round: Round,
    pub last_committed_round: Round,
    pub preferred_round: Round,
    pub locked_round: Option<Round>,
    pub locked_block_hash: Option<BlockHash>,
    pub highest_qc: Option<QuorumCertificate>,
    pub latest_tc: Option<TimeoutCertificate>,

    /// Ordered by hash and by round so duplicate-round and duplicate-hash checks
    /// match the recovered BTree walks around `0x44AB560`.
    pub block_hash_to_block: BTreeMap<BlockHash, KnownBlock>,
    pub round_to_block_hash: BTreeMap<Round, BlockHash>,
    pub pending_client_blocks: VecDeque<RegisteredClientBlock>,

    /// Signed timeouts are keyed by round then validator; duplicate timeout from
    /// the same node maps to `AlreadyHaveTimeoutFromNode` in `ConsensusRpcError`.
    pub round_to_timeouts: BTreeMap<Round, BTreeMap<ValidatorIndex, SignedTimeout>>,
    pub round_to_tc: BTreeMap<Round, TimeoutCertificate>,

    /// Mempool-owned state machine.  Seeds `0x44AB970` and `0x44ADFA0` are calls
    /// into this object, not duplicated in this file.
    pub mempool: Mempool,
    pub mempool_handoffs: VecDeque<MempoolHandoff>,

    /// Timer-owned fields are represented semantically; timer.rs owns the actual
    /// sleep handles from seeds `0x2043F70` / `0x22BF220`.
    pub next_round_deadline: Option<Instant>,
    pub last_round_advanced_at: Option<Instant>,
    pub consecutive_missed_rounds: u64,

    pub events: VecDeque<StateEvent>,
    pub asked_to_exit: bool,
}

impl ConsensusState {
    /// `0x44A8420` — intended IDA name `node_consensus_state__new`.
    ///
    /// The binary constructor initializes a large object ending near `+0xb04`, with
    /// map/vector fields for blocks, timeouts, validator snapshots, mempool queues,
    /// timers, metrics sinks, and status flags.  This recovered constructor keeps
    /// the same ownership split but exposes only source-level state.
    pub fn new(config: ConsensusStateConfig, initial_validators: ActiveValidatorSet) -> Self {
        let start_round = config.start_round;
        let mut events = VecDeque::new();
        events.push_back(StateEvent::Constructed { start_round });

        Self {
            config,
            status: ConsensusStatus::Constructing,
            validators: RoundValidatorSetHistory::new(start_round, initial_validators),
            current_round: start_round,
            highest_seen_round: start_round,
            last_committed_round: start_round.saturating_sub(1),
            preferred_round: start_round.saturating_sub(1),
            locked_round: None,
            locked_block_hash: None,
            highest_qc: None,
            latest_tc: None,
            block_hash_to_block: BTreeMap::new(),
            round_to_block_hash: BTreeMap::new(),
            pending_client_blocks: VecDeque::new(),
            round_to_timeouts: BTreeMap::new(),
            round_to_tc: BTreeMap::new(),
            mempool: Mempool::default(),
            mempool_handoffs: VecDeque::new(),
            next_round_deadline: None,
            last_round_advanced_at: None,
            consecutive_missed_rounds: 0,
            events,
            asked_to_exit: false,
        }
    }

    pub fn mark_active(&mut self) {
        if self.status != ConsensusStatus::Exiting {
            self.status = ConsensusStatus::Active;
        }
    }

    pub fn request_exit(&mut self) {
        self.asked_to_exit = true;
        self.status = ConsensusStatus::Exiting;
    }

    pub fn active_validator_set(&self) -> &ActiveValidatorSet {
        &self.validators.current
    }

    pub fn validator_set_for_round(&self, round: Round) -> Result<&ActiveValidatorSet, ConsensusStateError> {
        self.validators
            .snapshot_at_or_before(round)
            .ok_or(ConsensusStateError::MissingValidatorSetRound(round))
    }

    pub fn proposer_for_round(&self, round: Round) -> Result<ValidatorIndex, ConsensusStateError> {
        let validators: Vec<_> = self.active_validator_set().active_validators().map(|(idx, _)| idx).collect();
        if validators.is_empty() {
            return Err(ConsensusStateError::Rpc(ConsensusRpcError::EmptyValidators));
        }
        Ok(validators[(round as usize) % validators.len()])
    }

    /// `0x44B3200` / `0x44B6670` adjacency — validator/round notification hook.
    pub fn apply_validator_set_delta(&mut self, round: Round, delta: ValidatorSetDelta) {
        self.validators.apply_delta_at_round(round, delta);
        self.events.push_back(StateEvent::ValidatorSetUpdated {
            round,
            active_validators: self.validators.current.active_validator_count(),
        });
        self.advance_round_to(round, RoundAdvanceReason::ValidatorSetChanged { round });
    }

    /// `0x44AB560` — intended IDA name `node_consensus_state__register_client_block`.
    ///
    /// The recovered branch compares the block QC with the commit/client QC and
    /// formats `: Bad QCs:` when they disagree.  The binary then appends a
    pub fn register_client_block(
        &mut self,
        block: ClientBlock,
        registered_at: Option<Instant>,
    ) -> Result<BlockTransition, ConsensusStateError> {
        let block_round = block.block.round;
        if block_round <= self.last_committed_round {
            return Err(ConsensusStateError::Rpc(ConsensusRpcError::BadBlockRound {
                block_round,
                last_commit_round: self.last_committed_round,
            }));
        }

        if let (Some(block_qc), Some(commit_qc)) = (block.block.qc.as_ref(), block.commit_proof.as_ref()) {
            if block_qc.block_hash != commit_qc.block_hash || block_qc.round != commit_qc.round {
                self.events.push_back(StateEvent::BadQcs {
                    block_qc_round: block_qc.round,
                    commit_qc_round: commit_qc.round,
                });
                return Err(ConsensusStateError::BadQcs {
                    block_qc_round: block_qc.round,
                    commit_qc_round: commit_qc.round,
                });
            }
        }

        self.validate_client_block_proofs(&block)?;

        let block_hash = block.block_hash;
        self.pending_client_blocks.push_back(RegisteredClientBlock { block, registered_at });
        self.events.push_back(StateEvent::RegisteredClientBlock { block_hash, round: block_round });
        self.advance_round_to(block_round.saturating_add(1), RoundAdvanceReason::RegisteredBlock { block_hash, round: block_round });
        self.prune_old_client_blocks();

        Ok(BlockTransition {
            inserted: true,
            committed_round: Some(block_round),
            advanced_to: self.current_round,
        })
    }

    pub fn register_signed_block(
        &mut self,
        block_hash: BlockHash,
        signed_block: Signed<ConsensusBlock>,
        registered_at: Option<Instant>,
    ) -> Result<BlockTransition, ConsensusStateError> {
        let block = &signed_block.content;
        let block_round = block.round;

        if block_round <= self.last_committed_round {
            return Err(ConsensusStateError::Rpc(ConsensusRpcError::BadBlockRound {
                block_round,
                last_commit_round: self.last_committed_round,
            }));
        }
        if self.block_hash_to_block.contains_key(&block_hash) {
            return Err(ConsensusStateError::Rpc(ConsensusRpcError::BlockAlreadyRegistered));
        }
        if self.round_to_block_hash.contains_key(&block_round) {
            return Err(ConsensusStateError::Rpc(ConsensusRpcError::DuplicateBlockRound));
        }

        if let Some(qc) = block.qc.as_ref() {
            self.validate_block_qc(block_round, qc)?;
            self.observe_qc(qc.clone());
        } else if block_round != 0 {
            return Err(ConsensusStateError::Rpc(ConsensusRpcError::BadBlockQcRound));
        }

        if let Some(tc) = block.tc.as_ref() {
            self.validate_timeout_certificate(tc)?;
            if tc.round >= block_round {
                return Err(ConsensusStateError::Rpc(ConsensusRpcError::BadBlockTcRound));
            }
            self.latest_tc = Some(tc.clone());
        }

        let known = KnownBlock { block_hash, signed_block, registered_at, committed: false };
        self.round_to_block_hash.insert(block_round, block_hash);
        self.highest_seen_round = self.highest_seen_round.max(block_round);
        self.block_hash_to_block.insert(block_hash, known);
        self.events.push_back(StateEvent::RegisteredBlock { block_hash, round: block_round });

        let committed_round = self.try_commit_from_child_qc(block_hash, block_round)?;
        self.advance_round_to(block_round.saturating_add(1), RoundAdvanceReason::RegisteredBlock { block_hash, round: block_round });
        self.prune_old_blocks();

        Ok(BlockTransition { inserted: true, committed_round, advanced_to: self.current_round })
    }

    /// State-facing wrapper for mempool seed `0x44B8410`; verification and block/tx
    /// indexes remain in `mempool.rs`.  The caller supplies the already-recovered
    /// mempool signed-block payload; state.rs does not synthesize packet bytes.
    pub fn register_block_with_mempool<V: BlockVerifier>(
        &mut self,
        context: BlockContext,
        block_hash: BlockHash,
        signed_block: MempoolSignedBlock,
        verifier: &mut V,
    ) -> Result<(), ConsensusStateError> {
        self.mempool.register_block(context, block_hash, signed_block, verifier)?;
        self.drain_mempool_handoffs_and_events();
        Ok(())
    }

    /// `0x44ADFA0` is mempool-owned.  State supplies inbound queues and drains the
    /// resulting server/network handoffs.
    pub fn poll_mempool_state<V: BlockVerifier>(
        &mut self,
        inbound_txs: VecDeque<ExternalTx>,
        inbound_blocks_and_txs: VecDeque<BlocksAndTxsResponse>,
        now: Option<Instant>,
        verifier: &mut V,
    ) {
        let output = poll_mempool(
            &mut self.mempool,
            MempoolPollInput { inbound_txs, inbound_blocks_and_txs, now },
            verifier,
        );
        self.mempool_handoffs.extend(output.handoffs);
        self.events.extend(output.events.into_iter().map(StateEvent::Mempool));
    }

    pub fn record_signed_timeout(&mut self, timeout: SignedTimeout) -> Result<Option<TimeoutCertificate>, ConsensusStateError> {
        let round = timeout.content.round;
        let validator = timeout.content.validator;
        if round < self.current_round {
            return Err(ConsensusStateError::Rpc(ConsensusRpcError::TimeoutRoundMismatch));
        }

        let voters: Vec<_> = {
            let timeouts = self.round_to_timeouts.entry(round).or_default();
            if timeouts.contains_key(&validator) {
                return Err(ConsensusStateError::Rpc(ConsensusRpcError::AlreadyHaveTimeoutFromNode));
            }
            timeouts.insert(validator, timeout);
            timeouts.keys().copied().collect()
        };
        self.events.push_back(StateEvent::TimeoutRecorded { round, validator });

        let validators = self.validator_set_for_round(round)?;
        match validators.check_quorum_indices(voters) {
            Ok(summary) => {
                let signed_timeouts = self
                    .round_to_timeouts
                    .get(&round)
                    .map(|timeouts| timeouts.values().cloned().collect())
                    .unwrap_or_default();
                let tc = TimeoutCertificate { signed_timeouts, round };
                self.round_to_tc.insert(round, tc.clone());
                self.latest_tc = Some(tc.clone());
                self.events.push_back(StateEvent::TimeoutCertificateBuilt { round, voters: summary.counted });
                self.advance_round_to(round.saturating_add(1), RoundAdvanceReason::TimeoutCertificate { round });
                self.prune_old_timeouts();
                Ok(Some(tc))
            }
            Err(ValidatorSetError::NoQuorum { .. }) => Ok(None),
            Err(error) => Err(ConsensusStateError::ValidatorSet(error)),
        }
    }

    pub fn install_timeout_certificate(&mut self, tc: TimeoutCertificate) -> Result<(), ConsensusStateError> {
        self.validate_timeout_certificate(&tc)?;
        let round = tc.round;
        self.round_to_tc.insert(round, tc.clone());
        self.latest_tc = Some(tc);
        self.advance_round_to(round.saturating_add(1), RoundAdvanceReason::TimeoutCertificate { round });
        self.prune_old_timeouts();
        Ok(())
    }

    pub fn on_round_timer_elapsed(&mut self, now: Instant) -> Round {
        self.consecutive_missed_rounds = self.consecutive_missed_rounds.saturating_add(1);
        self.status = ConsensusStatus::WaitingForTimeout;
        let round = self.current_round.saturating_add(1);
        self.advance_round_to(round, RoundAdvanceReason::LocalTimer { round });
        self.next_round_deadline = Some(now + self.config.missed_round_backoff);
        round
    }

    pub fn arm_round_timer(&mut self, now: Instant) {
        self.next_round_deadline = Some(now + self.config.missed_round_backoff);
    }

    pub fn pop_event(&mut self) -> Option<StateEvent> {
        self.events.pop_front()
    }

    pub fn pop_mempool_handoff(&mut self) -> Option<MempoolHandoff> {
        self.mempool_handoffs.pop_front()
    }

    fn validate_block_qc(&self, block_round: Round, qc: &QuorumCertificate) -> Result<(), ConsensusStateError> {
        if qc.round >= block_round {
            return Err(ConsensusStateError::Rpc(ConsensusRpcError::BadBlockQcRound));
        }
        let validators = self.validator_set_for_round(qc.round)?;
        validators
            .check_quorum_indices(qc.signatures.iter().map(|(validator, _)| *validator))
            .map_err(|error| match error {
                ValidatorSetError::EmptyValidators => ConsensusStateError::Rpc(ConsensusRpcError::EmptyValidators),
                ValidatorSetError::NoQuorum { .. } => ConsensusStateError::Rpc(ConsensusRpcError::QcNoQuorum),
                other => ConsensusStateError::ValidatorSet(other),
            })?;
        Ok(())
    }

    fn validate_timeout_certificate(&self, tc: &TimeoutCertificate) -> Result<(), ConsensusStateError> {
        if tc.signed_timeouts.is_empty() {
            return Err(ConsensusStateError::Rpc(ConsensusRpcError::TcNoTimeout));
        }
        for timeout in &tc.signed_timeouts {
            if timeout.content.round != tc.round {
                return Err(ConsensusStateError::Rpc(ConsensusRpcError::TimeoutRoundMismatch));
            }
        }
        let validators = self.validator_set_for_round(tc.round)?;
        validators
            .check_quorum_indices(tc.signed_timeouts.iter().map(|timeout| timeout.content.validator))
            .map_err(|error| match error {
                ValidatorSetError::EmptyValidators => ConsensusStateError::Rpc(ConsensusRpcError::EmptyValidators),
                ValidatorSetError::NoQuorum { .. } => ConsensusStateError::Rpc(ConsensusRpcError::TcNoQuorum),
                other => ConsensusStateError::ValidatorSet(other),
            })?;
        Ok(())
    }

    fn validate_client_block_proofs(&self, block: &ClientBlock) -> Result<(), ConsensusStateError> {
        let Some(commit_proof) = block.commit_proof.as_ref() else {
            return Err(ConsensusStateError::Rpc(ConsensusRpcError::ClientBlockMissingCommitProof));
        };
        self.validate_block_qc(block.block.round.saturating_add(1), commit_proof)?;

        for tx_proof in &block.tx_commit_proofs {
            if tx_proof.round > block.block.round {
                return Err(ConsensusStateError::Rpc(ConsensusRpcError::ClientBlockTx));
            }
            self.validate_block_qc(block.block.round.saturating_add(1), tx_proof)?;
        }
        Ok(())
    }

    fn observe_qc(&mut self, qc: QuorumCertificate) {
        if self.highest_qc.as_ref().map_or(true, |old| qc.round > old.round) {
            self.preferred_round = self.preferred_round.max(qc.round);
            self.highest_qc = Some(qc);
        }
    }

    fn try_commit_from_child_qc(&mut self, child_hash: BlockHash, child_round: Round) -> Result<Option<Round>, ConsensusStateError> {
        let Some(child) = self.block_hash_to_block.get(&child_hash) else {
            return Ok(None);
        };
        let Some(qc) = child.signed_block.content.qc.as_ref() else {
            return Ok(None);
        };
        let parent_hash = qc.block_hash;
        let parent_round = qc.round;
        if parent_round <= self.last_committed_round {
            return Ok(None);
        }

        let Some(parent) = self.block_hash_to_block.get_mut(&parent_hash) else {
            return Ok(None);
        };
        if parent.round() != parent_round || child_round <= parent.round() {
            return Err(ConsensusStateError::Rpc(ConsensusRpcError::ChildQcCommitProof));
        }

        parent.committed = true;
        self.last_committed_round = parent.round();
        self.locked_round = Some(parent.round());
        self.locked_block_hash = Some(parent.block_hash);
        let committed_hash = parent.block_hash;
        let committed_round = parent.round();
        self.events.push_back(StateEvent::CommittedBlock { block_hash: committed_hash, round: committed_round });
        Ok(Some(committed_round))
    }

    fn advance_round_to(&mut self, next_round: Round, reason: RoundAdvanceReason) {
        if next_round <= self.current_round {
            return;
        }
        let from = self.current_round;
        self.current_round = next_round;
        self.highest_seen_round = self.highest_seen_round.max(next_round);
        self.validators.record_round(next_round);
        self.consecutive_missed_rounds = 0;
        self.last_round_advanced_at = None;
        self.status = ConsensusStatus::Active;
        self.events.push_back(StateEvent::RoundAdvanced { from, to: next_round, reason });
    }

    fn drain_mempool_handoffs_and_events(&mut self) {
        while let Some(handoff) = self.mempool.pop_handoff() {
            self.mempool_handoffs.push_back(handoff);
        }
        while let Some(event) = self.mempool.events.pop_front() {
            self.events.push_back(StateEvent::Mempool(event));
        }
    }

    fn prune_old_blocks(&mut self) {
        while self.round_to_block_hash.len() > self.config.block_retention {
            let Some((&oldest_round, &oldest_hash)) = self.round_to_block_hash.iter().next() else {
                break;
            };
            if oldest_round >= self.last_committed_round {
                break;
            }
            self.round_to_block_hash.remove(&oldest_round);
            self.block_hash_to_block.remove(&oldest_hash);
        }
    }

    fn prune_old_client_blocks(&mut self) {
        while self.pending_client_blocks.len() > self.config.block_retention {
            self.pending_client_blocks.pop_front();
        }
    }

    fn prune_old_timeouts(&mut self) {
        while self.round_to_timeouts.len() > self.config.timeout_retention {
            let Some((&oldest_round, _)) = self.round_to_timeouts.iter().next() else {
                break;
            };
            if oldest_round >= self.current_round.saturating_sub(self.config.timeout_retention as u64) {
                break;
            }
            self.round_to_timeouts.remove(&oldest_round);
            self.round_to_tc.remove(&oldest_round);
        }
    }
}

#[derive(Debug)]
pub enum ConsensusStateError {
    Rpc(ConsensusRpcError),
    ValidatorSet(ValidatorSetError),
    MempoolRegister(super::mempool::RegisterBlockError),
    MissingValidatorSetRound(Round),
    BadQcs { block_qc_round: Round, commit_qc_round: Round },
}

impl From<ConsensusRpcError> for ConsensusStateError {
    fn from(error: ConsensusRpcError) -> Self {
        Self::Rpc(error)
    }
}

impl From<ValidatorSetError> for ConsensusStateError {
    fn from(error: ValidatorSetError) -> Self {
        Self::ValidatorSet(error)
    }
}

impl From<super::mempool::RegisterBlockError> for ConsensusStateError {
    fn from(error: super::mempool::RegisterBlockError) -> Self {
        Self::MempoolRegister(error)
    }
}
