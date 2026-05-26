//! Reconstructed Rust for `/home/ubuntu/hl/code_Mainnet/node/src/consensus/mempool.rs`.
//!
//! Confidence: medium.  The central IDA queue was busy during this wave, so the
//! source below is grounded in local disassembly of seeds `0x44AB970`,
//! `0x44ADFA0`, and `0x44B8410`, local manifest string evidence, and nested
//! helper analysis of `0x44B8410` / `0x44B9800` / `0x44B9A50`.
//!
//! Key binary anchors:
//! - `0x44AB970` — block verifier / size-stat updater.  It walks the
//!   `block_hash_to_block` BTree by 32-byte keys, compares `committed`,
//!   `block hashes`, and `tx hashes` string labels at `0x6f4dc5..0x6f4de3`, and
//!   calls the same result builder as the register path.
//! - `0x44ADFA0` — large async poll state machine.  It dispatches
//!   `handle_blocks_and_txs`, `add_tx`, `dropping txs`, `Pruned rpc request throttle`,
//!   request retry, and size-stat logging.
//! - `0x44B8410` — `register_block`: verifies a signed block, checks the block
//!   sequence against the watermark at `self+0x198`, asserts unique insertion into
//!   `block_hash_to_block`, reconciles unknown tx hashes, and sends the block to
//!   the consensus handoff channel unless `self+0x230` is set.
//! - `0x44B9800` — helper that collects tx hashes from prior blocks before block
//!   registration.
//! - `0x44B9A50` — `add_tx`: checks committed/known tx indexes and sends an
//!   external transaction handoff unless handoff is suppressed.
//!
//! Pending IDA updates because `rename`/`set_comments` returned
//! `Server is busy (request queue full)`:
//! - Rename `0x44AB970` -> `node_consensus_mempool__verify_block`; add header
//!   comment for block/tx hash index verification and size stats.
//! - Rename `0x44ADFA0` -> `node_consensus_mempool__poll`; add header comment
//!   for the async mempool refresher/BlocksAndTxs/add_tx state machine.
//! - Rename `0x44B8410` -> `node_consensus_mempool__register_block`; add header
//!   comment for signed-block registration and block handoff.
//! - Rename `0x44B9800` -> `node_consensus_mempool__collect_prior_block_tx_hashes`.
//! - Rename `0x44B9A50` -> `node_consensus_mempool__add_tx`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};

pub type TxHash = [u8; 32];
pub type BlockHash = [u8; 32];
pub type SequenceNumber = u64;

pub const MEMPOOL_OK_SENTINEL: u64 = 0x8000_0000_0000_002a;
pub const REGISTER_BLOCK_STALE_SENTINEL: u64 = 0x8000_0000_0000_0003;
pub const REGISTER_BLOCK_DUPLICATE_SENTINEL: u64 = 0x8000_0000_0000_0006;
pub const REGISTER_BLOCK_CONFLICT_SENTINEL: u64 = 0x8000_0000_0000_000e;
pub const HANDOFF_ENTRY_SENTINEL: u64 = 0x8000_0000_0000_0000;
pub const ADD_TX_ENTRY_SENTINEL: u64 = 0x8000_0000_0000_0001;
pub const ADD_TX_EXISTING_BLOCK_SENTINEL: u64 = 0x8000_0000_0000_0023;
pub const RPC_REQUEST_THROTTLE_LIMIT: usize = 100;
pub const DEFAULT_RETRY_AFTER: Duration = Duration::from_millis(200);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalTx {
    pub tx_hash: TxHash,
    pub seq_num: SequenceNumber,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedBlock {
    pub block_hash: BlockHash,
    pub tx_hashes: Vec<TxHash>,
    pub sequence: SequenceNumber,
    pub round: u64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockContext {
    pub height: u64,
    pub round: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MempoolTx {
    pub tx_hash: TxHash,
    pub seq_num: SequenceNumber,
    pub bytes: Vec<u8>,
    pub first_seen_at: Option<Instant>,
    pub committed_by: Option<BlockHash>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredBlock {
    pub context: BlockContext,
    pub signed_block: SignedBlock,
    pub missing_tx_hashes: Vec<TxHash>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MempoolHandoff {
    ForwardExternalTx(ExternalTx),
    RegisterBlock(RegisteredBlock),
    RequestBlocksAndTxs {
        after_round: u64,
        until_block_hash: Option<BlockHash>,
        reason: RequestReason,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestReason {
    MissingTx,
    BehindBlockWatermark,
    RetryAfterWaitDuration,
    PartialResponse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifyError {
    BlockBelowWatermark {
        block_sequence: SequenceNumber,
        min_sequence: SequenceNumber,
    },
    DuplicateBlockHash(BlockHash),
    ConflictingBlockAtSequence {
        sequence: SequenceNumber,
        existing: BlockHash,
        incoming: BlockHash,
    },
    MissingTransactions(Vec<TxHash>),
    DuplicateTxHash(TxHash),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AddTxError {
    AlreadyCommitted(TxHash),
    AlreadyUncommitted(TxHash),
    AlreadyReferencedByBlock(TxHash),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegisterBlockError {
    VerifyBlock(String),
    StaleBlock {
        block_sequence: SequenceNumber,
        min_sequence: SequenceNumber,
    },
    DuplicateBlockHash(BlockHash),
    ConflictingBlockAtSequence {
        sequence: SequenceNumber,
        existing: BlockHash,
        incoming: BlockHash,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SizeStats {
    pub committed_tx_hashes: usize,
    pub uncommitted_txs: usize,
    pub blocks: usize,
    pub rpc_requests: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MempoolEvent {
    SizeStats(SizeStats),
    VerifyBlockOk { block_hash: BlockHash, sequence: SequenceNumber },
    VerifyBlockErr { block_hash: BlockHash, error: VerifyError },
    AddTx { tx_hash: TxHash, seq_num: SequenceNumber },
    DroppingTxs { count: usize, reason: &'static str },
    PrunedRpcRequestThrottle { before: usize, after: usize },
    HandleBlocksAndTxs { blocks: usize, txs: usize },
    MakingRequestAfterWaitDuration { after_round: u64 },
}

pub trait BlockVerifier {
    fn verify_block(&mut self, block: &SignedBlock) -> Result<(), String>;
}

#[derive(Clone, Debug, Default)]
pub struct ExternalTxQueue {
    by_hash: BTreeMap<TxHash, MempoolTx>,
    by_sequence: BTreeMap<SequenceNumber, TxHash>,
}

impl ExternalTxQueue {
    pub fn insert(&mut self, tx: ExternalTx, first_seen_at: Option<Instant>) -> Result<(), AddTxError> {
        if self.by_hash.contains_key(&tx.tx_hash) {
            return Err(AddTxError::AlreadyUncommitted(tx.tx_hash));
        }

        self.by_sequence.insert(tx.seq_num, tx.tx_hash);
        self.by_hash.insert(
            tx.tx_hash,
            MempoolTx {
                tx_hash: tx.tx_hash,
                seq_num: tx.seq_num,
                bytes: tx.bytes,
                first_seen_at,
                committed_by: None,
            },
        );
        Ok(())
    }

    pub fn remove_by_hash(&mut self, tx_hash: &TxHash) -> Option<MempoolTx> {
        let tx = self.by_hash.remove(tx_hash)?;
        self.by_sequence.remove(&tx.seq_num);
        Some(tx)
    }

    pub fn contains_hash(&self, tx_hash: &TxHash) -> bool {
        self.by_hash.contains_key(tx_hash)
    }

    pub fn get(&self, tx_hash: &TxHash) -> Option<&MempoolTx> {
        self.by_hash.get(tx_hash)
    }
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    pub fn drop_before_sequence(&mut self, min_sequence: SequenceNumber) -> Vec<MempoolTx> {
        let stale: Vec<TxHash> = self
            .by_sequence
            .range(..min_sequence)
            .map(|(_, tx_hash)| *tx_hash)
            .collect();

        let mut dropped = Vec::with_capacity(stale.len());
        for tx_hash in stale {
            if let Some(tx) = self.remove_by_hash(&tx_hash) {
                dropped.push(tx);
            }
        }
        dropped
    }
}

#[derive(Clone, Debug)]
pub struct Mempool {
    /// BTree/set at `self+0x58/+0x60` in helper analysis.
    pub committed_tx_hashes: BTreeSet<TxHash>,
    /// BTree-like tx hash index at `self+0x1a0/+0x1a8`.
    pub uncommitted_txs: ExternalTxQueue,
    /// BTree-like `block_hash_to_block` at `self+0x1b8/+0x1c0/+0x1c8`.
    pub block_hash_to_block: BTreeMap<BlockHash, RegisteredBlock>,
    /// Secondary sequence index; `0x44B8410` checks `SignedBlock+0x88` against `self+0x198`.
    pub block_sequence_to_hash: BTreeMap<SequenceNumber, BlockHash>,
    pub min_block_sequence: SequenceNumber,
    pub latest_tx_sequence: SequenceNumber,
    pub rpc_request_throttle: VecDeque<BlocksAndTxsRequest>,
    pub pending_handoff: VecDeque<MempoolHandoff>,
    pub events: VecDeque<MempoolEvent>,
    pub suppress_handoff: bool,
    pub retry_after: Duration,
    pub next_request_after: Option<Instant>,
}

impl Default for Mempool {
    fn default() -> Self {
        Self {
            committed_tx_hashes: BTreeSet::new(),
            uncommitted_txs: ExternalTxQueue::default(),
            block_hash_to_block: BTreeMap::new(),
            block_sequence_to_hash: BTreeMap::new(),
            min_block_sequence: 0,
            latest_tx_sequence: 0,
            rpc_request_throttle: VecDeque::new(),
            pending_handoff: VecDeque::new(),
            events: VecDeque::new(),
            suppress_handoff: false,
            retry_after: DEFAULT_RETRY_AFTER,
            next_request_after: None,
        }
    }
}

impl Mempool {
    /// `0x44B9A50` — intended IDA name `node_consensus_mempool__add_tx`.
    ///
    /// The helper first searches the committed/known tx structures using 32-byte
    /// `memcmp` keys, then creates a `0x168`-byte queue entry and wakes the
    /// channel at `self+0x158/+0x160` unless `self+0x230` is set.
    pub fn add_tx(&mut self, tx: ExternalTx, now: Option<Instant>) -> Result<(), AddTxError> {
        if self.committed_tx_hashes.contains(&tx.tx_hash) {
            return Err(AddTxError::AlreadyCommitted(tx.tx_hash));
        }
        if self.uncommitted_txs.contains_hash(&tx.tx_hash) {
            return Err(AddTxError::AlreadyUncommitted(tx.tx_hash));
        }
        if self.block_references_tx(&tx.tx_hash) {
            return Err(AddTxError::AlreadyReferencedByBlock(tx.tx_hash));
        }

        let tx_hash = tx.tx_hash;
        let seq_num = tx.seq_num;
        let handoff = ExternalTx { tx_hash, seq_num, bytes: tx.bytes.clone() };
        self.latest_tx_sequence = self.latest_tx_sequence.max(seq_num);
        self.uncommitted_txs.insert(tx, now)?;
        self.events.push_back(MempoolEvent::AddTx { tx_hash, seq_num });

        if !self.suppress_handoff {
            self.pending_handoff.push_back(MempoolHandoff::ForwardExternalTx(handoff));
        }
        Ok(())
    }

    /// `0x44B8410` — intended IDA name `node_consensus_mempool__register_block`.
    ///
    /// The binary logs `verify_block ok` / `verify_block err`, rejects stale
    /// sequences (`REGISTER_BLOCK_STALE_SENTINEL`), rejects duplicate block hashes
    /// (`REGISTER_BLOCK_DUPLICATE_SENTINEL`), logs `register_block unknown tx hashes`,
    /// and asserts that inserting into `block_hash_to_block` returns `None`.
    pub fn register_block<V: BlockVerifier>(
        &mut self,
        context: BlockContext,
        block_hash: BlockHash,
        signed_block: SignedBlock,
        verifier: &mut V,
    ) -> Result<(), RegisterBlockError> {
        verifier
            .verify_block(&signed_block)
            .map_err(RegisterBlockError::VerifyBlock)?;

        if signed_block.sequence < self.min_block_sequence {
            return Err(RegisterBlockError::StaleBlock {
                block_sequence: signed_block.sequence,
                min_sequence: self.min_block_sequence,
            });
        }

        if self.block_hash_to_block.contains_key(&block_hash) {
            return Err(RegisterBlockError::DuplicateBlockHash(block_hash));
        }

        if let Some(existing) = self.block_sequence_to_hash.get(&signed_block.sequence).copied() {
            if existing != block_hash {
                return Err(RegisterBlockError::ConflictingBlockAtSequence {
                    sequence: signed_block.sequence,
                    existing,
                    incoming: block_hash,
                });
            }
        }

        let missing_tx_hashes = self.unknown_tx_hashes_for_block(&signed_block);
        if !missing_tx_hashes.is_empty() {
            self.pending_handoff.push_back(MempoolHandoff::RequestBlocksAndTxs {
                after_round: signed_block.round,
                until_block_hash: Some(block_hash),
                reason: RequestReason::MissingTx,
            });
        }

        let registered = RegisteredBlock {
            context,
            signed_block: signed_block.clone(),
            missing_tx_hashes,
        };

        let old = self.block_hash_to_block.insert(block_hash, registered.clone());
        assert!(old.is_none(), "self.block_hash_to_block.insert(block_hash, signed_block).is_none()");
        self.block_sequence_to_hash.insert(signed_block.sequence, block_hash);

        for tx_hash in &signed_block.tx_hashes {
            self.committed_tx_hashes.insert(*tx_hash);
            if let Some(mut tx) = self.uncommitted_txs.remove_by_hash(tx_hash) {
                tx.committed_by = Some(block_hash);
            }
        }

        if !self.suppress_handoff {
            self.pending_handoff.push_back(MempoolHandoff::RegisterBlock(registered));
        }
        Ok(())
    }

    /// `0x44AB970` — intended IDA name `node_consensus_mempool__verify_block`.
    ///
    /// This mirrors the observed BTree walks and the `committed`, `block hashes`,
    /// and `tx hashes` size-stat labels.  It validates that a candidate block is
    /// not below the watermark, is not already present, does not conflict with the
    /// sequence index, and only references known or requestable tx hashes.
    pub fn verify_block(&mut self, block_hash: BlockHash, signed_block: &SignedBlock) -> Result<(), VerifyError> {
        if signed_block.sequence < self.min_block_sequence {
            let err = VerifyError::BlockBelowWatermark {
                block_sequence: signed_block.sequence,
                min_sequence: self.min_block_sequence,
            };
            self.events.push_back(MempoolEvent::VerifyBlockErr { block_hash, error: err.clone() });
            return Err(err);
        }

        if self.block_hash_to_block.contains_key(&block_hash) {
            let err = VerifyError::DuplicateBlockHash(block_hash);
            self.events.push_back(MempoolEvent::VerifyBlockErr { block_hash, error: err.clone() });
            return Err(err);
        }

        if let Some(existing) = self.block_sequence_to_hash.get(&signed_block.sequence).copied() {
            if existing != block_hash {
                let err = VerifyError::ConflictingBlockAtSequence {
                    sequence: signed_block.sequence,
                    existing,
                    incoming: block_hash,
                };
                self.events.push_back(MempoolEvent::VerifyBlockErr { block_hash, error: err.clone() });
                return Err(err);
            }
        }

        let mut seen = BTreeSet::new();
        for tx_hash in &signed_block.tx_hashes {
            if !seen.insert(*tx_hash) {
                let err = VerifyError::DuplicateTxHash(*tx_hash);
                self.events.push_back(MempoolEvent::VerifyBlockErr { block_hash, error: err.clone() });
                return Err(err);
            }
        }

        let missing = self.unknown_tx_hashes_for_block(signed_block);
        if !missing.is_empty() {
            let err = VerifyError::MissingTransactions(missing);
            self.events.push_back(MempoolEvent::VerifyBlockErr { block_hash, error: err.clone() });
            return Err(err);
        }

        self.events.push_back(MempoolEvent::VerifyBlockOk { block_hash, sequence: signed_block.sequence });
        self.events.push_back(MempoolEvent::SizeStats(self.size_stats()));
        Ok(())
    }

    /// `0x44B9800` — intended IDA name
    /// `node_consensus_mempool__collect_prior_block_tx_hashes`.
    ///
    /// The helper walks previously registered blocks and accumulates their tx hash
    /// vectors into a temporary set before `register_block` reconciles unknown txs.
    pub fn collect_prior_block_tx_hashes(&self, before_sequence: SequenceNumber) -> BTreeSet<TxHash> {
        let mut hashes = BTreeSet::new();
        for (sequence, block_hash) in self.block_sequence_to_hash.range(..before_sequence) {
            let _ = sequence;
            if let Some(block) = self.block_hash_to_block.get(block_hash) {
                hashes.extend(block.signed_block.tx_hashes.iter().copied());
            }
        }
        hashes
    }

    pub fn pop_handoff(&mut self) -> Option<MempoolHandoff> {
        self.pending_handoff.pop_front()
    }

    pub fn prune_committed_before(&mut self, min_sequence: SequenceNumber) -> Vec<MempoolTx> {
        self.min_block_sequence = self.min_block_sequence.max(min_sequence);
        let dropped = self.uncommitted_txs.drop_before_sequence(min_sequence);
        if !dropped.is_empty() {
            self.events.push_back(MempoolEvent::DroppingTxs { count: dropped.len(), reason: "below block watermark" });
        }
        dropped
    }

    pub fn prune_rpc_request_throttle(&mut self) {
        let before = self.rpc_request_throttle.len();
        while self.rpc_request_throttle.len() > RPC_REQUEST_THROTTLE_LIMIT {
            self.rpc_request_throttle.pop_front();
        }
        let after = self.rpc_request_throttle.len();
        if after != before {
            self.events.push_back(MempoolEvent::PrunedRpcRequestThrottle { before, after });
        }
    }

    pub fn size_stats(&self) -> SizeStats {
        SizeStats {
            committed_tx_hashes: self.committed_tx_hashes.len(),
            uncommitted_txs: self.uncommitted_txs.len(),
            blocks: self.block_hash_to_block.len(),
            rpc_requests: self.rpc_request_throttle.len(),
        }
    }

    fn unknown_tx_hashes_for_block(&self, signed_block: &SignedBlock) -> Vec<TxHash> {
        let prior_block_tx_hashes = self.collect_prior_block_tx_hashes(signed_block.sequence);
        signed_block
            .tx_hashes
            .iter()
            .copied()
            .filter(|tx_hash| {
                !self.committed_tx_hashes.contains(tx_hash)
                    && !self.uncommitted_txs.contains_hash(tx_hash)
                    && !prior_block_tx_hashes.contains(tx_hash)
            })
            .collect()
    }

    fn block_references_tx(&self, tx_hash: &TxHash) -> bool {
        self.block_hash_to_block
            .values()
            .any(|block| block.signed_block.tx_hashes.iter().any(|candidate| candidate == tx_hash))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlocksAndTxsResponse {
    pub blocks: Vec<(BlockContext, BlockHash, SignedBlock)>,
    pub txs: Vec<ExternalTx>,
    pub lowest_parent_round: u64,
    pub partial: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlocksAndTxsRequest {
    pub after_round: u64,
    pub until_block_hash: Option<BlockHash>,
    pub reason: RequestReason,
    pub requested_at: Instant,
}

#[derive(Clone, Debug, Default)]
pub struct MempoolPollInput {
    pub inbound_txs: VecDeque<ExternalTx>,
    pub inbound_blocks_and_txs: VecDeque<BlocksAndTxsResponse>,
    pub now: Option<Instant>,
}

#[derive(Clone, Debug, Default)]
pub struct MempoolPollOutput {
    pub handoffs: Vec<MempoolHandoff>,
    pub events: Vec<MempoolEvent>,
}

/// `0x44ADFA0` — intended IDA name `node_consensus_mempool__poll`.
///
/// Recovered shape of the large async state machine: ingest local external txs,
/// process `BlocksAndTxs` responses, call `add_tx` / `register_block`, prune the
/// RPC throttle, make retry requests after the wait duration, and drain handoff
/// messages into the consensus server/state queues.
pub fn poll_mempool<V: BlockVerifier>(
    mempool: &mut Mempool,
    mut input: MempoolPollInput,
    verifier: &mut V,
) -> MempoolPollOutput {
    let now = input.now;

    while let Some(tx) = input.inbound_txs.pop_front() {
        match mempool.add_tx(tx, now) {
            Ok(()) => {}
            Err(AddTxError::AlreadyCommitted(hash)) => {
                mempool.events.push_back(MempoolEvent::DroppingTxs { count: 1, reason: "already committed" });
                mempool.committed_tx_hashes.insert(hash);
            }
            Err(AddTxError::AlreadyUncommitted(_)) | Err(AddTxError::AlreadyReferencedByBlock(_)) => {
                mempool.events.push_back(MempoolEvent::DroppingTxs { count: 1, reason: "duplicate tx hash" });
            }
        }
    }

    while let Some(response) = input.inbound_blocks_and_txs.pop_front() {
        mempool.events.push_back(MempoolEvent::HandleBlocksAndTxs {
            blocks: response.blocks.len(),
            txs: response.txs.len(),
        });

        for tx in response.txs {
            let _ = mempool.add_tx(tx, now);
        }

        for (context, block_hash, signed_block) in response.blocks {
            let register_result = mempool.register_block(context, block_hash, signed_block.clone(), verifier);
            if register_result.is_err() && response.partial {
                mempool.pending_handoff.push_back(MempoolHandoff::RequestBlocksAndTxs {
                    after_round: response.lowest_parent_round,
                    until_block_hash: Some(block_hash),
                    reason: RequestReason::PartialResponse,
                });
            }
        }
    }

    mempool.prune_rpc_request_throttle();

    if let Some(now) = now {
        if mempool.next_request_after.map_or(false, |deadline| now >= deadline) {
            let after_round = mempool
                .block_sequence_to_hash
                .keys()
                .next_back()
                .copied()
                .unwrap_or(mempool.min_block_sequence);
            mempool.events.push_back(MempoolEvent::MakingRequestAfterWaitDuration { after_round });
            let request = BlocksAndTxsRequest {
                after_round,
                until_block_hash: mempool.block_sequence_to_hash.get(&after_round).copied(),
                reason: RequestReason::RetryAfterWaitDuration,
                requested_at: now,
            };
            mempool.rpc_request_throttle.push_back(request.clone());
            mempool.pending_handoff.push_back(MempoolHandoff::RequestBlocksAndTxs {
                after_round: request.after_round,
                until_block_hash: request.until_block_hash,
                reason: request.reason,
            });
            mempool.next_request_after = Some(now + mempool.retry_after);
        }
    }

    let mut output = MempoolPollOutput::default();
    while let Some(handoff) = mempool.pop_handoff() {
        output.handoffs.push(handoff);
    }
    while let Some(event) = mempool.events.pop_front() {
        output.events.push(event);
    }
    output
}
