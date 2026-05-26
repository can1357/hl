//! Reconstructed from `/home/ubuntu/hl/code_Mainnet/node/src/nv_stream.rs`.
//!
//! Confidence: medium-high for constants, state transitions, and stream message
//! flow; medium for Rust type names where the optimized binary carried erased
//! generic/async state.
//!
//! Seed EAs and recovered roles:
//! - `0x227A0E0` — bootstrap/setup poll state. Uses local ABCI state, saves it,
//!   builds nv-stream channels, compacts `nv_gossip_priority`, and copies a
//!   `0x3dc8`-byte initialized state into the caller output.
//! - `0x435FCA0` — tracing/instrumentation poll wrapper for
//!   `nv_stream_apply_execution_state` and `nv_stream_forward_client_blocks`.
//! - `0x4360000` — decoded client-block accept/buffer/flush path. Checks parent
//!   round against state `+0x108`, buffers 32-byte packet records, errors after
//!   more than 100 unconfirmed blocks, and flushes after execution-state material
//!   is present.
//! - `0x4389070` — gossip RPC bootstrap query loop; called here in windows of at
//!   most 100 `ClientBlocks` entries.
//! - `0x439BAF0` / `0x4759970` — `forward_client_blocks` async poll bodies;
//!   receive client blocks/txs, reject stale or peer-mismatched blocks, reconnect
//!   on reader exhaustion or process errors, and reset the reconnect state.
//! - `0x47B3B80` / `0x4B3C560` — net_utils channel receiver monomorphs used by
//!   this stream.
//! - `0x4B3B930` — node-bootstrap stream message read/dispatch future; labels
//!   `gossip stream msg`, `nv_stream_msg`, and `node_bootstrap`.
//! - `0x4B3C880` — callback/drop glue for the node-bootstrap dispatch path.
//!

#![allow(dead_code)]
#![allow(async_fn_in_trait)]

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, Instant};


pub const LOCAL_CHANNEL_LABEL: &str = "local";
pub const CLIENT_BLOCK_OR_TX_CHANNEL_LABEL: &str = "nv stream client block or tx";
pub const EXECUTION_STATE_CHANNEL_LABEL: &str = "nv stream execution state";
pub const NV_GOSSIP_PRIORITY_LABEL: &str = "nv_gossip_priority";
pub const MEMPOOL_TXS_LABEL: &str = "mempool_txs";
pub const APPLY_EXECUTION_STATE_SPAN: &str = "nv_stream_apply_execution_state";
pub const FORWARD_CLIENT_BLOCKS_SPAN: &str = "nv_stream_forward_client_blocks";
pub const GOSSIP_STREAM_MSG_LABEL: &str = "gossip stream msg";
pub const NV_STREAM_MSG_LABEL: &str = "nv_stream_msg";
pub const NODE_BOOTSTRAP_LABEL: &str = "node_bootstrap";

/// Channel capacity used by the nv-stream local queues.
pub const NV_STREAM_CHANNEL_CAPACITY: usize = 5_000;
/// Maximum pending client blocks buffered before execution-state material appears.
pub const MAX_UNCONFIRMED_CLIENT_BLOCKS: usize = 100;
/// Number of client blocks requested per gossip RPC bootstrap window.
pub const BOOTSTRAP_CLIENT_BLOCK_WINDOW: u64 = 100;
/// Reconnect limit stored in stream state after peer reset.
pub const RECONNECT_ROUND_LIMIT: u64 = 100_000;
/// `0x7d0`, passed with `0x3e8` into the stream receive/reconnect helper.
pub const FORWARD_RECV_LIMIT: usize = 2_000;
/// `0x3e8`, paired with `FORWARD_RECV_LIMIT` in the reconnect helper.
pub const FORWARD_RETRY_MILLIS: u64 = 1_000;
/// Maximum framed bytes accepted for a node-bootstrap stream message.
pub const NODE_BOOTSTRAP_READ_BUDGET: usize = 8_000_000;
/// Backoff used when the execution-state lock is contended.
pub const EXECUTION_STATE_LOCK_BACKOFF: Duration = Duration::from_secs(1);
/// f64 `20.0` is converted to a duration for node-bootstrap message reads.
pub const NODE_BOOTSTRAP_READ_TIMEOUT: Duration = Duration::from_secs(20);
/// f64 `300.0` is converted in the forward-client-block bootstrap path.
pub const FORWARD_CLIENT_BLOCKS_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(300);


#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Round(pub u64);

impl Round {
    pub const ZERO: Self = Self(0);

    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl fmt::Display for Round {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NodeIp(pub IpAddr);

impl fmt::Display for NodeIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockHash(pub [u8; 32]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalTx {
    pub payload: Vec<u8>,
    pub received_at: Instant,
}

/// Rust model of the packet record buffered before local stream forwarding.
///
/// In the binary, word 0 is an Arc-like block pointer. The rest of the record is
/// copied and later drained into the local nv-stream channel. The Rust model keeps
/// the semantic fields instead of exposing the pointer record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientBlockPacket {
    pub origin: NodeIp,
    /// Block field `+0x50`; compared with stream state `+0x108` before buffering.
    pub parent_round: Round,
    /// Block field `+0x98`; copied to stream state `+0x108` after parent match.
    pub round: Round,
    /// Block bytes at `+0x58..+0x77`; compared between adjacent pending records.
    pub hash: BlockHash,
    /// Block field `+0x108`; `i64::MIN` means execution-state material is absent.
    pub execution_marker: i64,
    /// Small counters read from the decoded block and passed to the verifier.
    pub state_counters: [u32; 3],
    /// [INFERENCE] Payload handed to the local node runtime after verification.
    pub payload: Vec<u8>,
}

impl ClientBlockPacket {
    pub fn has_execution_state(&self) -> bool {
        self.execution_marker != i64::MIN
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientBlockOrTx {
    ClientBlock(ClientBlockPacket),
    Tx(ExternalTx),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionStateSnapshot {
    pub latest_round: Round,
    pub state_hash: BlockHash,
    pub serialized_len: usize,
}

/// Compact 5-byte record copied from the local ABCI state into `nv_gossip_priority`.
///
/// The setup future copies records from a `0x140` stride source into a contiguous
/// 5-byte vector before constructing the priority object. The exact field split is
/// not used by nv_stream, so the raw bytes are preserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvGossipPriorityRecord {
    pub raw: [u8; 5],
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NvGossipPriority {
    pub records: Vec<NvGossipPriorityRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalAbciStateView {
    pub initial_height: u64,
    pub height: u64,
    pub latest_round: Round,
    pub node_ips: Vec<NodeIp>,
    pub serialized_state: Vec<u8>,
    pub priority_records: Vec<NvGossipPriorityRecord>,
}

#[derive(Clone, Debug)]
pub struct NvStreamChannels {
    pub local_client_block_or_tx: Channel<ClientBlockOrTx>,
    pub execution_state: Channel<ExecutionStateSnapshot>,
    pub mempool_txs: Channel<ExternalTx>,
}

impl NvStreamChannels {
    pub fn new() -> Self {
        Self {
            local_client_block_or_tx: Channel::with_label(CLIENT_BLOCK_OR_TX_CHANNEL_LABEL, NV_STREAM_CHANNEL_CAPACITY),
            execution_state: Channel::with_label(EXECUTION_STATE_CHANNEL_LABEL, NV_STREAM_CHANNEL_CAPACITY),
            mempool_txs: Channel::with_label(MEMPOOL_TXS_LABEL, NV_STREAM_CHANNEL_CAPACITY),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Channel<T> {
    pub label: &'static str,
    pub capacity_hint: usize,
    queue: VecDeque<T>,
}

impl<T> Channel<T> {
    pub fn with_label(label: &'static str, capacity_hint: usize) -> Self {
        Self { label, capacity_hint, queue: VecDeque::with_capacity(capacity_hint.min(8)) }
    }

    pub fn push(&mut self, value: T) {
        self.queue.push_back(value);
    }

    pub fn pop(&mut self) -> Option<T> {
        self.queue.pop_front()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[derive(Clone, Debug)]
pub struct NvStreamState {
    pub current_node_ip: NodeIp,
    /// Mirrors stream state `+0x108`: parent round expected by the next decoded block.
    pub expected_parent_round: Round,
    /// Mirrors stream state `+0x110`: latest batch-confirmed round.
    pub confirmed_round: Round,
    pub pending_client_blocks: Vec<ClientBlockPacket>,
    pub channels: NvStreamChannels,
    pub gossip_priority: NvGossipPriority,
    pub reconnect_round_limit: u64,
    pub forward_recv_limit: usize,
    pub forward_retry_delay: Duration,
    pub bootstrap_timeout: Duration,
}

impl NvStreamState {
    pub fn from_local_abci_state(current_node_ip: NodeIp, local: &LocalAbciStateView) -> Self {
        Self {
            current_node_ip,
            expected_parent_round: local.latest_round,
            confirmed_round: local.latest_round,
            pending_client_blocks: Vec::with_capacity(8),
            channels: NvStreamChannels::new(),
            gossip_priority: compact_nv_gossip_priority(local),
            reconnect_round_limit: RECONNECT_ROUND_LIMIT,
            forward_recv_limit: FORWARD_RECV_LIMIT,
            forward_retry_delay: Duration::from_millis(FORWARD_RETRY_MILLIS),
            bootstrap_timeout: FORWARD_CLIENT_BLOCKS_BOOTSTRAP_TIMEOUT,
        }
    }

    pub fn reset_after_reconnect(&mut self, current_node_ip: NodeIp) {
        self.current_node_ip = current_node_ip;
        self.pending_client_blocks.clear();
        self.pending_client_blocks.shrink_to(8);
        self.reconnect_round_limit = RECONNECT_ROUND_LIMIT;
        self.forward_recv_limit = FORWARD_RECV_LIMIT;
        self.forward_retry_delay = Duration::from_millis(FORWARD_RETRY_MILLIS);
    }
}

#[derive(Clone, Debug)]
pub struct BootstrapSetupResult {
    pub state: NvStreamState,
    pub saved_height: u64,
    pub saved_round: Round,
    pub serialized_state_len: usize,
}

pub trait InitialAbciStateStore {
    fn save_initial_local_abci_state(&mut self, state: &LocalAbciStateView) -> Result<(), NvStreamError>;
}

/// Build the nv-stream runtime from a local ABCI state snapshot.
pub fn bootstrap_setup_from_local_abci_state<S>(
    store: &mut S,
    current_node_ip: NodeIp,
    local: &LocalAbciStateView,
) -> Result<BootstrapSetupResult, NvStreamError>
where
    S: InitialAbciStateStore,
{
    log_using_local_abci_state(local.height, local.latest_round);
    store.save_initial_local_abci_state(local)?;
    log_saved_initial_local_abci_state(local.height, local.latest_round, local.serialized_state.len());

    let state = NvStreamState::from_local_abci_state(current_node_ip, local);
    Ok(BootstrapSetupResult {
        state,
        saved_height: local.height,
        saved_round: local.latest_round,
        serialized_state_len: local.serialized_state.len(),
    })
}

fn compact_nv_gossip_priority(local: &LocalAbciStateView) -> NvGossipPriority {
    NvGossipPriority { records: local.priority_records.clone() }
}

pub trait ClientBlockBatchVerifier {
    fn verify_client_block_batch(
        &mut self,
        previous_confirmed_round: Round,
        pending: &[ClientBlockPacket],
        execution_state: &ExecutionStateSnapshot,
    ) -> Result<(), NvStreamError>;
}

pub trait ExecutionStateAccess {
    fn latest_execution_state(&mut self) -> Result<ExecutionStateSnapshot, NvStreamError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientBlockApplyOutcome {
    Buffered { pending: usize },
    Flushed { count: usize, confirmed_round: Round },
}

/// Verify, buffer, and optionally flush one decoded client block.
pub fn verify_enqueue_or_flush_client_block<V, E>(
    state: &mut NvStreamState,
    packet: ClientBlockPacket,
    verifier: &mut V,
    execution_state: &mut E,
) -> Result<ClientBlockApplyOutcome, NvStreamError>
where
    V: ClientBlockBatchVerifier,
    E: ExecutionStateAccess,
{
    if packet.parent_round != state.expected_parent_round {
        return Err(NvStreamError::ClientBlockParentRound {
            expected: state.expected_parent_round,
            observed: packet.parent_round,
            round: packet.round,
        });
    }

    state.expected_parent_round = packet.round;
    let can_flush = packet.has_execution_state();
    state.pending_client_blocks.push(packet);

    if !can_flush {
        let pending = state.pending_client_blocks.len();
        if pending > MAX_UNCONFIRMED_CLIENT_BLOCKS {
            return Err(NvStreamError::TooManyUnconfirmedBlocks { pending });
        }
        return Ok(ClientBlockApplyOutcome::Buffered { pending });
    }

    let snapshot = execution_state.latest_execution_state()?;
    let old_pending = std::mem::take(&mut state.pending_client_blocks);

    if let Err(error) = verifier.verify_client_block_batch(state.confirmed_round, &old_pending, &snapshot) {
        state.pending_client_blocks = old_pending;
        log_failed_to_verify_client_block_batch(&error);
        return Err(NvStreamError::ClientBlockBatchVerification(Box::new(error)));
    }

    let flushed = old_pending.len();
    for packet in old_pending {
        state.channels.local_client_block_or_tx.push(ClientBlockOrTx::ClientBlock(packet));
    }
    state.confirmed_round = state.expected_parent_round;
    state.pending_client_blocks = Vec::with_capacity(8);

    Ok(ClientBlockApplyOutcome::Flushed { count: flushed, confirmed_round: state.confirmed_round })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardAction {
    Continue,
    Reconnect { reason: ReconnectReason },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconnectReason {
    ReaderClosed { current_node_ip: NodeIp },
    ProcessClientBlockError { round: Round, current_node_ip: NodeIp, message: String },
    NodeIpMismatch { expected: NodeIp, observed: NodeIp },
}

pub trait NvStreamReceiver {
    async fn recv_client_block_or_tx(&mut self) -> Option<ClientBlockOrTx>;
}

pub trait GossipClientBlocks {
    async fn query_client_blocks(&mut self, start_round: Round, end_round: Round) -> Result<Vec<ClientBlockPacket>, NvStreamError>;
}

pub trait NvStreamHooks {
    type Verifier: ClientBlockBatchVerifier;
    type Execution: ExecutionStateAccess;

    fn verifier_and_execution_state(&mut self) -> (&mut Self::Verifier, &mut Self::Execution);
    fn log(&mut self, target: &'static str, message: String);
    async fn sleep(&mut self, delay: Duration);
    async fn choose_next_peer(&mut self) -> Result<NodeIp, NvStreamError>;
    async fn forward_tx(&mut self, tx: ExternalTx) -> Result<(), NvStreamError>;
}

/// Forward local client blocks and transactions, reconnecting when the peer stream becomes unusable.
pub async fn forward_client_blocks<R, G, H>(
    state: &mut NvStreamState,
    receiver: &mut R,
    gossip: &mut G,
    hooks: &mut H,
) -> Result<ForwardAction, NvStreamError>
where
    R: NvStreamReceiver,
    G: GossipClientBlocks,
    H: NvStreamHooks,
{
    let Some(item) = receiver.recv_client_block_or_tx().await else {
        let reason = ReconnectReason::ReaderClosed { current_node_ip: state.current_node_ip };
        log_no_more_blocks_reconnecting(state.current_node_ip);
        reconnect_to_new_peer(state, hooks, reason.clone()).await?;
        return Ok(ForwardAction::Reconnect { reason });
    };

    match item {
        ClientBlockOrTx::Tx(tx) => {
            hooks.forward_tx(tx).await?;
            Ok(ForwardAction::Continue)
        }
        ClientBlockOrTx::ClientBlock(packet) => {
            if packet.origin != state.current_node_ip {
                let reason = ReconnectReason::NodeIpMismatch { expected: state.current_node_ip, observed: packet.origin };
                reconnect_to_new_peer(state, hooks, reason.clone()).await?;
                return Ok(ForwardAction::Reconnect { reason });
            }

            if packet.round.0 <= state.confirmed_round.0 {
                log_received_old_client_block(packet.parent_round, state.confirmed_round, state.current_node_ip);
                return Ok(ForwardAction::Continue);
            }

            if packet.parent_round.0 > state.expected_parent_round.0 {
                let bootstrap_start = state.expected_parent_round.next();
                let bootstrap_end = Round(packet.parent_round.0);
                bootstrap_missing_client_blocks(state, gossip, hooks, bootstrap_start, bootstrap_end).await?;
            }

            let round = packet.round;
            let (verifier, execution_state) = hooks.verifier_and_execution_state();
            match verify_enqueue_or_flush_client_block(state, packet, verifier, execution_state) {
                Ok(_) => Ok(ForwardAction::Continue),
                Err(error) => {
                    let reason = ReconnectReason::ProcessClientBlockError {
                        round,
                        current_node_ip: state.current_node_ip,
                        message: error.to_string(),
                    };
                    log_process_client_block_error(round, state.current_node_ip, &error);
                    reconnect_to_new_peer(state, hooks, reason.clone()).await?;
                    Ok(ForwardAction::Reconnect { reason })
                }
            }
        }
    }
}

pub async fn bootstrap_missing_client_blocks<G, H>(
    state: &mut NvStreamState,
    gossip: &mut G,
    hooks: &mut H,
    start_round: Round,
    end_round: Round,
) -> Result<usize, NvStreamError>
where
    G: GossipClientBlocks,
    H: NvStreamHooks,
{
    if end_round.0 < start_round.0 {
        return Ok(0);
    }

    log_starting_bootstrap(start_round, end_round);
    let mut next = start_round.0;
    let mut inserted = 0_usize;

    while next <= end_round.0 {
        let batch_end = end_round.0.min(next.saturating_add(BOOTSTRAP_CLIENT_BLOCK_WINDOW - 1));
        let blocks = gossip.query_client_blocks(Round(next), Round(batch_end)).await?;
        if blocks.is_empty() {
            return Err(NvStreamError::NoClientBlocks { start_round: Round(next), end_round: Round(batch_end) });
        }

        let first = blocks.first().map(|block| block.round).unwrap_or(Round(next));
        let last = blocks.last().map(|block| block.round).unwrap_or(Round(batch_end));
        log_got_client_blocks(blocks.len(), first, last);

        for block in blocks {
            let (verifier, execution_state) = hooks.verifier_and_execution_state();
            verify_enqueue_or_flush_client_block(state, block, verifier, execution_state)?;
            inserted += 1;
        }

        log_added_client_block_batch(inserted);
        if batch_end == u64::MAX {
            break;
        }
        next = batch_end + 1;
    }

    log_finished_bootstrap(start_round, end_round, inserted);
    Ok(inserted)
}

async fn reconnect_to_new_peer<H>(
    state: &mut NvStreamState,
    hooks: &mut H,
    _reason: ReconnectReason,
) -> Result<(), NvStreamError>
where
    H: NvStreamHooks,
{
    state.pending_client_blocks.clear();
    hooks.sleep(state.forward_retry_delay).await;
    let next_peer = hooks.choose_next_peer().await?;
    state.reset_after_reconnect(next_peer);
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NvStreamMessage {
    NodeBootstrap(NodeBootstrapMessage),
    ClientBlockOrTx(ClientBlockOrTx),
    ExecutionState(ExecutionStateSnapshot),
    Unknown { tag: u64, payload: Vec<u8> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeBootstrapMessage {
    pub source: NodeIp,
    pub payload: Vec<u8>,
}

pub trait NvStreamMessageCodec<S> {
    async fn read_message(
        &mut self,
        stream: &mut S,
        desc: &'static str,
        max_len: usize,
        timeout: Duration,
    ) -> Result<NvStreamMessage, NvStreamError>;
}

pub trait NvStreamMessageDispatcher {
    async fn dispatch_nv_stream_msg(&mut self, message: NvStreamMessage) -> Result<(), NvStreamError>;
}

/// Read and dispatch one node-bootstrap stream message.
pub async fn read_and_dispatch_node_bootstrap_message<S, C, D>(
    stream: &mut S,
    codec: &mut C,
    dispatcher: &mut D,
) -> Result<(), NvStreamError>
where
    C: NvStreamMessageCodec<S>,
    D: NvStreamMessageDispatcher,
{
    let message = codec
        .read_message(stream, GOSSIP_STREAM_MSG_LABEL, NODE_BOOTSTRAP_READ_BUDGET, NODE_BOOTSTRAP_READ_TIMEOUT)
        .await?;
    log_nv_stream_msg(&message);
    dispatcher.dispatch_nv_stream_msg(message).await
}

/// Poll an instrumented client-block future.
pub async fn poll_instrumented_client_block_future<T>(
    span_name: &'static str,
    future_name: &'static str,
    body: T,
) -> Result<(), NvStreamError>
where
    T: InstrumentedNvStreamFuture,
{
    let _span = NvStreamSpan { span_name, future_name };
    body.run().await
}

pub trait InstrumentedNvStreamFuture {
    async fn run(self) -> Result<(), NvStreamError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvStreamSpan {
    pub span_name: &'static str,
    pub future_name: &'static str,
}

#[derive(Debug)]
pub enum NvStreamError {
    StoreInitialState(String),
    ClientBlockParentRound { expected: Round, observed: Round, round: Round },
    TooManyUnconfirmedBlocks { pending: usize },
    ClientBlockBatchVerification(Box<NvStreamError>),
    ExecutionStateUnavailable(String),
    NoClientBlocks { start_round: Round, end_round: Round },
    Gossip(String),
    ChannelClosed(&'static str),
    Decode(String),
    Io(String),
}

impl fmt::Display for NvStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StoreInitialState(message) => write!(f, "failed to save initial local abci state: {message}"),
            Self::ClientBlockParentRound { expected, observed, round } => write!(
                f,
                "client block parent round mismatch @@ [expected_parent_round: {expected}] @ [observed_parent_round: {observed}] @ [round: {round}]"
            ),
            Self::TooManyUnconfirmedBlocks { .. } => f.write_str("Too many unconfirmed blocks"),
            Self::ClientBlockBatchVerification(error) => write!(f, "failed to verify client block batch: {error}"),
            Self::ExecutionStateUnavailable(message) => f.write_str(message),
            Self::NoClientBlocks { start_round, end_round } => {
                write!(f, "no client blocks returned @@ [start_round: {start_round}] @ [end_round: {end_round}]")
            }
            Self::Gossip(message) => f.write_str(message),
            Self::ChannelClosed(label) => write!(f, "{label} channel closed"),
            Self::Decode(message) => f.write_str(message),
            Self::Io(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for NvStreamError {}

#[derive(Clone, Debug, Default)]
pub struct InMemoryInitialAbciStateStore {
    pub saved: Vec<LocalAbciStateView>,
}

impl InitialAbciStateStore for InMemoryInitialAbciStateStore {
    fn save_initial_local_abci_state(&mut self, state: &LocalAbciStateView) -> Result<(), NvStreamError> {
        self.saved.push(state.clone());
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryExecutionState {
    pub latest: Option<ExecutionStateSnapshot>,
}

impl ExecutionStateAccess for InMemoryExecutionState {
    fn latest_execution_state(&mut self) -> Result<ExecutionStateSnapshot, NvStreamError> {
        self.latest
            .clone()
            .ok_or_else(|| NvStreamError::ExecutionStateUnavailable("nv stream execution state unavailable".to_owned()))
    }
}

#[derive(Clone, Debug, Default)]
pub struct ChainContinuityVerifier;

impl ClientBlockBatchVerifier for ChainContinuityVerifier {
    fn verify_client_block_batch(
        &mut self,
        previous_confirmed_round: Round,
        pending: &[ClientBlockPacket],
        _execution_state: &ExecutionStateSnapshot,
    ) -> Result<(), NvStreamError> {
        if pending.is_empty() {
            return Err(NvStreamError::Gossip("empty client block batch".to_owned()));
        }

        let mut previous_round = previous_confirmed_round;
        let mut previous_hash: Option<BlockHash> = None;
        for packet in pending {
            if packet.parent_round != previous_round {
                return Err(NvStreamError::ClientBlockParentRound {
                    expected: previous_round,
                    observed: packet.parent_round,
                    round: packet.round,
                });
            }
            if let Some(hash) = previous_hash {
                if hash == packet.hash && packet.round.0 != previous_round.0.saturating_add(1) {
                    return Err(NvStreamError::Gossip("client block hash/round continuity mismatch".to_owned()));
                }
            }
            previous_round = packet.round;
            previous_hash = Some(packet.hash);
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct NodeIpGossipPriority {
    pub weights: BTreeMap<NodeIp, u32>,
}

impl NodeIpGossipPriority {
    pub fn from_compact_records(node_ips: &[NodeIp], priority: &NvGossipPriority) -> Self {
        let mut weights = BTreeMap::new();
        for (idx, record) in priority.records.iter().enumerate() {
            if let Some(node_ip) = node_ips.get(idx).copied() {
                let weight = u32::from_le_bytes([record.raw[1], record.raw[2], record.raw[3], record.raw[4]]);
                weights.insert(node_ip, weight);
            }
        }
        Self { weights }
    }

    pub fn best_peer_except(&self, current: NodeIp) -> Option<NodeIp> {
        self.weights
            .iter()
            .filter(|(node_ip, _)| **node_ip != current)
            .max_by_key(|(_, weight)| *weight)
            .map(|(node_ip, _)| *node_ip)
    }
}

fn log_using_local_abci_state(height: u64, round: Round) {
    let _ = ("using local AbciState", height, round, LOCAL_CHANNEL_LABEL);
}

fn log_saved_initial_local_abci_state(height: u64, round: Round, len: usize) {
    let _ = ("saved initial local abci state", height, round, len);
}

fn log_failed_to_verify_client_block_batch(error: &NvStreamError) {
    let _ = ("failed to verify client block batch:", error);
}

fn log_received_old_client_block(parent_round: Round, confirmed_round: Round, current_node_ip: NodeIp) {
    let _ = ("received old client block, is peer behind?", parent_round, confirmed_round, current_node_ip);
}

fn log_no_more_blocks_reconnecting(current_node_ip: NodeIp) {
    let _ = ("forward_client_blocks no more blocks from reader, reconnecting to a new peer", current_node_ip);
}

fn log_process_client_block_error(round: Round, current_node_ip: NodeIp, error: &NvStreamError) {
    let _ = ("forward_client_blocks process_client_block error, reconnecting to a new peer", round, current_node_ip, error);
}

fn log_starting_bootstrap(start_round: Round, end_round: Round) {
    let _ = ("starting bootstrap", start_round, end_round, NODE_BOOTSTRAP_LABEL);
}

fn log_got_client_blocks(len: usize, first_round: Round, last_round: Round) {
    let _ = ("got client blocks", len, first_round, last_round);
}

fn log_added_client_block_batch(inserted: usize) {
    let _ = ("added client block batch during bootstrap", inserted);
}

fn log_finished_bootstrap(start_round: Round, end_round: Round, inserted: usize) {
    let _ = ("finished bootstrap", start_round, end_round, inserted);
}

fn log_nv_stream_msg(message: &NvStreamMessage) {
    let _ = (NV_STREAM_MSG_LABEL, NODE_BOOTSTRAP_LABEL, message);
}
