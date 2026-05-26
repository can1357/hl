//! Reconstruction of `/home/ubuntu/hl/code_Mainnet/node/src/consensus/network.rs`.
//!
//! Primary area: consensus networking setup and the send/receive bridge between
//! validator-local consensus state and validator-to-validator RPC/TCP streams.
//!
//! Seeds expanded:
//! - `0x454C2B0` — `node_consensus_network__spawn_forward_msgs_bridge`.
//!   String evidence: `forward msgs from src=` / ` to dest=`; spawn location
//!   `network.rs:198:17`; future size `0xBE0`; node-port base `4003` and local
//!   stride `1000`.
//! - `0x43848F0` — bootstrap/client-block sync async poll shared with consensus
//!   RPC. String evidence: `@@ starting bootstrap @@ [start_round: ...] @
//!   [end_round: ...]`, `@@ got ... client blocks first=... last=...`, and
//!   `@@ finished bootstrap @@ [start_round: ...] @ [end_round: ...]`.
//! - `0x4B399A0` — `tcp_stream_with_retry` / `async_sleep_retry` monomorph used by
//!   the bridge future.
//! - Followed xrefs not listed as seeds: `0x4360000` (`failed to verify client
//!   block batch:`) and `0x44AB560` (`: Bad QCs: ... and ...`).
//!
//! IDA-DEFERRED: the IDA server queue was full during this wave. Proposed names:
//! - `0x454C2B0` -> `node_consensus_network__spawn_forward_msgs_bridge`
//! - `0x4360000` -> `node_consensus_network__verify_and_flush_client_block_batch`
//! - `0x43848F0` -> `node_consensus_network__poll_bootstrap_client_blocks`
//! - `0x44AB560` -> `node_consensus_network__register_bootstrap_client_block`
//! - `0x4B399A0` -> `net_utils_async_sleep_retry__poll_tcp_stream_with_retry`

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use super::types::{
    BlockHash, ClientBlock, ConsensusRpcError, ConsensusRpcRequest, ConsensusRpcResponse, Round,
};

const CONSENSUS_FORWARD_BASE_PORT: u16 = 4003;
const LOCAL_VALIDATOR_PORT_STRIDE: u16 = 1_000;
const BOOTSTRAP_QUERY_WINDOW: u64 = 100;
const MAX_BOOTSTRAP_RANGE: u64 = 30_000;
const FORWARD_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
const FORWARD_CONNECT_RETRIES: usize = 10;
const FORWARD_RETRY_SLEEP: Duration = Duration::from_secs(2);
const FORWARD_RECONNECT_SLEEP: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ValidatorId(pub [u8; 20]);

impl fmt::Display for ValidatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Validator(")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// Compact node-port value used by the bridge setup function.
///
/// Recovered from `0x454C2B0`: low bit selects the local-validator form; the next
/// byte is a local validator ordinal. Non-local values carry an IPv4 address in
/// bits `8..=39` and always use consensus port 4003.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodePort(pub u64);

impl NodePort {
    pub fn socket_addr(self) -> Result<SocketAddr, NodePortError> {
        if self.0 & 1 != 0 {
            let ordinal = ((self.0 >> 8) & 0xff) as u16;
            let offset = ordinal
                .checked_mul(LOCAL_VALIDATOR_PORT_STRIDE)
                .ok_or(NodePortError::LocalPortOverflow { ordinal })?;
            let port = CONSENSUS_FORWARD_BASE_PORT
                .checked_add(offset)
                .ok_or(NodePortError::LocalPortOverflow { ordinal })?;
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port))
        } else {
            let raw_ip = ((self.0 >> 8) & 0xffff_ffff) as u32;
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(raw_ip.to_ne_bytes())),
                CONSENSUS_FORWARD_BASE_PORT,
            ))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePortError {
    LocalPortOverflow { ordinal: u16 },
}

#[derive(Clone, Debug)]
pub struct ConsensusNetworkConfig {
    pub home_validator: ValidatorId,
    pub local_listen_addr: SocketAddr,
    pub bootstrap_range_limit: u64,
    pub per_query_block_limit: u64,
    pub connect_timeout: Duration,
    pub connect_retries: usize,
    pub retry_sleep: Duration,
    pub reconnect_sleep: Duration,
}

impl ConsensusNetworkConfig {
    pub fn mainnet(home_validator: ValidatorId) -> Self {
        Self {
            home_validator,
            local_listen_addr: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                CONSENSUS_FORWARD_BASE_PORT,
            ),
            bootstrap_range_limit: MAX_BOOTSTRAP_RANGE,
            per_query_block_limit: BOOTSTRAP_QUERY_WINDOW,
            connect_timeout: FORWARD_CONNECT_TIMEOUT,
            connect_retries: FORWARD_CONNECT_RETRIES,
            retry_sleep: FORWARD_RETRY_SLEEP,
            reconnect_sleep: FORWARD_RECONNECT_SLEEP,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ValidatorRoute {
    pub validator: ValidatorId,
    pub node_port: NodePort,
    pub addr: SocketAddr,
    pub is_local_validator_port: bool,
}

#[derive(Clone, Debug)]
pub struct ConsensusNetwork {
    pub config: ConsensusNetworkConfig,
    pub active_routes: BTreeMap<ValidatorId, ValidatorRoute>,
    pub forward_bridges: Vec<ForwardBridgeConfig>,
    pub outbound: VecDeque<ForwardMessage>,
    pub inbound: VecDeque<ForwardMessage>,
    pub bootstrap: BootstrapState,
    pub pending_client_blocks: Vec<ClientBlock>,
    pub latest_committed_round: Round,
}

impl ConsensusNetwork {
    pub fn new(config: ConsensusNetworkConfig) -> Self {
        Self {
            config,
            active_routes: BTreeMap::new(),
            forward_bridges: Vec::new(),
            outbound: VecDeque::new(),
            inbound: VecDeque::new(),
            bootstrap: BootstrapState::default(),
            pending_client_blocks: Vec::new(),
            latest_committed_round: 0,
        }
    }

    /// Rebuilds validator routes and returns bridge tasks that should be spawned.
    ///
    /// The caller loops over validator records, decodes each `NodePort`, then calls
    /// `spawn_forward_msgs_bridge` for every source/destination edge. The binary's
    /// callers at `0x43970FE` and `0x47B25FD` copy 20-byte validator records and
    /// call `0x454C2B0` after finding a selected destination.
    pub fn install_validator_routes<I>(
        &mut self,
        routes: I,
        bridge: Arc<ConsensusBridge>,
        forward_to_self: bool,
    ) -> Result<Vec<ForwardBridgeConfig>, NetworkError>
    where
        I: IntoIterator<Item = (ValidatorId, NodePort)>,
    {
        let mut to_spawn = Vec::new();

        for (validator, node_port) in routes {
            let addr = node_port.socket_addr()?;
            let route = ValidatorRoute {
                validator,
                node_port,
                addr,
                is_local_validator_port: node_port.0 & 1 != 0,
            };

            if forward_to_self || validator != self.config.home_validator {
                let cfg = spawn_forward_msgs_bridge(
                    &self.config.home_validator,
                    node_port,
                    &validator,
                    Arc::clone(&bridge),
                    route.is_local_validator_port,
                )?;
                to_spawn.push(cfg.clone());
                self.forward_bridges.push(cfg);
            }

            self.active_routes.insert(validator, route);
        }

        Ok(to_spawn)
    }

    /// Records a message received from a bridge stream before consensus/RPC
    /// dispatch. The stream side has already decoded bincode and length framing.
    pub fn receive_forwarded_message(&mut self, message: ForwardMessage) {
        self.inbound.push_back(message);
    }

    /// Drains locally produced consensus messages into per-peer forwarding.
    pub fn queue_outbound_message(
        &mut self,
        dest: ValidatorId,
        request: ConsensusRpcRequest,
    ) -> Result<(), NetworkError> {
        let route = self
            .active_routes
            .get(&dest)
            .ok_or(NetworkError::UnknownValidator(dest))?;
        self.outbound.push_back(ForwardMessage {
            src: self.config.home_validator,
            dest,
            dest_addr: route.addr,
            payload: ConsensusWireMessage::RpcRequest(request),
        });
        Ok(())
    }

    /// Recovered behavior of `0x4360000`.
    ///
    /// The function compares the incoming client block's parent/previous round
    /// against the state's `latest_committed_round`, appends a 32-byte record to a
    /// pending vector, advances `latest_committed_round` from the block round, and
    /// flushes once the range is contiguous. On verification failure it formats
    /// `failed to verify client block batch:`.
    pub fn verify_and_flush_client_block_batch<V>(
        &mut self,
        block: ClientBlock,
        verifier: &V,
    ) -> Result<usize, NetworkError>
    where
        V: ClientBlockVerifier,
    {
        let round = block.block.round;
        let expected_parent = self.latest_committed_round;
        let observed_parent = block
            .block
            .qc
            .as_ref()
            .map(|qc| qc.round)
            .unwrap_or(expected_parent);

        if observed_parent != expected_parent {
            return Err(NetworkError::ClientBlockInvalidParentRound {
                expected: expected_parent,
                observed: observed_parent,
            });
        }

        self.pending_client_blocks.push(block);
        if self.pending_client_blocks.len() <= 100 {
            return Ok(0);
        }

        self.flush_pending_client_blocks(verifier)
    }

    pub fn flush_pending_client_blocks<V>(&mut self, verifier: &V) -> Result<usize, NetworkError>
    where
        V: ClientBlockVerifier,
    {
        if self.pending_client_blocks.is_empty() {
            return Ok(0);
        }

        let mut last_round = self.latest_committed_round;
        for block in &self.pending_client_blocks {
            if block.block.round != last_round.saturating_add(1) {
                return Err(NetworkError::ClientBlockNotConsecutive {
                    previous: last_round,
                    next: block.block.round,
                });
            }
            verifier
                .verify_client_block(block)
                .map_err(NetworkError::ClientBlockVerification)?;
            last_round = block.block.round;
        }

        let flushed = self.pending_client_blocks.len();
        self.pending_client_blocks.clear();
        self.latest_committed_round = last_round;
        Ok(flushed)
    }

    /// Recovered behavior of `0x44AB560`.
    ///
    /// During bootstrap, the code looks up the block by round/hash, compares QCs,
    /// logs `: Bad QCs: {left} and {right}` on mismatch, then appends a copied
    pub fn register_bootstrap_client_block(
        &mut self,
        block: ClientBlock,
    ) -> Result<(), NetworkError> {
        let Some(expected_qc) = block.commit_proof.as_ref() else {
            return Err(NetworkError::Consensus(ConsensusRpcError::ClientBlockMissingCommitProof));
        };

        if let Some(block_qc) = block.block.qc.as_ref() {
            if block_qc.block_hash != expected_qc.block_hash || block_qc.round != expected_qc.round {
                return Err(NetworkError::BadQcs {
                    block_qc_round: block_qc.round,
                    commit_qc_round: expected_qc.round,
                });
            }
        }

        self.bootstrap.received_blocks.push(block);
        Ok(())
    }

    /// Recovered behavior of the bootstrap portion of `0x43848F0`.
    pub async fn bootstrap_client_blocks<C, V>(
        &mut self,
        client: &mut C,
        verifier: &V,
        start_round: Round,
        end_round: Round,
    ) -> Result<(), NetworkError>
    where
        C: ConsensusRpcClient,
        V: ClientBlockVerifier,
    {
        if end_round.saturating_sub(start_round) > self.config.bootstrap_range_limit {
            return Err(NetworkError::BootstrapRangeTooLarge { start_round, end_round });
        }

        self.bootstrap.start_round = Some(start_round);
        self.bootstrap.end_round = Some(end_round);
        self.bootstrap.finished = false;

        let mut current = self.latest_committed_round.max(start_round.saturating_sub(1));
        while current < end_round {
            let query_start = current.saturating_add(1);
            let query_end = (current + self.config.per_query_block_limit).min(end_round);
            self.bootstrap.last_query = Some((query_start, query_end));

            let blocks = client
                .request_client_blocks(query_start, (query_end - query_start + 1) as u32)
                .await?;
            if blocks.is_empty() {
                return Err(NetworkError::Consensus(ConsensusRpcError::RpcPeerNoClientBlocks));
            }

            for block in blocks {
                self.register_bootstrap_client_block(block.clone())?;
                self.verify_and_flush_client_block_batch(block, verifier)?;
            }
            self.flush_pending_client_blocks(verifier)?;
            current = self.latest_committed_round;
        }

        self.bootstrap.finished = true;
        Ok(())
    }
}

/// Configuration captured into the `0x454C2B0` async future before Tokio spawn.
#[derive(Clone, Debug)]
pub struct ForwardBridgeConfig {
    pub label: String,
    pub src: ValidatorId,
    pub dest: ValidatorId,
    pub dest_addr: SocketAddr,
    pub bridge: Arc<ConsensusBridge>,
    pub is_local_validator_port: bool,
}

pub fn spawn_forward_msgs_bridge(
    src: &ValidatorId,
    dest_port: NodePort,
    dest: &ValidatorId,
    bridge: Arc<ConsensusBridge>,
    is_local_validator_port: bool,
) -> Result<ForwardBridgeConfig, NetworkError> {
    let dest_addr = dest_port.socket_addr()?;
    let label = format!("forward msgs from src={src} to dest={dest} {dest_addr}");

    Ok(ForwardBridgeConfig {
        label,
        src: *src,
        dest: *dest,
        dest_addr,
        bridge,
        is_local_validator_port,
    })
}

/// Runtime body represented by the 0xBE0-byte future spawned at `network.rs:198`.
pub async fn forward_msgs_bridge_task<T>(
    config: ForwardBridgeConfig,
    transport: &mut T,
) -> Result<(), NetworkError>
where
    T: ConsensusTransport,
{
    loop {
        let Some(message) = config.bridge.pop_outbound_for(config.dest) else {
            transport.sleep(config.bridge.reconnect_sleep()).await;
            continue;
        };

        let result = transport.send(config.dest_addr, &message).await;
        match result {
            Ok(()) => config.bridge.mark_sent(&message),
            Err(error) => {
                config.bridge.requeue_front(message);
                return Err(NetworkError::Transport(error));
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct ConsensusBridge {
    outbound: parking_lot::Mutex<VecDeque<ForwardMessage>>,
    sent: parking_lot::Mutex<Vec<ForwardMessageMeta>>,
    reconnect_sleep: Duration,
}

impl ConsensusBridge {
    pub fn new(reconnect_sleep: Duration) -> Self {
        Self {
            outbound: parking_lot::Mutex::new(VecDeque::new()),
            sent: parking_lot::Mutex::new(Vec::new()),
            reconnect_sleep,
        }
    }

    pub fn push_outbound(&self, message: ForwardMessage) {
        self.outbound.lock().push_back(message);
    }

    pub fn pop_outbound_for(&self, dest: ValidatorId) -> Option<ForwardMessage> {
        let mut outbound = self.outbound.lock();
        let pos = outbound.iter().position(|message| message.dest == dest)?;
        outbound.remove(pos)
    }

    pub fn requeue_front(&self, message: ForwardMessage) {
        self.outbound.lock().push_front(message);
    }

    pub fn mark_sent(&self, message: &ForwardMessage) {
        self.sent.lock().push(ForwardMessageMeta {
            src: message.src,
            dest: message.dest,
            dest_addr: message.dest_addr,
            kind: message.payload.kind(),
        });
    }

    pub fn reconnect_sleep(&self) -> Duration {
        self.reconnect_sleep
    }
}

#[derive(Clone, Debug)]
pub struct ForwardMessage {
    pub src: ValidatorId,
    pub dest: ValidatorId,
    pub dest_addr: SocketAddr,
    pub payload: ConsensusWireMessage,
}

#[derive(Clone, Debug)]
pub struct ForwardMessageMeta {
    pub src: ValidatorId,
    pub dest: ValidatorId,
    pub dest_addr: SocketAddr,
    pub kind: WireMessageKind,
}

#[derive(Clone, Debug)]
pub enum ConsensusWireMessage {
    RpcRequest(ConsensusRpcRequest),
    RpcResponse(ConsensusRpcResponse),
    ClientBlock(ClientBlock),
    Raw(Vec<u8>),
}

impl ConsensusWireMessage {
    fn kind(&self) -> WireMessageKind {
        match self {
            Self::RpcRequest(_) => WireMessageKind::RpcRequest,
            Self::RpcResponse(_) => WireMessageKind::RpcResponse,
            Self::ClientBlock(_) => WireMessageKind::ClientBlock,
            Self::Raw(_) => WireMessageKind::Raw,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireMessageKind {
    RpcRequest,
    RpcResponse,
    ClientBlock,
    Raw,
}

#[derive(Clone, Debug, Default)]
pub struct BootstrapState {
    pub start_round: Option<Round>,
    pub end_round: Option<Round>,
    pub last_query: Option<(Round, Round)>,
    pub received_blocks: Vec<ClientBlock>,
    pub finished: bool,
}

pub trait ConsensusRpcClient {
    fn request_client_blocks(
        &mut self,
        after_round: Round,
        max_blocks: u32,
    ) -> impl Future<Output = Result<Vec<ClientBlock>, NetworkError>> + Send;
}

pub trait ClientBlockVerifier {
    fn verify_client_block(&self, block: &ClientBlock) -> Result<(), ConsensusRpcError>;
}

pub trait ConsensusTransport {
    fn send(
        &mut self,
        addr: SocketAddr,
        message: &ForwardMessage,
    ) -> impl Future<Output = Result<(), TransportError>> + Send;

    fn sleep(&mut self, duration: Duration) -> impl Future<Output = ()> + Send;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkError {
    NodePort(NodePortError),
    UnknownValidator(ValidatorId),
    BootstrapRangeTooLarge { start_round: Round, end_round: Round },
    ClientBlockInvalidParentRound { expected: Round, observed: Round },
    ClientBlockNotConsecutive { previous: Round, next: Round },
    ClientBlockVerification(ConsensusRpcError),
    BadQcs { block_qc_round: Round, commit_qc_round: Round },
    Consensus(ConsensusRpcError),
    Transport(TransportError),
}

impl From<NodePortError> for NetworkError {
    fn from(error: NodePortError) -> Self {
        Self::NodePort(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportError {
    pub addr: SocketAddr,
    pub message: String,
}
