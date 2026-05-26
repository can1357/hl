//! Reconstructed Rust for `/home/ubuntu/hl/code_Mainnet/node/src/consensus/server.rs`.
//!
//! Primary seed EAs: `0x1FD7D00`, `0x1FD85F0`, `0x203D330`, `0x226C2D0`,
//! `0x227C0C0`, `0x227C870`, `0x22BE860`, `0x27D6C70`, `0x435E3D0`,
//! `0x438CB90`, `0x4391840`, `0x43965B0`, `0x4399360`, `0x4399E80`,
//! `0x47B12D0`, `0x47B1930`, `0x47B1EF0`, `0x47B6F90`, `0x47B75E0`,
//! `0x4B363B0`, `0x4B39010`.
//!
//! IDA annotation attempts were made for the reconstructed `node_consensus_server__...`
//! names, but the shared IDA worker returned `Server is busy (request queue full)`.
//! The exact names intended for IDA are kept on each function below. Evidence used here
//! includes the manifest source-path panic at `/home/ubuntu/hl/code_Mainnet/node/src/consensus/server.rs`,
//! disassembly of the seed ranges, and string anchors including `consensus connection bytes`,
//! `server_listen_get_node_ip`, `external_tx`, `consensus msg`, `node_disabler`,
//! `unprocessed_validator_to_ip`, `connecting_new_ip`, `copy_node_ips`,
//! `consensus forward external tx`, `Refresher request`, `Refresher response`,
//! `Incoming tcp stream`, `Received rpc request`, `send consensus rpc resp`,
//! `Dropping tcp stream`, and `Failed to send tcp response`.

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

pub const CONNECTION_BYTES_TICK: Duration = Duration::from_millis(10);
pub const COPY_NODE_IPS_RETRY: Duration = Duration::from_secs(5);
pub const REMOVE_INACTIVE_RETRY: Duration = Duration::from_secs(10);
pub const CONSENSUS_RPC_REQUEST_DESC: &str = "consensus rpc request";
pub const CONSENSUS_RPC_RESPONSE_DESC: &str = "consensus rpc resp";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ValidatorId(pub [u8; 20]);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct NodeIp {
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PeerEndpoint {
    pub validator: Option<ValidatorId>,
    pub addr: SocketAddr,
}

#[derive(Clone, Debug)]
pub struct ActiveValidatorEntry {
    pub validator: ValidatorId,
    pub index: u32,
    pub stake: u64,
    pub node_ip: Option<NodeIp>,
    pub last_seen_round: u64,
}

#[derive(Clone, Debug)]
pub struct ExternalTx {
    pub tx_hash: [u8; 32],
    pub seq_num: u64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ConsensusMessage {
    pub validator: ValidatorId,
    pub round: u64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum ConsensusRpcRequest {
    GetPeers,
    GetNodeIp { validator: ValidatorId },
    ClientBlocks { after_round: u64, max_blocks: u32 },
    RefresherRequest { bytes: Vec<u8> },
    NodeBootstrap { bytes: Vec<u8> },
    ExternalTx(ExternalTx),
    ConsensusMessage(ConsensusMessage),
    Unknown { tag: u64, bytes: Vec<u8> },
}

#[derive(Clone, Debug)]
pub enum ConsensusRpcResponse {
    Peers(Vec<(ValidatorId, NodeIp)>),
    NodeIp(Option<NodeIp>),
    ClientBlocks(Vec<Vec<u8>>),
    Ack,
    Error(String),
    Unknown { tag: u64, bytes: Vec<u8> },
}

#[derive(Clone, Debug)]
pub enum ServerEvent {
    AcceptedTcpStream(PeerEndpoint),
    ReceivedRpcRequest { peer: PeerEndpoint, bytes_len: usize },
    OutboundResponse { peer: PeerEndpoint, bytes_len: usize },
    DroppingTcpStream { peer: PeerEndpoint, reason: &'static str },
    ConnectionBytes(ConnectionBytesRecord),
    RefresherRequest,
    RefresherResponse,
}

#[derive(Clone, Debug)]
pub struct TcpConnectionFrame {
    pub peer: PeerEndpoint,
    pub request: Result<ConsensusRpcRequest, TcpFrameError>,
    pub keep_alive: bool,
    pub bytes_len: usize,
}

#[derive(Clone, Debug)]
pub enum TcpFrameError {
    Eof,
    Decode,
    Io,
}

#[derive(Clone, Debug)]
pub enum OutboundRequest {
    ForwardExternalTx(ExternalTx),
    ForwardConsensusMessage(ConsensusMessage),
    GetNodeIp { peer: PeerEndpoint, validator: ValidatorId },
    RemoveInactiveValidators,
    CopyNodeIps,
    RpcResponse { peer: PeerEndpoint, response: ConsensusRpcResponse },
}

#[derive(Clone, Debug)]
pub struct WorkerResponse {
    pub peer: PeerEndpoint,
    pub response: Result<ConsensusRpcResponse, String>,
}

#[derive(Clone, Debug, Default)]
pub struct ServerMetrics {
    pub accepted_streams: u64,
    pub inbound_rpc_requests: u64,
    pub outbound_rpc_responses: u64,
    pub inbound_bytes: u64,
    pub outbound_bytes: u64,
    pub dispatch_external_txs: u64,
    pub dispatch_consensus_msgs: u64,
    pub get_node_ip_requests: u64,
    pub dropped_tcp_streams: u64,
    pub inactive_validators_removed: u64,
    pub connection_byte_flushes: u64,
}

#[derive(Clone, Debug)]
pub struct ConnectionByteCounters {
    pub peer: PeerEndpoint,
    pub bytes_since_flush: u64,
    pub total_bytes: u64,
    pub open_connections: u32,
    pub outstanding_get_node_ip: u32,
    pub last_flush: Instant,
}

impl ConnectionByteCounters {
    fn new(peer: PeerEndpoint, now: Instant) -> Self {
        Self {
            peer,
            bytes_since_flush: 0,
            total_bytes: 0,
            open_connections: 0,
            outstanding_get_node_ip: 0,
            last_flush: now,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConnectionBytesRecord {
    pub peer: PeerEndpoint,
    pub bytes: u64,
    pub total_bytes: u64,
    pub open_connections: u32,
}

#[derive(Clone, Debug)]
pub struct PendingNodeIpLookup {
    pub peer: PeerEndpoint,
    pub validator: ValidatorId,
    pub started_at: Instant,
}

#[derive(Clone, Debug)]
pub enum ServerPoll {
    Pending,
    Progress,
    Complete,
}

#[derive(Debug)]
pub struct ConsensusServer {
    pub home_validator: ValidatorId,
    pub active_validator_to_ip: BTreeMap<ValidatorId, NodeIp>,
    pub active_validators: BTreeMap<ValidatorId, ActiveValidatorEntry>,
    pub connecting_new_ip: BTreeMap<ValidatorId, NodeIp>,
    pub unprocessed_validator_to_ip: BTreeMap<ValidatorId, NodeIp>,
    pub connection_bytes: BTreeMap<PeerEndpoint, ConnectionByteCounters>,
    pub pending_node_ip_lookups: VecDeque<PendingNodeIpLookup>,
    pub inbound_tcp_streams: VecDeque<TcpConnectionFrame>,
    pub outbound_requests: VecDeque<OutboundRequest>,
    pub pending_worker_responses: VecDeque<WorkerResponse>,
    pub tcp_responses: VecDeque<(PeerEndpoint, ConsensusRpcResponse)>,
    pub forward_external_txs: VecDeque<ExternalTx>,
    pub forwarded_external_txs: VecDeque<ExternalTx>,
    pub consensus_messages: VecDeque<ConsensusMessage>,
    pub tx_hash_to_seq_num: BTreeMap<[u8; 32], u64>,
    pub refresher_requests: VecDeque<Vec<u8>>,
    pub refresher_responses: VecDeque<ConsensusRpcResponse>,
    pub events: VecDeque<ServerEvent>,
    pub metrics: ServerMetrics,
    pub asked_to_exit: bool,
    pub next_copy_node_ips_at: Option<Instant>,
    pub next_remove_inactive_at: Option<Instant>,
}

impl ConsensusServer {
    pub fn new(home_validator: ValidatorId) -> Self {
        Self {
            home_validator,
            active_validator_to_ip: BTreeMap::new(),
            active_validators: BTreeMap::new(),
            connecting_new_ip: BTreeMap::new(),
            unprocessed_validator_to_ip: BTreeMap::new(),
            connection_bytes: BTreeMap::new(),
            pending_node_ip_lookups: VecDeque::new(),
            inbound_tcp_streams: VecDeque::new(),
            outbound_requests: VecDeque::new(),
            pending_worker_responses: VecDeque::new(),
            tcp_responses: VecDeque::new(),
            forward_external_txs: VecDeque::new(),
            forwarded_external_txs: VecDeque::new(),
            consensus_messages: VecDeque::new(),
            tx_hash_to_seq_num: BTreeMap::new(),
            refresher_requests: VecDeque::new(),
            refresher_responses: VecDeque::new(),
            events: VecDeque::new(),
            metrics: ServerMetrics::default(),
            asked_to_exit: false,
            next_copy_node_ips_at: None,
            next_remove_inactive_at: None,
        }
    }

    /// `0x435E3D0` — intended IDA name
    /// `node_consensus_server__spawn_or_run_consensus_server_task`.
    ///
    /// The binary builds a large task/future record, installs the current runtime
    /// context through TLS, then drives the server future. This synchronous model
    /// keeps the recovered scheduling contract: keep polling child arms until no
    /// arm reports progress or the exit flag is set.
    pub fn node_consensus_server__spawn_or_run_consensus_server_task(&mut self, now: Instant) -> ServerPoll {
        let mut progressed = false;

        loop {
            let before = self.total_queued_work();
            progressed |= self.node_consensus_server__poll_server_listen_dispatch_loop(now) != 0;
            progressed |= self.node_consensus_server__poll_consensus_rpc_response_forwarder();
            progressed |= self.node_consensus_server__poll_refresher_request_loop();
            progressed |= self.node_consensus_server__poll_copy_node_ips_and_remove_inactive(now);
            progressed |= self.node_consensus_server__drain_outbound_requests(now) != 0;

            if self.asked_to_exit {
                return ServerPoll::Complete;
            }
            if self.total_queued_work() == before {
                break;
            }
        }

        if progressed { ServerPoll::Progress } else { ServerPoll::Pending }
    }

    /// `0x203D330` — intended IDA name
    /// `node_consensus_server__poll_server_listen_dispatch_loop`.
    ///
    /// Recovered as the central server-listen async poll loop. It records elapsed
    /// time in the shared metrics block, swaps/updates the task waker, then splits
    /// each accepted request into the `external_tx` or `consensus` span. The two
    /// branch constructors call the sibling futures at `0x227C870` and `0x227C0C0`.
    pub fn node_consensus_server__poll_server_listen_dispatch_loop(&mut self, now: Instant) -> usize {
        let mut processed = 0;

        while let Some(frame) = self.inbound_tcp_streams.pop_front() {
            self.metrics.accepted_streams = self.metrics.accepted_streams.saturating_add(1);
            self.metrics.inbound_bytes = self.metrics.inbound_bytes.saturating_add(frame.bytes_len as u64);
            self.events.push_back(ServerEvent::AcceptedTcpStream(frame.peer.clone()));

            if let Some(record) = self.node_consensus_server__poll_consensus_connection_bytes(
                frame.peer.clone(),
                frame.bytes_len as u64,
                now,
            ) {
                self.events.push_back(ServerEvent::ConnectionBytes(record));
            }

            processed += 1;
            let keep_alive = frame.keep_alive;
            let peer = frame.peer.clone();
            match self.node_consensus_server__poll_consensus_rpc_tcp_stream(frame) {
                Some(response) => {
                    self.tcp_responses.push_back((peer, response));
                    if !keep_alive {
                        self.metrics.outbound_rpc_responses = self.metrics.outbound_rpc_responses.saturating_add(1);
                    }
                }
                None => {
                    self.metrics.dropped_tcp_streams = self.metrics.dropped_tcp_streams.saturating_add(1);
                }
            }
        }

        processed
    }

    /// `0x1FD7D00` — intended IDA name
    /// `node_consensus_server__poll_consensus_connection_bytes`.
    ///
    /// The optimized state machine has a discriminant at `self+0x393`, a 10ms
    /// child delay (`0x989680` ns), and string `consensus connection bytes`. It
    /// accumulates per-peer byte counts and periodically flushes the delta into a
    /// record consumed by the server metrics path.
    pub fn node_consensus_server__poll_consensus_connection_bytes(
        &mut self,
        peer: PeerEndpoint,
        bytes_read: u64,
        now: Instant,
    ) -> Option<ConnectionBytesRecord> {
        let counters = self
            .connection_bytes
            .entry(peer.clone())
            .or_insert_with(|| ConnectionByteCounters::new(peer.clone(), now));

        counters.bytes_since_flush = counters.bytes_since_flush.saturating_add(bytes_read);
        counters.total_bytes = counters.total_bytes.saturating_add(bytes_read);
        counters.open_connections = counters.open_connections.saturating_add(1);

        if now.duration_since(counters.last_flush) < CONNECTION_BYTES_TICK {
            return None;
        }

        let record = ConnectionBytesRecord {
            peer,
            bytes: counters.bytes_since_flush,
            total_bytes: counters.total_bytes,
            open_connections: counters.open_connections,
        };
        counters.bytes_since_flush = 0;
        counters.last_flush = now;
        self.metrics.connection_byte_flushes = self.metrics.connection_byte_flushes.saturating_add(1);
        Some(record)
    }

    /// `0x1FD85F0` — intended IDA name
    /// `node_consensus_server__poll_server_get_node_ip_connection`.
    ///
    /// Sibling of the connection-byte poller. The binary uses the label
    /// `server_listen_get_node_ip`, waits on the same 10ms delay helper, locks the
    /// per-peer table, and decrements the outstanding counter once the node-IP
    /// request has been resolved.
    pub fn node_consensus_server__poll_server_get_node_ip_connection(
        &mut self,
        lookup: PendingNodeIpLookup,
        now: Instant,
    ) -> Option<NodeIp> {
        let counters = self
            .connection_bytes
            .entry(lookup.peer.clone())
            .or_insert_with(|| ConnectionByteCounters::new(lookup.peer.clone(), lookup.started_at));

        counters.outstanding_get_node_ip = counters.outstanding_get_node_ip.saturating_add(1);
        if now.duration_since(lookup.started_at) < CONNECTION_BYTES_TICK {
            return None;
        }

        counters.outstanding_get_node_ip = counters.outstanding_get_node_ip.saturating_sub(1);
        self.metrics.get_node_ip_requests = self.metrics.get_node_ip_requests.saturating_add(1);
        self.active_validator_to_ip.get(&lookup.validator).cloned()
    }

    /// `0x27D6C70` — intended IDA name
    /// `node_consensus_server__lookup_home_validator_active_set_entry`.
    ///
    /// Disassembly shows a 20-byte `memcmp` walk over a BTree-like active-set map
    /// and a hard panic with `Home validator is inactive. May not have enough
    /// stake to be in active set.` when the home validator is absent.
    pub fn node_consensus_server__lookup_home_validator_active_set_entry(&self) -> &ActiveValidatorEntry {
        self.active_validators.get(&self.home_validator).unwrap_or_else(|| {
            panic!("Home validator is inactive. May not have enough stake to be in active set.")
        })
    }

    /// `0x435E810` — intended IDA name
    /// `node_consensus_server__dispatch_consensus_outbound_request`.
    ///
    /// Required foreign helper called by the pollers. It is a jump-table dispatch
    /// over a request discriminant, copies payload records of several sizes, and
    /// sends them to bounded channel helpers. The `tx_hash_to_seq_num remove` arm
    /// is modeled by removing entries when external tx forwarding completes.
    pub fn node_consensus_server__dispatch_consensus_outbound_request(
        &mut self,
        request: OutboundRequest,
    ) -> bool {
        match request {
            OutboundRequest::ForwardExternalTx(tx) => {
                self.tx_hash_to_seq_num.insert(tx.tx_hash, tx.seq_num);
                self.forwarded_external_txs.push_back(tx);
                self.metrics.dispatch_external_txs = self.metrics.dispatch_external_txs.saturating_add(1);
                true
            }
            OutboundRequest::ForwardConsensusMessage(msg) => {
                self.consensus_messages.push_back(msg);
                self.metrics.dispatch_consensus_msgs = self.metrics.dispatch_consensus_msgs.saturating_add(1);
                true
            }
            OutboundRequest::GetNodeIp { peer, validator } => {
                self.pending_node_ip_lookups.push_back(PendingNodeIpLookup {
                    peer,
                    validator,
                    started_at: Instant::now(),
                });
                true
            }
            OutboundRequest::RemoveInactiveValidators => self.node_consensus_server__poll_remove_inactive_validators(),
            OutboundRequest::CopyNodeIps => self.node_consensus_server__poll_copy_node_ips_and_remove_inactive(Instant::now()),
            OutboundRequest::RpcResponse { peer, response } => {
                self.tcp_responses.push_back((peer, response));
                true
            }
        }
    }

    /// `0x438CB90` / `0x47B1930` — intended IDA name
    /// `node_consensus_server__poll_remove_inactive_validators`.
    ///
    /// The state machine polls a child future at `0x4554D80`, treats result
    /// discriminant `0x0c` as completion, and on discriminant `0x0b` rebuilds the
    /// removal request through `0x435E810` after a `node_disabler` timer.
    pub fn node_consensus_server__poll_remove_inactive_validators(&mut self) -> bool {
        let mut removed = 0_u64;
        let active = &self.active_validator_to_ip;

        self.unprocessed_validator_to_ip.retain(|validator, _| {
            let keep = active.contains_key(validator);
            if !keep {
                removed = removed.saturating_add(1);
            }
            keep
        });

        self.connecting_new_ip.retain(|validator, _| {
            let keep = active.contains_key(validator);
            if !keep {
                removed = removed.saturating_add(1);
            }
            keep
        });

        if removed != 0 {
            self.metrics.inactive_validators_removed = self.metrics.inactive_validators_removed.saturating_add(removed);
            true
        } else {
            false
        }
    }

    /// `0x43965B0` / `0x47B1EF0` — intended IDA name
    /// `node_consensus_server__poll_copy_node_ips_and_remove_inactive`.
    ///
    /// Reconciles `unprocessed_validator_to_ip` and `connecting_new_ip`, logs the
    /// `copy_node_ips` and `remove_inactive_validators` spans, waits five seconds
    /// between nonempty passes, and asserts that the home validator stays active.
    pub fn node_consensus_server__poll_copy_node_ips_and_remove_inactive(&mut self, now: Instant) -> bool {
        if let Some(deadline) = self.next_copy_node_ips_at {
            if now < deadline {
                return false;
            }
        }

        let mut changed = false;
        let mut copied = Vec::new();

        for (validator, ip) in &self.unprocessed_validator_to_ip {
            if self.active_validator_to_ip.get(validator) != Some(ip) {
                copied.push((*validator, ip.clone()));
            }
        }
        for (validator, ip) in &self.connecting_new_ip {
            if self.active_validator_to_ip.get(validator) != Some(ip) {
                copied.push((*validator, ip.clone()));
            }
        }

        for (validator, ip) in copied {
            self.active_validator_to_ip.insert(validator, ip.clone());
            self.active_validators
                .entry(validator)
                .and_modify(|entry| entry.node_ip = Some(ip.clone()))
                .or_insert(ActiveValidatorEntry {
                    validator,
                    index: 0,
                    stake: 0,
                    node_ip: Some(ip),
                    last_seen_round: 0,
                });
            changed = true;
        }

        changed |= self.node_consensus_server__poll_remove_inactive_validators();

        assert!(
            self.active_validator_to_ip.contains_key(&self.home_validator),
            "Home validator has left the active set. May not have enough stake to be in active set"
        );

        if changed {
            self.next_copy_node_ips_at = Some(now + COPY_NODE_IPS_RETRY);
        }
        changed
    }

    /// `0x4399E80` / `0x47B12D0` — intended IDA name
    /// `node_consensus_server__poll_forward_external_txs`.
    ///
    /// Polls a child future at `0x4555230`, builds the span `consensus forward
    /// external tx`, inserts `tx_hash -> seq_num`, and sends the external tx to
    /// the bounded consensus channel helper.
    pub fn node_consensus_server__poll_forward_external_txs(&mut self) -> bool {
        let Some(tx) = self.forward_external_txs.pop_front() else {
            return false;
        };

        self.tx_hash_to_seq_num.insert(tx.tx_hash, tx.seq_num);
        self.forwarded_external_txs.push_back(tx);
        true
    }

    /// `0x47B6F90` — intended IDA name
    /// `node_consensus_server__poll_tx_hash_to_seq_num_insert`.
    ///
    /// Dedicated monomorph for the `tx_hash_to_seq_num insert` telemetry branch.
    pub fn node_consensus_server__poll_tx_hash_to_seq_num_insert(&mut self, tx: ExternalTx) -> Option<u64> {
        self.tx_hash_to_seq_num.insert(tx.tx_hash, tx.seq_num)
    }

    /// `0x4399360` / `0x47B75E0` — intended IDA name
    /// `node_consensus_server__poll_refresher_request_loop`.
    ///
    /// Polls the refresher request stream (`0x4554FC0`). Ready value discriminant
    /// `3` completes; discriminant `2` is a pending/closed branch. For real
    /// request values the binary logs `Refresher request`, locks the queue, pushes
    /// the request, and wakes the paired task.
    pub fn node_consensus_server__poll_refresher_request_loop(&mut self) -> bool {
        let mut progressed = false;

        while let Some(response) = self.refresher_responses.pop_front() {
            self.events.push_back(ServerEvent::RefresherResponse);
            self.outbound_requests.push_back(OutboundRequest::RpcResponse {
                peer: PeerEndpoint {
                    validator: None,
                    addr: SocketAddr::from(([0, 0, 0, 0], 0)),
                },
                response,
            });
            progressed = true;
        }

        if !self.refresher_requests.is_empty() {
            self.events.push_back(ServerEvent::RefresherRequest);
            progressed = true;
        }

        progressed
    }

    /// `0x4B363B0` — intended IDA name
    /// `node_consensus_server__poll_consensus_rpc_tcp_stream`.
    ///
    /// Per-connection TCP state machine. It logs `Incoming tcp stream`, reads one
    /// framed `consensus rpc request` through the net-utils/bincode helpers,
    /// dispatches it to the RPC worker, waits for `Outbound response`, serializes
    /// `consensus rpc resp`, and drops the stream on decode/write/channel errors.
    pub fn node_consensus_server__poll_consensus_rpc_tcp_stream(
        &mut self,
        frame: TcpConnectionFrame,
    ) -> Option<ConsensusRpcResponse> {
        let peer = frame.peer;
        self.events.push_back(ServerEvent::ReceivedRpcRequest {
            peer: peer.clone(),
            bytes_len: frame.bytes_len,
        });

        let request = match frame.request {
            Ok(request) => request,
            Err(TcpFrameError::Eof) => {
                self.events.push_back(ServerEvent::DroppingTcpStream { peer, reason: "early eof" });
                return None;
            }
            Err(TcpFrameError::Decode) => {
                self.events.push_back(ServerEvent::DroppingTcpStream { peer, reason: "decode" });
                return None;
            }
            Err(TcpFrameError::Io) => {
                self.events.push_back(ServerEvent::DroppingTcpStream { peer, reason: "io" });
                return None;
            }
        };

        self.metrics.inbound_rpc_requests = self.metrics.inbound_rpc_requests.saturating_add(1);
        let response = self.node_consensus_server__dispatch_consensus_rpc_request(peer.clone(), request);
        self.events.push_back(ServerEvent::OutboundResponse { peer, bytes_len: response.encoded_len_hint() });
        Some(response)
    }

    /// `0x4B39010` — intended IDA name
    /// `node_consensus_server__poll_consensus_rpc_response_forwarder`.
    ///
    /// Awaits a worker result and forwards the response to the TCP writer channel.
    /// The binary unwraps nested result-like variants, logs `Refresher response`,
    /// and calls the same bounded channel send helper used by external tx forwarders.
    pub fn node_consensus_server__poll_consensus_rpc_response_forwarder(&mut self) -> bool {
        let Some(worker) = self.pending_worker_responses.pop_front() else {
            return false;
        };

        let response = match worker.response {
            Ok(response) => response,
            Err(err) => ConsensusRpcResponse::Error(err),
        };
        self.tcp_responses.push_back((worker.peer, response));
        true
    }

    /// `0x438CB90` helper arm and `0x4391840` server-task arm — intended IDA name
    /// `node_consensus_server__poll_node_disabler_and_non_validator_catchup`.
    ///
    /// This models the strings adjacent to the source-path panic:
    /// `non-validator abci state not caught up yet ...` and `reading bytes for ...`.
    /// Non-validators stay in the accept/read loop, but validator-only work is
    /// withheld until local ABCI state has caught up enough to service consensus RPC.
    pub fn node_consensus_server__poll_node_disabler_and_non_validator_catchup(
        &mut self,
        is_validator: bool,
        abci_state_caught_up: bool,
        now: Instant,
    ) -> ServerPoll {
        if !is_validator && !abci_state_caught_up {
            self.next_remove_inactive_at = Some(now + REMOVE_INACTIVE_RETRY);
            return ServerPoll::Pending;
        }

        if self.next_remove_inactive_at.map_or(true, |deadline| now >= deadline) {
            if self.node_consensus_server__poll_remove_inactive_validators() {
                self.next_remove_inactive_at = Some(now + REMOVE_INACTIVE_RETRY);
                return ServerPoll::Progress;
            }
        }

        ServerPoll::Pending
    }

    fn node_consensus_server__dispatch_consensus_rpc_request(
        &mut self,
        peer: PeerEndpoint,
        request: ConsensusRpcRequest,
    ) -> ConsensusRpcResponse {
        match request {
            ConsensusRpcRequest::GetPeers => {
                let peers = self
                    .active_validator_to_ip
                    .iter()
                    .map(|(validator, ip)| (*validator, ip.clone()))
                    .collect();
                ConsensusRpcResponse::Peers(peers)
            }
            ConsensusRpcRequest::GetNodeIp { validator } => {
                self.metrics.get_node_ip_requests = self.metrics.get_node_ip_requests.saturating_add(1);
                ConsensusRpcResponse::NodeIp(self.active_validator_to_ip.get(&validator).cloned())
            }
            ConsensusRpcRequest::ClientBlocks { .. } => ConsensusRpcResponse::ClientBlocks(Vec::new()),
            ConsensusRpcRequest::RefresherRequest { bytes } => {
                self.refresher_requests.push_back(bytes);
                self.events.push_back(ServerEvent::RefresherRequest);
                ConsensusRpcResponse::Ack
            }
            ConsensusRpcRequest::NodeBootstrap { bytes } => ConsensusRpcResponse::Unknown { tag: 0, bytes },
            ConsensusRpcRequest::ExternalTx(tx) => {
                self.outbound_requests.push_back(OutboundRequest::ForwardExternalTx(tx));
                ConsensusRpcResponse::Ack
            }
            ConsensusRpcRequest::ConsensusMessage(msg) => {
                self.outbound_requests.push_back(OutboundRequest::ForwardConsensusMessage(msg));
                ConsensusRpcResponse::Ack
            }
            ConsensusRpcRequest::Unknown { tag, bytes } => {
                self.events.push_back(ServerEvent::DroppingTcpStream { peer, reason: "unknown consensus rpc request" });
                ConsensusRpcResponse::Unknown { tag, bytes }
            }
        }
    }

    fn node_consensus_server__drain_outbound_requests(&mut self, now: Instant) -> usize {
        let mut drained = 0;
        while let Some(request) = self.outbound_requests.pop_front() {
            if self.node_consensus_server__dispatch_consensus_outbound_request(request) {
                drained += 1;
            }
        }

        let mut pending = VecDeque::new();
        while let Some(lookup) = self.pending_node_ip_lookups.pop_front() {
            if self.node_consensus_server__poll_server_get_node_ip_connection(lookup.clone(), now).is_none() {
                pending.push_back(lookup);
            }
        }
        self.pending_node_ip_lookups = pending;

        drained
    }

    fn total_queued_work(&self) -> usize {
        self.inbound_tcp_streams.len()
            + self.outbound_requests.len()
            + self.pending_worker_responses.len()
            + self.refresher_responses.len()
            + self.forward_external_txs.len()
            + self.pending_node_ip_lookups.len()
    }
}

impl ConsensusRpcResponse {
    fn encoded_len_hint(&self) -> usize {
        match self {
            ConsensusRpcResponse::Peers(peers) => peers.len().saturating_mul(64),
            ConsensusRpcResponse::NodeIp(Some(_)) => 32,
            ConsensusRpcResponse::NodeIp(None) => 1,
            ConsensusRpcResponse::ClientBlocks(blocks) => blocks.iter().map(Vec::len).sum(),
            ConsensusRpcResponse::Ack => 1,
            ConsensusRpcResponse::Error(err) => err.len(),
            ConsensusRpcResponse::Unknown { bytes, .. } => bytes.len(),
        }
    }
}
