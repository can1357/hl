//! Reconstructed from `/home/ubuntu/hl/code_Mainnet/node/src/connections.rs`.
//!
//! Confidence: medium-high for connection-check ordering, rejection reasons,
//! peer-table updates, override-refresh/connect orchestration, listener/task
//! boundaries, literal log/error strings, and the peer cap. Medium for exact field
//! names and some async future layout names; those were recovered from
//! monomorphized poll functions rather than source metadata.
//!
//! Seed EAs expanded: `0x1FCFFF0`, `0x1FD1F70`, `0x1FD3EF0`, `0x1FD4230`,
//! `0x2033080`, `0x2035170`, `0x20367D0`, `0x203A190`, `0x203F3E0`,
//! `0x2041C60`, `0x225E3B0`, `0x225E860`, `0x2260FF0`, `0x22612D0`,
//! `0x22C0D30`, `0x22C15E0`, `0x45281C0`, `0x473F2E0`, `0x4740490`.
//!
//! IDA write plan from this reconstruction wave:
//! `node_connections__poll_connection_checks_{gossip,abci}`,
//! `node_connections__poll_handle_node_connection_{gossip,abci}`,
//! `node_connections__poll_accept_{gossip,abci}_stream_connections`,
//! `node_connections__write_connection_limit_error_{gossip,abci}`,
//! `node_connections__spawn_{gossip_rpc_request,gossip_stream,abci_stream_writer,gossip_stream_writer}`,
//! `node_connections__maybe_reject_peer_reason`,
//! `node_connections__update_and_get_overrides_with_file_tracker`, and
//! `node_connections__update_and_get_overrides_and_connect_peers`. The IDA
//! foreground queue rejected rename/comment/type calls while this file was
//! reconstructed, so the names above are recorded here for the next writable pass.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::sleep;

pub const MAX_GOSSIP_PEERS_HARD: usize = 100;
pub const DEFAULT_GOSSIP_PEERS: usize = 8;
pub const CONNECTION_LIMIT_CHECKS_ERROR: &str = "connection_limit_checks error";
pub const LOG_CONNECTION_CHECKS: &str = "connection_checks";
pub const LOG_HANDLE_NODE_CONNECTION: &str = "handle_node_connection";
pub const LOG_GOSSIP_RPC_REQUEST: &str = "gossip_rpc_request";
pub const LOG_VERIFY_RPC: &str = "verify_rpc";
pub const LOG_VERIFIED_GOSSIP_RPC: &str = "verified gossip rpc";
pub const LOG_SEND_ABCI_STATE: &str = "sending abci_state";
pub const LOG_SEND_ABCI_GREETING: &str = "send abci greeting";
pub const LOG_SEND_EVM_KVS: &str = "sending evm kvs";
pub const ROOT_CONNECT_RETRY: Duration = Duration::from_secs(10);
pub const PEER_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum NodeIp {
    Localhost,
    Ip(IpAddr),
}

impl NodeIp {
    #[inline]
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        Self::Ip(addr.ip()).canonicalize()
    }

    #[inline]
    pub fn canonicalize(self) -> Self {
        match self {
            Self::Ip(IpAddr::V4(ip)) if ip.is_loopback() => Self::Localhost,
            Self::Ip(IpAddr::V6(ip)) if ip.is_loopback() => Self::Localhost,
            other => other,
        }
    }

    #[inline]
    pub fn ip_addr(self) -> IpAddr {
        match self {
            Self::Localhost => IpAddr::V4(Ipv4Addr::LOCALHOST),
            Self::Ip(ip) => ip,
        }
    }

    #[inline]
    pub fn is_localhost(self) -> bool {
        matches!(self, Self::Localhost)
    }
}

impl fmt::Display for NodeIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Localhost => f.write_str("127.0.0.1"),
            Self::Ip(ip) => ip.fmt(f),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum ConnectionType {
    Gossip,
    Abci,
    Validator,
    Sentry,
}

impl ConnectionType {
    #[inline]
    pub fn accepts_abci(self) -> bool {
        matches!(self, Self::Abci | Self::Validator | Self::Sentry)
    }

    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gossip => "gossip",
            Self::Abci => "abci",
            Self::Validator => "validator",
            Self::Sentry => "sentry",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TcpGreeting {
    pub node_ip: NodeIp,
    pub connection_type: ConnectionType,
    pub verify_rpc: bool,
    pub request_abci_state: bool,
    pub request_evm_kvs: bool,
}

impl TcpGreeting {
    pub fn inferred_from_peer(peer_addr: SocketAddr, connection_type: ConnectionType) -> Self {
        Self {
            node_ip: NodeIp::from_socket_addr(peer_addr),
            connection_type,
            verify_rpc: true,
            request_abci_state: connection_type.accepts_abci(),
            request_evm_kvs: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AbciGreeting {
    pub node_ip: NodeIp,
    pub validator_index: Option<u32>,
    pub wants_state_snapshot: bool,
    pub wants_evm_kvs: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRole {
    Validator,
    Sentry,
    Reserved,
    PublicGossip,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectReason {
    NoQuorumYet,
    FailedToVerifyPeerRpc,
    AlreadyConnected,
    MaxPeersReached,
    NotValidatorOrSentry,
    AbciStateRequestRateLimited,
}

impl RejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoQuorumYet => "closing gossip stream because no quorum yet",
            Self::FailedToVerifyPeerRpc => "closing gossip stream because failed to verify peer rpc",
            Self::AlreadyConnected => "closing gossip stream because peer is already connected",
            Self::MaxPeersReached => "max peers reached",
            Self::NotValidatorOrSentry => "not validator or sentry",
            Self::AbciStateRequestRateLimited => "abci state request rate limited",
        }
    }
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub enum ConnectionError {
    Io(io::Error),
    Bincode(String),
    Rejected(RejectReason),
    Internal(&'static str),
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Bincode(error) => f.write_str(error),
            Self::Rejected(reason) => reason.fmt(f),
            Self::Internal(message) => f.write_str(message),
        }
    }
}

impl From<io::Error> for ConnectionError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Debug)]
pub struct PeerConnection {
    pub node_ip: NodeIp,
    pub peer_addr: SocketAddr,
    pub connection_type: ConnectionType,
    pub role: PeerRole,
    pub verified_rpc: bool,
    pub connected_at: Instant,
    pub last_rpc_at: Instant,
    pub requested_abci_state: bool,
    pub requested_evm_kvs: bool,
}

impl PeerConnection {
    fn new(peer_addr: SocketAddr, greeting: &TcpGreeting, role: PeerRole, verified_rpc: bool) -> Self {
        let now = Instant::now();
        Self {
            node_ip: greeting.node_ip.canonicalize(),
            peer_addr,
            connection_type: greeting.connection_type,
            role,
            verified_rpc,
            connected_at: now,
            last_rpc_at: now,
            requested_abci_state: greeting.request_abci_state,
            requested_evm_kvs: greeting.request_evm_kvs,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PeerSnapshot {
    pub node_ip: NodeIp,
    pub peer_addr: SocketAddr,
    pub connection_type: ConnectionType,
    pub role: PeerRole,
    pub verified_rpc: bool,
}

#[derive(Clone, Debug)]
pub struct GossipConfigInner {
    pub root_node_ips: Vec<NodeIp>,
    pub try_new_peers: bool,
    pub reserved_peer_ips: Vec<NodeIp>,
    pub n_gossip_peers: usize,
}

impl Default for GossipConfigInner {
    fn default() -> Self {
        Self {
            root_node_ips: Vec::new(),
            try_new_peers: false,
            reserved_peer_ips: Vec::new(),
            n_gossip_peers: DEFAULT_GOSSIP_PEERS,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GossipOverrideSnapshot {
    pub config: GossipConfigInner,
    pub loaded_at: SystemTime,
    pub update_elapsed_secs: f64,
    pub clone_elapsed_secs: f64,
}

#[derive(Debug)]
pub struct FileModTimeTracker<T> {
    pub path: PathBuf,
    pub last_value: Option<T>,
    pub last_modified: Option<SystemTime>,
    pub last_error: Option<String>,
}

impl<T> FileModTimeTracker<T> {
    pub fn new(path: PathBuf) -> Self {
        Self { path, last_value: None, last_modified: None, last_error: None }
    }
}

pub trait OverrideLoader<T> {
    fn load_if_modified(&mut self, tracker: &mut FileModTimeTracker<T>) -> Result<Option<T>, String>;
}

#[derive(Debug)]
pub struct PeerTable {
    peers: BTreeMap<NodeIp, PeerConnection>,
    validators: BTreeSet<NodeIp>,
    sentries: BTreeSet<NodeIp>,
    reserved: BTreeSet<NodeIp>,
    firewall_validators: BTreeSet<NodeIp>,
    pending_connects: HashSet<NodeIp>,
    max_gossip_peers: usize,
    has_quorum: bool,
    abci_state_rate_limiter: HashMap<NodeIp, Instant>,
}

impl PeerTable {
    pub fn new(max_gossip_peers: usize) -> Self {
        Self {
            peers: BTreeMap::new(),
            validators: BTreeSet::new(),
            sentries: BTreeSet::new(),
            reserved: BTreeSet::new(),
            firewall_validators: BTreeSet::new(),
            pending_connects: HashSet::new(),
            max_gossip_peers: max_gossip_peers.clamp(1, MAX_GOSSIP_PEERS_HARD),
            has_quorum: false,
            abci_state_rate_limiter: HashMap::new(),
        }
    }

    pub fn set_quorum(&mut self, has_quorum: bool) {
        self.has_quorum = has_quorum;
    }

    pub fn update_allowlists(
        &mut self,
        validators: impl IntoIterator<Item = NodeIp>,
        sentries: impl IntoIterator<Item = NodeIp>,
        reserved: impl IntoIterator<Item = NodeIp>,
        firewall_validators: impl IntoIterator<Item = NodeIp>,
    ) {
        self.validators = validators.into_iter().map(NodeIp::canonicalize).collect();
        self.sentries = sentries.into_iter().map(NodeIp::canonicalize).collect();
        self.reserved = reserved.into_iter().map(NodeIp::canonicalize).collect();
        self.firewall_validators = firewall_validators.into_iter().map(NodeIp::canonicalize).collect();
    }

    pub fn apply_gossip_config(&mut self, config: &GossipConfigInner) {
        self.reserved = config.reserved_peer_ips.iter().copied().map(NodeIp::canonicalize).collect();
        self.max_gossip_peers = config.n_gossip_peers.clamp(1, MAX_GOSSIP_PEERS_HARD);
    }

    #[inline]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn role_for(&self, node_ip: NodeIp) -> PeerRole {
        let node_ip = node_ip.canonicalize();
        if self.validators.contains(&node_ip) {
            PeerRole::Validator
        } else if self.sentries.contains(&node_ip) {
            PeerRole::Sentry
        } else if self.reserved.contains(&node_ip) {
            PeerRole::Reserved
        } else if !self.firewall_validators.contains(&node_ip) {
            PeerRole::PublicGossip
        } else {
            PeerRole::Unknown
        }
    }

    pub fn contains(&self, node_ip: NodeIp) -> bool {
        self.peers.contains_key(&node_ip.canonicalize())
    }

    pub fn maybe_reject_peer_reason(
        &mut self,
        node_ip: NodeIp,
        connection_type: ConnectionType,
        should_attempt_connect_on_peer_full: bool,
    ) -> Option<RejectReason> {
        let node_ip = node_ip.canonicalize();
        let role = self.role_for(node_ip);

        if !self.has_quorum && !node_ip.is_localhost() {
            return Some(RejectReason::NoQuorumYet);
        }

        if self.peers.contains_key(&node_ip) {
            return Some(RejectReason::AlreadyConnected);
        }

        if connection_type.accepts_abci() && !matches!(role, PeerRole::Validator | PeerRole::Sentry | PeerRole::Reserved) {
            return Some(RejectReason::NotValidatorOrSentry);
        }

        if !matches!(role, PeerRole::Validator | PeerRole::Sentry | PeerRole::Reserved) {
            let peer_full = self.peers.len() >= self.max_gossip_peers;
            if peer_full && !should_attempt_connect_on_peer_full {
                return Some(RejectReason::MaxPeersReached);
            }
        }

        None
    }

    pub fn check_abci_state_rate_limit(&mut self, node_ip: NodeIp, now: Instant) -> Result<(), RejectReason> {
        let node_ip = node_ip.canonicalize();
        if let Some(previous) = self.abci_state_rate_limiter.get(&node_ip) {
            if now.duration_since(*previous) < Duration::from_secs(1) {
                return Err(RejectReason::AbciStateRequestRateLimited);
            }
        }
        self.abci_state_rate_limiter.insert(node_ip, now);
        Ok(())
    }

    pub fn insert(&mut self, peer: PeerConnection) {
        self.pending_connects.remove(&peer.node_ip);
        self.peers.insert(peer.node_ip, peer);
    }

    pub fn remove(&mut self, node_ip: NodeIp) -> Option<PeerConnection> {
        self.peers.remove(&node_ip.canonicalize())
    }

    pub fn mark_pending_connect(&mut self, node_ip: NodeIp) -> bool {
        self.pending_connects.insert(node_ip.canonicalize())
    }

    pub fn clear_pending_connect(&mut self, node_ip: NodeIp) {
        self.pending_connects.remove(&node_ip.canonicalize());
    }

    pub fn snapshots(&self) -> Vec<PeerSnapshot> {
        self.peers
            .values()
            .map(|peer| PeerSnapshot {
                node_ip: peer.node_ip,
                peer_addr: peer.peer_addr,
                connection_type: peer.connection_type,
                role: peer.role,
                verified_rpc: peer.verified_rpc,
            })
            .collect()
    }

    pub fn expire_idle(&mut self, now: Instant) -> Vec<PeerConnection> {
        let expired: Vec<NodeIp> = self
            .peers
            .iter()
            .filter_map(|(node_ip, peer)| {
                (now.duration_since(peer.last_rpc_at) > PEER_IDLE_TIMEOUT).then_some(*node_ip)
            })
            .collect();
        expired.into_iter().filter_map(|node_ip| self.peers.remove(&node_ip)).collect()
    }
}

pub trait ConnectionIo {
    async fn read_tcp_greeting(&mut self) -> Result<TcpGreeting, ConnectionError>;
    async fn read_abci_greeting(&mut self) -> Result<AbciGreeting, ConnectionError>;
    async fn write_connection_limit_error(&mut self, reason: RejectReason) -> Result<(), ConnectionError>;
    async fn write_abci_greeting(&mut self, greeting: &AbciGreeting) -> Result<(), ConnectionError>;
    async fn write_abci_state(&mut self, state: &[u8]) -> Result<(), ConnectionError>;
    async fn write_evm_kvs_batch(&mut self, batch: &[u8]) -> Result<(), ConnectionError>;
    async fn shutdown(&mut self) -> Result<(), ConnectionError>;
}

pub trait RpcVerifier {
    async fn verify_rpc(&self, node_ip: NodeIp, io: &mut impl ConnectionIo) -> Result<bool, ConnectionError>;
}

pub trait AbciStateSource {
    async fn current_abci_greeting(&self) -> Result<AbciGreeting, ConnectionError>;
    async fn read_abci_state_snapshot(&self) -> Result<Vec<u8>, ConnectionError>;
    async fn read_evm_kvs_batch(&self) -> Result<Vec<u8>, ConnectionError>;
}

pub trait OutboundConnector {
    async fn connect_to_peer(&self, node_ip: NodeIp) -> Result<(), ConnectionError>;
}

#[derive(Debug)]
pub enum ConnectionCheck {
    Accepted(CheckedConnection),
    Rejected(RejectReason),
}

#[derive(Clone, Debug)]
pub struct CheckedConnection {
    pub peer_addr: SocketAddr,
    pub greeting: TcpGreeting,
    pub abci_greeting: Option<AbciGreeting>,
    pub role: PeerRole,
    pub verified_rpc: bool,
}

pub async fn connection_checks_gossip(
    table: &Arc<Mutex<PeerTable>>,
    peer_addr: SocketAddr,
    io: &mut impl ConnectionIo,
    verifier: &impl RpcVerifier,
) -> Result<ConnectionCheck, ConnectionError> {
    log_info(LOG_CONNECTION_CHECKS, "performing checks on stream");
    let greeting = io.read_tcp_greeting().await?;
    log_info(LOG_CONNECTION_CHECKS, "got tcp greeting");

    let node_ip = greeting.node_ip.canonicalize();
    {
        let mut locked = table.lock().expect("peer table lock poisoned");
        drop(locked.expire_idle(Instant::now()));
        if let Some(reason) = locked.maybe_reject_peer_reason(node_ip, ConnectionType::Gossip, false) {
            return Ok(ConnectionCheck::Rejected(reason));
        }
    }

    let verified_rpc = if greeting.verify_rpc {
        log_info(LOG_VERIFY_RPC, "verify_rpc");
        verifier.verify_rpc(node_ip, io).await?
    } else {
        false
    };

    if greeting.verify_rpc && !verified_rpc {
        return Ok(ConnectionCheck::Rejected(RejectReason::FailedToVerifyPeerRpc));
    }

    log_info(LOG_VERIFIED_GOSSIP_RPC, "verified gossip rpc");
    let role = table.lock().expect("peer table lock poisoned").role_for(node_ip);
    Ok(ConnectionCheck::Accepted(CheckedConnection {
        peer_addr,
        greeting,
        abci_greeting: None,
        role,
        verified_rpc,
    }))
}

pub async fn connection_checks_abci(
    table: &Arc<Mutex<PeerTable>>,
    peer_addr: SocketAddr,
    io: &mut impl ConnectionIo,
    verifier: &impl RpcVerifier,
) -> Result<ConnectionCheck, ConnectionError> {
    log_info(LOG_CONNECTION_CHECKS, "performing checks on stream");
    let greeting = io.read_tcp_greeting().await?;
    log_info(LOG_CONNECTION_CHECKS, "got tcp greeting");

    let node_ip = greeting.node_ip.canonicalize();
    {
        let mut locked = table.lock().expect("peer table lock poisoned");
        if let Some(reason) = locked.maybe_reject_peer_reason(node_ip, ConnectionType::Abci, false) {
            return Ok(ConnectionCheck::Rejected(reason));
        }
    }

    let verified_rpc = if greeting.verify_rpc {
        verifier.verify_rpc(node_ip, io).await?
    } else {
        false
    };
    if greeting.verify_rpc && !verified_rpc {
        return Ok(ConnectionCheck::Rejected(RejectReason::FailedToVerifyPeerRpc));
    }

    log_info(LOG_SEND_ABCI_GREETING, "abci_stream send tcp greeting");
    let abci_greeting = io.read_abci_greeting().await?;
    log_info(LOG_CONNECTION_CHECKS, "abci_stream recv greeting");

    let role = table.lock().expect("peer table lock poisoned").role_for(node_ip);
    Ok(ConnectionCheck::Accepted(CheckedConnection {
        peer_addr,
        greeting,
        abci_greeting: Some(abci_greeting),
        role,
        verified_rpc,
    }))
}

pub async fn handle_node_connection_gossip(
    table: Arc<Mutex<PeerTable>>,
    peer_addr: SocketAddr,
    io: &mut impl ConnectionIo,
    verifier: &impl RpcVerifier,
    state: &impl AbciStateSource,
) -> Result<(), ConnectionError> {
    let check = connection_checks_gossip(&table, peer_addr, io, verifier).await?;

    let checked = match check {
        ConnectionCheck::Rejected(reason) => {
            log_warn(LOG_CONNECTION_CHECKS, reason.as_str());
            io.write_connection_limit_error(reason).await?;
            return io.shutdown().await;
        }
        ConnectionCheck::Accepted(checked) => checked,
    };

    {
        let mut locked = table.lock().expect("peer table lock poisoned");
        if checked.greeting.request_abci_state {
            locked.check_abci_state_rate_limit(checked.greeting.node_ip, Instant::now())?;
        }
        locked.insert(PeerConnection::new(peer_addr, &checked.greeting, checked.role, checked.verified_rpc));
    }

    log_info(LOG_CONNECTION_CHECKS, "finished checks");
    if checked.greeting.request_abci_state {
        log_info(LOG_SEND_ABCI_STATE, "sending abci_state");
        let snapshot = state.read_abci_state_snapshot().await?;
        io.write_abci_state(&snapshot).await?;
        log_info(LOG_HANDLE_NODE_CONNECTION, "dropping connection after sending abci state");
        io.shutdown().await?;
    } else if checked.greeting.request_evm_kvs {
        log_info(LOG_SEND_EVM_KVS, "sending evm kvs");
        let batch = state.read_evm_kvs_batch().await?;
        io.write_evm_kvs_batch(&batch).await?;
    }

    Ok(())
}

pub async fn handle_node_connection_abci(
    table: Arc<Mutex<PeerTable>>,
    peer_addr: SocketAddr,
    io: &mut impl ConnectionIo,
    verifier: &impl RpcVerifier,
    state: &impl AbciStateSource,
) -> Result<(), ConnectionError> {
    let check = connection_checks_abci(&table, peer_addr, io, verifier).await?;

    let checked = match check {
        ConnectionCheck::Rejected(reason) => {
            log_warn(LOG_CONNECTION_CHECKS, reason.as_str());
            io.write_connection_limit_error(reason).await?;
            return io.shutdown().await;
        }
        ConnectionCheck::Accepted(checked) => checked,
    };

    let abci_greeting = state.current_abci_greeting().await?;
    log_info(LOG_SEND_ABCI_GREETING, "send abci greeting");
    io.write_abci_greeting(&abci_greeting).await?;

    {
        let mut locked = table.lock().expect("peer table lock poisoned");
        if checked.greeting.request_abci_state {
            locked.check_abci_state_rate_limit(checked.greeting.node_ip, Instant::now())?;
        }
        locked.insert(PeerConnection::new(peer_addr, &checked.greeting, checked.role, checked.verified_rpc));
    }

    if checked.greeting.request_abci_state {
        log_info(LOG_SEND_ABCI_STATE, "sending abci_state");
        let snapshot = state.read_abci_state_snapshot().await?;
        if let Err(error) = io.write_abci_state(&snapshot).await {
            log_warn(LOG_HANDLE_NODE_CONNECTION, "could not send abci_state");
            return Err(error);
        }
        log_info(LOG_HANDLE_NODE_CONNECTION, "successfully sent abci_state");
    }

    if checked.greeting.request_evm_kvs || checked.abci_greeting.as_ref().is_some_and(|g| g.wants_evm_kvs) {
        log_info(LOG_SEND_EVM_KVS, "sending evm kvs");
        let batch = state.read_evm_kvs_batch().await?;
        io.write_evm_kvs_batch(&batch).await?;
    }

    Ok(())
}

pub async fn write_connection_limit_error_gossip(io: &mut impl ConnectionIo, reason: RejectReason) -> Result<(), ConnectionError> {
    log_warn(LOG_CONNECTION_CHECKS, CONNECTION_LIMIT_CHECKS_ERROR);
    io.write_connection_limit_error(reason).await
}

pub async fn write_connection_limit_error_abci(io: &mut impl ConnectionIo, reason: RejectReason) -> Result<(), ConnectionError> {
    log_warn(LOG_CONNECTION_CHECKS, CONNECTION_LIMIT_CHECKS_ERROR);
    io.write_connection_limit_error(reason).await
}

pub trait TcpStreamFactory<Io> {
    fn wrap(&self, stream: TcpStream, peer_addr: SocketAddr) -> Io;
}

pub async fn accept_gossip_stream_connections<Io, Factory, Verifier, State>(
    listener: TcpListener,
    table: Arc<Mutex<PeerTable>>,
    factory: Factory,
    verifier: Arc<Verifier>,
    state: Arc<State>,
) -> Result<(), ConnectionError>
where
    Io: ConnectionIo + Send + 'static,
    Factory: TcpStreamFactory<Io> + Send + Sync + 'static,
    Verifier: RpcVerifier + Send + Sync + 'static,
    State: AbciStateSource + Send + Sync + 'static,
{
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let mut io = factory.wrap(stream, peer_addr);
        let peer_table = Arc::clone(&table);
        let verifier = Arc::clone(&verifier);
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(error) = handle_node_connection_gossip(peer_table, peer_addr, &mut io, verifier.as_ref(), state.as_ref()).await {
                log_warn(LOG_HANDLE_NODE_CONNECTION, &format!("dropping connection: {error}"));
            }
        });
    }
}

pub async fn accept_abci_stream_connections<Io, Factory, Verifier, State>(
    listener: TcpListener,
    table: Arc<Mutex<PeerTable>>,
    factory: Factory,
    verifier: Arc<Verifier>,
    state: Arc<State>,
) -> Result<(), ConnectionError>
where
    Io: ConnectionIo + Send + 'static,
    Factory: TcpStreamFactory<Io> + Send + Sync + 'static,
    Verifier: RpcVerifier + Send + Sync + 'static,
    State: AbciStateSource + Send + Sync + 'static,
{
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let mut io = factory.wrap(stream, peer_addr);
        let peer_table = Arc::clone(&table);
        let verifier = Arc::clone(&verifier);
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(error) = handle_node_connection_abci(peer_table, peer_addr, &mut io, verifier.as_ref(), state.as_ref()).await {
                log_warn(LOG_HANDLE_NODE_CONNECTION, &format!("dropping connection: {error}"));
            }
        });
    }
}

#[derive(Clone, Debug)]
pub struct ConnectPeerState {
    pub node_ip: NodeIp,
    pub last_attempt: Option<Instant>,
    pub failures: u32,
    pub in_flight: bool,
}

impl ConnectPeerState {
    fn should_attempt(&self, now: Instant) -> bool {
        if self.in_flight {
            return false;
        }
        let Some(last_attempt) = self.last_attempt else {
            return true;
        };
        let exponent = self.failures.min(6);
        let backoff = ROOT_CONNECT_RETRY.saturating_mul(1_u32 << exponent);
        now.duration_since(last_attempt) >= backoff
    }

    fn mark_attempt(&mut self, now: Instant) {
        self.last_attempt = Some(now);
        self.in_flight = true;
    }

    fn mark_finished(&mut self, success: bool) {
        self.in_flight = false;
        self.failures = if success { 0 } else { self.failures.saturating_add(1) };
    }
}

#[derive(Debug)]
pub struct ConnectionOrchestrator<C> {
    peer_table: Arc<Mutex<PeerTable>>,
    connector: Arc<C>,
    connect_states: BTreeMap<NodeIp, ConnectPeerState>,
    recent_roots: VecDeque<NodeIp>,
}

impl<C> ConnectionOrchestrator<C>
where
    C: OutboundConnector + Send + Sync + 'static,
{
    pub fn new(peer_table: Arc<Mutex<PeerTable>>, connector: Arc<C>) -> Self {
        Self {
            peer_table,
            connector,
            connect_states: BTreeMap::new(),
            recent_roots: VecDeque::new(),
        }
    }

    pub fn update_and_get_overrides_with_file_tracker<L>(
        &mut self,
        loader: &mut L,
        tracker: &mut FileModTimeTracker<GossipConfigInner>,
        force_include_current: bool,
    ) -> Result<Option<GossipOverrideSnapshot>, String>
    where
        L: OverrideLoader<GossipConfigInner>,
    {
        let update_started = Instant::now();
        let loaded = loader.load_if_modified(tracker)?;
        let update_elapsed_secs = update_started.elapsed().as_secs_f64();

        if let Some(config) = loaded {
            tracker.last_value = Some(config);
            tracker.last_modified = Some(SystemTime::now());
            tracker.last_error = None;
        } else if tracker.last_error.is_some() {
            log_warn("update_and_get_overrides", "(Last load of FileModTimeTracker failed:");
        }

        if !force_include_current && loaded_is_empty(&tracker.last_value) {
            return Ok(None);
        }

        let clone_started = Instant::now();
        let Some(config) = tracker.last_value.clone() else {
            return Ok(None);
        };
        let clone_elapsed_secs = clone_started.elapsed().as_secs_f64();

        Ok(Some(GossipOverrideSnapshot {
            config,
            loaded_at: tracker.last_modified.unwrap_or_else(SystemTime::now),
            update_elapsed_secs,
            clone_elapsed_secs,
        }))
    }

    pub async fn update_and_get_overrides_and_connect_peers<L>(
        &mut self,
        loader: &mut L,
        tracker: &mut FileModTimeTracker<GossipConfigInner>,
        force_include_current: bool,
    ) -> Result<Vec<JoinHandle<()>>, ConnectionError>
    where
        L: OverrideLoader<GossipConfigInner>,
    {
        let snapshot = self
            .update_and_get_overrides_with_file_tracker(loader, tracker, force_include_current)
            .map_err(ConnectionError::Bincode)?;
        let Some(snapshot) = snapshot else {
            return Ok(Vec::new());
        };

        {
            let mut table = self.peer_table.lock().expect("peer table lock poisoned");
            table.apply_gossip_config(&snapshot.config);
        }

        let now = Instant::now();
        let candidates = self.dedup_connect_candidates(&snapshot.config);
        let mut tasks = Vec::new();

        for node_ip in candidates {
            if !self.should_schedule_connect(node_ip, now) {
                continue;
            }

            let connector = Arc::clone(&self.connector);
            let table = Arc::clone(&self.peer_table);
            tasks.push(tokio::spawn(async move {
                let result = connector.connect_to_peer(node_ip).await;
                let mut locked = table.lock().expect("peer table lock poisoned");
                locked.clear_pending_connect(node_ip);
                if let Err(error) = result {
                    log_warn("gossip_server_connect_to_peer", &format!("connect failed for {node_ip}: {error}"));
                }
            }));
        }

        Ok(tasks)
    }

    fn dedup_connect_candidates(&mut self, config: &GossipConfigInner) -> Vec<NodeIp> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();

        for node_ip in config.root_node_ips.iter().chain(config.reserved_peer_ips.iter()) {
            let node_ip = node_ip.canonicalize();
            if seen.insert(node_ip) {
                out.push(node_ip);
                self.recent_roots.push_back(node_ip);
            }
        }

        if config.try_new_peers {
            let snapshots = self.peer_table.lock().expect("peer table lock poisoned").snapshots();
            for peer in snapshots {
                if seen.insert(peer.node_ip) {
                    out.push(peer.node_ip);
                }
            }
        }

        while self.recent_roots.len() > MAX_GOSSIP_PEERS_HARD {
            self.recent_roots.pop_front();
        }

        out
    }

    fn should_schedule_connect(&mut self, node_ip: NodeIp, now: Instant) -> bool {
        let mut table = self.peer_table.lock().expect("peer table lock poisoned");
        if table.contains(node_ip) || !table.mark_pending_connect(node_ip) {
            return false;
        }
        drop(table);

        let state = self.connect_states.entry(node_ip).or_insert(ConnectPeerState {
            node_ip,
            last_attempt: None,
            failures: 0,
            in_flight: false,
        });

        if state.should_attempt(now) {
            state.mark_attempt(now);
            true
        } else {
            self.peer_table.lock().expect("peer table lock poisoned").clear_pending_connect(node_ip);
            false
        }
    }

    pub fn mark_connect_finished(&mut self, node_ip: NodeIp, success: bool) {
        if let Some(state) = self.connect_states.get_mut(&node_ip.canonicalize()) {
            state.mark_finished(success);
        }
    }
}

fn loaded_is_empty(value: &Option<GossipConfigInner>) -> bool {
    value
        .as_ref()
        .is_none_or(|config| config.root_node_ips.is_empty() && config.reserved_peer_ips.is_empty())
}

pub fn spawn_gossip_rpc_request_task<F>(task: F) -> JoinHandle<()>
where
    F: Send + 'static + FnOnce(),
{
    tokio::spawn(async move {
        log_info(LOG_GOSSIP_RPC_REQUEST, "send gossip rpc request");
        task();
    })
}

pub fn spawn_gossip_stream_task<F>(task: F) -> JoinHandle<()>
where
    F: Send + 'static + FnOnce(),
{
    tokio::spawn(async move {
        log_info("node_stream_connection", "gossip_rpc_request");
        task();
    })
}

pub fn spawn_abci_stream_writer<F>(task: F) -> JoinHandle<()>
where
    F: Send + 'static + FnOnce(),
{
    tokio::spawn(async move {
        log_info("abci_stream", "node_stream_connection");
        task();
    })
}

pub fn spawn_gossip_stream_writer<F>(task: F) -> JoinHandle<()>
where
    F: Send + 'static + FnOnce(),
{
    tokio::spawn(async move {
        log_info("gossip_stream", "node_stream_connection");
        task();
    })
}

pub fn compact_node_ip_from_greeting(tag_and_ip: u64) -> NodeIp {
    if (tag_and_ip & 1) != 0 {
        return NodeIp::Localhost;
    }
    let raw = (tag_and_ip >> 8) as u32;
    NodeIp::Ip(IpAddr::V4(Ipv4Addr::from(raw.to_be_bytes()))).canonicalize()
}

pub fn log_rejecting_stream(peer: SocketAddr, connection_type: ConnectionType, reason: RejectReason) {
    log_warn(
        "rejecting stream",
        &format!(
            "@@ rejecting stream @@ [ip: {peer}] @ [connection_type: {}] @ [reason.as_str(): {}]",
            connection_type.as_str(),
            reason.as_str(),
        ),
    );
}

fn log_info(target: &str, message: &str) {
    eprintln!(" INFO {target}: {message}");
}

fn log_warn(target: &str, message: &str) {
    eprintln!(" WARN >>> {target} {message}");
}
