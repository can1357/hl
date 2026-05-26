//! Reconstructed from `/home/ubuntu/hl/code_Mainnet/node/src/gossip_config.rs`.
//!
//! Confidence: high for the JSON schema, override filename, missing-override
//! fallback roots for non-mainnet chains, root/reserved peer normalization,
//! non-empty root assertion, chain check, `n_gossip_peers` zero rejection, and
//! `split_client_blocks` propagation. Medium for the helper/type boundaries.
//!
//! Seed EAs from `recon/_meta/path_to_funcs.json`:
//! `0x22615B0`, `0x227A0E0`, `0x4356C90`, `0x439BAF0`, `0x4741210`,
//! `0x4741DC0`, `0x4743490`, `0x4744160`, `0x4759970`, `0x4B29760`,
//! `0x4B3C880`.
//!
//! Local anchors used:
//! - manifest `recon/manifest/code_Mainnet__node__src__gossip_config.json`;
//! - `bin/override_gossip_config.mainnet.json`, whose wire shape has all six
//!   `GossipConfigInner` fields and tagged node IPs such as `{ "Ip": "..." }`;
//! - startup/runtime reconstructions that already carried the recovered strings
//!   `override_gossip_config.json`, `assertion failed: !res.read().root_node_ips.is_empty()`,
//!   `n_gossip_peers clipped to`, `non-testing local chain`, and the file-tracker
//!   update/error labels;
//! - re-decompile of `0x4741DC0`, which showed missing-file fallback roots packed
//!   as 5-byte `NodeIp` records: `54.95.235.126`, `13.231.133.202`, and
//!   `54.249.160.165`.
//!
//! IDA applied: renamed/commented `0x4741DC0` as
//! `node_gossip_config__load_override_gossip_config`, `0x4741210` as
//! `node_gossip_config__update_file_mod_time_tracker_override`, `0x4743490` as
//! `node_gossip_config__apply_runtime_gossip_config`, and `0x4744160` as
//! `node_gossip_config__validate_non_testing_local_chain`; declared `hl_node_NodeIp`,
//! `hl_node_Chain`, `hl_rust_Vec_NodeIp`, and `hl_node_GossipConfigInner`; applied
//! corrected loader type `void(out, uint8 expected_chain, const void *data_dir_path)`
//! and re-decompiled it.
//!
//! IDA pending:
//! - Type signatures for `0x4741210`, `0x4743490`, and `0x4744160` still need
//!   decompile-confirmed parameters before `apply_types`.
//! - `0x22615B0` -> `node_gossip_config__sub_serde_gossip_config_inner`; comment pending
//!   decompile confirmation of the generated serde visitor/default branch.
//! - `0x227A0E0` -> `node_gossip_config__sub_bootstrap_config_setup`; comment pending
//!   decompile confirmation because local reconstructions also associate this EA
//!   with nv-stream bootstrap setup.
//! - `0x4356C90` -> `node_gossip_config__sub_serde_node_ip_or_field`; comment pending
//!   decompile confirmation of the generated `NodeIp`/field visitor role.
//! - `0x439BAF0` -> `node_gossip_config__poll_root_peer_bootstrap`; comment:
//!   `/home/ubuntu/hl/code_Mainnet/node/src/gossip_config.rs :: root peer bootstrap poll — refreshes override config, logs root node IPs, connects to ABCI stream, saves initial local ABCI state, and retries roots on failure`.
//! - `0x4759970` -> `node_nv_stream__poll_run_nv_stream`; foreign consumer in
//!   `node/src/nv_stream.rs`, included here because it consumes `split_client_blocks`
//!   and the loaded startup config.
//! - `0x4B29760` -> `node_gossip_config__sub_runtime_peer_rpc_consumer`; comment
//!   pending decompile confirmation; observed string cluster consumes gossip server,
//!   firewall IPs, peer RPC, ABCI stream, and candidate-peer greeting checks.
//! - `0x4B3C880` -> `node_gossip_config__sub_node_bootstrap_dispatch`; comment
//!   pending decompile confirmation; local disassembly shows calls to `0x4741210`
//!   and `0x4B29760` from a node-bootstrap dispatch/drop-glue state machine.

#![allow(dead_code)]

use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

pub const DATA_DIR: &str = "/hyperliquid_data";
pub const OVERRIDE_GOSSIP_CONFIG_FLN: &str = "override_gossip_config.json";
pub const DEFAULT_RUNTIME_GOSSIP_PEERS: usize = 8;
pub const DEFAULT_MAINNET_GOSSIP_PEERS: usize = 16;
pub const MAX_GOSSIP_PEERS_HARD: usize = 100;
pub const ROOT_CONNECT_RETRY: Duration = Duration::from_secs(10);
pub const SANDBOX_FALLBACK_ROOTS: &[[u8; 4]] = &[[54, 95, 235, 126]];
pub const TESTNET_FALLBACK_ROOTS: &[[u8; 4]] = &[[13, 231, 133, 202], [54, 249, 160, 165]];


/// Global chain enum used by config JSON.
///
/// Binary metadata exposes `Local`, `Sandbox`, `Testnet`, and `Mainnet` for the
/// broader `HlChain`; the startup reconstructions only exercised Mainnet,
/// Testnet, and Local in this file's callers. Keeping Sandbox here preserves the
/// recovered global chain surface without inventing a separate type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Chain {
    Local,
    Sandbox,
    Testnet,
    Mainnet,
}

impl Chain {
    #[inline]
    pub fn is_testing(self) -> bool {
        !matches!(self, Self::Mainnet)
    }

    #[inline]
    pub fn default_runtime_peer_count(self) -> usize {
        match self {
            Self::Mainnet => DEFAULT_MAINNET_GOSSIP_PEERS,
            Self::Local | Self::Sandbox | Self::Testnet => DEFAULT_RUNTIME_GOSSIP_PEERS,
        }
    }
}

impl FromStr for Chain {
    type Err = ChainParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "Local" => Ok(Self::Local),
            "Sandbox" => Ok(Self::Sandbox),
            "Testnet" => Ok(Self::Testnet),
            "Mainnet" => Ok(Self::Mainnet),
            other => Err(ChainParseError { value: other.to_owned() }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainParseError {
    pub value: String,
}

impl fmt::Display for ChainParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown chain `{}`", self.value)
    }
}

impl std::error::Error for ChainParseError {}

/// Node-IP wire enum.
///
/// Serde's externally tagged representation for `NodeIp::Ip(addr)` is exactly
/// `{ "Ip": "x.x.x.x" }`, matching the captured mainnet override. Loopback
/// addresses are canonicalized to the unit variant before runtime comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum NodeIp {
    Localhost,
    Ip(IpAddr),
}

impl NodeIp {
    #[inline]
    pub fn new(ip: IpAddr) -> Self {
        Self::Ip(ip).canonicalize()
    }

    #[inline]
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        Self::new(addr.ip())
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

/// Override-file schema.
///
/// The override parser uses this type without `serde(default)`: missing fields
/// are JSON parse errors. A separate `runtime_default` constructor below models
/// the connection-layer empty default observed in local reconstructions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GossipConfigInner {
    pub root_node_ips: Vec<NodeIp>,
    pub try_new_peers: bool,
    pub chain: Chain,
    pub reserved_peer_ips: Vec<NodeIp>,
    pub n_gossip_peers: usize,
    pub split_client_blocks: bool,
}

impl GossipConfigInner {
    pub fn runtime_default(chain: Chain) -> Self {
        Self {
            root_node_ips: Vec::new(),
            try_new_peers: false,
            chain,
            reserved_peer_ips: Vec::new(),
            n_gossip_peers: chain.default_runtime_peer_count(),
            split_client_blocks: false,
        }
    }

    /// Built when `override_gossip_config.json` is absent for the non-mainnet
    /// chain discriminants that carry compiled fallback roots. Re-decompile of
    /// `0x4741DC0` shows the peer count field initialized to `1` in this path.
    pub fn missing_override_default(chain: Chain) -> Option<Self> {
        let roots = default_root_node_ips_for_chain(chain);
        if roots.is_empty() {
            return None;
        }

        Some(Self {
            n_gossip_peers: 1,
            root_node_ips: roots,
            try_new_peers: false,
            chain,
            reserved_peer_ips: Vec::new(),
            split_client_blocks: false,
        })
    }

    pub fn normalize(mut self, expected_chain: Chain) -> Result<NormalizedGossipConfig, GossipConfigError> {
        if self.chain != expected_chain {
            return Err(GossipConfigError::UnsupportedChain {
                configured: self.chain,
                expected: expected_chain,
            });
        }
        if self.root_node_ips.is_empty() {
            return Err(GossipConfigError::EmptyRootNodeIps);
        }
        if self.n_gossip_peers == 0 {
            return Err(GossipConfigError::InvalidGossipPeerCount { configured: 0 });
        }

        canonicalize_and_dedup(&mut self.root_node_ips);
        canonicalize_and_dedup_reserved(&self.root_node_ips, &mut self.reserved_peer_ips);

        let mut connect_candidates = Vec::with_capacity(self.root_node_ips.len() + self.reserved_peer_ips.len());
        connect_candidates.extend(self.root_node_ips.iter().copied());
        connect_candidates.extend(self.reserved_peer_ips.iter().copied());

        let requested = self.n_gossip_peers;
        let clipped = requested.min(connect_candidates.len().max(1));
        let clipped_peer_count = if clipped == requested { None } else { Some(clipped) };
        if let Some(clipped) = clipped_peer_count {
            self.n_gossip_peers = clipped;
        }

        Ok(NormalizedGossipConfig {
            inner: self,
            connect_candidates,
            requested_peer_count: requested,
            clipped_peer_count,
        })
    }

    pub fn reserved_peer_set(&self) -> BTreeSet<NodeIp> {
        self.reserved_peer_ips.iter().copied().map(NodeIp::canonicalize).collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedGossipConfig {
    pub inner: GossipConfigInner,
    /// Root peers followed by reserved peers after canonicalization and dedupe.
    pub connect_candidates: Vec<NodeIp>,
    pub requested_peer_count: usize,
    /// `Some` when the recovered `n_gossip_peers clipped to` branch fired.
    pub clipped_peer_count: Option<usize>,
}

impl NormalizedGossipConfig {
    #[inline]
    pub fn n_gossip_peers(&self) -> usize {
        self.inner.n_gossip_peers
    }

    #[inline]
    pub fn split_client_blocks(&self) -> bool {
        self.inner.split_client_blocks
    }

    pub fn effective_peer_limit(&self) -> usize {
        self.inner.n_gossip_peers.clamp(1, MAX_GOSSIP_PEERS_HARD)
    }

    pub fn reserved_peer_set(&self) -> BTreeSet<NodeIp> {
        self.inner.reserved_peer_set()
    }

    /// Runtime peer-connection ordering observed in the root-peer/connect logic:
    /// configured roots first, configured reserved peers second, and only when
    /// `try_new_peers` is true, current peer snapshots after those lists.
    pub fn runtime_connect_candidates<'a>(&self, current_peers: impl IntoIterator<Item = &'a PeerSnapshot>) -> Vec<NodeIp> {
        let mut current_peers = current_peers.into_iter();
        let extra = if self.inner.try_new_peers { current_peers.size_hint().0 } else { 0 };
        let mut out = Vec::with_capacity(self.connect_candidates.len() + extra);
        let mut seen = HashSet::new();

        for peer in self.connect_candidates.iter().copied() {
            push_unique_peer(&mut out, &mut seen, peer);
        }
        if self.inner.try_new_peers {
            for peer in current_peers {
                push_unique_peer(&mut out, &mut seen, peer.node_ip);
            }
        }
        out
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerSnapshot {
    pub node_ip: NodeIp,
    pub role: PeerRole,
    pub verified_rpc: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRole {
    Validator,
    Sentry,
    Reserved,
    PublicGossip,
    Unknown,
}

impl PeerRole {
    #[inline]
    pub fn bypasses_public_peer_limit(self) -> bool {
        matches!(self, Self::Validator | Self::Sentry | Self::Reserved)
    }
}

#[derive(Clone, Debug)]
pub struct GossipRuntimeConfig {
    pub chain: Chain,
    pub root_node_ips: Vec<NodeIp>,
    pub reserved_peer_ips: Vec<NodeIp>,
    pub try_new_peers: bool,
    pub max_gossip_peers: usize,
    pub split_client_blocks: bool,
}

impl From<NormalizedGossipConfig> for GossipRuntimeConfig {
    fn from(config: NormalizedGossipConfig) -> Self {
        let max_gossip_peers = config.effective_peer_limit();
        let inner = config.inner;
        Self {
            chain: inner.chain,
            root_node_ips: inner.root_node_ips,
            reserved_peer_ips: inner.reserved_peer_ips,
            try_new_peers: inner.try_new_peers,
            max_gossip_peers,
            split_client_blocks: inner.split_client_blocks,
        }
    }
}

#[derive(Debug)]
pub enum GossipConfigError {
    Io { path: PathBuf, source: io::Error },
    Json { path: PathBuf, source: serde_json::Error },
    UnsupportedChain { configured: Chain, expected: Chain },
    EmptyRootNodeIps,
    InvalidGossipPeerCount { configured: usize },
    Metadata { path: PathBuf, source: io::Error },
}

impl fmt::Display for GossipConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "could not load file `{}`: {source}", path.display()),
            Self::Json { path, source } => write!(f, "could not parse json `{}`: {source}", path.display()),
            Self::UnsupportedChain { configured, expected } => {
                write!(f, "unsupported chain: config={configured:?}, expected={expected:?}")
            }
            Self::EmptyRootNodeIps => f.write_str("assertion failed: !res.read().root_node_ips.is_empty()"),
            Self::InvalidGossipPeerCount { configured } => write!(f, "invalid n_gossip_peers={configured}"),
            Self::Metadata { path, source } => write!(f, "could not stat file `{}`: {source}", path.display()),
        }
    }
}

impl std::error::Error for GossipConfigError {}

pub fn override_gossip_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(OVERRIDE_GOSSIP_CONFIG_FLN)
}

pub fn load_override_gossip_config(data_dir: &Path, expected_chain: Chain) -> Result<NormalizedGossipConfig, GossipConfigError> {
    let path = override_gossip_config_path(data_dir);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return missing_override_gossip_config(path.clone(), expected_chain);
        }
        Err(source) => return Err(GossipConfigError::Io { path: path.clone(), source }),
    };
    parse_override_gossip_config(&path, &bytes, expected_chain)
}

pub fn parse_override_gossip_config(
    path: &Path,
    bytes: &[u8],
    expected_chain: Chain,
) -> Result<NormalizedGossipConfig, GossipConfigError> {
    let inner = serde_json::from_slice::<GossipConfigInner>(bytes)
        .map_err(|source| GossipConfigError::Json { path: path.to_path_buf(), source })?;
    inner.normalize(expected_chain)
}
pub fn missing_override_gossip_config(path: PathBuf, expected_chain: Chain) -> Result<NormalizedGossipConfig, GossipConfigError> {
    match GossipConfigInner::missing_override_default(expected_chain) {
        Some(inner) => inner.normalize(expected_chain),
        None => Err(GossipConfigError::Io {
            path,
            source: io::Error::new(io::ErrorKind::NotFound, OVERRIDE_GOSSIP_CONFIG_FLN),
        }),
    }
}

pub fn default_root_node_ips_for_chain(chain: Chain) -> Vec<NodeIp> {
    let roots = match chain {
        Chain::Sandbox => SANDBOX_FALLBACK_ROOTS,
        Chain::Testnet => TESTNET_FALLBACK_ROOTS,
        Chain::Local | Chain::Mainnet => &[],
    };

    roots
        .iter()
        .copied()
        .map(|octets| NodeIp::Ip(IpAddr::from(octets)).canonicalize())
        .collect()
}

/// File-modification tracker used by the runtime override refresh path.
#[derive(Debug)]
pub struct FileModTimeTracker<T> {
    pub path: PathBuf,
    pub last_modified: Option<SystemTime>,
    pub last_value: Option<T>,
    pub last_error: Option<String>,
}

impl<T> FileModTimeTracker<T> {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            last_modified: None,
            last_value: None,
            last_error: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileTrackerUpdate<T> {
    Unchanged,
    Updated(T),
}

pub fn update_gossip_config_from_tracker(
    tracker: &mut FileModTimeTracker<NormalizedGossipConfig>,
    expected_chain: Chain,
) -> Result<FileTrackerUpdate<NormalizedGossipConfig>, GossipConfigError> {
    let metadata = fs::metadata(&tracker.path)
        .map_err(|source| GossipConfigError::Metadata { path: tracker.path.clone(), source })?;
    let modified = metadata
        .modified()
        .map_err(|source| GossipConfigError::Metadata { path: tracker.path.clone(), source })?;

    if tracker.last_modified == Some(modified) {
        return Ok(FileTrackerUpdate::Unchanged);
    }

    let bytes = fs::read(&tracker.path)
        .map_err(|source| GossipConfigError::Io { path: tracker.path.clone(), source })?;
    let config = parse_override_gossip_config(&tracker.path, &bytes, expected_chain)?;
    tracker.last_modified = Some(modified);
    tracker.last_value = Some(config.clone());
    tracker.last_error = None;
    Ok(FileTrackerUpdate::Updated(config))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GossipStatus {
    pub initial_height: u64,
    pub latest_height: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalAbciStateHeader {
    pub height: u64,
    pub node_ips: Vec<IpAddr>,
}

/// Recovered non-testing-chain guard for reusing a local ABCI state.
///
/// Testing chains accept a non-empty local state immediately. Mainnet requires
/// the machine's public IP, a configured root IP, or a configured reserved IP to
/// be present in the state header. Without public IP evidence it falls back to
/// requiring at least one configured root peer in the state header.
pub fn local_abci_state_matches_gossip_config(
    state: &LocalAbciStateHeader,
    config: &GossipConfigInner,
    public_ip: Option<IpAddr>,
) -> bool {
    if state.height == 0 || state.node_ips.is_empty() {
        return false;
    }
    if config.chain.is_testing() {
        return true;
    }

    if let Some(public_ip) = public_ip {
        state.node_ips.contains(&public_ip)
            || config.root_node_ips.iter().any(|ip| (*ip).ip_addr() == public_ip)
            || config.reserved_peer_ips.iter().any(|ip| (*ip).ip_addr() == public_ip)
    } else {
        config.root_node_ips.iter().any(|ip| state.node_ips.contains(&(*ip).ip_addr()))
    }
}

pub fn choose_bootstrap_root_peer<'a>(
    roots: impl IntoIterator<Item = &'a NodeIp>,
    mut status_for: impl FnMut(NodeIp) -> Option<GossipStatus>,
) -> Option<(NodeIp, GossipStatus)> {
    let mut first = None;
    let mut best = None;

    for root in roots {
        let root = (*root).canonicalize();
        if first.is_none() {
            first = Some(root);
        }
        if let Some(status) = status_for(root) {
            match best {
                None => best = Some((root, status)),
                Some((_, best_status)) if status.latest_height >= best_status.latest_height => best = Some((root, status)),
                Some(_) => {}
            }
        }
    }

    best.or_else(|| first.map(|root| (root, GossipStatus::default())))
}

pub fn slow_abci_services_split_client_blocks(config: &GossipRuntimeConfig) -> bool {
    config.split_client_blocks
}

pub fn mainnet_override_roots_observed_in_local_artifact() -> Vec<NodeIp> {
    const ROOTS: [[u8; 4]; 24] = [
        [54, 249, 65, 184],
        [54, 199, 122, 133],
        [54, 95, 224, 41],
        [35, 79, 111, 183],
        [18, 178, 246, 130],
        [18, 180, 228, 50],
        [52, 198, 4, 11],
        [13, 158, 244, 192],
        [35, 72, 88, 240],
        [35, 190, 230, 32],
        [35, 77, 205, 141],
        [52, 193, 46, 25],
        [54, 168, 150, 28],
        [45, 76, 206, 35],
        [57, 181, 193, 239],
        [54, 238, 174, 48],
        [116, 199, 229, 233],
        [64, 31, 51, 130],
        [35, 79, 116, 97],
        [54, 64, 2, 87],
        [13, 159, 221, 161],
        [18, 181, 155, 57],
        [218, 33, 8, 227],
        [52, 193, 108, 65],
    ];

    ROOTS
        .iter()
        .copied()
        .map(|octets| NodeIp::Ip(IpAddr::from(octets)))
        .collect()
}

fn canonicalize_and_dedup(peers: &mut Vec<NodeIp>) {
    let mut seen = HashSet::new();
    peers.retain_mut(|peer| {
        *peer = (*peer).canonicalize();
        seen.insert(*peer)
    });
}

fn canonicalize_and_dedup_reserved(roots: &[NodeIp], reserved: &mut Vec<NodeIp>) {
    let mut seen = HashSet::with_capacity(roots.len() + reserved.len());
    seen.extend(roots.iter().copied().map(NodeIp::canonicalize));
    reserved.retain_mut(|peer| {
        *peer = (*peer).canonicalize();
        seen.insert(*peer)
    });
}

fn push_unique_peer(out: &mut Vec<NodeIp>, seen: &mut HashSet<NodeIp>, peer: NodeIp) {
    let peer = peer.canonicalize();
    if seen.insert(peer) {
        out.push(peer);
    }
}
