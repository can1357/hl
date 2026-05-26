//! Reconstructed from `/home/ubuntu/hl/code_Mainnet/node/src/startup.rs`.
//!
//! Seed EAs expanded: 0x2017C80, 0x226C2D0, 0x227A0E0, 0x227BCF0,
//! 0x22B47C0, 0x4546C60, 0x4546FD0.
//!
//! IDA tag targets used for this reconstruction:
//! - `node_startup__load_gossip_config` for the config parser / serde visitor cluster
//!   (`override_gossip_config.json`, `GossipConfigInner`, six fields).
//! - `node_startup__root_peer_retry_loop` for the root-peer connect loop
//!   (`failed to find a peer to connect to, retrying from initial list`).
//! - `node_startup__run_non_validator_for_initial_state` for the non-validator
//!   bootstrap path (`running non-validator to get initial abci state for consensus`).
//! - `node_startup__bootstrap_consensus_state` for height quorum checks and ABCI
//!   snapshot linking (`gossip rpc height`, `unable to find at least 2 valid rpc heights`).
//! - `node_startup__validator_bootstrap` for validator config / public-IP checks.
//!
//! This file keeps foreign networking and database calls behind traits, but the
//! startup decisions, constants, error paths, and ordering are reconstructed as
//! concrete Rust control flow.

use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

pub const DATA_DIR: &str = "/hyperliquid_data";
pub const OVERRIDE_GOSSIP_CONFIG_FLN: &str = "override_gossip_config.json";
pub const NODE_CONFIG_FLN: &str = "node_config.json";
pub const NODE_GOSSIP_PRIORITY_CONFIG_FLN: &str = "node_gossip_priority_config";
pub const HEARTBEAT_JAILING_CONFIG_FLN: &str = "heartbeat_jailing_config";

pub const DEFAULT_N_GOSSIP_PEERS: usize = 16;
pub const MIN_VALID_RPC_HEIGHTS: usize = 2;
// [INFERENCE] The exact stale/lag threshold is not named in rodata; the branch is
// recovered from `local height is too far behind`.
pub const MAX_LOCAL_HEIGHT_LAG: u64 = 1_000;
pub const GOSSIP_RPC_TIMEOUT: Duration = Duration::from_secs(40);
pub const HEIGHT_QUERY_TIMEOUT: Duration = Duration::from_secs(3);
pub const ROOT_RETRY_SLEEP: Duration = Duration::from_secs(1);
pub const MAX_CLIENT_BLOCKS_PER_REQUEST: u64 = 100;

pub const GOSSIP_PORT_PRIMARY: u16 = 4001;
pub const GOSSIP_PORT_SECONDARY: u16 = 4002;
pub const CONSENSUS_PORT_START: u16 = 4003;
pub const CONSENSUS_PORT_END: u16 = 4006;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Chain {
    Mainnet,
    Testnet,
    Local,
}

impl Chain {
    #[inline]
    pub fn is_testing(&self) -> bool {
        matches!(self, Chain::Testnet | Chain::Local)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct NodeIp(pub IpAddr);

impl<'de> Deserialize<'de> for NodeIp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Tagged { Ip: IpAddr },
            Bare(IpAddr),
        }

        match Wire::deserialize(deserializer)? {
            Wire::Tagged { Ip } | Wire::Bare(Ip) => Ok(Self(Ip)),
        }
    }
}

impl Serialize for NodeIp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct TaggedIp {
            Ip: IpAddr,
        }

        TaggedIp { Ip: self.0 }.serialize(serializer)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GossipConfigInner {
    pub root_node_ips: Vec<NodeIp>,
    pub try_new_peers: bool,
    pub chain: Chain,
    pub reserved_peer_ips: Vec<NodeIp>,
    pub n_gossip_peers: usize,
    pub split_client_blocks: bool,
}

#[derive(Clone, Debug)]
pub struct NormalizedGossipConfig {
    pub inner: GossipConfigInner,
    pub connect_candidates: Vec<IpAddr>,
    pub n_gossip_peers: usize,
}

#[derive(Clone, Debug, Deserialize)]
pub struct NodeConfig {
    pub key: String,
    #[serde(default)]
    pub node_ip: Option<NodeIp>,
    #[serde(default)]
    pub sentry_ips: Vec<NodeIp>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeMode {
    NonValidator,
    Validator,
}

#[derive(Clone, Debug)]
pub struct StartupArgs {
    pub chain: Chain,
    pub mode: NodeMode,
    pub data_dir: PathBuf,
    pub override_public_ip_address: Option<IpAddr>,
    pub check_reachability: bool,
}

impl Default for StartupArgs {
    fn default() -> Self {
        Self {
            chain: Chain::Mainnet,
            mode: NodeMode::NonValidator,
            data_dir: PathBuf::from(DATA_DIR),
            override_public_ip_address: None,
            check_reachability: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GossipStatus {
    pub initial_height: u64,
    pub latest_height: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GreetingId {
    Live = 0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpGreeting {
    pub send_abci: bool,
    pub id: GreetingId,
}

impl TcpGreeting {
    pub const REQUEST_ABCI_LIVE: Self = Self {
        send_abci: true,
        id: GreetingId::Live,
    };
}

#[derive(Clone, Debug)]
pub struct AbciStateSnapshot {
    pub height: u64,
    pub round: u64,
    pub abci_time: SystemTime,
    pub wall_time: SystemTime,
    pub node_ips: Vec<IpAddr>,
    pub hardfork_version: u32,
}

#[derive(Clone, Debug)]
pub struct StartupArtifacts {
    pub gossip_config: NormalizedGossipConfig,
    pub abci_state: AbciStateSnapshot,
    pub bootstrap_peer: Option<IpAddr>,
    pub validator: bool,
    pub consensus_ports: Option<(u16, u16)>,
}

#[derive(Clone, Debug)]
pub struct PeerHeight {
    pub ip: IpAddr,
    pub status: GossipStatus,
    pub freshness: HeightFreshness,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeightFreshness {
    Fresh,
    Stale,
    Missing,
}

#[derive(Debug)]
pub enum StartupError {
    Io { path: PathBuf, source: std::io::Error },
    Json { path: PathBuf, source: serde_json::Error },
    UnsupportedChain { configured: Chain, expected: Chain },
    EmptyRootNodeIps,
    InvalidGossipPeerCount { configured: usize },
    NodeConfigMissing,
    PublicIpMismatch { configured: IpAddr, public: IpAddr },
    UnreachablePeers { peers: Vec<IpAddr> },
    NoBootstrapPeer { peers_tried: Vec<IpAddr> },
    UnableToFindAtLeastTwoValidRpcHeights { observed: Vec<PeerHeight> },
    LocalHeightFromStaleHardfork { local_height: u64, peer_initial_height: u64 },
    LocalHeightTooFarBehind { local_height: u64, target_height: u64 },
    AbciStream { peer: IpAddr, message: String },
    Rpc { peer: IpAddr, message: String },
    Service(String),
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartupError::Io { path, source } => write!(f, "could not load file `{}`: {source}", path.display()),
            StartupError::Json { path, source } => write!(f, "could not parse json `{}`: {source}", path.display()),
            StartupError::UnsupportedChain { configured, expected } => {
                write!(f, "unsupported chain: config={configured:?}, expected={expected:?}")
            }
            StartupError::EmptyRootNodeIps => write!(f, "assertion failed: !res.read().root_node_ips.is_empty()"),
            StartupError::InvalidGossipPeerCount { configured } => {
                write!(f, "invalid n_gossip_peers={configured}")
            }
            StartupError::NodeConfigMissing => write!(f, "failed to load node config"),
            StartupError::PublicIpMismatch { configured, public } => write!(
                f,
                "node ip to change to must match the machine's public ip: configured={configured}, public={public}"
            ),
            StartupError::UnreachablePeers { peers } => write!(
                f,
                "Unreachable peers were found. Do not run validator with current IP until all peers have added it to their firewalls. unreachable addresses: {peers:?}"
            ),
            StartupError::NoBootstrapPeer { peers_tried } => {
                write!(f, "failed to find a peer to connect to, retrying from initial list: {peers_tried:?}")
            }
            StartupError::UnableToFindAtLeastTwoValidRpcHeights { observed } => {
                write!(f, "unable to find at least 2 valid rpc heights: {observed:?}")
            }
            StartupError::LocalHeightFromStaleHardfork { local_height, peer_initial_height } => write!(
                f,
                "local height is from stale hardfork: local_height={local_height}, peer_initial_height={peer_initial_height}"
            ),
            StartupError::LocalHeightTooFarBehind { local_height, target_height } => write!(
                f,
                "local height is too far behind: local_height={local_height}, target_height={target_height}"
            ),
            StartupError::AbciStream { peer, message } => write!(f, "could not establish abci stream from {peer}, retrying: {message}"),
            StartupError::Rpc { peer, message } => write!(f, "unable to query height: {message} @@ [rpc_ip: {peer}]"),
            StartupError::Service(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for StartupError {}

// [INFERENCE] Foreign networking/database services are represented as a trait so
// this file can preserve startup control flow without inventing sibling modules.
pub trait StartupServices {
    fn read_file(&mut self, path: &Path) -> Result<Vec<u8>, std::io::Error>;
    fn public_ip(&mut self) -> Result<IpAddr, String>;
    fn check_reachability(&mut self, ip: IpAddr, port: u16, timeout: Duration) -> Result<bool, String>;
    fn query_gossip_status(&mut self, ip: IpAddr, timeout: Duration) -> Result<Option<GossipStatus>, String>;
    fn connect_abci_stream(&mut self, ip: IpAddr, greeting: TcpGreeting, timeout: Duration) -> Result<AbciStateSnapshot, String>;
    fn save_initial_local_abci_state(&mut self, state: &AbciStateSnapshot) -> Result<(), String>;
    fn linked_local_abci_state(&mut self) -> Result<Option<AbciStateSnapshot>, String>;
    fn start_gossip_rpc(&mut self, config: &NormalizedGossipConfig, state: &AbciStateSnapshot) -> Result<(), String>;
    fn start_consensus_rpc(&mut self, config: &NormalizedGossipConfig, state: &AbciStateSnapshot, validator: Option<&NodeConfig>) -> Result<(), String>;
    fn start_client_block_forwarder(&mut self, peer: IpAddr, start_round: u64, end_round: u64) -> Result<(), String>;
}

pub fn load_gossip_config<S: StartupServices>(
    services: &mut S,
    data_dir: &Path,
    expected_chain: Chain,
) -> Result<NormalizedGossipConfig, StartupError> {
    let path = data_dir.join(OVERRIDE_GOSSIP_CONFIG_FLN);
    let bytes = services
        .read_file(&path)
        .map_err(|source| StartupError::Io { path: path.clone(), source })?;
    let mut inner: GossipConfigInner = serde_json::from_slice(&bytes)
        .map_err(|source| StartupError::Json { path: path.clone(), source })?;

    if inner.chain != expected_chain {
        return Err(StartupError::UnsupportedChain {
            configured: inner.chain,
            expected: expected_chain,
        });
    }

    if inner.root_node_ips.is_empty() {
        return Err(StartupError::EmptyRootNodeIps);
    }

    if inner.n_gossip_peers == 0 {
        return Err(StartupError::InvalidGossipPeerCount { configured: 0 });
    }

    let mut seen = HashSet::new();
    inner.root_node_ips.retain(|ip| seen.insert(ip.0));
    inner.reserved_peer_ips.retain(|ip| seen.insert(ip.0));

    let mut connect_candidates = Vec::with_capacity(inner.root_node_ips.len() + inner.reserved_peer_ips.len());
    connect_candidates.extend(inner.root_node_ips.iter().map(|ip| ip.0));
    connect_candidates.extend(inner.reserved_peer_ips.iter().map(|ip| ip.0));

    let requested = inner.n_gossip_peers;
    let clipped = requested.min(connect_candidates.len().max(1));
    if clipped != requested {
        // Recovered log string: `n_gossip_peers clipped to`.
        inner.n_gossip_peers = clipped;
    }

    Ok(NormalizedGossipConfig {
        inner,
        connect_candidates,
        n_gossip_peers: clipped,
    })
}

pub fn load_node_config<S: StartupServices>(
    services: &mut S,
    data_dir: &Path,
) -> Result<NodeConfig, StartupError> {
    let path = data_dir.join(NODE_CONFIG_FLN);
    let bytes = services
        .read_file(&path)
        .map_err(|_| StartupError::NodeConfigMissing)?;
    serde_json::from_slice(&bytes).map_err(|source| StartupError::Json { path, source })
}

pub fn run_startup<S: StartupServices>(
    services: &mut S,
    args: StartupArgs,
) -> Result<StartupArtifacts, StartupError> {
    let gossip_config = load_gossip_config(services, &args.data_dir, args.chain.clone())?;

    let validator_config = match args.mode {
        NodeMode::Validator => Some(load_node_config(services, &args.data_dir)?),
        NodeMode::NonValidator => None,
    };

    if let Some(config) = validator_config.as_ref() {
        validate_validator_public_ip(services, config, args.override_public_ip_address)?;
        if args.check_reachability {
            validate_validator_reachability(services, config)?;
        }
    }

    let linked = services
        .linked_local_abci_state()
        .map_err(StartupError::Service)?;

    let (abci_state, bootstrap_peer) = match linked {
        Some(state) if is_linked_state_usable(&state, &gossip_config) => (state, None),
        Some(state) if validator_config.is_some() => {
            let (state, peer) = refresh_validator_state_from_gossip(services, &gossip_config, state.height)?;
            (state, Some(peer))
        }
        _ => {
            let (state, peer) = run_non_validator_for_initial_state(services, &gossip_config)?;
            (state, Some(peer))
        }
    };

    services
        .save_initial_local_abci_state(&abci_state)
        .map_err(StartupError::Service)?;

    services
        .start_gossip_rpc(&gossip_config, &abci_state)
        .map_err(StartupError::Service)?;

    services
        .start_consensus_rpc(&gossip_config, &abci_state, validator_config.as_ref())
        .map_err(StartupError::Service)?;

    if let Some(peer) = bootstrap_peer {
        forward_bootstrap_client_blocks(services, peer, abci_state.round, abci_state.height)?;
    }

    Ok(StartupArtifacts {
        gossip_config,
        abci_state,
        bootstrap_peer,
        validator: validator_config.is_some(),
        consensus_ports: validator_config.as_ref().map(|_| (CONSENSUS_PORT_START, CONSENSUS_PORT_END)),
    })
}

fn validate_validator_public_ip<S: StartupServices>(
    services: &mut S,
    config: &NodeConfig,
    override_public_ip_address: Option<IpAddr>,
) -> Result<(), StartupError> {
    let configured = match (override_public_ip_address, config.node_ip.as_ref()) {
        (Some(ip), _) => ip,
        (None, Some(ip)) => ip.0,
        (None, None) => return Ok(()),
    };

    let public = services.public_ip().map_err(StartupError::Service)?;
    if configured != public {
        return Err(StartupError::PublicIpMismatch { configured, public });
    }
    Ok(())
}

fn validate_validator_reachability<S: StartupServices>(
    services: &mut S,
    config: &NodeConfig,
) -> Result<(), StartupError> {
    let mut unreachable = Vec::new();
    for peer in &config.sentry_ips {
        match services.check_reachability(peer.0, GOSSIP_PORT_PRIMARY, HEIGHT_QUERY_TIMEOUT) {
            Ok(true) => {}
            Ok(false) | Err(_) => unreachable.push(peer.0),
        }
    }
    if unreachable.is_empty() {
        Ok(())
    } else {
        Err(StartupError::UnreachablePeers { peers: unreachable })
    }
}

fn is_linked_state_usable(state: &AbciStateSnapshot, config: &NormalizedGossipConfig) -> bool {
    if state.height == 0 || state.node_ips.is_empty() {
        return false;
    }

    if config.inner.chain.is_testing() {
        return true;
    }

    let configured: BTreeSet<IpAddr> = config.connect_candidates.iter().copied().collect();
    state.node_ips.iter().any(|ip| configured.contains(ip))
}

pub fn run_non_validator_for_initial_state<S: StartupServices>(
    services: &mut S,
    config: &NormalizedGossipConfig,
) -> Result<(AbciStateSnapshot, IpAddr), StartupError> {
    let observed = query_root_heights(services, config, 0)?;
    let target = select_height_quorum(&observed, 0)?;
    let mut tried = Vec::new();

    for peer in config.connect_candidates.iter().copied() {
        tried.push(peer);
        match services.connect_abci_stream(peer, TcpGreeting::REQUEST_ABCI_LIVE, GOSSIP_RPC_TIMEOUT) {
            Ok(state) => {
                if state.height < target.latest_height.saturating_sub(MAX_LOCAL_HEIGHT_LAG) {
                    return Err(StartupError::LocalHeightTooFarBehind {
                        local_height: state.height,
                        target_height: target.latest_height,
                    });
                }
                return Ok((state, peer));
            }
            Err(message) => {
                let _ = StartupError::AbciStream { peer, message };
                continue;
            }
        }
    }

    Err(StartupError::NoBootstrapPeer { peers_tried: tried })
}

pub fn refresh_validator_state_from_gossip<S: StartupServices>(
    services: &mut S,
    config: &NormalizedGossipConfig,
    local_height: u64,
) -> Result<(AbciStateSnapshot, IpAddr), StartupError> {
    let observed = query_root_heights(services, config, local_height)?;
    let target = select_height_quorum(&observed, local_height)?;

    if local_height < target.initial_height {
        return Err(StartupError::LocalHeightFromStaleHardfork {
            local_height,
            peer_initial_height: target.initial_height,
        });
    }

    if target.latest_height.saturating_sub(local_height) > MAX_LOCAL_HEIGHT_LAG {
        return Err(StartupError::LocalHeightTooFarBehind {
            local_height,
            target_height: target.latest_height,
        });
    }

    let peer = observed
        .iter()
        .find(|height| height.freshness == HeightFreshness::Fresh && height.status.latest_height >= target.latest_height)
        .map(|height| height.ip)
        .ok_or_else(|| StartupError::UnableToFindAtLeastTwoValidRpcHeights { observed: observed.clone() })?;

    let state = services
        .connect_abci_stream(peer, TcpGreeting::REQUEST_ABCI_LIVE, GOSSIP_RPC_TIMEOUT)
        .map_err(|message| StartupError::AbciStream { peer, message })?;

    Ok((state, peer))
}

pub fn query_root_heights<S: StartupServices>(
    services: &mut S,
    config: &NormalizedGossipConfig,
    local_height: u64,
) -> Result<Vec<PeerHeight>, StartupError> {
    let mut observed = Vec::with_capacity(config.connect_candidates.len());

    for peer in config.connect_candidates.iter().copied() {
        let status = match services.query_gossip_status(peer, HEIGHT_QUERY_TIMEOUT) {
            Ok(Some(status)) => status,
            Ok(None) => {
                observed.push(PeerHeight {
                    ip: peer,
                    status: GossipStatus::default(),
                    freshness: HeightFreshness::Missing,
                });
                continue;
            }
            Err(message) => return Err(StartupError::Rpc { peer, message }),
        };

        let freshness = classify_gossip_height(status, local_height);
        observed.push(PeerHeight { ip: peer, status, freshness });
    }

    Ok(observed)
}

fn classify_gossip_height(status: GossipStatus, local_height: u64) -> HeightFreshness {
    if status.latest_height == 0 {
        return HeightFreshness::Missing;
    }
    if local_height != 0 && status.latest_height + MAX_LOCAL_HEIGHT_LAG < local_height {
        return HeightFreshness::Stale;
    }
    HeightFreshness::Fresh
}

fn select_height_quorum(observed: &[PeerHeight], local_height: u64) -> Result<GossipStatus, StartupError> {
    let mut fresh: Vec<GossipStatus> = observed
        .iter()
        .filter(|height| height.freshness == HeightFreshness::Fresh)
        .map(|height| height.status)
        .collect();

    if fresh.len() < MIN_VALID_RPC_HEIGHTS {
        return Err(StartupError::UnableToFindAtLeastTwoValidRpcHeights { observed: observed.to_vec() });
    }

    fresh.sort_by_key(|status| status.latest_height);
    let quorum = fresh[fresh.len() / 2];

    if local_height != 0 && local_height < quorum.initial_height {
        return Err(StartupError::LocalHeightFromStaleHardfork {
            local_height,
            peer_initial_height: quorum.initial_height,
        });
    }

    Ok(quorum)
}

pub fn forward_bootstrap_client_blocks<S: StartupServices>(
    services: &mut S,
    peer: IpAddr,
    start_round: u64,
    end_round: u64,
) -> Result<(), StartupError> {
    for (after_round, until_round) in client_block_ranges(start_round, end_round) {
        services
            .start_client_block_forwarder(peer, after_round, until_round)
            .map_err(StartupError::Service)?;
    }
    Ok(())
}

pub fn client_block_ranges(start_round: u64, end_round: u64) -> impl Iterator<Item = (u64, u64)> {
    let mut after_round = start_round;
    std::iter::from_fn(move || {
        if after_round >= end_round {
            return None;
        }

        let until_round = after_round
            .saturating_add(MAX_CLIENT_BLOCKS_PER_REQUEST - 1)
            .min(end_round);
        let range = (after_round, until_round);
        after_round = until_round;
        Some(range)
    })
}
pub fn gossip_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(OVERRIDE_GOSSIP_CONFIG_FLN)
}

pub fn node_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(NODE_CONFIG_FLN)
}
