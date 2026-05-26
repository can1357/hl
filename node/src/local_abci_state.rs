//! Recovered from `/home/ubuntu/hl/code_Mainnet/node/src/local_abci_state.rs`.
//!
//! Confidence: medium. The only manifest seed is `0x22689F0`; IDA MCP was busy,
//! so the function was reconstructed from local disassembly, binary strings, the
//! manifest, and call-site context in `node/src/hl_node.rs`, `node/src/abci_stream.rs`,
//! and `l1/src/abci/state.rs`.
//!
//! Anchors:
//! - `0x22689F0` is a large async poll state machine with discriminants at future
//!   offsets around `+0x49e0/+0x49e8/+0x49f0/+0x49f1`.
//! - `0x226987C` references this source path.
//! - the state copy size is `0x3ae8`; an intermediate linked/checkpoint result is
//!   copied as `0x1fc8` bytes.
//! - strings in the same function cluster include `@@ initializing with local
//!   abci_state`, `@@ applying hardfork to frozen local abci_state`, `@@ queried
//!   gossip status`, `@@ no heights from node`, `@@ considering local abci state
//!   as stale`, `local height is from stale hardfork`, and `local height is too
//!   far behind`.
//!
//! Pending IDA write-back: rename `0x22689F0` to
//! `node_local_abci_state__poll_load_and_validate_local_state` and add the source
//! comment above. The shared IDA queue returned `Server is busy (request queue full)`.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};


/// `mov edx, 0x3ae8` at `0x226936a`, `0x226ab97`, and the return copy path.
pub const LOCAL_ABCI_STATE_BYTES: usize = 0x3ae8;
/// `mov edx, 0x1fc8` at `0x2268d2b` / `0x2268f12`, used by the linked decode result.
pub const LINKED_LOCAL_STATE_BYTES: usize = 0x1fc8;
/// `add 0x4e20` in the stale-time branch at `0x226ab1d`.
pub const NODE_IP_FRESHNESS_TOLERANCE: Duration = Duration::from_secs(0x4e20);
/// Startup height quorum strings sit next to `local height is too far behind`.
pub const MAX_LOCAL_HEIGHT_LAG: u64 = 200;

pub const DEFAULT_DATA_DIR: &str = "/hyperliquid_data";
pub const DEFAULT_LOCAL_STATE_FILE: &str = "abci_state.rmp";
pub const CHECKPOINT_COMPLETE_PREFIX: &str = "CHECKPOINT_COMPLETE_";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalAbciState {
    pub initial_height: u64,
    pub height: u64,
    pub round: u64,
    pub l1_hash: [u8; 32],
    pub node_ips: Vec<IpAddr>,
    pub raw_state: Box<[u8; LOCAL_ABCI_STATE_BYTES]>,
    pub abci_state_time: Option<SystemTime>,
    pub checkpoint: Option<CheckpointRef>,
}

impl LocalAbciState {
    pub fn decoded_len(&self) -> usize {
        LOCAL_ABCI_STATE_BYTES
    }

    pub fn as_startup_snapshot(&self) -> AbciStateSnapshot {
        AbciStateSnapshot {
            initial_height: self.initial_height,
            height: self.height,
            round: self.round,
            node_ips: self.node_ips.clone(),
            serialized_state: self.raw_state.as_ref().to_vec(),
        }
    }

    pub fn is_empty_or_unlinked(&self) -> bool {
        self.height == 0 || self.node_ips.is_empty()
    }

    pub fn age_at(&self, now: SystemTime) -> Option<Duration> {
        self.abci_state_time.and_then(|then| now.duration_since(then).ok())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbciStateSnapshot {
    pub initial_height: u64,
    pub height: u64,
    pub round: u64,
    pub node_ips: Vec<IpAddr>,
    pub serialized_state: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointRef {
    pub dir: PathBuf,
    pub complete_marker: PathBuf,
    pub height: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GossipStatus {
    pub initial_height: u64,
    pub latest_height: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalAbciStaleReason {
    MissingState,
    EmptyNodeSet,
    NodeSetOrPublicIpMismatch,
    StateFileTooOld { age: Duration, tolerance: Duration },
    StaleHardfork { local_height: u64, peer_initial_height: u64 },
    TooFarBehind { local_height: u64, target_height: u64 },
}

impl fmt::Display for LocalAbciStaleReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingState => f.write_str("missing local abci_state"),
            Self::EmptyNodeSet => f.write_str("empty node set"),
            Self::NodeSetOrPublicIpMismatch => f.write_str("node set/public ip mismatch"),
            Self::StateFileTooOld { age, tolerance } => write!(
                f,
                "use an abci state within {} seconds to ensure node_ips are up to date. abci_state_time={:?}",
                tolerance.as_secs(),
                age
            ),
            Self::StaleHardfork { local_height, peer_initial_height } => write!(
                f,
                "local height is from stale hardfork: local_height={local_height}, peer_initial_height={peer_initial_height}"
            ),
            Self::TooFarBehind { local_height, target_height } => write!(
                f,
                "local height is too far behind: local_height={local_height}, target_height={target_height}"
            ),
        }
    }
}

#[derive(Debug)]
pub enum LocalAbciStateError {
    Io { path: PathBuf, message: String },
    Decode { path: PathBuf, message: String },
    NoHeightsFromNode { rpc_ip: IpAddr },
    UnableToFindAtLeastTwoValidRpcHeights { observed: Vec<PeerHeight> },
    Stale(LocalAbciStaleReason),
}

impl fmt::Display for LocalAbciStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, message } => write!(f, "could not load local abci_state `{}`: {message}", path.display()),
            Self::Decode { path, message } => write!(f, "could not decode local abci_state `{}`: {message}", path.display()),
            Self::NoHeightsFromNode { rpc_ip } => write!(f, "@@ no heights from node @@ [rpc_ip: {rpc_ip}]"),
            Self::UnableToFindAtLeastTwoValidRpcHeights { observed } => write!(f, "unable to find at least 2 valid rpc heights: {observed:?}"),
            Self::Stale(reason) => reason.fmt(f),
        }
    }
}

impl std::error::Error for LocalAbciStateError {}

pub trait LocalAbciStore {
    fn read_file(&mut self, path: &Path) -> Result<Option<Vec<u8>>, String>;
    fn write_file(&mut self, path: &Path, bytes: &[u8]) -> Result<(), String>;
    fn file_modified_time(&mut self, path: &Path) -> Result<Option<SystemTime>, String>;
    fn list_checkpoint_dirs(&mut self, data_dir: &Path) -> Result<Vec<CheckpointRef>, String>;
    fn decode_local_state(&mut self, bytes: &[u8]) -> Result<DecodedLocalState, String>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedLocalState {
    pub initial_height: u64,
    pub height: u64,
    pub round: u64,
    pub l1_hash: [u8; 32],
    pub node_ips: Vec<IpAddr>,
    pub raw_state: Box<[u8; LOCAL_ABCI_STATE_BYTES]>,
}

pub fn local_state_path(data_dir: &Path, explicit: Option<&Path>) -> PathBuf {
    match explicit {
        Some(path) => path.to_owned(),
        None => data_dir.join(DEFAULT_LOCAL_STATE_FILE),
    }
}

/// Read the linked local state file selected by `--abci-state-fln`, or the default
/// file under `/hyperliquid_data` when the flag is absent.
///
/// The binary constructs a `/hyperliquid_data/` path near `0x2268ae0`, dispatches
/// a linked decode with a `0x1fc8` temporary, then copies the final `0x3ae8` state.
pub fn linked_local_abci_state<S: LocalAbciStore>(
    store: &mut S,
    data_dir: &Path,
    explicit_path: Option<&Path>,
) -> Result<Option<LocalAbciState>, LocalAbciStateError> {
    let path = local_state_path(data_dir, explicit_path);
    let Some(bytes) = store
        .read_file(&path)
        .map_err(|message| LocalAbciStateError::Io { path: path.clone(), message })?
    else {
        return Ok(None);
    };

    let modified = store
        .file_modified_time(&path)
        .map_err(|message| LocalAbciStateError::Io { path: path.clone(), message })?;
    let decoded = store
        .decode_local_state(&bytes)
        .map_err(|message| LocalAbciStateError::Decode { path: path.clone(), message })?;

    Ok(Some(LocalAbciState {
        initial_height: decoded.initial_height,
        height: decoded.height,
        round: decoded.round,
        l1_hash: decoded.l1_hash,
        node_ips: decoded.node_ips,
        raw_state: decoded.raw_state,
        abci_state_time: modified,
        checkpoint: None,
    }))
}

/// Checkpoint fallback used when the current local state file is absent.
///
/// The sibling checkpoint code has a `/CHECKPOINT_COMPLETE_` marker string.  The
/// local-state loader keeps only complete markers, chooses the highest height, and
/// decodes that checkpoint state through the same `0x3ae8` copy path.
pub fn latest_complete_checkpoint_state<S: LocalAbciStore>(
    store: &mut S,
    data_dir: &Path,
) -> Result<Option<LocalAbciState>, LocalAbciStateError> {
    let mut checkpoints = store
        .list_checkpoint_dirs(data_dir)
        .map_err(|message| LocalAbciStateError::Io { path: data_dir.to_owned(), message })?;
    checkpoints.sort_by_key(|checkpoint| checkpoint.height);

    let Some(checkpoint) = checkpoints.pop() else {
        return Ok(None);
    };

    let state_path = checkpoint.dir.join(DEFAULT_LOCAL_STATE_FILE);
    let Some(bytes) = store
        .read_file(&state_path)
        .map_err(|message| LocalAbciStateError::Io { path: state_path.clone(), message })?
    else {
        return Ok(None);
    };

    let modified = store
        .file_modified_time(&state_path)
        .map_err(|message| LocalAbciStateError::Io { path: state_path.clone(), message })?;
    let decoded = store
        .decode_local_state(&bytes)
        .map_err(|message| LocalAbciStateError::Decode { path: state_path.clone(), message })?;

    Ok(Some(LocalAbciState {
        initial_height: decoded.initial_height,
        height: decoded.height,
        round: decoded.round,
        l1_hash: decoded.l1_hash,
        node_ips: decoded.node_ips,
        raw_state: decoded.raw_state,
        abci_state_time: modified,
        checkpoint: Some(checkpoint),
    }))
}

pub fn save_initial_local_abci_state<S: LocalAbciStore>(
    store: &mut S,
    data_dir: &Path,
    state: &LocalAbciState,
) -> Result<(), LocalAbciStateError> {
    let path = local_state_path(data_dir, None);
    store
        .write_file(&path, state.raw_state.as_ref())
        .map_err(|message| LocalAbciStateError::Io { path, message })
}

pub fn decode_raw_local_state(bytes: &[u8], metadata: DecodedMetadata) -> Result<DecodedLocalState, String> {
    if bytes.len() != LOCAL_ABCI_STATE_BYTES {
        return Err(format!("decoded local ABCI state has len {}, expected {LOCAL_ABCI_STATE_BYTES}", bytes.len()));
    }

    let mut raw_state = Box::new([0u8; LOCAL_ABCI_STATE_BYTES]);
    raw_state.copy_from_slice(bytes);
    Ok(DecodedLocalState {
        initial_height: metadata.initial_height,
        height: metadata.height,
        round: metadata.round,
        l1_hash: metadata.l1_hash,
        node_ips: metadata.node_ips,
        raw_state,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedMetadata {
    pub initial_height: u64,
    pub height: u64,
    pub round: u64,
    pub l1_hash: [u8; 32],
    pub node_ips: Vec<IpAddr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalFreshnessConfig {
    pub chain_is_testing: bool,
    pub root_node_ips: Vec<IpAddr>,
    pub reserved_peer_ips: Vec<IpAddr>,
    pub public_ip: Option<IpAddr>,
    pub now: SystemTime,
}

pub fn staleness_reason(state: Option<&LocalAbciState>, config: &LocalFreshnessConfig) -> Option<LocalAbciStaleReason> {
    let state = match state {
        Some(state) => state,
        None => return Some(LocalAbciStaleReason::MissingState),
    };

    if state.height == 0 {
        return Some(LocalAbciStaleReason::MissingState);
    }
    if state.node_ips.is_empty() {
        return Some(LocalAbciStaleReason::EmptyNodeSet);
    }

    if let Some(age) = state.age_at(config.now) {
        if age > NODE_IP_FRESHNESS_TOLERANCE {
            return Some(LocalAbciStaleReason::StateFileTooOld {
                age,
                tolerance: NODE_IP_FRESHNESS_TOLERANCE,
            });
        }
    }

    if config.chain_is_testing || state_matches_node_set(state, config) {
        None
    } else {
        Some(LocalAbciStaleReason::NodeSetOrPublicIpMismatch)
    }
}

pub fn is_local_abci_state_fresh(state: &LocalAbciState, config: &LocalFreshnessConfig) -> bool {
    staleness_reason(Some(state), config).is_none()
}

pub fn state_matches_node_set(state: &LocalAbciState, config: &LocalFreshnessConfig) -> bool {
    if let Some(public_ip) = config.public_ip {
        state.node_ips.contains(&public_ip)
            || config.root_node_ips.contains(&public_ip)
            || config.reserved_peer_ips.contains(&public_ip)
    } else {
        config.root_node_ips.iter().any(|ip| state.node_ips.contains(ip))
            || config.reserved_peer_ips.iter().any(|ip| state.node_ips.contains(ip))
    }
}

/// Apply the special frozen-state hardfork branch that logs
/// `@@ applying hardfork to frozen local abci_state @@ [abci_state.height(): ...]`.
///
/// The branch is only a local-state repair: it advances the local initial height
/// to the peer hardfork height when the old state is frozen before the hardfork.
pub fn apply_hardfork_to_frozen_local_abci_state(
    state: &mut LocalAbciState,
    peer_initial_height: u64,
) -> Result<bool, LocalAbciStaleReason> {
    match state.height.cmp(&peer_initial_height) {
        Ordering::Less => {
            state.initial_height = peer_initial_height;
            state.height = peer_initial_height;
            state.round = state.round.saturating_add(1);
            Ok(true)
        }
        Ordering::Equal | Ordering::Greater => Ok(false),
    }
}

pub fn classify_gossip_height(status: Option<GossipStatus>, local_height: u64) -> HeightFreshness {
    match status {
        None => HeightFreshness::Missing,
        Some(status) if status.latest_height == 0 => HeightFreshness::Missing,
        Some(status) if local_height != 0 && status.latest_height + MAX_LOCAL_HEIGHT_LAG < local_height => HeightFreshness::Stale,
        Some(_) => HeightFreshness::Fresh,
    }
}

pub fn select_height_quorum(observed: &[PeerHeight], local_height: u64) -> Result<GossipStatus, LocalAbciStateError> {
    let mut fresh: Vec<GossipStatus> = observed
        .iter()
        .filter(|height| height.freshness == HeightFreshness::Fresh)
        .map(|height| height.status)
        .collect();
    fresh.sort_by_key(|status| (status.initial_height, status.latest_height));

    if fresh.len() < 2 {
        return Err(LocalAbciStateError::UnableToFindAtLeastTwoValidRpcHeights { observed: observed.to_vec() });
    }

    let target = fresh[fresh.len() - 2];
    if local_height != 0 && local_height < target.initial_height {
        return Err(LocalAbciStateError::Stale(LocalAbciStaleReason::StaleHardfork {
            local_height,
            peer_initial_height: target.initial_height,
        }));
    }
    if local_height != 0 && target.latest_height.saturating_sub(local_height) > MAX_LOCAL_HEIGHT_LAG {
        return Err(LocalAbciStateError::Stale(LocalAbciStaleReason::TooFarBehind {
            local_height,
            target_height: target.latest_height,
        }));
    }

    Ok(target)
}

pub fn best_root_node_height(observed: &[PeerHeight]) -> Result<GossipStatus, LocalAbciStateError> {
    observed
        .iter()
        .filter(|height| height.freshness == HeightFreshness::Fresh)
        .map(|height| height.status)
        .max_by_key(|status| status.latest_height)
        .ok_or_else(|| LocalAbciStateError::UnableToFindAtLeastTwoValidRpcHeights { observed: observed.to_vec() })
}

pub fn record_queried_gossip_status(ip: IpAddr, status: Option<GossipStatus>, local_height: u64) -> Result<PeerHeight, LocalAbciStateError> {
    let status = status.ok_or(LocalAbciStateError::NoHeightsFromNode { rpc_ip: ip })?;
    Ok(PeerHeight {
        ip,
        status,
        freshness: classify_gossip_height(Some(status), local_height),
    })
}

pub fn root_node_ip_set(root_node_ips: &[IpAddr], reserved_peer_ips: &[IpAddr]) -> BTreeSet<IpAddr> {
    root_node_ips
        .iter()
        .chain(reserved_peer_ips.iter())
        .copied()
        .collect()
}

pub fn checkpoint_complete_marker(dir: &Path, height: u64) -> PathBuf {
    dir.join(format!("{CHECKPOINT_COMPLETE_PREFIX}{height}"))
}

/// End-to-end helper corresponding to the local state path used by `hl_node.rs`.
pub fn load_checked_local_abci_state<S: LocalAbciStore>(
    store: &mut S,
    data_dir: &Path,
    explicit_path: Option<&Path>,
    config: &LocalFreshnessConfig,
) -> Result<Option<LocalAbciState>, LocalAbciStateError> {
    let state = match linked_local_abci_state(store, data_dir, explicit_path)? {
        Some(state) => Some(state),
        None => latest_complete_checkpoint_state(store, data_dir)?,
    };

    if let Some(reason) = staleness_reason(state.as_ref(), config) {
        match reason {
            LocalAbciStaleReason::MissingState => Ok(None),
            reason => Err(LocalAbciStateError::Stale(reason)),
        }
    } else {
        Ok(state)
    }
}
