//! Reconstructed from `/home/ubuntu/hl/code_Mainnet/node/src/firewall_ips.rs`.
//!
//! Confidence: medium for the set/check/update control flow, high for the startup
//! reachability interface and the validator/firewall mismatch log shape.
//!
//! IDA anchors used:
//! - `0x4B28FF0` (`sub_4B28FF0`) is the `tracing` event body whose rodata
//!   contains `<firewall does not match validators @@ [abci_minus_firewall: ...]
//!   @ [firewall_minus_abci: ...]`; it receives two computed set differences and
//!   only emits when the throttled tracing site is enabled.
//! - `0x28F6960` references the labels `firewall_ips_maybe_update`,
//!   `check_computed_ips`, `update_computed_ips`, and `update`, walks compact
//!   5-byte node-ip entries out of the validator/static config, checks the loaded
//!   firewall set against computed validator IPs, and conditionally publishes an
//!   updated handle.
//! - `0x28F52D0` is the shared loader/collector used by `0x28F6960`; it walks the
//!   validator tree and appends 0x20-byte decoded entries.
//!
//! IDA write status: `node_firewall_ips__log_validator_firewall_mismatch` rename
//! for `0x4B28FF0` was attempted but IDA returned `Server is busy (request queue
//! full)`. Pending writes are listed at the end of this file.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const FIREWALL_IPS_FLN: &str = "firewall_ips";
pub const FIREWALL_IPS_MAYBE_UPDATE: &str = "firewall_ips_maybe_update";
pub const CHECK_COMPUTED_IPS: &str = "check_computed_ips";
pub const UPDATE_COMPUTED_IPS: &str = "update_computed_ips";
pub const UPDATE: &str = "update";
pub const FIREWALL_MISMATCH_LOG: &str =
    "<firewall does not match validators @@ [abci_minus_firewall: _] @ [firewall_minus_abci: _]";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FirewallIpsError {
    Read { path: PathBuf, source: String },
    Parse { path: Option<PathBuf>, source: String },
    FirewallDoesNotMatchValidators(FirewallMismatch),
}

impl fmt::Display for FirewallIpsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => write!(f, "could not read {}: {source}", path.display()),
            Self::Parse { path: Some(path), source } => {
                write!(f, "could not parse {}: {source}", path.display())
            }
            Self::Parse { path: None, source } => write!(f, "could not parse firewall ips: {source}"),
            Self::FirewallDoesNotMatchValidators(mismatch) => mismatch.fmt(f),
        }
    }
}

impl std::error::Error for FirewallIpsError {}

/// Serde shape observed for node IPs elsewhere in the binary/config:
/// `[{"Ip":"1.2.3.4"}]`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct TaggedFirewallIp {
    #[serde(rename = "Ip")]
    pub ip: IpAddr,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum FirewallIpsJson {
    TaggedVec(Vec<TaggedFirewallIp>),
    // [INFERENCE] Accepted because the same `firewall_ips` key is present in the
    // RPC/status rodata cluster. The startup path only needs the resulting set.
    Wrapped { firewall_ips: Vec<TaggedFirewallIp> },
}

impl FirewallIpsJson {
    fn into_set(self) -> BTreeSet<IpAddr> {
        match self {
            Self::TaggedVec(entries) | Self::Wrapped { firewall_ips: entries } => {
                entries.into_iter().map(|entry| entry.ip).collect()
            }
        }
    }
}

/// Load the firewall allow-list used by the startup reachability check.
///
/// `hl_node.rs` maps errors from this function into
/// `failed to load firewall ips: ...`; this file keeps the lower-level I/O and
/// serde error text intact.
pub fn load_firewall_ips(path: &Path) -> Result<BTreeSet<IpAddr>, FirewallIpsError> {
    let bytes = fs::read(path).map_err(|error| FirewallIpsError::Read {
        path: path.to_path_buf(),
        source: io_error_string(error),
    })?;
    parse_firewall_ips_bytes(Some(path), &bytes)
}

pub fn parse_firewall_ips_bytes(
    path: Option<&Path>,
    bytes: &[u8],
) -> Result<BTreeSet<IpAddr>, FirewallIpsError> {
    serde_json::from_slice::<FirewallIpsJson>(bytes)
        .map(FirewallIpsJson::into_set)
        .map_err(|error| FirewallIpsError::Parse {
            path: path.map(Path::to_path_buf),
            source: error.to_string(),
        })
}

/// Compact node-ip enum copied by `0x28F6960` as five-byte records: a four-byte
/// payload followed by a one-byte tag. `StaticNodeIp::Ip` is the only variant
/// that contributes to the firewall set; the other tags are retained so callers
/// do not accidentally treat `Error`/local sentinel entries as public IPs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum StaticNodeIp {
    Ip(Ipv4Addr),
    Error(u32),
    LocalNode(u32),
    Unknown { tag: u8, payload: u32 },
}

impl StaticNodeIp {
    pub fn from_compact(payload: u32, tag: u8) -> Self {
        match tag {
            0 => Self::Ip(Ipv4Addr::from(payload.to_ne_bytes())),
            1 => Self::Error(payload),
            2 => Self::LocalNode(payload),
            tag => Self::Unknown { tag, payload },
        }
    }

    pub fn as_ip_addr(self) -> Option<IpAddr> {
        match self {
            Self::Ip(ip) => Some(IpAddr::V4(ip)),
            Self::Error(_) | Self::LocalNode(_) | Self::Unknown { .. } => None,
        }
    }
}

/// Recovered representation of the validator/static-config walk at
/// `0x28F6E97..0x28F6FCE`: entries are read in order, compacted to five-byte
/// `(payload, tag)` records, and non-IP variants are not admitted to the set.
pub fn computed_validator_ips<'a>(entries: impl IntoIterator<Item = &'a StaticNodeIp>) -> BTreeSet<IpAddr> {
    entries.into_iter().filter_map(|entry| entry.as_ip_addr()).collect()
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FirewallMismatch {
    pub abci_minus_firewall: Vec<IpAddr>,
    pub firewall_minus_abci: Vec<IpAddr>,
}

impl FirewallMismatch {
    pub fn is_empty(&self) -> bool {
        self.abci_minus_firewall.is_empty() && self.firewall_minus_abci.is_empty()
    }
}

impl fmt::Display for FirewallMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<firewall does not match validators @@ [abci_minus_firewall: {:?}] @ [firewall_minus_abci: {:?}]",
            self.abci_minus_firewall, self.firewall_minus_abci
        )
    }
}

/// `0x28F6960` calls the `check_computed_ips` site before `update_computed_ips`.
/// The seed logger `0x4B28FF0` receives exactly the two set differences below.
pub fn check_computed_ips(
    firewall_ips: &BTreeSet<IpAddr>,
    computed_validator_ips: &BTreeSet<IpAddr>,
) -> Result<(), FirewallIpsError> {
    let mismatch = firewall_mismatch(firewall_ips, computed_validator_ips);
    if mismatch.is_empty() {
        Ok(())
    } else {
        log_validator_firewall_mismatch(&mismatch);
        Err(FirewallIpsError::FirewallDoesNotMatchValidators(mismatch))
    }
}

pub fn firewall_mismatch(
    firewall_ips: &BTreeSet<IpAddr>,
    computed_validator_ips: &BTreeSet<IpAddr>,
) -> FirewallMismatch {
    FirewallMismatch {
        abci_minus_firewall: computed_validator_ips.difference(firewall_ips).copied().collect(),
        firewall_minus_abci: firewall_ips.difference(computed_validator_ips).copied().collect(),
    }
}

/// The startup reachability path skips root/reserved peers that are already in
/// `firewall_ips`, then probes every remaining root/reserved peer. Validator
/// sentries are always probed. This mirrors the `hl_node.rs` poll state machine
/// around `check_reachability_firewall_ips` and is kept here so the allow-list
/// semantics live with the parser/checker.
pub fn peers_requiring_startup_reachability_check(
    root_node_ips: impl IntoIterator<Item = IpAddr>,
    reserved_peer_ips: impl IntoIterator<Item = IpAddr>,
    validator_sentry_ips: impl IntoIterator<Item = IpAddr>,
    firewall_ips: &BTreeSet<IpAddr>,
) -> Vec<IpAddr> {
    let mut peers = Vec::new();
    peers.extend(
        root_node_ips
            .into_iter()
            .chain(reserved_peer_ips)
            .filter(|ip| !firewall_ips.contains(ip)),
    );
    peers.extend(validator_sentry_ips);
    peers
}

/// Result of the `firewall_ips_maybe_update` path at `0x28F6960`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FirewallUpdateDecision {
    NotAValidator,
    Unchanged,
    Updated { computed: BTreeSet<IpAddr> },
    Mismatch(FirewallMismatch),
}

/// Recovered high-level control flow for `firewall_ips_maybe_update`.
///
/// The binary first obtains the current firewall set, computes the validator IPs
/// from static config, runs `check_computed_ips`, and only enters the
/// `update_computed_ips` label when the computed set is accepted and differs
/// from the cached set.
pub fn firewall_ips_maybe_update(
    is_validator: bool,
    current_firewall_ips: &BTreeSet<IpAddr>,
    cached_computed_ips: &mut BTreeSet<IpAddr>,
    static_node_ips: &[StaticNodeIp],
) -> Result<FirewallUpdateDecision, FirewallIpsError> {
    if !is_validator {
        return Ok(FirewallUpdateDecision::NotAValidator);
    }

    let computed = computed_validator_ips(static_node_ips);
    let mismatch = firewall_mismatch(current_firewall_ips, &computed);
    if !mismatch.is_empty() {
        log_validator_firewall_mismatch(&mismatch);
        return Ok(FirewallUpdateDecision::Mismatch(mismatch));
    }

    if *cached_computed_ips == computed {
        return Ok(FirewallUpdateDecision::Unchanged);
    }

    *cached_computed_ips = computed.clone();
    Ok(FirewallUpdateDecision::Updated { computed })
}

/// `0x4B28FF0` is a throttled `tracing` event. We expose it as a normal function
/// in the reconstructed source; the exact sink is injected by the caller in the
/// original binary.
pub fn log_validator_firewall_mismatch(mismatch: &FirewallMismatch) {
    if !mismatch.is_empty() {
        let _ = FIREWALL_MISMATCH_LOG;
        let _ = (&mismatch.abci_minus_firewall, &mismatch.firewall_minus_abci);
    }
}

fn io_error_string(error: io::Error) -> String {
    error.to_string()
}

// Pending IDA operations when the database is writable:
// - rename `0x4B28FF0` -> `node_firewall_ips__log_validator_firewall_mismatch`
// - comment `0x4B28FF0`: `/home/ubuntu/hl/code_Mainnet/node/src/firewall_ips.rs :: log_validator_firewall_mismatch — tracing event for abci-minus-firewall/firewall-minus-abci set differences`
// - rename `0x28F6960` -> `node_firewall_ips__firewall_ips_maybe_update`
// - comment `0x28F6960`: `/home/ubuntu/hl/code_Mainnet/node/src/firewall_ips.rs :: firewall_ips_maybe_update — loads firewall IPs, computes validator IP set, checks mismatch, and updates cached computed IPs`
// - rename `0x28F52D0` -> `node_firewall_ips__collect_firewall_ip_entries`
// - comment `0x28F52D0`: `/home/ubuntu/hl/code_Mainnet/node/src/firewall_ips.rs :: collect_firewall_ip_entries — walks static validator/node-ip tree and emits decoded entries`
