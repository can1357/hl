//! Reconstructed Rust for `/home/ubuntu/hl/code_Mainnet/node/src/consensus/node_ips.rs`.
//!
//! Primary seed EA: `0x45C42B0`.
//!
//! Evidence anchors:
//! - `0x45BC960` serializes `NodeIp` to human-readable externally-tagged JSON:
//!   `{ "LocalNode": n }` or `{ "Ip": <IpAddr Display> }`.
//! - `0x45BCD00` serializes the same enum to MessagePack as a one-entry map with
//!   keys `LocalNode` (`0x6F7096`) and `Ip` (`0x6F7094`).
//! - `0x45C3AE0` is the packed-`IpAddr` firewall/private-address normalizer.
//! - `0x45C3D20` builds a 0x48-byte return object: three 24-byte Rust collections.
//! - `0x45C42B0` wraps that update and logs
//!   `Node IPs missing in ... defaulting to untrusted: ...` when a mode-3 caller has
//!   missing filtered IPs and must use fallback untrusted IPs.
//!
//! IDA annotation status: attempted rename of `0x45C42B0` to
//! `node_node_ips__copy_with_firewall_fallback`, but the shared IDA server returned
//! `Server is busy (request queue full)`. Pending annotations are listed at the end
//! of this file.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

pub type ValidatorId = [u8; 20];
pub type SignatureBytes = [u8; 65];

pub const LOG_NODE_IPS_MISSING: &str =
    "Node IPs missing in {fln}, defaulting to untrusted: {node_ips}. Update this file ASAP to avoid excessive timeouts and potential jailing.";
pub const FIREWALL_FILTERED_GET_FLN: &str = "firewall_filtered_get_fln";
pub const FIREWALL_FILTERED_CHECK_IS_BLOCKED: &str = "firewall_filtered_check_is_blocked";

/// Consensus node address identifier.
///
/// IDA layout evidence:
/// - outer discriminant at offset `+0`; tag `1` is `LocalNode`.
/// - `LocalNode` payload byte is at `+1`.
/// - `Ip` payload starts at `+1` and is delegated to `IpAddr` helpers by the
///   serializers at `0x45BC960` and `0x45BCD00`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum NodeIp {
    Ip(IpAddr),
    LocalNode(u8),
}

impl NodeIp {
    pub const LOCALHOST: Self = Self::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST));

    /// Recovered parser shape for config/profile strings.
    ///
    /// The binary strings prove externally-tagged `Ip`/`LocalNode` variants. The
    /// plain dotted/IP string path is used by `IpAddr` Display/serialization helpers.
    pub fn parse(value: &str) -> Result<Self, NodeIpParseError> {
        let value = value.trim();
        if value.is_empty() {
            return Err(NodeIpParseError::Empty);
        }

        if let Some(inner) = value.strip_prefix("LocalNode(").and_then(|s| s.strip_suffix(')')) {
            return parse_local_node(inner);
        }
        if let Some(inner) = value.strip_prefix("LocalNode:") {
            return parse_local_node(inner);
        }
        if let Some(inner) = value.strip_prefix("local:") {
            return parse_local_node(inner);
        }

        IpAddr::from_str(value)
            .map(Self::Ip)
            .map_err(|_| NodeIpParseError::InvalidIp)
    }

    pub fn is_local_node(self) -> bool {
        matches!(self, Self::LocalNode(_))
    }

    pub fn as_ip(self) -> Option<IpAddr> {
        match self {
            Self::Ip(ip) => Some(ip),
            Self::LocalNode(_) => None,
        }
    }

    pub fn as_ipv4(self) -> Option<Ipv4Addr> {
        match self {
            Self::Ip(IpAddr::V4(ip)) => Some(ip),
            _ => None,
        }
    }

    pub fn canonicalize_loopback(self) -> Self {
        match self {
            Self::Ip(IpAddr::V4(ip)) if ip.is_loopback() => Self::LocalNode(0),
            Self::Ip(IpAddr::V6(ip)) if ip.is_loopback() => Self::LocalNode(0),
            other => other,
        }
    }

    /// IDA: `0x45C3AE0` only transforms IPv4 packed `IpAddr` values; V6/local
    /// node values return unchanged through the odd-tag early return.
    pub fn firewall_filtered(self, map: &FirewallIpMap, prefer_private: bool) -> Self {
        match self {
            Self::Ip(IpAddr::V4(ip)) => Self::Ip(IpAddr::V4(map.translate(ip, prefer_private))),
            other => other,
        }
    }

    pub fn is_rfc1918_ipv4(self) -> bool {
        self.as_ipv4().is_some_and(is_private_v4_observed)
    }

    /// Human-readable form follows the helper used by the `Ip` serializer and the
    /// `LocalNode` debug/serializer variant name recovered from rodata.
    pub fn write_human_readable(self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::LocalNode(index) => write!(f, "LocalNode({index})"),
        }
    }
}

impl fmt::Display for NodeIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (*self).write_human_readable(f)
    }
}

fn parse_local_node(inner: &str) -> Result<NodeIp, NodeIpParseError> {
    let n = inner.trim().parse::<u8>().map_err(|_| NodeIpParseError::InvalidLocalNode)?;
    Ok(NodeIp::LocalNode(n))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeIpParseError {
    Empty,
    InvalidIp,
    InvalidLocalNode,
}

/// [INFERENCE] Prior struct notes named `NodeIpSignature`; current binary still
/// carries the `node_ip` field string in validator profile schemas and the
/// `payload=... signature=...` validation log, but no current `NodeIpSignature`
/// type-name string was present.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeIpSignature {
    pub node_ip: String,
    pub signature: SignatureBytes,
}

impl NodeIpSignature {
    pub fn parse_node_ip(&self) -> Result<NodeIp, NodeIpParseError> {
        NodeIp::parse(&self.node_ip)
    }

    pub fn into_verified_node_ip<V>(self, validator: ValidatorId, verifier: &V) -> Result<NodeIp, NodeIpSignatureError>
    where
        V: VerifyNodeIpSignature,
    {
        let node_ip = self.parse_node_ip().map_err(NodeIpSignatureError::Parse)?;
        if verifier.verify_node_ip_signature(&validator, &self.node_ip, &self.signature) {
            Ok(node_ip)
        } else {
            Err(NodeIpSignatureError::BadSignature)
        }
    }
}

pub trait VerifyNodeIpSignature {
    fn verify_node_ip_signature(
        &self,
        validator: &ValidatorId,
        node_ip_payload: &str,
        signature: &SignatureBytes,
    ) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeIpSignatureError {
    Parse(NodeIpParseError),
    BadSignature,
}

/// Private/public IPv4 mapping used by `firewall_filtered_check_is_blocked`.
///
/// IDA: `0x45C3AE0` reads a global pointer/count pair at `0x5786578/0x5786580`;
/// entries are 8 bytes, `{ private_ipv4_u32, public_ipv4_u32 }`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FirewallIpMap {
    private_to_public: BTreeMap<Ipv4Addr, Ipv4Addr>,
    public_to_private: BTreeMap<Ipv4Addr, Ipv4Addr>,
}

impl FirewallIpMap {
    pub fn new(entries: impl IntoIterator<Item = (Ipv4Addr, Ipv4Addr)>) -> Self {
        let mut map = Self::default();
        for (private, public) in entries {
            map.insert(private, public);
        }
        map
    }

    pub fn insert(&mut self, private: Ipv4Addr, public: Ipv4Addr) {
        self.private_to_public.insert(private, public);
        self.public_to_private.insert(public, private);
    }

    pub fn translate(&self, ip: Ipv4Addr, prefer_private: bool) -> Ipv4Addr {
        let private = is_private_v4_observed(ip);
        match (prefer_private, private) {
            (true, true) | (false, false) => ip,
            (true, false) => self.public_to_private.get(&ip).copied().unwrap_or(ip),
            (false, true) => self.private_to_public.get(&ip).copied().unwrap_or(ip),
        }
    }

    pub fn is_blocked(&self, ip: NodeIp, prefer_private: bool) -> bool {
        match ip {
            NodeIp::Ip(IpAddr::V4(v4)) => self.translate(v4, prefer_private) == v4
                && is_private_v4_observed(v4) != prefer_private,
            _ => false,
        }
    }
}

/// Exactly the RFC1918 checks observed in `0x45C3AE0`:
/// `10/8`, `172.16/12`, and `192.168/16`.
pub fn is_private_v4_observed(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    a == 10 || (a == 172 && (b & 0xf0) == 16) || (a == 192 && b == 168)
}

/// [INFERENCE] One validator-to-node-IP table plus its reverse indexes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodeIpBook {
    validator_to_ip: BTreeMap<ValidatorId, NodeIp>,
    ip_to_validator: BTreeMap<NodeIp, ValidatorId>,
    disabled_node_ips: BTreeSet<NodeIp>,
}

impl NodeIpBook {
    pub fn get(&self, validator: &ValidatorId) -> Option<NodeIp> {
        self.validator_to_ip.get(validator).copied()
    }

    pub fn validator_for(&self, node_ip: &NodeIp) -> Option<ValidatorId> {
        self.ip_to_validator.get(node_ip).copied()
    }

    pub fn contains_validator(&self, validator: &ValidatorId) -> bool {
        self.validator_to_ip.contains_key(validator)
    }

    pub fn upsert(&mut self, validator: ValidatorId, node_ip: NodeIp) -> Option<NodeIp> {
        if self.disabled_node_ips.contains(&node_ip) {
            return self.validator_to_ip.get(&validator).copied();
        }

        let previous = self.validator_to_ip.insert(validator, node_ip);
        if let Some(old) = previous {
            if self.ip_to_validator.get(&old).copied() == Some(validator) {
                self.ip_to_validator.remove(&old);
            }
        }
        self.ip_to_validator.insert(node_ip, validator);
        previous
    }

    pub fn remove_validator(&mut self, validator: &ValidatorId) -> Option<NodeIp> {
        let old = self.validator_to_ip.remove(validator)?;
        if self.ip_to_validator.get(&old).copied().as_ref() == Some(validator) {
            self.ip_to_validator.remove(&old);
        }
        Some(old)
    }

    pub fn disable_node_ip(&mut self, node_ip: NodeIp) -> Option<ValidatorId> {
        self.disabled_node_ips.insert(node_ip);
        let validator = self.ip_to_validator.remove(&node_ip)?;
        self.validator_to_ip.remove(&validator);
        Some(validator)
    }

    pub fn apply_signed_update<V>(
        &mut self,
        validator: ValidatorId,
        signed: NodeIpSignature,
        verifier: &V,
    ) -> Result<Option<NodeIp>, NodeIpSignatureError>
    where
        V: VerifyNodeIpSignature,
    {
        let node_ip = signed.into_verified_node_ip(validator, verifier)?;
        Ok(self.upsert(validator, node_ip))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&ValidatorId, &NodeIp)> {
        self.validator_to_ip.iter()
    }
}

/// [INFERENCE] IDA: `0x45C3D20` returns three 24-byte collections; `0x45C42B0`
/// copies the 0x48-byte value out and optionally logs when fallback untrusted
/// IPs were used.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodeIpUpdate {
    pub trusted: Vec<(ValidatorId, NodeIp)>,
    pub firewall_filtered: Vec<(ValidatorId, NodeIp)>,
    pub untrusted_fallback: Vec<(ValidatorId, NodeIp)>,
}

impl NodeIpUpdate {
    pub fn is_empty(&self) -> bool {
        self.trusted.is_empty() && self.firewall_filtered.is_empty() && self.untrusted_fallback.is_empty()
    }

    pub fn missing_node_ips_used(&self) -> bool {
        !self.untrusted_fallback.is_empty()
    }
}

/// Recovered high-level behavior of `0x45C3D20` + seed wrapper `0x45C42B0`.
///
/// `mode == 3` is the observed logging mode (`cmp dl, 3` at `0x45C42CD`). When a
/// validator is active but missing from the filtered map, the binary keeps the node
/// usable by inserting it into the untrusted fallback collection and emits the long
/// warning anchored at `0x6F7EDE`.
pub fn update_node_ips_with_firewall_fallback(
    active_validators: impl IntoIterator<Item = ValidatorId>,
    proposed_ips: &BTreeMap<ValidatorId, NodeIp>,
    current_book: &NodeIpBook,
    firewall: &FirewallIpMap,
    prefer_private: bool,
    mode: u8,
) -> (NodeIpBook, NodeIpUpdate) {
    let mut next = current_book.clone();
    let mut update = NodeIpUpdate::default();

    for validator in active_validators {
        let Some(proposed) = proposed_ips.get(&validator).copied() else {
            continue;
        };

        let filtered = proposed.firewall_filtered(firewall, prefer_private);
        if !firewall.is_blocked(proposed, prefer_private) {
            next.upsert(validator, filtered);
            update.trusted.push((validator, filtered));
        } else {
            update.firewall_filtered.push((validator, filtered));
            update.untrusted_fallback.push((validator, proposed));
            if mode == 3 {
                next.upsert(validator, proposed);
            }
        }
    }

    (next, update)
}

/// Thin helper corresponding to the string-named `firewall_filtered_get_fln` path.
/// The caller owns logging; this returns the exact condition and payload observed by
/// the seed wrapper.
pub fn firewall_filtered_get_fln(update: &NodeIpUpdate, mode: u8) -> Option<(&'static str, &[(ValidatorId, NodeIp)])> {
    if mode == 3 && update.missing_node_ips_used() {
        Some((FIREWALL_FILTERED_GET_FLN, &update.untrusted_fallback))
    } else {
        None
    }
}

