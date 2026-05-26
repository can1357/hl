//! Reconstructed from `/home/ubuntu/hl/code_Mainnet/net_utils/src/node_port.rs`.
//!
//! Confidence: high for the six discriminants, base-port constants, and checked
//! validator offset formula; medium for variant names except
//! `GossipRpcRequests`, which is anchored by the recovered listener label
//! `gossip_rpc_requests`; low for the semantic names of the two 3998/3999
//! service ports.
//!
//! Seeds expanded: `0x1FD4570`, `0x2037AC0`, `0x2039060`, `0x22C54A0`,
//! `0x43831E0`, `0x43848F0`, `0x4387F40`, `0x438ED70`, `0x454C2B0`,
//! `0x47B4950`.
//!
//! IDA anchors used:
//! - `0x438ED70`: monomorphized `NodePort::listen` future; references the
//!   `NodePort::listen` and `gossip_rpc_requests` strings. Its jump table maps
//!   discriminants `0..=5` to base ports `4001`, `4002`, `4003`, `4004`,
//!   `3998`, and `3999`.
//! - `0x47B4950`: second concrete `NodePort::listen` poll body with a different
//!   state layout; independently confirms the same six-way port jump table,
//!   the `gossip_rpc_requests` label, and the `validator_index * 1000` offset.
//! - `0x4387F40`: listener/connect path for discriminant `1`; computes
//!   `4002 + validator_index * 1000` with checked multiply/add before writing
//!   the packed IPv4 socket address fields.
//! - `0x454C2B0`: consensus-network spawn/listener wrapper for discriminant
//!   `2`; computes `4003 + validator_index * 1000` and routes arithmetic
//!   overflow to panic blocks near `0x454C47B`/`0x454C48D`.
//! - `0x43848F0`: listener/connect path for discriminant `3`; computes
//!   `4004 + validator_index * 1000`, binds validator-index mode to
//!   `127.0.0.1`, and otherwise preserves the packed peer IPv4 address.
//! - `0x22C54A0`: shared listen-with-retry future used by the node-port listen
//!   path; it constructs the endpoint, logs the `@@ trying @@ [ip: ...]` line,
//!   and calls the TCP bind/listen helper.
//! - `0x2039060`: outbound gossip RPC connect/send/receive retry state machine;
//!   uses node-port-derived peer endpoints before framed TCP request I/O.
//! - `0x1FD4570`: higher-level gossip RPC caller around `0x2039060`; uses the
//!   node-port endpoint selected for verified gossip RPC requests.
//! - `0x2037AC0` and `0x43831E0`: shared TCP framed I/O/ABCI-stream helpers
//!   reached from this source path; no additional enum constants recovered.
//!
//! IDA writes attempted in this worker: intended type `hl_net_utils_NodePort`
//! and names/comments `net_utils_node_port__listen_poll_gossip_rpc_requests`,
//! `net_utils_node_port__listen_poll_confirmed`,
//! `net_utils_node_port__connect_or_listen_gossip_rpc_requests`,
//! `net_utils_node_port__spawn_consensus_listener`,
//! `net_utils_node_port__connect_or_listen_consensus_rpc`. The shared IDA
//! foreground queue remained full, so these tags could not be committed here.

#![allow(dead_code)]

use std::convert::TryFrom;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub const GOSSIP_PORT: u16 = 4001;
pub const GOSSIP_RPC_REQUESTS_PORT: u16 = 4002;
pub const CONSENSUS_PORT: u16 = 4003;
pub const CONSENSUS_RPC_PORT: u16 = 4004;
pub const AUXILIARY_PORT_0: u16 = 3998;
pub const AUXILIARY_PORT_1: u16 = 3999;
pub const VALIDATOR_PORT_STRIDE: u16 = 1000;

const LOCAL_VALIDATOR_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

/// Protocol listener selector used by node networking code.
///
/// The recovered enum is stored as a one-byte discriminant. `NodePort::listen`
/// uses this discriminant as an index into a six-entry port table, then applies
/// `validator_index * 1000` when the endpoint selector requests a local
/// validator instance.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NodePort {
    /// Public gossip/peer-sync port.
    Gossip = 0,
    /// Secondary gossip RPC request listener; string label `gossip_rpc_requests`.
    GossipRpcRequests = 1,
    /// Primary validator consensus listener.
    Consensus = 2,
    /// Local validator consensus RPC listener used by reconnecting clients.
    ConsensusRpc = 3,
    /// [INFERENCE] Internal service port observed in the same jump table.
    Auxiliary0 = 4,
    /// [INFERENCE] Internal service port observed in the same jump table.
    Auxiliary1 = 5,
}

impl NodePort {
    pub const ALL: [NodePort; 6] = [
        NodePort::Gossip,
        NodePort::GossipRpcRequests,
        NodePort::Consensus,
        NodePort::ConsensusRpc,
        NodePort::Auxiliary0,
        NodePort::Auxiliary1,
    ];

    #[inline]
    pub const fn discriminant(self) -> u8 {
        self as u8
    }

    #[inline]
    pub const fn from_discriminant(discriminant: u8) -> Option<Self> {
        match discriminant {
            0 => Some(NodePort::Gossip),
            1 => Some(NodePort::GossipRpcRequests),
            2 => Some(NodePort::Consensus),
            3 => Some(NodePort::ConsensusRpc),
            4 => Some(NodePort::Auxiliary0),
            5 => Some(NodePort::Auxiliary1),
            _ => None,
        }
    }

    #[inline]
    pub const fn base_port(self) -> u16 {
        match self {
            NodePort::Gossip => GOSSIP_PORT,
            NodePort::GossipRpcRequests => GOSSIP_RPC_REQUESTS_PORT,
            NodePort::Consensus => CONSENSUS_PORT,
            NodePort::ConsensusRpc => CONSENSUS_RPC_PORT,
            NodePort::Auxiliary0 => AUXILIARY_PORT_0,
            NodePort::Auxiliary1 => AUXILIARY_PORT_1,
        }
    }

    #[inline]
    pub const fn from_base_port(port: u16) -> Option<Self> {
        match port {
            GOSSIP_PORT => Some(NodePort::Gossip),
            GOSSIP_RPC_REQUESTS_PORT => Some(NodePort::GossipRpcRequests),
            CONSENSUS_PORT => Some(NodePort::Consensus),
            CONSENSUS_RPC_PORT => Some(NodePort::ConsensusRpc),
            AUXILIARY_PORT_0 => Some(NodePort::Auxiliary0),
            AUXILIARY_PORT_1 => Some(NodePort::Auxiliary1),
            _ => None,
        }
    }

    #[inline]
    pub const fn name(self) -> &'static str {
        match self {
            NodePort::Gossip => "gossip",
            NodePort::GossipRpcRequests => "gossip_rpc_requests",
            NodePort::Consensus => "consensus",
            NodePort::ConsensusRpc => "consensus_rpc",
            NodePort::Auxiliary0 => "auxiliary_0",
            NodePort::Auxiliary1 => "auxiliary_1",
        }
    }

    #[inline]
    pub const fn is_gossip(self) -> bool {
        matches!(self, NodePort::Gossip | NodePort::GossipRpcRequests)
    }

    #[inline]
    pub const fn is_consensus(self) -> bool {
        matches!(self, NodePort::Consensus | NodePort::ConsensusRpc)
    }

    #[inline]
    pub const fn is_auxiliary(self) -> bool {
        matches!(self, NodePort::Auxiliary0 | NodePort::Auxiliary1)
    }

    /// Return the concrete TCP port for the endpoint selector.
    ///
    /// In local-validator mode the binary checks both the multiplication by
    /// `1000` and the final addition before narrowing the result to the socket
    /// port field. The same checked behavior is preserved here.
    #[inline]
    pub fn port_for(self, endpoint: NodePortEndpoint) -> Result<u16, NodePortError> {
        match endpoint {
            NodePortEndpoint::Ip(_) => Ok(self.base_port()),
            NodePortEndpoint::LocalValidator { validator_index } => {
                self.validator_port(validator_index)
            }
        }
    }

    #[inline]
    pub fn validator_port(self, validator_index: u16) -> Result<u16, NodePortError> {
        let offset = VALIDATOR_PORT_STRIDE
            .checked_mul(validator_index)
            .ok_or(NodePortError::PortOverflow {
                node_port: self,
                validator_index,
            })?;
        self.base_port()
            .checked_add(offset)
            .ok_or(NodePortError::PortOverflow {
                node_port: self,
                validator_index,
            })
    }

    #[inline]
    pub fn socket_addr(self, endpoint: NodePortEndpoint) -> Result<SocketAddr, NodePortError> {
        let ip = match endpoint {
            NodePortEndpoint::Ip(ip) => ip,
            NodePortEndpoint::LocalValidator { .. } => IpAddr::V4(LOCAL_VALIDATOR_IP),
        };
        Ok(SocketAddr::new(ip, self.port_for(endpoint)?))
    }
}

impl TryFrom<u8> for NodePort {
    type Error = NodePortError;

    #[inline]
    fn try_from(discriminant: u8) -> Result<Self, Self::Error> {
        Self::from_discriminant(discriminant).ok_or(NodePortError::UnknownDiscriminant(discriminant))
    }
}

impl From<NodePort> for u8 {
    #[inline]
    fn from(node_port: NodePort) -> Self {
        node_port.discriminant()
    }
}

impl TryFrom<u16> for NodePort {
    type Error = NodePortError;

    #[inline]
    fn try_from(port: u16) -> Result<Self, Self::Error> {
        Self::from_base_port(port).ok_or(NodePortError::UnknownBasePort(port))
    }
}

impl fmt::Display for NodePort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Address selector passed into the recovered node-port endpoint builder.
///
/// The concrete binary packs this in a small scalar: a low-bit flag selects the
/// local-validator path, while the non-flag path carries an IPv4 peer address.
/// The exact packed integer layout was not needed by the call sites recovered in
/// this wave, so the Rust reconstruction keeps the lossless semantic form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePortEndpoint {
    Ip(IpAddr),
    LocalValidator { validator_index: u16 },
}

impl NodePortEndpoint {
    #[inline]
    pub const fn localhost_validator(validator_index: u16) -> Self {
        Self::LocalValidator { validator_index }
    }

    #[inline]
    pub const fn ipv4(ip: Ipv4Addr) -> Self {
        Self::Ip(IpAddr::V4(ip))
    }

    /// Decode the non-validator IPv4 form observed in the packed endpoint path.
    ///
    /// The disassembly writes the stored IPv4 bytes directly into the socket
    /// address; the constant for local validator mode is `0x0100007f`, i.e.
    /// `127.0.0.1` after little-endian storage.
    #[inline]
    pub fn from_ipv4_le(raw: u32) -> Self {
        Self::Ip(IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes())))
    }
}

impl From<IpAddr> for NodePortEndpoint {
    #[inline]
    fn from(ip: IpAddr) -> Self {
        Self::Ip(ip)
    }
}

impl From<Ipv4Addr> for NodePortEndpoint {
    #[inline]
    fn from(ip: Ipv4Addr) -> Self {
        Self::Ip(IpAddr::V4(ip))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePortError {
    UnknownDiscriminant(u8),
    UnknownBasePort(u16),
    PortOverflow {
        node_port: NodePort,
        validator_index: u16,
    },
}

impl fmt::Display for NodePortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodePortError::UnknownDiscriminant(discriminant) => {
                write!(f, "unknown NodePort discriminant {discriminant}")
            }
            NodePortError::UnknownBasePort(port) => write!(f, "unknown NodePort base port {port}"),
            NodePortError::PortOverflow {
                node_port,
                validator_index,
            } => write!(
                f,
                "NodePort {node_port} overflows u16 port range for validator index {validator_index}",
            ),
        }
    }
}

impl std::error::Error for NodePortError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovered_base_ports_follow_discriminant_order() {
        let ports: Vec<u16> = NodePort::ALL.iter().copied().map(NodePort::base_port).collect();
        assert_eq!(ports, [4001, 4002, 4003, 4004, 3998, 3999]);
    }

    #[test]
    fn validator_ports_use_thousand_port_stride() {
        assert_eq!(NodePort::GossipRpcRequests.validator_port(2), Ok(6002));
        assert_eq!(NodePort::ConsensusRpc.validator_port(1), Ok(5004));
    }

    #[test]
    fn validator_port_overflow_is_checked() {
        assert!(matches!(
            NodePort::ConsensusRpc.validator_port(62),
            Err(NodePortError::PortOverflow { .. })
        ));
    }
}
