//! Reconstruction of `/home/ubuntu/hl/code_Mainnet/node/src/consensus/config.rs`.
//!
//! Confidence: medium for the validator/node-ip validation path, lower for the
//! opaque service handles copied into the returned configuration. Seed expanded:
//!
//! - `0x284A5A0` — constructor/builder for the local validator consensus config.
//!   Disassembly anchors:
//!   - `0x284A5BC..0x284A842`: copies the signer validator address from
//!     `signer + 0x80`, walks the `StaticConfig.node_ips` BTree tree at
//!     `static_config + 0xA48`, and panics if the validator address is absent.
//!   - `0x284A867..0x284ACB3`: reads `static_config + 0x8F2` as the public-ip
//!     validation flag, queries the host public IP, logs
//!     `could not get public ip, not validating against abci state: ...`, and
//!     checks the configured `node_ips` value.
//!   - `0x284AB6A..0x284ABED`: panics with
//!     `public_ip does not match abci state. public_ip=... abci_node_ip=...`
//!     when validation is enabled and the configured node IP is not exactly the
//!     discovered IPv4 address.
//!   - `0x284AE05..0x284AFAA`: clones the signer/config fragments, constructs an
//!     `Arc`-backed `node_ips` handle labelled by the literal `node_ips`, and
//!     returns the assembled config object.
//! - Adjacent helpers:
//!   - `0x284B1E0` / `0x284B430` / `0x284B550` / `0x284B660` format/compare the
//!     node-ip enum family; rodata contains the variant names `Error`, `Ip`, and
//!     `LocalNode`.
//!
//! IDA-DEFERRED: the server queue was full. Pending annotations:
//! - rename `0x284A5A0` -> `node_consensus_config__build_for_validator_from_static_config`
//! - comment `0x284A5A0` with the builder/validation summary above
//! - rename `0x284B430` -> `node_consensus_config__node_ip_eq_ignore_ascii_case`
//! - declare `hl_node_consensus_Config`, `hl_node_consensus_StaticConfig`, and
//!   `hl_node_consensus_StaticNodeIp` once IDA accepts type writes.

use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::Arc;

/// Offset constants observed in `0x284A5A0`.
pub const STATIC_CONFIG_VALIDATE_PUBLIC_IP_OFFSET: usize = 0x8f2;
pub const STATIC_CONFIG_ABCI_STATE_OFFSET: usize = 0x8f8;
pub const STATIC_CONFIG_NODE_IPS_OFFSET: usize = 0x0a48;
pub const SIGNER_VALIDATOR_ADDRESS_OFFSET: usize = 0x80;
pub const SIGNER_CONFIG_COPY_LEN: usize = 0x98;
pub const RETURNED_CONFIG_PREFIX_LEN: usize = 0x138;
pub const NODE_IPS_HANDLE_LABEL: &str = "node_ips";

/// Local validator address copied from the signer object at `signer + 0x80`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ValidatorAddress(pub [u8; 20]);

impl fmt::Display for ValidatorAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Compact consensus node-ip value stored as the `BTreeMap<ValidatorAddress, _>`
/// value in `StaticConfig.node_ips`.
///
/// `0x284A80C..0x284A817` copies one tag byte plus one `u32` payload from the map
/// entry. `0x284AB6A..0x284AB75` only accepts the `Ip` tag for public-ip
/// validation; any non-`Ip` value is treated as a mismatch when validation is on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticNodeIp {
    /// Observed validation tag `0`: payload is an IPv4 address as a host-order `u32`.
    Ip(Ipv4Addr),
    /// Adjacent formatter rodata exposes this variant name. Payload meaning is
    /// still opaque; it is preserved so validation can reject it faithfully.
    Error(u32),
    /// Adjacent formatter rodata exposes this variant name. The payload is likely
    /// a local validator ordinal or local-node selector.
    LocalNode(u32),
    /// Forward-compatible preservation for not-yet-observed tags.
    Unknown { tag: u8, payload: u32 },
}

impl StaticNodeIp {
    pub fn from_compact(tag: u8, payload: u32) -> Self {
        match tag {
            0 => Self::Ip(Ipv4Addr::from(payload.to_ne_bytes())),
            1 => Self::Error(payload),
            2 => Self::LocalNode(payload),
            tag => Self::Unknown { tag, payload },
        }
    }

    pub fn compact(self) -> (u8, u32) {
        match self {
            Self::Ip(ip) => (0, u32::from_ne_bytes(ip.octets())),
            Self::Error(payload) => (1, payload),
            Self::LocalNode(payload) => (2, payload),
            Self::Unknown { tag, payload } => (tag, payload),
        }
    }

    pub fn as_ipv4(self) -> Option<Ipv4Addr> {
        match self {
            Self::Ip(ip) => Some(ip),
            Self::Error(_) | Self::LocalNode(_) | Self::Unknown { .. } => None,
        }
    }
}

impl fmt::Display for StaticNodeIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Ip(ip) => write!(f, "Ip({ip})"),
            Self::Error(code) => write!(f, "Error({code})"),
            Self::LocalNode(ordinal) => write!(f, "LocalNode({ordinal})"),
            Self::Unknown { tag, payload } => write!(f, "Unknown(tag={tag}, payload={payload})"),
        }
    }
}

/// Minimal source-level shape for the static consensus config fields touched by
/// `0x284A5A0`.
#[derive(Clone, Debug)]
pub struct StaticConsensusConfig {
    /// Backed by the tree walked from `static_config + 0xA48`.
    pub node_ips: BTreeMap<ValidatorAddress, StaticNodeIp>,
    /// Byte read at `static_config + 0x8F2`.
    pub validate_public_ip: bool,
    /// Opaque state/options block rooted at `static_config + 0x8F8` and passed to
    /// helper callees while constructing the returned config.
    pub abci_state_options: AbciStateOptions,
}

#[derive(Clone, Debug, Default)]
pub struct AbciStateOptions {
    pub _unknown_field_at_0x000: Vec<u8>,
}

/// The signer/config fragment copied from the second constructor argument.
///
/// The binary copies `0x98` bytes into the returned config and reads the local
/// validator address at offset `0x80`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorSignerConfig {
    pub _unknown_field_at_0x000: [u8; SIGNER_VALIDATOR_ADDRESS_OFFSET],
    pub validator_address: ValidatorAddress,
    pub _unknown_field_at_0x094: [u8; SIGNER_CONFIG_COPY_LEN - SIGNER_VALIDATOR_ADDRESS_OFFSET - 20],
}

impl ValidatorSignerConfig {
    pub fn from_recovered_bytes(bytes: [u8; SIGNER_CONFIG_COPY_LEN]) -> Self {
        let mut prefix = [0u8; SIGNER_VALIDATOR_ADDRESS_OFFSET];
        prefix.copy_from_slice(&bytes[..SIGNER_VALIDATOR_ADDRESS_OFFSET]);

        let mut address = [0u8; 20];
        address.copy_from_slice(
            &bytes[SIGNER_VALIDATOR_ADDRESS_OFFSET..SIGNER_VALIDATOR_ADDRESS_OFFSET + 20],
        );

        let mut suffix = [0u8; SIGNER_CONFIG_COPY_LEN - SIGNER_VALIDATOR_ADDRESS_OFFSET - 20];
        suffix.copy_from_slice(&bytes[SIGNER_VALIDATOR_ADDRESS_OFFSET + 20..]);

        Self {
            _unknown_field_at_0x000: prefix,
            validator_address: ValidatorAddress(address),
            _unknown_field_at_0x094: suffix,
        }
    }
}

/// Arc-backed handle allocated near `0x284AEB3` after the `node_ips` label is
/// passed to the helper at `0x258AD80`.
#[derive(Clone, Debug)]
pub struct NodeIpsHandle {
    pub label: &'static str,
    pub home_validator: ValidatorAddress,
    pub entries: BTreeMap<ValidatorAddress, StaticNodeIp>,
    pub expected_home_node_ip: StaticNodeIp,
}

#[derive(Clone, Debug)]
pub struct ConsensusConfig {
    /// Stored at returned offset `+0x00` as an `Arc` allocation.
    pub node_ips_handle: Arc<NodeIpsHandle>,
    /// Copied from the signer argument at returned offset `+0x08..+0xA0`.
    pub signer: ValidatorSignerConfig,
    /// Options assembled by the opaque helpers before the final copy into
    /// returned offsets `+0xA0..+0x120`.
    pub runtime_options: ConsensusRuntimeOptions,
    /// Stored at returned offset `+0x120..+0x134`.
    pub home_validator: ValidatorAddress,
    /// Stored at returned offset `+0x134`.
    pub validate_public_ip: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ConsensusRuntimeOptions {
    pub public_ip_seen_at_startup: Option<Ipv4Addr>,
    pub abci_state_options: AbciStateOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsensusConfigError {
    ValidatorMissingFromNodeIps { validator: ValidatorAddress },
    PublicIpMismatch { public_ip: Ipv4Addr, abci_node_ip: StaticNodeIp },
}

impl fmt::Display for ConsensusConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::ValidatorMissingFromNodeIps { validator } => {
                write!(f, "validator is not in node_ips: {validator}")
            }
            Self::PublicIpMismatch { public_ip, abci_node_ip } => write!(
                f,
                "public_ip does not match abci state. public_ip={public_ip} abci_node_ip={abci_node_ip}"
            ),
        }
    }
}

impl std::error::Error for ConsensusConfigError {}

impl ConsensusConfig {
    /// Source-level reconstruction of `0x284A5A0`.
    ///
    /// The original code panics for a missing validator and for a mismatched
    /// public IP. This version returns the same failures as `Err` so callers can
    /// test the recovered logic without relying on panic formatting.
    pub fn build_for_validator_from_static_config(
        static_config: &StaticConsensusConfig,
        signer: ValidatorSignerConfig,
        public_ip_result: Result<Ipv4Addr, String>,
    ) -> Result<Self, ConsensusConfigError> {
        let home_validator = signer.validator_address;
        let expected_home_node_ip = static_config
            .node_ips
            .get(&home_validator)
            .copied()
            .ok_or(ConsensusConfigError::ValidatorMissingFromNodeIps {
                validator: home_validator,
            })?;

        let public_ip_seen_at_startup = match public_ip_result {
            Ok(public_ip) => {
                if static_config.validate_public_ip
                    && expected_home_node_ip.as_ipv4() != Some(public_ip)
                {
                    return Err(ConsensusConfigError::PublicIpMismatch {
                        public_ip,
                        abci_node_ip: expected_home_node_ip,
                    });
                }
                Some(public_ip)
            }
            Err(_message) => {
                // `0x284A990..0x284AA67` keeps building the config after logging
                // `could not get public ip, not validating against abci state: ...`.
                None
            }
        };

        let runtime_options = ConsensusRuntimeOptions {
            public_ip_seen_at_startup,
            abci_state_options: static_config.abci_state_options.clone(),
        };

        let node_ips_handle = Arc::new(NodeIpsHandle {
            label: NODE_IPS_HANDLE_LABEL,
            home_validator,
            entries: static_config.node_ips.clone(),
            expected_home_node_ip,
        });

        Ok(Self {
            node_ips_handle,
            signer,
            runtime_options,
            home_validator,
            validate_public_ip: static_config.validate_public_ip,
        })
    }

    /// Panic-preserving wrapper matching the binary's startup behavior.
    pub fn expect_for_validator_from_static_config(
        static_config: &StaticConsensusConfig,
        signer: ValidatorSignerConfig,
        public_ip_result: Result<Ipv4Addr, String>,
    ) -> Self {
        match Self::build_for_validator_from_static_config(static_config, signer, public_ip_result) {
            Ok(config) => config,
            Err(error) => panic!("{error}"),
        }
    }
}
