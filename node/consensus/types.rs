//! Reconstruction of `/home/ubuntu/hl/code_Mainnet/node/src/consensus/types.rs`.
//!
//! Confidence: Medium. These consensus wire/message shapes are adjacent to
//! `node/src/consensus/rpc.rs` and are recovered from serializer/debug strings around
//! `0x3969010..0x396BC00` plus the rpc task strings used by seeds
//! `0x43848F0`, `0x47B05F0`, `0x47B3F50`, and `0x4B33EB0`.
//!
//! IDA type names intended/applied when the IDA queue is available:
//!   - `hl_node_consensus_ConsensusRpcRequest`
//!   - `hl_node_consensus_ConsensusRpcResponse`
//!   - `hl_node_consensus_Block`, `hl_node_consensus_Timeout`, `hl_node_consensus_Tc`
//!   - `hl_node_consensus_SignedTimeout`, `hl_node_consensus_ValidatorSetSnapshot`

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;

pub type Round = u64;
pub type ValidatorIndex = u32;
pub type NodeIp = String;
pub type TxHash = [u8; 32];
pub type BlockHash = [u8; 32];
pub type AppHash = [u8; 32];
pub type SignatureBytes = [u8; 65];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signed<T> {
    /// IDA: `Signed` at `sub_396BC00`, content field starts at +0x00.
    pub content: T,
    /// IDA: signature starts at +0x70 for one observed monomorph.
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuorumCertificate {
    pub block_hash: BlockHash,
    pub round: Round,
    pub signatures: Vec<(ValidatorIndex, SignatureBytes)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Timeout {
    /// IDA: `Timeout` serializers `sub_3969010` / `sub_39697A0` carry qc, validator and round.
    pub qc: Option<QuorumCertificate>,
    pub validator: ValidatorIndex,
    pub round: Round,
}

pub type SignedTimeout = Signed<Timeout>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeoutCertificate {
    /// IDA: `Tc` (`sub_396AB40`) field +0x00 is `signed_timeouts`, +0x18 is `round`.
    pub signed_timeouts: Vec<SignedTimeout>,
    pub round: Round,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsensusBlock {
    /// IDA: `Block` serializers `sub_3969FB0` / `sub_396A960` mention proposer, round, tx_hashes, time, qc, tc.
    pub proposer: ValidatorIndex,
    pub round: Round,
    pub tx_hashes: Vec<TxHash>,
    pub time_millis: u64,
    pub qc: Option<QuorumCertificate>,
    pub tc: Option<TimeoutCertificate>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientBlock {
    pub block: ConsensusBlock,
    pub block_hash: BlockHash,
    pub app_hash: Option<AppHash>,
    pub commit_proof: Option<QuorumCertificate>,
    pub tx_commit_proofs: Vec<QuorumCertificate>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorSetSnapshot {
    /// IDA: `ValidatorSetSnapshot` at `sub_39F39F0` has stakes at +0 and jailed_validators at +0x20.
    pub stakes: BTreeMap<ValidatorIndex, u64>,
    pub jailed_validators: BTreeSet<ValidatorIndex>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConciseLtHashes {
    pub accounts_hash: [u8; 32],
    pub contracts_hash: [u8; 32],
    pub storage_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeartbeatSnapshot {
    pub validator_set_snapshot: ValidatorSetSnapshot,
    pub evm_block_number: u64,
    pub concise_lt_hashes: ConciseLtHashes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerInfo {
    pub validator: ValidatorIndex,
    pub node_ip: NodeIp,
    pub addr: Option<SocketAddr>,
    pub verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerResponse {
    pub peers: Vec<PeerInfo>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestContent {
    /// The validator that should service the request. `None` is used for peer fanout/round-robin.
    pub validator: Option<ValidatorIndex>,
    pub request: ConsensusRpcRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsensusRpcRequest {
    /// Observed string: `rpc_task_get_peers`.
    GetPeers,
    /// Observed seed behavior: `make_rpc_request_get_node_ip` builds this request to resolve a validator.
    GetNodeIp { validator: ValidatorIndex },
    /// Pull client blocks after a round during bootstrap or repair.
    /// Strings: `client blocks first=`, `last=`, `RpcPeerNoClientBlocks`.
    GetClientBlocks { after_round: Round, max_blocks: u32 },
    /// Publish one signed block to the remote validator.
    PublishBlock { block_hash: BlockHash, signed_block: Signed<ConsensusBlock> },
    /// Publish one signed timeout to the remote validator.
    PublishTimeout(SignedTimeout),
    /// Publish a timeout certificate once enough signed timeouts are collected.
    PublishTc(TimeoutCertificate),
    /// Fallback for not-yet-reconstructed bincode tags. Keeping the raw tag preserves dispatch behavior.
    Unknown { tag: u64, bytes: Vec<u8> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsensusRpcResponse {
    Peers(PeerResponse),
    NodeIp(Option<NodeIp>),
    ClientBlocks(Vec<ClientBlock>),
    Ack,
    Error(ConsensusRpcError),
    Unknown { tag: u64, bytes: Vec<u8> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsensusRpcError {
    Error(String),
    SignableContent,
    VerifySignature,
    VerifyQcSignature,
    BadBlockRound { block_round: Round, last_commit_round: Round },
    BadBlockQcRound,
    BadBlockTcRound,
    BlockAlreadyRegistered,
    QcRoundBeforeHardfork,
    QcNoQuorum,
    TcNoQuorum,
    TcNoTimeout,
    EmptyValidators,
    DuplicateBlockRound,
    TimeoutRoundMismatch,
    AlreadyHaveTimeoutFromNode,
    RpcNotFound,
    RpcRoundRobin,
    RpcPeerNoClientBlocks,
    ClientBlockQcRound,
    ClientBlockQcHash,
    ClientBlockTx,
    ClientBlockTxHashes,
    ClientBlockTime,
    ClientBlockMissingCommitProof,
    ClientBlockMissingTxCommitProof,
    ChildQcCommitProof,
    GrandchildQcCommitProof,
    Consecutive,
    PeerTimedOut,
    IncorrectRpcResponseVariant,
}

#[derive(Clone, Debug)]
pub struct ConsensusRpcConfig {
    pub bind_addr: SocketAddr,
    pub timeout_millis: u64,
    pub max_client_blocks_per_response: u32,
    pub override_c_signers_path: Option<String>,
}

impl Default for ConsensusRpcConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], 4003)),
            timeout_millis: 10_000,
            max_client_blocks_per_response: 1_000,
            override_c_signers_path: Some("/override_consensus_rpc_c_signers.json".to_owned()),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RpcSizeStats {
    pub inbound_bytes: u64,
    pub outbound_bytes: u64,
    pub response_bytes: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ConsensusRpcMaps {
    /// Spawn path string evidence: `hash_to_tx` / `rpc_hash_to_tx`.
    pub hash_to_tx: HashMap<TxHash, Vec<u8>>,
    /// Spawn path string evidence: `hash_to_block` / `rpc_hash_to_block`.
    pub hash_to_block: HashMap<BlockHash, ConsensusBlock>,
}
