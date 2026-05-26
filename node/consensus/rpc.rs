//! Reconstruction of `/home/ubuntu/hl/code_Mainnet/node/src/consensus/rpc.rs`.
//!
//! Confidence: Medium for task topology, string-driven dispatch, and error names; Low-to-Medium for
//! exact Rust type names because the assigned seeds are optimized async poll functions.
//!
//! Seeds expanded:
//!   - `0x43848F0` — large consensus RPC driver/bootstrap poll. String anchors:
//!     `make_rpc_request_get_node_ip`, `node_rpc_request`, `BUG: unknown validator:`,
//!     `client blocks first=`, `last=`, `@@ finished bootstrap @@ [start_round: ...]`.
//!   - `0x47B05F0` — outbound RPC future poll. Calls the request future at `0x4553EB0`,
//!     installs timeout state, logs ` -> ... : rpc`, and records `Peer response` / `Peer timed out`.
//!   - `0x47B3F50` — peer response/update future poll. Calls `0x4553910`, updates the peer table,
//!     and enters `rpc_task_get_peers` / peer timeout accounting.
//!   - `0x4B33EB0` — inbound/server RPC task poll. String anchors: `Rpc task inbound`,
//!     `Incoming tcp stream`, `Received rpc request`, `send consensus rpc resp`,
//!     `Failed to receive response from rpc task`, `override_consensus_rpc_c_signers.json`.
//!
//! IDA names intended/applied when the shared IDA queue is available:
//!   - `node_consensus_rpc__poll_driver_bootstrap` for `0x43848F0`
//!   - `node_consensus_rpc__poll_outbound_request` for `0x47B05F0`
//!   - `node_consensus_rpc__poll_peer_response_update` for `0x47B3F50`
//!   - `node_consensus_rpc__poll_inbound_server` for `0x4B33EB0`

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::types::{
    BlockHash, ClientBlock, ConsensusBlock, ConsensusRpcConfig, ConsensusRpcError, ConsensusRpcMaps,
    ConsensusRpcRequest, ConsensusRpcResponse, NodeIp, PeerInfo, PeerResponse, RequestContent,
    Round, RpcSizeStats, ValidatorIndex,
};

/// Status kept for each main validator connection.
///
/// String evidence: `rpc_clone_main_validators`, `Peer response`, `Peer timed out`.
#[derive(Clone, Debug)]
pub struct ConsensusRpcPeer {
    pub validator: ValidatorIndex,
    pub node_ip: NodeIp,
    pub addr: SocketAddr,
    pub verified: bool,
    pub last_response: Option<Instant>,
    pub consecutive_timeouts: u32,
}

#[derive(Clone, Debug)]
pub struct PendingRpcRequest {
    pub peer: ValidatorIndex,
    pub content: RequestContent,
    pub deadline: Instant,
    pub attempts: u32,
}

#[derive(Clone, Debug)]
pub struct InboundRpcRequest {
    pub peer: Option<ValidatorIndex>,
    pub content: RequestContent,
    pub payload_len: usize,
}

#[derive(Clone, Debug)]
pub struct OutboundRpcResponse {
    pub peer: ValidatorIndex,
    pub response: ConsensusRpcResponse,
    pub payload_len: usize,
}

#[derive(Debug)]
pub struct ConsensusRpcState {
    pub config: ConsensusRpcConfig,
    pub peers: HashMap<ValidatorIndex, ConsensusRpcPeer>,
    pub node_ip_to_validator: HashMap<NodeIp, ValidatorIndex>,
    pub round_robin_cursor: usize,
    pub outbound: VecDeque<PendingRpcRequest>,
    pub inbound: VecDeque<InboundRpcRequest>,
    pub responses: VecDeque<OutboundRpcResponse>,
    pub maps: ConsensusRpcMaps,
    pub stats: RpcSizeStats,
    pub bootstrap_start_round: Option<Round>,
    pub bootstrap_end_round: Option<Round>,
}

impl ConsensusRpcState {
    pub fn new(config: ConsensusRpcConfig, validators: impl IntoIterator<Item = ConsensusRpcPeer>) -> Self {
        let mut peers = HashMap::new();
        let mut node_ip_to_validator = HashMap::new();

        for peer in validators {
            node_ip_to_validator.insert(peer.node_ip.clone(), peer.validator);
            peers.insert(peer.validator, peer);
        }

        Self {
            config,
            peers,
            node_ip_to_validator,
            round_robin_cursor: 0,
            outbound: VecDeque::new(),
            inbound: VecDeque::new(),
            responses: VecDeque::new(),
            maps: ConsensusRpcMaps::default(),
            stats: RpcSizeStats::default(),
            bootstrap_start_round: None,
            bootstrap_end_round: None,
        }
    }

    /// Recovered behavior for the `make_rpc_request_get_node_ip` path.
    ///
    /// IDA: `0x43848F0` logs `BUG: unknown validator:` if the lookup cannot be satisfied.
    pub fn make_rpc_request_get_node_ip(
        &mut self,
        validator: ValidatorIndex,
    ) -> Result<PendingRpcRequest, ConsensusRpcError> {
        if !self.peers.contains_key(&validator) {
            return Err(ConsensusRpcError::RpcNotFound);
        }

        Ok(PendingRpcRequest {
            peer: validator,
            content: RequestContent {
                validator: Some(validator),
                request: ConsensusRpcRequest::GetNodeIp { validator },
            },
            deadline: Instant::now() + Duration::from_millis(self.config.timeout_millis),
            attempts: 0,
        })
    }

    /// Enqueue a request for a specific validator or fall back to round-robin.
    ///
    /// String evidence: `node_rpc_request`, `RpcRoundRobin`, `RpcNotFound`.
    pub fn enqueue_node_rpc_request(
        &mut self,
        request: ConsensusRpcRequest,
        validator: Option<ValidatorIndex>,
    ) -> Result<ValidatorIndex, ConsensusRpcError> {
        let peer = match validator {
            Some(validator) if self.peers.contains_key(&validator) => validator,
            Some(_) => return Err(ConsensusRpcError::RpcNotFound),
            None => self.next_round_robin_peer()?,
        };

        self.outbound.push_back(PendingRpcRequest {
            peer,
            content: RequestContent { validator: Some(peer), request },
            deadline: Instant::now() + Duration::from_millis(self.config.timeout_millis),
            attempts: 0,
        });

        Ok(peer)
    }

    fn next_round_robin_peer(&mut self) -> Result<ValidatorIndex, ConsensusRpcError> {
        if self.peers.is_empty() {
            return Err(ConsensusRpcError::EmptyValidators);
        }

        let mut validators: Vec<_> = self.peers.keys().copied().collect();
        validators.sort_unstable();
        let peer = validators[self.round_robin_cursor % validators.len()];
        self.round_robin_cursor = self.round_robin_cursor.wrapping_add(1);
        Ok(peer)
    }

    /// Handle an inbound request decoded by the TCP server task.
    ///
    /// IDA: `0x4B33EB0` has task labels `Rpc task inbound`, `Incoming tcp stream`,
    /// `Received rpc request`, then `send consensus rpc resp`.
    pub fn handle_inbound_request(&mut self, request: InboundRpcRequest) -> ConsensusRpcResponse {
        self.stats.inbound_bytes = self.stats.inbound_bytes.saturating_add(request.payload_len as u64);

        match request.content.request {
            ConsensusRpcRequest::GetPeers => ConsensusRpcResponse::Peers(self.rpc_task_get_peers()),
            ConsensusRpcRequest::GetNodeIp { validator } => {
                ConsensusRpcResponse::NodeIp(self.peers.get(&validator).map(|peer| peer.node_ip.clone()))
            }
            ConsensusRpcRequest::GetClientBlocks { after_round, max_blocks } => {
                match self.client_blocks_after(after_round, max_blocks) {
                    Ok(blocks) => ConsensusRpcResponse::ClientBlocks(blocks),
                    Err(err) => ConsensusRpcResponse::Error(err),
                }
            }
            ConsensusRpcRequest::PublishBlock { block_hash, signed_block } => {
                self.maps.hash_to_block.insert(block_hash, signed_block.content);
                ConsensusRpcResponse::Ack
            }
            ConsensusRpcRequest::PublishTimeout(_timeout) => ConsensusRpcResponse::Ack,
            ConsensusRpcRequest::PublishTc(_tc) => ConsensusRpcResponse::Ack,
            ConsensusRpcRequest::Unknown { tag, bytes } => {
                ConsensusRpcResponse::Unknown { tag, bytes }
            }
        }
    }

    /// Handle completion of an outbound peer request.
    ///
    /// IDA: `0x47B05F0` and `0x47B3F50` set peer state for `Peer response` and `Peer timed out`.
    pub fn record_peer_result(
        &mut self,
        validator: ValidatorIndex,
        response: Result<ConsensusRpcResponse, ConsensusRpcError>,
        payload_len: usize,
    ) -> Result<ConsensusRpcResponse, ConsensusRpcError> {
        match response {
            Ok(response) => {
                if let Some(peer) = self.peers.get_mut(&validator) {
                    peer.last_response = Some(Instant::now());
                    peer.consecutive_timeouts = 0;
                }
                self.stats.response_bytes = self.stats.response_bytes.saturating_add(payload_len as u64);
                Ok(response)
            }
            Err(ConsensusRpcError::PeerTimedOut) => {
                if let Some(peer) = self.peers.get_mut(&validator) {
                    peer.consecutive_timeouts = peer.consecutive_timeouts.saturating_add(1);
                }
                Err(ConsensusRpcError::PeerTimedOut)
            }
            Err(err) => Err(err),
        }
    }

    /// Request enough remote client blocks to cover `[start_round, end_round]`.
    ///
    /// IDA: `0x43848F0` logs `client blocks first=`, `last=`, then
    /// `@@ finished bootstrap @@ [start_round: ...] @ [end_round: ...]`.
    pub fn bootstrap_client_blocks(
        &mut self,
        start_round: Round,
        end_round: Round,
    ) -> Result<(), ConsensusRpcError> {
        if start_round > end_round {
            self.bootstrap_start_round = Some(start_round);
            self.bootstrap_end_round = Some(end_round);
            return Ok(());
        }

        self.bootstrap_start_round = Some(start_round);
        self.bootstrap_end_round = Some(end_round);

        let mut next = start_round;
        while next <= end_round {
            let remaining = end_round.saturating_sub(next).saturating_add(1);
            let batch = remaining.min(self.config.max_client_blocks_per_response as u64) as u32;
            self.enqueue_node_rpc_request(
                ConsensusRpcRequest::GetClientBlocks {
                    after_round: next.saturating_sub(1),
                    max_blocks: batch,
                },
                None,
            )?;
            next = next.saturating_add(batch as u64);
        }

        Ok(())
    }

    fn rpc_task_get_peers(&self) -> PeerResponse {
        PeerResponse {
            peers: self
                .peers
                .values()
                .map(|peer| PeerInfo {
                    validator: peer.validator,
                    node_ip: peer.node_ip.clone(),
                    addr: Some(peer.addr),
                    verified: peer.verified,
                })
                .collect(),
        }
    }

    fn client_blocks_after(
        &self,
        after_round: Round,
        max_blocks: u32,
    ) -> Result<Vec<ClientBlock>, ConsensusRpcError> {
        let mut blocks: Vec<_> = self
            .maps
            .hash_to_block
            .iter()
            .filter(|(_, block)| block.round > after_round)
            .map(|(block_hash, block)| ClientBlock {
                block: block.clone(),
                block_hash: *block_hash,
                app_hash: None,
                commit_proof: block.qc.clone(),
                tx_commit_proofs: Vec::new(),
            })
            .collect();

        blocks.sort_by_key(|block| block.block.round);
        blocks.truncate(max_blocks as usize);

        if blocks.is_empty() {
            return Err(ConsensusRpcError::RpcPeerNoClientBlocks);
        }

        validate_client_blocks(after_round, &blocks)?;
        Ok(blocks)
    }
}

/// Validate the critical client-block invariants named in the recovered error strings.
pub fn validate_client_blocks(
    after_round: Round,
    blocks: &[ClientBlock],
) -> Result<(), ConsensusRpcError> {
    let mut expected_round = after_round.saturating_add(1);
    let mut previous_hash = None;

    for block in blocks {
        if block.block.round != expected_round {
            return Err(ConsensusRpcError::Consecutive);
        }
        if let Some(qc) = &block.block.qc {
            if qc.round >= block.block.round {
                return Err(ConsensusRpcError::ClientBlockQcRound);
            }
            if let Some(previous_hash) = previous_hash {
                if qc.block_hash != previous_hash {
                    return Err(ConsensusRpcError::ClientBlockQcHash);
                }
            }
        } else if expected_round != after_round.saturating_add(1) {
            return Err(ConsensusRpcError::ClientBlockMissingCommitProof);
        }

        if block.block.tx_hashes.is_empty() && !block.tx_commit_proofs.is_empty() {
            return Err(ConsensusRpcError::ClientBlockTxHashes);
        }

        previous_hash = Some(block.block_hash);
        expected_round = expected_round.saturating_add(1);
    }

    Ok(())
}

/// Apply the peer override file used by `Rpc task inbound`.
///
/// IDA: seed `0x4B33EB0` references `/override_consensus_rpc_c_signers.json` before cloning
/// main validators. The binary treats missing/empty override as no filtering.
pub fn rpc_clone_main_validators(
    all_validators: &[ConsensusRpcPeer],
    override_c_signers: Option<&[ValidatorIndex]>,
) -> Vec<ConsensusRpcPeer> {
    match override_c_signers {
        None | Some([]) => all_validators.to_vec(),
        Some(allowed) => all_validators
            .iter()
            .filter(|peer| allowed.contains(&peer.validator))
            .cloned()
            .collect(),
    }
}

/// Dispatch a decoded bincode request. The framing and bincode reader live in sibling modules;
/// this function is the consensus-specific branch table.
pub fn dispatch_consensus_rpc_request(
    state: &mut ConsensusRpcState,
    peer: Option<ValidatorIndex>,
    request: ConsensusRpcRequest,
    payload_len: usize,
) -> ConsensusRpcResponse {
    state.handle_inbound_request(InboundRpcRequest {
        peer,
        content: RequestContent { validator: peer, request },
        payload_len,
    })
}

/// Check timeout exactly as the outbound async poll does before marking `Peer timed out`.
pub fn poll_outbound_deadline(request: &PendingRpcRequest, now: Instant) -> Result<(), ConsensusRpcError> {
    if now >= request.deadline {
        Err(ConsensusRpcError::PeerTimedOut)
    } else {
        Ok(())
    }
}

