//! Reconstructed from `/home/ubuntu/hl/code_Mainnet/node/src/gossip_rpc_client.rs`.
//!
//! Primary seed EAs: `0x1FD4570`, `0x2039060`, `0x22615B0`, `0x22689F0`,
//! `0x226BB20`, `0x4356C90`, `0x435CB20`, `0x4387F40`, `0x4389070`,
//! `0x4B29760`.
//!
//! Recovered control-flow anchors:
//! - `0x4387F40` / `0x2039060`: outbound request future. It builds a
//!   `NodePort::GossipRpcRequests` endpoint, labels connect as `rpc connect`,
//!   serializes a `GossipRpcRequest`, writes a framed packet under
//!   `send gossip rpc request`, reads `gossip response`, and decodes
//!   `GossipRpcResponse`.
//! - `0x435CB20` / `0x226BB20`: 10.0 second wrapper labelled
//!   `gossip_rpc_request`; timeout errors are formatted with `lu::timeout`,
//!   inner failures with `request err:`.
//! - `0x22689F0`: `AsyncSleepRetry` wrapper; failures log
//!   `AsyncSleepRetry::retry desc=[...] n_tries=... failed: ...`, then final
//!   exhaustion is returned as `async_sleep_retry retries exhausted`.
//! - `0x1FD4570`: higher-level request+verification path. After the raw RPC
//!   completes it performs a `verify_rpc` stage and logs `verified gossip rpc`.
//! - `0x4389070`: bootstrap/query loop. It logs `starting bootstrap`, queries
//!   client blocks in inclusive windows of at most 100, expects `ClientBlocks`,
//!   invokes a caller callback for every block, then logs `finished bootstrap`.
//!
//! IDA hygiene attempted but blocked by a full shared request queue. Intended
//! names include `node_gossip_rpc_client__poll_send_gossip_rpc_request`,
//! `node_gossip_rpc_client__poll_send_request_timeout`,
//! `node_gossip_rpc_client__poll_query_abci_blocks`, and
//! `node_gossip_rpc_client__poll_gossip_rpc_request_with_verification`.

#![allow(dead_code)]

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::gossip_rpc::{
    ClientBlockEntry, GossipRpcError, GossipRpcRequest, GossipRpcResponse,
    GossipStatus, DEFAULT_MAX_GOSSIP_PACKET_BYTES,
};
use crate::net_utils::async_sleep_retry::{
    async_sleep_retry, AsyncSleepRetryError, AsyncSleepRetryPolicy,
};
use crate::net_utils::node_port::{NodePort, NodePortEndpoint, NodePortError};
use crate::net_utils::tcp::read::{read_bytes, TcpReadError};
use crate::net_utils::tcp::write::{write_frame, TcpWriteError, TcpWriteOptions};

pub const RPC_CONNECT_DESC: &str = "rpc connect";
pub const SEND_REQUEST_DESC: &str = "send gossip rpc request";
pub const GOSSIP_RESPONSE_DESC: &str = "gossip response";
pub const REQUEST_TIMEOUT_DESC: &str = "gossip_rpc_request";
pub const VERIFY_RPC_DESC: &str = "verify_rpc";
pub const VERIFIED_LOG: &str = "verified gossip rpc";

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub const VERIFY_TIMEOUT: Duration = Duration::from_secs(5);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_BOOTSTRAP_BLOCKS_PER_REQUEST: u64 = 100;
pub const RESPONSE_WAIT_THRESHOLD: Duration = Duration::from_millis(100);

const RETRY_DELAY_STATUS: Duration = Duration::from_nanos(40);
const RETRY_DELAY_PEERS: Duration = Duration::from_nanos(10_000);
const RETRY_DELAY_PER_BLOCK: Duration = Duration::from_nanos(8_000_000);
const RETRY_DELAY_CAP: Duration = Duration::from_nanos(800_000_000);

pub type Result<T, E = GossipRpcClientError> = std::result::Result<T, E>;

#[derive(Clone, Debug)]
pub struct GossipRpcClientConfig {
    pub max_response_bytes: usize,
    pub request_timeout: Duration,
    pub verify_timeout: Duration,
    pub connect_timeout: Duration,
    pub retry_tries: usize,
    pub write_options: TcpWriteOptions,
}

impl Default for GossipRpcClientConfig {
    fn default() -> Self {
        Self {
            max_response_bytes: DEFAULT_MAX_GOSSIP_PACKET_BYTES,
            request_timeout: REQUEST_TIMEOUT,
            verify_timeout: VERIFY_TIMEOUT,
            connect_timeout: CONNECT_TIMEOUT,
            retry_tries: 10,
            write_options: TcpWriteOptions::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct GossipRpcClient {
    rpc_node_ip: NodePortEndpoint,
    config: GossipRpcClientConfig,
}

impl GossipRpcClient {
    pub fn new(rpc_node_ip: NodePortEndpoint) -> Self {
        Self { rpc_node_ip, config: GossipRpcClientConfig::default() }
    }

    pub fn with_config(rpc_node_ip: NodePortEndpoint, config: GossipRpcClientConfig) -> Self {
        Self { rpc_node_ip, config }
    }

    pub fn rpc_node_ip(&self) -> NodePortEndpoint {
        self.rpc_node_ip
    }

    pub fn endpoint_addr(&self) -> Result<SocketAddr> {
        Ok(NodePort::GossipRpcRequests.socket_addr(self.rpc_node_ip)?)
    }

    pub async fn request(&self, request: GossipRpcRequest) -> Result<GossipRpcResponse> {
        let policy = AsyncSleepRetryPolicy::new(
            REQUEST_TIMEOUT_DESC,
            self.config.retry_tries,
            request_retry_delay(&request),
        );
        let config = self.config.clone();
        let addr = self.endpoint_addr()?;

        async_sleep_retry(
            policy,
            |attempt| {
                let request = request.clone();
                let config = config.clone();
                async move {
                    let read_timeout_enabled = request_retry_delay(&request) >= RESPONSE_WAIT_THRESHOLD;
                    let response = request_with_timeout(addr, request, config, read_timeout_enabled).await?;
                    verify_not_remote_error(response).map_err(|error| {
                        RequestAttemptError::Remote {
                            attempt,
                            source: Box::new(error),
                        }
                    })
                }
            },
            |_, error| retry_delay_from_attempt_error(error),
        )
        .await
        .map_err(GossipRpcClientError::RetryExhausted)
    }

    pub async fn request_with_verification(&self, request: GossipRpcRequest) -> Result<GossipRpcResponse> {
        let response = self.request(request).await.map_err(|source| {
            log_request_error(&source);
            source
        })?;
        timeout(self.config.verify_timeout, verify_rpc_response(&response))
            .await
            .map_err(|_| GossipRpcClientError::Timeout { desc: VERIFY_RPC_DESC, timeout: self.config.verify_timeout })??;
        log_verified_gossip_rpc();
        Ok(response)
    }

    pub async fn query_gossip_status(&self) -> Result<Option<GossipStatus>> {
        let response = self
            .request_with_verification(GossipRpcRequest::GossipStatus)
            .await?;
        match response {
            GossipRpcResponse::GossipStatus(status) => Ok(status),
            other => Err(GossipRpcClientError::UnexpectedResponse {
                expected: "GossipStatus",
                actual: response_name(&other),
            }),
        }
    }

    pub async fn query_peers(&self) -> Result<Vec<crate::gossip_rpc::PeerInfo>> {
        let response = self.request_with_verification(GossipRpcRequest::Peers).await?;
        match response {
            GossipRpcResponse::Peers(peers) => Ok(peers),
            other => Err(GossipRpcClientError::UnexpectedResponse {
                expected: "Peers",
                actual: response_name(&other),
            }),
        }
    }

    pub async fn query_client_blocks(&self, start_round: u64, end_round: u64) -> Result<Vec<ClientBlockEntry>> {
        let request = client_blocks_request(start_round, end_round);
        let response = self.request_with_verification(request).await?;
        match response {
            GossipRpcResponse::ClientBlocks(blocks) => Ok(blocks),
            other => Err(GossipRpcClientError::UnexpectedResponse {
                expected: "ClientBlocks",
                actual: response_name(&other),
            }),
        }
    }

    pub async fn query_abci_blocks<F, Fut>(
        &self,
        start_round: u64,
        end_round: u64,
        mut add_client_block: F,
    ) -> Result<usize>
    where
        F: FnMut(ClientBlockEntry) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        if end_round < start_round {
            return Err(GossipRpcClientError::InvalidBlockRange { start_round, end_round });
        }

        log_starting_bootstrap(start_round, end_round);
        let mut next_round = start_round;
        let mut inserted = 0_usize;

        while next_round <= end_round {
            let batch_end = end_round.min(next_round.saturating_add(MAX_BOOTSTRAP_BLOCKS_PER_REQUEST - 1));
            log_querying_client_blocks(self.rpc_node_ip, next_round, batch_end);

            let blocks = self.query_client_blocks(next_round, batch_end).await?;
            if blocks.is_empty() {
                return Err(GossipRpcClientError::NoClientBlocks { start_round: next_round, end_round: batch_end });
            }

            let first_round = next_round;
            let last_round = next_round + blocks.len() as u64 - 1;
            log_got_client_blocks(blocks.len(), first_round, last_round);

            for block in blocks {
                add_client_block(block).await?;
                inserted += 1;
            }

            log_added_client_block_batch(inserted);
            if batch_end == u64::MAX {
                break;
            }
            next_round = batch_end + 1;
        }

        log_finished_bootstrap(start_round, end_round, inserted);
        Ok(inserted)
    }
}

pub async fn request_with_timeout(
    addr: SocketAddr,
    request: GossipRpcRequest,
    config: GossipRpcClientConfig,
    read_timeout_enabled: bool,
) -> std::result::Result<GossipRpcResponse, RequestAttemptError> {
    let request_timeout = config.request_timeout;
    timeout(
        request_timeout,
        send_gossip_rpc_request(addr, request, config, read_timeout_enabled),
    )
    .await
    .map_err(|_| RequestAttemptError::Timeout { desc: REQUEST_TIMEOUT_DESC, timeout: request_timeout })?
}

pub async fn send_gossip_rpc_request(
    addr: SocketAddr,
    request: GossipRpcRequest,
    config: GossipRpcClientConfig,
    read_timeout_enabled: bool,
) -> std::result::Result<GossipRpcResponse, RequestAttemptError> {
    let mut stream = connect_rpc_stream(addr, config.connect_timeout).await?;

    let payload = serialize_gossip_rpc_request(&request);
    write_frame(&mut stream, &payload, config.write_options)
        .await
        .map_err(RequestAttemptError::Write)?;

    let response_bytes = read_bytes(
        &mut stream,
        GOSSIP_RESPONSE_DESC,
        config.max_response_bytes,
        read_timeout_enabled,
    )
    .await
    .map_err(RequestAttemptError::Read)?;

    parse_gossip_rpc_response(&response_bytes).map_err(RequestAttemptError::Decode)
}

pub async fn connect_rpc_stream(addr: SocketAddr, connect_timeout: Duration) -> std::result::Result<TcpStream, RequestAttemptError> {
    timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| RequestAttemptError::ConnectTimedOut { addr, timeout: connect_timeout })?
        .map_err(RequestAttemptError::Connect)
}

pub fn serialize_gossip_rpc_request(request: &GossipRpcRequest) -> Vec<u8> {
    let mut payload = Vec::new();
    request.encode_bincode(&mut payload);
    payload
}

pub fn parse_gossip_rpc_response(bytes: &[u8]) -> std::result::Result<GossipRpcResponse, GossipRpcError> {
    GossipRpcResponse::decode_bincode(bytes)
}

pub fn client_blocks_request(start_round: u64, end_round: u64) -> GossipRpcRequest {
    GossipRpcRequest::ClientBlocks { start_round, end_round }
}

pub fn request_retry_delay(request: &GossipRpcRequest) -> Duration {
    match request {
        GossipRpcRequest::ClientBlocks { start_round, end_round } => {
            let span = end_round
                .saturating_sub(*start_round)
                .saturating_add(1);
            RETRY_DELAY_PER_BLOCK
                .checked_mul(span as u32)
                .unwrap_or(RETRY_DELAY_CAP)
                .min(RETRY_DELAY_CAP)
        }
        GossipRpcRequest::Peers => RETRY_DELAY_PEERS,
        GossipRpcRequest::GossipStatus => RETRY_DELAY_STATUS,
    }
}

async fn verify_rpc_response(response: &GossipRpcResponse) -> Result<()> {
    match response {
        GossipRpcResponse::Error(message) => Err(GossipRpcClientError::RemoteError(message.clone())),
        _ => Ok(()),
    }
}

fn verify_not_remote_error(response: GossipRpcResponse) -> std::result::Result<GossipRpcResponse, GossipRpcClientError> {
    match response {
        GossipRpcResponse::Error(message) => Err(GossipRpcClientError::RemoteError(message)),
        other => Ok(other),
    }
}

fn retry_delay_from_attempt_error(error: &RequestAttemptError) -> Duration {
    match error {
        RequestAttemptError::Remote { .. } => Duration::ZERO,
        RequestAttemptError::Timeout { .. } => Duration::from_secs(2),
        RequestAttemptError::ConnectTimedOut { .. } => Duration::from_secs(2),
        RequestAttemptError::Connect(_) => Duration::from_secs(2),
        RequestAttemptError::Write(_) => Duration::from_millis(100),
        RequestAttemptError::Read(_) => Duration::from_millis(100),
        RequestAttemptError::Decode(_) => Duration::ZERO,
    }
}

fn response_name(response: &GossipRpcResponse) -> &'static str {
    match response {
        GossipRpcResponse::ClientBlocks(_) => "ClientBlocks",
        GossipRpcResponse::Peers(_) => "Peers",
        GossipRpcResponse::GossipStatus(_) => "GossipStatus",
        GossipRpcResponse::Error(_) => "Error",
    }
}

#[derive(Debug)]
pub enum RequestAttemptError {
    Timeout { desc: &'static str, timeout: Duration },
    ConnectTimedOut { addr: SocketAddr, timeout: Duration },
    Connect(io::Error),
    Write(TcpWriteError),
    Read(TcpReadError),
    Decode(GossipRpcError),
    Remote { attempt: usize, source: Box<GossipRpcClientError> },
}

impl fmt::Display for RequestAttemptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout { desc, timeout } => write!(f, "lu::timeout {desc} after {timeout:?}"),
            Self::ConnectTimedOut { addr, timeout } => write!(f, "{RPC_CONNECT_DESC} to {addr} timed out after {timeout:?}"),
            Self::Connect(error) => write!(f, "{RPC_CONNECT_DESC}: {error}"),
            Self::Write(error) => write!(f, "{SEND_REQUEST_DESC}: {error}"),
            Self::Read(error) => write!(f, "{GOSSIP_RESPONSE_DESC}: {error}"),
            Self::Decode(error) => write!(f, "decode gossip response: {error}"),
            Self::Remote { source, .. } => write!(f, "{source}"),
        }
    }
}

impl std::error::Error for RequestAttemptError {}

#[derive(Debug)]
pub enum GossipRpcClientError {
    NodePort(NodePortError),
    Timeout { desc: &'static str, timeout: Duration },
    Request(RequestAttemptError),
    RetryExhausted(AsyncSleepRetryError<RequestAttemptError>),
    RemoteError(String),
    UnexpectedResponse { expected: &'static str, actual: &'static str },
    InvalidBlockRange { start_round: u64, end_round: u64 },
    NoClientBlocks { start_round: u64, end_round: u64 },
}

impl fmt::Display for GossipRpcClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NodePort(error) => write!(f, "rpc node port error: {error}"),
            Self::Timeout { desc, timeout } => write!(f, "lu::timeout {desc} after {timeout:?}"),
            Self::Request(error) => write!(f, "request err: {error}"),
            Self::RetryExhausted(error) => write!(f, "{error}"),
            Self::RemoteError(message) => write!(f, "remote gossip rpc error: {message}"),
            Self::UnexpectedResponse { expected, actual } => {
                write!(f, "unexpected rpc response in query_abci_blocks @@ [expected: {expected}] @ [resp: {actual}]")
            }
            Self::InvalidBlockRange { start_round, end_round } => {
                write!(f, "invalid query_abci_blocks range @@ [start_round: {start_round}] @ [end_round: {end_round}]")
            }
            Self::NoClientBlocks { start_round, end_round } => {
                write!(f, "no client blocks returned @@ [start_round: {start_round}] @ [end_round: {end_round}]")
            }
        }
    }
}

impl std::error::Error for GossipRpcClientError {}

impl From<NodePortError> for GossipRpcClientError {
    fn from(error: NodePortError) -> Self {
        Self::NodePort(error)
    }
}

impl From<RequestAttemptError> for GossipRpcClientError {
    fn from(error: RequestAttemptError) -> Self {
        Self::Request(error)
    }
}

fn log_request_error(error: &GossipRpcClientError) {
    let _ = ("request err:", error);
}

fn log_verified_gossip_rpc() {
    let _ = VERIFIED_LOG;
}

fn log_starting_bootstrap(start_round: u64, end_round: u64) {
    let _ = ("starting bootstrap", start_round, end_round);
}

fn log_querying_client_blocks(rpc_node_ip: NodePortEndpoint, start_round: u64, end_round: u64) {
    let _ = ("querying client blocks", rpc_node_ip, start_round, end_round);
}

fn log_got_client_blocks(len: usize, first_round: u64, last_round: u64) {
    let _ = ("got client blocks", len, first_round, last_round);
}

fn log_added_client_block_batch(inserted: usize) {
    let _ = ("added client block batch during bootstrap", inserted);
}

fn log_finished_bootstrap(start_round: u64, end_round: u64, inserted: usize) {
    let _ = ("finished bootstrap", start_round, end_round, inserted);
}
