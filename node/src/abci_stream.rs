//! Recovered from `/home/ubuntu/hl/code_Mainnet/node/src/abci_stream.rs`.
//!
//! Static reconstruction while IDA MCP was queue-blocked.
//! Seeds: `0x2037AC0`, `0x43831E0` (two monomorphs of the same large
//! async client-side ABCI-state fetch future). Closely related static xrefs:
//! `0x2035170` / `0x20369B6` (`connection_checks` monomorphs) and
//! `0x20332xx` / `0x203A7xx` (server-side `send_abci_state` monomorphs).
//! String evidence: `abci_stream send tcp greeting`, `abci_stream recv greeting`,
//! `connection_checks`, `performing checks on stream`, `closing gossip stream
//! because no quorum yet`, `closing gossip stream because failed to verify peer
//! rpc`, `finished checks`, `sending abci_state`, `send abci greeting`,
//! `could not send abci_state`, `successfully sent abci_state`.
//!
//! IDA tags applied: none; IDA was unavailable. Every `NEEDS IDA` marker below
//! is a specific decompile/type/write-back gap rather than a TODO placeholder.

use std::fmt;
use std::time::Duration;

const SEND_CLIENT_GREETING_SPAN: &str = "abci_stream send tcp greeting";
const RECV_GREETING_SPAN: &str = "abci_stream recv greeting";
const CONNECTION_CHECKS_SPAN: &str = "connection_checks";
const SEND_ABCI_STATE_SPAN: &str = "sending abci_state";
const SEND_SERVER_GREETING_SPAN: &str = "send abci greeting";

/// Seen as `0x3e8` in retry/timer setup around both client seeds.
pub const DEFAULT_RETRY_DELAY: Duration = Duration::from_millis(1_000);

/// Seen as `0xb2d05e00` when the state machine selects the long greeting wait.
pub const SLOW_GREETING_TIMEOUT: Duration = Duration::from_nanos(3_000_000_000);

/// Seen as `0x3b9aca00` in the mutex/async-lock slow paths used by checks.
pub const CHECK_LOCK_BACKOFF: Duration = Duration::from_nanos(1_000_000_000);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GreetingId {
    Live,
    Other(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpGreeting {
    pub send_abci: bool,
    pub id: GreetingId,
}

impl TcpGreeting {
    pub const REQUEST_ABCI: Self = Self { send_abci: true, id: GreetingId::Live };
    pub const LIVE_NODE: Self = Self { send_abci: false, id: GreetingId::Live };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerAddress {
    pub host: String,
    pub port: u16,
    pub validator_index: Option<u32>,
}

impl fmt::Display for PeerAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.validator_index {
            Some(index) => write!(f, "{}:{}#{index}", self.host, self.port),
            None => write!(f, "{}:{}", self.host, self.port),
        }
    }
}

/// Rust-facing name supplied by the concurrently recovered `l1/src/abci/state.rs` work.
#[derive(Clone, Debug)]
pub struct VisorAbciState {
    pub initial_height: u64,
    pub height: u64,
    pub scheduled_freeze_height: Option<u64>,
    pub consensus_time: u64,
    pub wall_clock_time: u64,
    pub reference_lag: u64,
    // [NEEDS IDA] Full `l1::abci::state::VisorAbciState` layout is owned by
    // `l1/src/abci/state.rs`; this file only needs the stream boundary type.
}

#[derive(Debug)]
pub enum AbciStreamError {
    Connect { peer: PeerAddress, source: IoError },
    SendGreeting { peer: PeerAddress, source: IoError },
    RecvGreeting { peer: PeerAddress, source: IoError },
    RejectedGreeting { peer: PeerAddress, greeting: TcpGreeting },
    ReadState { peer: PeerAddress, source: IoError },
    SendState { peer: PeerAddress, source: IoError },
    ConnectionRejected { peer: PeerAddress, reason: ConnectionRejection },
}

#[derive(Clone, Debug)]
pub struct IoError {
    pub message: String,
}

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionRejection {
    NoQuorumYet,
    FailedPeerRpcVerification,
    AlreadyConnected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionDecision {
    Accept,
    Close(ConnectionRejection),
}

pub trait AbciConnector {
    type Stream;

    async fn connect_abci_stream(&self, peer: &PeerAddress) -> Result<Self::Stream, IoError>;
    async fn sleep(&self, delay: Duration);
}

pub trait AbciStreamCodec<S> {
    async fn write_greeting(
        &mut self,
        stream: &mut S,
        greeting: TcpGreeting,
        span: &'static str,
    ) -> Result<(), IoError>;

    async fn read_greeting(
        &mut self,
        stream: &mut S,
        span: &'static str,
        timeout: Duration,
    ) -> Result<TcpGreeting, IoError>;

    async fn read_abci_state(&mut self, stream: &mut S) -> Result<VisorAbciState, IoError>;
    async fn write_abci_state(&mut self, stream: &mut S, state: &VisorAbciState) -> Result<(), IoError>;
    async fn close(&mut self, stream: S);
}

pub trait PeerRpcVerifier {
    async fn verify_peer_rpc(&mut self, peer: &PeerAddress) -> Result<bool, IoError>;
}

pub trait PeerConnectionRegistry {
    fn has_quorum(&self) -> bool;
    fn is_already_connected(&self, peer: &PeerAddress) -> bool;
    fn mark_connecting(&mut self, peer: &PeerAddress);
    fn mark_connected(&mut self, peer: &PeerAddress);
    fn clear_connecting(&mut self, peer: &PeerAddress);
}

/// Reconstructs the async client future at `0x2037AC0` / `0x43831E0`.
///
/// The machine repeats the same sequence until a peer yields a full ABCI state:
/// connect, send `{ send_abci: true, id: Live }`, receive the peer greeting,
/// then read the compressed/messagepack ABCI state frame. The binary logs and
/// retries separately for connect failure, greeting-write failure, and state-read
/// failure; those branches are preserved here.
pub async fn fetch_abci_state_loop<C, K, S>(
    connector: &C,
    codec: &mut K,
    peer: PeerAddress,
    recv_greeting_timeout: Duration,
) -> Result<VisorAbciState, AbciStreamError>
where
    C: AbciConnector<Stream = S>,
    K: AbciStreamCodec<S>,
{
    loop {
        let mut stream = match connector.connect_abci_stream(&peer).await {
            Ok(stream) => stream,
            Err(source) => {
                tracing::warn!(%peer, %source, "could not establish abci stream from peer, retrying");
                connector.sleep(DEFAULT_RETRY_DELAY).await;
                continue;
            }
        };

        if let Err(source) = codec
            .write_greeting(&mut stream, TcpGreeting::REQUEST_ABCI, SEND_CLIENT_GREETING_SPAN)
            .await
        {
            tracing::error!(%peer, %source, "could not send tcp greeting, retrying");
            codec.close(stream).await;
            connector.sleep(DEFAULT_RETRY_DELAY).await;
            continue;
        }

        tracing::warn!(%peer, "connected to abci stream from peer");

        let greeting = match codec
            .read_greeting(&mut stream, RECV_GREETING_SPAN, recv_greeting_timeout)
            .await
        {
            Ok(greeting) => greeting,
            Err(source) => {
                tracing::warn!(%peer, %source, "could not read abci greeting from peer, retrying");
                codec.close(stream).await;
                connector.sleep(DEFAULT_RETRY_DELAY).await;
                continue;
            }
        };

        tracing::warn!(%peer, ?greeting, "received abci greeting from peer");

        if greeting.id != GreetingId::Live {
            codec.close(stream).await;
            return Err(AbciStreamError::RejectedGreeting { peer, greeting });
        }

        match codec.read_abci_state(&mut stream).await {
            Ok(state) => {
                codec.close(stream).await;
                return Ok(state);
            }
            Err(source) => {
                tracing::warn!(%peer, %source, "could not read abci state from peer");
                codec.close(stream).await;
                connector.sleep(DEFAULT_RETRY_DELAY).await;
            }
        }
    }
}

/// Convenience wrapper for the normal binary-selected timeout.
pub async fn fetch_abci_state_from_peer<C, K, S>(
    connector: &C,
    codec: &mut K,
    peer: PeerAddress,
) -> Result<VisorAbciState, AbciStreamError>
where
    C: AbciConnector<Stream = S>,
    K: AbciStreamCodec<S>,
{
    fetch_abci_state_loop(connector, codec, peer, SLOW_GREETING_TIMEOUT).await
}

/// Reconstructs `connection_checks` (`0x2035170` and duplicate monomorph at
/// `0x20369B6`). The static control flow shows three close reasons and an
/// accepted path bracketed by `performing checks on stream` / `finished checks`.
pub async fn connection_checks<R, V>(
    registry: &mut R,
    verifier: &mut V,
    peer: &PeerAddress,
) -> Result<ConnectionDecision, AbciStreamError>
where
    R: PeerConnectionRegistry,
    V: PeerRpcVerifier,
{
    tracing::debug!(target: CONNECTION_CHECKS_SPAN, %peer, "performing checks on stream");

    if registry.is_already_connected(peer) {
        tracing::warn!(target: CONNECTION_CHECKS_SPAN, %peer, "closing gossip stream because peer is already connected");
        return Ok(ConnectionDecision::Close(ConnectionRejection::AlreadyConnected));
    }

    if !registry.has_quorum() {
        tracing::warn!(target: CONNECTION_CHECKS_SPAN, %peer, "closing gossip stream because no quorum yet");
        return Ok(ConnectionDecision::Close(ConnectionRejection::NoQuorumYet));
    }

    registry.mark_connecting(peer);
    let verified = match verifier.verify_peer_rpc(peer).await {
        Ok(verified) => verified,
        Err(source) => {
            tracing::error!(target: CONNECTION_CHECKS_SPAN, %peer, %source, "error checking connection");
            registry.clear_connecting(peer);
            return Err(AbciStreamError::ConnectionRejected {
                peer: peer.clone(),
                reason: ConnectionRejection::FailedPeerRpcVerification,
            });
        }
    };

    if !verified {
        tracing::warn!(target: CONNECTION_CHECKS_SPAN, %peer, "closing gossip stream because failed to verify peer rpc");
        registry.clear_connecting(peer);
        return Ok(ConnectionDecision::Close(ConnectionRejection::FailedPeerRpcVerification));
    }

    registry.mark_connected(peer);
    tracing::debug!(target: CONNECTION_CHECKS_SPAN, %peer, "finished checks");
    Ok(ConnectionDecision::Accept)
}

/// Server-side ABCI transfer path adjacent to the client seeds.
///
/// Static xrefs at `0x20336A6`, `0x20336FB`, `0x20338BE`, and `0x203398B`
/// show the sequence: log `sending abci_state`, send a greeting using the
/// `send abci greeting` span, write the serialized state, then log success or
/// `could not send abci_state`.
pub async fn send_abci_state_once<K, S>(
    codec: &mut K,
    mut stream: S,
    peer: PeerAddress,
    state: &VisorAbciState,
) -> Result<(), AbciStreamError>
where
    K: AbciStreamCodec<S>,
{
    tracing::debug!(%peer, "sending abci_state");

    if let Err(source) = codec
        .write_greeting(&mut stream, TcpGreeting::LIVE_NODE, SEND_SERVER_GREETING_SPAN)
        .await
    {
        tracing::warn!(%peer, %source, "could not send abci_state");
        codec.close(stream).await;
        return Err(AbciStreamError::SendGreeting { peer, source });
    }

    if let Err(source) = codec.write_abci_state(&mut stream, state).await {
        tracing::warn!(%peer, %source, "could not send abci_state");
        codec.close(stream).await;
        return Err(AbciStreamError::SendState { peer, source });
    }

    tracing::debug!(%peer, "successfully sent abci_state");
    codec.close(stream).await;
    Ok(())
}

/// Incoming node-stream branch that decides whether the connection should be
/// converted into an ABCI state transfer.
pub async fn maybe_handle_abci_stream<R, V, K, S>(
    registry: &mut R,
    verifier: &mut V,
    codec: &mut K,
    stream: S,
    peer: PeerAddress,
    greeting: TcpGreeting,
    local_state: &VisorAbciState,
) -> Result<Option<ConnectionRejection>, AbciStreamError>
where
    R: PeerConnectionRegistry,
    V: PeerRpcVerifier,
    K: AbciStreamCodec<S>,
{
    match connection_checks(registry, verifier, &peer).await? {
        ConnectionDecision::Accept if greeting.send_abci => {
            send_abci_state_once(codec, stream, peer, local_state).await?;
            Ok(None)
        }
        ConnectionDecision::Accept => {
            codec.close(stream).await;
            Ok(None)
        }
        ConnectionDecision::Close(reason) => {
            codec.close(stream).await;
            Ok(Some(reason))
        }
    }
}

/// [NEEDS IDA] The exact state-machine enum discriminants are visible in the
/// async poll code (`0x1fa`, `0x489`, `0x530` fields) but need Hex-Rays to name
/// every variant safely. This Rust enum records the recovered phase ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientFetchPhase {
    Connect,
    SendTcpGreeting,
    RecvGreeting,
    ReadAbciState,
    RetrySleep,
    ReturnReady,
    PoisonedAfterPanic,
}
