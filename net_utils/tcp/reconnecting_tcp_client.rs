//! Reconstructed from `/home/ubuntu/hl/code_Mainnet/net_utils/src/tcp/reconnecting_tcp_client.rs`.
//!
//! Confidence: medium for the state machine shape and constants, lower for some
//! field names. Seeds expanded: `0x43848F0`, `0x439F860`, `0x439FA90`,
//! `0x4B399A0`. Static disassembly was used because the IDA foreground worker
//! was queued behind another `open_idb`; pending IDA tags: rename/type/comment
//! for these four EAs and helper `0x43A17C0`.
//!
//! Recovered constants and strings:
//! - `tcp_stream_with_retry` format string at `0x1ffb5e`.
//! - `AsyncSleepRetry::retry desc=[...] n_tries=... failed: ...` at `0x1f2256`.
//! - `async_sleep_retry retries exhausted: ... [n_retries: ...]` at `0x1ebd40`.
//! - retry count `10`, retry delay multiplier/base `2.0`, outer reconnect delay
//!   `10.0`, connect timeout `60.0`.
//! - local peer RPC port construction: `127.0.0.1:(4004 + validator_index * 1000)`
//!   (`0x100007f`, `0xfa4`, `0x3e8`).

use std::fmt;
use std::io;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

const DEFAULT_RPC_PORT: u16 = 4004;
const VALIDATOR_PORT_STRIDE: u16 = 1000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
const INNER_CONNECT_RETRIES: usize = 10;
const INNER_RETRY_SLEEP: Duration = Duration::from_secs(2);
const OUTER_RECONNECT_SLEEP: Duration = Duration::from_secs(10);

/// Peer selector result consumed by the reconnecting client loop.
///
/// The binary stores this as a compact enum: the low tag byte is checked for the
/// successful peer case and the remaining bytes carry the selected validator
/// index. Tag `2` is treated as shutdown/no-peer and ends the current poll path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerSelection {
    /// Connect to the default local RPC port.
    LocalDefault,
    /// Connect to `127.0.0.1:(4004 + validator_index * 1000)`.
    LocalValidator { validator_index: u8 },
    /// No currently usable peer. The caller backs off before trying again.
    NoPeer,
}

impl PeerSelection {
    #[inline]
    pub fn socket_addr(self) -> Option<SocketAddr> {
        match self {
            PeerSelection::LocalDefault => Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                DEFAULT_RPC_PORT,
            )),
            PeerSelection::LocalValidator { validator_index } => {
                let port = DEFAULT_RPC_PORT.checked_add(
                    VALIDATOR_PORT_STRIDE
                        .checked_mul(u16::from(validator_index))?,
                )?;
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port))
            }
            PeerSelection::NoPeer => None,
        }
    }
}

/// Reconnect policy recovered from the async state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconnectPolicy {
    pub connect_timeout: Duration,
    pub connect_retries: usize,
    pub connect_retry_sleep: Duration,
    pub reconnect_sleep: Duration,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            connect_timeout: CONNECT_TIMEOUT,
            connect_retries: INNER_CONNECT_RETRIES,
            connect_retry_sleep: INNER_RETRY_SLEEP,
            reconnect_sleep: OUTER_RECONNECT_SLEEP,
        }
    }
}

/// Terminal result from one connected transport session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionExit {
    /// The stream ended or returned an I/O/protocol error; reconnect after delay.
    Reconnect,
    /// Peer selection reported a terminal no-peer condition.
    Stop,
}

/// Error emitted by the reconnecting client loop.
#[derive(Debug)]
pub enum ReconnectError<E> {
    PeerSelectionUnavailable,
    InvalidSelectedPeer(PeerSelection),
    ConnectRetriesExhausted { addr: SocketAddr, last_error: io::Error },
    Session(E),
}

impl<E: fmt::Display> fmt::Display for ReconnectError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerSelectionUnavailable => f.write_str("no peer available for reconnecting tcp client"),
            Self::InvalidSelectedPeer(selection) => write!(f, "invalid peer selection: {selection:?}"),
            Self::ConnectRetriesExhausted { addr, last_error } => {
                write!(f, "tcp_stream_with_retry exhausted for {addr}: {last_error}")
            }
            Self::Session(error) => write!(f, "reconnecting tcp client session failed: {error}"),
        }
    }
}

impl<E> std::error::Error for ReconnectError<E> where E: std::error::Error + 'static {}

/// Reconnecting TCP client driver.
///
/// The recovered state machine has two retry layers:
/// 1. `tcp_stream_with_retry`: connect to one chosen peer, retrying ten times
///    with a two-second sleep and a sixty-second per-connect timeout.
/// 2. the outer loop: after a connected session exits with an error/EOF, sleep
///    ten seconds, select a fresh peer, and repeat.
///
/// `select_peer` is intentionally invoked after each outer failure. The binary
/// logs `src -> dest: rpc` around this point and copies a fresh peer descriptor
/// into the future state before every `tcp_stream_with_retry` construction.
pub struct ReconnectingTcpClient<S, H> {
    select_peer: S,
    handle_stream: H,
    policy: ReconnectPolicy,
}

impl<S, H> ReconnectingTcpClient<S, H> {
    pub fn new(select_peer: S, handle_stream: H) -> Self {
        Self {
            select_peer,
            handle_stream,
            policy: ReconnectPolicy::default(),
        }
    }

    pub fn with_policy(select_peer: S, handle_stream: H, policy: ReconnectPolicy) -> Self {
        Self {
            select_peer,
            handle_stream,
            policy,
        }
    }
}

impl<S, H, SFut, HFut, E> ReconnectingTcpClient<S, H>
where
    S: FnMut() -> SFut,
    SFut: Future<Output = PeerSelection>,
    H: FnMut(TcpStream) -> HFut,
    HFut: Future<Output = Result<SessionExit, E>>,
    E: fmt::Display,
{
    pub async fn run(mut self) -> Result<(), ReconnectError<E>> {
        loop {
            let selection = (self.select_peer)().await;
            let Some(addr) = selection.socket_addr() else {
                return match selection {
                    PeerSelection::NoPeer => Err(ReconnectError::PeerSelectionUnavailable),
                    other => Err(ReconnectError::InvalidSelectedPeer(other)),
                };
            };

            let stream = tcp_stream_with_retry("tcp_stream_with_retry", addr, self.policy)
                .await
                .map_err(|last_error| ReconnectError::ConnectRetriesExhausted { addr, last_error })?;

            match (self.handle_stream)(stream).await {
                Ok(SessionExit::Stop) => return Ok(()),
                Ok(SessionExit::Reconnect) => sleep(self.policy.reconnect_sleep).await,
                Err(error) => {
                    warn_reconnect_failure(&error);
                    sleep(self.policy.reconnect_sleep).await;
                }
            }
        }
    }
}

/// Connects to a single peer with the inner retry loop recovered at `0x439F860`
/// and `0x439FA90`.
///
/// `0x439F860` constructs a future with a `60.0` timeout and delegates into the
/// generic retry future. A successful connect immediately feeds the resulting
/// stream into the caller's stream handler; an exhausted retry set returns the
/// last connect error.
pub async fn tcp_stream_with_retry(
    desc: &'static str,
    addr: SocketAddr,
    policy: ReconnectPolicy,
) -> Result<TcpStream, io::Error> {
    retry_with_sleep(desc, policy.connect_retries, policy.connect_retry_sleep, |n_tries| async move {
        match timeout(policy.connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(error)) => Err(error),
            Err(_elapsed) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "tcp_stream_with_retry connect timeout",
            )),
        }
    })
    .await
}

/// Generic sleep-and-retry helper recovered from the `0x439FA90` monomorph.
///
/// The binary formats the warning as:
/// `AsyncSleepRetry::retry desc=[{desc}] n_tries={n_tries} failed: {error}`.
/// After the configured number of retries is exhausted, the last error is
/// returned to the caller; the panic string observed in rodata belongs to an
/// `unwrap` at a higher monomorph callsite.
pub async fn retry_with_sleep<F, Fut, T, E>(
    desc: &'static str,
    n_retries: usize,
    retry_sleep: Duration,
    mut op: F,
) -> Result<T, E>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: fmt::Display,
{
    let mut last_error = None;

    for n_tries in 0..=n_retries {
        match op(n_tries).await {
            Ok(value) => return Ok(value),
            Err(error) => {
                warn_retry_failure(desc, n_tries, &error);
                last_error = Some(error);
            }
        }

        if n_tries != n_retries {
            sleep(retry_sleep).await;
        }
    }

    match last_error {
        Some(error) => Err(error),
        None => panic!(
            "async_sleep_retry retries exhausted: {} [n_retries: {}]",
            desc, n_retries
        ),
    }
}

/// Decodes the compact peer-selection tag used by the seed state machine.
///
/// [INFERENCE] This is factored out for readability; the binary stores the tag
/// in adjacent bytes and constructs the socket address in place.
pub fn decode_peer_selection(tag: u8, validator_index: u8) -> PeerSelection {
    match tag {
        0 => PeerSelection::LocalDefault,
        1 => PeerSelection::LocalValidator { validator_index },
        2 => PeerSelection::NoPeer,
        _ => PeerSelection::NoPeer,
    }
}

#[inline]
fn warn_retry_failure<E: fmt::Display>(desc: &str, n_tries: usize, error: &E) {
    tracing::warn!(
        target: "net_utils::tcp::reconnecting_tcp_client",
        "AsyncSleepRetry::retry desc=[{}] n_tries={} failed: {}",
        desc,
        n_tries,
        error,
    );
}

#[inline]
fn warn_reconnect_failure<E: fmt::Display>(error: &E) {
    tracing::warn!(
        target: "net_utils::tcp::reconnecting_tcp_client",
        "reconnecting tcp client stream failed: {}; reconnecting",
        error,
    );
}
