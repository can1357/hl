//! Reconstructed from `/home/ubuntu/hl/code_Mainnet/net_utils/src/tcp/tcp_listener.rs`.
//!
//! Confidence: medium-high for port arithmetic, bind/listen options, accept4
//! flags, and retry/accept control flow; medium for generic handler names and
//! externally supplied callback types.
//!
//! Seeds expanded: `0x2048F10`, `0x22C47A0`, `0x22C54A0`, `0x438ED70`,
//! `0x47B4950`.
//!
//! IDA anchors used:
//! - `0x4EE12C0`: socket helper creates IPv4/IPv6 TCP socket with
//!   `SOCK_CLOEXEC`, sets `SO_REUSEADDR`, binds, listens with backlog `128`,
//!   and closes the fd on any bind/listen failure.
//! - `0x3CD6220`: `accept4(listener_fd, ..., SOCK_NONBLOCK | SOCK_CLOEXEC)`;
//!   success returns the fd plus normalized peer address, failure returns the
//!   errno-packed I/O error.
//! - `0x22C54A0`: generic async listen-with-retry future. It constructs a
//!   `NodePort`, logs `@@ trying @@ [ip: ...]`, invokes the bind closure, and
//!   retries through the shared `AsyncSleepRetry` state machine.
//! - `0x47B4950`: concrete gossip listener setup. It allocates the static label
//!   `gossip_rpc_requests`, computes `127.0.0.1:(4002 + index * 1000)`, then
//!   enters the same retry/bind path.
//! - `0x2048F10` and `0x22C47A0`: listener accept-loop futures. They poll an
//!   upstream receiver/stream of accepted work, call the accept wrapper, close
//!   failed accepted fds, register successful fds with Tokio, call the supplied
//!   per-connection handler, then continue accepting.
//!
//! IDA writes attempted in this wave: intended names
//! `net_utils_tcp_listener__listen_with_retry_poll`,
//! `net_utils_tcp_listener__poll_accept_loop`,
//! `net_utils_tcp_listener__poll_gossip_accept_loop`,
//! `net_utils_tcp_listener__setup_gossip_listener`,
//! `net_utils_tcp_listener__record_accept_metrics`; the shared IDA foreground
//! queue was full, so comments/types could not be committed from this worker.

#![allow(dead_code)]

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

const LISTEN_BACKLOG: i32 = 128;
const VALIDATOR_PORT_STRIDE: u16 = 1000;
const GOSSIP_RPC_REQUESTS_PORT: u16 = 4002;
const RETRY_ATTEMPTS: usize = 10;
const RETRY_SLEEP: Duration = Duration::from_secs(2);

const SOCK_CLOEXEC: i32 = 0o2000000;
const SOCK_NONBLOCK: i32 = 0o0004000;
const SOCK_STREAM: i32 = 1;
const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const SOL_SOCKET: i32 = 1;
const SO_REUSEADDR: i32 = 2;
const DEFAULT_TCP_PROTOCOL: i32 = 0;

unsafe extern "C" {
    #[link_name = "socket"]
    fn libc_socket(domain: i32, ty: i32, protocol: i32) -> i32;
    #[link_name = "setsockopt"]
    fn libc_setsockopt(fd: i32, level: i32, optname: i32, optval: *const i32, optlen: u32) -> i32;
    #[link_name = "bind"]
    fn libc_bind(fd: i32, addr: *const SockAddrStorage, len: u32) -> i32;
    #[link_name = "listen"]
    fn libc_listen(fd: i32, backlog: i32) -> i32;
    #[link_name = "accept4"]
    fn libc_accept4(fd: i32, addr: *mut SockAddrStorage, len: *mut u32, flags: i32) -> i32;
    #[link_name = "close"]
    fn libc_close(fd: i32) -> i32;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrStorage {
    family: u16,
    data: [u8; 126],
}

impl SockAddrStorage {
    const fn zeroed() -> Self {
        Self { family: 0, data: [0; 126] }
    }
}

/// The compact listener address shape used by the recovered socket helpers.
///
/// The binary keeps an internal enum tag (`0` for IPv4, `1` for IPv6, `2` for
/// error) and stores ports in network byte order before calling `bind`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePort {
    Ipv4 { ip: Ipv4Addr, port: u16 },
    Ipv6 { ip: Ipv6Addr, port: u16 },
}

impl NodePort {
    pub fn gossip_rpc_requests(validator_index: u8) -> Result<Self, TcpListenError> {
        let offset = VALIDATOR_PORT_STRIDE
            .checked_mul(u16::from(validator_index))
            .ok_or(TcpListenError::PortOverflow {
                base: GOSSIP_RPC_REQUESTS_PORT,
                validator_index,
            })?;
        let port = GOSSIP_RPC_REQUESTS_PORT
            .checked_add(offset)
            .ok_or(TcpListenError::PortOverflow {
                base: GOSSIP_RPC_REQUESTS_PORT,
                validator_index,
            })?;

        Ok(Self::Ipv4 { ip: Ipv4Addr::LOCALHOST, port })
    }

    pub fn socket_addr(self) -> SocketAddr {
        match self {
            Self::Ipv4 { ip, port } => SocketAddr::new(IpAddr::V4(ip), port),
            Self::Ipv6 { ip, port } => SocketAddr::new(IpAddr::V6(ip), port),
        }
    }

    fn encode_sockaddr(self) -> (SockAddrStorage, u32) {
        let mut storage = SockAddrStorage::zeroed();
        match self {
            Self::Ipv4 { ip, port } => {
                storage.family = AF_INET as u16;
                storage.data[0..2].copy_from_slice(&port.to_be_bytes());
                storage.data[2..6].copy_from_slice(&ip.octets());
                (storage, 16)
            }
            Self::Ipv6 { ip, port } => {
                storage.family = AF_INET6 as u16;
                storage.data[0..2].copy_from_slice(&port.to_be_bytes());
                storage.data[6..22].copy_from_slice(&ip.octets());
                (storage, 28)
            }
        }
    }
}

impl fmt::Display for NodePort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.socket_addr().fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenRetryPolicy {
    pub attempts: usize,
    pub sleep: Duration,
}

impl Default for ListenRetryPolicy {
    fn default() -> Self {
        Self { attempts: RETRY_ATTEMPTS, sleep: RETRY_SLEEP }
    }
}

#[derive(Debug)]
pub enum TcpListenError {
    PortOverflow { base: u16, validator_index: u8 },
    Bind { addr: SocketAddr, source: io::Error },
    RetryExhausted { addr: SocketAddr, last_error: io::Error },
    Accept(io::Error),
    Handler(String),
}

impl fmt::Display for TcpListenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PortOverflow { base, validator_index } => {
                write!(f, "port overflow: base={base} validator_index={validator_index}")
            }
            Self::Bind { addr, source } => write!(f, "failed to bind/listen on {addr}: {source}"),
            Self::RetryExhausted { addr, last_error } => {
                write!(f, "listener bind retries exhausted for {addr}: {last_error}")
            }
            Self::Accept(error) => write!(f, "tcp listener accept failed: {error}"),
            Self::Handler(error) => f.write_str(error),
        }
    }
}

impl std::error::Error for TcpListenError {}

pub struct BoundTcpListener {
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl BoundTcpListener {
    pub fn listener(&self) -> &TcpListener {
        &self.listener
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn into_inner(self) -> TcpListener {
        self.listener
    }
}

/// Recovered low-level bind helper (`0x4EE12C0`).
///
/// It uses a raw socket so the option order and close-on-error behavior match the
/// binary: socket -> `SO_REUSEADDR` -> bind -> listen. The socket is created
/// with `SOCK_CLOEXEC` and default TCP protocol (`0`); this reconstructed source
/// sets the fd nonblocking before handing it to Tokio.
pub fn bind_node_port(addr: NodePort) -> Result<BoundTcpListener, TcpListenError> {
    let socket_addr = addr.socket_addr();
    let domain = match addr {
        NodePort::Ipv4 { .. } => AF_INET,
        NodePort::Ipv6 { .. } => AF_INET6,
    };

    let fd = unsafe { libc_socket(domain, SOCK_STREAM | SOCK_CLOEXEC, DEFAULT_TCP_PROTOCOL) };
    if fd < 0 {
        return Err(TcpListenError::Bind { addr: socket_addr, source: io::Error::last_os_error() });
    }

    match configure_bind_listen(fd, addr) {
        Ok(()) => {
            let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
            if let Err(source) = std_listener.set_nonblocking(true) {
                return Err(TcpListenError::Bind { addr: socket_addr, source });
            }
            let listener = TcpListener::from_std(std_listener)
                .map_err(|source| TcpListenError::Bind { addr: socket_addr, source })?;
            Ok(BoundTcpListener { listener, local_addr: socket_addr })
        }
        Err(source) => {
            unsafe { libc_close(fd) };
            Err(TcpListenError::Bind { addr: socket_addr, source })
        }
    }
}

fn configure_bind_listen(fd: RawFd, addr: NodePort) -> io::Result<()> {
    let one = 1i32;
    let rc = unsafe {
        libc_setsockopt(
            fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &one,
            core::mem::size_of_val(&one) as u32,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    let (storage, len) = addr.encode_sockaddr();
    if unsafe { libc_bind(fd, &storage, len) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc_listen(fd, LISTEN_BACKLOG) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Async bind/retry wrapper recovered from `0x22C54A0`.
pub async fn listen_with_retry(
    desc: &'static str,
    addr: NodePort,
    policy: ListenRetryPolicy,
) -> Result<BoundTcpListener, TcpListenError> {
    let socket_addr = addr.socket_addr();
    let mut last_error = None;

    for attempt in 0..=policy.attempts {
        warn_trying(desc, addr);
        match bind_node_port(addr) {
            Ok(listener) => return Ok(listener),
            Err(TcpListenError::Bind { source, .. }) => {
                warn_retry_failure(desc, attempt, &source);
                last_error = Some(source);
            }
            Err(error) => return Err(error),
        }

        if attempt != policy.attempts {
            sleep(policy.sleep).await;
        }
    }

    Err(TcpListenError::RetryExhausted {
        addr: socket_addr,
        last_error: last_error.unwrap_or_else(|| io::Error::other("listener retry exhausted without an OS error")),
    })
}

/// Concrete gossip listener constructor recovered from `0x47B4950`.
pub async fn listen_gossip_rpc_requests(
    validator_index: u8,
) -> Result<BoundTcpListener, TcpListenError> {
    let addr = NodePort::gossip_rpc_requests(validator_index)?;
    listen_with_retry("gossip_rpc_requests", addr, ListenRetryPolicy::default()).await
}

#[derive(Debug)]
pub struct AcceptedTcpStream {
    pub stream: TcpStream,
    pub peer_addr: SocketAddr,
}

/// Accept one connection using the low-level `accept4` wrapper semantics from
/// `0x3CD6220`.
pub fn accept4_nonblocking(listener_fd: RawFd) -> Result<(RawFd, SocketAddr), TcpListenError> {
    let mut storage = SockAddrStorage::zeroed();
    let mut len = core::mem::size_of::<SockAddrStorage>() as u32;
    let fd = unsafe {
        libc_accept4(
            listener_fd,
            &mut storage,
            &mut len,
            SOCK_NONBLOCK | SOCK_CLOEXEC,
        )
    };

    if fd < 0 {
        return Err(TcpListenError::Accept(io::Error::last_os_error()));
    }

    match decode_sockaddr(&storage, len) {
        Some(peer) => Ok((fd, peer)),
        None => {
            unsafe { libc_close(fd) };
            Err(TcpListenError::Accept(io::Error::new(
                io::ErrorKind::InvalidData,
                "accepted socket had unsupported peer address family",
            )))
        }
    }
}

fn decode_sockaddr(storage: &SockAddrStorage, len: u32) -> Option<SocketAddr> {
    match i32::from(storage.family) {
        AF_INET if len >= 16 => {
            let port = u16::from_be_bytes([storage.data[0], storage.data[1]]);
            let ip = Ipv4Addr::new(storage.data[2], storage.data[3], storage.data[4], storage.data[5]);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        AF_INET6 if len >= 28 => {
            let port = u16::from_be_bytes([storage.data[0], storage.data[1]]);
            let flowinfo =
                u32::from_ne_bytes([storage.data[2], storage.data[3], storage.data[4], storage.data[5]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&storage.data[6..22]);
            let scope_id =
                u32::from_ne_bytes([storage.data[22], storage.data[23], storage.data[24], storage.data[25]]);
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                port,
                flowinfo,
                scope_id,
            )))
        }
        _ => None,
    }
}

/// High-level accept loop represented by the two async state machines at
/// `0x2048F10` and `0x22C47A0`.
///
/// The disassembly shows two monomorphs with the same loop: poll accept, remove
/// a pending waiter from an intrusive list, convert/register the fd, invoke a
/// callback future and close fds when callback construction fails before returning to the listener state.
pub async fn run_accept_loop<H, Fut, E>(listener: TcpListener, mut handler: H) -> Result<(), TcpListenError>
where
    H: FnMut(AcceptedTcpStream) -> Fut,
    Fut: Future<Output = Result<(), E>>,
    E: fmt::Display,
{
    loop {
        listener.readable().await.map_err(TcpListenError::Accept)?;

        let (fd, peer_addr) = match accept4_nonblocking(listener.as_raw_fd()) {
            Ok(accepted) => accepted,
            Err(TcpListenError::Accept(error)) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        };

        let stream = tcp_stream_from_accepted_fd(fd)?;
        let accepted = AcceptedTcpStream { stream, peer_addr };

        handler(accepted)
            .await
            .map_err(|error| TcpListenError::Handler(format!("tcp listener connection handler failed: {error}")))?;
    }
}

fn tcp_stream_from_accepted_fd(fd: RawFd) -> Result<TcpStream, TcpListenError> {
    let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
    TcpStream::from_std(std_stream).map_err(TcpListenError::Accept)
}

/// Best-effort reconstruction of the address gate visible in the accept-loop
/// monomorphs (`0x20493B2..0x2049425`).
///
/// The binary checks compact IPv4/IPv6 encodings before mutating listener stats.
/// For source readability this is expressed as local/loopback acceptance. The
/// caller still accepts the connection; this predicate controls only the
/// bookkeeping path.
pub fn peer_counts_as_local_for_listener_stats(peer: SocketAddr) -> bool {
    match peer.ip() {
        IpAddr::V4(ip) => ip.is_loopback() || ip.octets()[0] == 11 || ip.octets()[0] == 13,
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}

fn warn_trying(desc: &str, addr: NodePort) {
    eprintln!(" WARN >>> {desc} @@ trying @@ [ip: {addr}]\n");
}

fn warn_retry_failure(desc: &str, attempt: usize, error: &io::Error) {
    eprintln!("AsyncSleepRetry::retry desc=[{desc}] n_tries={attempt} failed: {error}");
}
