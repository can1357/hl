//! Reconstructed from `/home/ubuntu/hl/code_Mainnet/net_utils/src/tcp/tcp_stream.rs`.
//!
//! Primary seed EAs expanded: `0x2034EB0`, `0x2036460`, `0x20485E0`,
//! `0x20487F0`, `0x22615B0`, `0x4387910`, `0x4387C80`, `0x439EDD0`,
//! `0x439EFE0`, `0x4B399A0`.
//!
//! Confidence: high for the read-exact, write-all, five-byte header, early-EOF,
//! pending/completed/poisoned state transitions, and frame layout. Confidence is
//! lower for the original public type names: the binary mostly exposes lowered
//! async futures and shared monomorphs also referenced from `tcp/read.rs`,
//! `tcp/write.rs`, `async_sleep_retry.rs`, and `reconnecting_tcp_client.rs`.
//!
//! IDA tag plan. The IDA worker was saturated by background analysis during this
//! wave, so these names/comments/types could not be committed even after retry:
//! - `0x2034EB0` / `0x4387C80` -> `net_utils_tcp_stream__poll_read_exact`
//! - `0x2036460` / `0x4387910` -> `net_utils_tcp_stream__poll_write_all`
//! - `0x20485E0` / `0x439EDD0` -> `net_utils_tcp_stream__poll_read_frame_header`
//! - `0x20487F0` / `0x439EFE0` -> `net_utils_tcp_stream__poll_read_frame`
//! - `0x22615B0` -> shared outer async client state machine with an embedded
//!   tcp-stream read await at source line 45.
//! - `0x4B399A0` -> shared reconnecting stream driver with an embedded
//!   tcp-stream connect/read await at source line 33.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::time::{sleep, timeout};

pub const FRAME_HEADER_LEN: usize = 5;
pub const COMPRESSION_FLAG_RAW: u8 = 0;
pub const COMPRESSION_FLAG_LZ4: u8 = 1;
pub const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(40);
pub const READ_PAYLOAD_TIMEOUT: Duration = Duration::from_secs(20);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
pub const CONNECT_RETRY_ATTEMPTS: usize = 10;
pub const CONNECT_RETRY_SLEEP: Duration = Duration::from_secs(2);
pub const MAX_READ_CHUNK_BYTES: usize = 4_000_000;
pub const EARLY_EOF_ERROR_CODE: u32 = 37;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RecoveredPollState {
    Initial = 0,
    Ready = 1,
    Poisoned = 2,
    Pending = 3,
}

impl Default for RecoveredPollState {
    fn default() -> Self {
        Self::Initial
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    pub payload_len: usize,
    pub compression_flag: u8,
}

impl FrameHeader {
    #[inline]
    pub fn is_lz4(self) -> bool {
        self.compression_flag == COMPRESSION_FLAG_LZ4
    }

    #[inline]
    pub fn encode(self) -> Result<[u8; FRAME_HEADER_LEN], TcpStreamError> {
        let payload_len = u32::try_from(self.payload_len).map_err(|_| TcpStreamError::FrameTooLarge {
            len: self.payload_len,
            max_len: u32::MAX as usize,
        })?;

        let mut header = [0_u8; FRAME_HEADER_LEN];
        header[..4].copy_from_slice(&payload_len.to_be_bytes());
        header[4] = self.compression_flag;
        Ok(header)
    }

    #[inline]
    pub fn decode(bytes: [u8; FRAME_HEADER_LEN]) -> Self {
        let payload_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        Self {
            payload_len,
            compression_flag: bytes[4],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpStreamPolicy {
    pub connect_timeout: Duration,
    pub connect_retries: usize,
    pub connect_retry_sleep: Duration,
    pub read_header_timeout: Duration,
    pub read_payload_timeout: Duration,
    pub use_read_timeouts: bool,
}

impl Default for TcpStreamPolicy {
    fn default() -> Self {
        Self {
            connect_timeout: CONNECT_TIMEOUT,
            connect_retries: CONNECT_RETRY_ATTEMPTS,
            connect_retry_sleep: CONNECT_RETRY_SLEEP,
            read_header_timeout: READ_HEADER_TIMEOUT,
            read_payload_timeout: READ_PAYLOAD_TIMEOUT,
            use_read_timeouts: true,
        }
    }
}

#[derive(Debug)]
pub enum TcpStreamError {
    ResolveAddress { desc: &'static str },
    ConnectTimedOut { addr: SocketAddr, timeout: Duration },
    ConnectRetriesExhausted { addr: SocketAddr, last_error: io::Error },
    Io { desc: &'static str, source: io::Error },
    EarlyEof { desc: &'static str, code: u32 },
    ReadTimedOut { desc: &'static str, timeout: Duration },
    WriteZero { desc: &'static str },
    FrameTooLarge { len: usize, max_len: usize },
    Decode { desc: &'static str, source: Box<dyn std::error::Error + Send + Sync> },
    Encode { desc: &'static str, source: Box<dyn std::error::Error + Send + Sync> },
    Lz4Decode { source: lz4_flex::block::DecompressError },
}

impl fmt::Display for TcpStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResolveAddress { desc } => write!(f, "{desc}: could not resolve to any address"),
            Self::ConnectTimedOut { addr, timeout } => write!(f, "connect to {addr} timed out after {timeout:?}"),
            Self::ConnectRetriesExhausted { addr, last_error } => {
                write!(f, "tcp_stream_with_retry exhausted for {addr}: {last_error}")
            }
            Self::Io { desc, source } => write!(f, "{desc}: {source}"),
            Self::EarlyEof { desc, code } => write!(f, "{desc}: early eof (code {code})"),
            Self::ReadTimedOut { desc, timeout } => write!(f, "{desc}: timed out after {timeout:?}"),
            Self::WriteZero { desc } => write!(f, "{desc}: failed to write whole buffer"),
            Self::FrameTooLarge { len, max_len } => write!(f, "tcp frame over limit @@ [len: {len}] @ [max_len: {max_len}]"),
            Self::Decode { desc, source } => write!(f, "{desc}: bincode decode failed: {source}"),
            Self::Encode { desc, source } => write!(f, "{desc}: bincode encode failed: {source}"),
            Self::Lz4Decode { source } => write!(f, "tcp stream lz4 decode failed: {source}"),
        }
    }
}

impl std::error::Error for TcpStreamError {}

pub trait BincodeCodec {
    type EncodeError: std::error::Error + Send + Sync + 'static;
    type DecodeError: std::error::Error + Send + Sync + 'static;

    fn encode_to_vec<T: ?Sized>(&self, value: &T) -> Result<Vec<u8>, Self::EncodeError>;
    fn decode_from_slice<T>(&self, bytes: &[u8]) -> Result<(T, usize), Self::DecodeError>;
}

#[derive(Debug)]
pub struct RecoveredStateSnapshot {
    pub read_exact: RecoveredPollState,
    pub write_all: RecoveredPollState,
    pub read_header: RecoveredPollState,
    pub read_frame: RecoveredPollState,
}

pub struct TcpStream {
    inner: TokioTcpStream,
    policy: TcpStreamPolicy,
    read_exact_state: RecoveredPollState,
    write_all_state: RecoveredPollState,
    read_header_state: RecoveredPollState,
    read_frame_state: RecoveredPollState,
}

impl TcpStream {
    pub fn from_tokio(inner: TokioTcpStream) -> Self {
        Self::with_policy(inner, TcpStreamPolicy::default())
    }

    pub fn with_policy(inner: TokioTcpStream, policy: TcpStreamPolicy) -> Self {
        Self {
            inner,
            policy,
            read_exact_state: RecoveredPollState::Initial,
            write_all_state: RecoveredPollState::Initial,
            read_header_state: RecoveredPollState::Initial,
            read_frame_state: RecoveredPollState::Initial,
        }
    }

    pub async fn connect(addr: SocketAddr) -> Result<Self, TcpStreamError> {
        Self::connect_with_policy(addr, TcpStreamPolicy::default()).await
    }

    /// Connects with the recovered line-33 policy: ten attempts, two seconds
    /// between attempts, and a sixty-second timeout around each `TcpStream::connect`.
    pub async fn connect_with_policy(addr: SocketAddr, policy: TcpStreamPolicy) -> Result<Self, TcpStreamError> {
        let inner = tcp_stream_with_retry("tcp_stream_with_retry", addr, policy).await?;
        Ok(Self::with_policy(inner, policy))
    }

    pub fn get_ref(&self) -> &TokioTcpStream {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut TokioTcpStream {
        &mut self.inner
    }

    pub fn into_inner(self) -> TokioTcpStream {
        self.inner
    }

    pub fn recovered_state(&self) -> RecoveredStateSnapshot {
        RecoveredStateSnapshot {
            read_exact: self.read_exact_state,
            write_all: self.write_all_state,
            read_header: self.read_header_state,
            read_frame: self.read_frame_state,
        }
    }

    /// Reads exactly the supplied buffer, matching the `0x2034EB0` / `0x4387C80`
    /// state machine.
    ///
    /// The lowered future keeps `(stream, ptr, len, filled)` in its frame. It
    /// marks state `3` before returning `Pending`, state `1` once complete, and
    /// state `2` on unwind. A poll that reports success without increasing the
    /// filled count constructs `io::ErrorKind::UnexpectedEof` with text
    /// `early eof` and numeric code `37` in the binary's packed error path.
    pub async fn read_exact_recovered(&mut self, desc: &'static str, dst: &mut [u8]) -> Result<(), TcpStreamError> {
        let timeout = self.policy.read_payload_timeout;
        let use_timeout = self.policy.use_read_timeouts;
        self.read_exact_or_eof(desc, dst, timeout, use_timeout).await
    }

    /// Writes the full buffer, matching the `0x2036460` / `0x4387910` state
    /// machine shared with `tcp/write.rs`.
    ///
    /// The recovered frame stores the active stream pointer, current slice
    /// pointer, and remaining length at offsets corresponding to `+0xc8`,
    /// `+0xd0`, and `+0xd8`. Each successful short write advances the pointer and
    /// subtracts the byte count. A `0` byte write maps to the immediate
    /// `0x1700000003`, the binary's packed `WriteZero` error.
    pub async fn write_all_recovered(&mut self, desc: &'static str, buf: &[u8]) -> Result<(), TcpStreamError> {
        self.write_all_state = RecoveredPollState::Initial;
        let mut remaining = buf;

        while !remaining.is_empty() {
            self.write_all_state = RecoveredPollState::Pending;
            let n = match self.inner.write(remaining).await {
                Ok(n) => n,
                Err(source) => {
                    self.write_all_state = RecoveredPollState::Ready;
                    return Err(TcpStreamError::Io { desc, source });
                }
            };

            if n == 0 {
                self.write_all_state = RecoveredPollState::Ready;
                return Err(TcpStreamError::WriteZero { desc });
            }

            remaining = &remaining[n..];
        }

        self.write_all_state = RecoveredPollState::Ready;
        Ok(())
    }

    /// Reads and decodes the five-byte frame header reconstructed at `0x20485E0`
    /// and `0x439EDD0`.
    pub async fn read_frame_header(&mut self) -> Result<FrameHeader, TcpStreamError> {
        self.read_header_state = RecoveredPollState::Initial;
        let mut header = [0_u8; FRAME_HEADER_LEN];
        let timeout = self.policy.read_header_timeout;
        let use_timeout = self.policy.use_read_timeouts;

        self.read_header_state = RecoveredPollState::Pending;
        let result = self
            .read_exact_or_eof("tcp_bytes", &mut header, timeout, use_timeout)
            .await
            .map(|()| FrameHeader::decode(header));

        self.read_header_state = RecoveredPollState::Ready;
        result
    }

    /// Reads one framed payload using the recovered `0x20487F0` / `0x439EFE0`
    /// orchestration: header await, limit check, exact payload allocation/read,
    /// optional LZ4 size-prepended decode when the flag byte is exactly `1`.
    pub async fn read_frame(&mut self, desc: &'static str, max_len: usize) -> Result<Vec<u8>, TcpStreamError> {
        self.read_frame_state = RecoveredPollState::Initial;

        self.read_frame_state = RecoveredPollState::Pending;
        let header = match self.read_frame_header().await {
            Ok(header) => header,
            Err(error) => {
                self.read_frame_state = RecoveredPollState::Ready;
                return Err(error);
            }
        };
        if header.payload_len > max_len {
            self.read_frame_state = RecoveredPollState::Ready;
            return Err(TcpStreamError::FrameTooLarge {
                len: header.payload_len,
                max_len,
            });
        }

        let mut payload = vec![0_u8; header.payload_len];
        if let Err(error) = self.read_payload_exact(desc, &mut payload).await {
            self.read_frame_state = RecoveredPollState::Ready;
            return Err(error);
        }

        let payload = if header.is_lz4() {
            match lz4_flex::block::decompress_size_prepended(&payload) {
                Ok(payload) => payload,
                Err(source) => {
                    self.read_frame_state = RecoveredPollState::Ready;
                    return Err(TcpStreamError::Lz4Decode { source });
                }
            }
        } else {
            payload
        };

        if payload.len() > max_len {
            self.read_frame_state = RecoveredPollState::Ready;
            return Err(TcpStreamError::FrameTooLarge {
                len: payload.len(),
                max_len,
            });
        }

        self.read_frame_state = RecoveredPollState::Ready;
        Ok(payload)
    }

    pub async fn read_bincode<T, C>(
        &mut self,
        desc: &'static str,
        max_len: usize,
        codec: &C,
    ) -> Result<T, TcpStreamError>
    where
        C: BincodeCodec + ?Sized,
    {
        let bytes = self.read_frame(desc, max_len).await?;
        let (value, _consumed) = codec
            .decode_from_slice(&bytes)
            .map_err(|source| TcpStreamError::Decode { desc, source: Box::new(source) })?;
        Ok(value)
    }

    pub async fn write_frame(&mut self, desc: &'static str, payload: &[u8], compress: bool) -> Result<(), TcpStreamError> {
        let (flag, frame_payload) = if compress {
            (COMPRESSION_FLAG_LZ4, lz4_flex::block::compress_prepend_size(payload))
        } else {
            (COMPRESSION_FLAG_RAW, payload.to_vec())
        };

        let header = FrameHeader {
            payload_len: frame_payload.len(),
            compression_flag: flag,
        }
        .encode()?;

        self.write_all_recovered(desc, &header).await?;
        self.write_all_recovered(desc, &frame_payload).await
    }

    pub async fn write_bincode<T, C>(
        &mut self,
        desc: &'static str,
        value: &T,
        codec: &C,
        compress: bool,
    ) -> Result<(), TcpStreamError>
    where
        T: ?Sized,
        C: BincodeCodec + ?Sized,
    {
        let bytes = codec
            .encode_to_vec(value)
            .map_err(|source| TcpStreamError::Encode { desc, source: Box::new(source) })?;
        self.write_frame(desc, &bytes, compress).await
    }

    async fn read_payload_exact(&mut self, desc: &'static str, mut dst: &mut [u8]) -> Result<(), TcpStreamError> {
        while !dst.is_empty() {
            let chunk_len = dst.len().min(MAX_READ_CHUNK_BYTES);
            let (chunk, rest) = dst.split_at_mut(chunk_len);
            let timeout = self.policy.read_payload_timeout;
            let use_timeout = self.policy.use_read_timeouts;
            self.read_exact_or_eof(desc, chunk, timeout, use_timeout).await?;
            dst = rest;
        }
        Ok(())
    }

    async fn read_exact_or_eof(
        &mut self,
        desc: &'static str,
        mut dst: &mut [u8],
        read_timeout: Duration,
        use_timeout: bool,
    ) -> Result<(), TcpStreamError> {
        self.read_exact_state = RecoveredPollState::Initial;

        while !dst.is_empty() {
            self.read_exact_state = RecoveredPollState::Pending;
            let result = if use_timeout {
                match timeout(read_timeout, self.inner.read(dst)).await {
                    Ok(result) => result,
                    Err(_elapsed) => {
                        self.read_exact_state = RecoveredPollState::Ready;
                        return Err(TcpStreamError::ReadTimedOut { desc, timeout: read_timeout });
                    }
                }
            } else {
                self.inner.read(dst).await
            };

            let n = match result {
                Ok(n) => n,
                Err(source) => {
                    self.read_exact_state = RecoveredPollState::Ready;
                    return Err(TcpStreamError::Io { desc, source });
                }
            };

            if n == 0 {
                self.read_exact_state = RecoveredPollState::Ready;
                return Err(TcpStreamError::EarlyEof {
                    desc,
                    code: EARLY_EOF_ERROR_CODE,
                });
            }

            let (_, rest) = dst.split_at_mut(n);
            dst = rest;
        }

        self.read_exact_state = RecoveredPollState::Ready;
        Ok(())
    }
}

/// Shared connect retry helper represented by the tcp-stream line-33 refs inside
/// the larger `0x4B399A0` reconnecting-client monomorph.
pub async fn tcp_stream_with_retry(
    desc: &'static str,
    addr: SocketAddr,
    policy: TcpStreamPolicy,
) -> Result<TokioTcpStream, TcpStreamError> {
    retry_io(desc, policy.connect_retries, policy.connect_retry_sleep, |attempt| async move {
        match timeout(policy.connect_timeout, TokioTcpStream::connect(addr)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(source)) => Err(TcpStreamError::Io { desc, source }),
            Err(_elapsed) => Err(TcpStreamError::ConnectTimedOut {
                addr,
                timeout: policy.connect_timeout,
            }),
        }
        .map_err(|error| (attempt, error))
    })
    .await
    .map_err(|(_attempt, error)| match error {
        TcpStreamError::Io { source, .. } => TcpStreamError::ConnectRetriesExhausted { addr, last_error: source },
        other => other,
    })
}

pub async fn retry_io<F, Fut, T>(
    desc: &'static str,
    n_tries: usize,
    retry_sleep: Duration,
    mut f: F,
) -> Result<T, (usize, TcpStreamError)>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Result<T, (usize, TcpStreamError)>>,
{
    let attempts = n_tries.max(1);
    let mut last_error = None;

    for attempt in 0..attempts {
        match f(attempt).await {
            Ok(value) => return Ok(value),
            Err((n, error)) => {
                warn_retry_failure(desc, n, &error);
                last_error = Some((n, error));
                if attempt + 1 != attempts {
                    sleep(retry_sleep).await;
                }
            }
        }
    }

    Err(last_error.expect("retry loop always records an error before exhaustion"))
}

fn warn_retry_failure(desc: &str, n_tries: usize, error: &TcpStreamError) {
    let _ = (desc, n_tries, error);
}
