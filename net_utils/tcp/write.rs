//! Reconstructed from `/home/ubuntu/hl/code_Mainnet/net_utils/src/tcp/write.rs`.
//!
//! Confidence: high for the wire frame shape, length endianness, compression
//! threshold, LZ4 size-prefix convention, write-all loop, and 60 second timeout;
//! medium for wrapper names and metric plumbing in inlined async monomorphs.
//!
//! Seed EAs expanded: `0x1FD7810`, `0x2036460`, `0x2037AC0`, `0x204B0A0`,
//! `0x204B1F0`, `0x204B340`, `0x43831E0`, `0x4386F70`, `0x4387910`,
//! `0x43A17C0`, `0x4B363B0`.
//!
//! IDA anchors used:
//! - `0x2036460`: generic `poll_write_all` future. It loops on
//!   `AsyncWrite::poll_write`, advances the slice after partial writes, returns
//!   `Pending` without losing progress, panics through the Rust slice path
//!   `"mid > len"` if a write count exceeds the remaining length, and converts
//!   `Ok(0)` to an I/O error (`0x1700000003`).
//! - `0x204B340`: main TCP frame writer monomorph. It builds
//!   `[u32 BE length][u8 compression_flag][payload]`, optionally compresses the
//!   payload, writes the complete buffer with the helper above, and records
//!   elapsed-time/byte-count stats around both compression and socket write.
//! - `0x43A17C0`: second monomorph of the same frame writer used by a different
//!   stream/future type. Its control flow and constants match `0x204B340`.
//! - `0x4B363B0`: larger owner future with the same inline frame construction;
//!   this confirms the shared constants (`0x401`, `0xffff`, `0x3d0900`, 60s) and
//!   compressed payload prefix layout.
//! - `0x204B0A0` and `0x204B1F0`: bincode-serialize-then-write wrappers using
//!   serializer callees `0x28BFBD0` / `0x28BF690`, a hard-coded timeout of
//!   `60.0`, and the same frame writer.
//! - `0x1FD7810`: wrapper labelled by rodata `"write evm kv batch"`; it serializes
//!   a payload and delegates to the common frame writer.
//! - `0x2037AC0`: foreign ABCI connection-check future. It calls the frame writer
//!   for `"abci_stream send tcp greeting"` and a tcp/read helper for the matching
//!   receive side; source placement belongs to `node/src/abci_stream.rs`.
//!
//! IDA writes attempted: `net_utils_tcp_write__poll_write_all_chunk`,
//! `net_utils_tcp_write__poll_write_frame`,
//! `net_utils_tcp_write__poll_write_bincode_packet`,
//! `net_utils_tcp_write__poll_write_evm_kv_batch`, and
//! `node_abci_stream__poll_connection_checks`. The shared IDA queue was full, so
//! this worker could not commit renames/comments/types.

#![allow(dead_code)]

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::AsyncWrite;

const FRAME_TIMEOUT: Duration = Duration::from_secs(60);
const COMPRESSION_THRESHOLD: usize = 0x401;
const SMALL_COMPRESS_SCRATCH: usize = 0x2000;
const LARGE_COMPRESS_SCRATCH: usize = 0x4000;
const SMALL_INPUT_LIMIT: usize = 0xffff;
const FRAME_HEADER_LEN: usize = 5;
const LZ4_SIZE_PREFIX_LEN: usize = 4;
const STATS_BUCKET_NANOS: u64 = 0x3d0900;
const DISABLE_COMPRESSION_PORT_MASKED: u16 = 0x0f9e;
const TCP_CHUNK_LABEL: &str = "tcp_chunk";
const EVM_KV_BATCH_LABEL: &str = "write evm kv batch";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompressionFlag {
    Raw = 0,
    Lz4 = 1,
}

impl CompressionFlag {
    #[inline]
    fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TcpWriteOptions {
    /// The recovered code skips compression when `(port & !1) == 0x0f9e`.
    /// [INFERENCE] This is a peer/listener port field stored in the stream state.
    pub peer_port_masked: Option<u16>,
    pub compression_enabled: bool,
    pub timeout: Duration,
}

impl Default for TcpWriteOptions {
    fn default() -> Self {
        Self {
            peer_port_masked: None,
            compression_enabled: true,
            timeout: FRAME_TIMEOUT,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TcpFrame {
    pub flag: CompressionFlag,
    /// The bytes after the one-byte compression flag. For compressed frames this
    /// includes the 4-byte little-endian uncompressed-size prefix used by
    /// `lz4_flex::block::compress_prepend_size`.
    pub payload: Vec<u8>,
}

impl TcpFrame {
    pub fn total_len(&self) -> usize {
        FRAME_HEADER_LEN + self.payload.len()
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), TcpWriteError> {
        let len = u32::try_from(self.payload.len()).map_err(|_| TcpWriteError::FrameTooLarge {
            len: self.payload.len(),
        })?;

        out.reserve(FRAME_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&len.to_be_bytes());
        out.push(self.flag.as_u8());
        out.extend_from_slice(&self.payload);
        Ok(())
    }

    pub fn into_wire_bytes(self) -> Result<Vec<u8>, TcpWriteError> {
        let mut out = Vec::with_capacity(self.total_len());
        self.encode_into(&mut out)?;
        Ok(out)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TcpWriteStats {
    pub raw_len: usize,
    pub framed_len: usize,
    pub flag: CompressionFlag,
    pub compress_elapsed: Duration,
    pub write_elapsed: Duration,
    pub stats_bucket_nanos: u64,
}

#[derive(Debug)]
pub enum TcpWriteError {
    FrameTooLarge { len: usize },
    Io(io::Error),
    Bincode(BincodeWriteError),
}

impl fmt::Display for TcpWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge { len } => write!(f, "tcp frame payload too large: {len}"),
            Self::Io(error) => write!(f, "tcp write failed: {error}"),
            Self::Bincode(error) => write!(f, "bincode serialization failed: {error}"),
        }
    }
}

impl std::error::Error for TcpWriteError {}

impl From<io::Error> for TcpWriteError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<BincodeWriteError> for TcpWriteError {
    fn from(error: BincodeWriteError) -> Self {
        Self::Bincode(error)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BincodeWriteError {
    label: &'static str,
    message: &'static str,
}

impl BincodeWriteError {
    pub const fn new(label: &'static str, message: &'static str) -> Self {
        Self { label, message }
    }
}

impl fmt::Display for BincodeWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.label, self.message)
    }
}

impl std::error::Error for BincodeWriteError {}

/// Local stand-in for bincode-fork's recovered `Encode` trait.
///
/// The write wrappers in this file call monomorphized serializers before entering
/// `poll_write_frame`; the concrete serializer bodies belong under
/// `recon/bincode_fork/src/ser/write.rs`.
pub trait BincodePacket {
    fn encode_bincode(&self, out: &mut Vec<u8>) -> Result<(), BincodeWriteError>;
}

#[derive(Debug)]
pub struct WriteAllChunk<'a, W> {
    writer: Pin<&'a mut W>,
    remaining: &'a [u8],
}

impl<'a, W: AsyncWrite + ?Sized> WriteAllChunk<'a, W> {
    pub fn new(writer: Pin<&'a mut W>, chunk: &'a [u8]) -> Self {
        Self { writer, remaining: chunk }
    }

    pub fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.remaining.is_empty() {
            let written = match self.writer.as_mut().poll_write(cx, self.remaining) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    )))
                }
                Poll::Ready(Ok(written)) => written,
            };

            if written > self.remaining.len() {
                panic!("mid > len");
            }
            self.remaining = &self.remaining[written..];
        }

        Poll::Ready(Ok(()))
    }
}

/// Recovered `0x2036460` behavior in direct async form.
pub async fn write_all_chunk<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    mut chunk: &[u8],
) -> io::Result<()> {
    use tokio::io::AsyncWriteExt;

    while !chunk.is_empty() {
        let written = writer.write(chunk).await?;
        if written == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "failed to write whole buffer"));
        }
        if written > chunk.len() {
            panic!("mid > len");
        }
        chunk = &chunk[written..];
    }
    Ok(())
}

pub fn should_compress(payload_len: usize, options: TcpWriteOptions) -> bool {
    if !options.compression_enabled || payload_len < COMPRESSION_THRESHOLD {
        return false;
    }

    match options.peer_port_masked {
        Some(port) => (port & !1) != DISABLE_COMPRESSION_PORT_MASKED,
        None => true,
    }
}

pub fn build_frame(payload: &[u8], options: TcpWriteOptions) -> Result<TcpFrame, TcpWriteError> {
    if payload.len() > u32::MAX as usize {
        return Err(TcpWriteError::FrameTooLarge { len: payload.len() });
    }
    if should_compress(payload.len(), options) {
        let started = Instant::now();
        let compressed = compress_payload_prepend_size(payload);
        let _compress_elapsed = started.elapsed();

        return Ok(TcpFrame { flag: CompressionFlag::Lz4, payload: compressed });
    }

    Ok(TcpFrame { flag: CompressionFlag::Raw, payload: payload.to_vec() })
}

fn compress_payload_prepend_size(payload: &[u8]) -> Vec<u8> {
    // `0x204B340` allocates a Vec whose first four bytes are the original length,
    // then writes LZ4 block bytes after that prefix. It uses 8 KiB scratch for
    // inputs below 64 KiB and 16 KiB scratch above that; the final Vec capacity is
    // still allowed to grow if the compressed block exceeds the first reserve.
    let scratch = if payload.len() < SMALL_INPUT_LIMIT {
        SMALL_COMPRESS_SCRATCH
    } else {
        LARGE_COMPRESS_SCRATCH
    };
    let mut out = Vec::with_capacity(LZ4_SIZE_PREFIX_LEN + scratch.max(payload.len()));
    let raw_len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&raw_len.to_le_bytes());
    out.extend_from_slice(&lz4_flex::block::compress(payload));
    out
}

/// Recovered `0x204B340` / `0x43A17C0` behavior.
pub async fn write_frame<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    payload: &[u8],
    options: TcpWriteOptions,
) -> Result<TcpWriteStats, TcpWriteError> {
    let compress_started = Instant::now();
    let frame = build_frame(payload, options)?;
    let compress_elapsed = compress_started.elapsed();
    let flag = frame.flag;
    let raw_len = payload.len();
    let wire = frame.into_wire_bytes()?;
    let framed_len = wire.len();

    let write_started = Instant::now();
    write_all_chunk(writer, &wire).await?;
    let write_elapsed = write_started.elapsed();

    Ok(TcpWriteStats {
        raw_len,
        framed_len,
        flag,
        compress_elapsed,
        write_elapsed,
        stats_bucket_nanos: STATS_BUCKET_NANOS,
    })
}

pub async fn write_bincode_packet<W, T>(
    writer: &mut W,
    value: &T,
    options: TcpWriteOptions,
) -> Result<TcpWriteStats, TcpWriteError>
where
    W: AsyncWrite + Unpin + ?Sized,
    T: BincodePacket + ?Sized,
{
    let mut payload = Vec::new();
    value.encode_bincode(&mut payload)?;
    write_frame(writer, &payload, options).await
}

/// Recovered `0x1FD7810` wrapper label.
pub async fn write_evm_kv_batch<W, T>(
    writer: &mut W,
    batch: &T,
    mut options: TcpWriteOptions,
) -> Result<TcpWriteStats, TcpWriteError>
where
    W: AsyncWrite + Unpin + ?Sized,
    T: BincodePacket + ?Sized,
{
    options.timeout = FRAME_TIMEOUT;
    let mut payload = Vec::new();
    encode_labeled_bincode(EVM_KV_BATCH_LABEL, batch, &mut payload)?;
    write_frame(writer, &payload, options).await
}

/// Recovered `0x204B0A0`/`0x204B1F0` shape: serialize first, then enter the
/// common TCP frame writer with a 60 second timeout.
pub async fn write_labeled_bincode_packet<W, T>(
    writer: &mut W,
    label: &'static str,
    value: &T,
    mut options: TcpWriteOptions,
) -> Result<TcpWriteStats, TcpWriteError>
where
    W: AsyncWrite + Unpin + ?Sized,
    T: BincodePacket + ?Sized,
{
    options.timeout = FRAME_TIMEOUT;
    let mut payload = Vec::new();
    encode_labeled_bincode(label, value, &mut payload)?;
    write_frame(writer, &payload, options).await
}

fn encode_labeled_bincode<T: BincodePacket + ?Sized>(
    label: &'static str,
    value: &T,
    out: &mut Vec<u8>,
) -> Result<(), BincodeWriteError> {
    let before = out.len();
    value.encode_bincode(out).map_err(|_| BincodeWriteError::new(label, "serialize failed"))?;
    if out.len() < before {
        return Err(BincodeWriteError::new(label, "serializer truncated output"));
    }
    Ok(())
}

/// [INFERENCE: adapter] The binary's stats code labels socket chunks as
/// `"tcp_chunk"`; this adapter exposes that recovered label to callsites that
/// record per-write metrics outside the frame writer.
pub fn tcp_chunk_label() -> &'static str {
    TCP_CHUNK_LABEL
}

/// Build the exact bytes sent on the wire without performing socket I/O.
pub fn encode_wire_frame_for_test(
    payload: &[u8],
    options: TcpWriteOptions,
) -> Result<Vec<u8>, TcpWriteError> {
    build_frame(payload, options)?.into_wire_bytes()
}
