//! Reconstructed from `/home/ubuntu/hl/code_Mainnet/net_utils/src/tcp/read.rs`.
//!
//! Confidence: high for frame layout, bounds checks, chunking, timeout constants,
//! and the compression-flag predicate. Seeds expanded: `0x20485E0`, `0x2049950`,
//! `0x204AE20`, plus matching monomorphs `0x43A0260`, `0x4386A40`, and
//! `0x4B72900`. Static disassembly was used because the IDA foreground worker
//! rejected new work with `Server is busy (request queue full)`.
//!
//! IDA tag plan, not applied due worker saturation:
//! - `0x20485E0` -> `net_utils_tcp_read__read_frame_header`
//! - `0x2049950` -> `net_utils_tcp_read__read_bytes`
//! - `0x204AE20` -> `net_utils_tcp_read__read_deserialized_value__mono_204AE20`
//! - `0x43A0260` -> `net_utils_tcp_read__read_bytes__mono_43A0260`
//! - `0x4386A40` -> `net_utils_tcp_read__read_deserialized_value__mono_4386A40`
//! - `0x4B72900` -> `net_utils_tcp_read__read_bytes__mono_4B72900`
//!
//! Recovered wire format and constants:
//! - header is exactly `[u32_be payload_len][u8 compression_flag]`.
//! - only flag `1` is treated as compressed; `0` and all other values are raw.
//! - header reads use the string `tcp_bytes` and a `40.0` second timeout.
//! - payload reads use the string `tcp_read_exact`, at most `4_000_000` bytes per
//!   read, and a `20.0` second timeout.
//! - early EOF constructs error code `37` with string `early eof`.
//! - over-limit formatting strings observed:
//!   `tcp read bytes over limit @@ [desc: ...] @ [len: ...] @ [max_len: ...]`
//!   and `tcp::read_bytes over limit @@ [len: ...] @ [max_len: ...]`.

use std::fmt;
use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

pub const FRAME_HEADER_LEN: usize = 5;
pub const COMPRESSION_FLAG_RAW: u8 = 0;
pub const COMPRESSION_FLAG_LZ4: u8 = 1;
pub const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(40);
pub const READ_CHUNK_TIMEOUT: Duration = Duration::from_secs(20);
pub const MAX_READ_CHUNK_BYTES: usize = 4_000_000;
pub const EARLY_EOF_CODE: u32 = 37;

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
}

#[derive(Debug)]
pub enum TcpReadError {
    EarlyEof { desc: &'static str, code: u32 },
    TimedOut { desc: &'static str, timeout: Duration },
    Io { desc: &'static str, source: io::Error },
    OverLimit { desc: &'static str, len: usize, max_len: usize },
    Lz4InputTooShort { len: usize },
    Lz4DecodedOverLimit { decoded_len: usize, max_len: usize },
    Lz4Decode { source: lz4_flex::block::DecompressError },
    BincodeDecode { source: Box<dyn std::error::Error + Send + Sync> },
}

impl fmt::Display for TcpReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EarlyEof { desc, code } => write!(f, "{desc}: early eof (code {code})"),
            Self::TimedOut { desc, timeout } => write!(f, "{desc}: timed out after {timeout:?}"),
            Self::Io { desc, source } => write!(f, "{desc}: {source}"),
            Self::OverLimit { desc, len, max_len } => {
                write!(f, "tcp read bytes over limit @@ [desc: {desc}] @ [len: {len}] @ [max_len: {max_len}]")
            }
            Self::Lz4InputTooShort { len } => {
                write!(f, "lz4 size-prepended payload too short: {len} bytes")
            }
            Self::Lz4DecodedOverLimit { decoded_len, max_len } => {
                write!(f, "lz4 decoded bytes over limit @@ [len: {decoded_len}] @ [max_len: {max_len}]")
            }
            Self::Lz4Decode { source } => write!(f, "tcp::read_bytes decompression failure: {source}"),
            Self::BincodeDecode { source } => write!(f, "tcp::read_value decode failure: {source}"),
        }
    }
}

impl std::error::Error for TcpReadError {}

/// Reads and parses the five-byte TCP frame header.
///
/// The current binary's `0x20485E0` helper reads exactly five bytes into a stack
/// buffer, byte-swaps the first four bytes as a big-endian `u32`, then reads the
/// flag from byte four. A zero-length payload is valid and returns immediately
/// from `read_bytes` after the max-size check.
pub async fn read_frame_header<R>(stream: &mut R, use_timeout: bool) -> Result<FrameHeader, TcpReadError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; FRAME_HEADER_LEN];
    read_exact_or_eof(stream, "tcp_bytes", &mut header, READ_HEADER_TIMEOUT, use_timeout).await?;

    let payload_len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let compression_flag = header[4];

    Ok(FrameHeader {
        payload_len,
        compression_flag,
    })
}

/// Reads one complete Hyperliquid TCP frame and returns the payload bytes.
///
/// The binary checks `payload_len <= max_len` before allocation. It then
/// allocates an exact-sized vector, reads the payload in chunks capped at
/// `4_000_000` bytes, and decompresses only when the header flag is exactly `1`.
/// Unknown non-zero flags are therefore accepted as raw frames.
pub async fn read_bytes<R>(
    stream: &mut R,
    desc: &'static str,
    max_len: usize,
    use_timeout: bool,
) -> Result<Vec<u8>, TcpReadError>
where
    R: AsyncRead + Unpin,
{
    let header = read_frame_header(stream, use_timeout).await?;

    if header.payload_len > max_len {
        return Err(TcpReadError::OverLimit {
            desc,
            len: header.payload_len,
            max_len,
        });
    }

    let mut bytes = vec![0_u8; header.payload_len];
    read_payload_exact(stream, desc, &mut bytes, use_timeout).await?;

    if header.is_lz4() {
        decompress_lz4_size_prepended_with_limit(&bytes, max_len)
    } else {
        Ok(bytes)
    }
}

/// Reads a framed bincode value.
///
/// [INFERENCE] The concrete decode monomorphs at `0x204AE20` and `0x4386A40`
/// call `read_bytes` and then a bincode-fork decode-from-slice helper, finally
/// freeing the frame buffer. This wrapper models that ownership path while
/// leaving the exact bincode-fork trait bounds generic.
pub trait BincodeFrameDecoder<T> {
    type Error: std::error::Error + Send + Sync + 'static;

    fn decode_from_slice(&self, bytes: &[u8]) -> Result<(T, usize), Self::Error>;
}

pub async fn read_bincode<T, R, D>(
    stream: &mut R,
    desc: &'static str,
    max_len: usize,
    decoder: &D,
    use_timeout: bool,
) -> Result<T, TcpReadError>
where
    R: AsyncRead + Unpin,
    D: BincodeFrameDecoder<T> + ?Sized,
{
    let bytes = read_bytes(stream, desc, max_len, use_timeout).await?;
    let (value, _consumed) = decoder
        .decode_from_slice(&bytes)
        .map_err(|source| TcpReadError::BincodeDecode { source: Box::new(source) })?;
    Ok(value)
}

async fn read_payload_exact<R>(
    stream: &mut R,
    desc: &'static str,
    mut dst: &mut [u8],
    use_timeout: bool,
) -> Result<(), TcpReadError>
where
    R: AsyncRead + Unpin,
{
    let total_len = dst.len();
    let mut offset = 0_usize;

    while !dst.is_empty() {
        let chunk_len = dst.len().min(MAX_READ_CHUNK_BYTES);
        let (chunk, rest) = dst.split_at_mut(chunk_len);
        read_exact_or_eof(stream, "tcp_read_exact", chunk, READ_CHUNK_TIMEOUT, use_timeout).await?;
        offset += chunk_len;
        dst = rest;

        if offset >= MAX_READ_CHUNK_BYTES && offset < total_len {
            log_large_read_progress(desc, offset, total_len);
        }
    }

    Ok(())
}

async fn read_exact_or_eof<R>(
    stream: &mut R,
    desc: &'static str,
    mut dst: &mut [u8],
    read_timeout: Duration,
    use_timeout: bool,
) -> Result<(), TcpReadError>
where
    R: AsyncRead + Unpin,
{
    while !dst.is_empty() {
        let read_result = if use_timeout {
            match timeout(read_timeout, stream.read(dst)).await {
                Ok(result) => result,
                Err(_elapsed) => return Err(TcpReadError::TimedOut { desc, timeout: read_timeout }),
            }
        } else {
            stream.read(dst).await
        };

        let n = read_result.map_err(|source| TcpReadError::Io { desc, source })?;
        if n == 0 {
            return Err(TcpReadError::EarlyEof {
                desc,
                code: EARLY_EOF_CODE,
            });
        }

        let (_, rest) = dst.split_at_mut(n);
        dst = rest;
    }

    Ok(())
}

/// Decompresses the LZ4 payload variant used by the frame reader.
///
/// The call at `0x204AAD2` passes `max_len` to the decompressor wrapper before
/// freeing the compressed frame. The wrapped format matches `lz4_flex`'s
/// size-prepended block format: a little-endian `u32` decoded length followed by
/// the compressed block. The decoded size is checked before allocation.
fn decompress_lz4_size_prepended_with_limit(
    compressed: &[u8],
    max_len: usize,
) -> Result<Vec<u8>, TcpReadError> {
    if compressed.len() < 4 {
        return Err(TcpReadError::Lz4InputTooShort { len: compressed.len() });
    }

    let decoded_len = u32::from_le_bytes([
        compressed[0],
        compressed[1],
        compressed[2],
        compressed[3],
    ]) as usize;

    if decoded_len > max_len {
        return Err(TcpReadError::Lz4DecodedOverLimit { decoded_len, max_len });
    }

    lz4_flex::block::decompress(&compressed[4..], decoded_len)
        .map_err(|source| TcpReadError::Lz4Decode { source })
}

#[inline]
fn log_large_read_progress(desc: &'static str, offset: usize, total_len: usize) {
    tracing::warn!(
        target: "net_utils::tcp::read",
        "WARN >>> @@ reading bytes for {desc}: {offset}/{total_len}"
    );
}
