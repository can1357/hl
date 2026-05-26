//! Reconstructed from `/home/ubuntu/hl/code_Mainnet/node/src/gossip_rpc.rs`.
//!
//! Seeds: `0x4386F70`, `0x438ED70`, `0x4398D60`, `0x473CE40`, `0x47B0B50`,
//! `0x47B4950`, `0x4B28410`; expanded codec helpers `0x438B5C0` and
//! `0x438B6E0`.
//!
//! Recovered facts:
//! - `0x438B5C0` decodes `GossipRpcRequest` tags `0..=2`: tag `0` is
//!   `ClientBlocks { start_round, end_round }`, while tags `1` (`Peers`) and
//!   `2` (`GossipStatus`) are unit variants.
//! - `0x438B6E0` decodes `GossipRpcResponse` tags `0..=3`: `ClientBlocks`,
//!   `Peers`, `GossipStatus(Option<GossipStatus>)`, `Error`.
//! - invalid tags construct bincode invalid-variant errors with literal type names
//!   `GossipRpcRequest` / `GossipRpcResponse`.
//! - packet framing is net_utils TCP: `[u32_be payload_len][u8 compression_flag]`.
//! IDA rename/comment/type writes were attempted but the shared worker queue was
//! full, so the intended names are recorded here rather than committed.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;

use crate::net_utils::tcp::read::{read_bytes, TcpReadError};
use crate::net_utils::tcp::write::{write_frame, TcpWriteError, TcpWriteOptions};

pub const GOSSIP_FRAME_LABEL: &str = "gossip_rpc";
pub const DEFAULT_MAX_GOSSIP_PACKET_BYTES: usize = 4_000_000;
pub const GOSSIP_HANDLER_QUEUE_CAPACITY: usize = 32;

const HANDLER_READY: u64 = 0x01;
const HANDLER_CLAIMED: u64 = 0x02;
const HANDLER_BUSY: u64 = 0x04;
const HANDLER_CALLABLE_MASK: u64 = HANDLER_READY | HANDLER_BUSY;

pub type Result<T, E = GossipRpcError> = std::result::Result<T, E>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GossipStatus {
    pub initial_height: u64,
    pub latest_height: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockHash(pub [u8; 32]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientBlockWire {
    /// [INFERENCE] The response helper at `0x438B6E0` delegates this payload to a
    /// foreign block decoder (`0x4589B30`). Keep bytes here rather than inventing
    /// consensus/l1 internals in the gossip enum file.
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientBlockEntry {
    pub block_hash: BlockHash,
    pub block: ClientBlockWire,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerInfo {
    /// [INFERENCE] Payload helper `0x496F730` owns exact peer layout.
    pub validator: Option<u32>,
    pub ip: String,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GossipRpcRequest {
    /// Discriminant 0. Requests an inclusive client-block round window.
    ClientBlocks { start_round: u64, end_round: u64 },
    /// Discriminant 1. Unit variant.
    Peers,
    /// Discriminant 2. Unit variant.
    GossipStatus,
}

impl GossipRpcRequest {
    pub const fn discriminant(&self) -> u32 {
        match self {
            Self::ClientBlocks { .. } => 0,
            Self::Peers => 1,
            Self::GossipStatus => 2,
        }
    }

    pub fn decode_bincode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = BincodeCursor::new(bytes);
        let tag = cursor.read_varint_u32()?;
        let request = match tag {
            0 => Self::ClientBlocks {
                start_round: cursor.read_varint_u64()?,
                end_round: cursor.read_varint_u64()?,
            },
            1 => Self::Peers,
            2 => Self::GossipStatus,
            other => return Err(GossipRpcError::InvalidVariant {
                type_name: "GossipRpcRequest",
                tag: other as u64,
                allowed: 0..=2,
            }),
        };
        cursor.finish()?;
        Ok(request)
    }

    pub fn encode_bincode(&self, out: &mut Vec<u8>) {
        match self {
            Self::ClientBlocks { start_round, end_round } => {
                encode_varint_u64(out, 0);
                encode_varint_u64(out, *start_round);
                encode_varint_u64(out, *end_round);
            }
            Self::Peers => encode_varint_u64(out, 1),
            Self::GossipStatus => encode_varint_u64(out, 2),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GossipRpcResponse {
    ClientBlocks(Vec<ClientBlockEntry>),
    Peers(Vec<PeerInfo>),
    GossipStatus(Option<GossipStatus>),
    Error(String),
}

impl GossipRpcResponse {
    pub const fn discriminant(&self) -> u32 {
        match self {
            Self::ClientBlocks(_) => 0,
            Self::Peers(_) => 1,
            Self::GossipStatus(_) => 2,
            Self::Error(_) => 3,
        }
    }

    pub fn decode_bincode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = BincodeCursor::new(bytes);
        let tag = cursor.read_varint_u32()?;
        let response = match tag {
            0 => Self::ClientBlocks(decode_client_blocks_payload(&mut cursor)?),
            1 => Self::Peers(decode_peers_payload(&mut cursor)?),
            2 => Self::GossipStatus(decode_gossip_status_payload(&mut cursor)?),
            3 => Self::Error(cursor.read_string()?),
            other => return Err(GossipRpcError::InvalidVariant {
                type_name: "GossipRpcResponse",
                tag: other as u64,
                allowed: 0..=3,
            }),
        };
        cursor.finish()?;
        Ok(response)
    }

    pub fn encode_bincode(&self, out: &mut Vec<u8>) {
        match self {
            Self::ClientBlocks(blocks) => {
                encode_varint_u64(out, 0);
                encode_varint_u64(out, blocks.len() as u64);
                for entry in blocks {
                    out.extend_from_slice(&entry.block_hash.0);
                    encode_varint_u64(out, entry.block.bytes.len() as u64);
                    out.extend_from_slice(&entry.block.bytes);
                }
            }
            Self::Peers(peers) => {
                encode_varint_u64(out, 1);
                encode_varint_u64(out, peers.len() as u64);
                for peer in peers {
                    match peer.validator {
                        Some(validator) => {
                            out.push(1);
                            encode_varint_u64(out, validator as u64);
                        }
                        None => out.push(0),
                    }
                    encode_string(out, &peer.ip);
                    encode_varint_u64(out, peer.port as u64);
                }
            }
            Self::GossipStatus(status) => {
                encode_varint_u64(out, 2);
                encode_optional_gossip_status(out, *status);
            }
            Self::Error(message) => {
                encode_varint_u64(out, 3);
                encode_string(out, message);
            }
        }
    }
}

impl fmt::Display for GossipRpcResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientBlocks(blocks) => f.debug_tuple("ClientBlocks").field(blocks).finish(),
            Self::Peers(peers) => f.debug_tuple("Peers").field(peers).finish(),
            Self::GossipStatus(status) => f.debug_tuple("GossipStatus").field(status).finish(),
            Self::Error(error) => f.debug_tuple("Error").field(error).finish(),
        }
    }
}

#[derive(Debug)]
pub enum GossipRpcError {
    DecodeEof { needed: usize, remaining: usize },
    TrailingBytes { remaining: usize },
    VarintReservedByte(u8),
    VarintOverflow { target: &'static str, value: u128 },
    InvalidUtf8(std::str::Utf8Error),
    InvalidVariant { type_name: &'static str, tag: u64, allowed: std::ops::RangeInclusive<u64> },
    TcpRead(TcpReadError),
    TcpWrite(TcpWriteError),
    ResponseDropped,
}

impl fmt::Display for GossipRpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecodeEof { needed, remaining } => write!(f, "bincode eof: needed {needed}, remaining {remaining}"),
            Self::TrailingBytes { remaining } => write!(f, "bincode left {remaining} trailing bytes"),
            Self::VarintReservedByte(byte) => write!(f, "reserved bincode varint byte 0x{byte:02x}"),
            Self::VarintOverflow { target, value } => write!(f, "bincode varint {value} does not fit in {target}"),
            Self::InvalidUtf8(error) => write!(f, "invalid utf8 string payload: {error}"),
            Self::InvalidVariant { type_name, tag, allowed } => write!(f, "invalid {type_name} variant {tag}; expected {allowed:?}"),
            Self::TcpRead(error) => write!(f, "tcp read failed: {error}"),
            Self::TcpWrite(error) => write!(f, "tcp write failed: {error}"),
            Self::ResponseDropped => write!(f, "Failed to receive response from rpc task"),
        }
    }
}

impl std::error::Error for GossipRpcError {}

impl From<TcpReadError> for GossipRpcError {
    fn from(error: TcpReadError) -> Self { Self::TcpRead(error) }
}

impl From<TcpWriteError> for GossipRpcError {
    fn from(error: TcpWriteError) -> Self { Self::TcpWrite(error) }
}

#[derive(Debug)]
pub struct BincodeCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BincodeCursor<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }

    pub fn finish(&self) -> Result<()> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if remaining == 0 { Ok(()) } else { Err(GossipRpcError::TrailingBytes { remaining }) }
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if remaining < len {
            return Err(GossipRpcError::DecodeEof { needed: len, remaining });
        }
        let start = self.offset;
        self.offset += len;
        Ok(&self.bytes[start..start + len])
    }

    fn read_u8(&mut self) -> Result<u8> { Ok(self.read_exact(1)?[0]) }

    pub fn read_varint_u32(&mut self) -> Result<u32> {
        let value = self.read_varint_u128()?;
        u32::try_from(value).map_err(|_| GossipRpcError::VarintOverflow { target: "u32", value })
    }

    pub fn read_varint_u64(&mut self) -> Result<u64> {
        let value = self.read_varint_u128()?;
        u64::try_from(value).map_err(|_| GossipRpcError::VarintOverflow { target: "u64", value })
    }

    pub fn read_string(&mut self) -> Result<String> {
        let len = self.read_varint_u64()? as usize;
        let bytes = self.read_exact(len)?;
        let value = std::str::from_utf8(bytes).map_err(GossipRpcError::InvalidUtf8)?;
        Ok(value.to_owned())
    }

    fn read_varint_u128(&mut self) -> Result<u128> {
        match self.read_u8()? {
            marker @ 0..=250 => Ok(marker as u128),
            251 => Ok(u16::from_le_bytes(self.read_exact(2)?.try_into().unwrap()) as u128),
            252 => Ok(u32::from_le_bytes(self.read_exact(4)?.try_into().unwrap()) as u128),
            253 => Ok(u64::from_le_bytes(self.read_exact(8)?.try_into().unwrap()) as u128),
            254 => Ok(u128::from_le_bytes(self.read_exact(16)?.try_into().unwrap())),
            reserved => Err(GossipRpcError::VarintReservedByte(reserved)),
        }
    }
}

fn encode_varint_u64(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=250 => out.push(value as u8),
        251..=0xffff => {
            out.push(251);
            out.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(252);
            out.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            out.push(253);
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
}

fn encode_string(out: &mut Vec<u8>, value: &str) {
    encode_varint_u64(out, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}
fn encode_optional_gossip_status(out: &mut Vec<u8>, status: Option<GossipStatus>) {
    match status {
        Some(status) => {
            out.push(1);
            encode_varint_u64(out, status.initial_height);
            encode_varint_u64(out, status.latest_height);
        }
        None => out.push(0),
    }
}

fn decode_gossip_status_payload(cursor: &mut BincodeCursor<'_>) -> Result<Option<GossipStatus>> {
    match cursor.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(GossipStatus { initial_height: cursor.read_varint_u64()?, latest_height: cursor.read_varint_u64()? })),
        other => Err(GossipRpcError::InvalidVariant {
            type_name: "core::option::Option<GossipStatus>",
            tag: other as u64,
            allowed: 0..=1,
        }),
    }
}

fn decode_client_blocks_payload(cursor: &mut BincodeCursor<'_>) -> Result<Vec<ClientBlockEntry>> {
    let len = cursor.read_varint_u64()? as usize;
    let mut blocks = Vec::with_capacity(len);
    for _ in 0..len {
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(cursor.read_exact(32)?);
        let block_len = cursor.read_varint_u64()? as usize;
        let block_bytes = cursor.read_exact(block_len)?.to_vec();
        blocks.push(ClientBlockEntry { block_hash: BlockHash(hash), block: ClientBlockWire { bytes: block_bytes } });
    }
    Ok(blocks)
}

fn decode_peers_payload(cursor: &mut BincodeCursor<'_>) -> Result<Vec<PeerInfo>> {
    let len = cursor.read_varint_u64()? as usize;
    let mut peers = Vec::with_capacity(len);
    for _ in 0..len {
        let validator = match cursor.read_u8()? {
            0 => None,
            _ => Some(cursor.read_varint_u32()?),
        };
        let ip = cursor.read_string()?;
        let port = cursor.read_varint_u64()? as u16;
        peers.push(PeerInfo { validator, ip, port });
    }
    Ok(peers)
}

pub type ResponseSender = oneshot::Sender<GossipRpcResponse>;
pub type ResponseReceiver = oneshot::Receiver<GossipRpcResponse>;

pub struct QueuedGossipRpcRequest {
    pub request: GossipRpcRequest,
    pub reply_to: ResponseSender,
}

pub trait GossipRpcHandler: Send + Sync + 'static {
    fn handle(&self, request: GossipRpcRequest, reply_to: ResponseSender);
}

pub struct GossipHandlerSlot {
    flags: AtomicU64,
    handler: Arc<dyn GossipRpcHandler>,
}

impl GossipHandlerSlot {
    pub fn new(handler: Arc<dyn GossipRpcHandler>) -> Self {
        Self { flags: AtomicU64::new(HANDLER_READY), handler }
    }

    /// Recovered claim loop: spin while bit 2 is set, CAS in bit 1, and invoke
    /// only when `(old_flags & 5) == 1`.
    fn try_call(&self, request: GossipRpcRequest, reply_to: ResponseSender) -> std::result::Result<DispatchOutcome, ResponseSender> {
        let mut old = self.flags.load(Ordering::Acquire);
        loop {
            while (old & HANDLER_BUSY) != 0 {
                std::hint::spin_loop();
                old = self.flags.load(Ordering::Acquire);
            }
            match self.flags.compare_exchange_weak(old, old | HANDLER_CLAIMED, Ordering::AcqRel, Ordering::Acquire) {
                Ok(claimed_from) => {
                    if (claimed_from & HANDLER_CALLABLE_MASK) == HANDLER_READY {
                        self.handler.handle(request, reply_to);
                        self.flags.fetch_and(!HANDLER_CLAIMED, Ordering::Release);
                        return Ok(DispatchOutcome::HandledImmediately);
                    }
                    self.flags.fetch_and(!HANDLER_CLAIMED, Ordering::Release);
                    return Err(reply_to);
                }
                Err(next) => old = next,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchOutcome {
    HandledImmediately,
    LeftQueued,
    NoHandler,
}

#[derive(Default)]
pub struct GossipDispatcher {
    handlers: Vec<Option<Arc<GossipHandlerSlot>>>,
    queue: Mutex<VecDeque<QueuedGossipRpcRequest>>,
}

impl GossipDispatcher {
    pub fn new() -> Self {
        Self { handlers: vec![None, None, None], queue: Mutex::new(VecDeque::with_capacity(GOSSIP_HANDLER_QUEUE_CAPACITY)) }
    }

    pub fn register_handler(&mut self, tag: u32, handler: Arc<dyn GossipRpcHandler>) {
        let index = tag as usize;
        if self.handlers.len() <= index {
            self.handlers.resize_with(index + 1, || None);
        }
        self.handlers[index] = Some(Arc::new(GossipHandlerSlot::new(handler)));
    }

    /// Source equivalent of the enqueue/vtable-dispatch path. The binary copies a
    /// fixed-size request object into a 32-slot queue, but if the selected handler
    /// can be claimed immediately it calls through the handler vtable at +16.
    pub fn enqueue_gossip_rpc_request(&self, request: GossipRpcRequest) -> Result<(ResponseReceiver, DispatchOutcome)> {
        let (reply_to, reply_rx) = oneshot::channel();
        let tag = request.discriminant() as usize;
        let handler = self.handlers.get(tag).and_then(|slot| slot.as_ref()).cloned();

        if let Some(slot) = handler {
            match slot.try_call(request.clone(), reply_to) {
                Ok(DispatchOutcome::HandledImmediately) => return Ok((reply_rx, DispatchOutcome::HandledImmediately)),
                Ok(other) => return Ok((reply_rx, other)),
                Err(reply_to) => {
                    self.push_queued(request, reply_to);
                    return Ok((reply_rx, DispatchOutcome::LeftQueued));
                }
            }
        }

        self.push_queued(request, reply_to);
        Ok((reply_rx, DispatchOutcome::NoHandler))
    }

    pub fn pop_queued(&self) -> Option<QueuedGossipRpcRequest> {
        self.queue.lock().pop_front()
    }

    fn push_queued(&self, request: GossipRpcRequest, reply_to: ResponseSender) {
        let mut queue = self.queue.lock();
        if queue.len() == GOSSIP_HANDLER_QUEUE_CAPACITY {
            queue.pop_front();
        }
        queue.push_back(QueuedGossipRpcRequest { request, reply_to });
    }
}

pub async fn read_gossip_rpc_request<R>(stream: &mut R, max_len: usize, use_timeout: bool) -> Result<GossipRpcRequest>
where
    R: AsyncRead + Unpin,
{
    let bytes = read_bytes(stream, GOSSIP_FRAME_LABEL, max_len, use_timeout).await?;
    GossipRpcRequest::decode_bincode(&bytes)
}

pub async fn write_gossip_rpc_response<W>(stream: &mut W, response: &GossipRpcResponse, options: TcpWriteOptions) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut payload = Vec::new();
    response.encode_bincode(&mut payload);
    write_frame(stream, &payload, options).await?;
    Ok(())
}

pub async fn handle_gossip_rpc_packet<S>(stream: &mut S, dispatcher: &GossipDispatcher, options: TcpWriteOptions) -> Result<DispatchOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_gossip_rpc_request(stream, DEFAULT_MAX_GOSSIP_PACKET_BYTES, true).await?;
    let (reply_rx, outcome) = dispatcher.enqueue_gossip_rpc_request(request)?;
    let response = reply_rx.await.map_err(|_| GossipRpcError::ResponseDropped)?;
    write_gossip_rpc_response(stream, &response, options).await?;
    Ok(outcome)
}
