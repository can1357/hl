//! Recovered from `/home/ubuntu/hl/code_Mainnet/node/src/stream_msg.rs`.
//!
//! Confidence: high for the outer bincode framing, bincode varint enum tags,
//! and the observed serializer/deserializer control-flow at the EAs below;
//! medium for semantic names of opaque consensus payloads that are decoded by
//! foreign callees outside this source file. Those fields are kept as explicit
//! raw/newtype payloads instead of pretending to know their full layouts.
//!
//! Seeds: `0x466E3F0`.
//! Local expansion while IDA was queue-blocked:
//! - `0x466E3F0`: bincode decode + `Result::unwrap` for a 24-byte payload,
//!   then allocates a `0x28` byte `ArcInner<T>`.
//! - `0x466E750`: `GreetingHash` bincode `Deserialize` entry.
//! - `0x466EB70`: serializer for a 32-byte hash payload used by
//!   `GreetingHash`.
//! - `0x4674820`: `AbciStreamGreeting` bincode `Deserialize` entry.
//! - `0x4674B50`: variadic/compatibility greeting reducer.
//!
//! IDA tags applied: none; the IDA worker rejected narrow rename/comment calls
//! with `Server is busy (request queue full)`. Pending operations are listed in
//! the worker result.

#![allow(dead_code)]

use std::fmt;
use std::sync::Arc;


pub const EA_DECODE_GREETING_HASH_ARC: u64 = 0x466_E3F0;
pub const EA_DECODE_GREETING_HASH: u64 = 0x466_E750;
pub const EA_ENCODE_HASH32: u64 = 0x466_EB70;
pub const EA_DECODE_ABCI_STREAM_GREETING: u64 = 0x467_4820;
pub const EA_REDUCE_VARIADIC_ABCI_STREAM_GREETING: u64 = 0x467_4B50;

/// Node TCP stream envelope recovered from the local protocol notes and frame
/// readers used by the node streams.
///
/// The bincode payload is carried inside `[u32 be length][u8 compression_flag]`.
/// A flag of `0` means the bytes are passed directly to the bincode decoder;
/// flag `1` is used by the large LZ4 ABCI-state path, not by the small greeting
/// hashes reconstructed in this file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamFrame<'a> {
    pub compression: StreamCompression,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamCompression {
    Raw,
    Lz4,
    Other(u8),
}

impl From<u8> for StreamCompression {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Raw,
            1 => Self::Lz4,
            other => Self::Other(other),
        }
    }
}

impl StreamCompression {
    #[inline]
    pub const fn as_wire_byte(self) -> u8 {
        match self {
            Self::Raw => 0,
            Self::Lz4 => 1,
            Self::Other(value) => value,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamMsgError {
    ShortFrame,
    LengthMismatch { declared: usize, actual: usize },
    CompressedGreeting,
    UnexpectedEof { needed: usize, remaining: usize },
    NonCanonicalVarint,
    IntegerTooWide { marker: u8, target: &'static str },
    InvalidEnumTag { ty: &'static str, tag: u64 },
    ForeignDecode { ty: &'static str },
}

impl fmt::Display for StreamMsgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortFrame => f.write_str("stream frame shorter than 5-byte header"),
            Self::LengthMismatch { declared, actual } => {
                write!(f, "stream frame length mismatch: declared={declared} actual={actual}")
            }
            Self::CompressedGreeting => f.write_str("small stream greeting must be raw bincode"),
            Self::UnexpectedEof { needed, remaining } => {
                write!(f, "unexpected EOF: needed {needed} bytes, remaining {remaining}")
            }
            Self::NonCanonicalVarint => f.write_str("non-canonical bincode varint"),
            Self::IntegerTooWide { marker, target } => {
                write!(f, "bincode varint marker 0x{marker:02x} is too wide for {target}")
            }
            Self::InvalidEnumTag { ty, tag } => write!(f, "invalid {ty} enum tag {tag}"),
            Self::ForeignDecode { ty } => write!(f, "foreign decoder for {ty} is required"),
        }
    }
}

impl std::error::Error for StreamMsgError {}

pub fn decode_frame(bytes: &[u8]) -> Result<StreamFrame<'_>, StreamMsgError> {
    if bytes.len() < 5 {
        return Err(StreamMsgError::ShortFrame);
    }

    let declared = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let actual = bytes.len() - 5;
    if declared != actual {
        return Err(StreamMsgError::LengthMismatch { declared, actual });
    }

    Ok(StreamFrame {
        compression: StreamCompression::from(bytes[4]),
        payload: &bytes[5..],
    })
}

pub fn encode_frame(frame: StreamFrame<'_>, out: &mut Vec<u8>) {
    let len = frame.payload.len() as u32;
    out.extend_from_slice(&len.to_be_bytes());
    out.push(frame.compression.as_wire_byte());
    out.extend_from_slice(frame.payload);
}

/// Bincode-fork's compact integer format as observed in `0x466BC10`/`0x466BD10`:
/// direct bytes for `0..=250`, then markers `0xFB`/`0xFC`/`0xFD`/`0xFE` for
/// little-endian `u16`/`u32`/`u64`/`u128`.
#[derive(Clone, Copy, Debug)]
pub struct BincodeReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> BincodeReader<'a> {
    #[inline]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    #[inline]
    pub const fn remaining(&self) -> usize {
        self.bytes.len() - self.cursor
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.cursor == self.bytes.len()
    }

    pub fn read_exact<const N: usize>(&mut self) -> Result<[u8; N], StreamMsgError> {
        if self.remaining() < N {
            return Err(StreamMsgError::UnexpectedEof { needed: N, remaining: self.remaining() });
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.bytes[self.cursor..self.cursor + N]);
        self.cursor += N;
        Ok(out)
    }

    #[inline]
    pub fn read_u8(&mut self) -> Result<u8, StreamMsgError> {
        Ok(self.read_exact::<1>()?[0])
    }

    pub fn read_var_u64(&mut self) -> Result<u64, StreamMsgError> {
        let marker = self.read_u8()?;
        match marker {
            0..=250 => Ok(marker as u64),
            0xFB => Ok(u16::from_le_bytes(self.read_exact::<2>()?) as u64),
            0xFC => Ok(u32::from_le_bytes(self.read_exact::<4>()?) as u64),
            0xFD => Ok(u64::from_le_bytes(self.read_exact::<8>()?)),
            0xFE => Err(StreamMsgError::IntegerTooWide { marker, target: "u64" }),
            0xFF => Err(StreamMsgError::NonCanonicalVarint),
        }
    }

    #[inline]
    pub fn read_var_u32(&mut self) -> Result<u32, StreamMsgError> {
        let value = self.read_var_u64()?;
        if value > u32::MAX as u64 {
            return Err(StreamMsgError::IntegerTooWide { marker: 0xFD, target: "u32" });
        }
        Ok(value as u32)
    }
}

pub fn write_var_u64(value: u64, out: &mut Vec<u8>) {
    if value <= 250 {
        out.push(value as u8);
    } else if value <= u16::MAX as u64 {
        out.push(0xFB);
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= u32::MAX as u64 {
        out.push(0xFC);
        out.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        out.push(0xFD);
        out.extend_from_slice(&value.to_le_bytes());
    }
}

#[inline]
pub fn write_var_u32(value: u32, out: &mut Vec<u8>) {
    write_var_u64(value as u64, out);
}

/// Opaque consensus proof/hash tail decoded by foreign callees.
///
/// Placement evidence: `GreetingHash` tag `0` at `0x466E851..0x466EA8E`
/// reads exactly 32 raw bytes first, then calls `0x496EC70` and stores a
/// 24-byte result at output offsets `+0x28..+0x40`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GreetingHashWithProof {
    pub hash: [u8; 32],
    pub proof: ForeignProof24,
}

/// [INFERENCE: semantic name] 24 bytes copied from the `0x496EC70` decoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForeignProof24 {
    pub bytes: [u8; 24],
}

/// [INFERENCE: semantic name] payload returned by `0x49784E0` under
/// `GreetingHash` tag `1`. The callee has two output shapes: a compact 32-byte
/// hash arm and a full 80-byte arm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsensusGreetingHash {
    Compact([u8; 32]),
    Full([u8; 80]),
}

/// `GreetingHash` enum recovered from `0x466E750`.
///
/// Observed bincode tags:
/// - `0`: `hash: [u8; 32]` followed by a 24-byte foreign proof (`0x496EC70`).
/// - `1`: nested hash enum decoded by `0x49784E0`, with 32- or 80-byte arms.
/// - `2`: one `u64`-sized value decoded by `0x485BAA0` and stored at `+0x8`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GreetingHash {
    /// [INFERENCE] Client-block quorum/greeting hash arm.
    WithProof(GreetingHashWithProof),
    /// [INFERENCE] Consensus/ABCI greeting hash arm.
    Consensus(ConsensusGreetingHash),
    /// [INFERENCE] Height/round/id-only hash arm; stored as one qword.
    Scalar(u64),
}

impl GreetingHash {
    pub const TYPE_NAME: &'static str = "GreetingHash";

    pub fn decode_with<C: StreamMsgForeignCodec>(reader: &mut BincodeReader<'_>, foreign: &C) -> Result<Self, StreamMsgError> {
        match reader.read_var_u32()? {
            0 => {
                let hash = reader.read_exact::<32>()?;
                let proof = foreign.decode_foreign_proof24(reader)?;
                Ok(Self::WithProof(GreetingHashWithProof { hash, proof }))
            }
            1 => Ok(Self::Consensus(foreign.decode_consensus_greeting_hash(reader)?)),
            2 => Ok(Self::Scalar(foreign.decode_scalar_hash(reader)?)),
            tag => Err(StreamMsgError::InvalidEnumTag { ty: Self::TYPE_NAME, tag: tag as u64 }),
        }
    }

    pub fn encode_with<C: StreamMsgForeignCodec>(&self, out: &mut Vec<u8>, foreign: &C) -> Result<(), StreamMsgError> {
        match self {
            Self::WithProof(value) => {
                write_var_u32(0, out);
                out.extend_from_slice(&value.hash);
                foreign.encode_foreign_proof24(&value.proof, out)
            }
            Self::Consensus(value) => {
                write_var_u32(1, out);
                foreign.encode_consensus_greeting_hash(value, out)
            }
            Self::Scalar(value) => {
                write_var_u32(2, out);
                foreign.encode_scalar_hash(*value, out);
                Ok(())
            }
        }
    }
}

/// `0x466E3F0` decodes a `GreetingHash`-adjacent 24-byte payload and wraps it in
/// an `Arc` (`0x28` byte allocation = `ArcInner` header plus 24-byte value).
pub fn decode_arc_greeting_hash<C: StreamMsgForeignCodec>(payload: &[u8], foreign: &C) -> Result<Arc<GreetingHash>, StreamMsgError> {
    let mut reader = BincodeReader::new(payload);
    let value = GreetingHash::decode_with(&mut reader, foreign)?;
    Ok(Arc::new(value))
}

/// One entry in the vector arm of `AbciStreamGreeting` tag `0`.
///
/// The reducer at `0x4674B50` walks entries in `0x40`-byte strides, so the
/// source type used by that path is 64 bytes wide. Its full owner appears to be
/// consensus/client-block code; this mirror preserves the boundary layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamGreetingSource64 {
    pub bytes: [u8; 64],
}

/// `AbciStreamGreeting` enum recovered from `0x4674820`.
///
/// Observed bincode tags:
/// - `0`: vector decoded with element decoder `0x466BBB0`, then `u64`, then
///   nested `GreetingHash` (`0x466E750`).
/// - `1`: three consecutive `u64` values.
/// - `2`, `3`, `4`, `5`: unit variants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AbciStreamGreeting {
    /// [INFERENCE] Full greeting carrying source entries, a height/round, and
    /// the computed greeting hash.
    Full {
        sources: Vec<StreamGreetingSource64>,
        height_or_round: u64,
        hash: GreetingHash,
    },
    /// [INFERENCE] Legacy compact format; retained by the variadic reducer.
    LegacyTriple(u64, u64, u64),
    UnitTag2,
    UnitTag3,
    UnitTag4,
    UnitTag5,
}

impl AbciStreamGreeting {
    pub const TYPE_NAME: &'static str = "AbciStreamGreeting";

    pub fn decode_with<C: StreamMsgForeignCodec>(payload: &[u8], foreign: &C) -> Result<Self, StreamMsgError> {
        let mut reader = BincodeReader::new(payload);
        Self::decode_from_reader(&mut reader, foreign)
    }

    pub fn decode_frame_with<C: StreamMsgForeignCodec>(bytes: &[u8], foreign: &C) -> Result<Self, StreamMsgError> {
        let frame = decode_frame(bytes)?;
        if frame.compression != StreamCompression::Raw {
            return Err(StreamMsgError::CompressedGreeting);
        }
        Self::decode_with(frame.payload, foreign)
    }

    pub fn decode_from_reader<C: StreamMsgForeignCodec>(reader: &mut BincodeReader<'_>, foreign: &C) -> Result<Self, StreamMsgError> {
        match reader.read_var_u32()? {
            0 => {
                let sources = foreign.decode_stream_greeting_sources(reader)?;
                let height_or_round = reader.read_var_u64()?;
                let hash = GreetingHash::decode_with(reader, foreign)?;
                Ok(Self::Full { sources, height_or_round, hash })
            }
            1 => {
                let a = reader.read_var_u64()?;
                let b = reader.read_var_u64()?;
                let c = reader.read_var_u64()?;
                Ok(Self::LegacyTriple(a, b, c))
            }
            2 => Ok(Self::UnitTag2),
            3 => Ok(Self::UnitTag3),
            4 => Ok(Self::UnitTag4),
            5 => Ok(Self::UnitTag5),
            tag => Err(StreamMsgError::InvalidEnumTag { ty: Self::TYPE_NAME, tag: tag as u64 }),
        }
    }

    pub fn encode_with<C: StreamMsgForeignCodec>(&self, out: &mut Vec<u8>, foreign: &C) -> Result<(), StreamMsgError> {
        match self {
            Self::Full { sources, height_or_round, hash } => {
                write_var_u32(0, out);
                foreign.encode_stream_greeting_sources(sources, out)?;
                write_var_u64(*height_or_round, out);
                hash.encode_with(out, foreign)
            }
            Self::LegacyTriple(a, b, c) => {
                write_var_u32(1, out);
                write_var_u64(*a, out);
                write_var_u64(*b, out);
                write_var_u64(*c, out);
                Ok(())
            }
            Self::UnitTag2 => {
                write_var_u32(2, out);
                Ok(())
            }
            Self::UnitTag3 => {
                write_var_u32(3, out);
                Ok(())
            }
            Self::UnitTag4 => {
                write_var_u32(4, out);
                Ok(())
            }
            Self::UnitTag5 => {
                write_var_u32(5, out);
                Ok(())
            }
        }
    }

    pub fn encode_frame_with<C: StreamMsgForeignCodec>(&self, out: &mut Vec<u8>, foreign: &C) -> Result<(), StreamMsgError> {
        let mut payload = Vec::new();
        self.encode_with(&mut payload, foreign)?;
        encode_frame(StreamFrame { compression: StreamCompression::Raw, payload: &payload }, out);
        Ok(())
    }
}

/// Compatibility reducer for stream greeting forms.
///
/// The machine iterates over 64-byte source entries and tries several foreign
/// projections before producing the full greeting. It errors with static labels
/// adjacent to `0x6F71DA`/`0x6F71E1` when required projections are absent. This
/// Rust helper expresses the recovered invariant without cloning opaque entries.
pub fn reduce_variadic_abci_stream_greeting<C: StreamMsgForeignCodec>(
    sources: &[StreamGreetingSource64],
    foreign: &C,
) -> Result<AbciStreamGreeting, StreamMsgError> {
    let mut selected_sources: Option<Vec<StreamGreetingSource64>> = None;
    let mut selected_hash: Option<GreetingHash> = None;
    let mut selected_height: Option<u64> = None;

    for source in sources {
        if selected_sources.is_none() {
            if let Some(projected) = foreign.project_sources_from_entry(source)? {
                selected_sources = Some(projected);
            }
        }
        if selected_hash.is_none() {
            if let Some(hash) = foreign.project_hash_from_entry(source)? {
                selected_hash = Some(hash);
            }
        }
        if selected_height.is_none() {
            if let Some(height) = foreign.project_height_from_entry(source)? {
                selected_height = Some(height);
            }
        }
    }

    match (selected_sources, selected_height, selected_hash) {
        (Some(sources), Some(height_or_round), Some(hash)) => Ok(AbciStreamGreeting::Full { sources, height_or_round, hash }),
        _ => Err(StreamMsgError::ForeignDecode { ty: "VariadicAbciStreamGreeting" }),
    }
}

/// Thin interface for callees owned by consensus/client-block code.
///
/// This keeps `bincode-fork` and foreign consensus layouts out of this file,
/// while preserving the dispatch and byte-level boundaries proven by the local
/// disassembly.
pub trait StreamMsgForeignCodec {
    fn decode_foreign_proof24(&self, reader: &mut BincodeReader<'_>) -> Result<ForeignProof24, StreamMsgError> {
        let bytes = reader.read_exact::<24>()?;
        Ok(ForeignProof24 { bytes })
    }

    fn encode_foreign_proof24(&self, proof: &ForeignProof24, out: &mut Vec<u8>) -> Result<(), StreamMsgError> {
        out.extend_from_slice(&proof.bytes);
        Ok(())
    }

    fn decode_consensus_greeting_hash(&self, reader: &mut BincodeReader<'_>) -> Result<ConsensusGreetingHash, StreamMsgError>;
    fn encode_consensus_greeting_hash(&self, hash: &ConsensusGreetingHash, out: &mut Vec<u8>) -> Result<(), StreamMsgError>;

    fn decode_scalar_hash(&self, reader: &mut BincodeReader<'_>) -> Result<u64, StreamMsgError> {
        reader.read_var_u64()
    }

    fn encode_scalar_hash(&self, value: u64, out: &mut Vec<u8>) {
        write_var_u64(value, out);
    }

    fn decode_stream_greeting_sources(&self, reader: &mut BincodeReader<'_>) -> Result<Vec<StreamGreetingSource64>, StreamMsgError>;
    fn encode_stream_greeting_sources(&self, sources: &[StreamGreetingSource64], out: &mut Vec<u8>) -> Result<(), StreamMsgError>;

    fn project_sources_from_entry(&self, _entry: &StreamGreetingSource64) -> Result<Option<Vec<StreamGreetingSource64>>, StreamMsgError> {
        Ok(None)
    }

    fn project_hash_from_entry(&self, _entry: &StreamGreetingSource64) -> Result<Option<GreetingHash>, StreamMsgError> {
        Ok(None)
    }

    fn project_height_from_entry(&self, _entry: &StreamGreetingSource64) -> Result<Option<u64>, StreamMsgError> {
        Ok(None)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RawStreamMsgCodec;

impl StreamMsgForeignCodec for RawStreamMsgCodec {
    fn decode_consensus_greeting_hash(&self, reader: &mut BincodeReader<'_>) -> Result<ConsensusGreetingHash, StreamMsgError> {
        let tag = reader.read_var_u32()?;
        match tag {
            0 => Ok(ConsensusGreetingHash::Compact(reader.read_exact::<32>()?)),
            1 => Ok(ConsensusGreetingHash::Full(reader.read_exact::<80>()?)),
            other => Err(StreamMsgError::InvalidEnumTag { ty: "ConsensusGreetingHash", tag: other as u64 }),
        }
    }

    fn encode_consensus_greeting_hash(&self, hash: &ConsensusGreetingHash, out: &mut Vec<u8>) -> Result<(), StreamMsgError> {
        match hash {
            ConsensusGreetingHash::Compact(bytes) => {
                write_var_u32(0, out);
                out.extend_from_slice(bytes);
            }
            ConsensusGreetingHash::Full(bytes) => {
                write_var_u32(1, out);
                out.extend_from_slice(bytes);
            }
        }
        Ok(())
    }

    fn decode_stream_greeting_sources(&self, reader: &mut BincodeReader<'_>) -> Result<Vec<StreamGreetingSource64>, StreamMsgError> {
        let len = reader.read_var_u64()? as usize;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(StreamGreetingSource64 { bytes: reader.read_exact::<64>()? });
        }
        Ok(out)
    }

    fn encode_stream_greeting_sources(&self, sources: &[StreamGreetingSource64], out: &mut Vec<u8>) -> Result<(), StreamMsgError> {
        write_var_u64(sources.len() as u64, out);
        for source in sources {
            out.extend_from_slice(&source.bytes);
        }
        Ok(())
    }
}
