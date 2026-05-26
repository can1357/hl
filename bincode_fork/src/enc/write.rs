//! Thin interface for `/home/ubuntu/hl/bincode-fork/src/enc/write.rs`.
//!
//! This crate is not a primary reconstruction target. Keep this file as a small
//! compatibility surface for packet/TCP reconstructions only; do not fan out more
//! agents on bincode internals unless packet behavior requires one exact helper.
//!
//! Binary-grounded facts retained:
//! - slice exhaustion constructs `EncodeError::UnexpectedEnd`;
//! - count-only writes advance a single `usize` counter;
//! - size/count helpers are used by packet serializer monomorphs.
use crate::error::EncodeError;

/// Destination used by the encoder to receive already-serialized bytes.
///
/// Implementations must either write the whole input slice or return an
/// `EncodeError`. The encoder assumes partial success is not possible.
pub trait Writer {
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError>;
}

impl<T: Writer + ?Sized> Writer for &mut T {
    #[inline]
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        (**self).write(bytes)
    }
}

/// Writer over caller-owned storage.
///
/// The active `slice` field is the remaining unwritten tail. `original_length`
/// is kept so callers can recover the number of bytes emitted after encoding.
pub struct SliceWriter<'storage> {
    slice: &'storage mut [u8],
    original_length: usize,
}

impl<'storage> SliceWriter<'storage> {
    #[inline]
    pub fn new(bytes: &'storage mut [u8]) -> SliceWriter<'storage> {
        let original_length = bytes.len();
        SliceWriter {
            slice: bytes,
            original_length,
        }
    }

    #[inline]
    pub fn bytes_written(&self) -> usize {
        self.original_length - self.slice.len()
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.slice.len()
    }

    #[inline]
    pub fn remaining_slice(&self) -> &[u8] {
        &*self.slice
    }
}

impl Writer for SliceWriter<'_> {
    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        if bytes.len() > self.slice.len() {
            return Err(EncodeError::UnexpectedEnd);
        }

        let (dst, rest) = core::mem::take(&mut self.slice).split_at_mut(bytes.len());
        dst.copy_from_slice(bytes);
        self.slice = rest;
        Ok(())
    }
}

/// Count-only writer used by `encode_to_vec` to pre-size protocol packet buffers.
#[derive(Default, Debug, Clone, Copy, Eq, PartialEq)]
pub struct SizeWriter {
    pub bytes_written: usize,
}

impl SizeWriter {
    #[inline]
    pub const fn new() -> Self {
        Self { bytes_written: 0 }
    }

    #[inline]
    pub const fn bytes_written(&self) -> usize {
        self.bytes_written
    }

    #[inline]
    pub fn reserve_written(&mut self, additional: usize) {
        self.bytes_written = checked_add_written(self.bytes_written, additional);
    }
}

impl Writer for SizeWriter {
    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        self.reserve_written(bytes.len());
        Ok(())
    }
}

#[inline]
fn checked_add_written(current: usize, additional: usize) -> usize {
    match current.checked_add(additional) {
        Some(next) => next,
        None => panic!("attempt to add with overflow"),
    }
}

const SINGLE_BYTE_MAX: u64 = 250;

/// Count the bytes that `varint_encode_u32` will emit into any real writer.
///
/// Recovered from SizeWriter monomorphs at `0x27AB280` and `0x4AA9C90`: the
/// value itself is not read by the writer after this length decision, and the
/// endian flag is immaterial for byte count.
#[inline]
pub(crate) const fn encoded_u32_varint_len(value: u32) -> usize {
    if value as u64 <= SINGLE_BYTE_MAX {
        1
    } else if value <= u16::MAX as u32 {
        3
    } else {
        5
    }
}

/// Count the bytes that `varint_encode_u64`/`varint_encode_usize` will emit.
///
/// Recovered from SizeWriter monomorphs at `0x27AB5B0` and `0x4AAA230`:
/// one raw byte for values <= 250, otherwise a one-byte marker plus a 16-, 32-,
/// or 64-bit payload.
#[inline]
pub(crate) const fn encoded_u64_varint_len(value: u64) -> usize {
    if value <= SINGLE_BYTE_MAX {
        1
    } else if value <= u16::MAX as u64 {
        3
    } else if value <= u32::MAX as u64 {
        5
    } else {
        9
    }
}

#[inline]
pub(crate) const fn encoded_usize_varint_len(value: usize) -> usize {
    encoded_u64_varint_len(value as u64)
}

/// SizeWriter-specialized helper for length-prefixed byte/string payloads.
///
/// Packet serializers inline this pattern: count the bincode varint length,
/// then count the raw payload bytes. Any overflow follows the same panic path as
/// `SizeWriter::write` in the recovered binary rather than becoming an
/// `EncodeError`.
#[inline]
pub(crate) fn count_len_prefixed_bytes(writer: &mut SizeWriter, len: usize) -> Result<(), EncodeError> {
    writer.reserve_written(encoded_usize_varint_len(len));
    writer.reserve_written(len);
    Ok(())
}

#[inline]
pub(crate) fn count_fixed_bytes(writer: &mut SizeWriter, len: usize) -> Result<(), EncodeError> {
    writer.reserve_written(len);
    Ok(())
}
