//! Reconstructed bincode-fork write helpers required by TCP write wrappers.
//!
//! Source placement: `/home/ubuntu/hl/bincode-fork/src/ser/write.rs` is
//! [INFERENCE] from the `net_utils/src/tcp/write.rs` callees `0x28BFBD0`,
//! `0x28BF690`, and `0x28C0110`, which serialize concrete packet values into a
//! `Vec<u8>` immediately before TCP framing.
//!
//! Confidence: high for the varint encoding constants and little-endian scalar
//! writes; medium for trait/module names because the stripped binary only exposes
//! monomorphized serializers.
//!
//! IDA writes attempted from the TCP write wave: helper names
//! `bincode_fork_ser_write__encode_to_vec_varint_le` and
//! `bincode_fork_ser_write__vec_writer_write_all`; the shared IDA queue was full.

#![allow(dead_code)]

use core::fmt;

const SINGLE_BYTE_MAX: u128 = 250;
const U16_TAG: u8 = 251;
const U32_TAG: u8 = 252;
const U64_TAG: u8 = 253;
const U128_TAG: u8 = 254;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EncodeError {
    Message(&'static str),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for EncodeError {}

pub trait Encoder {
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError>;
}

pub trait Encode {
    fn encode<E: Encoder + ?Sized>(&self, encoder: &mut E) -> Result<(), EncodeError>;
}

#[derive(Debug, Default)]
pub struct VecWriter {
    bytes: Vec<u8>,
}

impl VecWriter {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self { bytes: Vec::with_capacity(capacity) }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Encoder for VecWriter {
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

pub fn encode_to_vec_varint_le<T: Encode + ?Sized>(value: &T) -> Result<Vec<u8>, EncodeError> {
    let mut writer = VecWriter::new();
    value.encode(&mut writer)?;
    Ok(writer.into_inner())
}

#[inline]
pub fn write_u8<E: Encoder + ?Sized>(encoder: &mut E, value: u8) -> Result<(), EncodeError> {
    encoder.write(&[value])
}

#[inline]
pub fn write_bool<E: Encoder + ?Sized>(encoder: &mut E, value: bool) -> Result<(), EncodeError> {
    write_u8(encoder, u8::from(value))
}

#[inline]
pub fn write_le_u16<E: Encoder + ?Sized>(encoder: &mut E, value: u16) -> Result<(), EncodeError> {
    encoder.write(&value.to_le_bytes())
}

#[inline]
pub fn write_le_u32<E: Encoder + ?Sized>(encoder: &mut E, value: u32) -> Result<(), EncodeError> {
    encoder.write(&value.to_le_bytes())
}

#[inline]
pub fn write_le_u64<E: Encoder + ?Sized>(encoder: &mut E, value: u64) -> Result<(), EncodeError> {
    encoder.write(&value.to_le_bytes())
}

#[inline]
pub fn write_le_u128<E: Encoder + ?Sized>(encoder: &mut E, value: u128) -> Result<(), EncodeError> {
    encoder.write(&value.to_le_bytes())
}

pub fn write_varint_u128<E: Encoder + ?Sized>(encoder: &mut E, value: u128) -> Result<(), EncodeError> {
    match value {
        0..=SINGLE_BYTE_MAX => write_u8(encoder, value as u8),
        251..=0xffff => {
            write_u8(encoder, U16_TAG)?;
            write_le_u16(encoder, value as u16)
        }
        0x1_0000..=0xffff_ffff => {
            write_u8(encoder, U32_TAG)?;
            write_le_u32(encoder, value as u32)
        }
        0x1_0000_0000..=0xffff_ffff_ffff_ffff => {
            write_u8(encoder, U64_TAG)?;
            write_le_u64(encoder, value as u64)
        }
        _ => {
            write_u8(encoder, U128_TAG)?;
            write_le_u128(encoder, value)
        }
    }
}

#[inline]
pub fn write_varint_usize<E: Encoder + ?Sized>(encoder: &mut E, value: usize) -> Result<(), EncodeError> {
    write_varint_u128(encoder, value as u128)
}

#[inline]
pub fn write_varint_u64<E: Encoder + ?Sized>(encoder: &mut E, value: u64) -> Result<(), EncodeError> {
    write_varint_u128(encoder, value as u128)
}

#[inline]
pub fn write_varint_u32<E: Encoder + ?Sized>(encoder: &mut E, value: u32) -> Result<(), EncodeError> {
    write_varint_u128(encoder, value as u128)
}

#[inline]
pub fn write_varint_i64<E: Encoder + ?Sized>(encoder: &mut E, value: i64) -> Result<(), EncodeError> {
    write_varint_u64(encoder, zigzag_i64(value))
}

#[inline]
pub fn write_varint_i32<E: Encoder + ?Sized>(encoder: &mut E, value: i32) -> Result<(), EncodeError> {
    write_varint_u32(encoder, zigzag_i32(value))
}

#[inline]
fn zigzag_i32(value: i32) -> u32 {
    ((value << 1) ^ (value >> 31)) as u32
}

#[inline]
fn zigzag_i64(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)) as u64
}

impl Encode for u8 {
    fn encode<E: Encoder + ?Sized>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        write_u8(encoder, *self)
    }
}

impl Encode for bool {
    fn encode<E: Encoder + ?Sized>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        write_bool(encoder, *self)
    }
}

impl Encode for u32 {
    fn encode<E: Encoder + ?Sized>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        write_varint_u32(encoder, *self)
    }
}

impl Encode for u64 {
    fn encode<E: Encoder + ?Sized>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        write_varint_u64(encoder, *self)
    }
}

impl<T: Encode> Encode for Vec<T> {
    fn encode<E: Encoder + ?Sized>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        write_varint_usize(encoder, self.len())?;
        for item in self {
            item.encode(encoder)?;
        }
        Ok(())
    }
}


impl Encode for String {
    fn encode<E: Encoder + ?Sized>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        write_varint_usize(encoder, self.len())?;
        encoder.write(self.as_bytes())
    }
}

impl Encode for &str {
    fn encode<E: Encoder + ?Sized>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        write_varint_usize(encoder, self.len())?;
        encoder.write(self.as_bytes())
    }
}
