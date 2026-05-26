//! Reconstructed bincode varint decode helpers required by `de/impls.rs`.
//!
//! Source placement: `/home/ubuntu/hl/bincode-fork/src/varint/*` is
//! [INFERENCE] from bincode-fork module layout and calls from `de/impls.rs`.
//! Compatibility-only varint helpers for packet parsing. Protocol callers should
//! anchor exact behavior at their packet decoder EAs rather than this helper file.
//! decoder at `0x3828580`; top-level network deserialize wrapper `0x382F8A0`
//! uses this varint+little-endian configuration.

use core::convert::TryInto;

use crate::{
    config::Endianness,
    de::read::Reader,
    error::{DecodeError, IntegerType},
};

const SINGLE_BYTE_MAX: u8 = 250;
const U16_BYTE: u8 = 251;
const U32_BYTE: u8 = 252;
const U64_BYTE: u8 = 253;
const U128_BYTE: u8 = 254;

// Compatibility-only helper bodies; keep follow-up analysis anchored to concrete
// packet decoder/encoder call sites.

#[inline(never)]
#[cold]
const fn invalid_varint_discriminant<T>(expected: IntegerType, found: IntegerType) -> Result<T, DecodeError> {
    Err(DecodeError::InvalidIntegerType { expected, found })
}

#[inline]
fn read_u16(bytes: &[u8], endian: Endianness) -> u16 {
    match endian {
        Endianness::Big => u16::from_be_bytes(bytes[..2].try_into().unwrap()),
        Endianness::Little => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
    }
}

#[inline]
fn read_u32(bytes: &[u8], endian: Endianness) -> u32 {
    match endian {
        Endianness::Big => u32::from_be_bytes(bytes[..4].try_into().unwrap()),
        Endianness::Little => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
    }
}

#[inline]
fn read_u64(bytes: &[u8], endian: Endianness) -> u64 {
    match endian {
        Endianness::Big => u64::from_be_bytes(bytes[..8].try_into().unwrap()),
        Endianness::Little => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
    }
}

#[inline]
fn read_u128(bytes: &[u8], endian: Endianness) -> u128 {
    match endian {
        Endianness::Big => u128::from_be_bytes(bytes[..16].try_into().unwrap()),
        Endianness::Little => u128::from_le_bytes(bytes[..16].try_into().unwrap()),
    }
}

#[inline(never)]
#[cold]
fn read_slow<R: Reader, const N: usize>(read: &mut R) -> Result<[u8; N], DecodeError> {
    let mut bytes = [0u8; N];
    read.read(&mut bytes)?;
    Ok(bytes)
}

pub fn varint_decode_u16<R: Reader>(read: &mut R, endian: Endianness) -> Result<u16, DecodeError> {
    if let Some(bytes) = read.peek_read(3) {
        let (out, used) = match bytes[0] {
            byte @ 0..=SINGLE_BYTE_MAX => (byte as u16, 1),
            U16_BYTE => (read_u16(&bytes[1..], endian), 3),
            U32_BYTE => return invalid_varint_discriminant(IntegerType::U16, IntegerType::U32),
            U64_BYTE => return invalid_varint_discriminant(IntegerType::U16, IntegerType::U64),
            U128_BYTE => return invalid_varint_discriminant(IntegerType::U16, IntegerType::U128),
            _ => return invalid_varint_discriminant(IntegerType::U16, IntegerType::Reserved),
        };
        read.consume(used);
        Ok(out)
    } else {
        match read_slow::<R, 1>(read)?[0] {
            byte @ 0..=SINGLE_BYTE_MAX => Ok(byte as u16),
            U16_BYTE => Ok(read_u16(&read_slow::<R, 2>(read)?, endian)),
            U32_BYTE => invalid_varint_discriminant(IntegerType::U16, IntegerType::U32),
            U64_BYTE => invalid_varint_discriminant(IntegerType::U16, IntegerType::U64),
            U128_BYTE => invalid_varint_discriminant(IntegerType::U16, IntegerType::U128),
            _ => invalid_varint_discriminant(IntegerType::U16, IntegerType::Reserved),
        }
    }
}

pub fn varint_decode_u32<R: Reader>(read: &mut R, endian: Endianness) -> Result<u32, DecodeError> {
    if let Some(bytes) = read.peek_read(5) {
        let (out, used) = match bytes[0] {
            byte @ 0..=SINGLE_BYTE_MAX => (byte as u32, 1),
            U16_BYTE => (read_u16(&bytes[1..], endian) as u32, 3),
            U32_BYTE => (read_u32(&bytes[1..], endian), 5),
            U64_BYTE => return invalid_varint_discriminant(IntegerType::U32, IntegerType::U64),
            U128_BYTE => return invalid_varint_discriminant(IntegerType::U32, IntegerType::U128),
            _ => return invalid_varint_discriminant(IntegerType::U32, IntegerType::Reserved),
        };
        read.consume(used);
        Ok(out)
    } else {
        match read_slow::<R, 1>(read)?[0] {
            byte @ 0..=SINGLE_BYTE_MAX => Ok(byte as u32),
            U16_BYTE => Ok(read_u16(&read_slow::<R, 2>(read)?, endian) as u32),
            U32_BYTE => Ok(read_u32(&read_slow::<R, 4>(read)?, endian)),
            U64_BYTE => invalid_varint_discriminant(IntegerType::U32, IntegerType::U64),
            U128_BYTE => invalid_varint_discriminant(IntegerType::U32, IntegerType::U128),
            _ => invalid_varint_discriminant(IntegerType::U32, IntegerType::Reserved),
        }
    }
}

pub fn varint_decode_u64<R: Reader>(read: &mut R, endian: Endianness) -> Result<u64, DecodeError> {
    if let Some(bytes) = read.peek_read(9) {
        let (out, used) = match bytes[0] {
            byte @ 0..=SINGLE_BYTE_MAX => (byte as u64, 1),
            U16_BYTE => (read_u16(&bytes[1..], endian) as u64, 3),
            U32_BYTE => (read_u32(&bytes[1..], endian) as u64, 5),
            U64_BYTE => (read_u64(&bytes[1..], endian), 9),
            U128_BYTE => return invalid_varint_discriminant(IntegerType::U64, IntegerType::U128),
            _ => return invalid_varint_discriminant(IntegerType::U64, IntegerType::Reserved),
        };
        read.consume(used);
        Ok(out)
    } else {
        match read_slow::<R, 1>(read)?[0] {
            byte @ 0..=SINGLE_BYTE_MAX => Ok(byte as u64),
            U16_BYTE => Ok(read_u16(&read_slow::<R, 2>(read)?, endian) as u64),
            U32_BYTE => Ok(read_u32(&read_slow::<R, 4>(read)?, endian) as u64),
            U64_BYTE => Ok(read_u64(&read_slow::<R, 8>(read)?, endian)),
            U128_BYTE => invalid_varint_discriminant(IntegerType::U64, IntegerType::U128),
            _ => invalid_varint_discriminant(IntegerType::U64, IntegerType::Reserved),
        }
    }
}

pub fn varint_decode_usize<R: Reader>(read: &mut R, endian: Endianness) -> Result<usize, DecodeError> {
    match varint_decode_u64(read, endian) {
        Ok(value) => value.try_into().map_err(|_| DecodeError::OutsideUsizeRange(value)),
        Err(DecodeError::InvalidIntegerType { found, .. }) => Err(DecodeError::InvalidIntegerType {
            expected: IntegerType::Usize,
            found,
        }),
        Err(e) => Err(e),
    }
}

pub fn varint_decode_u128<R: Reader>(read: &mut R, endian: Endianness) -> Result<u128, DecodeError> {
    if let Some(bytes) = read.peek_read(17) {
        let (out, used) = match bytes[0] {
            byte @ 0..=SINGLE_BYTE_MAX => (byte as u128, 1),
            U16_BYTE => (read_u16(&bytes[1..], endian) as u128, 3),
            U32_BYTE => (read_u32(&bytes[1..], endian) as u128, 5),
            U64_BYTE => (read_u64(&bytes[1..], endian) as u128, 9),
            U128_BYTE => (read_u128(&bytes[1..], endian), 17),
            _ => return invalid_varint_discriminant(IntegerType::U128, IntegerType::Reserved),
        };
        read.consume(used);
        Ok(out)
    } else {
        match read_slow::<R, 1>(read)?[0] {
            byte @ 0..=SINGLE_BYTE_MAX => Ok(byte as u128),
            U16_BYTE => Ok(read_u16(&read_slow::<R, 2>(read)?, endian) as u128),
            U32_BYTE => Ok(read_u32(&read_slow::<R, 4>(read)?, endian) as u128),
            U64_BYTE => Ok(read_u64(&read_slow::<R, 8>(read)?, endian) as u128),
            U128_BYTE => Ok(read_u128(&read_slow::<R, 16>(read)?, endian)),
            _ => invalid_varint_discriminant(IntegerType::U128, IntegerType::Reserved),
        }
    }
}


pub fn varint_decode_i16<R: Reader>(read: &mut R, endian: Endianness) -> Result<i16, DecodeError> {
    let n = varint_decode_u16(read, endian).map_err(DecodeError::change_integer_type_to_signed)?;
    Ok(if n % 2 == 0 { (n / 2) as i16 } else { !(n / 2) as i16 })
}

pub fn varint_decode_i32<R: Reader>(read: &mut R, endian: Endianness) -> Result<i32, DecodeError> {
    let n = varint_decode_u32(read, endian).map_err(DecodeError::change_integer_type_to_signed)?;
    Ok(if n % 2 == 0 { (n / 2) as i32 } else { !(n / 2) as i32 })
}

pub fn varint_decode_i64<R: Reader>(read: &mut R, endian: Endianness) -> Result<i64, DecodeError> {
    let n = varint_decode_u64(read, endian).map_err(DecodeError::change_integer_type_to_signed)?;
    Ok(if n % 2 == 0 { (n / 2) as i64 } else { !(n / 2) as i64 })
}

pub fn varint_decode_i128<R: Reader>(read: &mut R, endian: Endianness) -> Result<i128, DecodeError> {
    let n = varint_decode_u128(read, endian).map_err(DecodeError::change_integer_type_to_signed)?;
    Ok(if n % 2 == 0 { (n / 2) as i128 } else { !(n / 2) as i128 })
}

pub fn varint_decode_isize<R: Reader>(read: &mut R, endian: Endianness) -> Result<isize, DecodeError> {
    match varint_decode_i64(read, endian) {
        Ok(val) => Ok(val as isize),
        Err(DecodeError::InvalidIntegerType { found, .. }) => Err(DecodeError::InvalidIntegerType {
            expected: IntegerType::Isize,
            found: found.into_signed(),
        }),
        Err(e) => Err(e),
    }
}
