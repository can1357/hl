//! Thin interface for `/home/ubuntu/hl/bincode-fork/src/de/impls.rs`.
//!
//! This crate is not a primary reconstruction target. Keep this file as a
//! packet/parser compatibility surface only. The primitive decode APIs below are
//! preserved to make protocol reconstructions readable; do not treat this as a
//! full source recovery of bincode-fork internals.
//!
//! Binary-grounded packet anchors retained: prior local routine notes identify
//! `bincode_deserialize_varint_le`, core deserialize wrappers, and varint decode
//! helpers used by gossip/consensus packet parsing.

use super::{
    read::{BorrowReader, Reader},
    BorrowDecode, BorrowDecoder, Decode, Decoder,
};
use crate::{
    config::{Endianness, IntEncoding, InternalEndianConfig, InternalIntEncodingConfig},
    error::{DecodeError, IntegerType},
    impl_borrow_decode,
};
use core::{
    cell::{Cell, RefCell},
    cmp::Reverse,
    num::{
        NonZeroI128, NonZeroI16, NonZeroI32, NonZeroI64, NonZeroI8, NonZeroIsize,
        NonZeroU128, NonZeroU16, NonZeroU32, NonZeroU64, NonZeroU8, NonZeroUsize,
        Wrapping,
    },
    ops::{Bound, Range, RangeInclusive},
    time::Duration,
};

// Compatibility-only primitive Decode/BorrowDecode impls. Keep changes here narrow;
// protocol behavior should be grounded at the packet call sites, not by reversing
// the whole bincode fork.

impl<Context> Decode<Context> for bool {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(false),
            1 => Ok(true),
            x => Err(DecodeError::InvalidBooleanValue(x)),
        }
    }
}
impl_borrow_decode!(bool);

impl<Context> Decode<Context> for u8 {
    #[inline]
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(1)?;
        if let Some(buf) = decoder.reader().peek_read(1) {
            let byte = buf[0];
            decoder.reader().consume(1);
            Ok(byte)
        } else {
            let mut bytes = [0u8; 1];
            decoder.reader().read(&mut bytes)?;
            Ok(bytes[0])
        }
    }
}
impl_borrow_decode!(u8);

macro_rules! decode_nonzero {
    ($ty:ty, $inner:ty, $integer:ident) => {
        impl<Context> Decode<Context> for $ty {
            fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
                <$ty>::new(<$inner>::decode(decoder)?).ok_or(DecodeError::NonZeroTypeIsZero {
                    non_zero_type: IntegerType::$integer,
                })
            }
        }
        impl_borrow_decode!($ty);
    };
}

decode_nonzero!(NonZeroU8, u8, U8);

impl<Context> Decode<Context> for u16 {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(2)?;
        match D::C::INT_ENCODING {
            IntEncoding::Variable => crate::varint::varint_decode_u16(decoder.reader(), D::C::ENDIAN),
            IntEncoding::Fixed => {
                let mut bytes = [0u8; 2];
                decoder.reader().read(&mut bytes)?;
                Ok(match D::C::ENDIAN {
                    Endianness::Little => u16::from_le_bytes(bytes),
                    Endianness::Big => u16::from_be_bytes(bytes),
                })
            }
        }
    }
}
impl_borrow_decode!(u16);
decode_nonzero!(NonZeroU16, u16, U16);

impl<Context> Decode<Context> for u32 {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(4)?;
        match D::C::INT_ENCODING {
            IntEncoding::Variable => crate::varint::varint_decode_u32(decoder.reader(), D::C::ENDIAN),
            IntEncoding::Fixed => {
                let mut bytes = [0u8; 4];
                decoder.reader().read(&mut bytes)?;
                Ok(match D::C::ENDIAN {
                    Endianness::Little => u32::from_le_bytes(bytes),
                    Endianness::Big => u32::from_be_bytes(bytes),
                })
            }
        }
    }
}
impl_borrow_decode!(u32);
decode_nonzero!(NonZeroU32, u32, U32);

impl<Context> Decode<Context> for u64 {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(8)?;
        match D::C::INT_ENCODING {
            IntEncoding::Variable => crate::varint::varint_decode_u64(decoder.reader(), D::C::ENDIAN),
            IntEncoding::Fixed => {
                let mut bytes = [0u8; 8];
                decoder.reader().read(&mut bytes)?;
                Ok(match D::C::ENDIAN {
                    Endianness::Little => u64::from_le_bytes(bytes),
                    Endianness::Big => u64::from_be_bytes(bytes),
                })
            }
        }
    }
}
impl_borrow_decode!(u64);
decode_nonzero!(NonZeroU64, u64, U64);

impl<Context> Decode<Context> for u128 {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(16)?;
        match D::C::INT_ENCODING {
            IntEncoding::Variable => crate::varint::varint_decode_u128(decoder.reader(), D::C::ENDIAN),
            IntEncoding::Fixed => {
                let mut bytes = [0u8; 16];
                decoder.reader().read(&mut bytes)?;
                Ok(match D::C::ENDIAN {
                    Endianness::Little => u128::from_le_bytes(bytes),
                    Endianness::Big => u128::from_be_bytes(bytes),
                })
            }
        }
    }
}
impl_borrow_decode!(u128);
decode_nonzero!(NonZeroU128, u128, U128);

impl<Context> Decode<Context> for usize {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(8)?;
        match D::C::INT_ENCODING {
            IntEncoding::Variable => crate::varint::varint_decode_usize(decoder.reader(), D::C::ENDIAN),
            IntEncoding::Fixed => {
                let mut bytes = [0u8; 8];
                decoder.reader().read(&mut bytes)?;
                let value = match D::C::ENDIAN {
                    Endianness::Little => u64::from_le_bytes(bytes),
                    Endianness::Big => u64::from_be_bytes(bytes),
                };
                value.try_into().map_err(|_| DecodeError::OutsideUsizeRange(value))
            }
        }
    }
}
impl_borrow_decode!(usize);
decode_nonzero!(NonZeroUsize, usize, Usize);

impl<Context> Decode<Context> for i8 {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(1)?;
        let mut bytes = [0u8; 1];
        decoder.reader().read(&mut bytes)?;
        Ok(bytes[0] as i8)
    }
}
impl_borrow_decode!(i8);
decode_nonzero!(NonZeroI8, i8, I8);

impl<Context> Decode<Context> for i16 {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(2)?;
        match D::C::INT_ENCODING {
            IntEncoding::Variable => crate::varint::varint_decode_i16(decoder.reader(), D::C::ENDIAN),
            IntEncoding::Fixed => {
                let mut bytes = [0u8; 2];
                decoder.reader().read(&mut bytes)?;
                Ok(match D::C::ENDIAN {
                    Endianness::Little => i16::from_le_bytes(bytes),
                    Endianness::Big => i16::from_be_bytes(bytes),
                })
            }
        }
    }
}
impl_borrow_decode!(i16);
decode_nonzero!(NonZeroI16, i16, I16);

impl<Context> Decode<Context> for i32 {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(4)?;
        match D::C::INT_ENCODING {
            IntEncoding::Variable => crate::varint::varint_decode_i32(decoder.reader(), D::C::ENDIAN),
            IntEncoding::Fixed => {
                let mut bytes = [0u8; 4];
                decoder.reader().read(&mut bytes)?;
                Ok(match D::C::ENDIAN {
                    Endianness::Little => i32::from_le_bytes(bytes),
                    Endianness::Big => i32::from_be_bytes(bytes),
                })
            }
        }
    }
}
impl_borrow_decode!(i32);
decode_nonzero!(NonZeroI32, i32, I32);

impl<Context> Decode<Context> for i64 {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(8)?;
        match D::C::INT_ENCODING {
            IntEncoding::Variable => crate::varint::varint_decode_i64(decoder.reader(), D::C::ENDIAN),
            IntEncoding::Fixed => {
                let mut bytes = [0u8; 8];
                decoder.reader().read(&mut bytes)?;
                Ok(match D::C::ENDIAN {
                    Endianness::Little => i64::from_le_bytes(bytes),
                    Endianness::Big => i64::from_be_bytes(bytes),
                })
            }
        }
    }
}
impl_borrow_decode!(i64);
decode_nonzero!(NonZeroI64, i64, I64);

impl<Context> Decode<Context> for i128 {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(16)?;
        match D::C::INT_ENCODING {
            IntEncoding::Variable => crate::varint::varint_decode_i128(decoder.reader(), D::C::ENDIAN),
            IntEncoding::Fixed => {
                let mut bytes = [0u8; 16];
                decoder.reader().read(&mut bytes)?;
                Ok(match D::C::ENDIAN {
                    Endianness::Little => i128::from_le_bytes(bytes),
                    Endianness::Big => i128::from_be_bytes(bytes),
                })
            }
        }
    }
}
impl_borrow_decode!(i128);
decode_nonzero!(NonZeroI128, i128, I128);

impl<Context> Decode<Context> for isize {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(8)?;
        match D::C::INT_ENCODING {
            IntEncoding::Variable => crate::varint::varint_decode_isize(decoder.reader(), D::C::ENDIAN),
            IntEncoding::Fixed => {
                let mut bytes = [0u8; 8];
                decoder.reader().read(&mut bytes)?;
                Ok(match D::C::ENDIAN {
                    Endianness::Little => i64::from_le_bytes(bytes),
                    Endianness::Big => i64::from_be_bytes(bytes),
                } as isize)
            }
        }
    }
}
impl_borrow_decode!(isize);
decode_nonzero!(NonZeroIsize, isize, Isize);

impl<Context> Decode<Context> for f32 {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(4)?;
        let mut bytes = [0u8; 4];
        decoder.reader().read(&mut bytes)?;
        Ok(match D::C::ENDIAN {
            Endianness::Little => f32::from_le_bytes(bytes),
            Endianness::Big => f32::from_be_bytes(bytes),
        })
    }
}
impl_borrow_decode!(f32);

impl<Context> Decode<Context> for f64 {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(8)?;
        let mut bytes = [0u8; 8];
        decoder.reader().read(&mut bytes)?;
        Ok(match D::C::ENDIAN {
            Endianness::Little => f64::from_le_bytes(bytes),
            Endianness::Big => f64::from_be_bytes(bytes),
        })
    }
}
impl_borrow_decode!(f64);

impl<Context, T: Decode<Context>> Decode<Context> for Wrapping<T> {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        Ok(Wrapping(T::decode(decoder)?))
    }
}
impl<'de, Context, T: BorrowDecode<'de, Context>> BorrowDecode<'de, Context> for Wrapping<T> {
    fn borrow_decode<D: BorrowDecoder<'de, Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        Ok(Wrapping(T::borrow_decode(decoder)?))
    }
}

impl<Context, T: Decode<Context>> Decode<Context> for Reverse<T> {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        Ok(Reverse(T::decode(decoder)?))
    }
}
impl<'de, Context, T: BorrowDecode<'de, Context>> BorrowDecode<'de, Context> for Reverse<T> {
    fn borrow_decode<D: BorrowDecoder<'de, Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        Ok(Reverse(T::borrow_decode(decoder)?))
    }
}

impl<Context> Decode<Context> for char {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut array = [0u8; 4];
        decoder.reader().read(&mut array[..1])?;
        let width = utf8_char_width(array[0]);
        if width == 0 {
            return Err(DecodeError::InvalidCharEncoding(array));
        }
        decoder.claim_bytes_read(width)?;
        if width == 1 {
            return Ok(array[0] as char);
        }
        decoder.reader().read(&mut array[1..width])?;
        core::str::from_utf8(&array[..width])
            .ok()
            .and_then(|s| s.chars().next())
            .ok_or(DecodeError::InvalidCharEncoding(array))
    }
}
impl_borrow_decode!(char);

impl<'a, 'de: 'a, Context> BorrowDecode<'de, Context> for &'a [u8] {
    fn borrow_decode<D: BorrowDecoder<'de, Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        let len = super::decode_slice_len(decoder)?;
        decoder.claim_bytes_read(len)?;
        decoder.borrow_reader().take_bytes(len)
    }
}

impl<'a, 'de: 'a, Context> BorrowDecode<'de, Context> for &'a str {
    fn borrow_decode<D: BorrowDecoder<'de, Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        let slice = <&[u8]>::borrow_decode(decoder)?;
        core::str::from_utf8(slice).map_err(|inner| DecodeError::Utf8 { inner })
    }
}

impl<Context, T, const N: usize> Decode<Context> for [T; N]
where
    T: Decode<Context>,
{
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(core::mem::size_of::<[T; N]>())?;
        if unty::type_equal::<T, u8>() {
            let mut buf = [0u8; N];
            decoder.reader().read(&mut buf)?;
            let ptr = &mut buf as *mut _ as *mut [T; N];
            Ok(unsafe { ptr.read() })
        } else {
            let result = super::impl_core::collect_into_array(&mut (0..N).map(|_| {
                decoder.unclaim_bytes_read(core::mem::size_of::<T>());
                T::decode(decoder)
            }));
            result.unwrap()
        }
    }
}

impl<'de, T, const N: usize, Context> BorrowDecode<'de, Context> for [T; N]
where
    T: BorrowDecode<'de, Context>,
{
    fn borrow_decode<D: BorrowDecoder<'de, Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        decoder.claim_bytes_read(core::mem::size_of::<[T; N]>())?;
        if unty::type_equal::<T, u8>() {
            let mut buf = [0u8; N];
            decoder.reader().read(&mut buf)?;
            let ptr = &mut buf as *mut _ as *mut [T; N];
            Ok(unsafe { ptr.read() })
        } else {
            let result = super::impl_core::collect_into_array(&mut (0..N).map(|_| {
                decoder.unclaim_bytes_read(core::mem::size_of::<T>());
                T::borrow_decode(decoder)
            }));
            result.unwrap()
        }
    }
}

impl<Context> Decode<Context> for () {
    fn decode<D: Decoder<Context = Context>>(_: &mut D) -> Result<Self, DecodeError> {
        Ok(())
    }
}
impl_borrow_decode!(());

impl<Context, T> Decode<Context> for core::marker::PhantomData<T> {
    fn decode<D: Decoder<Context = Context>>(_: &mut D) -> Result<Self, DecodeError> {
        Ok(core::marker::PhantomData)
    }
}
impl_borrow_decode!(core::marker::PhantomData<T>, T);

impl<Context, T> Decode<Context> for Option<T>
where
    T: Decode<Context>,
{
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        match super::decode_option_variant(decoder, core::any::type_name::<Option<T>>())? {
            Some(_) => Ok(Some(T::decode(decoder)?)),
            None => Ok(None),
        }
    }
}

impl<'de, T, Context> BorrowDecode<'de, Context> for Option<T>
where
    T: BorrowDecode<'de, Context>,
{
    fn borrow_decode<D: BorrowDecoder<'de, Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        match super::decode_option_variant(decoder, core::any::type_name::<Option<T>>())? {
            Some(_) => Ok(Some(T::borrow_decode(decoder)?)),
            None => Ok(None),
        }
    }
}

impl<Context, T, U> Decode<Context> for Result<T, U>
where
    T: Decode<Context>,
    U: Decode<Context>,
{
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        match u32::decode(decoder)? {
            0 => Ok(Ok(T::decode(decoder)?)),
            1 => Ok(Err(U::decode(decoder)?)),
            x => Err(DecodeError::UnexpectedVariant {
                found: x,
                allowed: &crate::error::AllowedEnumVariants::Range { max: 1, min: 0 },
                type_name: core::any::type_name::<Result<T, U>>(),
            }),
        }
    }
}

impl<'de, T, U, Context> BorrowDecode<'de, Context> for Result<T, U>
where
    T: BorrowDecode<'de, Context>,
    U: BorrowDecode<'de, Context>,
{
    fn borrow_decode<D: BorrowDecoder<'de, Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        match u32::decode(decoder)? {
            0 => Ok(Ok(T::borrow_decode(decoder)?)),
            1 => Ok(Err(U::borrow_decode(decoder)?)),
            x => Err(DecodeError::UnexpectedVariant {
                found: x,
                allowed: &crate::error::AllowedEnumVariants::Range { max: 1, min: 0 },
                type_name: core::any::type_name::<Result<T, U>>(),
            }),
        }
    }
}

impl<Context, T> Decode<Context> for Cell<T>
where
    T: Decode<Context>,
{
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        Ok(Cell::new(T::decode(decoder)?))
    }
}
impl<'de, T, Context> BorrowDecode<'de, Context> for Cell<T>
where
    T: BorrowDecode<'de, Context>,
{
    fn borrow_decode<D: BorrowDecoder<'de, Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        Ok(Cell::new(T::borrow_decode(decoder)?))
    }
}

impl<Context, T> Decode<Context> for RefCell<T>
where
    T: Decode<Context>,
{
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        Ok(RefCell::new(T::decode(decoder)?))
    }
}
impl<'de, T, Context> BorrowDecode<'de, Context> for RefCell<T>
where
    T: BorrowDecode<'de, Context>,
{
    fn borrow_decode<D: BorrowDecoder<'de, Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        Ok(RefCell::new(T::borrow_decode(decoder)?))
    }
}

impl<Context> Decode<Context> for Duration {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        const NANOS_PER_SEC: u64 = 1_000_000_000;
        let secs: u64 = Decode::decode(decoder)?;
        let nanos: u32 = Decode::decode(decoder)?;
        if secs.checked_add(u64::from(nanos) / NANOS_PER_SEC).is_none() {
            return Err(DecodeError::InvalidDuration { secs, nanos });
        }
        Ok(Duration::new(secs, nanos))
    }
}
impl_borrow_decode!(Duration);

impl<Context, T> Decode<Context> for Range<T>
where
    T: Decode<Context>,
{
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        let min = T::decode(decoder)?;
        let max = T::decode(decoder)?;
        Ok(min..max)
    }
}
impl<'de, T, Context> BorrowDecode<'de, Context> for Range<T>
where
    T: BorrowDecode<'de, Context>,
{
    fn borrow_decode<D: BorrowDecoder<'de, Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        let min = T::borrow_decode(decoder)?;
        let max = T::borrow_decode(decoder)?;
        Ok(min..max)
    }
}

impl<Context, T> Decode<Context> for RangeInclusive<T>
where
    T: Decode<Context>,
{
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        let min = T::decode(decoder)?;
        let max = T::decode(decoder)?;
        Ok(RangeInclusive::new(min, max))
    }
}
impl<'de, T, Context> BorrowDecode<'de, Context> for RangeInclusive<T>
where
    T: BorrowDecode<'de, Context>,
{
    fn borrow_decode<D: BorrowDecoder<'de, Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        let min = T::borrow_decode(decoder)?;
        let max = T::borrow_decode(decoder)?;
        Ok(RangeInclusive::new(min, max))
    }
}

impl<T, Context> Decode<Context> for Bound<T>
where
    T: Decode<Context>,
{
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        match u32::decode(decoder)? {
            0 => Ok(Bound::Unbounded),
            1 => Ok(Bound::Included(T::decode(decoder)?)),
            2 => Ok(Bound::Excluded(T::decode(decoder)?)),
            x => Err(DecodeError::UnexpectedVariant {
                allowed: &crate::error::AllowedEnumVariants::Range { max: 2, min: 0 },
                found: x,
                type_name: core::any::type_name::<Bound<T>>(),
            }),
        }
    }
}

impl<'de, T, Context> BorrowDecode<'de, Context> for Bound<T>
where
    T: BorrowDecode<'de, Context>,
{
    fn borrow_decode<D: BorrowDecoder<'de, Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        match u32::decode(decoder)? {
            0 => Ok(Bound::Unbounded),
            1 => Ok(Bound::Included(T::borrow_decode(decoder)?)),
            2 => Ok(Bound::Excluded(T::borrow_decode(decoder)?)),
            x => Err(DecodeError::UnexpectedVariant {
                allowed: &crate::error::AllowedEnumVariants::Range { max: 2, min: 0 },
                found: x,
                type_name: core::any::type_name::<Bound<T>>(),
            }),
        }
    }
}

const UTF8_CHAR_WIDTH: [u8; 256] = [
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

const fn utf8_char_width(b: u8) -> usize {
    UTF8_CHAR_WIDTH[b as usize] as usize
}
