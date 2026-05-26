use core::convert::TryFrom;
use core::fmt;
use core::fmt::Write as _;
use core::ops::{Add, AddAssign, Neg, Sub, SubAssign};
use core::str::FromStr;

use rust_decimal::prelude::{FromPrimitive, ToPrimitive};
use rust_decimal::Decimal;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de;

pub const FP_DECIMALS: u8 = 8;
pub const FP_SCALE: i64 = 100_000_000;
pub const PERP_PRICE_DECIMALS: u8 = 6;
pub const SPOT_PRICE_DECIMALS: u8 = 8;
pub const MAX_WIRE_SIGNIFICANT_FIGURES: u8 = 5;
pub const USDC_NTLI_PER_USDC_NTL: i64 = 10_000;
pub const DECIBPS_PER_ONE: i64 = 100_000;
pub const PX_SZ_NOTIONAL_SCALE: u128 = 100_000_000_000_000;

const MAX_SCALED_I64: i128 = i64::MAX as i128 - 1;

const POW10_I64: [i64; 19] = [
    1,
    10,
    100,
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
    10_000_000_000,
    100_000_000_000,
    1_000_000_000_000,
    10_000_000_000_000,
    100_000_000_000_000,
    1_000_000_000_000_000,
    10_000_000_000_000_000,
    100_000_000_000_000_000,
    1_000_000_000_000_000_000,
];

const POW10_U64: [u64; 20] = [
    1,
    10,
    100,
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
    10_000_000_000,
    100_000_000_000,
    1_000_000_000_000,
    10_000_000_000_000,
    100_000_000_000_000,
    1_000_000_000_000_000,
    10_000_000_000_000_000,
    100_000_000_000_000_000,
    1_000_000_000_000_000_000,
    10_000_000_000_000_000_000,
];

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Px(pub PxPriv);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct UsdcPx(pub PxPriv);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Sz(pub SzPriv);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Szi(pub SziPriv);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Wei(pub WeiPriv);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Ntl(pub NtlPriv);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct UsdcNtl(pub NtlPriv);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct UsdcBigSpotNtl(pub BigNtlPriv);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Ntli(pub NtliPriv);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct UsdcNtli(pub NtliPriv);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct UsdcRoughNtli(pub NtliPriv);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Pdi(pub i64);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Decibps(pub i64);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FpDecimal(pub i64);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct RawLeverage(pub u32);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct MaxLeverage(pub RawLeverage);

#[repr(transparent)]
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct DecimalString(pub String);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UsdcNtlScaleSerde(pub UsdcNtl, pub u8);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PxPriv(pub i64);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct SzPriv(pub u64);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct SziPriv(pub i64);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct WeiPriv(pub u64);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct NtlPriv(pub u64);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct BigNtlPriv(pub u128);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct NtliPriv(pub i64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoundMode {
    RejectFractional,
    Round,
    Truncate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QtyParseError {
    Empty,
    Negative,
    InvalidByte,
    InvalidDecimal,
    TooManyDecimals,
    TooManySignificantFigures,
    NonPositive,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QtyArithmeticError {
    Underflow,
    Overflow,
    DivideByZero,
    InvalidScale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SzSign {
    Short,
    Flat,
    Long,
}

impl fmt::Display for QtyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "empty quantity",
            Self::Negative => "negative quantity",
            Self::InvalidByte => "invalid quantity byte",
            Self::InvalidDecimal => "Invalid decimal number",
            Self::TooManyDecimals => "Invalid number of decimals",
            Self::TooManySignificantFigures => "too many significant figures",
            Self::NonPositive => "non-positive quantity",
            Self::Overflow => "quantity overflow",
        })
    }
}

impl std::error::Error for QtyParseError {}

macro_rules! raw_newtype {
    ($ty:ident, $raw:ty) => {
        impl $ty {
            #[inline]
            pub const fn from_raw(raw: $raw) -> Self {
                Self(raw)
            }

            #[inline]
            pub const fn raw(self) -> $raw {
                self.0
            }
        }
    };
}

raw_newtype!(PxPriv, i64);
raw_newtype!(SzPriv, u64);
raw_newtype!(SziPriv, i64);
raw_newtype!(WeiPriv, u64);
raw_newtype!(NtlPriv, u64);
raw_newtype!(BigNtlPriv, u128);
raw_newtype!(NtliPriv, i64);

impl DecimalString {
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Px {
    pub const ZERO: Self = Self(PxPriv(0));
    pub const ONE_PERP: Self = Self(PxPriv(1_000_000));
    pub const ONE_SPOT: Self = Self(PxPriv(100_000_000));

    #[inline]
    pub const fn from_raw(raw: i64) -> Self {
        Self(PxPriv(raw))
    }

    #[inline]
    pub const fn raw(self) -> i64 {
        self.0 .0
    }

    #[inline]
    pub const fn is_positive(self) -> bool {
        self.raw() > 0
    }

    #[inline]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.raw().checked_add(rhs.raw()).map(Self::from_raw)
    }

    #[inline]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.raw().checked_sub(rhs.raw()).map(Self::from_raw)
    }

    #[inline]
    pub const fn scale(decimals: u8) -> Option<i64> {
        if (decimals as usize) < POW10_I64.len() {
            Some(POW10_I64[decimals as usize])
        } else {
            None
        }
    }

    #[inline]
    pub const fn wire_decimals(sz_decimals: u8, spot: bool) -> Option<u8> {
        let base = if spot { SPOT_PRICE_DECIMALS } else { PERP_PRICE_DECIMALS };
        if sz_decimals <= base { Some(base - sz_decimals) } else { None }
    }

    pub fn parse_wire_for_asset(input: &str, sz_decimals: u8, spot: bool) -> Result<Self, QtyParseError> {
        let decimals = Self::wire_decimals(sz_decimals, spot).ok_or(QtyParseError::TooManyDecimals)?;
        Self::parse_wire(input, decimals)
    }

    pub fn parse_wire(input: &str, decimals: u8) -> Result<Self, QtyParseError> {
        let scale = Self::scale(decimals).ok_or(QtyParseError::TooManyDecimals)?;
        let (whole, frac, frac_digits, seen_nonzero) = parse_unsigned_decimal_parts(input, decimals)?;
        if !seen_nonzero {
            return Err(QtyParseError::NonPositive);
        }
        let mut raw = whole.checked_mul(scale as u128).ok_or(QtyParseError::Overflow)?;
        let missing = decimals - frac_digits;
        raw = raw
            .checked_add(frac.checked_mul(Self::scale(missing).unwrap() as u128).ok_or(QtyParseError::Overflow)?)
            .ok_or(QtyParseError::Overflow)?;
        if raw > i64::MAX as u128 {
            return Err(QtyParseError::Overflow);
        }
        let px = Self::from_raw(raw as i64);
        if !px.fits_wire(decimals) {
            return Err(QtyParseError::TooManySignificantFigures);
        }
        Ok(px)
    }

    pub fn from_decimal_string(s: DecimalString) -> Result<Self, QtyParseError> {
        let raw = parse_decimal_string_to_scaled_i64_8(&s.0)?;
        if raw < 0 { Err(QtyParseError::Negative) } else { Ok(Self::from_raw(raw)) }
    }

    pub fn to_decimal_string(self) -> String {
        scaled_i64_8_to_decimal_string(self.raw())
    }

    pub fn fmt_decimal(self, decimals: u8, f: &mut impl fmt::Write) -> fmt::Result {
        let scale = Self::scale(decimals).ok_or(fmt::Error)?;
        fmt_signed_scaled(self.raw(), scale as u128, decimals, f)
    }

    pub fn fits_wire(self, decimals: u8) -> bool {
        if self.raw() <= 0 || Self::scale(decimals).is_none() {
            return false;
        }
        let mut raw = self.raw();
        while raw % 10 == 0 {
            raw /= 10;
        }
        let mut digits = 0u8;
        while raw != 0 {
            digits += 1;
            raw /= 10;
        }
        digits <= MAX_WIRE_SIGNIFICANT_FIGURES
    }

    #[inline]
    pub const fn is_divisible_by_tick(self, tick: Self) -> bool {
        tick.raw() > 0 && self.raw() % tick.raw() == 0
    }

    #[inline]
    pub const fn floor_to_tick(self, tick: Self) -> Option<Self> {
        if self.raw() < 0 || tick.raw() <= 0 {
            None
        } else {
            Some(Self::from_raw((self.raw() / tick.raw()) * tick.raw()))
        }
    }

    pub fn ceil_to_tick(self, tick: Self) -> Option<Self> {
        if self.raw() < 0 || tick.raw() <= 0 {
            return None;
        }
        let rem = self.raw() % tick.raw();
        if rem == 0 {
            Some(self)
        } else {
            (self.raw() / tick.raw()).checked_add(1).and_then(|q| q.checked_mul(tick.raw())).map(Self::from_raw)
        }
    }

    pub fn mul_size(self, sz: Sz, scale: i64, rounding: RoundMode) -> Option<Ntl> {
        if self.raw() < 0 || scale <= 0 {
            return None;
        }
        let product = (self.raw() as i128).checked_mul(sz.raw() as i128)?;
        let raw = div_round_nonnegative(product, scale as i128, rounding)?;
        if raw < 0 || raw > u64::MAX as i128 { None } else { Some(Ntl::from_raw(raw as u64)) }
    }
}

impl UsdcPx {
    pub const ZERO: Self = Self(PxPriv(0));

    #[inline]
    pub const fn from_raw(raw: i64) -> Self {
        Self(PxPriv(raw))
    }

    #[inline]
    pub const fn raw(self) -> i64 {
        self.0 .0
    }
}

impl Sz {
    pub const ZERO: Self = Self(SzPriv(0));
    pub const ONE: Self = Self(SzPriv(1));
    pub const MAX: Self = Self(SzPriv(u64::MAX));

    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self(SzPriv(raw))
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0 .0
    }

    #[inline]
    pub const fn is_zero(self) -> bool {
        self.raw() == 0
    }

    #[inline]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.raw().checked_add(rhs.raw()).map(Self::from_raw)
    }

    #[inline]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.raw().checked_sub(rhs.raw()).map(Self::from_raw)
    }

    #[inline]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self::from_raw(self.raw().saturating_add(rhs.raw()))
    }

    #[inline]
    pub const fn saturating_sub(self, rhs: Self) -> Self {
        Self::from_raw(self.raw().saturating_sub(rhs.raw()))
    }

    pub fn add_recording_overflow(self, rhs: Self) -> Self {
        match self.checked_add(rhs) {
            Some(value) => value,
            None => {
                record_qty_overflow();
                Self::MAX
            }
        }
    }

    pub fn sub_recording_underflow(self, rhs: Self) -> Self {
        match self.checked_sub(rhs) {
            Some(value) => value,
            None => {
                record_qty_underflow();
                Self::ZERO
            }
        }
    }

    #[inline]
    pub fn signed(self, positive: bool) -> Szi {
        let raw = i64::try_from(self.raw()).expect("size exceeds signed range");
        if positive { Szi::from_raw(raw) } else { Szi::from_raw(raw.checked_neg().expect("size exceeds signed range")) }
    }

    pub fn ceil_to_increment(self, increment: Sz) -> Sz {
        if increment.raw() == 0 {
            return self;
        }
        let q = self.raw() / increment.raw();
        let r = self.raw() % increment.raw();
        let rounded_q = q + u64::from(r != 0);
        Sz::from_raw(increment.raw().saturating_mul(rounded_q).max(u64::from(rounded_q != 0)))
    }

    pub fn floor_to_increment(self, increment: Sz) -> Sz {
        if increment.raw() == 0 {
            return self;
        }
        Sz::from_raw(increment.raw().saturating_mul(self.raw() / increment.raw()))
    }

    pub fn floor_to_visible_bucket(self) -> Sz {
        let step = visible_bucket_step(self.raw());
        if step == 0 { self } else { Sz::from_raw(step.saturating_mul(self.raw() / step)) }
    }
}

impl Szi {
    pub const ZERO: Self = Self(SziPriv(0));
    pub const MAX: Self = Self(SziPriv(i64::MAX));
    pub const MIN: Self = Self(SziPriv(i64::MIN));

    #[inline]
    pub const fn from_raw(raw: i64) -> Self {
        Self(SziPriv(raw))
    }

    #[inline]
    pub const fn raw(self) -> i64 {
        self.0 .0
    }

    #[inline]
    pub const fn sign(self) -> SzSign {
        if self.raw() > 0 { SzSign::Long } else if self.raw() < 0 { SzSign::Short } else { SzSign::Flat }
    }

    #[inline]
    pub fn abs(self) -> Sz {
        Sz::from_raw(self.raw().checked_abs().expect("called `Result::unwrap()` on an `Err` value") as u64)
    }

    pub fn add_recording_overflow(self, rhs: Self) -> Self {
        match self.raw().checked_add(rhs.raw()) {
            Some(raw) => Self::from_raw(raw),
            None => {
                record_qty_overflow();
                Self::from_raw(self.raw().saturating_add(rhs.raw()))
            }
        }
    }

    pub fn sub_recording_overflow(self, rhs: Self) -> Self {
        match self.raw().checked_sub(rhs.raw()) {
            Some(raw) => Self::from_raw(raw),
            None => {
                record_qty_overflow();
                Self::from_raw(self.raw().saturating_sub(rhs.raw()))
            }
        }
    }
}

impl Wei {
    pub const ZERO: Self = Self(WeiPriv(0));
    pub const ONE_QUOTE: Self = Self(WeiPriv(100_000_000));

    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self(WeiPriv(raw))
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0 .0
    }

    #[inline]
    pub const fn scale(decimals: u8) -> Option<u64> {
        if (decimals as usize) < POW10_U64.len() { Some(POW10_U64[decimals as usize]) } else { None }
    }

    #[inline]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.raw().checked_add(rhs.raw()).map(Self::from_raw)
    }

    #[inline]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.raw().checked_sub(rhs.raw()).map(Self::from_raw)
    }

    #[inline]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self::from_raw(self.raw().saturating_add(rhs.raw()))
    }

    #[inline]
    pub const fn saturating_sub(self, rhs: Self) -> Self {
        Self::from_raw(self.raw().saturating_sub(rhs.raw()))
    }

    pub fn parse_decimal(input: &str, decimals: u8) -> Result<Self, QtyParseError> {
        let scale = Self::scale(decimals).ok_or(QtyParseError::TooManyDecimals)?;
        let (whole, frac, frac_digits, _) = parse_unsigned_decimal_parts(input, decimals)?;
        let mut raw = whole.checked_mul(scale as u128).ok_or(QtyParseError::Overflow)?;
        let missing = decimals - frac_digits;
        raw = raw
            .checked_add(frac.checked_mul(Self::scale(missing).unwrap() as u128).ok_or(QtyParseError::Overflow)?)
            .ok_or(QtyParseError::Overflow)?;
        if raw > u64::MAX as u128 { Err(QtyParseError::Overflow) } else { Ok(Self::from_raw(raw as u64)) }
    }

    pub fn fmt_decimal(self, decimals: u8, f: &mut impl fmt::Write) -> fmt::Result {
        let scale = Self::scale(decimals).ok_or(fmt::Error)?;
        fmt_unsigned_scaled(self.raw() as u128, scale as u128, decimals, f)
    }
}

impl Ntl {
    pub const ZERO: Self = Self(NtlPriv(0));
    pub const MAX: Self = Self(NtlPriv(u64::MAX));

    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self(NtlPriv(raw))
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0 .0
    }

    #[inline]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.raw().checked_add(rhs.raw()).map(Self::from_raw)
    }

    #[inline]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.raw().checked_sub(rhs.raw()).map(Self::from_raw)
    }

    #[inline]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self::from_raw(self.raw().saturating_add(rhs.raw()))
    }

    #[inline]
    pub const fn saturating_sub(self, rhs: Self) -> Self {
        Self::from_raw(self.raw().saturating_sub(rhs.raw()))
    }
}

impl UsdcNtl {
    pub const ZERO: Self = Self(NtlPriv(0));
    pub const MAX: Self = Self(NtlPriv(u64::MAX));

    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self(NtlPriv(raw))
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0 .0
    }

    #[inline]
    pub fn to_ntli(self) -> Option<UsdcNtli> {
        self.raw().checked_mul(USDC_NTLI_PER_USDC_NTL as u64).and_then(|v| i64::try_from(v).ok()).map(UsdcNtli::from_raw)
    }
}

impl UsdcBigSpotNtl {
    pub const ZERO: Self = Self(BigNtlPriv(0));

    #[inline]
    pub const fn from_raw(raw: u128) -> Self {
        Self(BigNtlPriv(raw))
    }

    #[inline]
    pub const fn raw(self) -> u128 {
        self.0 .0
    }

    #[inline]
    pub fn try_to_usdc_ntl(self) -> Option<UsdcNtl> {
        if self.raw() <= u64::MAX as u128 { Some(UsdcNtl::from_raw(self.raw() as u64)) } else { None }
    }
}

impl Ntli {
    pub const ZERO: Self = Self(NtliPriv(0));

    #[inline]
    pub const fn from_raw(raw: i64) -> Self {
        Self(NtliPriv(raw))
    }

    #[inline]
    pub const fn raw(self) -> i64 {
        self.0 .0
    }
}

impl UsdcNtli {
    pub const ZERO: Self = Self(NtliPriv(0));

    #[inline]
    pub const fn from_raw(raw: i64) -> Self {
        Self(NtliPriv(raw))
    }

    #[inline]
    pub const fn raw(self) -> i64 {
        self.0 .0
    }

    #[inline]
    pub const fn to_usdc_ntl_trunc(self) -> i64 {
        self.raw() / USDC_NTLI_PER_USDC_NTL
    }

    #[inline]
    pub fn unsigned_abs_to_usdc_ntl_trunc(self) -> UsdcNtl {
        UsdcNtl::from_raw(self.raw().unsigned_abs() / USDC_NTLI_PER_USDC_NTL as u64)
    }
}

impl UsdcRoughNtli {
    #[inline]
    pub const fn from_raw(raw: i64) -> Self {
        Self(NtliPriv(raw))
    }

    #[inline]
    pub const fn raw(self) -> i64 {
        self.0 .0
    }

    #[inline]
    pub const fn to_usdc_ntl_trunc(self) -> i64 {
        self.raw() / USDC_NTLI_PER_USDC_NTL
    }
}

impl Decibps {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(DECIBPS_PER_ONE);

    #[inline]
    pub const fn from_raw(raw: i64) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> i64 {
        self.0
    }

    #[inline]
    pub fn apply_to_ntl(self, ntl: Ntl, rounding: RoundMode) -> Option<Ntl> {
        let product = (ntl.raw() as i128).checked_mul(self.raw() as i128)?;
        let raw = div_round_signed_nonnegative_output(product, DECIBPS_PER_ONE as i128, rounding)?;
        if raw < 0 || raw > u64::MAX as i128 { None } else { Some(Ntl::from_raw(raw as u64)) }
    }
}

impl FpDecimal {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(FP_SCALE);

    #[inline]
    pub const fn from_raw(raw: i64) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> i64 {
        self.0
    }

    #[inline]
    pub fn to_decimal_string(self) -> String {
        scaled_i64_8_to_decimal_string(self.raw())
    }
}

impl FromStr for FpDecimal {
    type Err = QtyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_decimal_string_to_scaled_i64_8(s).map(Self)
    }
}

impl FromStr for Px {
    type Err = QtyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_decimal_string(DecimalString(s.to_owned()))
    }
}

impl fmt::Display for Px {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_decimal_string())
    }
}

impl fmt::Display for UsdcPx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&scaled_i64_8_to_decimal_string(self.raw()))
    }
}

impl fmt::Display for Sz {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw().fmt(f)
    }
}

impl fmt::Display for Szi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw().fmt(f)
    }
}

impl fmt::Display for Wei {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw().fmt(f)
    }
}

impl fmt::Display for Ntl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw().fmt(f)
    }
}

impl fmt::Display for UsdcNtl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw().fmt(f)
    }
}

impl fmt::Display for Ntli {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw().fmt(f)
    }
}

impl fmt::Display for UsdcNtli {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw().fmt(f)
    }
}

impl fmt::Display for UsdcRoughNtli {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw().fmt(f)
    }
}

impl fmt::Display for FpDecimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_decimal_string())
    }
}

impl Add for Sz {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add_recording_overflow(rhs)
    }
}

impl AddAssign for Sz {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for Sz {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub_recording_underflow(rhs)
    }
}

impl SubAssign for Sz {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Add for Szi {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add_recording_overflow(rhs)
    }
}

impl Sub for Szi {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub_recording_overflow(rhs)
    }
}

impl Neg for Szi {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self::from_raw(self.raw().checked_neg().expect("called `Result::unwrap()` on an `Err` value"))
    }
}

impl Add for Wei {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.checked_add(rhs).expect("attempt to add with overflow")
    }
}

impl Sub for Wei {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.checked_sub(rhs).expect("attempt to subtract with overflow")
    }
}

impl Add for Ntl {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.saturating_add(rhs)
    }
}

impl Sub for Ntl {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.saturating_sub(rhs)
    }
}

impl Add for UsdcNtl {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self::from_raw(self.raw().saturating_add(rhs.raw()))
    }
}

impl Sub for UsdcNtl {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::from_raw(self.raw().saturating_sub(rhs.raw()))
    }
}

impl Serialize for FpDecimal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_decimal_string())
    }
}

impl<'de> Deserialize<'de> for FpDecimal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let DecimalString(value) = DecimalString::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

pub fn decimal_to_scaled_i64(decimal: Decimal, round_mode: RoundMode, decimals: u8) -> Result<i64, QtyParseError> {
    let scale = 10_i64.checked_pow(decimals as u32).ok_or(QtyParseError::TooManyDecimals)?;
    let scaled = decimal
        .checked_mul(Decimal::from(scale))
        .ok_or(QtyParseError::TooManyDecimals)?;
    let rounded = match round_mode {
        RoundMode::RejectFractional => {
            if scaled.fract() != Decimal::ZERO {
                return Err(QtyParseError::TooManyDecimals);
            }
            scaled
        }
        RoundMode::Round => scaled.round(),
        RoundMode::Truncate => scaled.trunc(),
    };
    if rounded.is_sign_negative() {
        return Err(QtyParseError::Negative);
    }
    let raw = rounded.to_i128().ok_or(QtyParseError::Overflow)?;
    if raw <= MAX_SCALED_I64 { Ok(raw as i64) } else { Err(QtyParseError::Overflow) }
}

pub fn parse_decimal_string_to_scaled_i64_8(input: &str) -> Result<i64, QtyParseError> {
    let decimal = Decimal::from_str(input).map_err(|_| QtyParseError::InvalidDecimal)?;
    let parsed_float = f64::from_str(input).map_err(|_| QtyParseError::InvalidDecimal)?;
    if !parsed_float.is_finite() {
        return Err(QtyParseError::InvalidDecimal);
    }
    let mut normalized = decimal;
    normalized.normalize_assign();
    if normalized.to_string() != parsed_float.to_string() {
        return Err(QtyParseError::InvalidDecimal);
    }
    decimal_to_scaled_i64(decimal, RoundMode::RejectFractional, FP_DECIMALS)
}

pub fn scaled_i64_8_to_decimal_string(raw: i64) -> String {
    let mut value = u64::try_from(raw).expect("called `Result::unwrap()` on an `Err` value");
    let mut scale = FP_DECIMALS as u32;
    while scale != 0 && value % 10 == 0 {
        value /= 10;
        scale -= 1;
    }
    Decimal::from_i128_with_scale(value as i128, scale).to_string()
}

pub fn replace_resting_order_sz_total(total: &mut Sz, old_sz: Sz, new_sz: Sz) {
    if old_sz != new_sz {
        *total = total.sub_recording_underflow(old_sz).add_recording_overflow(new_sz);
    }
}

pub fn apply_open_interest_transition(aggregate_abs_sz: &mut Szi, nonzero_count: &mut i64, old_sz: Szi, new_sz: Szi) {
    match (old_sz.raw() == 0, new_sz.raw() == 0) {
        (true, false) => *nonzero_count = nonzero_count.saturating_add(1),
        (false, true) if *nonzero_count != 0 => *nonzero_count -= 1,
        _ => {}
    }
    let without_old = aggregate_abs_sz.sub_recording_overflow(Szi::from_raw(old_sz.abs().raw() as i64));
    *aggregate_abs_sz = without_old.add_recording_overflow(Szi::from_raw(new_sz.abs().raw() as i64));
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WeiPair {
    pub checked: Wei,
    pub saturating: Wei,
}

pub fn debit_wei_pair(pair: &mut WeiPair, amount: Wei) -> Result<(), QtyArithmeticError> {
    pair.checked = pair.checked.checked_sub(amount).ok_or(QtyArithmeticError::Underflow)?;
    pair.saturating = match pair.saturating.checked_sub(amount) {
        Some(value) => value,
        None => {
            record_qty_underflow();
            Wei::ZERO
        }
    };
    Ok(())
}

pub fn add_usdc_ntli_to_two_totals(first: &mut i64, second: &mut i64, delta: UsdcNtli, second_delta: Option<UsdcNtli>) {
    *first = first.saturating_add(delta.to_usdc_ntl_trunc());
    *second = second.saturating_add(second_delta.unwrap_or(delta).to_usdc_ntl_trunc());
}

pub fn usdc_notional_from_px_sz(px: UsdcPx, sz: Sz, scale: i64, rounding: RoundMode) -> Option<UsdcNtl> {
    if px.raw() < 0 || scale <= 0 {
        return None;
    }
    let product = (px.raw() as i128).checked_mul(sz.raw() as i128)?;
    let raw = div_round_nonnegative(product, scale as i128, rounding)?;
    if raw < 0 || raw > u64::MAX as i128 { None } else { Some(UsdcNtl::from_raw(raw as u64)) }
}

pub fn big_spot_notional_from_px_sz(px: UsdcPx, sz: Sz, scale: u128, rounding: RoundMode) -> Option<UsdcBigSpotNtl> {
    if px.raw() < 0 || scale == 0 {
        return None;
    }
    let product = (px.raw() as u128).checked_mul(sz.raw() as u128)?;
    let raw = div_round_u128(product, scale, rounding)?;
    Some(UsdcBigSpotNtl::from_raw(raw))
}

fn parse_unsigned_decimal_parts(input: &str, decimals: u8) -> Result<(u128, u128, u8, bool), QtyParseError> {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return Err(QtyParseError::Empty);
    }
    if bytes[0] == b'-' {
        return Err(QtyParseError::Negative);
    }
    if bytes[0] == b'+' {
        return Err(QtyParseError::InvalidByte);
    }

    let mut whole = 0u128;
    let mut frac = 0u128;
    let mut frac_digits = 0u8;
    let mut seen_dot = false;
    let mut seen_digit = false;
    let mut seen_nonzero = false;

    for &byte in bytes {
        if byte == b'.' {
            if seen_dot {
                return Err(QtyParseError::InvalidByte);
            }
            seen_dot = true;
            continue;
        }
        if !byte.is_ascii_digit() {
            return Err(QtyParseError::InvalidByte);
        }
        seen_digit = true;
        let digit = (byte - b'0') as u128;
        if digit != 0 {
            seen_nonzero = true;
        }
        if seen_dot {
            if frac_digits == decimals {
                if digit == 0 {
                    continue;
                }
                return Err(QtyParseError::TooManyDecimals);
            }
            frac = frac.checked_mul(10).and_then(|v| v.checked_add(digit)).ok_or(QtyParseError::Overflow)?;
            frac_digits += 1;
        } else {
            whole = whole.checked_mul(10).and_then(|v| v.checked_add(digit)).ok_or(QtyParseError::Overflow)?;
        }
    }

    if !seen_digit { Err(QtyParseError::Empty) } else { Ok((whole, frac, frac_digits, seen_nonzero)) }
}

fn fmt_signed_scaled(raw: i64, scale: u128, decimals: u8, f: &mut impl fmt::Write) -> fmt::Result {
    if raw < 0 {
        f.write_char('-')?;
    }
    fmt_unsigned_scaled(raw.unsigned_abs() as u128, scale, decimals, f)
}

fn fmt_unsigned_scaled(raw: u128, scale: u128, decimals: u8, f: &mut impl fmt::Write) -> fmt::Result {
    let whole = raw / scale;
    let frac = raw % scale;
    write!(f, "{whole}")?;
    if decimals == 0 || frac == 0 {
        return Ok(());
    }
    f.write_char('.')?;
    let mut divisor = scale / 10;
    let mut remaining = frac;
    let mut digits_left = decimals;
    while digits_left != 0 {
        let digit = remaining / divisor;
        remaining %= divisor;
        divisor /= 10;
        f.write_char((b'0' + digit as u8) as char)?;
        digits_left -= 1;
        if remaining == 0 {
            break;
        }
    }
    Ok(())
}

fn div_round_nonnegative(numerator: i128, denominator: i128, rounding: RoundMode) -> Option<i128> {
    if numerator < 0 || denominator <= 0 {
        return None;
    }
    let q = numerator / denominator;
    let r = numerator % denominator;
    match rounding {
        RoundMode::RejectFractional => if r == 0 { Some(q) } else { None },
        RoundMode::Truncate => Some(q),
        RoundMode::Round => if r.checked_mul(2)? >= denominator { q.checked_add(1) } else { Some(q) },
    }
}

fn div_round_signed_nonnegative_output(numerator: i128, denominator: i128, rounding: RoundMode) -> Option<i128> {
    if denominator <= 0 {
        return None;
    }
    if numerator >= 0 {
        div_round_nonnegative(numerator, denominator, rounding)
    } else {
        let value = div_round_nonnegative(numerator.checked_neg()?, denominator, rounding)?;
        value.checked_neg()
    }
}

fn div_round_u128(numerator: u128, denominator: u128, rounding: RoundMode) -> Option<u128> {
    if denominator == 0 {
        return None;
    }
    let q = numerator / denominator;
    let r = numerator % denominator;
    match rounding {
        RoundMode::RejectFractional => if r == 0 { Some(q) } else { None },
        RoundMode::Truncate => Some(q),
        RoundMode::Round => if r.checked_mul(2)? >= denominator { q.checked_add(1) } else { Some(q) },
    }
}

fn visible_bucket_step(sz: u64) -> u64 {
    if sz < 100_000 {
        1
    } else if sz < 1_000_000 {
        10
    } else if sz < 10_000_000 {
        100
    } else if sz < 100_000_000 {
        1_000
    } else if sz < 1_000_000_000 {
        10_000
    } else if sz < 10_000_000_000 {
        100_000
    } else if sz < 1_000_000_000_000 {
        1_000_000
    } else if sz < 10_000_000_000_000 {
        10_000_000
    } else if sz < 100_000_000_000_000 {
        100_000_000
    } else if sz <= 0x5af3_107a_3fff {
        1_000_000_000
    } else if sz <= 0x38d7_ea4c_67fff {
        0x2540_be400
    } else if sz < 0x2386_f26f_c10000 {
        0x1748_76e800
    } else if sz < 0x1634_5785_d8a0000 {
        0x0e8d_4a51000
    } else if sz < 0x0de0_b6b3_a7640000 {
        0x0918_4e72_a000
    } else if sz < 0x8ac7_2304_89e80000 {
        0x05af_3107_a4000
    } else {
        1_000_000_000
    }
}

#[cold]
fn record_qty_underflow() {
    tracing::warn!("quantity arithmetic underflow");
}

#[cold]
fn record_qty_overflow() {
    tracing::warn!("quantity arithmetic overflow");
}
