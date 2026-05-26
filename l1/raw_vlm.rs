#![allow(dead_code)]

use core::fmt;
use core::ops::{Add, AddAssign, Sub, SubAssign};
use core::str::FromStr;

/// Raw, unweighted trading volume accumulator.
///
/// Binary evidence for this type is a transparent `u64` newtype: every recovered
/// accumulation site loads the raw component from the second qword of a
/// `(scaled, raw)` pair and carries it in the x86-64 `rdx` return register.  The
/// optimized code checks every raw-volume addition for carry and falls back to
/// `u64::MAX` after the overflow hook runs.
#[repr(transparent)]
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RawVlm(u64);

/// Companion scaled-volume word observed next to `RawVlm` in state records.
///
/// The owning source for this newtype is `scaled_vlm`; this local definition is
/// intentionally tiny because raw-volume helpers manipulate the pair directly.
#[repr(transparent)]
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ScaledVlm(u64);

/// State-map value shape used by the recovered per-user volume lookups.
///
/// Hash-map hits contribute `scaled` from value offset `+0x40` and `raw` from
/// value offset `+0x48`; helper returns carry the two words as `(rax, rdx)`.
#[repr(C)]
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct ScaledAndRawVlm {
    pub scaled: ScaledVlm,
    pub raw: RawVlm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawVlmParseError {
    Empty,
    Sign,
    InvalidByte(u8),
    Overflow,
}

impl RawVlm {
    pub const ZERO: Self = Self(0);
    pub const MAX: Self = Self(u64::MAX);

    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.0.checked_add(rhs.0) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    #[inline]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    #[inline]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    #[inline]
    pub const fn saturating_sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }

    #[inline]
    pub fn checked_mul_u64(self, rhs: u64) -> Option<Self> {
        self.0.checked_mul(rhs).map(Self)
    }

    #[inline]
    pub fn checked_div_u64(self, rhs: u64) -> Option<Self> {
        if rhs == 0 {
            None
        } else {
            Some(Self(self.0 / rhs))
        }
    }

    /// Parse the wire/API form observed through serde as a decimal string.
    ///
    /// No allocation is needed: the binary expected a string visitor, then
    /// accumulated base-10 digits into the raw `u64` word.  Signs, whitespace,
    /// decimal points, and separators are rejected.
    pub fn parse_bytes(bytes: &[u8]) -> Result<Self, RawVlmParseError> {
        if bytes.is_empty() {
            return Err(RawVlmParseError::Empty);
        }

        let mut raw = 0_u64;
        for &byte in bytes {
            match byte {
                b'0'..=b'9' => {
                    let digit = u64::from(byte - b'0');
                    raw = raw
                        .checked_mul(10)
                        .and_then(|value| value.checked_add(digit))
                        .ok_or(RawVlmParseError::Overflow)?;
                }
                b'+' | b'-' => return Err(RawVlmParseError::Sign),
                _ => return Err(RawVlmParseError::InvalidByte(byte)),
            }
        }

        Ok(Self(raw))
    }

    #[inline]
    pub fn parse_str(value: &str) -> Result<Self, RawVlmParseError> {
        Self::parse_bytes(value.as_bytes())
    }

    /// Write the raw integer form to an existing formatter/writer.
    #[inline]
    pub fn fmt_raw(self, f: &mut impl fmt::Write) -> fmt::Result {
        write!(f, "{}", self.0)
    }

    /// Convert to an `f64` using a caller-supplied fixed-point scale.
    ///
    /// Perp and spot call sites use different product scales before feeding raw
    /// volume accounting, so the scale is intentionally explicit here.
    #[inline]
    pub fn to_f64_with_scale(self, scale: u64) -> Option<f64> {
        if scale == 0 {
            None
        } else {
            Some((self.0 as f64) / (scale as f64))
        }
    }

    #[inline]
    pub fn from_u128_checked(raw: u128) -> Option<Self> {
        if raw > u64::MAX as u128 {
            None
        } else {
            Some(Self(raw as u64))
        }
    }
}

impl ScaledVlm {
    pub const ZERO: Self = Self(0);
    pub const MAX: Self = Self(u64::MAX);

    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl ScaledAndRawVlm {
    pub const ZERO: Self = Self {
        scaled: ScaledVlm::ZERO,
        raw: RawVlm::ZERO,
    };

    #[inline]
    pub const fn new(scaled: ScaledVlm, raw: RawVlm) -> Self {
        Self { scaled, raw }
    }

    #[inline]
    pub const fn raw(self) -> RawVlm {
        self.raw
    }

    #[inline]
    pub const fn scaled(self) -> ScaledVlm {
        self.scaled
    }

    #[inline]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        Some(Self {
            scaled: ScaledVlm(self.scaled.0.checked_add(rhs.scaled.0)?),
            raw: self.raw.checked_add(rhs.raw)?,
        })
    }

    #[inline]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self {
            scaled: self.scaled.saturating_add(rhs.scaled),
            raw: self.raw.saturating_add(rhs.raw),
        }
    }

    #[inline]
    pub fn add_record(&mut self, record: Self) {
        *self = self.saturating_add(record);
    }
}

impl Add for RawVlm {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        self.saturating_add(rhs)
    }
}

impl AddAssign for RawVlm {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = self.saturating_add(rhs);
    }
}

impl Sub for RawVlm {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        self.saturating_sub(rhs)
    }
}

impl SubAssign for RawVlm {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.saturating_sub(rhs);
    }
}

impl From<u64> for RawVlm {
    #[inline]
    fn from(raw: u64) -> Self {
        Self(raw)
    }
}

impl From<RawVlm> for u64 {
    #[inline]
    fn from(value: RawVlm) -> Self {
        value.0
    }
}

impl FromStr for RawVlm {
    type Err = RawVlmParseError;

    #[inline]
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse_str(value)
    }
}

impl fmt::Debug for RawVlm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RawVlm").field(&self.0).finish()
    }
}

impl fmt::Display for RawVlm {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for ScaledVlm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ScaledVlm").field(&self.0).finish()
    }
}

#[cfg(feature = "serde")]
mod serde_impl {
    use super::{RawVlm, RawVlmParseError};
    use core::fmt;
    use serde::de::{self, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl Serialize for RawVlm {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                serializer.collect_str(self)
            } else {
                serializer.serialize_newtype_struct("RawVlm", &self.raw())
            }
        }
    }

    impl<'de> Deserialize<'de> for RawVlm {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                deserializer.deserialize_str(RawVlmVisitor)
            } else {
                deserializer.deserialize_newtype_struct("RawVlm", RawVlmVisitor)
            }
        }
    }

    struct RawVlmVisitor;

    impl<'de> Visitor<'de> for RawVlmVisitor {
        type Value = RawVlm;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("tuple struct RawVlm or a decimal raw-volume string")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(RawVlm::from_raw(value))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            RawVlm::parse_str(value).map_err(raw_vlm_parse_error)
        }

        fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.visit_str(value)
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.visit_str(&value)
        }

        fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_any(self)
        }
    }

    fn raw_vlm_parse_error<E>(error: RawVlmParseError) -> E
    where
        E: de::Error,
    {
        match error {
            RawVlmParseError::Empty => E::custom("empty raw volume"),
            RawVlmParseError::Sign => E::custom("raw volume cannot be signed"),
            RawVlmParseError::InvalidByte(byte) => E::custom(format_args!("invalid raw volume byte 0x{byte:02x}")),
            RawVlmParseError::Overflow => E::custom("raw volume overflows u64"),
        }
    }
}
