use core::fmt;
use core::ops::{Add, AddAssign, Div, Mul, Sub, SubAssign};

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Raw notional values are stored in micro-USD.
///
/// Frontend/risk renderers in the binary convert these counters with `/ 1_000_000.0`.
/// The separate `10_000` divisor seen in volume/account updates is an aggregate bucket
/// scale, not the decimal scale of the `Ntl` newtype.
pub const NTL_SCALE: u64 = 1_000_000;
pub const NTL_SCALE_F64: f64 = 1_000_000.0;
pub const ACCOUNT_VOLUME_DIVISOR: i64 = 10_000;

pub const MAX_WIRE_NTL_RAW: u64 = 0x0ccc_cccc_cccc_cccc;
pub const MAX_SAFE_TIMES_100_RAW: u64 = 0x028f_5c28_f5c2_8f5c;
pub const MAX_SAFE_TIMES_10_000_RAW: u64 = 0x0068_db8b_ac71_0cb;
pub const CONVERTED_NTL_CAP_RAW: u64 = 0x0147_ae14_7ae1_47ae;
pub const ASSET_CONVERSION_CAP_RAW: u64 = 0x0023_86f2_6fc1_0000;

pub const NTL_CAP_BUMP_RAW: u64 = 50_000_000_000;
pub const NORMAL_ASSET_NTL_CAP_RAW: u64 = 5_000_000_000_000;
pub const MODE3_ASSET_NTL_CAP_RAW: u64 = 1_000_000_000_000;

pub const MAX_MARGIN_TIER_COUNT: usize = 3;
pub const MAX_MARGIN_LEVERAGE: u8 = 50;
pub const MAX_MARGIN_LOWER_BOUND_RAW: u64 = 1_000_000_000_000_000;

#[repr(transparent)]
#[derive(Copy, Clone, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Ntl(pub u64);

#[repr(transparent)]
#[derive(Copy, Clone, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NtlPriv(pub u64);

#[repr(transparent)]
#[derive(Copy, Clone, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct BigNtlPriv(pub u64);

/// Signed notional delta used by isolated-margin and volume update paths.
#[repr(transparent)]
#[derive(Copy, Clone, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NtliPriv(pub i64);

/// Minimal peer quantity shapes used by the recovered conversion methods.
#[repr(transparent)]
#[derive(Copy, Clone, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Px(pub u64);

#[repr(transparent)]
#[derive(Copy, Clone, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Sz(pub i64);

#[repr(transparent)]
#[derive(Copy, Clone, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Wei(pub u64);

impl Ntl {
    pub const ZERO: Self = Self(0);
    pub const ONE_USD: Self = Self(NTL_SCALE);
    pub const MAX_WIRE: Self = Self(MAX_WIRE_NTL_RAW);
    pub const CONVERTED_CAP: Self = Self(CONVERTED_NTL_CAP_RAW);

    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn from_whole_usd(usd: u64) -> Option<Self> {
        match usd.checked_mul(NTL_SCALE) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    #[inline]
    pub fn from_f64_lossy(usd: f64) -> Option<Self> {
        if !usd.is_finite() || usd < 0.0 {
            return None;
        }
        let raw = usd * NTL_SCALE_F64;
        if raw > u64::MAX as f64 {
            None
        } else {
            Some(Self(raw.trunc() as u64))
        }
    }

    #[inline]
    pub fn to_f64(self) -> f64 {
        self.0 as f64 / NTL_SCALE_F64
    }

    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.0.checked_add(rhs.0) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    #[inline]
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    #[inline]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    #[inline]
    pub const fn saturating_sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }

    #[inline]
    pub const fn min(self, rhs: Self) -> Self {
        if self.0 <= rhs.0 { self } else { rhs }
    }

    #[inline]
    pub const fn max(self, rhs: Self) -> Self {
        if self.0 >= rhs.0 { self } else { rhs }
    }

    #[inline]
    pub const fn clamp(self, max: Self) -> Self {
        if self.0 > max.0 { max } else { self }
    }

    /// Round up to the next whole micro-USD multiple.
    #[inline]
    pub const fn ceil_to_multiple(self, multiple: u64) -> Option<Self> {
        if multiple == 0 {
            return None;
        }
        let rem = self.0 % multiple;
        if rem == 0 {
            Some(self)
        } else {
            match self.0.checked_add(multiple - rem) {
                Some(raw) => Some(Self(raw)),
                None => None,
            }
        }
    }

    #[inline]
    pub const fn floor_to_multiple(self, multiple: u64) -> Option<Self> {
        if multiple == 0 {
            None
        } else {
            Some(Self(self.0 - self.0 % multiple))
        }
    }

    /// Multiply by a basis-point-like numerator and divide by denominator, flooring.
    #[inline]
    pub fn mul_ratio_floor(self, numerator: u64, denominator: u64) -> Option<Self> {
        if denominator == 0 {
            return None;
        }
        let raw = (self.0 as u128).checked_mul(numerator as u128)? / denominator as u128;
        if raw > u64::MAX as u128 { None } else { Some(Self(raw as u64)) }
    }

    #[inline]
    pub fn mul_ratio_ceil(self, numerator: u64, denominator: u64) -> Option<Self> {
        if denominator == 0 {
            return None;
        }
        let product = (self.0 as u128).checked_mul(numerator as u128)?;
        let denominator = denominator as u128;
        let raw = product.checked_add(denominator - 1)? / denominator;
        if raw > u64::MAX as u128 { None } else { Some(Self(raw as u64)) }
    }

    /// Spot/perp conversion recovered from frontend and risk callers:
    /// `raw_ntl = raw_amount_or_lots * raw_price / asset_scale`.
    #[inline]
    pub fn from_px_sz_floor(px: Px, sz: Sz, asset_scale: u64) -> Option<Self> {
        if asset_scale == 0 {
            return None;
        }
        let abs_sz = sz.0.unsigned_abs() as u128;
        let raw = abs_sz.checked_mul(px.0 as u128)? / asset_scale as u128;
        if raw > u64::MAX as u128 { None } else { Some(Self(raw as u64)) }
    }

    #[inline]
    pub fn from_px_wei_floor(px: Px, wei: Wei, wei_scale: u64) -> Option<Self> {
        if wei_scale == 0 {
            return None;
        }
        let raw = (wei.0 as u128).checked_mul(px.0 as u128)? / wei_scale as u128;
        if raw > u64::MAX as u128 { None } else { Some(Self(raw as u64)) }
    }

    #[inline]
    pub fn to_size_lots_floor(self, px: Px, asset_scale: u64) -> Option<Sz> {
        if px.0 == 0 {
            return None;
        }
        let lots = (self.0 as u128).checked_mul(asset_scale as u128)? / px.0 as u128;
        if lots > i64::MAX as u128 { None } else { Some(Sz(lots as i64)) }
    }

    #[inline]
    pub const fn apply_asset_cap_bump(current: Self, mode: AssetCapMode) -> Self {
        let bumped = current.0.saturating_add(NTL_CAP_BUMP_RAW);
        let max = match mode {
            AssetCapMode::Mode3 => MODE3_ASSET_NTL_CAP_RAW,
            AssetCapMode::Normal => NORMAL_ASSET_NTL_CAP_RAW,
        };
        if bumped > max { Self(max) } else { Self(bumped) }
    }

    #[inline]
    pub fn parse_decimal(s: &str) -> Result<Self, ParseNtlError> {
        parse_micro_decimal(s).map(Self)
    }
}

impl NtlPriv {
    #[inline]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn into_public(self) -> Ntl {
        Ntl(self.0)
    }
}

impl BigNtlPriv {
    #[inline]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }
}

impl NtliPriv {
    #[inline]
    pub const fn raw(self) -> i64 {
        self.0
    }

    /// Account volume fields at offsets +16/+24 receive signed notional deltas divided
    /// by 10_000, using Rust signed division truncation toward zero.
    #[inline]
    pub const fn to_account_volume_delta(self) -> i64 {
        self.0 / ACCOUNT_VOLUME_DIVISOR
    }

    #[inline]
    pub const fn saturating_add_to(self, accumulator: i64) -> i64 {
        accumulator.saturating_add(self.to_account_volume_delta())
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssetCapMode {
    Normal,
    Mode3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawMarginTier {
    pub lower_bound: Ntl,
    pub max_leverage: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarginTier {
    pub lower_bound: Ntl,
    pub max_leverage: u8,
    /// Precomputed `sum(prev.lower / prev_lev - prev.lower / this_lev)` used by the
    /// two margin formulas recovered from the table builder.
    pub prior_contribution: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarginTable {
    tiers: Vec<MarginTier>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MarginTableError {
    EmptyTiers,
    TooManyTiers { len: usize },
    LowerBoundTooLarge { raw: u64 },
    LowerBoundDoesNotStartAtZero,
    LowerBoundNotIncreasing,
    MaxLeverageTooLarge { leverage: u8 },
    MaxLeverageNotDecreasing,
}

impl MarginTable {
    pub fn try_from_raw(raw: Vec<RawMarginTier>) -> Result<Self, MarginTableError> {
        if raw.is_empty() {
            return Err(MarginTableError::EmptyTiers);
        }
        if raw.len() > MAX_MARGIN_TIER_COUNT {
            return Err(MarginTableError::TooManyTiers { len: raw.len() });
        }

        let first = &raw[0];
        validate_margin_tier(first)?;
        if first.lower_bound.0 != 0 {
            return Err(MarginTableError::LowerBoundDoesNotStartAtZero);
        }

        let mut tiers = Vec::with_capacity(raw.len());
        let mut previous_lower = first.lower_bound.0;
        let mut previous_leverage = first.max_leverage;
        let mut contribution = 0u64;

        tiers.push(MarginTier {
            lower_bound: first.lower_bound,
            max_leverage: first.max_leverage,
            prior_contribution: 0,
        });

        for tier in raw.iter().skip(1) {
            validate_margin_tier(tier)?;
            if tier.lower_bound.0 <= previous_lower {
                return Err(MarginTableError::LowerBoundNotIncreasing);
            }
            if tier.max_leverage >= previous_leverage {
                return Err(MarginTableError::MaxLeverageNotDecreasing);
            }

            // The binary inserts a precomputed tier term using the same integer divisions
            // later consumed by the margin lookup helpers.
            let at_previous = previous_lower / (2 * previous_leverage as u64);
            let at_current = previous_lower / (2 * tier.max_leverage as u64);
            contribution = contribution.saturating_add(at_current.saturating_sub(at_previous));

            tiers.push(MarginTier {
                lower_bound: tier.lower_bound,
                max_leverage: tier.max_leverage,
                prior_contribution: contribution,
            });

            previous_lower = tier.lower_bound.0;
            previous_leverage = tier.max_leverage;
        }

        Ok(Self { tiers })
    }

    #[inline]
    pub fn tiers(&self) -> &[MarginTier] {
        &self.tiers
    }

    pub fn tier_for(&self, ntl: Ntl) -> &MarginTier {
        let mut selected = &self.tiers[0];
        for tier in &self.tiers[1..] {
            if ntl.0 < tier.lower_bound.0 {
                break;
            }
            selected = tier;
        }
        selected
    }

    /// Formula recovered at the first margin helper:
    /// `(2 * ntl - 4 * leverage * prior_contribution).saturating_sub(0) / (6 * leverage)`.
    pub fn margin_after_tier_offset_div_6x_leverage(&self, ntl: Ntl) -> u64 {
        let tier = self.tier_for(ntl);
        let leverage = tier.max_leverage as u64;
        let lhs = ntl.0.saturating_mul(2);
        let rhs = tier.prior_contribution.saturating_mul(4 * leverage);
        let numerator = lhs.saturating_sub(rhs);
        numerator / (6 * leverage)
    }

    /// Formula recovered at the second margin helper:
    /// `ntl / (2 * leverage) - prior_contribution`, saturating at zero on underflow.
    pub fn ntl_div_2x_leverage_minus_prior_contribution(&self, ntl: Ntl) -> u64 {
        let tier = self.tier_for(ntl);
        let leverage = tier.max_leverage as u64;
        (ntl.0 / (2 * leverage)).saturating_sub(tier.prior_contribution)
    }
}

fn validate_margin_tier(tier: &RawMarginTier) -> Result<(), MarginTableError> {
    if tier.lower_bound.0 >= MAX_WIRE_NTL_RAW {
        return Err(MarginTableError::LowerBoundTooLarge { raw: tier.lower_bound.0 });
    }
    if tier.lower_bound.0 > MAX_MARGIN_LOWER_BOUND_RAW {
        return Err(MarginTableError::LowerBoundTooLarge { raw: tier.lower_bound.0 });
    }
    if tier.max_leverage > MAX_MARGIN_LEVERAGE {
        return Err(MarginTableError::MaxLeverageTooLarge { leverage: tier.max_leverage });
    }
    Ok(())
}

impl Add for Ntl {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign for Ntl {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl Sub for Ntl {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl SubAssign for Ntl {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl Mul<u64> for Ntl {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: u64) -> Self::Output {
        Self(self.0 * rhs)
    }
}

impl Div<u64> for Ntl {
    type Output = Self;

    #[inline]
    fn div(self, rhs: u64) -> Self::Output {
        Self(self.0 / rhs)
    }
}

impl fmt::Debug for Ntl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ntl").field(&self.0).finish()
    }
}

impl fmt::Display for Ntl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_micro_decimal(self.0, f)
    }
}

impl fmt::Debug for NtlPriv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NtlPriv").field(&self.0).finish()
    }
}

impl fmt::Debug for BigNtlPriv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BigNtlPriv").field(&self.0).finish()
    }
}

impl fmt::Debug for NtliPriv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NtliPriv").field(&self.0).finish()
    }
}

impl Serialize for Ntl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("Ntl", &self.0)
    }
}

impl<'de> Deserialize<'de> for Ntl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_newtype_struct("Ntl", NtlVisitor)
    }
}

struct NtlVisitor;

impl<'de> Visitor<'de> for NtlVisitor {
    type Value = Ntl;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("tuple struct Ntl")
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Ntl(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value < 0 {
            Err(E::invalid_value(de::Unexpected::Signed(value), &"u64 for Ntl"))
        } else {
            Ok(Ntl(value as u64))
        }
    }
}

macro_rules! impl_raw_u64_serde {
    ($type:ident, $expecting:literal) => {
        impl Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_u64(self.0)
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct RawVisitor;

                impl<'de> Visitor<'de> for RawVisitor {
                    type Value = $type;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str($expecting)
                    }

                    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                        Ok($type(value))
                    }

                    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        if value < 0 {
                            Err(E::invalid_value(de::Unexpected::Signed(value), &$expecting))
                        } else {
                            Ok($type(value as u64))
                        }
                    }
                }

                deserializer.deserialize_u64(RawVisitor)
            }
        }
    };
}

impl_raw_u64_serde!(NtlPriv, "u64 for NtlPriv");
impl_raw_u64_serde!(BigNtlPriv, "u64 for BigNtlPriv");

impl Serialize for NtliPriv {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(self.0)
    }
}

impl<'de> Deserialize<'de> for NtliPriv {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NtliVisitor;

        impl<'de> Visitor<'de> for NtliVisitor {
            type Value = NtliPriv;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("i64 for NtliPriv")
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(NtliPriv(value))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value > i64::MAX as u64 {
                    Err(E::invalid_value(de::Unexpected::Unsigned(value), &"i64 for NtliPriv"))
                } else {
                    Ok(NtliPriv(value as i64))
                }
            }
        }

        deserializer.deserialize_i64(NtliVisitor)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ParseNtlError {
    Empty,
    InvalidByte,
    TooManyFractionalDigits,
    Overflow,
}

fn parse_micro_decimal(s: &str) -> Result<u64, ParseNtlError> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Err(ParseNtlError::Empty);
    }

    let mut whole = 0u64;
    let mut frac = 0u64;
    let mut frac_digits = 0u32;
    let mut seen_dot = false;
    let mut seen_digit = false;

    for &byte in bytes {
        match byte {
            b'0'..=b'9' => {
                seen_digit = true;
                let digit = (byte - b'0') as u64;
                if seen_dot {
                    if frac_digits == 6 {
                        return Err(ParseNtlError::TooManyFractionalDigits);
                    }
                    frac = frac.checked_mul(10).ok_or(ParseNtlError::Overflow)?;
                    frac = frac.checked_add(digit).ok_or(ParseNtlError::Overflow)?;
                    frac_digits += 1;
                } else {
                    whole = whole.checked_mul(10).ok_or(ParseNtlError::Overflow)?;
                    whole = whole.checked_add(digit).ok_or(ParseNtlError::Overflow)?;
                }
            }
            b'.' if !seen_dot => seen_dot = true,
            _ => return Err(ParseNtlError::InvalidByte),
        }
    }

    if !seen_digit {
        return Err(ParseNtlError::Empty);
    }

    while frac_digits < 6 {
        frac *= 10;
        frac_digits += 1;
    }

    whole
        .checked_mul(NTL_SCALE)
        .and_then(|scaled| scaled.checked_add(frac))
        .ok_or(ParseNtlError::Overflow)
}

fn fmt_micro_decimal(raw: u64, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let whole = raw / NTL_SCALE;
    let mut frac = raw % NTL_SCALE;
    if frac == 0 {
        return write!(f, "{whole}");
    }

    let mut width = 6usize;
    while frac % 10 == 0 {
        frac /= 10;
        width -= 1;
    }
    write!(f, "{whole}.{frac:0width$}")
}
