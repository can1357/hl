use core::fmt;
use core::ops::{Add, AddAssign, Sub, SubAssign};

/// Raw atom count for token quantities.
///
/// The recovered serde visitor accepts `u64` and rejects signed integers with the
/// diagnostic "invalid value {n} for WeiPriv when visiting i64".  Token display
/// precision is metadata-driven by `weiDecimals`; there is no single global
/// decimal exponent for every token.
#[repr(transparent)]
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WeiPriv(u64);

/// Public tuple wrapper for Wei amounts.
///
/// Serde names the outer wrapper as `Wei` and the inner raw visitor as
/// `WeiPriv`.  Arithmetic is unsigned: checked subtraction panics/returns an
/// error at account-total boundaries, while several availability paths saturate
/// the free bucket to zero after logging.
#[repr(transparent)]
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Wei(pub WeiPriv);

/// Wider amount used while constructing a newly listed token's genesis supply.
/// The blacklist/genesis paths carry user allocations wider than account Wei;
/// conversion to `Wei` is explicit and fails if the final atom count exceeds
/// `u64::MAX`.
#[repr(transparent)]
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GenesisWei(pub u128);

pub const QUOTE_WEI_DECIMALS: u8 = 8;
pub const QUOTE_WEI_SCALE: u64 = 100_000_000;
pub const PX_SZ_NOTIONAL_SCALE: u128 = 100_000_000_000_000;
pub const WEI_FACTOR_SCALE: f64 = 100_000_000.0;
pub const MAX_FACTOR: f64 = 1.01;
pub const BUFFER_FACTOR: f64 = 1.001;
pub const ADD_BUFFER_WEI: u64 = 1_000_000;
pub const MAX_AVAILABILITY_CAP_WEI: u64 = 1_000_000_000_000_000;

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

const POW10_U128: [u128; 39] = [
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
    100_000_000_000_000_000_000,
    1_000_000_000_000_000_000_000,
    10_000_000_000_000_000_000_000,
    100_000_000_000_000_000_000_000,
    1_000_000_000_000_000_000_000_000,
    10_000_000_000_000_000_000_000_000,
    100_000_000_000_000_000_000_000_000,
    1_000_000_000_000_000_000_000_000_000,
    10_000_000_000_000_000_000_000_000_000,
    100_000_000_000_000_000_000_000_000_000,
    1_000_000_000_000_000_000_000_000_000_000,
    10_000_000_000_000_000_000_000_000_000_000,
    100_000_000_000_000_000_000_000_000_000_000,
    1_000_000_000_000_000_000_000_000_000_000_000,
    10_000_000_000_000_000_000_000_000_000_000_000,
    100_000_000_000_000_000_000_000_000_000_000_000,
    1_000_000_000_000_000_000_000_000_000_000_000_000,
    10_000_000_000_000_000_000_000_000_000_000_000_000,
    100_000_000_000_000_000_000_000_000_000_000_000_000,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WeiParseError {
    Empty,
    Negative,
    InvalidByte,
    TooManyDecimals,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WeiArithmeticError {
    Underflow,
    Overflow,
    InvalidDecimals,
    InvalidFactor,
    EmptyDistribution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rounding {
    Down,
    Up,
    Nearest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WeiBalance {
    pub total: Wei,
    pub available: Wei,
    pub notional: u64,
}

impl WeiPriv {
    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl Wei {
    pub const ZERO: Self = Self(WeiPriv(0));
    pub const ONE_QUOTE: Self = Self(WeiPriv(QUOTE_WEI_SCALE));

    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self(WeiPriv(raw))
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0.raw()
    }

    #[inline]
    pub const fn is_zero(self) -> bool {
        self.raw() == 0
    }

    #[inline]
    pub const fn scale(decimals: u8) -> Option<u64> {
        if (decimals as usize) < POW10_U64.len() {
            Some(POW10_U64[decimals as usize])
        } else {
            None
        }
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

    /// Parse an integer string that is already denominated in Wei atoms.
    pub fn parse_raw_str(input: &str) -> Result<Self, WeiParseError> {
        let mut raw = 0u64;
        let mut saw_digit = false;
        let bytes = input.as_bytes();
        if bytes.is_empty() {
            return Err(WeiParseError::Empty);
        }
        if bytes[0] == b'-' {
            return Err(WeiParseError::Negative);
        }
        if bytes[0] == b'+' {
            return Err(WeiParseError::InvalidByte);
        }

        let mut i = 0;
        while i < bytes.len() {
            let byte = bytes[i];
            if byte < b'0' || byte > b'9' {
                return Err(WeiParseError::InvalidByte);
            }
            saw_digit = true;
            let digit = (byte - b'0') as u64;
            raw = raw
                .checked_mul(10)
                .and_then(|value| value.checked_add(digit))
                .ok_or(WeiParseError::Overflow)?;
            i += 1;
        }

        if saw_digit {
            Ok(Self::from_raw(raw))
        } else {
            Err(WeiParseError::Empty)
        }
    }

    /// Parse a token-denominated decimal amount using the token's `weiDecimals`.
    /// Extra trailing fractional zeros are accepted because they do not change
    /// the integer atom count; any non-zero excess precision is rejected.
    pub fn parse_decimal(input: &str, decimals: u8) -> Result<Self, WeiParseError> {
        let scale = Self::scale(decimals).ok_or(WeiParseError::TooManyDecimals)?;
        let bytes = input.as_bytes();
        if bytes.is_empty() {
            return Err(WeiParseError::Empty);
        }
        if bytes[0] == b'-' {
            return Err(WeiParseError::Negative);
        }
        if bytes[0] == b'+' {
            return Err(WeiParseError::InvalidByte);
        }

        let mut whole = 0u64;
        let mut frac = 0u64;
        let mut frac_digits = 0u8;
        let mut seen_dot = false;
        let mut seen_digit = false;

        let mut i = 0;
        while i < bytes.len() {
            let byte = bytes[i];
            if byte == b'.' {
                if seen_dot {
                    return Err(WeiParseError::InvalidByte);
                }
                seen_dot = true;
                i += 1;
                continue;
            }
            if byte < b'0' || byte > b'9' {
                return Err(WeiParseError::InvalidByte);
            }
            seen_digit = true;
            let digit = (byte - b'0') as u64;
            if seen_dot {
                if frac_digits == decimals {
                    if digit == 0 {
                        i += 1;
                        continue;
                    }
                    return Err(WeiParseError::TooManyDecimals);
                }
                frac = frac
                    .checked_mul(10)
                    .and_then(|value| value.checked_add(digit))
                    .ok_or(WeiParseError::Overflow)?;
                frac_digits += 1;
            } else {
                whole = whole
                    .checked_mul(10)
                    .and_then(|value| value.checked_add(digit))
                    .ok_or(WeiParseError::Overflow)?;
            }
            i += 1;
        }

        if !seen_digit {
            return Err(WeiParseError::Empty);
        }

        let missing = decimals - frac_digits;
        let frac_scale = Self::scale(missing).ok_or(WeiParseError::TooManyDecimals)?;
        let raw = whole
            .checked_mul(scale)
            .and_then(|value| frac.checked_mul(frac_scale).and_then(|frac_raw| value.checked_add(frac_raw)))
            .ok_or(WeiParseError::Overflow)?;
        Ok(Self::from_raw(raw))
    }

    #[inline]
    pub fn from_f64(value: f64, decimals: u8, rounding: Rounding) -> Result<Self, WeiParseError> {
        let scale = Self::scale(decimals).ok_or(WeiParseError::TooManyDecimals)? as f64;
        if !value.is_finite() {
            return Err(WeiParseError::InvalidByte);
        }
        if value < 0.0 {
            return Err(WeiParseError::Negative);
        }
        let scaled = value * scale;
        if scaled > u64::MAX as f64 {
            return Err(WeiParseError::Overflow);
        }
        let raw = match rounding {
            Rounding::Down => scaled.floor(),
            Rounding::Up => scaled.ceil(),
            Rounding::Nearest => scaled.round(),
        } as u64;
        Ok(Self::from_raw(raw))
    }

    #[inline]
    pub fn to_f64(self, decimals: u8) -> Option<f64> {
        let scale = Self::scale(decimals)? as f64;
        Some((self.raw() as f64) / scale)
    }

    pub fn fmt_decimal(self, decimals: u8, f: &mut impl fmt::Write) -> fmt::Result {
        let scale = match Self::scale(decimals) {
            Some(scale) => scale,
            None => return Err(fmt::Error),
        };
        let raw = self.raw();
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
            digits_left -= 1;
            f.write_char((b'0' + digit as u8) as char)?;
            if remaining == 0 {
                break;
            }
        }
        Ok(())
    }

    #[inline]
    pub fn convert_decimals(self, from_decimals: u8, to_decimals: u8, rounding: Rounding) -> Option<Self> {
        if from_decimals == to_decimals {
            return Some(self);
        }
        if to_decimals > from_decimals {
            let factor = Self::scale(to_decimals - from_decimals)?;
            return self.raw().checked_mul(factor).map(Self::from_raw);
        }
        let divisor = Self::scale(from_decimals - to_decimals)?;
        div_round_u64(self.raw(), divisor, rounding).map(Self::from_raw)
    }

    /// Recovered cap helpers convert a raw integer factor by 1e8, require it not
    /// to exceed 1.01, multiply the amount by the factor, then apply a 1.001
    /// buffer and add 1_000_000 atoms. Float-to-integer conversion truncates
    /// toward zero after the normal Rust saturating float-to-int lowering.
    pub fn buffered_cap(self, factor_int: u64) -> Result<Self, WeiArithmeticError> {
        let factor = (factor_int as f64) / WEI_FACTOR_SCALE;
        if !(0.0..=MAX_FACTOR).contains(&factor) {
            return Err(WeiArithmeticError::InvalidFactor);
        }
        let scaled = saturating_f64_to_u64((self.raw() as f64) * factor);
        let buffered = saturating_f64_to_u64((scaled as f64) * BUFFER_FACTOR);
        Ok(Self::from_raw(buffered.saturating_add(ADD_BUFFER_WEI)))
    }

    /// Compute notional-like quote Wei from raw price and size fixed-point units.
    /// The decompiled paths use a 1e14 divisor for `px * sz` products.
    pub fn from_px_sz_notional(px_raw: u64, sz_raw: u64, rounding: Rounding) -> Option<Self> {
        let product = (px_raw as u128).checked_mul(sz_raw as u128)?;
        let raw = div_round_u128(product, PX_SZ_NOTIONAL_SCALE, rounding)?;
        if raw <= u64::MAX as u128 {
            Some(Self::from_raw(raw as u64))
        } else {
            None
        }
    }
}

impl GenesisWei {
    #[inline]
    pub const fn from_raw(raw: u128) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u128 {
        self.0
    }

    #[inline]
    pub const fn scale(decimals: u8) -> Option<u128> {
        if (decimals as usize) < POW10_U128.len() {
            Some(POW10_U128[decimals as usize])
        } else {
            None
        }
    }

    pub fn parse_decimal(input: &str, decimals: u8) -> Result<Self, WeiParseError> {
        let scale = Self::scale(decimals).ok_or(WeiParseError::TooManyDecimals)?;
        let bytes = input.as_bytes();
        if bytes.is_empty() {
            return Err(WeiParseError::Empty);
        }
        if bytes[0] == b'-' {
            return Err(WeiParseError::Negative);
        }
        if bytes[0] == b'+' {
            return Err(WeiParseError::InvalidByte);
        }

        let mut whole = 0u128;
        let mut frac = 0u128;
        let mut frac_digits = 0u8;
        let mut seen_dot = false;
        let mut seen_digit = false;

        let mut i = 0;
        while i < bytes.len() {
            let byte = bytes[i];
            if byte == b'.' {
                if seen_dot {
                    return Err(WeiParseError::InvalidByte);
                }
                seen_dot = true;
                i += 1;
                continue;
            }
            if byte < b'0' || byte > b'9' {
                return Err(WeiParseError::InvalidByte);
            }
            seen_digit = true;
            let digit = (byte - b'0') as u128;
            if seen_dot {
                if frac_digits == decimals {
                    if digit == 0 {
                        i += 1;
                        continue;
                    }
                    return Err(WeiParseError::TooManyDecimals);
                }
                frac = frac
                    .checked_mul(10)
                    .and_then(|value| value.checked_add(digit))
                    .ok_or(WeiParseError::Overflow)?;
                frac_digits += 1;
            } else {
                whole = whole
                    .checked_mul(10)
                    .and_then(|value| value.checked_add(digit))
                    .ok_or(WeiParseError::Overflow)?;
            }
            i += 1;
        }

        if !seen_digit {
            return Err(WeiParseError::Empty);
        }

        let missing = decimals - frac_digits;
        let frac_scale = Self::scale(missing).ok_or(WeiParseError::TooManyDecimals)?;
        let raw = whole
            .checked_mul(scale)
            .and_then(|value| frac.checked_mul(frac_scale).and_then(|frac_raw| value.checked_add(frac_raw)))
            .ok_or(WeiParseError::Overflow)?;
        Ok(Self(raw))
    }

    #[inline]
    pub fn try_into_account_wei(self) -> Option<Wei> {
        if self.0 <= u64::MAX as u128 {
            Some(Wei::from_raw(self.0 as u64))
        } else {
            None
        }
    }

    pub fn fmt_decimal(self, decimals: u8, f: &mut impl fmt::Write) -> fmt::Result {
        let scale = match Self::scale(decimals) {
            Some(scale) => scale,
            None => return Err(fmt::Error),
        };
        let whole = self.0 / scale;
        let frac = self.0 % scale;
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
            digits_left -= 1;
            f.write_char((b'0' + digit as u8) as char)?;
            if remaining == 0 {
                break;
            }
        }
        Ok(())
    }
}

impl WeiBalance {
    #[inline]
    pub const fn new(total: Wei, available: Wei, notional: u64) -> Self {
        Self { total, available, notional }
    }

    /// Debit both total and available.  Total is checked; available saturates to
    /// zero when the debit exceeds the free bucket, matching the recovered
    /// two-field subtraction helper.
    pub fn debit_total_saturating_available(&mut self, amount: Wei) -> Result<(), WeiArithmeticError> {
        self.total = self.total.checked_sub(amount).ok_or(WeiArithmeticError::Underflow)?;
        self.available = self.available.saturating_sub(amount);
        Ok(())
    }

    /// Credit total and available, saturating to `u64::MAX` on overflow.  The
    /// state update path keeps going after logging overflow instead of wrapping.
    pub fn credit_saturating(&mut self, amount: Wei) {
        self.total = self.total.saturating_add(amount);
        self.available = self.available.saturating_add(amount);
    }

    /// Debit total and rescale the notional bucket by `new_total / old_total`.
    /// The binary uses floating conversion for this ratio on one hot path; this
    /// integer version preserves the same truncation direction without losing
    /// precision.
    pub fn debit_and_rescale_notional(&mut self, amount: Wei) -> Result<(), WeiArithmeticError> {
        let old_total = self.total.raw();
        self.debit_total_saturating_available(amount)?;
        if old_total == 0 {
            self.notional = 0;
            return Ok(());
        }
        let product = (self.notional as u128).saturating_mul(self.total.raw() as u128);
        self.notional = (product / old_total as u128).min(u64::MAX as u128) as u64;
        Ok(())
    }
}

/// Adjust a list of per-user Wei rows so the sum exactly equals `target_total`.
/// Rows are `(user_index, wei)` pairs in source order; when there is leftover
/// positive dust it is added to the first row, and when there is excess each row
/// is reduced by at most `floor(row * reduction_factor)`.
pub fn normalize_wei_distribution(
    rows: &mut [(u32, Wei)],
    target_total: Wei,
    reduction_factor: f64,
) -> Result<(), WeiArithmeticError> {
    if rows.is_empty() {
        return Err(WeiArithmeticError::EmptyDistribution);
    }
    let mut total = 0u64;
    let mut i = 0;
    while i < rows.len() {
        total = total.checked_add(rows[i].1.raw()).ok_or(WeiArithmeticError::Overflow)?;
        i += 1;
    }
    if total == 0 {
        return Err(WeiArithmeticError::EmptyDistribution);
    }

    let target = target_total.raw();
    if target >= total {
        let leftover = target - total;
        rows[0].1 = rows[0].1.checked_add(Wei::from_raw(leftover)).ok_or(WeiArithmeticError::Overflow)?;
        return Ok(());
    }

    if !(0.0..=MAX_FACTOR).contains(&reduction_factor) {
        return Err(WeiArithmeticError::InvalidFactor);
    }
    let mut excess = total - target;
    let mut j = 0;
    while j < rows.len() && excess != 0 {
        let row_raw = rows[j].1.raw();
        let max_reduce = saturating_f64_to_u64((row_raw as f64) * reduction_factor).min(row_raw);
        let reduce = max_reduce.min(excess);
        rows[j].1 = Wei::from_raw(row_raw - reduce);
        excess -= reduce;
        j += 1;
    }
    if excess != 0 {
        return Err(WeiArithmeticError::Underflow);
    }

    let mut final_total = 0u64;
    let mut k = 0;
    while k < rows.len() {
        final_total = final_total.checked_add(rows[k].1.raw()).ok_or(WeiArithmeticError::Overflow)?;
        k += 1;
    }
    if final_total == target {
        Ok(())
    } else {
        Err(WeiArithmeticError::Underflow)
    }
}

impl Add for Wei {
    type Output = Wei;

    #[inline]
    fn add(self, rhs: Wei) -> Wei {
        self.checked_add(rhs).expect("Wei addition overflow")
    }
}

impl AddAssign for Wei {
    #[inline]
    fn add_assign(&mut self, rhs: Wei) {
        *self = *self + rhs;
    }
}

impl Sub for Wei {
    type Output = Wei;

    #[inline]
    fn sub(self, rhs: Wei) -> Wei {
        self.checked_sub(rhs).expect("Wei subtraction underflow")
    }
}

impl SubAssign for Wei {
    #[inline]
    fn sub_assign(&mut self, rhs: Wei) {
        *self = *self - rhs;
    }
}

impl fmt::Debug for WeiPriv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("WeiPriv").field(&self.0).finish()
    }
}

impl fmt::Debug for Wei {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Wei").field(&self.0).finish()
    }
}

impl fmt::Display for Wei {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_decimal(QUOTE_WEI_DECIMALS, f)
    }
}

impl fmt::Debug for GenesisWei {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("GenesisWei").field(&self.0).finish()
    }
}

#[cfg(feature = "serde")]
mod serde_impls {
    use super::{Wei, WeiPriv};
    use core::fmt;
    use serde::de::{self, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl Serialize for WeiPriv {
        #[inline]
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_u64(self.raw())
        }
    }

    impl<'de> Deserialize<'de> for WeiPriv {
        #[inline]
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_u64(WeiPrivVisitor)
        }
    }

    struct WeiPrivVisitor;

    impl<'de> Visitor<'de> for WeiPrivVisitor {
        type Value = WeiPriv;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("u64 for WeiPriv")
        }

        #[inline]
        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(WeiPriv::from_raw(value))
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Err(E::custom(format_args!(
                "invalid value {value} for WeiPriv when visiting i64"
            )))
        }
    }

    impl Serialize for Wei {
        #[inline]
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_newtype_struct("Wei", &self.0)
        }
    }

    impl<'de> Deserialize<'de> for Wei {
        #[inline]
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct WeiVisitor;

            impl<'de> Visitor<'de> for WeiVisitor {
                type Value = Wei;

                fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("tuple struct Wei")
                }

                #[inline]
                fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
                where
                    D: Deserializer<'de>,
                {
                    WeiPriv::deserialize(deserializer).map(Wei)
                }
            }

            deserializer.deserialize_newtype_struct("Wei", WeiVisitor)
        }
    }
}

#[inline]
fn div_round_u64(numerator: u64, denominator: u64, rounding: Rounding) -> Option<u64> {
    if denominator == 0 {
        return None;
    }
    let q = numerator / denominator;
    let r = numerator % denominator;
    match rounding {
        Rounding::Down => Some(q),
        Rounding::Up => {
            if r == 0 {
                Some(q)
            } else {
                q.checked_add(1)
            }
        }
        Rounding::Nearest => {
            if (r as u128).checked_mul(2)? >= denominator as u128 {
                q.checked_add(1)
            } else {
                Some(q)
            }
        }
    }
}

#[inline]
fn div_round_u128(numerator: u128, denominator: u128, rounding: Rounding) -> Option<u128> {
    if denominator == 0 {
        return None;
    }
    let q = numerator / denominator;
    let r = numerator % denominator;
    match rounding {
        Rounding::Down => Some(q),
        Rounding::Up => {
            if r == 0 {
                Some(q)
            } else {
                q.checked_add(1)
            }
        }
        Rounding::Nearest => {
            if r.checked_mul(2)? >= denominator {
                q.checked_add(1)
            } else {
                Some(q)
            }
        }
    }
}

#[inline]
fn saturating_f64_to_u64(value: f64) -> u64 {
    if value.is_nan() || value <= 0.0 {
        0
    } else if value >= u64::MAX as f64 {
        u64::MAX
    } else {
        value as u64
    }
}
