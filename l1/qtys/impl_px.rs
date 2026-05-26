use core::fmt;

/// Price quantity used by L1 matching and action validation.
///
/// Prices are carried as signed fixed-point integers. The order path only accepts
/// non-negative prices; a recovered inlined unwrap path checks the signed result
/// before taking its absolute value. Constants observed in the decimal helpers
/// include 1e6 and 1e8, which match the perp/spot wire decimal envelopes below.
#[repr(transparent)]
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Px(i64);

pub const PERP_PRICE_DECIMALS: u8 = 6;
pub const SPOT_PRICE_DECIMALS: u8 = 8;
pub const MAX_WIRE_SIGNIFICANT_FIGURES: u8 = 5;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PxParseError {
    Empty,
    Negative,
    InvalidByte,
    TooManyDecimals,
    TooManySignificantFigures,
    NonPositive,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rounding {
    Down,
    Up,
    Nearest,
}

impl Px {
    pub const ZERO: Self = Self(0);
    pub const ONE_PERP: Self = Self(1_000_000);
    pub const ONE_SPOT: Self = Self(100_000_000);

    #[inline]
    pub const fn from_raw(raw: i64) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> i64 {
        self.0
    }

    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub const fn is_positive(self) -> bool {
        self.0 > 0
    }

    #[inline]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.0.checked_add(rhs.0) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    #[inline]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    #[inline]
    pub fn abs(self) -> Option<Self> {
        match self.0.checked_abs() {
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

    /// Decimal places allowed for a wire price once asset size decimals are known.
    /// Perp prices use the 1e6 envelope; spot prices use the 1e8 envelope.
    #[inline]
    pub const fn wire_decimals(sz_decimals: u8, spot: bool) -> Option<u8> {
        let base = if spot { SPOT_PRICE_DECIMALS } else { PERP_PRICE_DECIMALS };
        if sz_decimals <= base {
            Some(base - sz_decimals)
        } else {
            None
        }
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
    pub fn parse_wire_for_asset(input: &str, sz_decimals: u8, spot: bool) -> Result<Self, PxParseError> {
        let decimals = Self::wire_decimals(sz_decimals, spot).ok_or(PxParseError::TooManyDecimals)?;
        Self::parse_wire(input, decimals)
    }

    /// Parse a positive decimal price into the fixed-point scale selected by
    /// `decimals`. The parser performs the same class of checks as the recovered
    /// order-wire path: no sign, no more fractional digits than the scale,
    /// non-zero final raw price, and at most five significant digits after
    /// canonical trailing zeros are removed.
    pub fn parse_wire(input: &str, decimals: u8) -> Result<Self, PxParseError> {
        let scale = Self::scale(decimals).ok_or(PxParseError::TooManyDecimals)?;
        let bytes = input.as_bytes();
        if bytes.is_empty() {
            return Err(PxParseError::Empty);
        }
        if bytes[0] == b'-' {
            return Err(PxParseError::Negative);
        }
        if bytes[0] == b'+' {
            return Err(PxParseError::InvalidByte);
        }

        let mut whole: i64 = 0;
        let mut frac: i64 = 0;
        let mut frac_digits: u8 = 0;
        let mut seen_dot = false;
        let mut seen_digit = false;
        let mut seen_nonzero = false;

        let mut i = 0;
        while i < bytes.len() {
            let byte = bytes[i];
            if byte == b'.' {
                if seen_dot {
                    return Err(PxParseError::InvalidByte);
                }
                seen_dot = true;
                i += 1;
                continue;
            }
            if byte < b'0' || byte > b'9' {
                return Err(PxParseError::InvalidByte);
            }

            let digit = (byte - b'0') as i64;
            seen_digit = true;
            if digit != 0 {
                seen_nonzero = true;
            }

            if seen_dot {
                if frac_digits == decimals {
                    if digit == 0 {
                        i += 1;
                        continue;
                    }
                    return Err(PxParseError::TooManyDecimals);
                }
                frac = frac.checked_mul(10).and_then(|v| v.checked_add(digit)).ok_or(PxParseError::Overflow)?;
                frac_digits += 1;
            } else {
                whole = whole.checked_mul(10).and_then(|v| v.checked_add(digit)).ok_or(PxParseError::Overflow)?;
            }
            i += 1;
        }

        if !seen_digit {
            return Err(PxParseError::Empty);
        }
        if !seen_nonzero {
            return Err(PxParseError::NonPositive);
        }

        let mut raw = whole.checked_mul(scale).ok_or(PxParseError::Overflow)?;
        let missing = decimals - frac_digits;
        let frac_scale = Self::scale(missing).ok_or(PxParseError::TooManyDecimals)?;
        raw = raw.checked_add(frac.checked_mul(frac_scale).ok_or(PxParseError::Overflow)?).ok_or(PxParseError::Overflow)?;
        if raw <= 0 {
            return Err(PxParseError::NonPositive);
        }
        let px = Self(raw);
        if !px.fits_wire(decimals) {
            return Err(PxParseError::TooManySignificantFigures);
        }
        Ok(px)
    }

    #[inline]
    pub fn from_f64(value: f64, decimals: u8, rounding: Rounding) -> Result<Self, PxParseError> {
        let scale = Self::scale(decimals).ok_or(PxParseError::TooManyDecimals)? as f64;
        if !value.is_finite() {
            return Err(PxParseError::InvalidByte);
        }
        if value <= 0.0 {
            return Err(PxParseError::NonPositive);
        }
        let scaled = value * scale;
        if scaled > i64::MAX as f64 {
            return Err(PxParseError::Overflow);
        }
        let raw = match rounding {
            Rounding::Down => scaled.floor(),
            Rounding::Up => scaled.ceil(),
            Rounding::Nearest => scaled.round(),
        } as i64;
        let px = Self(raw);
        if !px.fits_wire(decimals) {
            return Err(PxParseError::TooManySignificantFigures);
        }
        Ok(px)
    }

    #[inline]
    pub fn to_f64(self, decimals: u8) -> Option<f64> {
        let scale = Self::scale(decimals)? as f64;
        Some((self.0 as f64) / scale)
    }

    /// Construct a price from a notional/size ratio in raw integer units.
    /// `scale` is normally `10^(6 - sz_decimals)` for perps or
    /// `10^(8 - sz_decimals)` for spot assets.
    #[inline]
    pub fn from_ratio(numerator: i128, denominator: i128, scale: i64, rounding: Rounding) -> Option<Self> {
        if denominator <= 0 || scale <= 0 || numerator < 0 {
            return None;
        }
        let scaled = numerator.checked_mul(scale as i128)?;
        let value = div_round_nonnegative(scaled, denominator, rounding)?;
        if value > i64::MAX as i128 {
            None
        } else {
            Some(Self(value as i64))
        }
    }

    /// Multiply a raw size by this price and divide by the selected fixed-point
    /// scale. This mirrors the matching-path notional computation and keeps the
    /// intermediate in i128 to avoid losing high bits before rounding.
    #[inline]
    pub fn mul_size_raw(self, size_raw: i64, scale: i64, rounding: Rounding) -> Option<i64> {
        if self.0 < 0 || size_raw < 0 || scale <= 0 {
            return None;
        }
        let product = (self.0 as i128).checked_mul(size_raw as i128)?;
        let value = div_round_nonnegative(product, scale as i128, rounding)?;
        if value > i64::MAX as i128 {
            None
        } else {
            Some(value as i64)
        }
    }

    #[inline]
    pub fn round_to_tick(self, tick: Self, rounding: Rounding) -> Option<Self> {
        if self.0 < 0 || tick.0 <= 0 {
            return None;
        }
        let units = div_round_nonnegative(self.0 as i128, tick.0 as i128, rounding)?;
        let raw = units.checked_mul(tick.0 as i128)?;
        if raw > i64::MAX as i128 {
            None
        } else {
            Some(Self(raw as i64))
        }
    }

    #[inline]
    pub const fn floor_to_tick(self, tick: Self) -> Option<Self> {
        if self.0 < 0 || tick.0 <= 0 {
            return None;
        }
        Some(Self((self.0 / tick.0) * tick.0))
    }

    #[inline]
    pub fn ceil_to_tick(self, tick: Self) -> Option<Self> {
        if self.0 < 0 || tick.0 <= 0 {
            return None;
        }
        let rem = self.0 % tick.0;
        if rem == 0 {
            Some(self)
        } else {
            match (self.0 / tick.0).checked_add(1).and_then(|q| q.checked_mul(tick.0)) {
                Some(raw) => Some(Self(raw)),
                None => None,
            }
        }
    }

    /// Format without allocating through the caller's `fmt::Write` sink.
    pub fn fmt_decimal(self, decimals: u8, f: &mut impl fmt::Write) -> fmt::Result {
        let scale = match Self::scale(decimals) {
            Some(scale) => scale,
            None => return Err(fmt::Error),
        };
        let raw = self.0;
        if raw < 0 {
            f.write_char('-')?;
        }
        let abs = raw.unsigned_abs() as u128;
        let scale_u = scale as u128;
        let whole = abs / scale_u;
        let frac = abs % scale_u;
        write!(f, "{whole}")?;
        if decimals == 0 || frac == 0 {
            return Ok(());
        }

        f.write_char('.')?;
        let mut divisor = scale_u / 10;
        let mut remaining = frac;
        let mut digits_left = decimals;
        while digits_left != 0 {
            let digit = remaining / divisor;
            remaining %= divisor;
            divisor /= 10;
            digits_left -= 1;
            if remaining == 0 {
                f.write_char((b'0' + digit as u8) as char)?;
                break;
            }
            f.write_char((b'0' + digit as u8) as char)?;
        }
        Ok(())
    }

    /// Returns true when the raw value can be represented on the order wire for
    /// the given decimal envelope without changing value.
    pub fn fits_wire(self, decimals: u8) -> bool {
        if self.0 <= 0 {
            return false;
        }
        let mut raw = self.0;
        while raw % 10 == 0 {
            raw /= 10;
        }
        let mut sig = 0u8;
        let mut value = raw;
        while value != 0 {
            sig += 1;
            value /= 10;
        }
        sig <= MAX_WIRE_SIGNIFICANT_FIGURES && Self::scale(decimals).is_some()
    }
}

impl fmt::Debug for Px {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Px").field(&self.0).finish()
    }
}

impl fmt::Display for Px {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_decimal(PERP_PRICE_DECIMALS, f)
    }
}

#[inline]
fn div_round_nonnegative(numerator: i128, denominator: i128, rounding: Rounding) -> Option<i128> {
    if numerator < 0 || denominator <= 0 {
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
