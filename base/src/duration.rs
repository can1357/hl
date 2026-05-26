//! Reconstructed duration utilities used by timer, latency, and consensus code.
//!
//! The binary stores the project duration newtype as `f64` seconds.  The hot
//! conversions keep microsecond precision when crossing into `std::time::Duration`,
//! and chrono timestamp helpers use microseconds for differences and nanoseconds
//! for additions.

use std::fmt;
use std::ops::{Add, AddAssign, Div, Mul, Sub, SubAssign};
use std::str::FromStr;
use std::time::Duration as StdDuration;

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

const MICROS_PER_SEC: u64 = 1_000_000;
const NANOS_PER_MICRO: u64 = 1_000;
const NANOS_PER_SEC_U32: u32 = 1_000_000_000;
const NANOS_PER_SEC_I64: i64 = 1_000_000_000;
const SECONDS_PER_DAY: i64 = 86_400;

/// Project duration representation: seconds as an `f64`.
///
/// Recovered callsites treat negative values as programmer errors before any
/// conversion to OS/std duration types, but ordinary arithmetic preserves the
/// raw seconds until an invariant-checking method is called.
#[derive(Clone, Copy, Debug, Default, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Duration(pub f64);

impl Duration {
    pub const ZERO: Self = Self(0.0);
    pub const SECOND: Self = Self(1.0);
    pub const MINUTE: Self = Self(60.0);
    pub const HOUR: Self = Self(3_600.0);
    pub const DAY: Self = Self(SECONDS_PER_DAY as f64);

    #[inline]
    pub const fn from_secs_f64(seconds: f64) -> Self {
        Self(seconds)
    }

    #[inline]
    pub const fn from_secs(seconds: u64) -> Self {
        Self(seconds as f64)
    }

    #[inline]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis as f64 / 1_000.0)
    }

    #[inline]
    pub const fn from_micros(micros: u64) -> Self {
        Self(micros as f64 / MICROS_PER_SEC as f64)
    }

    #[inline]
    pub fn from_std(duration: StdDuration) -> Self {
        Self(duration.as_secs() as f64 + duration.subsec_nanos() as f64 / NANOS_PER_SEC_I64 as f64)
    }

    #[inline]
    pub const fn as_secs_f64(self) -> f64 {
        self.0
    }

    #[inline]
    pub fn is_zero(self) -> bool {
        self.0 == 0.0
    }

    #[inline]
    pub fn is_finite(self) -> bool {
        self.0.is_finite()
    }

    /// Assert and return `self`; recovered line sites use this before ratios and
    /// wall-clock conversions.
    #[inline]
    pub fn assert_nonnegative(self) -> Self {
        assert!(self.0 >= 0.0);
        self
    }

    /// Assert and return `self`; recovered denominator checks require strictly
    /// positive duration values.
    #[inline]
    pub fn assert_positive(self) -> Self {
        assert!(self.0 > 0.0);
        self
    }

    #[inline]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        if self.0 >= rhs.0 {
            Some(Self(self.0 - rhs.0))
        } else {
            None
        }
    }

    #[inline]
    pub fn saturating_sub(self, rhs: Self) -> Self {
        self.checked_sub(rhs).unwrap_or(Self::ZERO)
    }

    /// Ratio of two nonnegative duration values.
    ///
    /// Recovered assertions: numerator must be nonnegative, denominator must be
    /// strictly positive.
    #[inline]
    pub fn div_duration(self, rhs: Self) -> f64 {
        self.assert_nonnegative();
        rhs.assert_positive();
        self.0 / rhs.0
    }

    /// Convert to `std::time::Duration` using the recovered microsecond path.
    ///
    /// The binary asserts nonnegative seconds, rounds `seconds * 1_000_000`,
    /// clamps to `u64::MAX`, then splits into seconds and nanoseconds.
    #[inline]
    pub fn to_std(self) -> StdDuration {
        self.assert_nonnegative();

        let micros = (self.0 * MICROS_PER_SEC as f64).round().clamp(0.0, u64::MAX as f64) as u64;
        StdDuration::new(
            micros / MICROS_PER_SEC,
            ((micros % MICROS_PER_SEC) * NANOS_PER_MICRO) as u32,
        )
    }

    #[inline]
    pub fn add_to_naive_datetime(self, base: NaiveDateTime) -> NaiveDateTime {
        naive_datetime_add_secs_f64(base, self.0)
    }

    #[inline]
    pub fn ceil(self) -> Self {
        Self(self.0.ceil())
    }
}

impl From<StdDuration> for Duration {
    #[inline]
    fn from(duration: StdDuration) -> Self {
        Self::from_std(duration)
    }
}

impl From<Duration> for StdDuration {
    #[inline]
    fn from(duration: Duration) -> Self {
        duration.to_std()
    }
}

impl Add for Duration {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign for Duration {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl Sub for Duration {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        assert!(self.0 >= rhs.0);
        Self(self.0 - rhs.0)
    }
}

impl SubAssign for Duration {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        assert!(self.0 >= rhs.0);
        self.0 -= rhs.0;
    }
}

impl Mul<f64> for Duration {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: f64) -> Self::Output {
        Self(self.0 * rhs)
    }
}

impl Mul<Duration> for f64 {
    type Output = Duration;

    #[inline]
    fn mul(self, rhs: Duration) -> Self::Output {
        Duration(self * rhs.0)
    }
}

impl Div<f64> for Duration {
    type Output = Self;

    #[inline]
    fn div(self, rhs: f64) -> Self::Output {
        Self(self.0 / rhs)
    }
}

impl Div<Duration> for Duration {
    type Output = f64;

    #[inline]
    fn div(self, rhs: Duration) -> Self::Output {
        self.div_duration(rhs)
    }
}

impl fmt::Display for Duration {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for Duration {
    type Err = std::num::ParseFloatError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<f64>().map(Self)
    }
}

/// Decimal-string wrapper used by `DurationString` serde paths.
///
/// The binary-visible error chain names the inner type `DecimalString`, then
/// wraps it as `DurationString`; no unit-suffix grammar was recovered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecimalString(pub String);

impl FromStr for DecimalString {
    type Err = std::convert::Infallible;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for DecimalString {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// String-backed duration newtype.
///
/// Serde/debug evidence shows a tuple struct named `DurationString` with one
/// element and an inner `DecimalString` parse layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurationString(pub DecimalString);

impl DurationString {
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0.0
    }

    #[inline]
    pub fn parse_duration(&self) -> Result<Duration, std::num::ParseFloatError> {
        self.as_str().parse::<f64>().map(Duration)
    }
}

impl From<Duration> for DurationString {
    #[inline]
    fn from(duration: Duration) -> Self {
        Self(DecimalString(duration.0.to_string()))
    }
}

impl TryFrom<DurationString> for Duration {
    type Error = std::num::ParseFloatError;

    #[inline]
    fn try_from(value: DurationString) -> Result<Self, Self::Error> {
        value.0.0.parse::<f64>().map(Self)
    }
}

impl fmt::Display for DurationString {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DurationString {
    type Err = std::convert::Infallible;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(DecimalString(s.to_owned())))
    }
}

/// Return `(later - earlier)` as seconds, truncated to microsecond precision.
///
/// If timestamps are reversed, the recovered helper logs `"Time Sub"` and returns
/// zero rather than a negative duration.
pub fn seconds_since_or_zero(later: NaiveDateTime, earlier: NaiveDateTime) -> f64 {
    if later < earlier {
        tracing::error!(?later, ?earlier, "Time Sub");
        return 0.0;
    }

    later
        .signed_duration_since(earlier)
        .num_microseconds()
        .map(|micros| micros as f64 / MICROS_PER_SEC as f64)
        .unwrap_or(0.0)
}

/// Add an `f64` seconds delta to a chrono `NaiveDateTime`.
///
/// Recovered behavior multiplies by 1e9, treats NaN as zero, clamps finite values
/// into the `i64` nanosecond range, normalizes with Euclidean division, then uses
/// chrono checked addition.
pub fn naive_datetime_add_secs_f64(base: NaiveDateTime, seconds: f64) -> NaiveDateTime {
    let raw_nanos = seconds * NANOS_PER_SEC_I64 as f64;
    let total_nanos = if raw_nanos.is_nan() {
        0
    } else {
        raw_nanos.clamp(i64::MIN as f64, i64::MAX as f64) as i64
    };

    let secs = total_nanos.div_euclid(NANOS_PER_SEC_I64);
    let nanos = total_nanos.rem_euclid(NANOS_PER_SEC_I64);
    let delta = chrono::Duration::seconds(secs) + chrono::Duration::nanoseconds(nanos);

    base.checked_add_signed(delta)
        .expect("`NaiveDateTime + TimeDelta` overflowed")
}

/// Move `candidate` forward by whole `interval` steps until it is not earlier
/// than `floor`.
///
/// Consensus timer paths use this to catch a scheduled timestamp up to the next
/// block/tick boundary without drifting fractional intervals.
pub fn advance_by_interval_until_at_least(
    candidate: NaiveDateTime,
    floor: NaiveDateTime,
    interval: Duration,
) -> NaiveDateTime {
    interval.assert_positive();
    if candidate >= floor {
        return candidate;
    }

    let missed = seconds_since_or_zero(floor, candidate) / interval.0;
    let steps = missed.ceil();
    assert!(steps >= 0.0);
    naive_datetime_add_secs_f64(candidate, steps * interval.0)
}

/// UTC formatting grammar observed in duration-adjacent timestamp helpers.
pub fn parse_utc_naive(input: &str) -> Result<NaiveDateTime, chrono::ParseError> {
    NaiveDateTime::parse_from_str(input, "%Y-%m-%dT%H:%M:%SZ")
}

pub fn format_utc_naive(datetime: NaiveDateTime) -> String {
    datetime.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Helper matching the sec/nsec normalization used when adding rounded
/// microseconds to an existing timespec pair.
#[inline]
pub fn checked_add_micros_to_pair(
    base_secs: u64,
    base_nanos: u32,
    delta_micros: u64,
) -> Option<(u64, u32)> {
    let mut secs = base_secs.checked_add(delta_micros / MICROS_PER_SEC)?;
    let mut nanos = base_nanos.checked_add(((delta_micros % MICROS_PER_SEC) * NANOS_PER_MICRO) as u32)?;
    if nanos >= NANOS_PER_SEC_U32 {
        nanos -= NANOS_PER_SEC_U32;
        secs = secs.checked_add(1)?;
    }
    Some((secs, nanos))
}
