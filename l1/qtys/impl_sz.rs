use core::fmt;
use core::convert::TryFrom;
use core::ops::{Add, AddAssign, Neg, Sub, SubAssign};

/// Non-negative size quantity used by orders and fill accounting.
///
/// The binary carries this as a plain `u64`. Checked subtraction sites first record
/// the arithmetic violation and then continue with zero; checked addition sites
/// continue with `u64::MAX`.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Sz(pub u64);

/// Signed size delta used by position/open-interest accounting.
///
/// Long and short exposure share the same storage: positive and negative values
/// are side-bearing sizes, while absolute value contributes to open interest.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct SignedSz(pub i64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SzSign {
    Short,
    Flat,
    Long,
}

impl Sz {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);
    pub const MAX: Self = Self(u64::MAX);

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
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
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self)
    }

    #[inline]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).map(Self)
    }

    #[inline]
    pub fn add_recording_overflow(self, rhs: Self) -> Self {
        match self.0.checked_add(rhs.0) {
            Some(v) => Self(v),
            None => {
                record_sz_add_overflow();
                Self(u64::MAX)
            }
        }
    }

    #[inline]
    pub fn sub_recording_underflow(self, rhs: Self) -> Self {
        match self.0.checked_sub(rhs.0) {
            Some(v) => Self(v),
            None => {
                record_sz_sub_underflow();
                Self(0)
            }
        }
    }

    #[inline]
    pub fn signed(self, is_buy_or_long: bool) -> SignedSz {
        let raw = i64::try_from(self.0).expect("size exceeds signed range");
        if is_buy_or_long {
            SignedSz(raw)
        } else {
            SignedSz(raw.checked_neg().expect("size exceeds signed range"))
        }
    }

    #[inline]
    pub fn ceil_to_increment(self, increment: Sz) -> Sz {
        if increment.0 == 0 {
            return self;
        }
        let q = self.0 / increment.0;
        let r = self.0 % increment.0;
        let rounded_q = q + u64::from(r != 0);
        Sz(increment.0.saturating_mul(rounded_q).max(u64::from(rounded_q != 0)))
    }

    #[inline]
    pub fn floor_to_increment(self, increment: Sz) -> Sz {
        if increment.0 == 0 {
            return self;
        }
        Sz(increment.0.saturating_mul(self.0 / increment.0))
    }

    /// Rounds a proposed size down to the largest visible decimal bucket used by
    /// liquidation/ADL candidate generation. The branch ladder mirrors the
    /// recovered comparisons against 1e5..1e9 and larger powers of ten.
    pub fn floor_to_visible_bucket(self) -> Sz {
        let step = visible_bucket_step(self.0);
        if step == 0 {
            return self;
        }
        Sz(step.saturating_mul(self.0 / step))
    }

    #[inline]
    pub fn as_f64(self) -> f64 {
        self.0 as f64
    }

    #[inline]
    pub fn from_f64_floor_clamped(value: f64) -> Self {
        if !value.is_finite() || value <= 0.0 {
            return Self::ZERO;
        }
        if value >= u64::MAX as f64 {
            return Self::MAX;
        }
        Self(value.floor() as u64)
    }

    #[inline]
    pub fn from_f64_round_clamped(value: f64) -> Self {
        if !value.is_finite() || value <= 0.0 {
            return Self::ZERO;
        }
        if value >= u64::MAX as f64 {
            return Self::MAX;
        }
        Self(value.round() as u64)
    }

    pub fn fmt_decimals(self, decimals: usize, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if decimals == 0 {
            return fmt::Display::fmt(&self.0, f);
        }
        let scale = pow10_u64(decimals).unwrap_or(u64::MAX);
        let whole = self.0 / scale;
        let frac = self.0 % scale;
        if frac == 0 {
            return fmt::Display::fmt(&whole, f);
        }
        write!(f, "{}.", whole)?;
        let mut divisor = scale / 10;
        while divisor != 0 {
            let digit = (frac / divisor) % 10;
            if frac % divisor == 0 {
                return fmt::Display::fmt(&digit, f);
            }
            write!(f, "{}", digit)?;
            divisor /= 10;
        }
        Ok(())
    }
}

impl SignedSz {
    pub const ZERO: Self = Self(0);
    pub const MAX: Self = Self(i64::MAX);
    pub const MIN: Self = Self(i64::MIN);

    #[inline]
    pub const fn raw(self) -> i64 {
        self.0
    }

    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub const fn sign(self) -> SzSign {
        if self.0 > 0 {
            SzSign::Long
        } else if self.0 < 0 {
            SzSign::Short
        } else {
            SzSign::Flat
        }
    }

    #[inline]
    pub fn abs(self) -> Sz {
        match self.0.checked_abs() {
            Some(v) => Sz(v as u64),
            None => panic!("called `Result::unwrap()` on an `Err` value"),
        }
    }

    #[inline]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self)
    }

    #[inline]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).map(Self)
    }

    #[inline]
    pub fn add_recording_overflow(self, rhs: Self) -> Self {
        match self.0.checked_add(rhs.0) {
            Some(v) => Self(v),
            None => {
                record_signed_sz_overflow();
                Self(self.0.saturating_add(rhs.0))
            }
        }
    }

    #[inline]
    pub fn sub_recording_overflow(self, rhs: Self) -> Self {
        match self.0.checked_sub(rhs.0) {
            Some(v) => Self(v),
            None => {
                record_signed_sz_overflow();
                Self(self.0.saturating_sub(rhs.0))
            }
        }
    }

    #[inline]
    pub fn from_side(raw: Sz, is_buy_or_long: bool) -> Self {
        raw.signed(is_buy_or_long)
    }

    #[inline]
    pub fn flips_side_after(self, delta: Self) -> bool {
        let next = self.add_recording_overflow(delta);
        !self.is_zero() && self.sign() != next.sign()
    }
}

impl From<u64> for Sz {
    #[inline]
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Sz> for u64 {
    #[inline]
    fn from(value: Sz) -> Self {
        value.0
    }
}

impl TryFrom<i64> for Sz {
    type Error = ();

    #[inline]
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        if value < 0 { Err(()) } else { Ok(Self(value as u64)) }
    }
}

impl From<i64> for SignedSz {
    #[inline]
    fn from(value: i64) -> Self {
        Self(value)
    }
}

impl From<SignedSz> for i64 {
    #[inline]
    fn from(value: SignedSz) -> Self {
        value.0
    }
}

impl Add for Sz {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        self.add_recording_overflow(rhs)
    }
}

impl AddAssign for Sz {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add_recording_overflow(rhs);
    }
}

impl Sub for Sz {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        self.sub_recording_underflow(rhs)
    }
}

impl SubAssign for Sz {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub_recording_underflow(rhs);
    }
}

impl Add for SignedSz {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        self.add_recording_overflow(rhs)
    }
}

impl AddAssign for SignedSz {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add_recording_overflow(rhs);
    }
}

impl Sub for SignedSz {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        self.sub_recording_overflow(rhs)
    }
}

impl SubAssign for SignedSz {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub_recording_overflow(rhs);
    }
}

impl Neg for SignedSz {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        match self.0.checked_neg() {
            Some(v) => Self(v),
            None => panic!("called `Result::unwrap()` on an `Err` value"),
        }
    }
}

impl fmt::Debug for Sz {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Sz {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for SignedSz {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for SignedSz {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Updates total resting size when an order changes size. This shape appears in
/// both 616-byte and 632-byte event-vector monomorphs.
#[inline]
pub fn replace_resting_order_sz_total(total: &mut Sz, old_sz: Sz, new_sz: Sz) {
    if old_sz != new_sz {
        *total = total.sub_recording_underflow(old_sz).add_recording_overflow(new_sz);
    }
}

/// Removes resting size from an aggregate. Removal helpers clamp underflow to
/// zero after recording the violation.
#[inline]
pub fn remove_resting_order_sz(total: &mut Sz, removed: Sz) {
    *total = total.sub_recording_underflow(removed);
}

/// Applies a signed size transition to absolute open interest and non-zero slot
/// count. The recovered map helpers perform this logic around BTree entry lookup.
pub fn apply_open_interest_transition(
    aggregate_abs_sz: &mut SignedSz,
    nonzero_count: &mut i64,
    old_sz: SignedSz,
    new_sz: SignedSz,
) {
    match (old_sz.is_zero(), new_sz.is_zero()) {
        (true, false) => *nonzero_count = nonzero_count.saturating_add(1),
        (false, true) if *nonzero_count != 0 => *nonzero_count -= 1,
        _ => {}
    }

    let without_old = aggregate_abs_sz.sub_recording_overflow(SignedSz(old_sz.abs().0 as i64));
    *aggregate_abs_sz = without_old.add_recording_overflow(SignedSz(new_sz.abs().0 as i64));
}

/// Computes the signed size after applying a side-dependent raw-size delta.
#[inline]
pub fn signed_delta_after_existing(existing: SignedSz, raw_sz: Sz, subtract_as_short: bool) -> SignedSz {
    existing.sub_recording_overflow(raw_sz.signed(!subtract_as_short))
}

/// Returns true when a fill delta moves a non-flat position from long to short or
/// short to long. The binary records the user key on exactly these sign changes.
#[inline]
pub fn crosses_position_side(before: SignedSz, delta: SignedSz) -> bool {
    before.flips_side_after(delta)
}

#[inline]
fn pow10_u64(decimals: usize) -> Option<u64> {
    let mut out = 1u64;
    let mut n = 0usize;
    while n < decimals {
        out = out.checked_mul(10)?;
        n += 1;
    }
    Some(out)
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
fn record_sz_sub_underflow() {
    // Recovered call sites invoke a shared diagnostic hook, then continue with 0.
}

#[cold]
fn record_sz_add_overflow() {
    // Recovered call sites invoke a shared diagnostic hook, then continue with u64::MAX.
}

#[cold]
fn record_signed_sz_overflow() {
    // Recovered call sites invoke a shared diagnostic hook, then continue saturated.
}
