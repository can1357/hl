#![allow(dead_code)]

use core::fmt;
use core::ops::{Add, AddAssign, Sub, SubAssign};
use core::str::FromStr;
use std::collections::BTreeMap;

use crate::raw_vlm::RawVlm;

/// Scaled trading volume accumulator.
///
/// The binary carries this as a transparent `u64` newtype.  The reflected serde
/// name is `tuple struct ScaledVlm`; arithmetic sites use checked unsigned
/// addition and, after the recovered overflow hook, keep executing with
/// `u64::MAX` as the saturated value.
#[repr(transparent)]
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ScaledVlm(u64);

/// Notional accumulator used by the fold helpers that consume scaled volume.
#[repr(transparent)]
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ntl(u64);

/// User key shape copied at scaled-volume lookup sites.
#[repr(transparent)]
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UserAddress {
    pub bytes: [u8; 20],
}

/// State-map value shape returned in the small-struct ABI as `(rax, rdx)`.
#[repr(C)]
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct ScaledAndRawVlm {
    pub scaled: ScaledVlm,
    pub raw: RawVlm,
}

pub const USER_ACTION_BASE_LIMIT: u64 = 1_000;
pub const USER_ACTION_PRIVILEGED_LIMIT: u64 = 10_000;
pub const USER_ACTION_VOLUME_STEP: u64 = 500_000_000;
pub const USER_ACTION_MAX_VOLUME_BONUS: u64 = 4_000;
pub const USER_ACTION_MAX_LIMIT: u64 = USER_ACTION_BASE_LIMIT + USER_ACTION_MAX_VOLUME_BONUS;

/// Recovered threshold in the daily-volume update gate (`0x5f5e100`).
pub const MIN_DAILY_UPDATE_SCALED_VLM: ScaledVlm = ScaledVlm(100_000_000);

/// The daily BTree entry path rejects a new date once the per-user map already
/// has ten date entries (`len > 9` before inserting the new date).
pub const MAX_DAILY_SCALED_VLM_ENTRIES: usize = 10;

/// Timestamp gate used by the daily update path before recording a new daily
/// entry.  The binary constructs a five-day chrono delta for this comparison.
pub const DAILY_UPDATE_DELAY_DAYS: u32 = 5;

/// Account priority / tier field computed by a caller of the user lookup:
/// `scaled / 100 + 10000`.
pub const ACCOUNT_PRIORITY_BASE: u64 = 10_000;
pub const ACCOUNT_PRIORITY_SCALED_DIVISOR: u64 = 100;

/// Successful perp notifications divide `qty * px` by this value.
pub const PERP_NOTIONAL_PRODUCT_SCALE: u64 = 1_000_000;

/// Successful spot notifications divide `qty * px` by this value.
pub const SPOT_NOTIONAL_PRODUCT_SCALE: u64 = 100_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScaledVlmParseError {
    Empty,
    Sign,
    InvalidByte(u8),
    Overflow,
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
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self)
    }

    #[inline]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    #[inline]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).map(Self)
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

    /// Dynamic per-user action cap recovered from perp/spot action gates:
    /// `1000 + min(total_scaled / 500_000_000, 4000)`.
    #[inline]
    pub const fn action_limit(self) -> u64 {
        let bonus = self.0 / USER_ACTION_VOLUME_STEP;
        USER_ACTION_BASE_LIMIT + if bonus > USER_ACTION_MAX_VOLUME_BONUS {
            USER_ACTION_MAX_VOLUME_BONUS
        } else {
            bonus
        }
    }

    #[inline]
    pub const fn privileged_action_limit() -> u64 {
        USER_ACTION_PRIVILEGED_LIMIT
    }

    /// Account priority/tier seed observed as `scaled / 100 + 10000`.
    #[inline]
    pub const fn account_priority(self) -> u64 {
        (self.0 / ACCOUNT_PRIORITY_SCALED_DIVISOR) + ACCOUNT_PRIORITY_BASE
    }

    /// The daily gate returns the shortfall payload as `(scaled as i32) / 100.0`
    /// when volume is below `100_000_000`.
    #[inline]
    pub fn daily_update_shortfall_value(self) -> f64 {
        (self.0 as i32 as f64) / 100.0
    }

    pub fn parse_bytes(bytes: &[u8]) -> Result<Self, ScaledVlmParseError> {
        if bytes.is_empty() {
            return Err(ScaledVlmParseError::Empty);
        }

        let mut raw = 0_u64;
        for &byte in bytes {
            match byte {
                b'0'..=b'9' => {
                    let digit = u64::from(byte - b'0');
                    raw = raw
                        .checked_mul(10)
                        .and_then(|value| value.checked_add(digit))
                        .ok_or(ScaledVlmParseError::Overflow)?;
                }
                b'+' | b'-' => return Err(ScaledVlmParseError::Sign),
                _ => return Err(ScaledVlmParseError::InvalidByte(byte)),
            }
        }

        Ok(Self(raw))
    }

    #[inline]
    pub fn parse_str(value: &str) -> Result<Self, ScaledVlmParseError> {
        Self::parse_bytes(value.as_bytes())
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

impl Ntl {
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
    pub fn checked_add_scaled_vlm(self, scaled: ScaledVlm) -> Option<Self> {
        self.0.checked_add(scaled.0).map(Self)
    }

    #[inline]
    pub const fn saturating_add_scaled_vlm(self, scaled: ScaledVlm) -> Self {
        Self(self.0.saturating_add(scaled.0))
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
    pub const fn scaled(self) -> ScaledVlm {
        self.scaled
    }

    #[inline]
    pub const fn raw(self) -> RawVlm {
        self.raw
    }

    #[inline]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        Some(Self {
            scaled: self.scaled.checked_add(rhs.scaled)?,
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

    /// Recovered overflow behavior for volume-map accumulation: checked adds
    /// trigger the diagnostic path, then the optimized code keeps the saturated
    /// `u64::MAX` component.
    #[inline]
    pub fn add_after_overflow_hook(self, rhs: Self) -> Self {
        self.saturating_add(rhs)
    }
}

pub trait ScaledVlmStore {
    fn base_user_vlm(&self, user: &UserAddress) -> ScaledAndRawVlm;
    fn per_dex_user_vlms<'a>(&'a self, user: &'a UserAddress) -> impl Iterator<Item = ScaledAndRawVlm> + 'a;
}

/// Sum one user's base map entry and every per-dex map entry.  Recovered state
/// layouts used either vector pointer/len at offsets `0x5c0/0x5c8` or
/// `0x1040/0x1048`; each per-dex element was `0x2f0` bytes and the value fields
/// read here were at `+0x40` (scaled) and `+0x48` (raw).
pub fn user_scaled_and_raw_vlm<S>(state: &S, user: &UserAddress) -> ScaledAndRawVlm
where
    S: ScaledVlmStore,
{
    let mut total = ScaledAndRawVlm::ZERO;
    for entry in state.per_dex_user_vlms(user) {
        total = total.add_after_overflow_hook(entry);
    }
    total.add_after_overflow_hook(state.base_user_vlm(user))
}

#[inline]
pub fn fold_user_scaled_vlm<S>(state: &S, acc: Ntl, user: &UserAddress) -> Ntl
where
    S: ScaledVlmStore,
{
    acc.saturating_add_scaled_vlm(user_scaled_and_raw_vlm(state, user).scaled)
}

pub fn fold_users_scaled_vlm<'a, S, I>(users: I, state: &S, mut acc: Ntl) -> Ntl
where
    S: ScaledVlmStore,
    I: IntoIterator<Item = &'a UserAddress>,
{
    for user in users {
        acc = fold_user_scaled_vlm(state, acc, user);
    }
    acc
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DailyScaledVlms {
    by_date_ordinal: BTreeMap<i32, ScaledAndRawVlm>,
}

impl DailyScaledVlms {
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.by_date_ordinal.is_empty()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.by_date_ordinal.len()
    }

    #[inline]
    pub fn get(&self, date_ordinal: i32) -> ScaledAndRawVlm {
        self.by_date_ordinal
            .get(&date_ordinal)
            .copied()
            .unwrap_or(ScaledAndRawVlm::ZERO)
    }

    /// Sums the previous `days` date ordinals, matching the recovered helper
    /// called by tier recomputation.  The raw side is accumulated to preserve the
    /// binary's overflow checks even when the caller only consumes `scaled`.
    pub fn sum_previous_days(&self, today_ordinal: i32, days: u32) -> ScaledAndRawVlm {
        if days == 0 {
            return ScaledAndRawVlm::ZERO;
        }

        let mut total = ScaledAndRawVlm::ZERO;
        let mut day = 1_u32;
        while day <= days {
            let date = today_ordinal.saturating_sub(day as i32);
            total = total.add_after_overflow_hook(self.get(date));
            day += 1;
        }
        total
    }

    /// Insert/update the current daily entry.  The binary rejects insertion when
    /// a user's daily map already has ten entries.
    pub fn record_current_day(
        &mut self,
        date_ordinal: i32,
        value: ScaledAndRawVlm,
    ) -> Result<(), DailyScaledVlmError> {
        if !self.by_date_ordinal.contains_key(&date_ordinal)
            && self.by_date_ordinal.len() >= MAX_DAILY_SCALED_VLM_ENTRIES
        {
            return Err(DailyScaledVlmError::TooManyEntries);
        }
        self.by_date_ordinal.insert(date_ordinal, value);
        Ok(())
    }

    #[inline]
    pub fn clear_user(&mut self) {
        self.by_date_ordinal.clear();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DailyScaledVlmError {
    TooEarly,
    TooLittle(ScaledVlm),
    TooManyEntries,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DailyScaledVlmUpdate {
    Applied,
    Cleared,
    TooEarly,
    TooLittle { scaled: ScaledVlm, display_value: f64 },
    TooManyEntries,
}

/// Source-level model of the recovered daily update gate.  `now_allowed` is the
/// result of the five-day timestamp comparison performed before insertion.
pub fn apply_daily_scaled_vlm_update<S>(
    state: &S,
    daily: &mut DailyScaledVlms,
    user: &UserAddress,
    date_ordinal: i32,
    now_allowed: bool,
    should_record: bool,
) -> DailyScaledVlmUpdate
where
    S: ScaledVlmStore,
{
    let total = user_scaled_and_raw_vlm(state, user);
    if total.scaled < MIN_DAILY_UPDATE_SCALED_VLM {
        return DailyScaledVlmUpdate::TooLittle {
            scaled: total.scaled,
            display_value: total.scaled.daily_update_shortfall_value(),
        };
    }

    if !should_record {
        daily.clear_user();
        return DailyScaledVlmUpdate::Cleared;
    }

    if !now_allowed {
        return DailyScaledVlmUpdate::TooEarly;
    }

    match daily.record_current_day(date_ordinal, total) {
        Ok(()) => DailyScaledVlmUpdate::Applied,
        Err(DailyScaledVlmError::TooManyEntries) => DailyScaledVlmUpdate::TooManyEntries,
        Err(DailyScaledVlmError::TooEarly | DailyScaledVlmError::TooLittle(_)) => unreachable!(),
    }
}

#[inline]
pub fn raw_vlm_from_perp_product(qty_raw: u64, px_raw: u64) -> Option<RawVlm> {
    qty_raw
        .checked_mul(px_raw)?
        .checked_div(PERP_NOTIONAL_PRODUCT_SCALE)
        .map(RawVlm::from_raw)
}

#[inline]
pub fn raw_vlm_from_spot_product(qty_raw: u64, px_raw: u64) -> Option<RawVlm> {
    qty_raw
        .checked_mul(px_raw)?
        .checked_div(SPOT_NOTIONAL_PRODUCT_SCALE)
        .map(RawVlm::from_raw)
}

#[inline]
pub fn action_limit_for_scaled_vlm(total_scaled: ScaledVlm, privileged_vault: bool) -> u64 {
    if privileged_vault {
        ScaledVlm::privileged_action_limit()
    } else {
        total_scaled.action_limit()
    }
}

#[inline]
pub fn scaled_vlm_priority(total_scaled: ScaledVlm) -> u64 {
    total_scaled.account_priority()
}

impl Add for ScaledVlm {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        self.saturating_add(rhs)
    }
}

impl AddAssign for ScaledVlm {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = self.saturating_add(rhs);
    }
}

impl Sub for ScaledVlm {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        self.saturating_sub(rhs)
    }
}

impl SubAssign for ScaledVlm {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.saturating_sub(rhs);
    }
}

impl From<u64> for ScaledVlm {
    #[inline]
    fn from(raw: u64) -> Self {
        Self(raw)
    }
}

impl From<ScaledVlm> for u64 {
    #[inline]
    fn from(value: ScaledVlm) -> Self {
        value.0
    }
}

impl FromStr for ScaledVlm {
    type Err = ScaledVlmParseError;

    #[inline]
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse_str(value)
    }
}

impl fmt::Debug for ScaledVlm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ScaledVlm").field(&self.0).finish()
    }
}

impl fmt::Display for ScaledVlm {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Ntl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ntl").field(&self.0).finish()
    }
}

#[cfg(feature = "serde")]
mod serde_impl {
    use super::{ScaledVlm, ScaledVlmParseError};
    use core::fmt;
    use serde::de::{self, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl Serialize for ScaledVlm {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                serializer.collect_str(self)
            } else {
                serializer.serialize_newtype_struct("ScaledVlm", &self.raw())
            }
        }
    }

    impl<'de> Deserialize<'de> for ScaledVlm {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                deserializer.deserialize_str(ScaledVlmVisitor)
            } else {
                deserializer.deserialize_newtype_struct("ScaledVlm", ScaledVlmVisitor)
            }
        }
    }

    struct ScaledVlmVisitor;

    impl<'de> Visitor<'de> for ScaledVlmVisitor {
        type Value = ScaledVlm;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("tuple struct ScaledVlm or a decimal scaled-volume string")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(ScaledVlm::from_raw(value))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            ScaledVlm::parse_str(value).map_err(scaled_vlm_parse_error)
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

    fn scaled_vlm_parse_error<E>(error: ScaledVlmParseError) -> E
    where
        E: de::Error,
    {
        match error {
            ScaledVlmParseError::Empty => E::custom("empty scaled volume"),
            ScaledVlmParseError::Sign => E::custom("scaled volume cannot be signed"),
            ScaledVlmParseError::InvalidByte(byte) => {
                E::custom(format_args!("invalid scaled volume byte 0x{byte:02x}"))
            }
            ScaledVlmParseError::Overflow => E::custom("scaled volume overflows u64"),
        }
    }
}
