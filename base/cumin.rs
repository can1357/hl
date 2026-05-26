//! Cumulative-minute helpers.
//!
//! The recovered hot paths inline this helper before day-boundary and sampler
//! reporting checks.  The inlined arithmetic is `hour * 60 + minute`, where
//! `hour = seconds_from_midnight / 3600` and `minute = (seconds_from_midnight / 60) % 60`.

use std::convert::TryFrom;

use chrono::{NaiveDateTime, Timelike};

pub const MIN_CUMIN: u16 = 0;
pub const MAX_CUMIN: u16 = 24 * 60;
pub const MINUTES_PER_HOUR: u16 = 60;
pub const SECONDS_PER_MINUTE: u32 = 60;
pub const SECONDS_PER_HOUR: u32 = 60 * SECONDS_PER_MINUTE;

/// Minute index in a UTC day, inclusive of `1440` for the exact day boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Cumin(u16);

impl Cumin {
    #[inline]
    pub fn new(cumin: u16) -> Self {
        assert!(cumin <= MAX_CUMIN);
        Self(cumin)
    }

    #[inline]
    pub fn get(self) -> u16 {
        self.0
    }

    /// Convert seconds-from-midnight into the cumulative minute used by state
    /// samplers and time-gated block handling.
    ///
    /// Recovered panic behavior:
    /// - convert the computed `u32` with `u16::try_from(...).unwrap()`;
    /// - then assert `cumin <= 1440`.
    #[inline]
    pub fn from_seconds_from_midnight(seconds_from_midnight: u32) -> Self {
        let hour = seconds_from_midnight / SECONDS_PER_HOUR;
        let minute = (seconds_from_midnight / SECONDS_PER_MINUTE) % u32::from(MINUTES_PER_HOUR);
        let cumin = u16::try_from(hour * u32::from(MINUTES_PER_HOUR) + minute).unwrap();
        Self::new(cumin)
    }

    #[inline]
    pub fn from_naive_datetime(datetime: NaiveDateTime) -> Self {
        let cumin = u16::try_from(datetime.hour() * u32::from(MINUTES_PER_HOUR) + datetime.minute()).unwrap();
        Self::new(cumin)
    }

    #[inline]
    pub fn hour(self) -> u16 {
        self.0 / MINUTES_PER_HOUR
    }

    #[inline]
    pub fn minute(self) -> u16 {
        self.0 % MINUTES_PER_HOUR
    }

    #[inline]
    pub fn is_day_boundary(self) -> bool {
        self.0 == MAX_CUMIN
    }
}

#[inline]
pub fn seconds_from_midnight_to_cumin(seconds_from_midnight: u32) -> u16 {
    Cumin::from_seconds_from_midnight(seconds_from_midnight).get()
}

#[inline]
pub fn naive_datetime_to_cumin(datetime: NaiveDateTime) -> u16 {
    Cumin::from_naive_datetime(datetime).get()
}

impl From<Cumin> for u16 {
    #[inline]
    fn from(cumin: Cumin) -> Self {
        cumin.0
    }
}

