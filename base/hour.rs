use std::fmt;
use std::io::{self, Write};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{Datelike, Duration as ChronoDuration, NaiveDate, NaiveDateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};

use crate::liner::{Liner, LinerTime};

pub const SECONDS_PER_HOUR: u32 = 3_600;
pub const SECONDS_PER_DAY: i64 = 86_400;
pub const MILLIS_PER_SECOND: i64 = 1_000;
pub const MILLIS_PER_DAY: i64 = 86_400_000;
pub const MICROS_PER_SECOND: i64 = 1_000_000;
pub const NANOS_PER_SECOND: i64 = 1_000_000_000;
pub const UNIX_EPOCH_DAYS_FROM_CE: i32 = 719_163;

const DATE_FORMAT_YYYYMMDD: &str = "%Y%m%d";
const CHRONO_UNWRAP_UPPER_BOUND_SECONDS: u32 = 0xE1000;
const ASSERTED_MAX_SECONDS_OF_DAY: u32 = 0x15F90;
const ACCUMULATOR_BUCKET_PREFIX: &str = "accumulator_buckets/";
const ACCUMULATOR_BUCKET_PERIOD_SECONDS: f64 = 30.0;

static FORCE_FLUSH_DAILY_LINERS: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct Date(pub NaiveDate);

impl Date {
    #[inline]
    pub fn from_naive_date(date: NaiveDate) -> Self {
        Self(date)
    }

    #[inline]
    pub fn from_naive_datetime(datetime: NaiveDateTime) -> Self {
        Self(datetime.date())
    }

    #[inline]
    pub fn today_utc() -> Self {
        Self::from_naive_datetime(utc_now_naive_datetime())
    }

    #[inline]
    pub fn as_naive_date(self) -> NaiveDate {
        self.0
    }

    #[inline]
    pub fn num_days_from_ce(self) -> i32 {
        self.0.num_days_from_ce()
    }

    pub fn from_yyyymmdd_number(value: i32) -> Result<Self, ParseDateError> {
        if value < 0 {
            return Err(ParseDateError);
        }

        let year = value / 10_000;
        let month = ((value / 100) % 100) as u32;
        let day = (value % 100) as u32;
        NaiveDate::from_ymd_opt(year, month, day)
            .map(Self)
            .ok_or(ParseDateError)
    }

    #[inline]
    pub fn yyyymmdd_number(self) -> i32 {
        self.0.year() * 10_000 + self.0.month() as i32 * 100 + self.0.day() as i32
    }

    pub fn parse_yyyymmdd(input: &str) -> Result<Self, ParseDateError> {
        let bytes = input.as_bytes();
        if bytes.len() != 8 || !bytes.iter().all(u8::is_ascii_digit) {
            return Err(ParseDateError);
        }

        let mut value = 0i32;
        for &byte in bytes {
            value = value * 10 + i32::from(byte - b'0');
        }
        Self::from_yyyymmdd_number(value)
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.format(DATE_FORMAT_YYYYMMDD).fmt(f)
    }
}

impl fmt::Debug for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl From<NaiveDate> for Date {
    #[inline]
    fn from(date: NaiveDate) -> Self {
        Self::from_naive_date(date)
    }
}

impl FromStr for Date {
    type Err = ParseDateError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse_yyyymmdd(input)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseDateError;

impl fmt::Display for ParseDateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid yyyymmdd date")
    }
}

impl std::error::Error for ParseDateError {}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct Hour(u8);

impl Hour {
    pub const MIN: Self = Self(0);
    pub const MAX: Self = Self(24);

    #[inline]
    pub fn new(hour: u8) -> Self {
        assert!(hour <= Self::MAX.0, "assertion failed: hour <= 24");
        Self(hour)
    }

    #[inline]
    pub fn get(self) -> u8 {
        self.0
    }

    #[inline]
    pub fn from_naive_datetime(datetime: NaiveDateTime) -> Self {
        Self::from_seconds_from_midnight(datetime.num_seconds_from_midnight())
    }

    #[inline]
    pub fn from_seconds_from_midnight(seconds_from_midnight: u32) -> Self {
        if seconds_from_midnight >= CHRONO_UNWRAP_UPPER_BOUND_SECONDS {
            panic!("called Result::unwrap() on an Err value");
        }
        assert!(
            seconds_from_midnight < ASSERTED_MAX_SECONDS_OF_DAY,
            "assertion failed: hour <= 24"
        );
        Self::new((seconds_from_midnight / SECONDS_PER_HOUR) as u8)
    }
}

impl fmt::Display for Hour {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => f.write_str("0"),
            1 => f.write_str("1"),
            2 => f.write_str("2"),
            3 => f.write_str("3"),
            4 => f.write_str("4"),
            5 => f.write_str("5"),
            6 => f.write_str("6"),
            7 => f.write_str("7"),
            8 => f.write_str("8"),
            9 => f.write_str("9"),
            10 => f.write_str("10"),
            11 => f.write_str("11"),
            12 => f.write_str("12"),
            13 => f.write_str("13"),
            14 => f.write_str("14"),
            15 => f.write_str("15"),
            16 => f.write_str("16"),
            17 => f.write_str("17"),
            18 => f.write_str("18"),
            19 => f.write_str("19"),
            20 => f.write_str("20"),
            21 => f.write_str("21"),
            22 => f.write_str("22"),
            23 => f.write_str("23"),
            24 => f.write_str("24"),
            _ => unreachable!("Hour::new validates the range"),
        }
    }
}

impl fmt::Debug for Hour {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl TryFrom<u8> for Hour {
    type Error = ParseHourError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value <= Self::MAX.0 {
            Ok(Self(value))
        } else {
            Err(ParseHourError)
        }
    }
}

impl From<Hour> for u8 {
    #[inline]
    fn from(hour: Hour) -> Self {
        hour.0
    }
}

impl FromStr for Hour {
    type Err = ParseHourError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let value = input.parse::<u8>().map_err(|_| ParseHourError)?;
        Self::try_from(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseHourError;

impl fmt::Display for ParseHourError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid hour")
    }
}

impl std::error::Error for ParseHourError {}

#[inline]
pub fn hour_from_time(datetime: NaiveDateTime) -> Hour {
    Hour::from_naive_datetime(datetime)
}

#[inline]
pub fn date_and_hour(datetime: NaiveDateTime) -> (Date, Hour) {
    (Date::from_naive_datetime(datetime), Hour::from_naive_datetime(datetime))
}

#[inline]
pub fn utc_now_naive_datetime() -> NaiveDateTime {
    Utc::now().naive_utc()
}

#[inline]
pub fn naive_datetime_to_unix_millis_or_zero(datetime: NaiveDateTime) -> i64 {
    let days = i64::from(datetime.date().num_days_from_ce() - UNIX_EPOCH_DAYS_FROM_CE);
    let millis = days * MILLIS_PER_DAY
        + i64::from(datetime.num_seconds_from_midnight()) * MILLIS_PER_SECOND
        + i64::from(datetime.timestamp_subsec_nanos() / 1_000_000);
    millis.max(0)
}

#[inline]
pub fn unix_seconds_f64_now() -> f64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => {
            let micros = duration
                .as_secs()
                .saturating_mul(MICROS_PER_SECOND as u64)
                .saturating_add(u64::from(duration.subsec_nanos() / 1_000));
            micros as f64 / MICROS_PER_SECOND as f64
        }
        Err(_) => 0.0,
    }
}

#[inline]
pub fn checked_add_seconds(datetime: NaiveDateTime, seconds: i64) -> NaiveDateTime {
    datetime
        .checked_add_signed(ChronoDuration::seconds(seconds))
        .expect("`NaiveDateTime + TimeDelta` overflowed")
}

#[inline]
pub fn hour_with_offset(datetime: NaiveDateTime, offset_seconds: i64) -> Hour {
    Hour::from_naive_datetime(checked_add_seconds(datetime, offset_seconds))
}

#[inline]
pub fn date_and_hour_with_offset(datetime: NaiveDateTime, offset_seconds: i64) -> (Date, Hour) {
    date_and_hour(checked_add_seconds(datetime, offset_seconds))
}

#[inline]
pub fn hour_boundary_changed_with_offset(
    previous: NaiveDateTime,
    current: NaiveDateTime,
    offset_seconds: i64,
) -> bool {
    date_and_hour_with_offset(previous, offset_seconds) != date_and_hour_with_offset(current, offset_seconds)
}

#[derive(Debug)]
pub struct DailyLiner {
    root: String,
    liner: Liner,
    current_date: Date,
    last_write_at: NaiveDateTime,
    hourly: bool,
    current_hour: Hour,
    force_flush: bool,
}

impl DailyLiner {
    pub fn new(prefix: &str) -> Self {
        Self::new_in_run_dir(crate::production::run_dir(), prefix)
    }

    pub fn new_in_run_dir(run_dir: impl AsRef<str>, prefix: &str) -> Self {
        validate_liner_prefix(prefix);

        let now = utc_now_naive_datetime();
        let date = Date::from_naive_datetime(now);
        let raw_root = format!("{}/data/{}", run_dir.as_ref(), prefix);
        let root = unique_daily_liner_root(&raw_root);
        let liner = Liner::from_path(daily_path(&root, date));

        Self {
            root,
            liner,
            current_date: date,
            last_write_at: now,
            hourly: false,
            current_hour: Hour::MIN,
            force_flush: false,
        }
    }

    #[inline]
    pub fn root(&self) -> &str {
        &self.root
    }

    #[inline]
    pub fn is_hourly(&self) -> bool {
        self.hourly
    }

    #[inline]
    pub fn current_date(&self) -> Date {
        self.current_date
    }

    #[inline]
    pub fn current_hour(&self) -> Hour {
        self.current_hour
    }

    #[inline]
    pub fn last_write_at(&self) -> NaiveDateTime {
        self.last_write_at
    }

    #[inline]
    pub fn set_force_flush(&mut self, force_flush: bool) {
        self.force_flush = force_flush;
    }

    pub fn into_hourly(mut self) -> Self {
        self.force_hourly_rotation();
        self
    }

    pub fn force_hourly_rotation(&mut self) {
        let now = utc_now_naive_datetime();
        let date = Date::from_naive_datetime(now);
        let hour = Hour::from_naive_datetime(now);
        self.liner = Liner::from_path(hourly_path(&self.root, date, hour));
        self.current_date = date;
        self.current_hour = hour;
        self.hourly = true;
        self.last_write_at = now;
    }

    pub fn write_bytes(&mut self, timestamp: NaiveDateTime, bytes: &[u8]) {
        self.rotate_for_timestamp(timestamp);
        self.liner.write_bytes(liner_time(timestamp), bytes);
        self.last_write_at = timestamp;
        self.flush_if_forced();
    }

    pub fn write_owned_line(&mut self, mut line: Vec<u8>) -> NaiveDateTime {
        let timestamp = utc_now_naive_datetime();
        self.rotate_for_timestamp(timestamp);
        line.push(b'\n');
        self.liner.write_bytes(liner_time(timestamp), &line);
        self.last_write_at = timestamp;
        self.flush_if_forced();
        timestamp
    }

    pub fn write_line(&mut self, timestamp: NaiveDateTime, line: impl AsRef<[u8]>) {
        let bytes = line.as_ref();
        let mut owned = Vec::with_capacity(bytes.len() + 1);
        owned.extend_from_slice(bytes);
        owned.push(b'\n');
        self.write_bytes(timestamp, &owned);
    }

    fn rotate_for_timestamp(&mut self, timestamp: NaiveDateTime) {
        let date = Date::from_naive_datetime(timestamp);
        if self.hourly {
            let hour = Hour::from_naive_datetime(timestamp);
            if date != self.current_date || hour != self.current_hour {
                self.liner = Liner::from_path(hourly_path(&self.root, date, hour));
                self.current_date = date;
                self.current_hour = hour;
            }
        } else if date != self.current_date {
            self.liner = Liner::from_path(daily_path(&self.root, date));
            self.current_date = date;
        }
    }

    #[inline]
    fn flush_if_forced(&mut self) {
        if self.force_flush && FORCE_FLUSH_DAILY_LINERS.load(Ordering::Relaxed) {
            self.liner.flush_suppressing_errors();
        }
    }
}

pub fn set_global_daily_liner_flush_enabled(enabled: bool) {
    FORCE_FLUSH_DAILY_LINERS.store(enabled, Ordering::Relaxed);
}

pub fn global_daily_liner_flush_enabled() -> bool {
    FORCE_FLUSH_DAILY_LINERS.load(Ordering::Relaxed)
}

#[inline]
pub fn daily_path(root: &str, date: Date) -> String {
    format!("{root}/{date}")
}

#[inline]
pub fn hourly_path(root: &str, date: Date, hour: Hour) -> String {
    format!("{root}/hourly/{date}/{hour}")
}

pub fn validate_liner_prefix(prefix: &str) {
    if !prefix.is_empty() && (prefix.as_bytes()[0] == b'/' || prefix.as_bytes()[prefix.len() - 1] == b'/') {
        panic!("assertion failed: !prefix.starts_with('/') && !prefix.ends_with('/')");
    }
}

fn unique_daily_liner_root(raw_root: &str) -> String {
    // [INFERENCE] The call target is the base singleton helper named with random suffix
    // behavior. The decompiled caller stores only the returned string in DailyLiner.
    crate::singleton_set::SingletonSet::new_with_random_suffix::<DailyLiner>(raw_root)
        .name()
        .to_owned()
}

#[derive(Debug)]
pub struct AccumulatorBucketLiner {
    name: String,
    liner: DailyLiner,
    pending_n: u64,
    pending_delta: i64,
    period_seconds: f64,
    last_emit_at: Option<NaiveDateTime>,
}

impl AccumulatorBucketLiner {
    pub fn new(name: &str) -> Self {
        let prefix = format!("{ACCUMULATOR_BUCKET_PREFIX}{name}");
        let liner = DailyLiner::new(&prefix).into_hourly();
        Self {
            name: name.to_owned(),
            liner,
            pending_n: 0,
            pending_delta: 0,
            period_seconds: ACCUMULATOR_BUCKET_PERIOD_SECONDS,
            last_emit_at: None,
        }
    }

    pub fn new_in_run_dir(run_dir: impl AsRef<str>, name: &str) -> Self {
        let prefix = format!("{ACCUMULATOR_BUCKET_PREFIX}{name}");
        let liner = DailyLiner::new_in_run_dir(run_dir, &prefix).into_hourly();
        Self {
            name: name.to_owned(),
            liner,
            pending_n: 0,
            pending_delta: 0,
            period_seconds: ACCUMULATOR_BUCKET_PERIOD_SECONDS,
            last_emit_at: None,
        }
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    pub fn pending_n(&self) -> u64 {
        self.pending_n
    }

    #[inline]
    pub fn pending_delta(&self) -> i64 {
        self.pending_delta
    }

    pub fn accumulate_and_maybe_emit(&mut self, delta: i64) {
        let now = utc_now_naive_datetime();
        self.accumulate_and_maybe_emit_at(now, delta);
    }

    pub fn accumulate_and_maybe_emit_at(&mut self, now: NaiveDateTime, delta: i64) {
        self.pending_n = self.pending_n.saturating_add(1);
        self.pending_delta = self.pending_delta.saturating_add(delta);

        if let Some(previous) = self.last_emit_at {
            if seconds_since_or_zero(now, previous) <= self.period_seconds {
                return;
            }
        }

        self.last_emit_at = Some(now);
        let sample = AccumulatorBucketSample {
            time: now,
            n: self.pending_n,
            delta: self.pending_delta,
        };
        self.write_sample(&sample).unwrap();
        self.pending_n = 0;
        self.pending_delta = 0;
    }

    fn write_sample(&mut self, sample: &AccumulatorBucketSample) -> io::Result<()> {
        let mut row = Vec::with_capacity(128);
        serialize_accumulator_bucket_sample(sample, &mut row)?;
        row.push(b'\n');
        self.liner.write_bytes(sample.time, &row);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct AccumulatorBucketSample {
    pub time: NaiveDateTime,
    pub n: u64,
    pub delta: i64,
}

pub fn serialize_accumulator_bucket_sample(
    sample: &AccumulatorBucketSample,
    out: &mut Vec<u8>,
) -> io::Result<()> {
    write!(
        out,
        "{{\"time\":\"{}\",\"n\":{},\"delta\":{}}}",
        sample.time, sample.n, sample.delta
    )
}

#[inline]
fn seconds_since_or_zero(later: NaiveDateTime, earlier: NaiveDateTime) -> f64 {
    if later <= earlier {
        0.0
    } else {
        let delta = later - earlier;
        delta.num_microseconds().unwrap_or(i64::MAX) as f64 / MICROS_PER_SECOND as f64
    }
}

#[inline]
fn liner_time(timestamp: NaiveDateTime) -> LinerTime {
    LinerTime {
        unix_seconds: timestamp.timestamp(),
        nanos: timestamp.timestamp_subsec_nanos(),
    }
}
