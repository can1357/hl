use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::str::FromStr;
use std::time::{Duration as StdDuration, SystemTime, UNIX_EPOCH};

use chrono::{Datelike, NaiveDate, NaiveDateTime, Timelike, Utc};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const NANOS_PER_SECOND: u32 = 1_000_000_000;
pub const MICROS_PER_SECOND: u64 = 1_000_000;
pub const MILLIS_PER_SECOND: u64 = 1_000;
pub const NANOS_PER_MILLI: u64 = 1_000_000;
pub const SECONDS_PER_MINUTE: u32 = 60;
pub const SECONDS_PER_HOUR: u32 = 3_600;
pub const SECONDS_PER_DAY: u64 = 86_400;
pub const MILLIS_PER_DAY: u64 = 86_400_000;
pub const UNIX_EPOCH_DAYS_FROM_CE: i32 = 719_163;

const COMPACT_DATE_FORMAT: &str = "%Y%m%d";
const UTC_SECONDS_FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";
const UTC_MILLIS_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.3fZ";
const CHRONO_UNWRAP_UPPER_BOUND_SECONDS: u32 = 0xE1000;
const ASSERTED_MAX_SECONDS_OF_DAY: u32 = 0x15F90;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimeError {
    UnixMillisOutOfRange(u64),
    InvalidCompactDate,
    InvalidNanoseconds(u32),
    Io(io::ErrorKind, String),
    SystemTimeBeforeEpoch(StdDuration),
    ChronoRange,
    Parse(String),
}

impl fmt::Display for TimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnixMillisOutOfRange(millis) => {
                write!(f, "from_unix_millis: out-of-range input {millis}")
            }
            Self::InvalidCompactDate => f.write_str("invalid yyyymmdd date"),
            Self::InvalidNanoseconds(nanos) => write!(f, "invalid time nanos={nanos}"),
            Self::Io(_, err) => f.write_str(err),
            Self::SystemTimeBeforeEpoch(duration) => write!(f, "SystemTimeError({duration:?})"),
            Self::ChronoRange => f.write_str("input is out of range"),
            Self::Parse(err) => f.write_str(err),
        }
    }
}

impl std::error::Error for TimeError {}

impl From<chrono::ParseError> for TimeError {
    fn from(err: chrono::ParseError) -> Self {
        Self::Parse(err.to_string())
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Time(pub NaiveDateTime);

impl Time {
    #[inline]
    pub const fn new(datetime: NaiveDateTime) -> Self {
        Self(datetime)
    }

    #[inline]
    pub fn now() -> Self {
        Self(utc_now_naive_datetime())
    }

    #[inline]
    pub fn as_naive_datetime(self) -> NaiveDateTime {
        self.0
    }

    #[inline]
    pub fn to_unix_millis(self) -> u64 {
        naive_datetime_to_unix_millis(self.0)
    }

    #[inline]
    pub fn from_unix_millis(millis: u64) -> Result<Self, TimeError> {
        from_unix_millis(millis).map(Self)
    }

    #[inline]
    pub fn hour(self) -> u32 {
        hour_from_naive_datetime(self.0)
    }

    #[inline]
    pub fn checked_add_seconds(self, seconds: i32) -> Option<Self> {
        checked_add_seconds_to_naive_datetime(self.0, seconds).map(Self)
    }

    #[inline]
    pub fn format_utc_millis(self) -> String {
        format_utc_millis(self.0)
    }
}

impl Default for Time {
    #[inline]
    fn default() -> Self {
        Self(NaiveDateTime::from_timestamp_opt(0, 0).expect("Unix epoch is a valid NaiveDateTime"))
    }
}

impl fmt::Debug for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Time").field(&self.0).finish()
    }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.format(UTC_MILLIS_FORMAT))
    }
}

impl From<NaiveDateTime> for Time {
    #[inline]
    fn from(datetime: NaiveDateTime) -> Self {
        Self(datetime)
    }
}

impl From<Time> for NaiveDateTime {
    #[inline]
    fn from(time: Time) -> Self {
        time.0
    }
}

impl FromStr for Time {
    type Err = TimeError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_time_string(input).map(Self)
    }
}

impl Serialize for Time {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("Time", &self.format_utc_millis())
    }
}

impl<'de> Deserialize<'de> for Time {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_newtype_struct("Time", TimeVisitor)
    }
}

pub fn deserialize_nullable_time<'de, D>(deserializer: D) -> Result<Option<Time>, D::Error>
where
    D: Deserializer<'de>,
{
    struct NullableTimeVisitor;

    impl<'de> Visitor<'de> for NullableTimeVisitor {
        type Value = Option<Time>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("tuple struct Time")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            Time::deserialize(deserializer).map(Some)
        }
    }

    deserializer.deserialize_option(NullableTimeVisitor)
}

struct TimeVisitor;

impl<'de> Visitor<'de> for TimeVisitor {
    type Value = Time;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("tuple struct Time")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Time::from_str(value).map_err(E::custom)
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
        let value = String::deserialize(deserializer)?;
        Time::from_str(&value).map_err(de::Error::custom)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let value: String = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(0, &"tuple struct Time with 1 element"))?;
        Time::from_str(&value).map_err(de::Error::custom)
    }
}

#[inline]
pub fn utc_now_naive_datetime() -> NaiveDateTime {
    system_time_to_naive_datetime(SystemTime::now()).expect("SystemTime before Unix epoch")
}

#[inline]
pub fn now_unix_seconds_f64() -> f64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration_to_seconds_f64_truncated_to_micros(duration),
        Err(err) => duration_to_seconds_f64_truncated_to_micros(err.duration()),
    }
}

#[inline]
pub fn duration_to_seconds_f64_truncated_to_micros(duration: StdDuration) -> f64 {
    let micros = duration
        .as_secs()
        .saturating_mul(MICROS_PER_SECOND)
        .saturating_add(u64::from(duration.subsec_nanos() / 1_000));
    micros as f64 / MICROS_PER_SECOND as f64
}

pub fn system_time_to_naive_datetime(time: SystemTime) -> Result<NaiveDateTime, TimeError> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .map_err(|err| TimeError::SystemTimeBeforeEpoch(err.duration()))?;
    duration_since_epoch_to_naive_datetime(duration)
}

pub fn duration_since_epoch_to_naive_datetime(duration: StdDuration) -> Result<NaiveDateTime, TimeError> {
    let secs = duration.as_secs();
    let days = secs / SECONDS_PER_DAY;
    let days_from_ce = days
        .checked_add(UNIX_EPOCH_DAYS_FROM_CE as u64)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or(TimeError::ChronoRange)?;
    let seconds_from_midnight = (secs % SECONDS_PER_DAY) as u32;
    let date = NaiveDate::from_num_days_from_ce_opt(days_from_ce).ok_or(TimeError::ChronoRange)?;
    date.and_hms_nano_opt(
        seconds_from_midnight / SECONDS_PER_HOUR,
        (seconds_from_midnight % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE,
        seconds_from_midnight % SECONDS_PER_MINUTE,
        duration.subsec_nanos(),
    )
    .ok_or(TimeError::ChronoRange)
}

pub fn from_unix_millis(millis: u64) -> Result<NaiveDateTime, TimeError> {
    let secs = millis / MILLIS_PER_SECOND;
    let millis_of_second = millis % MILLIS_PER_SECOND;
    let nanos = (millis_of_second * NANOS_PER_MILLI) as u32;
    let secs = i64::try_from(secs).map_err(|_| TimeError::UnixMillisOutOfRange(millis))?;
    NaiveDateTime::from_timestamp_opt(secs, nanos).ok_or(TimeError::UnixMillisOutOfRange(millis))
}

pub fn naive_datetime_to_unix_millis(datetime: NaiveDateTime) -> u64 {
    let days = i64::from(datetime.date().num_days_from_ce() - UNIX_EPOCH_DAYS_FROM_CE);
    let millis = days
        .saturating_mul(MILLIS_PER_DAY as i64)
        .saturating_add(i64::from(datetime.num_seconds_from_midnight()) * MILLIS_PER_SECOND as i64)
        .saturating_add(i64::from(datetime.timestamp_subsec_nanos() / 1_000_000));
    millis.max(0) as u64
}

pub fn checked_add_seconds_to_naive_datetime(
    datetime: NaiveDateTime,
    delta_secs: i32,
) -> Option<NaiveDateTime> {
    datetime.checked_add_signed(chrono::Duration::seconds(i64::from(delta_secs)))
}

pub fn hour_from_naive_datetime(datetime: NaiveDateTime) -> u32 {
    let seconds_from_midnight = datetime.num_seconds_from_midnight();
    if seconds_from_midnight >= CHRONO_UNWRAP_UPPER_BOUND_SECONDS {
        panic!("called Result::unwrap() on an Err value");
    }
    assert!(
        seconds_from_midnight < ASSERTED_MAX_SECONDS_OF_DAY,
        "assertion failed: hour <= 24"
    );
    seconds_from_midnight / SECONDS_PER_HOUR
}

pub fn seconds_since_or_zero(later: NaiveDateTime, earlier: NaiveDateTime) -> f64 {
    if later < earlier {
        tracing::error!(?later, ?earlier, "Time Sub");
        return 0.0;
    }

    later
        .signed_duration_since(earlier)
        .num_microseconds()
        .map(|micros| micros as f64 / MICROS_PER_SECOND as f64)
        .unwrap_or(0.0)
}

#[inline]
pub fn packed_date_delta_secs(lhs: NaiveDate, rhs: NaiveDate) -> i64 {
    i64::from(lhs.num_days_from_ce() - rhs.num_days_from_ce()) * SECONDS_PER_DAY as i64
}

pub fn format_yyyymmdd(date: NaiveDate) -> String {
    date.format(COMPACT_DATE_FORMAT).to_string()
}

pub fn fmt_yyyymmdd(date: &NaiveDate, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", date.format(COMPACT_DATE_FORMAT))
}

pub fn parse_yyyymmdd(input: &str) -> Result<NaiveDate, TimeError> {
    let bytes = input.as_bytes();
    if bytes.len() != 8 || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(TimeError::InvalidCompactDate);
    }

    let year = parse_two_or_four_digits(&bytes[0..4])?;
    let month = parse_two_or_four_digits(&bytes[4..6])?;
    let day = parse_two_or_four_digits(&bytes[6..8])?;
    NaiveDate::from_ymd_opt(year, month as u32, day as u32).ok_or(TimeError::InvalidCompactDate)
}

fn parse_two_or_four_digits(bytes: &[u8]) -> Result<i32, TimeError> {
    let mut value = 0i32;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return Err(TimeError::InvalidCompactDate);
        }
        value = value * 10 + i32::from(byte - b'0');
    }
    Ok(value)
}

pub fn parse_utc_naive(input: &str) -> Result<NaiveDateTime, chrono::ParseError> {
    NaiveDateTime::parse_from_str(input, UTC_SECONDS_FORMAT)
}

pub fn format_utc_naive(datetime: NaiveDateTime) -> String {
    datetime.format(UTC_SECONDS_FORMAT).to_string()
}

pub fn format_utc_millis(datetime: NaiveDateTime) -> String {
    datetime.format(UTC_MILLIS_FORMAT).to_string()
}

pub fn parse_time_string(input: &str) -> Result<NaiveDateTime, TimeError> {
    NaiveDateTime::parse_from_str(input, UTC_MILLIS_FORMAT)
        .or_else(|_| NaiveDateTime::parse_from_str(input, UTC_SECONDS_FORMAT))
        .map_err(TimeError::from)
}

pub fn path_metadata_exists(path: impl AsRef<Path>) -> bool {
    fs::metadata(path).is_ok()
}

pub fn path_is_dir(path: impl AsRef<Path>) -> bool {
    match fs::metadata(path) {
        Ok(metadata) => metadata.is_dir(),
        Err(_) => false,
    }
}

pub fn path_is_regular_file(path: impl AsRef<Path>) -> bool {
    match fs::metadata(path) {
        Ok(metadata) => metadata.is_file(),
        Err(_) => false,
    }
}

pub fn path_len_is_zero(path: impl AsRef<Path>) -> bool {
    match fs::metadata(path) {
        Ok(metadata) => metadata.len() == 0,
        Err(_) => false,
    }
}

pub fn stat_modified_chrono(path: impl AsRef<Path>) -> Result<NaiveDateTime, TimeError> {
    let metadata = fs::metadata(path.as_ref()).map_err(|err| TimeError::Io(err.kind(), err.to_string()))?;
    let modified = metadata
        .modified()
        .map_err(|err| TimeError::Io(err.kind(), err.to_string()))?;
    let duration = modified
        .duration_since(UNIX_EPOCH)
        .map_err(|err| TimeError::SystemTimeBeforeEpoch(err.duration()))?;

    if duration.subsec_nanos() >= NANOS_PER_SECOND {
        return Err(TimeError::InvalidNanoseconds(duration.subsec_nanos()));
    }
    if duration.as_secs() > u32::MAX as u64 {
        return Err(TimeError::ChronoRange);
    }

    let whole_seconds = StdDuration::new(duration.as_secs(), 0);
    duration_since_epoch_to_naive_datetime(whole_seconds)
}

pub fn path_age_seconds(path: impl AsRef<Path>) -> Result<f64, String> {
    let path = path.as_ref();
    let metadata = fs::metadata(path)
        .map_err(|err| format_fod_age_metadata_error(path, &err))?;
    let modified = metadata
        .modified()
        .map_err(|err| format_fod_age_mtime_error(path, &err))?;
    let elapsed = SystemTime::now()
        .duration_since(modified)
        .map_err(|err| format!("fod_age could not convert file mtime to SystemDuration {}: {err}", path.display()))?;
    Ok(duration_to_seconds_f64_truncated_to_micros(elapsed))
}

pub fn format_fod_age_mtime_error(path: &Path, err: &dyn fmt::Display) -> String {
    format!("fod_age could not get file mtime {}: {err}", path.display())
}

pub fn format_fod_age_metadata_error(path: &Path, err: &dyn fmt::Display) -> String {
    format!("fod_age metadata {}: {err}", path.display())
}

#[inline]
pub fn utc_now_time() -> Time {
    Time::now()
}

#[inline]
pub fn utc_now_millis() -> u64 {
    naive_datetime_to_unix_millis(utc_now_naive_datetime())
}

#[inline]
pub fn utc_now_string_millis() -> String {
    format_utc_millis(Utc::now().naive_utc())
}
