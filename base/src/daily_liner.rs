use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{Datelike, NaiveDate, NaiveDateTime, Timelike, Utc};

use crate::liner::{Liner, LinerTime};
use crate::singleton_set::SingletonSet;

const DATA_COMPONENT: &str = "data";
const HOURLY_COMPONENT: &str = "hourly";
const SECONDS_PER_HOUR: u32 = 3_600;
const MAX_ACCEPTED_SECONDS_OF_DAY: u32 = 90_000;

/// Wall-clock timestamp used by the daily liner.
///
/// The binary passes a compact chrono-like value into the write functions:
/// day, second-of-day, and nanosecond.  Rotation uses the formatted date and
/// `second_of_day / 3600`; the inner `Liner` receives the same instant for its
/// periodic flush policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DailyLinerTime {
    pub date: NaiveDate,
    pub second_of_day: u32,
    pub nanosecond: u32,
}

impl DailyLinerTime {
    pub fn now_utc() -> Self {
        Self::from_naive_utc(Utc::now().naive_utc())
    }

    pub fn from_naive_utc(ts: NaiveDateTime) -> Self {
        Self {
            date: ts.date(),
            second_of_day: ts.time().num_seconds_from_midnight(),
            nanosecond: ts.time().nanosecond(),
        }
    }

    pub fn from_unix_parts(unix_seconds: i64, nanosecond: u32) -> Self {
        let ts = NaiveDateTime::from_timestamp_opt(unix_seconds, nanosecond)
            .unwrap_or_else(|| NaiveDateTime::from_timestamp_opt(0, 0).unwrap());
        Self::from_naive_utc(ts)
    }

    #[inline]
    pub fn hour(self) -> u8 {
        let hour = self.second_of_day / SECONDS_PER_HOUR;
        assert!(hour <= 24, "assertion failed: hour <= 24");
        hour as u8
    }

    #[inline]
    pub fn as_liner_time(self) -> LinerTime {
        let midnight = self.date.and_hms_opt(0, 0, 0).unwrap();
        LinerTime {
            unix_seconds: midnight.and_utc().timestamp() + self.second_of_day as i64,
            nanos: self.nanosecond,
        }
    }

    #[inline]
    fn validate(self) {
        // The decompiled path contains an unwrap edge before the explicit hour
        // assertion, then asserts that the derived hour is no larger than 24.
        if self.second_of_day >= MAX_ACCEPTED_SECONDS_OF_DAY {
            panic!("assertion failed: hour <= 24");
        }
    }
}

/// Daily/hourly rotating line writer.
///
/// Recovered behavior:
/// - keys must not start or end with `/`;
/// - the base path is `<run-root>/data/<key>`, registered through the singleton
///   set with a random suffix on collision;
/// - construction opens `<base>/<yyyymmdd>`;
/// - `force_hourly_rotation` switches to `<base>/hourly/<yyyymmdd>/<hour>` and
///   removes the old daily file when it still exists but is empty;
/// - writes rotate on date changes in daily mode, and on date/hour changes in
///   hourly mode;
/// - the inner `Liner` performs buffered writes and timestamp-based flushes;
/// - callers can request an extra flush after every write.
#[derive(Debug)]
pub struct DailyLiner {
    base_path: String,
    _singleton: SingletonSet,
    liner: Option<Liner>,
    current_date: NaiveDate,
    last_write_time: DailyLinerTime,
    hourly_mode: bool,
    current_hour: u8,
    flush_each_write: bool,
}

impl DailyLiner {
    /// IDA: `base_daily_liner__new` (`0x1402050`).
    pub fn new(key: &str, flush_each_write: bool) -> Self {
        Self::new_in_run_root(default_run_root(), key, flush_each_write)
    }

    pub fn new_in_run_root(run_root: impl AsRef<Path>, key: &str, flush_each_write: bool) -> Self {
        validate_key(key);

        let base_path = data_path(run_root.as_ref(), key);
        let singleton = SingletonSet::new_with_random_suffix::<DailyLiner>(&base_path);
        let base_path = singleton.name().to_owned();
        let now = DailyLinerTime::now_utc();
        let daily_path = daily_path(&base_path, now.date);

        Self {
            base_path,
            _singleton: singleton,
            liner: Some(Liner::from_path(daily_path)),
            current_date: now.date,
            last_write_time: now,
            hourly_mode: false,
            current_hour: 0,
            flush_each_write,
        }
    }

    #[inline]
    pub fn base_path(&self) -> &str {
        &self.base_path
    }

    #[inline]
    pub fn current_date(&self) -> NaiveDate {
        self.current_date
    }

    #[inline]
    pub fn hourly_mode(&self) -> bool {
        self.hourly_mode
    }

    #[inline]
    pub fn current_hour(&self) -> u8 {
        self.current_hour
    }

    /// IDA: `base_daily_liner__force_hourly_rotation` (`0x14019B0`).
    pub fn force_hourly_rotation(&mut self) {
        let now = DailyLinerTime::now_utc();
        self.rotate_to_hourly(now);
    }

    /// IDA: `base_daily_liner__write_bytes_rotating` (`0x1401D40`).
    pub fn write_bytes(&mut self, now: DailyLinerTime, bytes: &[u8]) {
        if self.liner.is_none() {
            return;
        }

        now.validate();
        self.rotate_if_needed(now);

        if let Some(liner) = self.liner.as_mut() {
            liner.write_bytes(now.as_liner_time(), bytes);
            self.last_write_time = now;
            if self.flush_each_write {
                liner.flush_suppressing_errors();
            }
        }
    }

    /// IDA: `base_daily_liner__write_owned_line_rotating` (`0x14023C0`).
    pub fn write_owned_line(&mut self, now: DailyLinerTime, line: Vec<u8>) {
        if self.liner.is_none() {
            return;
        }

        now.validate();
        self.rotate_if_needed(now);

        if let Some(liner) = self.liner.as_mut() {
            liner.write_owned_line(now.as_liner_time(), line);
            self.last_write_time = now;
            if self.flush_each_write {
                liner.flush_suppressing_errors();
            }
        }
    }

    pub fn write_line(&mut self, now: DailyLinerTime, line: impl AsRef<[u8]>) {
        let bytes = line.as_ref();
        let mut owned = Vec::with_capacity(bytes.len() + 1);
        owned.extend_from_slice(bytes);
        self.write_owned_line(now, owned);
    }

    pub fn flush_suppressing_errors(&mut self) {
        if let Some(liner) = self.liner.as_mut() {
            liner.flush_suppressing_errors();
        }
    }

    pub fn flush(&mut self) -> io::Result<()> {
        match self.liner.as_mut() {
            Some(liner) => liner.flush(),
            None => Ok(()),
        }
    }

    fn rotate_if_needed(&mut self, now: DailyLinerTime) {
        if self.hourly_mode {
            let hour = now.hour();
            if self.current_date != now.date || self.current_hour != hour {
                self.replace_liner(hourly_path(&self.base_path, now.date, hour));
                self.current_date = now.date;
                self.hourly_mode = true;
                self.current_hour = hour;
            }
        } else if self.current_date != now.date {
            self.replace_liner(daily_path(&self.base_path, now.date));
            self.current_date = now.date;
        }
    }

    fn rotate_to_hourly(&mut self, now: DailyLinerTime) {
        now.validate();
        let old_daily_path = daily_path(&self.base_path, now.date);
        let hour = now.hour();
        self.replace_liner(hourly_path(&self.base_path, now.date, hour));
        self.current_date = now.date;
        self.hourly_mode = true;
        self.current_hour = hour;

        remove_empty_regular_file(&old_daily_path).expect("called `Result::unwrap()` on an `Err` value");
    }

    fn replace_liner(&mut self, path: String) {
        if let Some(liner) = self.liner.as_mut() {
            liner.flush_suppressing_errors();
        }
        self.liner = Some(Liner::from_path(path));
    }
}

impl Drop for DailyLiner {
    fn drop(&mut self) {
        if let Some(liner) = self.liner.as_mut() {
            liner.flush_suppressing_errors();
        }
    }
}

fn validate_key(key: &str) {
    let bytes = key.as_bytes();
    if bytes.first() == Some(&b'/') || bytes.last() == Some(&b'/') {
        panic!("daily liner key must not start or end with '/'");
    }
}

fn default_run_root() -> PathBuf {
    // [INFERENCE] The binary formats a global run-root string before the literal
    // `/data/`.  In reconstructed standalone use, an unset root preserves the
    // observed absolute `/data/<key>` fallback.
    std::env::var_os("HL_RUN_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(PathBuf::new)
}

fn data_path(run_root: &Path, key: &str) -> String {
    if run_root.as_os_str().is_empty() {
        format!("/{DATA_COMPONENT}/{key}")
    } else {
        run_root.join(DATA_COMPONENT).join(key).to_string_lossy().into_owned()
    }
}

fn daily_path(base_path: &str, date: NaiveDate) -> String {
    format!("{base_path}/{}", yyyymmdd(date))
}

fn hourly_path(base_path: &str, date: NaiveDate, hour: u8) -> String {
    format!("{base_path}/{HOURLY_COMPONENT}/{}/{}", yyyymmdd(date), hour)
}

fn yyyymmdd(date: NaiveDate) -> String {
    format!("{:04}{:02}{:02}", date.year(), date.month(), date.day())
}

fn remove_empty_regular_file(path: &str) -> io::Result<()> {
    let Ok(metadata) = fs::metadata(path) else {
        return Ok(());
    };
    if !metadata.file_type().is_file() || metadata.len() != 0 {
        return Ok(());
    }
    fs::remove_file(path)
}

#[allow(dead_code)]
fn time_from_system_time(time: SystemTime) -> DailyLinerTime {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => DailyLinerTime::from_unix_parts(duration.as_secs() as i64, duration.subsec_nanos()),
        Err(error) => {
            let duration = error.duration();
            if duration.subsec_nanos() == 0 {
                DailyLinerTime::from_unix_parts(-(duration.as_secs() as i64), 0)
            } else {
                DailyLinerTime::from_unix_parts(
                    -(duration.as_secs() as i64) - 1,
                    1_000_000_000 - duration.subsec_nanos(),
                )
            }
        }
    }
}
