use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::{Datelike, NaiveDateTime, Timelike, Utc};
use serde::de::DeserializeOwned;


use crate::crit_msg::{crit_msg, CritMsgIgnore};
use crate::duration::{seconds_since_or_zero, Duration as HlDuration};
use crate::file_mod_time_tracker::{expand_tilde_path, path_is_regular_file, stat_modified_chrono};
use crate::liner::{Liner, LinerTime};

pub type CritMsgIgnores = Vec<CritMsgIgnore>;
pub type FirewallIps = BTreeSet<IpAddr>;

const DEFAULT_CHECK_INTERVAL: HlDuration = HlDuration::from_secs_f64(5.0);
const SECONDS_PER_HOUR: u32 = 0xE10;
const ASSERTED_MAX_SECONDS_OF_DAY: u32 = 0x15F90;
const CHRONO_UNWRAP_UPPER_BOUND: u32 = 0xE1000;
const JSON_SCRATCH_CAPACITY: usize = 128;

/// Timestamp gate used by raw-mdg readers and throttled emit sites.
///
/// The optimized binary carries this as a compact `Option<NaiveDateTime>` and
/// tests the first timestamp word for the uninitialized sentinel. Keeping the
/// source as `Option<NaiveDateTime>` matches the recovered control flow: a
/// missing marker always runs, otherwise elapsed seconds must be strictly larger
/// than the configured interval.
pub type RawMdgMarker = Option<NaiveDateTime>;

pub fn raw_mdg_now() -> NaiveDateTime {
    Utc::now().naive_utc()
}

pub fn should_run_after_interval(marker: &mut RawMdgMarker, interval: HlDuration) -> bool {
    let now = raw_mdg_now();
    if let Some(previous) = *marker {
        if seconds_since_or_zero(now, previous) <= interval.as_secs_f64() {
            return false;
        }
    }
    *marker = Some(now);
    true
}

#[derive(Clone, Debug)]
pub struct RawMdg<T> {
    path: PathBuf,
    value: T,
    check_interval: HlDuration,
    last_checked: RawMdgMarker,
    last_load_error: Option<String>,
    last_modified: NaiveDateTime,
}

impl<T> RawMdg<T>
where
    T: Clone,
{
    pub fn new(path: impl Into<PathBuf>, default_value: T) -> Self {
        Self {
            path: path.into(),
            value: default_value,
            check_interval: DEFAULT_CHECK_INTERVAL,
            last_checked: None,
            last_load_error: None,
            last_modified: unix_epoch_datetime(),
        }
    }

    pub fn with_check_interval(mut self, check_interval: HlDuration) -> Self {
        self.check_interval = check_interval;
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn clone_value(&self) -> T {
        self.value.clone()
    }

    pub fn last_load_error(&self) -> Option<&str> {
        self.last_load_error.as_deref()
    }

    pub fn update_if_modified(&mut self) -> bool
    where
        T: DeserializeOwned,
    {
        self.update_if_modified_with(read_raw_mdg_file::<T>)
    }


    pub fn update_if_modified_with<F>(&mut self, mut read: F) -> bool
    where
        F: FnMut(&Path) -> Result<T, RawMdgError>,
    {
        if !should_run_after_interval(&mut self.last_checked, self.check_interval) {
            return false;
        }

        if !path_is_regular_file(&self.path) {
            return false;
        }

        let modified = stat_modified_chrono(&self.path).expect("called Result::unwrap() on an Err value");
        if modified <= self.last_modified {
            return false;
        }

        match read(&self.path) {
            Ok(value) => {
                self.value = value;
                self.last_modified = modified;
                self.last_load_error = None;
                tracing::trace!(path = %self.path.display(), "raw mdg reloaded");
                true
            }
            Err(error) => {
                let rendered = error.to_string();
                crit_msg(
                    "raw_mdg::update",
                    format!("Error updating FileModTimeTracker for {}: {rendered}", self.path.display()),
                );
                self.last_load_error = Some(rendered);
                false
            }
        }
    }
}

impl RawMdg<CritMsgIgnores>
where
    CritMsgIgnores: DeserializeOwned,
{
    pub fn update_crit_msg_ignores_if_modified(&mut self) -> bool {
        self.update_if_modified_with(read_crit_msg_ignores)
    }
}

impl RawMdg<FirewallIps>
where
    FirewallIps: DeserializeOwned,
{
    pub fn update_firewall_ips_if_modified(&mut self) -> bool {
        self.update_if_modified_with(read_firewall_ips)
    }
}

pub fn read_crit_msg_ignores(path: &Path) -> Result<CritMsgIgnores, RawMdgError> {
    read_raw_mdg_file(path)
}

pub fn read_firewall_ips(path: &Path) -> Result<FirewallIps, RawMdgError> {
    read_raw_mdg_file(path)
}

pub fn read_raw_mdg_file<T>(path: &Path) -> Result<T, RawMdgError>
where
    T: DeserializeOwned,
{
    let path = expand_tilde_path(path);
    if !path_is_regular_file(&path) {
        return Err(RawMdgError::MissingFile { path });
    }

    if has_rmp_extension(&path) {
        let bytes = fs::read(&path).map_err(|source| RawMdgError::Read {
            path: path.clone(),
            source,
        })?;
        rmp_serde::from_slice(&bytes).map_err(|source| RawMdgError::Rmp { path, source })
    } else {
        let text = fs::read_to_string(&path).map_err(|source| RawMdgError::ReadToString {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&text).map_err(|source| RawMdgError::Json { path, source })
    }
}

#[derive(Debug)]
pub enum RawMdgError {
    MissingFile { path: PathBuf },
    Read { path: PathBuf, source: io::Error },
    ReadToString { path: PathBuf, source: io::Error },
    Json { path: PathBuf, source: serde_json::Error },
    Rmp { path: PathBuf, source: rmp_serde::decode::Error },
}

impl fmt::Display for RawMdgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingFile { path } => write!(f, "missing file: {}", path.display()),
            Self::Read { path, source } => write!(f, "read: {}: {source}", path.display()),
            Self::ReadToString { path, source } => write!(f, "read_to_string: {}: {source}", path.display()),
            Self::Json { path, source } => write!(f, "serde_json::from_str: {}: {source}", path.display()),
            Self::Rmp { path, source } => write!(f, "rmp_serde::from_slice: {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for RawMdgError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } | Self::ReadToString { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::Rmp { source, .. } => Some(source),
            Self::MissingFile { .. } => None,
        }
    }
}

#[derive(Debug)]
pub struct RawMdgRotatingWriter {
    root: String,
    liner: Liner,
    current_day: i32,
    last_write_at: RawMdgMarker,
    rotate_hourly: bool,
    current_hour: u8,
    force_flush: bool,
}

impl RawMdgRotatingWriter {
    pub fn new(root: impl Into<String>, rotate_hourly: bool, force_flush: bool) -> Self {
        let root = root.into();
        let liner = Liner::from_path(root.clone());
        Self {
            root,
            liner,
            current_day: i32::MIN,
            last_write_at: None,
            rotate_hourly,
            current_hour: u8::MAX,
            force_flush,
        }
    }

    pub fn write_bytes_rotating(&mut self, timestamp: NaiveDateTime, bytes: &[u8]) {
        self.rotate_for_timestamp(timestamp);
        self.liner.write_bytes(liner_time(timestamp), bytes);
        self.last_write_at = Some(timestamp);
        if self.force_flush {
            self.liner.flush_suppressing_errors();
        }
    }

    pub fn write_aggregate_json_line(&mut self, sample: &AggregateSample) {
        let mut row = Vec::with_capacity(JSON_SCRATCH_CAPACITY);
        serialize_aggregate_json(sample, &mut row).expect("writing JSON into Vec cannot fail");
        row.push(b'\n');
        self.write_bytes_rotating(sample.time, &row);
    }

    fn rotate_for_timestamp(&mut self, timestamp: NaiveDateTime) {
        let (day, hour) = day_and_hour(timestamp);
        let must_rotate = if self.rotate_hourly {
            self.current_day != day || self.current_hour != hour
        } else {
            self.current_day != day
        };

        if !must_rotate {
            return;
        }

        let path = if self.rotate_hourly {
            format!("{}/hourly/{}/{}", self.root, day, hour)
        } else {
            format!("{}/{}", self.root, day)
        };
        self.liner = Liner::from_path(path);
        self.current_day = day;
        self.current_hour = hour;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateSample {
    pub n: u64,
    pub delta: i64,
    pub time: NaiveDateTime,
}

pub fn serialize_aggregate_json(sample: &AggregateSample, out: &mut Vec<u8>) -> io::Result<()> {
    write!(
        out,
        "{{\"time\":\"{}\",\"n\":{},\"delta\":{}}}",
        sample.time, sample.n, sample.delta
    )
}

#[derive(Debug)]
pub struct RawMdgAggregate {
    writer: RawMdgRotatingWriter,
    pending_n: u64,
    pending_delta: i64,
    aggregate_flush_period: HlDuration,
    last_aggregate_flush_at: RawMdgMarker,
}

impl RawMdgAggregate {
    pub fn new(writer: RawMdgRotatingWriter, aggregate_flush_period: HlDuration) -> Self {
        Self {
            writer,
            pending_n: 0,
            pending_delta: 0,
            aggregate_flush_period,
            last_aggregate_flush_at: None,
        }
    }

    pub fn accumulate_and_maybe_emit(&mut self, delta: i64) {
        self.pending_n = self.pending_n.saturating_add(1);
        self.pending_delta = self.pending_delta.saturating_add(delta);

        let now = raw_mdg_now();
        if let Some(previous) = self.last_aggregate_flush_at {
            if seconds_since_or_zero(now, previous) <= self.aggregate_flush_period.as_secs_f64() {
                return;
            }
        }
        self.last_aggregate_flush_at = Some(now);

        let sample = AggregateSample {
            n: self.pending_n,
            delta: self.pending_delta,
            time: now,
        };
        self.writer.write_aggregate_json_line(&sample);
        self.pending_n = 0;
        self.pending_delta = 0;
    }

    pub fn write_bytes(&mut self, timestamp: NaiveDateTime, bytes: &[u8]) {
        self.writer.write_bytes_rotating(timestamp, bytes);
    }
}

fn has_rmp_extension(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if file_name == ".." {
        return false;
    }
    let Some(dot) = file_name.rfind('.') else {
        return false;
    };
    dot != 0 && file_name[dot + 1..].eq_ignore_ascii_case("rmp")
}

fn day_and_hour(timestamp: NaiveDateTime) -> (i32, u8) {
    let seconds_of_day = timestamp.num_seconds_from_midnight();
    if seconds_of_day >= CHRONO_UNWRAP_UPPER_BOUND {
        panic!("called Result::unwrap() on an Err value");
    }
    assert!(seconds_of_day < ASSERTED_MAX_SECONDS_OF_DAY, "assertion failed: hour <= 24");
    let hour = seconds_of_day / SECONDS_PER_HOUR;
    assert!(hour <= 24, "assertion failed: hour <= 24");
    (timestamp.num_days_from_ce(), hour as u8)
}

fn liner_time(timestamp: NaiveDateTime) -> LinerTime {
    LinerTime {
        unix_seconds: timestamp.timestamp(),
        nanos: timestamp.timestamp_subsec_nanos(),
    }
}

fn unix_epoch_datetime() -> NaiveDateTime {
    NaiveDateTime::from_timestamp_opt(0, 0).expect("unix epoch is valid")
}
