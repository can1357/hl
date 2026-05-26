use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{NaiveDateTime, Utc};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::crit_msg::crit_msg;
use crate::duration::{seconds_since_or_zero, Duration as HlDuration};

const DEFAULT_CHECK_INTERVAL: HlDuration = HlDuration::from_secs_f64(5.0);
const DEV_NULL: &str = "/dev/null";

#[derive(Clone, Debug)]
pub struct FileModTimeTracker<T> {
    path: PathBuf,
    value: T,
    check_interval: HlDuration,
    last_checked: Option<NaiveDateTime>,
    last_load_error: Option<String>,
    last_modified: NaiveDateTime,
}

impl<T> FileModTimeTracker<T>
where
    T: Clone + DeserializeOwned + Serialize,
{
    pub fn new(path: impl Into<PathBuf>, default_value: T) -> Self {
        Self::new_with_initial_value(path, default_value, false)
    }

    pub fn new_with_initial_value(path: impl Into<PathBuf>, default_value: T, write_if_missing: bool) -> Self {
        let path = path.into();
        let mut tracker = Self {
            path,
            value: default_value,
            check_interval: DEFAULT_CHECK_INTERVAL,
            last_checked: None,
            last_load_error: None,
            last_modified: unix_epoch_datetime(),
        };

        if path_is_regular_file(&tracker.path) {
            match tracker.load_current_file() {
                Ok((value, modified)) => {
                    tracker.value = value;
                    tracker.last_modified = modified;
                }
                Err(err) => tracker.record_initial_load_error(err),
            }
        } else if write_if_missing {
            tracker
                .write_initial_value()
                .expect("called `Result::unwrap()` on an `Err` value");
        }

        tracker
    }

    pub fn with_check_interval(mut self, check_interval: HlDuration) -> Self {
        self.check_interval = check_interval;
        self
    }

    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[inline]
    pub fn value(&self) -> &T {
        &self.value
    }

    #[inline]
    pub fn last_load_error(&self) -> Option<&str> {
        self.last_load_error.as_deref()
    }

    pub fn clone_value_logging_last_error(&self) -> T {
        if let Some(error) = &self.last_load_error {
            crit_msg(
                "file_mod_time_tracker::last_load_error",
                format!("Last load of FileModTimeTracker failed: {error}"),
            );
        }
        self.value.clone()
    }

    pub fn update_if_modified(&mut self) -> bool {
        let now = Utc::now().naive_utc();
        if let Some(last_checked) = self.last_checked {
            if seconds_since_or_zero(now, last_checked) <= self.check_interval.as_secs_f64() {
                return false;
            }
        }
        self.last_checked = Some(now);

        if !path_is_regular_file(&self.path) {
            return false;
        }

        let modified = stat_modified_chrono(&self.path)
            .expect("called `Result::unwrap()` on an `Err` value");
        if modified <= self.last_modified {
            return false;
        }

        match self.read_expanded_file() {
            Ok(value) => {
                self.value = value;
                self.last_modified = modified;
                self.last_load_error = None;
                true
            }
            Err(err) => {
                self.record_update_error(err);
                false
            }
        }
    }

    fn load_current_file(&self) -> Result<(T, NaiveDateTime), FileModTimeTrackerError> {
        let modified = stat_modified_chrono(&self.path)?;
        let value = self.read_expanded_file()?;
        Ok((value, modified))
    }

    fn read_expanded_file(&self) -> Result<T, FileModTimeTrackerError> {
        let path = expand_tilde_path(&self.path);
        if !path_is_regular_file(&path) {
            return Err(FileModTimeTrackerError::MissingFile { path });
        }

        if has_rmp_extension(&path) {
            let bytes = fs::read(&path).map_err(|source| FileModTimeTrackerError::Read {
                path: path.clone(),
                source,
            })?;
            rmp_serde::from_slice(&bytes).map_err(|source| FileModTimeTrackerError::Rmp { path, source })
        } else {
            let text = fs::read_to_string(&path).map_err(|source| FileModTimeTrackerError::ReadToString {
                path: path.clone(),
                source,
            })?;
            serde_json::from_str(&text).map_err(|source| FileModTimeTrackerError::Json { path, source })
        }
    }

    fn write_initial_value(&self) -> Result<(), FileModTimeTrackerError> {
        if self.path == Path::new(DEV_NULL) {
            return Ok(());
        }
        if path_try_exists(&self.path)? {
            if path_is_regular_file(&self.path) {
                return Ok(());
            }
            return Err(FileModTimeTrackerError::NotRegularFile {
                path: self.path.clone(),
            });
        }

        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| FileModTimeTrackerError::CreateDir {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
        }

        let rendered = serde_json::to_vec_pretty(&self.value).map_err(|source| FileModTimeTrackerError::JsonWrite {
            path: self.path.clone(),
            source,
        })?;
        fs::write(&self.path, rendered).map_err(|source| FileModTimeTrackerError::Write {
            path: self.path.clone(),
            source,
        })
    }

    fn record_initial_load_error(&mut self, err: FileModTimeTrackerError) {
        let error = err.to_string();
        crit_msg(
            "file_mod_time_tracker::initial_load",
            format!("could not load file, using default value. Error: {error}"),
        );
        self.last_load_error = Some(error);
    }

    fn record_update_error(&mut self, err: FileModTimeTrackerError) {
        let error = err.to_string();
        crit_msg(
            "file_mod_time_tracker::update",
            format!("Error updating FileModTimeTracker for {}: {error}", self.path.display()),
        );
        self.last_load_error = Some(error);
    }
}

pub fn path_is_regular_file(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(metadata) => metadata.file_type().is_file(),
        Err(_) => false,
    }
}

pub fn stat_modified_chrono(path: &Path) -> Result<NaiveDateTime, FileModTimeTrackerError> {
    let metadata = fs::metadata(path).map_err(|source| FileModTimeTrackerError::Metadata {
        path: path.to_path_buf(),
        source,
    })?;
    let modified = metadata
        .modified()
        .map_err(|source| FileModTimeTrackerError::ModifiedTime {
            path: path.to_path_buf(),
            source,
        })?;
    system_time_to_chrono(modified).ok_or_else(|| FileModTimeTrackerError::InvalidTimestamp {
        path: path.to_path_buf(),
    })
}

pub fn expand_tilde_path(path: &Path) -> PathBuf {
    let Some(path_str) = path.to_str() else {
        return path.to_path_buf();
    };
    let Some(rest) = path_str.strip_prefix("~/") else {
        return path.to_path_buf();
    };
    let Some(home) = std::env::var_os("HOME") else {
        return path.to_path_buf();
    };

    let mut expanded = PathBuf::from(home);
    expanded.push(rest);
    expanded
}

fn path_try_exists(path: &Path) -> Result<bool, FileModTimeTrackerError> {
    path.try_exists().map_err(|source| FileModTimeTrackerError::Metadata {
        path: path.to_path_buf(),
        source,
    })
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

fn system_time_to_chrono(time: SystemTime) -> Option<NaiveDateTime> {
    let duration = time.duration_since(UNIX_EPOCH).ok()?;
    if duration.subsec_nanos() >= 1_000_000_000 {
        return None;
    }
    let seconds = i64::try_from(duration.as_secs()).ok()?;

    // The recovered helper validates the OS nanosecond field, but constructs the
    // comparable chrono value with a zero fractional component before storing it.
    NaiveDateTime::from_timestamp_opt(seconds, 0)
}

fn unix_epoch_datetime() -> NaiveDateTime {
    NaiveDateTime::from_timestamp_opt(0, 0).expect("unix epoch is valid")
}

#[derive(Debug)]
pub enum FileModTimeTrackerError {
    Metadata { path: PathBuf, source: io::Error },
    ModifiedTime { path: PathBuf, source: io::Error },
    InvalidTimestamp { path: PathBuf },
    MissingFile { path: PathBuf },
    NotRegularFile { path: PathBuf },
    CreateDir { path: PathBuf, source: io::Error },
    Read { path: PathBuf, source: io::Error },
    ReadToString { path: PathBuf, source: io::Error },
    Write { path: PathBuf, source: io::Error },
    Json { path: PathBuf, source: serde_json::Error },
    JsonWrite { path: PathBuf, source: serde_json::Error },
    Rmp { path: PathBuf, source: rmp_serde::decode::Error },
}

impl fmt::Display for FileModTimeTrackerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Metadata { path, source } => write!(f, "metadata {}: {source}", path.display()),
            Self::ModifiedTime { path, source } => write!(f, "modified {}: {source}", path.display()),
            Self::InvalidTimestamp { path } => write!(f, "invalid timestamp for {}", path.display()),
            Self::MissingFile { path } => write!(f, "missing file: {}", path.display()),
            Self::NotRegularFile { path } => write!(f, "not a regular file: {}", path.display()),
            Self::CreateDir { path, source } => write!(f, "create_dir_all {}: {source}", path.display()),
            Self::Read { path, source } => write!(f, "read: {}: {source}", path.display()),
            Self::ReadToString { path, source } => write!(f, "read_to_string: {}: {source}", path.display()),
            Self::Write { path, source } => write!(f, "write {}: {source}", path.display()),
            Self::Json { path, source } => write!(f, "serde_json::from_str: {}: {source}", path.display()),
            Self::JsonWrite { path, source } => write!(f, "serde_json::to_vec_pretty: {}: {source}", path.display()),
            Self::Rmp { path, source } => write!(f, "rmp_serde::from_slice: {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for FileModTimeTrackerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Metadata { source, .. }
            | Self::ModifiedTime { source, .. }
            | Self::CreateDir { source, .. }
            | Self::Read { source, .. }
            | Self::ReadToString { source, .. }
            | Self::Write { source, .. } => Some(source),
            Self::Json { source, .. } | Self::JsonWrite { source, .. } => Some(source),
            Self::Rmp { source, .. } => Some(source),
            Self::InvalidTimestamp { .. } | Self::MissingFile { .. } | Self::NotRegularFile { .. } => None,
        }
    }
}
