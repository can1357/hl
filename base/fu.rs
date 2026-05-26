use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::error::Error;
use std::fmt::{self, Debug, Display};
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::task;

use crate::crit_msg::crit_msg;
use crate::file_mod_time_tracker::{expand_tilde_path, path_is_regular_file};
use crate::shell::{Shell, ShellError};

pub type Result<T, E = FuError> = std::result::Result<T, E>;

const DEFAULT_RETRY_SLEEPS: [f64; 3] = [0.001, 0.05, 1.0];
const MICROS_PER_SEC: u64 = 1_000_000;
const NANOS_PER_MICRO: u32 = 1_000;
const CREATE_DIR_MODE: u32 = 0o777;
const READ_EXACT_CHUNK: usize = 4_000_000;
const ROCKSDB_TOO_LARGE_THRESHOLD_BYTES: u64 = 0x2e90edc << 11;

#[derive(Debug)]
pub enum FuError {
    Io { op: &'static str, path: PathBuf, source: io::Error },
    JsonRead { path: PathBuf, source: serde_json::Error },
    JsonWrite { path: PathBuf, source: serde_json::Error },
    RmpRead { path: PathBuf, source: rmp_serde::decode::Error },
    RmpWrite { path: PathBuf, source: rmp_serde::encode::Error },
    Shell(ShellError),
    Join(task::JoinError),
    Message(String),
}

impl fmt::Display for FuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FuError::Io { op, path, source } => write!(f, "{op} {}: {source}", path.display()),
            FuError::JsonRead { path, source } => write!(f, "json load {}: {source}", path.display()),
            FuError::JsonWrite { path, source } => write!(f, "json save {}: {source}", path.display()),
            FuError::RmpRead { path, source } => write!(f, "rmp load {}: {source}", path.display()),
            FuError::RmpWrite { path, source } => write!(f, "rmp save {}: {source}", path.display()),
            FuError::Shell(source) => Display::fmt(source, f),
            FuError::Join(source) => Display::fmt(source, f),
            FuError::Message(message) => f.write_str(message),
        }
    }
}

impl Error for FuError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            FuError::Io { source, .. } => Some(source),
            FuError::JsonRead { source, .. } => Some(source),
            FuError::JsonWrite { source, .. } => Some(source),
            FuError::RmpRead { source, .. } => Some(source),
            FuError::RmpWrite { source, .. } => Some(source),
            FuError::Shell(source) => Some(source),
            FuError::Join(source) => Some(source),
            FuError::Message(_) => None,
        }
    }
}

impl From<ShellError> for FuError {
    fn from(source: ShellError) -> Self {
        FuError::Shell(source)
    }
}

impl From<task::JoinError> for FuError {
    fn from(source: task::JoinError) -> Self {
        FuError::Join(source)
    }
}

pub fn default_retry_sleeps() -> &'static [f64] {
    &DEFAULT_RETRY_SLEEPS
}

/// Run a fallible operation, sleeping between retries.
///
/// Evidence: the default sleep table is `[0.001, 0.05, 1.0]` seconds. The
/// sleep conversion multiplies seconds by `1_000_000.0`, clamps to unsigned
/// microseconds, then calls `nanosleep` with `tv_nsec = micros % 1_000_000 * 1000`.
/// Interrupted sleeps resume with the kernel-provided remaining timespec.
pub fn sleep_retry<T, E, F>(label: &str, mut operation: F, sleep_times: Option<&[f64]>) -> std::result::Result<T, String>
where
    E: Display,
    F: FnMut() -> std::result::Result<T, E>,
{
    let sleeps = sleep_times.unwrap_or(default_retry_sleeps());
    let mut last_err = match operation() {
        Ok(value) => return Ok(value),
        Err(err) => err,
    };

    for seconds in sleeps {
        sleep_seconds(*seconds);
        match operation() {
            Ok(value) => return Ok(value),
            Err(err) => last_err = err,
        }
    }

    Err(format!(
        "sleep_retry retried {label} for sleep times {sleeps:?}\n last err {last_err}"
    ))
}

pub fn sleep_seconds(seconds: f64) {
    let Some(duration) = seconds_to_sleep_duration(seconds) else {
        return;
    };
    thread::sleep(duration);
}

pub fn seconds_to_sleep_duration(seconds: f64) -> Option<Duration> {
    let micros_f64 = seconds * MICROS_PER_SEC as f64;
    let micros = if !micros_f64.is_finite() {
        if micros_f64.is_sign_positive() { u64::MAX } else { 0 }
    } else if micros_f64 <= 0.0 {
        0
    } else if micros_f64 >= u64::MAX as f64 {
        u64::MAX
    } else {
        micros_f64 as u64
    };

    if micros == 0 {
        return None;
    }

    let secs = micros / MICROS_PER_SEC;
    let nanos = (micros % MICROS_PER_SEC) as u32 * NANOS_PER_MICRO;
    Some(Duration::new(secs, nanos))
}

/// Directory predicate used before creating parents.
///
/// Evidence: the recovered predicate checks the directory mode bit and returns
/// false on metadata errors; it does not panic on missing paths.
pub fn path_is_dir(path: impl AsRef<Path>) -> bool {
    fs::metadata(path.as_ref())
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
}

pub fn ensure_parent_dir(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() || path_is_dir(parent) {
        return Ok(());
    }

    fs::create_dir_all(parent).map_err(|source| FuError::Io {
        op: "ensure_dirs",
        path: parent.to_path_buf(),
        source,
    })?;

    #[cfg(unix)]
    {
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(CREATE_DIR_MODE));
    }

    Ok(())
}

/// Write a byte slice, creating missing parent directories and retrying once.
///
/// Evidence: the helper retries after `mkdir` with mode `0o777` and formats
/// create-dir failures with the `ensure_dirs ` prefix.
pub fn write_bytes_creating_parent(path: impl AsRef<Path>, bytes: &[u8]) -> Result<()> {
    let path = path.as_ref();
    match fs::write(path, bytes) {
        Ok(()) => Ok(()),
        Err(_) => {
            ensure_parent_dir(path)?;
            fs::write(path, bytes).map_err(|source| FuError::Io {
                op: "write",
                path: path.to_path_buf(),
                source,
            })
        }
    }
}

/// Create an empty file if it is missing or not a regular file.
///
/// Evidence: callers treat a null/zero return as success. The shared call site
/// at line 254:23 drops the error object in checkpoint-complete touch users.
pub fn touch_if_missing(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    if path_is_regular_file(path) {
        return Ok(());
    }
    write_bytes_creating_parent(path, &[])
}

/// Asynchronous touch wrapper used by state machines labelled `async_touch`.
pub async fn async_touch(path: impl Into<PathBuf>) {
    let path = path.into();
    task::spawn_blocking(move || touch_if_missing(path))
        .await
        .expect("called `Result::unwrap()` on an `Err` value")
        .expect("called `Result::unwrap()` on an `Err` value");
}

/// Variant labelled `async_touch_alert_on_fail`; failures are reported and swallowed.
pub async fn async_touch_alert_on_fail(path: impl Into<PathBuf>) {
    let path = path.into();
    let result = task::spawn_blocking(move || touch_if_missing(path)).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            crit_msg("async_touch_alert_on_fail", err.to_string());
        }
        Err(err) => {
            crit_msg("async_touch_alert_on_fail", err.to_string());
        }
    }
}

pub async fn async_touch_all(paths: impl IntoIterator<Item = PathBuf>) {
    for path in paths {
        let _ = task::spawn_blocking(move || touch_if_missing(path)).await;
    }
}

/// Copy a regular source file to a destination.
///
/// Evidence: the missing-source error string begins with
/// `copy_file: source file ` and ends with ` doesn't exist`.
pub fn copy_file_or_err(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<u64> {
    let from = from.as_ref();
    let to = to.as_ref();
    if !path_is_regular_file(from) {
        return Err(FuError::Message(format!(
            "copy_file: source file {} doesn't exist",
            from.display()
        )));
    }
    ensure_parent_dir(to)?;
    fs::copy(from, to).map_err(|source| FuError::Io {
        op: "copy_file",
        path: to.to_path_buf(),
        source,
    })
}

/// Shell out to `cp` using either recursive copy or hard-link copy.
///
/// Evidence: the command string cluster contains `cp`, `-R`, `-al`, and
/// `copy_file`; save helpers unwrap errors returned by this call.
pub fn cp_path_shell(from: impl AsRef<Path>, to: impl AsRef<Path>, hard_link_copy: bool) -> Result<()> {
    ensure_parent_dir(to.as_ref())?;
    let flag = if hard_link_copy { "-al" } else { "-R" };
    let args = vec![
        "cp".to_string(),
        flag.to_string(),
        from.as_ref().to_string_lossy().into_owned(),
        to.as_ref().to_string_lossy().into_owned(),
    ];
    Shell::from_args(&args)?.wait()?;
    Ok(())
}

pub fn loadp<T>(path: impl AsRef<Path>) -> Result<T>
where
    T: DeserializeOwned,
{
    let path = expand_tilde_path(path.as_ref());
    if has_rmp_extension(&path) {
        let bytes = fs::read(&path).map_err(|source| FuError::Io {
            op: "read",
            path: path.clone(),
            source,
        })?;
        rmp_serde::from_slice(&bytes).map_err(|source| FuError::RmpRead { path, source })
    } else {
        let text = fs::read_to_string(&path).map_err(|source| FuError::Io {
            op: "read_to_string",
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&text).map_err(|source| FuError::JsonRead { path, source })
    }
}

/// Spawn a blocking `loadp` task and unwrap the join/result layers.
///
/// Evidence: the async task label is `async_loadp`; the poll side unwraps the
/// blocking task result before using the deserialized vector payload.
pub async fn async_loadp<T>(path: impl Into<PathBuf>) -> T
where
    T: DeserializeOwned + Send + 'static,
{
    let path = path.into();
    task::spawn_blocking(move || loadp(path))
        .await
        .expect("called `Result::unwrap()` on an `Err` value")
        .expect("called `Result::unwrap()` on an `Err` value")
}

pub fn savep<T>(path: impl AsRef<Path>, value: &T, hard_link_copy: bool) -> Result<()>
where
    T: Serialize,
{
    let path = expand_tilde_path(path.as_ref());
    let bytes = serialize_for_path(&path, value)?;
    let tmp_path = temp_save_path(&path);

    write_bytes_creating_parent(&tmp_path, &bytes)?;

    if hard_link_copy {
        cp_path_shell(&tmp_path, &path, true)?;
    } else {
        copy_file_or_err(&tmp_path, &path)?;
    }

    let _ = fs::remove_file(&tmp_path);
    Ok(())
}

/// Save through a temporary path and ensure the final path exists.
///
/// Evidence: the large save body checks `path_is_regular_file`, calls the `cp`
/// helper, calls `touch_if_missing`, then optionally `copy_file` before returning
/// a 48-byte state object to its caller.
pub fn savep_atomic_copy<T>(path: impl AsRef<Path>, value: &T, hard_link_copy: bool) -> Result<()>
where
    T: Serialize,
{
    savep(&path, value, hard_link_copy)?;
    if !path_is_regular_file(path.as_ref()) {
        touch_if_missing(path.as_ref())?;
    }
    Ok(())
}

pub async fn async_savep<T>(path: impl Into<PathBuf>, value: T, hard_link_copy: bool) -> Result<()>
where
    T: Serialize + Send + 'static,
{
    let path = path.into();
    task::spawn_blocking(move || savep(path, &value, hard_link_copy)).await?
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum TimedCategory {
    Exchange,
    Rpc,
    Evmstate,
}

impl TimedCategory {
    pub fn from_byte(value: u8) -> Self {
        match value {
            0 => TimedCategory::Exchange,
            1 => TimedCategory::Rpc,
            _ => TimedCategory::Evmstate,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TimedCategory::Exchange => "Exchange",
            TimedCategory::Rpc => "Rpc",
            TimedCategory::Evmstate => "Evmstate",
        }
    }
}

/// Format the category/timing string used by timed dispatch wrappers.
///
/// Evidence: selector bytes map to `Exchange`, `Rpc`, and `Evmstate`; the helper
/// is called after subtracting two `Timespec::now()` samples.
pub fn format_timed_category_path(category: TimedCategory, elapsed: Duration, suffix: impl Display) -> String {
    format!("{} {:.6}s {}", category.as_str(), elapsed.as_secs_f64(), suffix)
}

/// Dispatch a u8-keyed BTree entry while preserving the observed category label.
///
/// Evidence: the monomorph walks a BTree node by u8 key, invokes the selected
/// value, unwraps its result, and formats the elapsed time under the chosen
/// category byte.
pub fn timed_btree_u8_dispatch<A, R, E, F>(
    dispatch: &BTreeMap<u8, F>,
    category: u8,
    arg: A,
) -> std::result::Result<R, E>
where
    A: Clone,
    F: Fn(A) -> std::result::Result<R, E>,
{
    let selected = dispatch
        .get(&category)
        .or_else(|| dispatch.range(category..).next().map(|(_, f)| f))
        .expect("internal error: empty timed dispatch map");
    selected(arg)
}

pub fn read_exact_chunk_size() -> usize {
    READ_EXACT_CHUNK
}

pub fn rocksdb_too_large_threshold_bytes() -> u64 {
    ROCKSDB_TOO_LARGE_THRESHOLD_BYTES
}

fn serialize_for_path<T>(path: &Path, value: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    if has_rmp_extension(path) {
        rmp_serde::to_vec_named(value).map_err(|source| FuError::RmpWrite {
            path: path.to_path_buf(),
            source,
        })
    } else {
        serde_json::to_vec_pretty(value).map_err(|source| FuError::JsonWrite {
            path: path.to_path_buf(),
            source,
        })
    }
}

fn temp_save_path(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

fn has_rmp_extension(path: &Path) -> bool {
    path.extension() == Some(OsStr::new("rmp"))
}
