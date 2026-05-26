//! Recovered from `/home/ubuntu/hl/code_Mainnet/node/src/abci_checkpoint.rs`.
//!
//! Seed: `0x432FC10`; expanded locally through adjacent rodata/function-table
//! entries while IDA MCP was queue-full.
//!
//! High-confidence local evidence:
//! - `0x432FC10` references source-location entries for this file and constructs
//!   the retry suffix `zip_inner_retry` before unwrapping a move/rename result.
//! - `0x432E930` uses strings `visor_abci_states` and `get_visor_state`, stores
//!   `0x48`-byte records, caps the in-memory history at `0x14`, sleeps five
//!   seconds on every pass, and logs `visor lag increased ...` when an older
//!   record is more than thirty seconds newer than the latest one.
//! - `0x432F310` branches on a bool: true logs `tar_evm_checkpoints failed`,
//!   false calls prune with `n_keep = 0x64` and logs
//!   `prune_lowest_evm_checkpoints failed`.
//! - Foreign checkpoint loader `0x332E0A0` builds `<base>/checkpoint`, parses
//!   decimal directory names as heights, requires `CHECKPOINT_COMPLETE`, and
//!   returns `(height, path)` records.
//!
//! IDA tags applied: none; queue-full prevented `rename`/`set_comments`.
//! Pending IDA operations:
//! - rename/comment `0x432FC10` as `node_abci_checkpoint__rename_checkpoint_file`.
//! - rename/comment `0x432E930` as `node_abci_checkpoint__monitor_visor_state_lag`.
//! - rename/comment `0x432F310` as `node_abci_checkpoint__periodic_evm_checkpoint_maintenance`.
//! - rename/comment `0x432F5F0` as `node_abci_checkpoint__serialize_checkpoint_state`.
//! - rename/comment `0x432F680` as `node_abci_checkpoint__load_visor_states_into_channels`.
//! - rename/comment `0x432F9C0` as `node_abci_checkpoint__flush_locked_checkpoint_bytes`.
//! - rename/comment `0x332E0A0`, `0x37E2960`, and `0x37E3A70` as the shared
//!   checkpoint loader/tar/prune helpers used by this file.

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

pub const CHECKPOINT_DIR: &str = "checkpoint";
pub const CHECKPOINT_COMPLETE: &str = "CHECKPOINT_COMPLETE";
pub const VISOR_ABCI_STATES_DIR: &str = "visor_abci_states";
pub const ZIP_INNER_RETRY: &str = "zip_inner_retry";
pub const DAILY_EVM_CHECKPOINTS_DIR: &str = "daily_evm_checkpoints";
pub const TMP_EVM_TAR_PREFIX: &str = "evm_state_checkpoints";
pub const DEFAULT_PRUNE_KEEP: usize = 100;
pub const VISOR_HISTORY_LIMIT: usize = 20;
pub const VISOR_MONITOR_SLEEP: Duration = Duration::from_secs(5);
pub const VISOR_LAG_ALERT_THRESHOLD: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DbCheckpointInfo {
    pub height: u64,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbciCheckpointPath {
    pub date: String,
    pub height: u64,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmCheckpointTarPlan {
    pub first_height: u64,
    pub last_height: u64,
    pub target: PathBuf,
    pub tmp: PathBuf,
    pub members: Vec<DbCheckpointInfo>,
}

#[derive(Clone, Debug)]
pub struct VisorStateRecord {
    /// Parsed from the checkpoint/visor state filename or record payload.
    pub height: u64,
    /// File mtime converted to a system duration; invalid chrono conversions in
    /// the binary fall back to zero before comparison.
    pub file_age: Duration,
    pub path: PathBuf,
}

#[derive(Debug)]
pub enum CheckpointError {
    MissingOuterDir { path: PathBuf },
    NoCheckpoints { path: PathBuf },
    NoCurrentCheckpoint { path: PathBuf },
    Io { path: PathBuf, source: io::Error },
    TarFailed { status: Option<i32>, stderr: String },
}

impl CheckpointError {
    fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io { path: path.into(), source }
    }
}

pub trait CheckpointCodec<State> {
    fn encode_checkpoint(&mut self, state: &State, out: &mut Vec<u8>) -> io::Result<()>;
    fn decode_checkpoint(&mut self, bytes: &[u8]) -> io::Result<State>;
}

pub trait VisorStateSource {
    fn get_visor_state(&mut self) -> io::Result<Option<VisorStateRecord>>;
    fn log_visor_lag_increased(&mut self, oldest: &VisorStateRecord, current: &VisorStateRecord);
    fn sleep(&mut self, duration: Duration);
}

pub fn checkpoint_outer_dir(base: &Path) -> PathBuf {
    base.join(CHECKPOINT_DIR)
}

pub fn checkpoint_complete_marker(checkpoint: &Path) -> PathBuf {
    checkpoint.join(CHECKPOINT_COMPLETE)
}

pub fn visor_abci_states_dir(base: &Path) -> PathBuf {
    base.join(VISOR_ABCI_STATES_DIR)
}

/// File-name logic recovered from loader `0x332E0A0`.
///
/// Decimal names parse to heights. A single leading `+` is accepted. Empty
/// names, bare signs, `-`, non-digits, and overflowing values are skipped.
pub fn parse_checkpoint_height(name: &OsStr) -> Option<u64> {
    let s = name.to_str()?;
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    let digits = match bytes[0] {
        b'+' if bytes.len() > 1 => &bytes[1..],
        b'+' | b'-' => return None,
        _ => bytes,
    };

    let mut value = 0u64;
    for &byte in digits {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
    }
    Some(value)
}

/// Loader recovered from foreign helper `0x332E0A0`.
///
/// It scans `<base>/checkpoint`, keeps only numeric directories with a
/// `CHECKPOINT_COMPLETE` marker, and sorts by height for consumers that select
/// the newest or prune the lowest heights.
pub fn load_checkpoint_dirs(base: &Path) -> Result<Vec<DbCheckpointInfo>, CheckpointError> {
    let outer = checkpoint_outer_dir(base);
    if !outer.is_dir() {
        return Err(CheckpointError::MissingOuterDir { path: outer });
    }

    let mut checkpoints = Vec::new();
    let entries = fs::read_dir(&outer).map_err(|source| CheckpointError::io(&outer, source))?;
    for entry in entries {
        let entry = entry.map_err(|source| CheckpointError::io(&outer, source))?;
        let Some(height) = parse_checkpoint_height(&entry.file_name()) else {
            continue;
        };
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if !checkpoint_complete_marker(&path).is_file() {
            continue;
        }
        checkpoints.push(DbCheckpointInfo { height, path });
    }

    if checkpoints.is_empty() {
        return Err(CheckpointError::NoCheckpoints { path: outer });
    }

    checkpoints.sort_unstable_by_key(|checkpoint| checkpoint.height);
    Ok(checkpoints)
}

pub fn current_checkpoint(base: &Path) -> Result<DbCheckpointInfo, CheckpointError> {
    load_checkpoint_dirs(base)?
        .pop()
        .ok_or_else(|| CheckpointError::NoCurrentCheckpoint { path: checkpoint_outer_dir(base) })
}

/// Naming recovered around `0x37E2960`.
pub fn daily_evm_checkpoint_tar_path(data_root: &Path, date: &str, first_height: u64, last_height: u64) -> PathBuf {
    data_root
        .join(DAILY_EVM_CHECKPOINTS_DIR)
        .join(date)
        .join(format!("{first_height}_{last_height}.tar"))
}

/// Naming recovered around `0x37E2960`: `/tmp/evm_state_checkpoints_{date}_{first}_{last}.tar`.
pub fn tmp_evm_checkpoint_tar_path(date: &str, first_height: u64, last_height: u64) -> PathBuf {
    PathBuf::from(format!("/tmp/{TMP_EVM_TAR_PREFIX}_{date}_{first_height}_{last_height}.tar"))
}

pub fn plan_daily_evm_checkpoint_tar(
    data_root: &Path,
    date: &str,
    members: Vec<DbCheckpointInfo>,
) -> Option<EvmCheckpointTarPlan> {
    let first_height = members.first()?.height;
    let last_height = members.last()?.height;
    Some(EvmCheckpointTarPlan {
        first_height,
        last_height,
        target: daily_evm_checkpoint_tar_path(data_root, date, first_height, last_height),
        tmp: tmp_evm_checkpoint_tar_path(date, first_height, last_height),
        members,
    })
}

/// Tar flow recovered from `0x37E2960` as called by `0x432F310`'s true branch.
///
/// The binary skips when the target tar already exists, creates a temp tar under
/// `/tmp`, and then moves it into the daily target path.
pub fn tar_daily_evm_checkpoints(data_root: &Path, date: &str) -> Result<Option<EvmCheckpointTarPlan>, CheckpointError> {
    let members = match load_checkpoint_dirs(data_root) {
        Ok(members) => members,
        Err(CheckpointError::NoCheckpoints { .. }) => return Ok(None),
        Err(err) => return Err(err),
    };

    let Some(plan) = plan_daily_evm_checkpoint_tar(data_root, date, members) else {
        return Ok(None);
    };
    if plan.target.exists() {
        return Ok(None);
    }

    if let Some(parent) = plan.target.parent() {
        fs::create_dir_all(parent).map_err(|source| CheckpointError::io(parent, source))?;
    }

    let outer = checkpoint_outer_dir(data_root);
    let mut command = Command::new("tar");
    command.arg("-cf").arg(&plan.tmp).arg("-C").arg(&outer);
    for member in &plan.members {
        // Heights are the checkpoint directory names; this avoids passing full
        // paths after `-C <base>/checkpoint`, matching the loader's layout.
        command.arg(member.height.to_string());
    }

    let output = command.output().map_err(|source| CheckpointError::io(&plan.tmp, source))?;
    if !output.status.success() {
        return Err(CheckpointError::TarFailed {
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    fs::rename(&plan.tmp, &plan.target).map_err(|source| CheckpointError::io(&plan.target, source))?;
    Ok(Some(plan))
}

/// Prune flow recovered from `0x37E3A70`; `0x432F310` passes `n_keep = 100`.
pub fn prune_lowest_evm_checkpoints(data_root: &Path, n_keep: usize) -> Result<Vec<DbCheckpointInfo>, CheckpointError> {
    let checkpoints = match load_checkpoint_dirs(data_root) {
        Ok(checkpoints) => checkpoints,
        Err(CheckpointError::NoCheckpoints { .. }) => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let prune_count = checkpoints.len().saturating_sub(n_keep);
    let mut removed = Vec::with_capacity(prune_count);

    for checkpoint in checkpoints.into_iter().take(prune_count) {
        if checkpoint.path.exists() {
            fs::remove_dir_all(&checkpoint.path).map_err(|source| CheckpointError::io(&checkpoint.path, source))?;
        }
        removed.push(checkpoint);
    }

    Ok(removed)
}

/// Branch wrapper recovered from `0x432F310`.
pub fn periodic_evm_checkpoint_maintenance(
    data_root: &Path,
    tar_previous_day: bool,
    date: &str,
) -> Result<(), CheckpointError> {
    if tar_previous_day {
        let _ = tar_daily_evm_checkpoints(data_root, date)?;
    } else {
        let _ = prune_lowest_evm_checkpoints(data_root, DEFAULT_PRUNE_KEEP)?;
    }
    Ok(())
}

/// [INFERENCE: extension] protocol notes and state dump code use `.rmp` for ABCI
/// snapshots; the local cluster proves the `visor_abci_states` directory name and
/// numeric height handling, but not the literal `.rmp` suffix in this function.
pub fn visor_abci_state_path(data_root: &Path, date: &str, height: u64) -> AbciCheckpointPath {
    AbciCheckpointPath {
        date: date.to_owned(),
        height,
        path: visor_abci_states_dir(data_root).join(date).join(format!("{height}.rmp")),
    }
}

pub fn serialize_checkpoint_state<State, C>(state: &State, codec: &mut C) -> io::Result<Vec<u8>>
where
    C: CheckpointCodec<State>,
{
    let mut bytes = Vec::new();
    codec.encode_checkpoint(state, &mut bytes)?;
    Ok(bytes)
}

pub fn write_serialized_checkpoint<State, C>(path: &Path, state: &State, codec: &mut C) -> io::Result<()>
where
    C: CheckpointCodec<State>,
{
    let bytes = serialize_checkpoint_state(state, codec)?;
    write_checkpoint_bytes(path, &bytes)
}

/// Atomic-ish write path matching `0x432FC10`'s temp-label/move behavior.
pub fn write_checkpoint_bytes(final_path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = final_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = retry_checkpoint_path(final_path);
    {
        let mut file = File::create(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    rename_checkpoint_file(&tmp_path, final_path)
}

pub fn retry_checkpoint_path(final_path: &Path) -> PathBuf {
    let file_name = final_path.file_name().unwrap_or_else(|| OsStr::new("checkpoint"));
    final_path.with_file_name(format!("{}.{}", file_name.to_string_lossy(), ZIP_INNER_RETRY))
}

/// Seed `0x432FC10`: the binary unwraps this move and frees both source and temp
/// strings after comparing/building the `zip_inner_retry` path.
pub fn rename_checkpoint_file(tmp_path: &Path, final_path: &Path) -> io::Result<()> {
    fs::rename(tmp_path, final_path)
}

/// Recovered shape of `0x432F9C0`: sleep for sixty seconds, clone the protected
/// buffer while holding the byte lock, then call the zip/write helper outside the
/// critical section. The caller owns the lock implementation; this function keeps
/// the recovered timing and clone-before-write behavior.
pub fn flush_locked_checkpoint_bytes<F, W>(mut clone_locked_bytes: F, mut write: W) -> io::Result<()>
where
    F: FnMut() -> Option<(PathBuf, Vec<u8>)>,
    W: FnMut(&Path, &[u8]) -> io::Result<()>,
{
    loop {
        std::thread::sleep(Duration::from_secs(60));
        if let Some((path, bytes)) = clone_locked_bytes() {
            write(&path, &bytes)?;
        }
    }
}

pub fn monitor_visor_state_lag<S: VisorStateSource>(source: &mut S) -> io::Result<()> {
    let mut history = VecDeque::with_capacity(VISOR_HISTORY_LIMIT);
    loop {
        if let Some(current) = source.get_visor_state()? {
            if history.len() == VISOR_HISTORY_LIMIT {
                history.pop_front();
            }

            if let Some(oldest) = history.front() {
                if oldest.file_age > VISOR_LAG_ALERT_THRESHOLD && oldest.file_age > current.file_age {
                    source.log_visor_lag_increased(oldest, &current);
                }
            }

            history.push_back(current);
        }
        source.sleep(VISOR_MONITOR_SLEEP);
    }
}

pub fn visor_record_from_path(path: PathBuf) -> io::Result<Option<VisorStateRecord>> {
    let Some(height) = path.file_stem().and_then(parse_checkpoint_height) else {
        return Ok(None);
    };
    let metadata = fs::metadata(&path)?;
    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let file_age = SystemTime::now().duration_since(modified).unwrap_or_default();
    Ok(Some(VisorStateRecord { height, file_age, path }))
}
