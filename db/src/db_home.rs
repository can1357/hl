use std::error::Error;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

const CHECKPOINT_DIR: &str = "checkpoint";
const CHECKPOINT_COMPLETE: &str = "CHECKPOINT_COMPLETE";
const LT_HASHES_JSON: &str = "lt_hashes.json";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DbBundle {
    Exchange,
    Rpc,
    EvmState,
}

impl DbBundle {
    pub const ALL: [Self; 3] = [Self::Exchange, Self::Rpc, Self::EvmState];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exchange => "Exchange",
            Self::Rpc => "Rpc",
            Self::EvmState => "EvmState",
        }
    }
}

impl fmt::Display for DbBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DbHome {
    path: PathBuf,
}

impl DbHome {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn as_path(&self) -> &Path {
        &self.path
    }

    pub fn into_path_buf(self) -> PathBuf {
        self.path
    }

    pub fn checkpoint_outer_dir(&self) -> PathBuf {
        self.path.join(CHECKPOINT_DIR)
    }

    pub fn checkpoint_dir(&self, shard: u64) -> PathBuf {
        self.checkpoint_outer_dir().join(shard.to_string())
    }

    pub fn checkpoint_path(&self, shard: u64) -> DbCheckpointPath {
        DbCheckpointPath {
            path: self.checkpoint_dir(shard),
            shard,
        }
    }

    pub fn bundle_path(&self, shard: u64, bundle: DbBundle) -> PathBuf {
        self.checkpoint_dir(shard).join(bundle.as_str())
    }

    pub fn lt_hashes_path(&self, shard: u64) -> PathBuf {
        self.checkpoint_dir(shard).join(LT_HASHES_JSON)
    }

    pub fn evm_state_db_home(&self) -> Result<EvmStateDbHome, DbHomeError> {
        EvmStateDbHome::new(self)
    }

    pub fn ensure_checkpoint_outer_dir(&self) -> Result<PathBuf, DbHomeError> {
        let path = self.checkpoint_outer_dir();
        if !path_is_dir(&path) {
            fs::create_dir_all(&path).map_err(|source| DbHomeError::Io {
                op: "create_dir_all",
                path: path.clone(),
                source,
            })?;
        }
        Ok(path)
    }

    pub fn ensure_checkpoint_dir(&self, shard: u64) -> Result<DbCheckpointPath, DbHomeError> {
        let checkpoint = self.checkpoint_path(shard);
        if !path_is_dir(checkpoint.path()) {
            fs::create_dir_all(checkpoint.path()).map_err(|source| DbHomeError::Io {
                op: "create_dir_all",
                path: checkpoint.path.clone(),
                source,
            })?;
        }
        Ok(checkpoint)
    }

    /// Return loadable checkpoints from the checkpoint outer directory, newest first.
    ///
    /// Recovered control flow: the binary formats `<db_home>/checkpoint`, rejects a
    /// missing outer directory, collects numeric children with no suffix, reverses
    /// the sorted list, parses the last path component as `u64`, and keeps a child
    /// if either `<child>/CHECKPOINT_COMPLETE` or legacy `<child>/EvmState` is a
    /// regular file. Signed and overflowing numeric components are ignored.
    pub fn checkpoint_paths(&self) -> Result<Vec<DbCheckpointPath>, DbHomeError> {
        let outer = self.checkpoint_outer_dir();
        if !path_is_dir(&outer) {
            return Err(DbHomeError::CheckpointOuterDirMissing(outer));
        }

        let mut checkpoint_dirs = collect_sorted_numbered_paths(&outer)?;
        if checkpoint_dirs.is_empty() {
            return Err(DbHomeError::NoCheckpoints(outer));
        }

        checkpoint_dirs.reverse();
        let mut out = Vec::new();
        let mut rejected = Vec::new();
        for path in checkpoint_dirs {
            let Some(shard) = parse_last_component_u64(&path) else {
                continue;
            };
            let checkpoint = DbCheckpointPath { path, shard };
            if checkpoint.is_loadable() {
                out.push(checkpoint);
            } else {
                rejected.push(checkpoint.path);
            }
        }

        if out.is_empty() {
            return Err(DbHomeError::UnableToLoadAnyCurrentCheckpoint { outer, rejected });
        }
        Ok(out)
    }

    pub fn checkpoint_for_shard(&self, shard: u64) -> Result<Option<DbCheckpointPath>, DbHomeError> {
        let mut checkpoints = self.checkpoint_paths()?;
        for checkpoint in checkpoints.drain(..) {
            if checkpoint.shard == shard {
                return Ok(Some(checkpoint));
            }
        }
        Ok(None)
    }

    pub fn latest_checkpoint(&self) -> Result<DbCheckpointPath, DbHomeError> {
        self.checkpoint_paths()?
            .into_iter()
            .next()
            .ok_or_else(|| DbHomeError::NoCheckpoints(self.checkpoint_outer_dir()))
    }

    /// Create a new checkpoint directory by copying a bundle from an existing checkpoint.
    /// The hard-link branch mirrors the observed `cp -al` path; the other branch uses
    /// a regular file copy. Callers touch `CHECKPOINT_COMPLETE` after all bundle files
    /// and `lt_hashes.json` have been published.
    pub fn copy_bundle_to_checkpoint(
        &self,
        from: &DbCheckpointPath,
        to_shard: u64,
        bundle: DbBundle,
        hard_link_copy: bool,
    ) -> Result<PathBuf, DbHomeError> {
        let to = self.ensure_checkpoint_dir(to_shard)?.bundle_path(bundle);
        let from = from.bundle_path(bundle);
        if hard_link_copy {
            copy_path_shell(&from, &to, true)?;
        } else {
            copy_regular_file(&from, &to)?;
        }
        touch_if_missing(&to)?;
        Ok(to)
    }
}

impl fmt::Display for DbHome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.path.display().fmt(f)
    }
}

impl From<PathBuf> for DbHome {
    fn from(path: PathBuf) -> Self {
        Self::new(path)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DbCheckpointPath {
    path: PathBuf,
    shard: u64,
}

impl DbCheckpointPath {
    pub fn new(home: &DbHome, shard: u64) -> Self {
        home.checkpoint_path(shard)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn shard(&self) -> u64 {
        self.shard
    }

    pub fn bundle_path(&self, bundle: DbBundle) -> PathBuf {
        self.path.join(bundle.as_str())
    }

    pub fn checkpoint_complete_path(&self) -> PathBuf {
        self.path.join(CHECKPOINT_COMPLETE)
    }

    pub fn lt_hashes_path(&self) -> PathBuf {
        self.path.join(LT_HASHES_JSON)
    }

    pub fn is_loadable(&self) -> bool {
        path_is_regular_file(&self.checkpoint_complete_path())
            || path_is_regular_file(&self.bundle_path(DbBundle::EvmState))
    }

    pub fn mark_complete(&self) -> Result<(), DbHomeError> {
        touch_if_missing(&self.checkpoint_complete_path())
    }

    pub fn into_path_buf(self) -> PathBuf {
        self.path
    }
}

impl fmt::Display for DbCheckpointPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.path.display().fmt(f)
    }
}

/// Path helper used before opening the EVM RocksDB instance.
///
/// The binary formats the home path, rejects homes that already contain a DB
/// bundle name, then appends `EvmState` for the RocksDB directory.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EvmStateDbHome {
    path: PathBuf,
}

impl EvmStateDbHome {
    pub fn new(db_home: &DbHome) -> Result<Self, DbHomeError> {
        reject_home_containing_bundle_name(db_home.as_path())?;
        Ok(Self {
            path: db_home.as_path().join(DbBundle::EvmState.as_str()),
        })
    }

    pub fn as_path(&self) -> &Path {
        &self.path
    }

    pub fn into_path_buf(self) -> PathBuf {
        self.path
    }
}

impl fmt::Display for EvmStateDbHome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.path.display().fmt(f)
    }
}

#[derive(Debug)]
pub enum DbHomeError {
    CheckpointOuterDirMissing(PathBuf),
    ReadDir { path: PathBuf, source: io::Error },
    NoCheckpoints(PathBuf),
    UnableToLoadAnyCurrentCheckpoint { outer: PathBuf, rejected: Vec<PathBuf> },
    HomeContainsBundle { home: PathBuf, bundle: DbBundle },
    Io { op: &'static str, path: PathBuf, source: io::Error },
}

impl fmt::Display for DbHomeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CheckpointOuterDirMissing(path) => {
                write!(f, "checkpoint outer dir does not exist {}", path.display())
            }
            Self::ReadDir { path, source } => write!(f, "read_dir {} failed: {source}", path.display()),
            Self::NoCheckpoints(path) => write!(f, "no checkpoints to load: {}", path.display()),
            Self::UnableToLoadAnyCurrentCheckpoint { outer, rejected } => write!(
                f,
                "unable to load any current checkpoint from {} {:?}",
                outer.display(),
                rejected
            ),
            Self::HomeContainsBundle { home, bundle } => {
                write!(f, "$db_home contains db_bundle in path: {} contains {bundle}", home.display())
            }
            Self::Io { op, path, source } => write!(f, "{op} {} failed: {source}", path.display()),
        }
    }
}

impl Error for DbHomeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ReadDir { source, .. } | Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn collect_sorted_numbered_paths(base_dir: &Path) -> Result<Vec<PathBuf>, DbHomeError> {
    let read_dir = fs::read_dir(base_dir).map_err(|source| DbHomeError::ReadDir {
        path: base_dir.to_path_buf(),
        source,
    })?;

    let mut out = Vec::new();
    for entry in read_dir {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if parse_last_component_u64(&path).is_some() {
            out.push(path);
        }
    }
    out.sort_by(|a, b| {
        let lhs = parse_last_component_u64(a).unwrap_or(0);
        let rhs = parse_last_component_u64(b).unwrap_or(0);
        lhs.cmp(&rhs)
    });
    Ok(out)
}

fn parse_last_component_u64(path: &Path) -> Option<u64> {
    let name = path.file_name()?.to_str()?;
    parse_unsigned_decimal_u64(name)
}

fn parse_unsigned_decimal_u64(s: &str) -> Option<u64> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || matches!(bytes[0], b'+' | b'-') {
        return None;
    }

    let mut value = 0_u64;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((byte - b'0') as u64)?;
    }
    Some(value)
}

fn path_is_dir(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
}

fn path_is_regular_file(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
}

fn touch_if_missing(path: &Path) -> Result<(), DbHomeError> {
    if path_is_regular_file(path) {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !path_is_dir(parent) {
            fs::create_dir_all(parent).map_err(|source| DbHomeError::Io {
                op: "create_dir_all",
                path: parent.to_path_buf(),
                source,
            })?;
        }
    }

    OpenOptions::new()
        .create(true)
        .write(true)
        .open(path)
        .map(|_| ())
        .map_err(|source| DbHomeError::Io {
            op: "touch",
            path: path.to_path_buf(),
            source,
        })
}

fn copy_regular_file(from: &Path, to: &Path) -> Result<(), DbHomeError> {
    if !path_is_regular_file(from) {
        return Err(DbHomeError::Io {
            op: "copy_file",
            path: from.to_path_buf(),
            source: io::Error::new(io::ErrorKind::NotFound, "source bundle file does not exist"),
        });
    }

    if let Some(parent) = to.parent() {
        if !parent.as_os_str().is_empty() && !path_is_dir(parent) {
            fs::create_dir_all(parent).map_err(|source| DbHomeError::Io {
                op: "create_dir_all",
                path: parent.to_path_buf(),
                source,
            })?;
        }
    }

    fs::copy(from, to)
        .map(|_| ())
        .map_err(|source| DbHomeError::Io {
            op: "copy_file",
            path: to.to_path_buf(),
            source,
        })
}

fn copy_path_shell(from: &Path, to: &Path, hard_link_copy: bool) -> Result<(), DbHomeError> {
    if let Some(parent) = to.parent() {
        if !parent.as_os_str().is_empty() && !path_is_dir(parent) {
            fs::create_dir_all(parent).map_err(|source| DbHomeError::Io {
                op: "create_dir_all",
                path: parent.to_path_buf(),
                source,
            })?;
        }
    }

    let flag = if hard_link_copy { "-al" } else { "-R" };
    let status = std::process::Command::new("cp")
        .arg(flag)
        .arg(from)
        .arg(to)
        .status()
        .map_err(|source| DbHomeError::Io {
            op: "cp",
            path: from.to_path_buf(),
            source,
        })?;

    if status.success() {
        Ok(())
    } else {
        Err(DbHomeError::Io {
            op: "cp",
            path: to.to_path_buf(),
            source: io::Error::new(io::ErrorKind::Other, format!("cp exited with {status}")),
        })
    }
}

fn reject_home_containing_bundle_name(path: &Path) -> Result<(), DbHomeError> {
    let rendered = path.to_string_lossy();
    for bundle in DbBundle::ALL {
        if rendered.contains(bundle.as_str()) {
            return Err(DbHomeError::HomeContainsBundle {
                home: path.to_path_buf(),
                bundle,
            });
        }
    }
    Ok(())
}
