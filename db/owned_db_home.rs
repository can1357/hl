use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base::singleton_set::SingletonSet;

use crate::db_home::{DbHome, DbHomeError, EvmStateDbHome};

const OWNED_DB_DIR_SINGLETON_PREFIX: &str = "OwnedDbDir";
const STATE_DEFAULT_BLOCK_CACHE_GIB: usize = 2;
const CHECKPOINT_DEFAULT_BLOCK_CACHE_GIB: usize = 16;
const STATE_WRITE_BUFFER_SIZE: usize = 0x4000;
const CHECKPOINT_WRITE_BUFFER_SIZE: usize = 0x8000;
const READ_AHEAD_SIZE: usize = 0x0800_0000;

#[derive(Debug)]
pub struct OwnedDbHome {
    path: PathBuf,
    _owned_db_dir: OwnedDbDirGuard,
}

impl OwnedDbHome {
    /// Create the per-owned-db directory guard and keep the path alive behind an Arc.
    ///
    /// Recovered behavior: paths containing `checkpoint` take the logging branch
    /// with message text `OwnedDbDir invalid dir`, but construction still proceeds.
    pub fn new(path: PathBuf) -> Arc<Self> {
        if path.to_string_lossy().contains("checkpoint") {
            tracing::warn!(path = %path.display(), "OwnedDbDir invalid dir");
        }

        Arc::new(Self {
            _owned_db_dir: OwnedDbDirGuard::new(&path),
            path,
        })
    }

    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[inline]
    pub fn into_path_buf(self) -> PathBuf {
        self.path
    }
}

#[derive(Debug)]
struct OwnedDbDirGuard {
    // The binary registers `OwnedDbDir` with the rendered path and relies on the
    // guard's Drop implementation to unregister the live directory.
    _singleton: SingletonSet,
}

impl OwnedDbDirGuard {
    fn new(path: &Path) -> Self {
        let name = format!("{OWNED_DB_DIR_SINGLETON_PREFIX}{}", path.display());
        Self {
            _singleton: SingletonSet::new::<OwnedDbDirGuard>(&name),
        }
    }
}

pub type OwnedDbHomeMap = BTreeMap<u8, Arc<OwnedDbHome>>;

#[derive(Clone, Debug)]
pub struct OwnedDbHomes {
    db_home: DbHome,
    homes: OwnedDbHomeMap,
}

impl OwnedDbHomes {
    pub fn new(db_home: DbHome, homes: OwnedDbHomeMap) -> Self {
        Self { db_home, homes }
    }

    #[inline]
    pub fn db_home(&self) -> &DbHome {
        &self.db_home
    }

    #[inline]
    pub fn homes(&self) -> &OwnedDbHomeMap {
        &self.homes
    }

    #[inline]
    pub fn get(&self, shard: u8) -> Option<&Arc<OwnedDbHome>> {
        self.homes.get(&shard)
    }

    /// Open the non-checkpoint state bundle DB for `shard`.
    ///
    /// The indexed lookup intentionally mirrors the recovered panic path
    /// (`no entry found for key`) when the shard has no owned home entry.
    pub fn open_state_bundle_db<DB, E, F>(
        &self,
        shard: u8,
        block_cache_gib: Option<usize>,
        open: F,
    ) -> Result<OpenedOwnedDb<DB>, OwnedDbOpenError<E>>
    where
        F: FnOnce(&EvmStateDbHome, RocksDbOpenConfig) -> Result<DB, E>,
    {
        let owned_home = Arc::clone(&self.homes[&shard]);
        let db_path = self.db_home.evm_state_db_home()?;
        let config = RocksDbOpenConfig::state(block_cache_gib);
        let db = open(&db_path, config).map_err(OwnedDbOpenError::Open)?;
        Ok(OpenedOwnedDb::new(db, owned_home))
    }

    /// Open the checkpoint/bundle DB for `shard`.
    ///
    /// The checkpoint variant uses the larger default block cache and write
    /// buffer. The caller supplies the already-derived DB path because the
    /// recovered monomorph has an early disabled sentinel before the common open
    /// sequence.
    pub fn open_checkpoint_bundle_db<DB, E, F>(
        &self,
        shard: u8,
        checkpoint_db_home: Option<&DbHome>,
        block_cache_gib: Option<usize>,
        open: F,
    ) -> Result<Option<OpenedOwnedDb<DB>>, OwnedDbOpenError<E>>
    where
        F: FnOnce(&DbHome, RocksDbOpenConfig) -> Result<DB, E>,
    {
        let Some(checkpoint_db_home) = checkpoint_db_home else {
            return Ok(None);
        };

        let owned_home = Arc::clone(&self.homes[&shard]);
        let config = RocksDbOpenConfig::checkpoint(block_cache_gib);
        let db = open(checkpoint_db_home, config).map_err(OwnedDbOpenError::Open)?;
        Ok(Some(OpenedOwnedDb::new(db, owned_home)))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnedDbOpenKind {
    StateBundle,
    CheckpointBundle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RocksDbOpenConfig {
    pub kind: OwnedDbOpenKind,
    pub block_cache_bytes: usize,
    pub write_buffer_size: usize,
    pub verify_checksums: bool,
    pub read_ahead_size: usize,
}

impl RocksDbOpenConfig {
    pub fn state(block_cache_gib: Option<usize>) -> Self {
        Self {
            kind: OwnedDbOpenKind::StateBundle,
            block_cache_bytes: block_cache_bytes(block_cache_gib, STATE_DEFAULT_BLOCK_CACHE_GIB),
            write_buffer_size: STATE_WRITE_BUFFER_SIZE,
            verify_checksums: true,
            read_ahead_size: READ_AHEAD_SIZE,
        }
    }

    pub fn checkpoint(block_cache_gib: Option<usize>) -> Self {
        Self {
            kind: OwnedDbOpenKind::CheckpointBundle,
            block_cache_bytes: block_cache_bytes(block_cache_gib, CHECKPOINT_DEFAULT_BLOCK_CACHE_GIB),
            write_buffer_size: CHECKPOINT_WRITE_BUFFER_SIZE,
            verify_checksums: true,
            read_ahead_size: READ_AHEAD_SIZE,
        }
    }
}

#[derive(Clone, Debug)]
pub struct OpenedOwnedDb<DB> {
    db: DB,
    owned_home: Arc<OwnedDbHome>,
}

impl<DB> OpenedOwnedDb<DB> {
    pub fn new(db: DB, owned_home: Arc<OwnedDbHome>) -> Self {
        Self { db, owned_home }
    }

    #[inline]
    pub fn db(&self) -> &DB {
        &self.db
    }

    #[inline]
    pub fn owned_home(&self) -> &Arc<OwnedDbHome> {
        &self.owned_home
    }

    pub fn into_parts(self) -> (DB, Arc<OwnedDbHome>) {
        (self.db, self.owned_home)
    }
}

#[derive(Debug)]
pub enum OwnedDbOpenError<E> {
    DbHome(DbHomeError),
    Open(E),
}

impl<E> fmt::Display for OwnedDbOpenError<E>
where
    E: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DbHome(err) => err.fmt(f),
            Self::Open(err) => err.fmt(f),
        }
    }
}

impl<E> Error for OwnedDbOpenError<E>
where
    E: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::DbHome(err) => Some(err),
            Self::Open(err) => Some(err),
        }
    }
}

impl<E> From<DbHomeError> for OwnedDbOpenError<E> {
    fn from(err: DbHomeError) -> Self {
        Self::DbHome(err)
    }
}

fn block_cache_bytes(requested_gib: Option<usize>, default_gib: usize) -> usize {
    let gib = requested_gib.unwrap_or(default_gib);
    if gib >> 34 == 0 {
        gib << 30
    } else {
        usize::MAX
    }
}
