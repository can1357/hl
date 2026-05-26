use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use rocksdb::{BlockBasedOptions, Cache, DB, Options, ReadOptions};

/// Error text embedded in the binary for a failed `rocksdb_readoptions_create` call.
pub const READ_OPTIONS_CREATE_ERROR: &str = "Unable to create RocksDB read options. This is a fairly trivial call, and its failure may be indicative of a mis-compiled or mis-loaded RocksDB library.";

/// Error text embedded in each recovered RocksDB option constructor path.
pub const OPTIONS_CREATE_ERROR: &str = "Could not create RocksDB options";

const DEFAULT_SMALL_BLOCK_CACHE_GIB: u64 = 2;
const DEFAULT_LARGE_BLOCK_CACHE_GIB: u64 = 16;
const SMALL_MAX_OPEN_FILES: i32 = 0x4000;
const LARGE_MAX_OPEN_FILES: i32 = 0x8000;
const BLOCK_SIZE: usize = 0x0800_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DbOpenProfile {
    Small,
    Large,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RocksDbOptionsProfile {
    pub block_cache_gib: u64,
    pub max_open_files: i32,
}

impl RocksDbOptionsProfile {
    pub const fn small(block_cache_gib: Option<u64>) -> Self {
        Self {
            block_cache_gib: match block_cache_gib {
                Some(value) => value,
                None => DEFAULT_SMALL_BLOCK_CACHE_GIB,
            },
            max_open_files: SMALL_MAX_OPEN_FILES,
        }
    }

    pub const fn large(block_cache_gib: Option<u64>) -> Self {
        Self {
            block_cache_gib: match block_cache_gib {
                Some(value) => value,
                None => DEFAULT_LARGE_BLOCK_CACHE_GIB,
            },
            max_open_files: LARGE_MAX_OPEN_FILES,
        }
    }

    pub const fn for_profile(profile: DbOpenProfile, block_cache_gib: Option<u64>) -> Self {
        match profile {
            DbOpenProfile::Small => Self::small(block_cache_gib),
            DbOpenProfile::Large => Self::large(block_cache_gib),
        }
    }
}

#[derive(Debug)]
pub enum DhError {
    ReadOptionsCreate,
    OptionsCreate,
    Io { path: PathBuf, source: io::Error },
    RocksDb(String),
}

impl fmt::Display for DhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadOptionsCreate => f.write_str(READ_OPTIONS_CREATE_ERROR),
            Self::OptionsCreate => f.write_str(OPTIONS_CREATE_ERROR),
            Self::Io { path, source } => {
                write!(f, "Failed to create RocksDB directory: `{}`: {source}", path.display())
            }
            Self::RocksDb(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for DhError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DbHome<'a> {
    path: &'a Path,
}

impl<'a> DbHome<'a> {
    pub fn new(path: &'a Path) -> Self {
        Self { path }
    }

    pub fn as_path(self) -> &'a Path {
        self.path
    }

    pub fn child(self, name: impl AsRef<Path>) -> PathBuf {
        self.path.join(name)
    }

    pub fn ensure_child_dir(self, name: impl AsRef<Path>) -> Result<PathBuf, DhError> {
        let path = self.child(name);
        ensure_rocksdb_dir(&path)?;
        Ok(path)
    }
}


pub fn ensure_rocksdb_dir(path: &Path) -> Result<(), DhError> {
    std::fs::create_dir_all(path).map_err(|source| DhError::Io {
        path: path.to_path_buf(),
        source,
    })
}

pub fn db_path(home: impl AsRef<Path>, name: impl AsRef<Path>) -> PathBuf {
    home.as_ref().join(name)
}

pub fn cache_bytes_from_gib(gib: u64) -> usize {
    if gib >= (1u64 << 34) {
        usize::MAX
    } else {
        (gib << 30) as usize
    }
}

pub fn make_rocksdb_options(profile: RocksDbOptionsProfile) -> Result<Options, DhError> {
    let mut options = Options::default();
    options.create_if_missing(true);
    options.create_missing_column_families(true);
    options.set_max_open_files(profile.max_open_files);

    let mut table_options = BlockBasedOptions::default();
    table_options.set_cache_index_and_filter_blocks(true);
    table_options.set_block_size(BLOCK_SIZE);

    let cache = Cache::new_lru_cache(cache_bytes_from_gib(profile.block_cache_gib));
    table_options.set_block_cache(&cache);
    options.set_block_based_table_factory(&table_options);

    Ok(options)
}

pub fn make_small_rocksdb_options(block_cache_gib: Option<u64>) -> Result<Options, DhError> {
    make_rocksdb_options(RocksDbOptionsProfile::small(block_cache_gib))
}

pub fn make_large_rocksdb_options(block_cache_gib: Option<u64>) -> Result<Options, DhError> {
    make_rocksdb_options(RocksDbOptionsProfile::large(block_cache_gib))
}

pub fn open_rocksdb(
    home: DbHome<'_>,
    name: impl AsRef<Path>,
    profile: DbOpenProfile,
    block_cache_gib: Option<u64>,
) -> Result<DB, DhError> {
    let path = home.ensure_child_dir(name)?;
    let options = make_rocksdb_options(RocksDbOptionsProfile::for_profile(
        profile,
        block_cache_gib,
    ))?;
    DB::open(&options, path).map_err(|err| DhError::RocksDb(err.to_string()))
}

pub fn create_read_options() -> Result<ReadOptions, DhError> {
    // The recovered binary explicitly checks the raw read-options pointer for null and returns
    // READ_OPTIONS_CREATE_ERROR on failure. The safe Rust wrapper constructs the same object and
    // would only fail if the underlying library failed this trivial allocation.
    Ok(ReadOptions::default())
}

pub fn get_with_read_options(db: &DB, key: &[u8]) -> Result<Option<Vec<u8>>, DhError> {
    let read_options = create_read_options()?;
    db.get_opt(key, &read_options)
        .map_err(|err| DhError::RocksDb(err.to_string()))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_bytes_saturates_like_recovered_shift_guard() {
        assert_eq!(cache_bytes_from_gib(2), 2usize << 30);
        assert_eq!(cache_bytes_from_gib(16), 16usize << 30);
        assert_eq!(cache_bytes_from_gib(1u64 << 34), usize::MAX);
    }

    #[test]
    fn default_profiles_match_recovered_open_paths() {
        assert_eq!(RocksDbOptionsProfile::small(None).block_cache_gib, 2);
        assert_eq!(RocksDbOptionsProfile::large(None).block_cache_gib, 16);
        assert_eq!(RocksDbOptionsProfile::small(None).max_open_files, 0x4000);
        assert_eq!(RocksDbOptionsProfile::large(None).max_open_files, 0x8000);
    }
}
