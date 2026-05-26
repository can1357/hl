use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::db_home::{DbBundle, DbHome};

pub const STATE_DEFAULT_CACHE_GIB: u64 = 2;
pub const CHECKPOINT_DEFAULT_CACHE_GIB: u64 = 16;
pub const STATE_BLOCK_SIZE: usize = 0x4000;
pub const CHECKPOINT_BLOCK_SIZE: usize = 0x8000;
pub const OPTIONS_RECOVERED_128_MIB_FIELD: usize = 0x800_0000;

const GIB_SHIFT: u32 = 30;
const CACHE_GIB_SATURATION_SHIFT: u32 = 34;

pub type DbHomeMap = BTreeMap<u8, Arc<DbHome>>;

#[derive(Clone, Debug, Default)]
pub struct StateDbHomes {
    homes: DbHomeMap,
}

impl StateDbHomes {
    pub fn new(homes: DbHomeMap) -> Self {
        Self { homes }
    }

    pub fn homes(&self) -> &DbHomeMap {
        &self.homes
    }

    fn home_for_bundle(&self, bundle_id: u8) -> Arc<DbHome> {
        self.homes
            .get(&bundle_id)
            .cloned()
            .expect("no entry found for key")
    }

    fn validate_before_open(&self) {
        validate_no_home_contains_bundle(&self.homes, &[DbBundle::EvmState]);
    }
}

#[derive(Clone, Debug, Default)]
pub struct CheckpointDbHomes {
    homes: DbHomeMap,
    open_enabled: bool,
}

impl CheckpointDbHomes {
    pub fn new(homes: DbHomeMap, open_enabled: bool) -> Self {
        Self { homes, open_enabled }
    }

    pub fn homes(&self) -> &DbHomeMap {
        &self.homes
    }

    pub fn open_enabled(&self) -> bool {
        self.open_enabled
    }

    fn home_for_bundle(&self, bundle_id: u8) -> Arc<DbHome> {
        self.homes
            .get(&bundle_id)
            .cloned()
            .expect("no entry found for key")
    }

    fn validate_before_open(&self) {
        validate_no_home_contains_bundle(&self.homes, &[DbBundle::Exchange, DbBundle::Rpc]);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenProfile {
    State,
    Checkpoint,
}

impl OpenProfile {
    pub fn defaults(self) -> RocksDbOpenOptions {
        match self {
            Self::State => RocksDbOpenOptions {
                cache_bytes: cache_bytes_from_gib(STATE_DEFAULT_CACHE_GIB),
                block_size: STATE_BLOCK_SIZE,
                create_if_missing: true,
                recovered_128_mib_field: OPTIONS_RECOVERED_128_MIB_FIELD,
            },
            Self::Checkpoint => RocksDbOpenOptions {
                cache_bytes: cache_bytes_from_gib(CHECKPOINT_DEFAULT_CACHE_GIB),
                block_size: CHECKPOINT_BLOCK_SIZE,
                create_if_missing: true,
                recovered_128_mib_field: OPTIONS_RECOVERED_128_MIB_FIELD,
            },
        }
    }

    fn with_cache_gib(self, cache_gib: Option<u64>) -> RocksDbOpenOptions {
        let mut options = self.defaults();
        if let Some(cache_gib) = cache_gib {
            options.cache_bytes = cache_bytes_from_gib(cache_gib);
        }
        options
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RocksDbOpenOptions {
    pub cache_bytes: usize,
    pub block_size: usize,
    pub create_if_missing: bool,
    /// Recovered setter writes `0x8000000` into the large RocksDB options object
    /// at field offset `0x4a8`.  The wrapper treats it as an opaque project
    /// constant rather than exposing the upstream RocksDB option surface.
    pub recovered_128_mib_field: usize,
}

pub fn cache_bytes_from_gib(cache_gib: u64) -> usize {
    if cache_gib >> CACHE_GIB_SATURATION_SHIFT == 0 {
        (cache_gib << GIB_SHIFT) as usize
    } else {
        usize::MAX
    }
}

pub trait RocksDbBackend: Send + Sync + 'static {
    type Db: Send + Sync + 'static;
    type Error: fmt::Debug;
    type Iterator<'a>: RocksDbIterator + 'a
    where
        Self: 'a;

    fn open(&self, path: &Path, options: &RocksDbOpenOptions) -> Result<Self::Db, Self::Error>;
    fn get(&self, db: &Self::Db, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;
    fn put(&self, db: &Self::Db, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;
    fn iterator<'a>(&'a self, db: &'a Self::Db, mode: IteratorStart<'a>) -> Self::Iterator<'a>;
}

pub trait RocksDbIterator {
    type Error: fmt::Debug;

    fn seek_to_first(&mut self) -> Result<(), Self::Error>;
    fn seek(&mut self, key: &[u8]) -> Result<(), Self::Error>;
    fn current(&self) -> Result<Option<(&[u8], &[u8])>, Self::Error>;
    fn next(&mut self) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IteratorStart<'a> {
    First,
    From(&'a [u8]),
}

pub struct RocksDb<B: RocksDbBackend> {
    backend: Arc<B>,
    raw: B::Db,
    home: Arc<DbHome>,
    profile: OpenProfile,
    options: RocksDbOpenOptions,
}

impl<B: RocksDbBackend> RocksDb<B> {
    fn open_unwrapped(
        backend: Arc<B>,
        home: Arc<DbHome>,
        profile: OpenProfile,
        cache_gib: Option<u64>,
    ) -> Self {
        let options = profile.with_cache_gib(cache_gib);
        let raw = backend.open(home.as_path(), &options).unwrap();
        Self {
            backend,
            raw,
            home,
            profile,
            options,
        }
    }

    pub fn home(&self) -> &Arc<DbHome> {
        &self.home
    }

    pub fn path(&self) -> &Path {
        self.home.as_path()
    }

    pub fn profile(&self) -> OpenProfile {
        self.profile
    }

    pub fn open_options(&self) -> RocksDbOpenOptions {
        self.options
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, B::Error> {
        self.backend.get(&self.raw, key)
    }

    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), B::Error> {
        self.backend.put(&self.raw, key, value)
    }

    pub fn iterator(&self, mode: IteratorStart<'_>) -> B::Iterator<'_> {
        self.backend.iterator(&self.raw, mode)
    }
}

pub fn open_state_bundle_db<B: RocksDbBackend>(
    backend: Arc<B>,
    homes: &StateDbHomes,
    bundle_id: u8,
    cache_gib: Option<u64>,
) -> RocksDb<B> {
    let home = homes.home_for_bundle(bundle_id);
    homes.validate_before_open();
    RocksDb::open_unwrapped(backend, home, OpenProfile::State, cache_gib)
}

pub fn open_checkpoint_bundle_db<B: RocksDbBackend>(
    backend: Arc<B>,
    homes: &CheckpointDbHomes,
    bundle_id: u8,
    cache_gib: Option<u64>,
) -> Option<RocksDb<B>> {
    let home = homes.home_for_bundle(bundle_id);
    if !homes.open_enabled() {
        return None;
    }
    homes.validate_before_open();
    Some(RocksDb::open_unwrapped(
        backend,
        home,
        OpenProfile::Checkpoint,
        cache_gib,
    ))
}

pub fn open_state_bundles<B: RocksDbBackend>(
    backend: Arc<B>,
    homes: &StateDbHomes,
    bundle_ids: impl IntoIterator<Item = u8>,
    cache_gib: Option<u64>,
) -> Vec<(u8, Arc<RocksDb<B>>)> {
    let mut out = Vec::new();
    for bundle_id in bundle_ids {
        if bundle_id == 3 {
            continue;
        }
        let db = open_state_bundle_db(Arc::clone(&backend), homes, bundle_id, cache_gib);
        out.push((bundle_id, Arc::new(db)));
    }
    out
}

pub fn open_checkpoint_bundles<B: RocksDbBackend>(
    backend: Arc<B>,
    homes: &CheckpointDbHomes,
    bundle_ids: impl IntoIterator<Item = u8>,
    cache_gib: Option<u64>,
) -> Vec<(u8, Arc<Option<RocksDb<B>>>)> {
    let mut out = Vec::new();
    for bundle_id in bundle_ids {
        let db = open_checkpoint_bundle_db(Arc::clone(&backend), homes, bundle_id, cache_gib);
        out.push((bundle_id, Arc::new(db)));
    }
    out
}

fn validate_no_home_contains_bundle(homes: &DbHomeMap, bundles: &[DbBundle]) {
    for home in homes.values() {
        let rendered = home.as_path().to_string_lossy();
        for bundle in bundles {
            if contains_ascii_case_insensitive(rendered.as_bytes(), bundle.as_str().as_bytes())
            {
                panic!("$db_home contains db_bundle in path");
            }
        }
    }
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}
pub fn owned_path_for_logging(db_home: &Arc<DbHome>) -> PathBuf {
    db_home.as_path().to_path_buf()
}
