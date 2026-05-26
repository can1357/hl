use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const EVM_KVS_MESSAGE_LABEL: &str = "evmkvsmsg";
pub const WRITE_EVM_KV_BATCH_LABEL: &str = "write evm kv batch";
pub const TCP_BYTES_LABEL: &str = "tcp_bytes";
pub const TCP_READ_EXACT_LABEL: &str = "tcp_read_exact";
pub const CHECKPOINT_DIR: &str = "checkpoint";
pub const CHECKPOINT_COMPLETE: &str = "CHECKPOINT_COMPLETE";
pub const TMP_EVM_CHECKPOINT_PREFIX: &str = "evm_state_checkpoints";
pub const DAILY_EVM_CHECKPOINTS_DIR: &str = "daily_evm_checkpoints";

pub const WRITE_EVM_KVS_TIMEOUT: Duration = Duration::from_secs(60);
pub const TCP_BYTES_TIMEOUT: Duration = Duration::from_secs(40);
pub const TCP_READ_EXACT_TIMEOUT: Duration = Duration::from_secs(20);
pub const LARGE_KV_WARN_BYTES: usize = 1_000_000;
pub const MAX_BATCH_BYTES: usize = 2_000_000;
pub const TCP_READ_CHUNK_BYTES: usize = 4_000_000;
pub const DEFAULT_PRUNE_KEEP: usize = 100;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmKv {
    pub key: Box<[u8]>,
    pub value: Box<[u8]>,
}

impl EvmKv {
    pub fn new(key: impl Into<Box<[u8]>>, value: impl Into<Box<[u8]>>) -> Self {
        Self { key: key.into(), value: value.into() }
    }

    pub fn byte_len(&self) -> usize {
        self.key.len().saturating_add(self.value.len())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvmKvBatch {
    pub entries: Vec<EvmKv>,
    pub next_key: Option<Box<[u8]>>,
    pub total_bytes: usize,
}

impl EvmKvBatch {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvmKvsWireMessage {
    Batch(EvmKvBatch),
    Finished { checkpoint_height: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmCheckpointPath {
    pub height: u64,
    pub checkpoint_dir: PathBuf,
    pub tmp_dir: PathBuf,
    pub complete_marker: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmKvsTransferStats {
    pub batches: usize,
    pub entries: usize,
    pub bytes: usize,
    pub elapsed: Duration,
}

#[derive(Debug)]
pub enum EvmKvsError {
    Io { path: Option<PathBuf>, source: io::Error },
    Store(String),
    Codec(String),
    RocksDbBug,
    HeightMismatch { checkpoint_height: u64, expected_height: u64 },
    FrameTooLarge { len: usize },
    InvalidFrameFlag(u8),
    ExistingCheckpoint { path: PathBuf },
}

impl EvmKvsError {
    fn io(source: io::Error) -> Self {
        Self::Io { path: None, source }
    }

    fn path_io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io { path: Some(path.into()), source }
    }
}

impl fmt::Display for EvmKvsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path: Some(path), source } => write!(f, "{}: {source}", path.display()),
            Self::Io { path: None, source } => fmt::Display::fmt(source, f),
            Self::Store(message) => f.write_str(message),
            Self::Codec(message) => f.write_str(message),
            Self::RocksDbBug => f.write_str("rocksdb bug"),
            Self::HeightMismatch { checkpoint_height, expected_height } => {
                write!(f, "evm kvs height mismatch: checkpoint={checkpoint_height} expected={expected_height}")
            }
            Self::FrameTooLarge { len } => write!(f, "evm kvs frame too large: {len}"),
            Self::InvalidFrameFlag(flag) => write!(f, "invalid evm kvs frame compression flag: {flag}"),
            Self::ExistingCheckpoint { path } => write!(f, "checkpoint already exists: {}", path.display()),
        }
    }
}

impl std::error::Error for EvmKvsError {}

impl From<io::Error> for EvmKvsError {
    fn from(source: io::Error) -> Self {
        Self::io(source)
    }
}

pub trait EvmKvsLogger {
    fn info(&mut self, message: &str);
    fn warn(&mut self, message: &str);
}

pub trait EvmKvsIterator {
    fn seek_to_first(&mut self) -> Result<(), EvmKvsError>;
    fn seek(&mut self, key: &[u8]) -> Result<(), EvmKvsError>;
    fn next(&mut self) -> Result<(), EvmKvsError>;
    fn current(&self) -> Result<Option<(&[u8], &[u8])>, EvmKvsError>;
}

pub trait EvmKvsStore {
    type Iter<'a>: EvmKvsIterator
    where
        Self: 'a;

    fn iter(&self) -> Result<Self::Iter<'_>, EvmKvsError>;
    fn put_kv(&mut self, key: &[u8], value: &[u8]) -> Result<(), EvmKvsError>;
    fn flush(&mut self) -> Result<(), EvmKvsError>;
}

pub trait EvmKvsCodec {
    fn encode_message(&mut self, message: &EvmKvsWireMessage, out: &mut Vec<u8>) -> Result<(), EvmKvsError>;
    fn decode_message(&mut self, bytes: &[u8]) -> Result<EvmKvsWireMessage, EvmKvsError>;
}

pub fn checkpoint_outer_dir(data_root: &Path) -> PathBuf {
    data_root.join(CHECKPOINT_DIR)
}

pub fn evm_checkpoint_dir(data_root: &Path, height: u64) -> PathBuf {
    checkpoint_outer_dir(data_root).join(height.to_string())
}

pub fn evm_checkpoint_complete_marker(data_root: &Path, height: u64) -> PathBuf {
    evm_checkpoint_dir(data_root, height).join(CHECKPOINT_COMPLETE)
}

pub fn tmp_evm_checkpoint_dir(height: u64) -> PathBuf {
    PathBuf::from(format!("/tmp/{TMP_EVM_CHECKPOINT_PREFIX}_{height}"))
}

pub fn daily_evm_checkpoint_dir(data_root: &Path, date: &str) -> PathBuf {
    data_root.join(DAILY_EVM_CHECKPOINTS_DIR).join(date)
}

pub fn evm_checkpoint_paths(data_root: &Path, height: u64) -> EvmCheckpointPath {
    let checkpoint_dir = evm_checkpoint_dir(data_root, height);
    let complete_marker = checkpoint_dir.join(CHECKPOINT_COMPLETE);
    EvmCheckpointPath { height, checkpoint_dir, tmp_dir: tmp_evm_checkpoint_dir(height), complete_marker }
}

pub fn checkpoint_exists(data_root: &Path, height: u64) -> bool {
    evm_checkpoint_complete_marker(data_root, height).is_file()
}

pub fn save_evm_kvs_checkpoint_bytes(data_root: &Path, height: u64, bytes: &[u8]) -> Result<PathBuf, EvmKvsError> {
    let paths = evm_checkpoint_paths(data_root, height);
    fs::create_dir_all(&paths.checkpoint_dir).map_err(|source| EvmKvsError::path_io(&paths.checkpoint_dir, source))?;

    // [INFERENCE] The binary logs the checkpoint byte object when ABCI state is serialized;
    // the exact leaf name is not present as a standalone string, so keep the recovered
    // per-height checkpoint directory and write a single KVS payload file inside it.
    let path = paths.checkpoint_dir.join("evm_kvs_checkpoint");
    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp).map_err(|source| EvmKvsError::path_io(&tmp, source))?;
        file.write_all(bytes).map_err(|source| EvmKvsError::path_io(&tmp, source))?;
        file.sync_all().map_err(|source| EvmKvsError::path_io(&tmp, source))?;
    }
    fs::rename(&tmp, &path).map_err(|source| EvmKvsError::path_io(&path, source))?;
    Ok(path)
}

pub fn mark_checkpoint_complete(data_root: &Path, height: u64) -> Result<(), EvmKvsError> {
    let marker = evm_checkpoint_complete_marker(data_root, height);
    if let Some(parent) = marker.parent() {
        fs::create_dir_all(parent).map_err(|source| EvmKvsError::path_io(parent, source))?;
    }
    File::create(&marker)
        .and_then(|mut file| file.write_all(b""))
        .map_err(|source| EvmKvsError::path_io(&marker, source))
}

pub fn prune_lowest_evm_checkpoints(data_root: &Path, n_keep: usize) -> Result<Vec<PathBuf>, EvmKvsError> {
    let outer = checkpoint_outer_dir(data_root);
    let mut checkpoints = Vec::new();
    let entries = match fs::read_dir(&outer) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(EvmKvsError::path_io(&outer, error)),
    };

    for entry in entries {
        let entry = entry.map_err(|source| EvmKvsError::path_io(&outer, source))?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else { continue };
        let Ok(height) = name.parse::<u64>() else { continue };
        let path = entry.path();
        if path.join(CHECKPOINT_COMPLETE).is_file() {
            checkpoints.push((height, path));
        }
    }

    checkpoints.sort_unstable_by_key(|(height, _)| *height);
    let prune_count = checkpoints.len().saturating_sub(n_keep);
    let mut removed = Vec::with_capacity(prune_count);
    for (_, path) in checkpoints.into_iter().take(prune_count) {
        fs::remove_dir_all(&path).map_err(|source| EvmKvsError::path_io(&path, source))?;
        removed.push(path);
    }
    Ok(removed)
}

pub fn collect_next_evm_kvs_batch<I, L>(
    iter: &mut I,
    start_after: Option<&[u8]>,
    logger: &mut L,
) -> Result<EvmKvBatch, EvmKvsError>
where
    I: EvmKvsIterator,
    L: EvmKvsLogger,
{
    match start_after {
        Some(key) => {
            iter.seek(key)?;
            match iter.current()? {
                Some((found, _)) if found == key => iter.next()?,
                Some(_) => return Err(EvmKvsError::RocksDbBug),
                None => return Ok(EvmKvBatch::default()),
            }
        }
        None => iter.seek_to_first()?,
    }

    let mut batch = EvmKvBatch { entries: Vec::with_capacity(8), next_key: None, total_bytes: 0 };
    while let Some((key, value)) = iter.current()? {
        let kv_bytes = key.len().saturating_add(value.len());
        if kv_bytes > LARGE_KV_WARN_BYTES {
            logger.warn(&format!("evm kvs large kv @@ [n_bytes: {kv_bytes}]"));
        }

        if !batch.entries.is_empty() && batch.total_bytes.saturating_add(kv_bytes) > MAX_BATCH_BYTES {
            batch.next_key = Some(key.into());
            break;
        }

        let entry = EvmKv::new(key, value);
        batch.total_bytes = batch.total_bytes.saturating_add(entry.byte_len());
        batch.entries.push(entry);
        iter.next()?;

        if kv_bytes > MAX_BATCH_BYTES || batch.total_bytes >= MAX_BATCH_BYTES {
            if let Some((next_key, _)) = iter.current()? {
                batch.next_key = Some(next_key.into());
            }
            break;
        }
    }

    Ok(batch)
}

pub fn collect_all_evm_kvs<S, L>(store: &S, logger: &mut L) -> Result<Vec<EvmKv>, EvmKvsError>
where
    S: EvmKvsStore,
    L: EvmKvsLogger,
{
    let mut iter = store.iter()?;
    let mut cursor = None::<Box<[u8]>>;
    let mut out = Vec::new();

    loop {
        let batch = collect_next_evm_kvs_batch(&mut iter, cursor.as_deref(), logger)?;
        let next = batch.next_key.clone();
        out.extend(batch.entries);
        match next {
            Some(key) => cursor = Some(key),
            None => break,
        }
    }

    Ok(out)
}

pub fn encode_evm_kvs_message<C>(codec: &mut C, message: &EvmKvsWireMessage) -> Result<Vec<u8>, EvmKvsError>
where
    C: EvmKvsCodec,
{
    let mut out = Vec::new();
    codec.encode_message(message, &mut out)?;
    Ok(out)
}

pub fn decode_evm_kvs_message<C>(codec: &mut C, bytes: &[u8]) -> Result<EvmKvsWireMessage, EvmKvsError>
where
    C: EvmKvsCodec,
{
    codec.decode_message(bytes)
}

pub fn encode_tcp_frame(payload: &[u8], compressed: bool, out: &mut Vec<u8>) -> Result<(), EvmKvsError> {
    let len = u32::try_from(payload.len()).map_err(|_| EvmKvsError::FrameTooLarge { len: payload.len() })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.push(u8::from(compressed));
    out.extend_from_slice(payload);
    Ok(())
}

pub fn read_tcp_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>, EvmKvsError> {
    let mut header = [0u8; 5];
    reader.read_exact(&mut header)?;
    let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    match header[4] {
        0 => read_exact_payload(reader, len),
        1 => {
            let compressed = read_exact_payload(reader, len)?;
            decompress_lz4_size_prepended(&compressed)
        }
        other => Err(EvmKvsError::InvalidFrameFlag(other)),
    }
}

fn read_exact_payload<R: Read>(reader: &mut R, len: usize) -> Result<Vec<u8>, EvmKvsError> {
    let mut bytes = vec![0u8; len];
    let mut read = 0usize;
    while read < len {
        let end = len.min(read.saturating_add(TCP_READ_CHUNK_BYTES));
        reader.read_exact(&mut bytes[read..end])?;
        read = end;
    }
    Ok(bytes)
}

fn decompress_lz4_size_prepended(bytes: &[u8]) -> Result<Vec<u8>, EvmKvsError> {
    lz4_flex::block::decompress_size_prepended(bytes)
        .map_err(|error| EvmKvsError::Codec(format!("lz4 decode failed: {error}")))
}

pub fn write_evm_kv_batch<W, C>(writer: &mut W, codec: &mut C, batch: EvmKvBatch) -> Result<(), EvmKvsError>
where
    W: Write,
    C: EvmKvsCodec,
{
    let mut payload = Vec::new();
    codec.encode_message(&EvmKvsWireMessage::Batch(batch), &mut payload)?;
    let mut frame = Vec::with_capacity(payload.len().saturating_add(5));
    encode_tcp_frame(&payload, false, &mut frame)?;
    writer.write_all(&frame)?;
    Ok(())
}

pub fn write_all_evm_kvs_to_stream<S, W, C, L>(
    store: &S,
    writer: &mut W,
    codec: &mut C,
    checkpoint_height: u64,
    logger: &mut L,
) -> Result<EvmKvsTransferStats, EvmKvsError>
where
    S: EvmKvsStore,
    W: Write,
    C: EvmKvsCodec,
    L: EvmKvsLogger,
{
    let started = Instant::now();
    let mut iter = store.iter()?;
    let mut cursor = None::<Box<[u8]>>;
    let mut stats = EvmKvsTransferStats { batches: 0, entries: 0, bytes: 0, elapsed: Duration::ZERO };

    loop {
        let batch = collect_next_evm_kvs_batch(&mut iter, cursor.as_deref(), logger)?;
        if batch.is_empty() {
            break;
        }
        stats.batches += 1;
        stats.entries += batch.entries.len();
        stats.bytes = stats.bytes.saturating_add(batch.total_bytes);
        cursor = batch.next_key.clone();
        write_evm_kv_batch(writer, codec, batch)?;
        if cursor.is_none() {
            break;
        }
    }

    let mut payload = Vec::new();
    codec.encode_message(&EvmKvsWireMessage::Finished { checkpoint_height }, &mut payload)?;
    let mut frame = Vec::with_capacity(payload.len().saturating_add(5));
    encode_tcp_frame(&payload, false, &mut frame)?;
    writer.write_all(&frame)?;

    stats.elapsed = started.elapsed();
    logger.info(&format!("@@ wrote evm kvs to stream @@ [n_bytes: {}] [n_batches: {}]", stats.bytes, stats.batches));
    Ok(stats)
}

pub fn receive_evm_kvs_checkpoint<R, C, S, L>(
    reader: &mut R,
    codec: &mut C,
    store: &mut S,
    data_root: &Path,
    expected_height: u64,
    logger: &mut L,
) -> Result<EvmKvsTransferStats, EvmKvsError>
where
    R: Read,
    C: EvmKvsCodec,
    S: EvmKvsStore,
    L: EvmKvsLogger,
{
    let paths = evm_checkpoint_paths(data_root, expected_height);
    if paths.complete_marker.is_file() {
        logger.warn(&format!(
            "receiving evm kvs for checkpoint that already exists @@ [checkpoint_dir: {}]",
            paths.checkpoint_dir.display()
        ));
        return Err(EvmKvsError::ExistingCheckpoint { path: paths.checkpoint_dir });
    }

    fs::create_dir_all(&paths.tmp_dir).map_err(|source| EvmKvsError::path_io(&paths.tmp_dir, source))?;
    let started = Instant::now();
    let mut stats = EvmKvsTransferStats { batches: 0, entries: 0, bytes: 0, elapsed: Duration::ZERO };

    loop {
        let frame = read_tcp_frame(reader)?;
        match codec.decode_message(&frame)? {
            EvmKvsWireMessage::Batch(batch) => {
                for entry in batch.entries {
                    stats.entries += 1;
                    stats.bytes = stats.bytes.saturating_add(entry.byte_len());
                    store.put_kv(&entry.key, &entry.value)?;
                }
                stats.batches += 1;
                if stats.bytes >> 11 > 0x02e9_0edc {
                    return Err(EvmKvsError::Store("RocksDb too large".to_owned()));
                }
            }
            EvmKvsWireMessage::Finished { checkpoint_height } => {
                if checkpoint_height != 0 && checkpoint_height != expected_height {
                    logger.warn(&format!(
                        "@@ evm kvs height mismatch @@ [checkpoint_height: {checkpoint_height}] [expected_height: {expected_height}]"
                    ));
                    return Err(EvmKvsError::HeightMismatch { checkpoint_height, expected_height });
                }
                break;
            }
        }
    }

    store.flush()?;
    fs::create_dir_all(&paths.checkpoint_dir).map_err(|source| EvmKvsError::path_io(&paths.checkpoint_dir, source))?;
    mark_checkpoint_complete(data_root, expected_height)?;
    let _ = fs::remove_dir_all(&paths.tmp_dir);

    stats.elapsed = started.elapsed();
    Ok(stats)
}
