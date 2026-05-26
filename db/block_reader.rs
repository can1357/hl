use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;

pub type BlockHeight = u64;
pub type BlockHash = [u8; 32];

pub const MAX_ARCHIVE_BATCH: usize = 5;
pub const HEIGHT_KEY_LEN: usize = 8;
pub const STORED_BLOCK_RECORD_LEN: usize = 0x398;
pub const BLOOM_LEN: usize = 0x100;

// 0x27B6540 and 0x27BBE50 compare this selector through the DB column-family map.
// The byte value was recovered as the call-site shape rather than as a string name.
pub const CLIENT_BLOCKS_CF: u8 = 0;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientBlock {
    // The block reader returns the ClientBlock value as an owned payload.  This file preserves
    // the exact bytes at the reader boundary instead of inventing field values for the
    // bincode-fork parser reconstructed elsewhere.
    pub encoded: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientBlocksResponse {
    // Wire shape: GossipRpcResponse::ClientBlocks(Vec<(BlockHash, ClientBlock)>).
    pub blocks: Vec<(BlockHash, ClientBlock)>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BlocksAndTxsPayload {
    pub heights: Vec<BlockHeight>,
    pub price_ratios: Vec<f64>,
    pub normalized_weights: Vec<f64>,
    pub tx_targets: Vec<Vec<(u64, u64)>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockReadError {
    InvalidRange,
    TooManyRequested { requested: usize, max: usize },
    MissingColumnFamily(u8),
    Iterator(String),
    MissingRecord(BlockHeight),
    MalformedHeightKey { len: usize },
    MalformedRecord { height: Option<BlockHeight>, len: usize },
    InvalidWeightSeries,
    ChildReadFailed,
}

impl fmt::Display for BlockReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRange => f.write_str("invalid client block range"),
            Self::TooManyRequested { requested, max } => {
                write!(f, "too many client blocks requested: {requested} > {max}")
            }
            Self::MissingColumnFamily(cf) => write!(f, "missing column family {cf}"),
            Self::Iterator(err) => f.write_str(err),
            Self::MissingRecord(height) => write!(f, "missing client block at height {height}"),
            Self::MalformedHeightKey { len } => write!(f, "malformed block height key length {len}"),
            Self::MalformedRecord { height, len } => match height {
                Some(height) => write!(f, "malformed client block record at height {height}: {len} bytes"),
                None => write!(f, "malformed client block record: {len} bytes"),
            },
            Self::InvalidWeightSeries => f.write_str("invalid block weight/percentage series"),
            Self::ChildReadFailed => f.write_str("client block child read failed"),
        }
    }
}

pub trait BlockReaderDb {
    type Iter<'a>: Iterator<Item = Result<(Cow<'a, [u8]>, Cow<'a, [u8]>), BlockReadError>>
    where
        Self: 'a;

    fn iter_from<'a>(&'a self, cf: u8, key: &[u8]) -> Result<Self::Iter<'a>, BlockReadError>;
    fn get(&self, cf: u8, key: &[u8]) -> Result<Option<Vec<u8>>, BlockReadError>;
}

#[derive(Clone, Debug)]
pub struct BlockReader<D> {
    db: D,
    column_families: BTreeMap<u8, ()>,
}

impl<D> BlockReader<D> {
    pub fn new(db: D, column_families: BTreeMap<u8, ()>) -> Self {
        Self { db, column_families }
    }

    fn require_cf(&self, cf: u8) -> Result<(), BlockReadError> {
        if self.column_families.contains_key(&cf) {
            Ok(())
        } else {
            // 0x27BBE50: missing map entry takes the same error path as a bad iterator item;
            // source-level reconstruction keeps it distinct before formatting to RPC error tag 33.
            Err(BlockReadError::MissingColumnFamily(cf))
        }
    }
}

impl<D: BlockReaderDb> BlockReader<D> {
    pub fn read_client_block(&self, height: BlockHeight) -> Result<Option<(BlockHash, ClientBlock)>, BlockReadError> {
        self.require_cf(CLIENT_BLOCKS_CF)?;
        let key = encode_height_key(height);
        let Some(raw) = self.db.get(CLIENT_BLOCKS_CF, &key)? else {
            return Ok(None);
        };
        let record = decode_stored_client_block(Some(height), &raw)?;
        Ok(Some((record.hash, record.block)))
    }

    pub fn read_client_blocks_after(
        &self,
        after_height: BlockHeight,
        requested: usize,
    ) -> Result<ClientBlocksResponse, BlockReadError> {
        self.require_cf(CLIENT_BLOCKS_CF)?;
        if requested > MAX_ARCHIVE_BATCH {
            return Err(BlockReadError::TooManyRequested { requested, max: MAX_ARCHIVE_BATCH });
        }
        let start_height = after_height.checked_add(1).ok_or(BlockReadError::InvalidRange)?;
        let start_key = encode_height_key(start_height);
        let mut iter = self.db.iter_from(CLIENT_BLOCKS_CF, &start_key)?;
        let mut out = Vec::with_capacity(requested);

        while out.len() < requested {
            let Some(next) = iter.next() else { break };
            let (key, value) = next?;
            let height = decode_height_key(&key)?;
            if height < start_height {
                continue;
            }
            let record = decode_stored_client_block(Some(height), &value)?;
            out.push((record.hash, record.block));
        }

        Ok(ClientBlocksResponse { blocks: out })
    }

    pub fn read_exact_client_blocks(
        &self,
        first_height: BlockHeight,
        count: usize,
    ) -> Result<ClientBlocksResponse, BlockReadError> {
        if count > MAX_ARCHIVE_BATCH {
            return Err(BlockReadError::TooManyRequested { requested: count, max: MAX_ARCHIVE_BATCH });
        }

        let mut blocks = Vec::with_capacity(count);
        for offset in 0..count {
            let height = first_height
                .checked_add(offset as u64)
                .ok_or(BlockReadError::InvalidRange)?;
            match self.read_client_block(height)? {
                Some(block) => blocks.push(block),
                None => return Err(BlockReadError::MissingRecord(height)),
            }
        }
        Ok(ClientBlocksResponse { blocks })
    }

    pub fn read_filtered_client_blocks(
        &self,
        after_height: BlockHeight,
        requested: usize,
        filter: &BlockFilter,
    ) -> Result<ClientBlocksResponse, BlockReadError> {
        let response = self.read_client_blocks_after(after_height, requested)?;
        let mut blocks = Vec::with_capacity(response.blocks.len());
        for (hash, block) in response.blocks {
            if filter.accepts(&block.encoded) {
                blocks.push((hash, block));
            }
        }
        Ok(ClientBlocksResponse { blocks })
    }

    pub fn read_blocks_and_txs_payload(
        &self,
        after_height: BlockHeight,
        requested: usize,
    ) -> Result<BlocksAndTxsPayload, BlockReadError> {
        let response = self.read_client_blocks_after(after_height, requested.min(MAX_ARCHIVE_BATCH))?;
        let mut heights = Vec::with_capacity(response.blocks.len());
        let mut price_ratios = Vec::with_capacity(response.blocks.len());
        let mut normalized_weights = Vec::with_capacity(response.blocks.len());
        let mut tx_targets = Vec::with_capacity(response.blocks.len());

        for (index, (_hash, block)) in response.blocks.iter().enumerate() {
            let height = after_height
                .checked_add(1)
                .and_then(|height| height.checked_add(index as u64))
                .ok_or(BlockReadError::InvalidRange)?;
            let metrics = decode_record_metrics(height, &block.encoded)?;
            heights.push(height);
            price_ratios.push(metrics.price_ratio);
            normalized_weights.push(metrics.normalized_weight);
            tx_targets.push(metrics.tx_targets);
        }

        validate_monotone_percentages(&price_ratios)?;
        Ok(BlocksAndTxsPayload { heights, price_ratios, normalized_weights, tx_targets })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlockFilter {
    pub required_blooms: Vec<[u8; BLOOM_LEN]>,
    pub excluded_blooms: Vec<[u8; BLOOM_LEN]>,
}

impl BlockFilter {
    pub fn accepts(&self, encoded_block: &[u8]) -> bool {
        let Some(bloom) = block_bloom(encoded_block) else {
            return self.required_blooms.is_empty();
        };

        if !self.required_blooms.is_empty()
            && !self.required_blooms.iter().any(|mask| bloom_contains_mask(bloom, mask))
        {
            return false;
        }

        !self.excluded_blooms.iter().any(|mask| bloom_contains_mask(bloom, mask))
    }
}

#[derive(Clone, Debug)]
struct StoredClientBlock {
    hash: BlockHash,
    block: ClientBlock,
}

#[derive(Clone, Debug)]
struct RecordMetrics {
    price_ratio: f64,
    normalized_weight: f64,
    tx_targets: Vec<(u64, u64)>,
}

pub fn encode_height_key(height: BlockHeight) -> [u8; HEIGHT_KEY_LEN] {
    // [INFERENCE] Lexicographic DB iteration over heights requires big-endian u64 keys.
    height.to_be_bytes()
}

pub fn decode_height_key(key: &[u8]) -> Result<BlockHeight, BlockReadError> {
    if key.len() != HEIGHT_KEY_LEN {
        return Err(BlockReadError::MalformedHeightKey { len: key.len() });
    }
    let mut bytes = [0u8; HEIGHT_KEY_LEN];
    bytes.copy_from_slice(key);
    Ok(u64::from_be_bytes(bytes))
}

fn decode_stored_client_block(height: Option<BlockHeight>, raw: &[u8]) -> Result<StoredClientBlock, BlockReadError> {
    if raw.len() < 32 {
        return Err(BlockReadError::MalformedRecord { height, len: raw.len() });
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&raw[..32]);
    let block_bytes = &raw[32..];

    Ok(StoredClientBlock {
        hash,
        block: decode_client_block(block_bytes),
    })
}

fn decode_client_block(encoded: &[u8]) -> ClientBlock {
    // The binary returns ClientBlock values as part of Vec<(BlockHash, ClientBlock)>.
    ClientBlock { encoded: encoded.to_vec() }
}

fn decode_record_metrics(height: BlockHeight, encoded: &[u8]) -> Result<RecordMetrics, BlockReadError> {
    if encoded.len() < STORED_BLOCK_RECORD_LEN - 32 {
        return Err(BlockReadError::MalformedRecord { height: Some(height), len: encoded.len() });
    }

    // 0x27B6540 consumes 920-byte records.  Offsets below are after the 32-byte hash split:
    // +0x218/+0x220 feed a ratio, +0x18 feeds a normalized scalar, +0x2f8/+0x300 and
    // +0x340/+0x348 describe transaction target slices.
    let denominator = read_f64_le(encoded, 0x218).unwrap_or(0.0);
    let numerator = read_f64_le(encoded, 0x220).unwrap_or(0.0);
    let price_ratio = if denominator == 0.0 { 0.0 } else { numerator / denominator };

    let normalized_weight = if encoded.get(0x10).copied().unwrap_or(0) == 0 {
        0.0
    } else {
        read_f64_le(encoded, 0x18).unwrap_or(0.0) / 786_432.0
    };

    let tx_targets = decode_tx_targets(encoded);
    Ok(RecordMetrics { price_ratio, normalized_weight, tx_targets })
}

fn validate_monotone_percentages(values: &[f64]) -> Result<(), BlockReadError> {
    // 0x27B6540 rejects values greater than 100.0 and descending adjacent entries.
    for pair in values.windows(2) {
        if pair[0] > 100.0 || pair[0] > pair[1] {
            return Err(BlockReadError::InvalidWeightSeries);
        }
    }
    if values.last().copied().unwrap_or(0.0) > 100.0 {
        return Err(BlockReadError::InvalidWeightSeries);
    }
    Ok(())
}

fn block_bloom(encoded_block: &[u8]) -> Option<&[u8; BLOOM_LEN]> {
    // 0x27C1710 compares 0x100-byte masks against each record's bloom area.
    let bytes = encoded_block.get(0xf0..0xf0 + BLOOM_LEN)?;
    bytes.try_into().ok()
}

fn bloom_contains_mask(bloom: &[u8; BLOOM_LEN], mask: &[u8; BLOOM_LEN]) -> bool {
    bloom.iter().zip(mask.iter()).all(|(byte, mask)| byte & mask == *mask)
}

fn read_f64_le(bytes: &[u8], offset: usize) -> Option<f64> {
    let slice = bytes.get(offset..offset + 8)?;
    let mut raw = [0u8; 8];
    raw.copy_from_slice(slice);
    Some(f64::from_le_bytes(raw))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    let slice = bytes.get(offset..offset + 8)?;
    let mut raw = [0u8; 8];
    raw.copy_from_slice(slice);
    Some(u64::from_le_bytes(raw))
}

fn decode_tx_targets(encoded: &[u8]) -> Vec<(u64, u64)> {
    let base = read_u64_le(encoded, 0x2f8).unwrap_or(0);
    let len = read_u64_le(encoded, 0x300).unwrap_or(0) as usize;
    let aux_base = read_u64_le(encoded, 0x340).unwrap_or(0);
    let aux_len = read_u64_le(encoded, 0x348).unwrap_or(0) as usize;

    let count = len.min(aux_len).min(64);
    let mut targets = Vec::with_capacity(count);
    for i in 0..count {
        targets.push((base.saturating_add(i as u64), aux_base.saturating_add(i as u64)));
    }
    targets
}
