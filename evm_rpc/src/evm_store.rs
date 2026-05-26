use core::future::Future;
use core::pin::Pin;

pub type B256 = [u8; 32];
pub type Address = [u8; 20];
pub type U256 = u128;
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = RpcResult<T>> + Send + 'a>>;

// Recovered typed-state lookup key used by the wrappers before any block or tx
// read.  A missing map entry is not treated as an empty result; it is converted
// through the common RPC error formatter (observed as error tag 33).
pub const EVM_STORE_TYPE_KEY: (u64, u64) = (0x47d2_0110_2d73_a440, 0x5620_b352_3d31_cccb);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcError {
    MissingEvmStore,
    Store(String),
    InvalidBlockRange,
    InvalidFilter,
}

pub type RpcResult<T> = Result<T, RpcError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockTag {
    Earliest,
    Latest,
    Safe,
    Finalized,
    Pending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockId {
    Hash(B256),
    Number(u64),
    Tag(BlockTag),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockQuery {
    Hash(B256),
    Number(u64),
    Earliest,
    Latest,
    Safe,
    Finalized,
    Pending,
}

impl From<BlockId> for BlockQuery {
    fn from(id: BlockId) -> Self {
        match id {
            BlockId::Hash(hash) => Self::Hash(hash),
            BlockId::Number(number) => Self::Number(number),
            BlockId::Tag(BlockTag::Earliest) => Self::Earliest,
            BlockId::Tag(BlockTag::Latest) => Self::Latest,
            BlockId::Tag(BlockTag::Safe) => Self::Safe,
            BlockId::Tag(BlockTag::Finalized) => Self::Finalized,
            BlockId::Tag(BlockTag::Pending) => Self::Pending,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockHeader {
    pub hash: B256,
    pub parent_hash: B256,
    pub number: u64,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub base_fee_per_gas: Option<U256>,
    pub logs_bloom: Bloom,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredBlock {
    pub header: BlockHeader,
    pub transactions: Vec<RecoveredTransaction>,
    pub receipts: Vec<StoredReceipt>,
    pub system_transactions: Vec<SystemTransaction>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredTransaction {
    pub hash: B256,
    pub from: Address,
    pub to: Option<Address>,
    pub nonce: u64,
    pub value: U256,
    pub gas_limit: u64,
    pub gas_price: Option<U256>,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub input: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemTransaction {
    pub index: u64,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredReceipt {
    pub transaction_hash: B256,
    pub transaction_index: u64,
    pub block_hash: B256,
    pub block_number: u64,
    pub cumulative_gas_used: u64,
    pub gas_used: u64,
    pub effective_gas_price: U256,
    pub status: Option<u64>,
    pub contract_address: Option<Address>,
    pub logs: Vec<Log>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Vec<u8>,
    pub block_hash: B256,
    pub block_number: u64,
    pub transaction_hash: B256,
    pub transaction_index: u64,
    pub log_index: u64,
    pub removed: bool,
}

pub type Bloom = [u8; 256];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionLocator {
    pub block: BlockQuery,
    pub index: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionResponse {
    pub hash: B256,
    pub from: Address,
    pub to: Option<Address>,
    pub nonce: u64,
    pub value: U256,
    pub gas: u64,
    pub gas_price: Option<U256>,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub input: Vec<u8>,
    pub block_hash: Option<B256>,
    pub block_number: Option<u64>,
    pub transaction_index: Option<u64>,
    pub effective_gas_price: Option<U256>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockResponse {
    pub hash: B256,
    pub parent_hash: B256,
    pub number: u64,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub base_fee_per_gas: Option<U256>,
    pub transactions: BlockTransactions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockTransactions {
    Hashes(Vec<B256>),
    Full(Vec<TransactionResponse>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Filter {
    pub from_block: Option<BlockQuery>,
    pub to_block: Option<BlockQuery>,
    pub block_hash: Option<B256>,
    pub addresses: Vec<Address>,
    /// Topic slots follow JSON-RPC semantics: an empty slot matches anything;
    /// a non-empty slot matches any one topic in that position.
    pub topics: Vec<Vec<B256>>,
    /// Recovered code precomputes 256-byte masks and rejects blocks/logs by
    /// AND+compare before exact topic matching.
    pub bloom_masks: Vec<Bloom>,
}

pub trait EvmStoreSource {
    type Backend: EvmStoreBackend;

    fn evm_store(&self) -> Option<&Self::Backend>;
}

pub trait EvmStoreBackend: Sync {
    fn latest_block_number<'a>(&'a self) -> StoreFuture<'a, Option<u64>>;
    fn safe_block_number<'a>(&'a self) -> StoreFuture<'a, Option<u64>>;
    fn finalized_block_number<'a>(&'a self) -> StoreFuture<'a, Option<u64>>;
    fn block_number_by_hash<'a>(&'a self, hash: &'a B256) -> StoreFuture<'a, Option<u64>>;
    fn transaction_locator<'a>(&'a self, hash: &'a B256) -> StoreFuture<'a, Option<TransactionLocator>>;
    fn block_by_number<'a>(&'a self, number: u64) -> StoreFuture<'a, Option<StoredBlock>>;
    fn blocks_by_number<'a>(&'a self, first: u64, last: u64) -> StoreFuture<'a, Vec<StoredBlock>>;
}

#[derive(Clone, Debug)]
pub struct EvmStore<S> {
    state: S,
}

impl<S> EvmStore<S> {
    pub fn new(state: S) -> Self {
        Self { state }
    }

    pub fn into_inner(self) -> S {
        self.state
    }
}

impl<S> EvmStore<S>
where
    S: EvmStoreSource + Sync,
{
    fn backend(&self) -> RpcResult<&S::Backend> {
        self.state.evm_store().ok_or(RpcError::MissingEvmStore)
    }

    pub async fn block_response_from_query(
        &self,
        query: BlockQuery,
        full_transactions: bool,
    ) -> RpcResult<Option<BlockResponse>> {
        let Some(block) = self.resolve_block_query(query).await? else {
            return Ok(None);
        };
        Ok(Some(format_block_response(&block, full_transactions)))
    }

    pub async fn get_block_by_hash(
        &self,
        hash: B256,
        full_transactions: bool,
    ) -> RpcResult<Option<BlockResponse>> {
        let backend = self.backend()?;
        let Some(number) = backend.block_number_by_hash(&hash).await? else {
            return Ok(None);
        };
        self.block_response_from_query(BlockQuery::Number(number), full_transactions)
            .await
    }

    pub async fn transaction_by_block_index_from_query(
        &self,
        query: BlockQuery,
        index: u64,
    ) -> RpcResult<Option<TransactionResponse>> {
        let Some(block) = self.resolve_block_query(query).await? else {
            return Ok(None);
        };
        Ok(transaction_response_at(&block, index))
    }

    pub async fn read_block_then_tx_by_index(
        &self,
        query: BlockQuery,
        index: u64,
    ) -> RpcResult<Option<TransactionResponse>> {
        self.transaction_by_block_index_from_query(query, index).await
    }

    pub async fn get_transaction_by_hash(
        &self,
        hash: B256,
    ) -> RpcResult<Option<TransactionResponse>> {
        let backend = self.backend()?;
        let Some(locator) = backend.transaction_locator(&hash).await? else {
            return Ok(None);
        };
        self.read_block_then_tx_by_index(locator.block, locator.index).await
    }

    pub async fn get_transaction_by_block_hash_and_index(
        &self,
        hash: B256,
        index: u64,
    ) -> RpcResult<Option<TransactionResponse>> {
        let backend = self.backend()?;
        let Some(number) = backend.block_number_by_hash(&hash).await? else {
            return Ok(None);
        };
        self.read_block_then_tx_by_index(BlockQuery::Number(number), index)
            .await
    }

    pub async fn block_tx_count_from_query(&self, query: BlockQuery) -> RpcResult<Option<u64>> {
        let Some(block) = self.resolve_block_query(query).await? else {
            return Ok(None);
        };
        Ok(Some(block.transactions.len() as u64))
    }

    pub async fn get_block_tx_count_by_hash(&self, hash: B256) -> RpcResult<Option<u64>> {
        let backend = self.backend()?;
        let Some(number) = backend.block_number_by_hash(&hash).await? else {
            return Ok(None);
        };
        self.block_tx_count_from_query(BlockQuery::Number(number)).await
    }

    pub async fn get_transaction_receipt(&self, hash: B256) -> RpcResult<Option<StoredReceipt>> {
        let backend = self.backend()?;
        let Some(locator) = backend.transaction_locator(&hash).await? else {
            return Ok(None);
        };
        let Some(block) = self.resolve_block_query(locator.block).await? else {
            return Ok(None);
        };
        Ok(receipt_at(&block, locator.index).cloned())
    }

    pub async fn get_block_receipts(&self, id: BlockId) -> RpcResult<Option<Vec<StoredReceipt>>> {
        let Some(block) = self.resolve_block_query(id.into()).await? else {
            return Ok(None);
        };
        Ok(Some(block.receipts))
    }

    pub async fn get_system_txs_by_block_hash(
        &self,
        hash: B256,
    ) -> RpcResult<Option<Vec<SystemTransaction>>> {
        let backend = self.backend()?;
        let Some(number) = backend.block_number_by_hash(&hash).await? else {
            return Ok(None);
        };
        let Some(block) = self.resolve_block_query(BlockQuery::Number(number)).await? else {
            return Ok(None);
        };
        Ok(Some(block.system_transactions))
    }

    pub async fn get_logs_filtered_blocks(&self, filter: Filter) -> RpcResult<Vec<Log>> {
        let backend = self.backend()?;
        let (first, last) = self.resolve_filter_range(&filter).await?;
        if first > last {
            return Ok(Vec::new());
        }

        let blocks = backend.blocks_by_number(first, last).await?;
        let mut logs = Vec::new();
        for block in &blocks {
            if let Some(hash) = filter.block_hash {
                if block.header.hash != hash {
                    continue;
                }
            }
            if !filter.bloom_masks.is_empty() && !bloom_matches_any(&block.header.logs_bloom, &filter.bloom_masks) {
                continue;
            }
            append_matching_logs(block, &filter, &mut logs);
        }
        Ok(logs)
    }

    async fn resolve_filter_range(&self, filter: &Filter) -> RpcResult<(u64, u64)> {
        if let Some(hash) = filter.block_hash {
            let Some(number) = self.backend()?.block_number_by_hash(&hash).await? else {
                return Ok((1, 0));
            };
            return Ok((number, number));
        }

        let from = match filter.from_block.unwrap_or(BlockQuery::Latest) {
            BlockQuery::Pending => return Ok((1, 0)),
            query => self.resolve_number_query(query).await?,
        };
        let to = match filter.to_block.unwrap_or(BlockQuery::Latest) {
            BlockQuery::Pending => return Ok((1, 0)),
            query => self.resolve_number_query(query).await?,
        };
        Ok((from, to))
    }

    async fn resolve_number_query(&self, query: BlockQuery) -> RpcResult<u64> {
        match query {
            BlockQuery::Number(number) => Ok(number),
            BlockQuery::Earliest => Ok(0),
            BlockQuery::Hash(hash) => self
                .backend()?
                .block_number_by_hash(&hash)
                .await?
                .ok_or(RpcError::InvalidBlockRange),
            BlockQuery::Latest => self
                .backend()?
                .latest_block_number()
                .await?
                .ok_or(RpcError::InvalidBlockRange),
            BlockQuery::Safe => self
                .backend()?
                .safe_block_number()
                .await?
                .ok_or(RpcError::InvalidBlockRange),
            BlockQuery::Finalized => self
                .backend()?
                .finalized_block_number()
                .await?
                .ok_or(RpcError::InvalidBlockRange),
            BlockQuery::Pending => Err(RpcError::InvalidBlockRange),
        }
    }

    async fn resolve_block_query(&self, query: BlockQuery) -> RpcResult<Option<StoredBlock>> {
        let backend = self.backend()?;
        let number = match query {
            BlockQuery::Number(number) => Some(number),
            BlockQuery::Earliest => Some(0),
            BlockQuery::Pending => None,
            BlockQuery::Hash(hash) => backend.block_number_by_hash(&hash).await?,
            BlockQuery::Latest => backend.latest_block_number().await?,
            BlockQuery::Safe => backend.safe_block_number().await?,
            BlockQuery::Finalized => backend.finalized_block_number().await?,
        };
        match number {
            Some(number) => backend.block_by_number(number).await,
            None => Ok(None),
        }
    }
}

fn format_block_response(block: &StoredBlock, full_transactions: bool) -> BlockResponse {
    let transactions = if full_transactions {
        BlockTransactions::Full(
            block
                .transactions
                .iter()
                .enumerate()
                .map(|(index, tx)| transaction_response(block, tx, index as u64))
                .collect(),
        )
    } else {
        BlockTransactions::Hashes(block.transactions.iter().map(|tx| tx.hash).collect())
    };

    BlockResponse {
        hash: block.header.hash,
        parent_hash: block.header.parent_hash,
        number: block.header.number,
        timestamp: block.header.timestamp,
        gas_limit: block.header.gas_limit,
        gas_used: block.header.gas_used,
        base_fee_per_gas: block.header.base_fee_per_gas,
        transactions,
    }
}

fn transaction_response_at(block: &StoredBlock, index: u64) -> Option<TransactionResponse> {
    block
        .transactions
        .get(index as usize)
        .map(|tx| transaction_response(block, tx, index))
}

fn transaction_response(block: &StoredBlock, tx: &RecoveredTransaction, index: u64) -> TransactionResponse {
    TransactionResponse {
        hash: tx.hash,
        from: tx.from,
        to: tx.to,
        nonce: tx.nonce,
        value: tx.value,
        gas: tx.gas_limit,
        gas_price: tx.gas_price,
        max_fee_per_gas: tx.max_fee_per_gas,
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
        input: tx.input.clone(),
        block_hash: Some(block.header.hash),
        block_number: Some(block.header.number),
        transaction_index: Some(index),
        effective_gas_price: effective_gas_price(tx, block.header.base_fee_per_gas),
    }
}

fn receipt_at(block: &StoredBlock, index: u64) -> Option<&StoredReceipt> {
    block.receipts.get(index as usize)
}

fn effective_gas_price(tx: &RecoveredTransaction, base_fee: Option<U256>) -> Option<U256> {
    match base_fee {
        None => tx.gas_price.or(tx.max_fee_per_gas),
        Some(base_fee) => match (tx.max_fee_per_gas, tx.max_priority_fee_per_gas, tx.gas_price) {
            (Some(max_fee), Some(priority), _) => {
                if max_fee < base_fee {
                    Some(max_fee)
                } else {
                    Some(base_fee.saturating_add((max_fee - base_fee).min(priority)))
                }
            }
            (_, _, Some(gas_price)) => Some(gas_price),
            (Some(max_fee), _, _) => Some(max_fee),
            _ => Some(base_fee),
        },
    }
}

fn append_matching_logs(block: &StoredBlock, filter: &Filter, out: &mut Vec<Log>) {
    for receipt in &block.receipts {
        for log in &receipt.logs {
            if log_matches_filter(log, filter) {
                out.push(log.clone());
            }
        }
    }
}

fn log_matches_filter(log: &Log, filter: &Filter) -> bool {
    if !filter.addresses.is_empty() && !filter.addresses.iter().any(|address| *address == log.address) {
        return false;
    }

    for (slot, choices) in filter.topics.iter().enumerate() {
        if choices.is_empty() {
            continue;
        }
        let Some(topic) = log.topics.get(slot) else {
            return false;
        };
        if !choices.iter().any(|choice| choice == topic) {
            return false;
        }
    }

    true
}

fn bloom_matches_any(block_bloom: &Bloom, masks: &[Bloom]) -> bool {
    masks.iter().all(|mask| bloom_contains(block_bloom, mask))
}

fn bloom_contains(block_bloom: &Bloom, mask: &Bloom) -> bool {
    block_bloom
        .iter()
        .zip(mask.iter())
        .all(|(block, required)| (*block & *required) == *required)
}
