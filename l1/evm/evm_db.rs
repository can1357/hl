use std::array;
use std::collections::BTreeMap;

pub type Address = [u8; 20];
pub type B256 = [u8; 32];

pub const EVM_DB_REVISION_SLOTS: usize = 20;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: Self = Self([0, 0, 0, 0]);

    pub const fn from_u64(value: u64) -> Self {
        Self([value, 0, 0, 0])
    }

    pub const fn is_zero(self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }
}

/// Recovered directly from local IDA type `hl_l1_evm_DbAccountInfo`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DbAccountInfo {
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: B256,
    pub code_len: u64,
    pub is_touched: bool,
    pub is_selfdestructed: bool,
}

impl DbAccountInfo {
    pub fn blank() -> Self {
        Self::default()
    }

    pub fn with_code_hash(mut self, code_hash: B256, code_len: u64) -> Self {
        self.code_hash = code_hash;
        self.code_len = code_len;
        self
    }

    pub fn has_code(&self) -> bool {
        self.code_len != 0 || self.code_hash != [0; 32]
    }

    pub fn mark_touched(&mut self) {
        self.is_touched = true;
    }

    pub fn mark_selfdestructed(&mut self) {
        self.is_touched = true;
        self.is_selfdestructed = true;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct StorageKey {
    pub address: Address,
    pub slot: U256,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DbStorageSlot {
    pub key: StorageKey,
    pub value: U256,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DbContractCode {
    pub code_hash: B256,
    pub bytes: Vec<u8>,
}

impl DbContractCode {
    pub fn new(code_hash: B256, bytes: Vec<u8>) -> Self {
        Self { code_hash, bytes }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvmStateSnapshot {
    pub accounts: BTreeMap<Address, DbAccountInfo>,
    pub storage: BTreeMap<StorageKey, DbStorageSlot>,
    pub contracts: BTreeMap<B256, DbContractCode>,
    pub block_hashes: BTreeMap<u64, B256>,
}

impl EvmStateSnapshot {
    pub fn account(&self, address: &Address) -> Option<&DbAccountInfo> {
        self.accounts.get(address)
    }

    pub fn account_mut(&mut self, address: &Address) -> Option<&mut DbAccountInfo> {
        self.accounts.get_mut(address)
    }

    pub fn upsert_account(&mut self, address: Address, info: DbAccountInfo) -> &mut DbAccountInfo {
        self.accounts.entry(address).or_insert(info)
    }

    pub fn storage_slot(&self, address: &Address, slot: &U256) -> Option<&DbStorageSlot> {
        self.storage.get(&StorageKey {
            address: *address,
            slot: *slot,
        })
    }

    pub fn storage_value(&self, address: &Address, slot: &U256) -> U256 {
        self.storage_slot(address, slot)
            .map(|entry| entry.value)
            .unwrap_or(U256::ZERO)
    }

    pub fn set_storage(&mut self, address: Address, slot: U256, value: U256) {
        let key = StorageKey { address, slot };
        self.storage.insert(key, DbStorageSlot { key, value });
    }

    pub fn contract(&self, code_hash: &B256) -> Option<&DbContractCode> {
        self.contracts.get(code_hash)
    }

    pub fn set_contract(&mut self, code_hash: B256, bytes: Vec<u8>) {
        self.contracts
            .insert(code_hash, DbContractCode::new(code_hash, bytes));
    }

    pub fn set_block_hash(&mut self, block_number: u64, block_hash: B256) {
        self.block_hashes.insert(block_number, block_hash);
    }

    pub fn block_hash(&self, block_number: u64) -> Option<&B256> {
        self.block_hashes.get(&block_number)
    }

    pub fn merge_from(&mut self, other: Self) {
        self.accounts.extend(other.accounts);
        self.storage.extend(other.storage);
        self.contracts.extend(other.contracts);
        self.block_hashes.extend(other.block_hashes);
    }
}

/// Recovered directly from local IDA type `hl_l1_evm_ExecutionCheckpoint`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExecutionCheckpoint {
    pub gas_limit: u64,
    pub gas_remaining: u64,
    pub gas_refund: u64,
    pub access_epoch: u64,
}

/// Runtime EVM DB core.
///
/// IDA exposes this object as twenty opaque handle slots plus an active revision byte.
/// [INFERENCE] The reconstructed source models each slot as a typed snapshot layer because
/// that is the simplest representation that supports the observed account/storage/code/block
/// queries used by the HyperEVM execution path.
#[derive(Clone, Debug)]
pub struct EvmStateCore {
    pub revisions: [Option<EvmStateSnapshot>; EVM_DB_REVISION_SLOTS],
    pub checkpoint: Option<ExecutionCheckpoint>,
    pub active_revision: u8,
}

impl Default for EvmStateCore {
    fn default() -> Self {
        Self {
            revisions: array::from_fn(|_| None),
            checkpoint: None,
            active_revision: 0,
        }
    }
}

impl EvmStateCore {
    pub fn new() -> Self {
        let mut core = Self::default();
        core.revisions[0] = Some(EvmStateSnapshot::default());
        core
    }

    pub fn active_revision_index(&self) -> usize {
        usize::from(self.active_revision).min(EVM_DB_REVISION_SLOTS.saturating_sub(1))
    }

    pub fn active_snapshot(&self) -> Option<&EvmStateSnapshot> {
        self.revisions[self.active_revision_index()].as_ref()
    }

    pub fn active_snapshot_mut(&mut self) -> &mut EvmStateSnapshot {
        let idx = self.active_revision_index();
        self.revisions[idx].get_or_insert_with(EvmStateSnapshot::default)
    }

    pub fn select_revision(&mut self, revision: usize) {
        assert!(revision < EVM_DB_REVISION_SLOTS, "revision slot out of range");
        self.active_revision = revision as u8;
        if self.revisions[revision].is_none() {
            self.revisions[revision] = Some(EvmStateSnapshot::default());
        }
    }

    pub fn fork_revision_from_active(&mut self, revision: usize) {
        assert!(revision < EVM_DB_REVISION_SLOTS, "revision slot out of range");
        let snapshot = self.active_snapshot().cloned().unwrap_or_default();
        self.revisions[revision] = Some(snapshot);
    }

    pub fn merge_revision_into_active(&mut self, source_revision: usize) {
        assert!(source_revision < EVM_DB_REVISION_SLOTS, "revision slot out of range");
        if source_revision == self.active_revision_index() {
            return;
        }
        let Some(source) = self.revisions[source_revision].take() else {
            return;
        };
        self.active_snapshot_mut().merge_from(source);
    }

    pub fn set_checkpoint(&mut self, checkpoint: ExecutionCheckpoint) {
        self.checkpoint = Some(checkpoint);
    }

    pub fn clear_checkpoint(&mut self) {
        self.checkpoint = None;
    }
}

pub trait HyperEvmDbView {
    fn basic(&self, address: &Address) -> Option<&DbAccountInfo>;
    fn storage_slot(&self, address: &Address, slot: &U256) -> Option<&DbStorageSlot>;
    fn storage_value(&self, address: &Address, slot: &U256) -> U256;
    fn code_by_hash(&self, code_hash: &B256) -> Option<&DbContractCode>;
    fn block_hash(&self, block_number: u64) -> Option<&B256>;
}

pub trait HyperEvmDbMut: HyperEvmDbView {
    fn upsert_account(&mut self, address: Address, info: DbAccountInfo) -> &mut DbAccountInfo;
    fn touch_account(&mut self, address: Address) -> &mut DbAccountInfo;
    fn mark_selfdestructed(&mut self, address: Address) -> &mut DbAccountInfo;
    fn set_storage(&mut self, address: Address, slot: U256, value: U256);
    fn set_contract_code(&mut self, code_hash: B256, bytes: Vec<u8>);
    fn set_block_hash(&mut self, block_number: u64, block_hash: B256);
}

#[derive(Clone, Debug, Default)]
pub struct EvmDb {
    pub core: EvmStateCore,
}

impl EvmDb {
    pub fn new() -> Self {
        Self {
            core: EvmStateCore::new(),
        }
    }

    pub fn from_snapshot(snapshot: EvmStateSnapshot) -> Self {
        let mut core = EvmStateCore::default();
        core.revisions[0] = Some(snapshot);
        Self { core }
    }

    pub fn snapshot(&self) -> Option<&EvmStateSnapshot> {
        self.core.active_snapshot()
    }

    pub fn snapshot_mut(&mut self) -> &mut EvmStateSnapshot {
        self.core.active_snapshot_mut()
    }

    pub fn into_snapshot(self) -> Option<EvmStateSnapshot> {
        self.core.revisions[self.core.active_revision_index()].clone()
    }

    pub fn select_revision(&mut self, revision: usize) {
        self.core.select_revision(revision);
    }

    pub fn fork_revision_from_active(&mut self, revision: usize) {
        self.core.fork_revision_from_active(revision);
    }

    pub fn merge_revision_into_active(&mut self, source_revision: usize) {
        self.core.merge_revision_into_active(source_revision);
    }

    pub fn checkpoint(&mut self, checkpoint: ExecutionCheckpoint) {
        self.core.set_checkpoint(checkpoint);
    }

    pub fn clear_checkpoint(&mut self) {
        self.core.clear_checkpoint();
    }

    pub fn account_has_code(&self, address: &Address) -> bool {
        self.basic(address).is_some_and(DbAccountInfo::has_code)
    }
}

impl HyperEvmDbView for EvmDb {
    fn basic(&self, address: &Address) -> Option<&DbAccountInfo> {
        self.snapshot()?.account(address)
    }

    fn storage_slot(&self, address: &Address, slot: &U256) -> Option<&DbStorageSlot> {
        self.snapshot()?.storage_slot(address, slot)
    }

    fn storage_value(&self, address: &Address, slot: &U256) -> U256 {
        self.snapshot()
            .map(|snapshot| snapshot.storage_value(address, slot))
            .unwrap_or(U256::ZERO)
    }

    fn code_by_hash(&self, code_hash: &B256) -> Option<&DbContractCode> {
        self.snapshot()?.contract(code_hash)
    }

    fn block_hash(&self, block_number: u64) -> Option<&B256> {
        self.snapshot()?.block_hash(block_number)
    }
}

impl HyperEvmDbMut for EvmDb {
    fn upsert_account(&mut self, address: Address, info: DbAccountInfo) -> &mut DbAccountInfo {
        self.snapshot_mut().upsert_account(address, info)
    }

    fn touch_account(&mut self, address: Address) -> &mut DbAccountInfo {
        let account = self
            .snapshot_mut()
            .accounts
            .entry(address)
            .or_insert_with(DbAccountInfo::blank);
        account.mark_touched();
        account
    }

    fn mark_selfdestructed(&mut self, address: Address) -> &mut DbAccountInfo {
        let account = self
            .snapshot_mut()
            .accounts
            .entry(address)
            .or_insert_with(DbAccountInfo::blank);
        account.mark_selfdestructed();
        account
    }

    fn set_storage(&mut self, address: Address, slot: U256, value: U256) {
        self.snapshot_mut().set_storage(address, slot, value);
    }

    fn set_contract_code(&mut self, code_hash: B256, bytes: Vec<u8>) {
        self.snapshot_mut().set_contract(code_hash, bytes);
    }

    fn set_block_hash(&mut self, block_number: u64, block_hash: B256) {
        self.snapshot_mut().set_block_hash(block_number, block_hash);
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NoEvmDb;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum EvmDbSerde {
    #[default]
    NoEvmDb,
    // [INFERENCE] The populated variant name is reconstructed. The binary only exposes the
    // `NoEvmDb` variant name directly, while the other branch serializes a concrete DB snapshot.
    Snapshot(EvmStateSnapshot),
}

impl EvmDbSerde {
    pub fn from_db(db: Option<&EvmDb>) -> Self {
        match db.and_then(EvmDb::snapshot).cloned() {
            Some(snapshot) => Self::Snapshot(snapshot),
            None => Self::NoEvmDb,
        }
    }

    pub fn into_db(self) -> Option<EvmDb> {
        match self {
            Self::NoEvmDb => None,
            Self::Snapshot(snapshot) => Some(EvmDb::from_snapshot(snapshot)),
        }
    }

    pub fn as_snapshot(&self) -> Option<&EvmStateSnapshot> {
        match self {
            Self::NoEvmDb => None,
            Self::Snapshot(snapshot) => Some(snapshot),
        }
    }
}
