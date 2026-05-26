use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub type Address = [u8; 20];
pub type B256 = [u8; 32];

const SUCCESS_TAG: u8 = 5;
const VM_ERROR_SENTINEL: u64 = 0x8000_0000_0000_0002;
const DEFAULT_CALL_GAS: u64 = 21_000;
const REVISION_TABLE_OFFSET: usize = 0x1198;
const CHECKPOINT_BLOCK_SIZE: usize = 688;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: Self = Self([0, 0, 0, 0]);

    pub const fn from_u64(value: u64) -> Self {
        Self([value, 0, 0, 0])
    }

    pub fn low_u64_saturating(self) -> u64 {
        if self.0[1] | self.0[2] | self.0[3] == 0 {
            self.0[0]
        } else {
            u64::MAX
        }
    }

    fn most_significant_bit(self) -> Option<u16> {
        for limb in (0..4).rev() {
            let value = self.0[limb];
            if value != 0 {
                return Some((limb as u16) * 64 + (63 - value.leading_zeros() as u16));
            }
        }
        None
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DbAccountInfo {
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: B256,
    pub code_len: u64,
    pub is_contract: bool,
}

impl Default for DbAccountInfo {
    fn default() -> Self {
        Self {
            nonce: 0,
            balance: U256::ZERO,
            code_hash: [0; 32],
            code_len: 0,
            is_contract: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StorageKey {
    pub address: Address,
    pub slot: U256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DbStorageSlot {
    pub address: Address,
    pub slot: U256,
    pub value: U256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DbContractCode {
    pub code_hash: B256,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StateWriteBatch {
    pub accounts: Vec<(Address, Option<DbAccountInfo>)>,
    pub storage: Vec<(StorageKey, U256)>,
    pub codes: Vec<DbContractCode>,
}

pub trait EvmBackingStore: Send + Sync {
    fn read_account(&self, address: &Address) -> Option<DbAccountInfo>;
    fn read_storage(&self, key: &StorageKey) -> U256;
    fn read_code(&self, code_hash: &B256) -> Option<Vec<u8>>;
    fn read_block_hash(&self, number: u64) -> Option<B256>;
    fn write_batch(&self, batch: StateWriteBatch);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccountState {
    Missing,
    Loaded(DbAccountInfo),
    Destroyed(DbAccountInfo),
}

impl AccountState {
    pub fn info(&self) -> Option<&DbAccountInfo> {
        match self {
            Self::Loaded(info) | Self::Destroyed(info) => Some(info),
            Self::Missing => None,
        }
    }

    pub fn info_mut(&mut self) -> Option<&mut DbAccountInfo> {
        match self {
            Self::Loaded(info) | Self::Destroyed(info) => Some(info),
            Self::Missing => None,
        }
    }

    fn is_destroyed(&self) -> bool {
        matches!(self, Self::Destroyed(_))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountOverlay {
    pub state: AccountState,
    pub touched: bool,
    pub dirty: bool,
    pub newly_created: bool,
}

impl AccountOverlay {
    fn missing() -> Self {
        Self {
            state: AccountState::Missing,
            touched: true,
            dirty: false,
            newly_created: false,
        }
    }

    fn loaded(info: DbAccountInfo) -> Self {
        Self {
            state: AccountState::Loaded(info),
            touched: true,
            dirty: false,
            newly_created: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvmStateSnapshot {
    Clean,
    Overlay {
        accounts: BTreeMap<Address, AccountOverlay>,
        storage: BTreeMap<StorageKey, U256>,
        codes: BTreeMap<B256, Vec<u8>>,
        checkpoint: ExecutionCheckpoint,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionCheckpoint {
    pub gas_limit: u64,
    pub gas_remaining: u64,
    pub gas_refund: u64,
    pub min_gas_observed: u64,
    pub block_number: u64,
    pub timestamp: u64,
    pub base_fee: U256,
    pub coinbase: Address,
    pub parent_hash: B256,
}

impl Default for ExecutionCheckpoint {
    fn default() -> Self {
        Self {
            gas_limit: u64::MAX,
            gas_remaining: u64::MAX,
            gas_refund: 0,
            min_gas_observed: u64::MAX,
            block_number: 0,
            timestamp: 0,
            base_fee: U256::ZERO,
            coinbase: [0; 20],
            parent_hash: [0; 32],
        }
    }
}

impl ExecutionCheckpoint {
    pub fn with_call_gas(mut self, requested: U256) -> Self {
        let gas = requested.low_u64_saturating();
        self.gas_limit = gas;
        self.gas_remaining = gas;
        self.min_gas_observed = self.min_gas_observed.min(gas);
        self
    }

    pub fn charge_gas(&mut self, amount: u64) -> Result<(), VmStateError> {
        if self.gas_remaining < amount {
            self.gas_remaining = 0;
            return Err(VmStateError::OutOfGas { gas_limit: self.gas_limit });
        }
        self.gas_remaining -= amount;
        self.min_gas_observed = self.min_gas_observed.min(self.gas_remaining);
        Ok(())
    }

    pub fn refund_gas(&mut self, amount: u64) {
        self.gas_refund = self.gas_refund.saturating_add(amount);
        self.gas_remaining = self.gas_remaining.saturating_add(amount).min(self.gas_limit);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvmRevision {
    Frontier,
    Homestead,
    Byzantium,
    Istanbul,
    Berlin,
    London,
    Shanghai,
    Cancun,
    Latest,
    Unknown(u8),
}

impl EvmRevision {
    pub fn from_selector(selector: u8) -> Self {
        // The optimized table builder has explicit cases for 0..19 and folds several
        // adjacent selectors onto the same table block.  The public names below are
        // the semantic groupings used by the recovered dispatch logic, not upstream
        // enum discriminants.
        match selector {
            0 | 1 => Self::Frontier,
            2 | 3 => Self::Homestead,
            4..=6 => Self::Byzantium,
            7..=11 => Self::Istanbul,
            12..=14 => Self::Berlin,
            15 | 16 => Self::London,
            17 => Self::Shanghai,
            18 | 19 => Self::Cancun,
            0xff => Self::Latest,
            other => Self::Unknown(other),
        }
    }

    pub fn selector(self) -> u8 {
        match self {
            Self::Frontier => 0,
            Self::Homestead => 2,
            Self::Byzantium => 4,
            Self::Istanbul => 8,
            Self::Berlin => 12,
            Self::London => 15,
            Self::Shanghai => 17,
            Self::Cancun => 18,
            Self::Latest => 0xff,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionTables {
    pub selector: u8,
    pub revision: EvmRevision,
    pub installed_callbacks: usize,
}

impl RevisionTables {
    fn build(selector: u8) -> Self {
        // Recovered evidence: the binary copies a 0x800-byte static table for each
        // selector group, then allocates six 16-byte callback objects and stores a
        // selector byte at offset 0x1198.  The source model keeps the selector and
        // revision identity while Rust vtables replace the raw callback table.
        let revision = EvmRevision::from_selector(selector);
        let installed_callbacks = match selector {
            0..=19 | 0xff => 6,
            _ => 6,
        };
        Self {
            selector,
            revision,
            installed_callbacks,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateCheckpoint {
    account_deltas: BTreeMap<Address, Option<AccountOverlay>>,
    storage_deltas: BTreeMap<StorageKey, Option<U256>>,
    code_deltas: BTreeMap<B256, Option<Vec<u8>>>,
    warm_addresses: BTreeSet<Address>,
    warm_storage: BTreeSet<StorageKey>,
    execution: ExecutionCheckpoint,
}

impl StateCheckpoint {
    fn capture(state: &EvmState) -> Self {
        Self {
            account_deltas: BTreeMap::new(),
            storage_deltas: BTreeMap::new(),
            code_deltas: BTreeMap::new(),
            warm_addresses: state.warm_addresses.clone(),
            warm_storage: state.warm_storage.clone(),
            execution: state.execution.clone(),
        }
    }
}

#[derive(Clone)]
pub struct EvmState {
    backing: Option<Arc<dyn EvmBackingStore>>,
    db_handles: Vec<Arc<dyn EvmBackingStore>>,
    revision_tables: RevisionTables,
    execution: ExecutionCheckpoint,
    accounts: BTreeMap<Address, AccountOverlay>,
    storage: BTreeMap<StorageKey, U256>,
    codes: BTreeMap<B256, Vec<u8>>,
    block_hashes: BTreeMap<u64, B256>,
    warm_addresses: BTreeSet<Address>,
    warm_storage: BTreeSet<StorageKey>,
    checkpoints: Vec<StateCheckpoint>,
}

impl Default for EvmState {
    fn default() -> Self {
        Self::new(None, 0)
    }
}

impl EvmState {
    pub fn new(backing: Option<Arc<dyn EvmBackingStore>>, revision_selector: u8) -> Self {
        let mut state = Self {
            backing,
            db_handles: Vec::new(),
            revision_tables: RevisionTables::build(revision_selector),
            execution: ExecutionCheckpoint::default(),
            accounts: BTreeMap::new(),
            storage: BTreeMap::new(),
            codes: BTreeMap::new(),
            block_hashes: BTreeMap::new(),
            warm_addresses: BTreeSet::new(),
            warm_storage: BTreeSet::new(),
            checkpoints: Vec::new(),
        };
        state.install_revision(revision_selector);
        state
    }

    pub fn with_db_handles(backing: Arc<dyn EvmBackingStore>, handles: Vec<Arc<dyn EvmBackingStore>>, revision_selector: u8) -> Self {
        let mut state = Self::new(Some(backing), revision_selector);
        state.db_handles = handles;
        state
    }

    pub fn active_revision(&self) -> EvmRevision {
        self.revision_tables.revision
    }

    pub fn active_revision_selector(&self) -> u8 {
        self.revision_tables.selector
    }

    pub fn install_revision(&mut self, selector: u8) {
        if self.revision_tables.selector == selector {
            return;
        }
        // The binary drains callback thunks from the old table into the new table
        // before dropping the old 0x11a0-byte revision block.  State overlays are not
        // discarded by a revision switch.
        self.revision_tables = RevisionTables::build(selector);
    }

    pub fn execution_checkpoint(&self) -> &ExecutionCheckpoint {
        &self.execution
    }

    pub fn execution_checkpoint_mut(&mut self) -> &mut ExecutionCheckpoint {
        &mut self.execution
    }

    pub fn set_execution_checkpoint(&mut self, checkpoint: ExecutionCheckpoint) {
        self.execution = checkpoint;
    }

    pub fn begin_checkpoint(&mut self) -> usize {
        let index = self.checkpoints.len();
        self.checkpoints.push(StateCheckpoint::capture(self));
        index
    }

    pub fn commit_checkpoint(&mut self, checkpoint: usize) {
        if checkpoint + 1 != self.checkpoints.len() {
            return;
        }
        let child = self.checkpoints.pop().expect("checkpoint index checked");
        if let Some(parent) = self.checkpoints.last_mut() {
            for (address, before) in child.account_deltas {
                parent.account_deltas.entry(address).or_insert(before);
            }
            for (key, before) in child.storage_deltas {
                parent.storage_deltas.entry(key).or_insert(before);
            }
            for (hash, before) in child.code_deltas {
                parent.code_deltas.entry(hash).or_insert(before);
            }
        }
    }

    pub fn revert_checkpoint(&mut self, checkpoint: usize) {
        if checkpoint + 1 != self.checkpoints.len() {
            return;
        }
        let checkpoint = self.checkpoints.pop().expect("checkpoint index checked");
        for (address, previous) in checkpoint.account_deltas.into_iter().rev() {
            match previous {
                Some(value) => {
                    self.accounts.insert(address, value);
                }
                None => {
                    self.accounts.remove(&address);
                }
            }
        }
        for (key, previous) in checkpoint.storage_deltas.into_iter().rev() {
            match previous {
                Some(value) => {
                    self.storage.insert(key, value);
                }
                None => {
                    self.storage.remove(&key);
                }
            }
        }
        for (hash, previous) in checkpoint.code_deltas.into_iter().rev() {
            match previous {
                Some(value) => {
                    self.codes.insert(hash, value);
                }
                None => {
                    self.codes.remove(&hash);
                }
            }
        }
        self.warm_addresses = checkpoint.warm_addresses;
        self.warm_storage = checkpoint.warm_storage;
        self.execution = checkpoint.execution;
    }

    pub fn snapshot(&self) -> EvmStateSnapshot {
        if self.accounts.is_empty() && self.storage.is_empty() && self.codes.is_empty() {
            EvmStateSnapshot::Clean
        } else {
            EvmStateSnapshot::Overlay {
                accounts: self.accounts.clone(),
                storage: self.storage.clone(),
                codes: self.codes.clone(),
                checkpoint: self.execution.clone(),
            }
        }
    }

    pub fn restore_snapshot(&mut self, snapshot: EvmStateSnapshot) {
        match snapshot {
            EvmStateSnapshot::Clean => {
                self.accounts.clear();
                self.storage.clear();
                self.codes.clear();
            }
            EvmStateSnapshot::Overlay {
                accounts,
                storage,
                codes,
                checkpoint,
            } => {
                self.accounts = accounts;
                self.storage = storage;
                self.codes = codes;
                self.execution = checkpoint;
            }
        }
    }

    pub fn warm_address(&mut self, address: Address) -> bool {
        self.warm_addresses.insert(address)
    }

    pub fn warm_storage_key(&mut self, address: Address, slot: U256) -> bool {
        self.warm_storage.insert(StorageKey { address, slot })
    }

    pub fn is_address_warm(&self, address: &Address) -> bool {
        self.warm_addresses.contains(address)
    }

    pub fn is_storage_warm(&self, address: &Address, slot: U256) -> bool {
        self.warm_storage.contains(&StorageKey { address: *address, slot })
    }

    pub fn get_account(&mut self, address: &Address) -> Option<&DbAccountInfo> {
        if !self.accounts.contains_key(address) {
            let loaded = self
                .backing
                .as_ref()
                .and_then(|db| db.read_account(address))
                .map(AccountOverlay::loaded)
                .unwrap_or_else(AccountOverlay::missing);
            self.accounts.insert(*address, loaded);
        }
        self.warm_addresses.insert(*address);
        self.accounts.get(address).and_then(|entry| entry.state.info())
    }

    pub fn touch_account(&mut self, address: Address) {
        self.record_account_before(address);
        if !self.accounts.contains_key(&address) {
            let loaded = self
                .backing
                .as_ref()
                .and_then(|db| db.read_account(&address))
                .map(AccountOverlay::loaded)
                .unwrap_or_else(AccountOverlay::missing);
            self.accounts.insert(address, loaded);
        }
        if let Some(entry) = self.accounts.get_mut(&address) {
            entry.touched = true;
        }
        self.warm_addresses.insert(address);
    }

    pub fn create_account(&mut self, address: Address) -> &mut DbAccountInfo {
        self.record_account_before(address);
        let entry = self.accounts.entry(address).or_insert_with(|| AccountOverlay {
            state: AccountState::Loaded(DbAccountInfo::default()),
            touched: true,
            dirty: true,
            newly_created: true,
        });
        if entry.state.is_destroyed() || matches!(entry.state, AccountState::Missing) {
            entry.state = AccountState::Loaded(DbAccountInfo::default());
        }
        entry.touched = true;
        entry.dirty = true;
        entry.newly_created = true;
        entry.state.info_mut().expect("account was just created")
    }

    pub fn set_balance(&mut self, address: Address, balance: U256) {
        let info = self.create_or_load_account(address);
        info.balance = balance;
    }

    pub fn set_nonce(&mut self, address: Address, nonce: u64) {
        let info = self.create_or_load_account(address);
        info.nonce = nonce;
    }

    pub fn set_code_hash(&mut self, address: Address, code_hash: B256, code_len: u64) {
        let info = self.create_or_load_account(address);
        info.code_hash = code_hash;
        info.code_len = code_len;
        info.is_contract = code_len != 0;
    }

    pub fn selfdestruct_account(&mut self, address: Address) {
        self.record_account_before(address);
        let previous = self
            .accounts
            .remove(&address)
            .or_else(|| {
                self.backing
                    .as_ref()
                    .and_then(|db| db.read_account(&address))
                    .map(AccountOverlay::loaded)
            })
            .unwrap_or_else(AccountOverlay::missing);
        let state = match previous.state {
            AccountState::Loaded(info) | AccountState::Destroyed(info) => AccountState::Destroyed(info),
            AccountState::Missing => AccountState::Missing,
        };
        self.accounts.insert(
            address,
            AccountOverlay {
                state,
                touched: true,
                dirty: true,
                newly_created: previous.newly_created,
            },
        );
    }

    pub fn get_storage(&mut self, address: Address, slot: U256) -> U256 {
        let key = StorageKey { address, slot };
        self.warm_address(address);
        self.warm_storage.insert(key);
        if let Some(value) = self.storage.get(&key) {
            return *value;
        }
        self.backing.as_ref().map_or(U256::ZERO, |db| db.read_storage(&key))
    }

    pub fn set_storage(&mut self, address: Address, slot: U256, value: U256) -> U256 {
        let key = StorageKey { address, slot };
        self.record_storage_before(key);
        let previous = self.get_storage(address, slot);
        self.storage.insert(key, value);
        self.warm_storage.insert(key);
        self.touch_account(address);
        previous
    }

    pub fn get_code(&mut self, code_hash: B256) -> Option<&[u8]> {
        if !self.codes.contains_key(&code_hash) {
            if let Some(bytes) = self.backing.as_ref().and_then(|db| db.read_code(&code_hash)) {
                self.codes.insert(code_hash, bytes);
            }
        }
        self.codes.get(&code_hash).map(Vec::as_slice)
    }

    pub fn install_code(&mut self, address: Address, code_hash: B256, code: Vec<u8>) {
        self.record_code_before(code_hash);
        let code_len = code.len() as u64;
        self.codes.insert(code_hash, code);
        self.set_code_hash(address, code_hash, code_len);
    }

    pub fn block_hash(&mut self, number: u64) -> Option<B256> {
        if let Some(hash) = self.block_hashes.get(&number) {
            return Some(*hash);
        }
        let hash = self.backing.as_ref().and_then(|db| db.read_block_hash(number))?;
        self.block_hashes.insert(number, hash);
        Some(hash)
    }

    pub fn set_block_hash(&mut self, number: u64, hash: B256) {
        self.block_hashes.insert(number, hash);
    }

    pub fn execute_with_checkpoint<F>(&mut self, requested_gas: U256, revision_selector: u8, mut f: F) -> VmExecutionOutcome
    where
        F: FnMut(&mut Self) -> Result<VmExit, VmStateError>,
    {
        self.install_revision(revision_selector);
        let saved_limit = self.execution.gas_limit;
        let saved_remaining = self.execution.gas_remaining;
        let requested_cap = gas_cap_from_u256(requested_gas);
        self.execution.gas_limit = requested_cap;
        self.execution.gas_remaining = requested_cap;
        self.execution.min_gas_observed = self.execution.min_gas_observed.min(requested_cap);

        let checkpoint = self.begin_checkpoint();
        let result = match f(self) {
            Ok(exit) => {
                self.commit_checkpoint(checkpoint);
                VmExecutionOutcome::Success {
                    exit,
                    gas_used: requested_cap.saturating_sub(self.execution.gas_remaining),
                    state: self.snapshot(),
                }
            }
            Err(error) => {
                self.revert_checkpoint(checkpoint);
                VmExecutionOutcome::Error(map_vm_error(error))
            }
        };

        self.execution.gas_limit = saved_limit;
        self.execution.gas_remaining = saved_remaining;
        result
    }

    pub fn flush_overlay(&mut self) -> StateWriteBatch {
        let mut batch = StateWriteBatch::default();
        for (address, overlay) in std::mem::take(&mut self.accounts) {
            if !overlay.dirty && !overlay.touched {
                continue;
            }
            match overlay.state {
                AccountState::Missing => batch.accounts.push((address, None)),
                AccountState::Loaded(info) => batch.accounts.push((address, Some(info))),
                AccountState::Destroyed(mut info) => {
                    info.balance = U256::ZERO;
                    info.code_hash = [0; 32];
                    info.code_len = 0;
                    batch.accounts.push((address, Some(info)));
                }
            }
        }
        batch.storage.extend(std::mem::take(&mut self.storage));
        batch.codes.extend(
            std::mem::take(&mut self.codes)
                .into_iter()
                .map(|(code_hash, bytes)| DbContractCode { code_hash, bytes }),
        );
        if let Some(db) = &self.backing {
            db.write_batch(batch.clone());
        }
        batch
    }

    pub fn clear_transient_accesses(&mut self) {
        self.warm_addresses.clear();
        self.warm_storage.clear();
    }

    fn create_or_load_account(&mut self, address: Address) -> &mut DbAccountInfo {
        self.record_account_before(address);
        if !self.accounts.contains_key(&address) {
            let overlay = self
                .backing
                .as_ref()
                .and_then(|db| db.read_account(&address))
                .map(AccountOverlay::loaded)
                .unwrap_or_else(|| AccountOverlay {
                    state: AccountState::Loaded(DbAccountInfo::default()),
                    touched: true,
                    dirty: true,
                    newly_created: true,
                });
            self.accounts.insert(address, overlay);
        }
        let entry = self.accounts.get_mut(&address).expect("inserted above");
        if matches!(entry.state, AccountState::Missing) {
            entry.state = AccountState::Loaded(DbAccountInfo::default());
            entry.newly_created = true;
        }
        entry.touched = true;
        entry.dirty = true;
        self.warm_addresses.insert(address);
        entry.state.info_mut().expect("missing converted to loaded")
    }

    fn record_account_before(&mut self, address: Address) {
        let previous = self.accounts.get(&address).cloned();
        if let Some(checkpoint) = self.checkpoints.last_mut() {
            checkpoint.account_deltas.entry(address).or_insert(previous);
        }
    }

    fn record_storage_before(&mut self, key: StorageKey) {
        let previous = self.storage.get(&key).copied();
        if let Some(checkpoint) = self.checkpoints.last_mut() {
            checkpoint.storage_deltas.entry(key).or_insert(previous);
        }
    }

    fn record_code_before(&mut self, code_hash: B256) {
        let previous = self.codes.get(&code_hash).cloned();
        if let Some(checkpoint) = self.checkpoints.last_mut() {
            checkpoint.code_deltas.entry(code_hash).or_insert(previous);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VmExit {
    Stop,
    Return(Vec<u8>),
    Revert(Vec<u8>),
    SelfDestruct,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VmStateError {
    Engine { tag: u8, status: u8, payload: Vec<u8> },
    OutOfGas { gas_limit: u64 },
    InvalidOpcode { opcode: u8 },
    StackUnderflow,
    StackOverflow,
    StateUnavailable,
    UnreachableVmResult,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VmExecutionOutcome {
    Success {
        exit: VmExit,
        gas_used: u64,
        state: EvmStateSnapshot,
    },
    Error(VmEncodedError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmEncodedError {
    pub sentinel: u64,
    pub code: u8,
    pub status: u8,
    pub payload: Vec<u8>,
}

pub fn gas_cap_from_u256(value: U256) -> u64 {
    match value.most_significant_bit() {
        None => 0,
        Some(bit) if bit < 192 => value.0[0],
        Some(_) => u64::MAX,
    }
}

pub fn retry_with_gas_cap<F>(state: &mut EvmState, requested_gas: U256, revision_selector: u8, f: F) -> VmExecutionOutcome
where
    F: FnMut(&mut EvmState) -> Result<VmExit, VmStateError>,
{
    // Recovered helper temporarily replaces the checkpoint gas word, calls the main
    // executor, restores the old gas word, and maps successful non-error VM states
    // into a small encoded status when the retry still fails.
    state.execute_with_checkpoint(requested_gas, revision_selector, f)
}

pub fn map_vm_error(error: VmStateError) -> VmEncodedError {
    match error {
        VmStateError::Engine { tag, status, payload } => map_engine_error(tag, status, payload),
        VmStateError::OutOfGas { gas_limit } => VmEncodedError {
            sentinel: VM_ERROR_SENTINEL,
            code: 13,
            status: 8,
            payload: gas_limit.to_le_bytes().to_vec(),
        },
        VmStateError::InvalidOpcode { opcode } => VmEncodedError {
            sentinel: VM_ERROR_SENTINEL,
            code: 28,
            status: opcode,
            payload: Vec::new(),
        },
        VmStateError::StackUnderflow => VmEncodedError {
            sentinel: VM_ERROR_SENTINEL,
            code: 29,
            status: 0,
            payload: Vec::new(),
        },
        VmStateError::StackOverflow => VmEncodedError {
            sentinel: VM_ERROR_SENTINEL,
            code: 20,
            status: 0,
            payload: Vec::new(),
        },
        VmStateError::StateUnavailable => VmEncodedError {
            sentinel: VM_ERROR_SENTINEL,
            code: 15,
            status: 0,
            payload: Vec::new(),
        },
        VmStateError::UnreachableVmResult => unreachable!("internal error: entered unreachable code"),
    }
}

fn map_engine_error(tag: u8, status: u8, payload: Vec<u8>) -> VmEncodedError {
    // Evidence from the result-normalization switch: engine tag 0 becomes outer code
    // 13 except for status 10; tag 1 ORs the inner status with 0x0a; tag 3 maps to
    // code 28; tag 4 maps to code 29; tag 2 is the unreachable arm.
    let code = match tag {
        0 => 13,
        1 => status | 0x0a,
        2 => unreachable!("internal error: entered unreachable code"),
        3 => 28,
        4 => 29,
        _ => status,
    };
    VmEncodedError {
        sentinel: VM_ERROR_SENTINEL,
        code,
        status,
        payload,
    }
}

pub fn success_tag() -> u8 {
    SUCCESS_TAG
}

pub fn recovered_layout_notes() -> (usize, usize) {
    (REVISION_TABLE_OFFSET, CHECKPOINT_BLOCK_SIZE)
}
