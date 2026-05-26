use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, VecDeque};

pub type Address = [u8; 20];
pub type B256 = [u8; 32];

const ABSENT_SENTINEL: u64 = 0x8000_0000_0000_0000;
const VM_ERROR_SENTINEL: u64 = 0x8000_0000_0000_0002;
const VM_SUCCESS_TAG: u8 = 5;
const UINT_CONVERSION_ERROR: &str = "Uint conversion error";

const RAW_TX_POOL_PRUNE_THRESHOLD: usize = 10_000;
const RAW_TX_POOL_PER_SENDER_KEEP: usize = 8;
const RAW_TX_POOL_REINSERT_LIMIT: usize = 5_000;
const SMALL_ACCOUNT_GAS_LIMIT: u64 = 3_000_000;
const BIG_ACCOUNT_GAS_LIMIT: u64 = 30_000_000;
const MIN_POOL_FEE_CAP_WEI: u64 = 100_000_000;
const COLLECT_ELIGIBILITY_FLOOR_WEI: u64 = 1_000_000_000;
const STATE_HISTORY_DEPTH: u64 = 256;

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawTxPoolInsertResult {
    Evicted = 0x014f,
    Retained = 0x0186,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: Self = Self([0, 0, 0, 0]);

    pub const fn from_u64(value: u64) -> Self {
        Self([value, 0, 0, 0])
    }

    pub fn low_u64_or_uint_conversion_error(self) -> u64 {
        if self.0[1] != 0 || self.0[2] != 0 || self.0[3] != 0 {
            panic!("{UINT_CONVERSION_ERROR}");
        }
        self.0[0]
    }

    fn is_zero(self) -> bool {
        self.0 == [0, 0, 0, 0]
    }
}

fn cmp_u256(left: U256, right: U256) -> Ordering {
    for idx in (0..4).rev() {
        match left.0[idx].cmp(&right.0[idx]) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

fn saturating_add_u64(left: u64, right: u64) -> u64 {
    left.checked_add(right).unwrap_or(u64::MAX)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxEnvelopeKind {
    Legacy,
    Eip2930,
    Eip1559,
    Eip4844,
    Eip7702,
    System,
    Unknown(u8),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxSnapshot {
    pub sender: Address,
    pub tx_key: B256,
    pub cached_key_dirty: bool,
    pub kind: TxEnvelopeKind,
    pub nonce: u64,
    pub gas_limit: u64,
    pub fee_cap: U256,
    pub priority_fee: U256,
    pub value: U256,
    pub upfront_cost: U256,
    pub sequence: u64,
}

impl TxSnapshot {
    pub fn materialize_cached_tx_key_if_dirty(&mut self) {
        // The recovered helper only writes the cached key when the dirty word is non-zero.
        // In reconstructed source the parsed transaction already carries the key, so the
        // observable state change is clearing the dirty marker before comparisons.
        if self.cached_key_dirty {
            self.cached_key_dirty = false;
        }
    }

    fn effective_tip(&self) -> U256 {
        if self.priority_fee.is_zero() || cmp_u256(self.priority_fee, self.fee_cap) == Ordering::Greater {
            self.fee_cap
        } else {
            self.priority_fee
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct AccountCtx {
    pub address: Address,
    pub account_key: u64,
    pub account_subkey: u32,
    pub nonce: u64,
    pub balance: U256,
    pub big_block_gas_limit: bool,
}

#[derive(Clone, Debug)]
pub struct PruneReferenceTx {
    pub sender: Address,
    pub nonce: u64,
    pub gas_limit: u64,
    pub fee_floor: U256,
    pub priority_mask: U256,
    pub sequence: u64,
}

#[derive(Clone, Debug, Default)]
pub struct RawTxPool {
    by_sender: BTreeMap<Address, Vec<TxSnapshot>>,
    total_count: usize,
}

impl RawTxPool {
    pub fn push_tx_snapshot_for_sender(&mut self, mut tx: TxSnapshot, trim_sender_bucket: bool) -> bool {
        tx.materialize_cached_tx_key_if_dirty();
        let bucket = self.by_sender.entry(tx.sender).or_default();
        bucket.push(tx);
        self.total_count = self.total_count.saturating_add(1);
        sort_sender_bucket(bucket);

        if trim_sender_bucket && bucket.len() > RAW_TX_POOL_PER_SENDER_KEEP {
            let evict = bucket.len() - RAW_TX_POOL_PER_SENDER_KEEP;
            bucket.drain(0..evict);
            self.total_count = self.total_count.saturating_sub(evict);
        }

        self.total_count >= RAW_TX_POOL_PRUNE_THRESHOLD
    }

    pub fn contains_sender_tx_key(&mut self, sender: &Address, tx_key: &B256) -> bool {
        let Some(bucket) = self.by_sender.get_mut(sender) else {
            return false;
        };
        for tx in bucket {
            tx.materialize_cached_tx_key_if_dirty();
            if &tx.tx_key == tx_key {
                return true;
            }
        }
        false
    }

    fn pop_best_for_sender(&mut self, sender: &Address) -> Option<TxSnapshot> {
        let bucket = self.by_sender.get_mut(sender)?;
        let tx = bucket.pop();
        if tx.is_some() {
            self.total_count = self.total_count.saturating_sub(1);
        }
        if bucket.is_empty() {
            self.by_sender.remove(sender);
        }
        tx
    }

    fn merge_from(&mut self, other: RawTxPool) {
        for (_, bucket) in other.by_sender {
            for tx in bucket {
                self.push_tx_snapshot_for_sender(tx, false);
            }
        }
    }

    fn prune_pool_to_priority_window(&mut self, reference: &PruneReferenceTx, priority_mask: u64) {
        let old = std::mem::take(&mut self.by_sender);
        self.total_count = 0;

        let mut candidates = Vec::new();
        for (_, bucket) in old {
            for tx in bucket {
                let score = score_tx_against_reference(&tx, reference, priority_mask);
                if score.keep {
                    candidates.push((score, tx));
                }
            }
        }

        candidates.sort_by(|(left_score, left_tx), (right_score, right_tx)| {
            left_score
                .cmp(right_score)
                .then_with(|| left_tx.nonce.cmp(&right_tx.nonce))
                .then_with(|| left_tx.sequence.cmp(&right_tx.sequence))
        });

        for (_, tx) in candidates.into_iter().rev().take(RAW_TX_POOL_REINSERT_LIMIT) {
            self.push_tx_snapshot_for_sender(tx, false);
        }
    }
}

fn sort_sender_bucket(bucket: &mut [TxSnapshot]) {
    bucket.sort_by(|left, right| {
        score_tx_for_sender(left)
            .cmp(&score_tx_for_sender(right))
            .then_with(|| right.nonce.cmp(&left.nonce))
            .then_with(|| right.sequence.cmp(&left.sequence))
    });
}

fn score_tx_for_sender(tx: &TxSnapshot) -> u128 {
    let fee = tx.fee_cap.0[0] as u128;
    let tip = tx.effective_tip().0[0] as u128;
    (fee << 64) | tip
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct PriorityScore {
    keep: bool,
    fee_cap: u64,
    priority: u64,
    distance: u64,
}

fn score_tx_against_reference(tx: &TxSnapshot, reference: &PruneReferenceTx, priority_mask: u64) -> PriorityScore {
    let fee_cap = tx.fee_cap.0[0];
    let priority = tx.effective_tip().0[0] & priority_mask;
    let distance = tx.nonce.abs_diff(reference.nonce);
    PriorityScore {
        keep: fee_cap >= reference.fee_floor.0[0],
        fee_cap,
        priority,
        distance: u64::MAX - distance,
    }
}

#[derive(Clone, Debug)]
pub struct PendingWorkItem {
    pub sender: Address,
    pub tx_key: B256,
    pub tx: Option<TxSnapshot>,
    pub minimum_fee_cap: U256,
}

#[derive(Clone, Debug, Default)]
pub struct PendingWorkBatch {
    pub execution_order: Vec<PendingWorkItem>,
    pub deferred_pool: RawTxPool,
}

#[derive(Clone, Debug, Default)]
pub struct EndBlockEvmContext {
    pub block_number: u64,
    pub block_gas_limit: u64,
    pub raw_txs_from_actions: Vec<TxSnapshot>,
    pub delayed_txs: Vec<TxSnapshot>,
    pub account_nonces: HashMap<Address, u64>,
}

#[derive(Clone, Debug, Default)]
pub struct GasSink {
    pub gas_used: u64,
    pub by_sender: HashMap<Address, u64>,
}

impl GasSink {
    fn add_gas(&mut self, sender: Address, gas: u64) {
        self.gas_used = saturating_add_u64(self.gas_used, gas);
        let entry = self.by_sender.entry(sender).or_insert(0);
        *entry = saturating_add_u64(*entry, gas);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactorTxError {
    VmRejected { tag: u8, payload: VmErrorPayload },
    Internal,
    BalanceUnderflow,
    GasUnderflow,
    BlockGasLimit { gas_used: u64, tx_gas: u64, block_limit: u64 },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VmErrorPayload {
    pub code: u64,
    pub data: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VmReturn {
    Success(TxExecutionSuccess),
    Error(TransactorTxError),
}

impl VmReturn {
    pub fn from_recovered_parts(discriminant: u64, tag: u8, payload: VmErrorPayload, success: TxExecutionSuccess) -> Self {
        if discriminant == VM_ERROR_SENTINEL {
            let error = match tag {
                0 | 1 | 2 => TransactorTxError::VmRejected { tag, payload },
                _ => TransactorTxError::Internal,
            };
            Self::Error(error)
        } else {
            Self::Success(success)
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StateEffect {
    pub address: Address,
    pub gas_delta: u64,
    pub balance_delta: U256,
    pub log_key: B256,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TxExecutionSuccess {
    pub tx_key: B256,
    pub sender: Address,
    pub gas_used: u64,
    pub refunded_gas: u64,
    pub state_effects: Vec<StateEffect>,
    pub output: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxExecutionRecord {
    pub tx_key: B256,
    pub sender: Address,
    pub gas_used: u64,
    pub success: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvmBlockExecutionOutput {
    pub touched_accounts: Vec<Address>,
    pub tx_records: Vec<TxExecutionRecord>,
    pub successful_txs: Vec<TxSnapshot>,
    pub errors: Vec<(B256, TransactorTxError)>,
    pub total_gas_used: u64,
    pub gas_by_sender: HashMap<Address, u64>,
    pub snapshot: HyperEvmSnapshot,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HyperEvmSnapshot {
    pub block_number: u64,
    pub state_root: B256,
    pub gas_used: u64,
    pub touched_accounts: Vec<Address>,
}

#[derive(Clone, Debug)]
pub struct PreparedEvmTx {
    pub tx: TxSnapshot,
    pub dry_run: bool,
}

pub trait HyperEvmExecutor {
    fn execute_transactor_tx(&mut self, tx: &PreparedEvmTx, gas_sink: &mut GasSink) -> VmReturn;
    fn snapshot_after_block(&self, block_number: u64, gas_used: u64, touched: &[Address]) -> HyperEvmSnapshot;
}

pub trait EvmOutputSink {
    fn record_success(&mut self, record: &TxExecutionRecord, success: &TxExecutionSuccess);
    fn record_error(&mut self, tx_key: B256, error: &TransactorTxError);
    fn commit_snapshot(&mut self, snapshot: &HyperEvmSnapshot);
}

pub trait EvmCommitHook {
    fn commit(&mut self, sink: &mut dyn EvmOutputSink, output: &EvmBlockExecutionOutput);
}

#[derive(Default)]
pub struct NoopEvmCommitHook;

impl EvmCommitHook for NoopEvmCommitHook {
    fn commit(&mut self, _sink: &mut dyn EvmOutputSink, _output: &EvmBlockExecutionOutput) {}
}

#[derive(Default)]
pub struct EvmTransactor {
    pub small_raw_tx_pool: RawTxPool,
    pub big_raw_tx_pool: RawTxPool,
    pub pending_slot_a: RawTxPool,
    pub pending_slot_b: RawTxPool,
    pub delayed_raw_txs: VecDeque<TxSnapshot>,
    pub current_snapshot: HyperEvmSnapshot,
    pub alternate_snapshot: HyperEvmSnapshot,
    pub state_history: BTreeMap<u64, HyperEvmSnapshot>,
}

impl EvmTransactor {
    pub fn insert_raw_tx_and_prune_pool(
        &mut self,
        use_big_pool: bool,
        mut tx: TxSnapshot,
        account: &AccountCtx,
    ) -> RawTxPoolInsertResult {
        tx.sender = account.address;
        tx.materialize_cached_tx_key_if_dirty();
        let sender = tx.sender;
        let tx_key = tx.tx_key;

        let needs_prune = {
            let pool = if use_big_pool {
                &mut self.big_raw_tx_pool
            } else {
                &mut self.small_raw_tx_pool
            };
            pool.push_tx_snapshot_for_sender(tx, true)
        };

        if needs_prune {
            let reference = self.build_prune_reference_tx(use_big_pool, account);
            let priority_mask = reference.priority_mask.low_u64_or_uint_conversion_error();
            let pool = if use_big_pool {
                &mut self.big_raw_tx_pool
            } else {
                &mut self.small_raw_tx_pool
            };
            pool.prune_pool_to_priority_window(&reference, priority_mask);
        }

        let retained = if use_big_pool {
            self.big_raw_tx_pool.contains_sender_tx_key(&sender, &tx_key)
        } else {
            self.small_raw_tx_pool.contains_sender_tx_key(&sender, &tx_key)
        };

        if retained {
            RawTxPoolInsertResult::Retained
        } else {
            RawTxPoolInsertResult::Evicted
        }
    }

    pub fn collect_pending_evm_work(&mut self, ctx: &EndBlockEvmContext) -> PendingWorkBatch {
        let mut batch = PendingWorkBatch::default();

        for tx in ctx.raw_txs_from_actions.iter().chain(ctx.delayed_txs.iter()) {
            self.collect_one_pending_tx(tx.clone(), &mut batch);
        }

        while let Some(tx) = self.delayed_raw_txs.pop_front() {
            self.collect_one_pending_tx(tx, &mut batch);
        }

        batch
    }

    fn collect_one_pending_tx(&mut self, mut tx: TxSnapshot, batch: &mut PendingWorkBatch) {
        tx.materialize_cached_tx_key_if_dirty();
        if tx.tx_key == [0; 32] || cmp_u256(tx.fee_cap, U256::from_u64(COLLECT_ELIGIBILITY_FLOOR_WEI)) == Ordering::Less {
            batch.deferred_pool.push_tx_snapshot_for_sender(tx, false);
            return;
        }

        batch.execution_order.push(PendingWorkItem {
            sender: tx.sender,
            tx_key: tx.tx_key,
            tx: Some(tx),
            minimum_fee_cap: U256::from_u64(COLLECT_ELIGIBILITY_FLOOR_WEI),
        });
    }

    pub fn execute_pending_evm_block<E, S>(
        &mut self,
        use_next_slot: bool,
        ctx: &mut EndBlockEvmContext,
        executor: &mut E,
        sink: &mut S,
    ) -> EvmBlockExecutionOutput
    where
        E: HyperEvmExecutor,
        S: EvmOutputSink,
    {
        let mut output = EvmBlockExecutionOutput::default();
        let mut gas_sink = GasSink::default();
        let work = self.collect_pending_evm_work(ctx);
        let mut active_pool = if use_next_slot {
            std::mem::take(&mut self.pending_slot_b)
        } else {
            std::mem::take(&mut self.pending_slot_a)
        };
        active_pool.merge_from(work.deferred_pool);

        let mut deferred = RawTxPool::default();
        for item in work.execution_order {
            let Some(mut tx) = active_pool.pop_best_for_sender(&item.sender).or(item.tx) else {
                continue;
            };
            tx.materialize_cached_tx_key_if_dirty();

            let account_nonce = *ctx.account_nonces.get(&tx.sender).unwrap_or(&0);
            if tx.nonce < account_nonce {
                continue;
            }
            if tx.nonce > account_nonce.saturating_add(RAW_TX_POOL_PER_SENDER_KEEP as u64) {
                deferred.push_tx_snapshot_for_sender(tx, false);
                continue;
            }

            let projected_gas = saturating_add_u64(gas_sink.gas_used, tx.gas_limit);
            if projected_gas > ctx.block_gas_limit {
                let error = TransactorTxError::BlockGasLimit {
                    gas_used: gas_sink.gas_used,
                    tx_gas: tx.gas_limit,
                    block_limit: ctx.block_gas_limit,
                };
                if gas_sink.gas_used != 0 {
                    deferred.push_tx_snapshot_for_sender(tx, false);
                } else {
                    sink.record_error(tx.tx_key, &error);
                    output.errors.push((tx.tx_key, error));
                }
                continue;
            }

            let prepared = PreparedEvmTx { tx: tx.clone(), dry_run: false };
            match executor.execute_transactor_tx(&prepared, &mut gas_sink) {
                VmReturn::Success(success) => {
                    let gas_used = success.gas_used;
                    gas_sink.add_gas(tx.sender, gas_used);
                    for effect in &success.state_effects {
                        remember_unique_account(&mut output.touched_accounts, effect.address);
                    }
                    remember_unique_account(&mut output.touched_accounts, tx.sender);

                    let record = TxExecutionRecord {
                        tx_key: tx.tx_key,
                        sender: tx.sender,
                        gas_used,
                        success: true,
                    };
                    sink.record_success(&record, &success);
                    output.tx_records.push(record);
                    output.successful_txs.push(tx);
                }
                VmReturn::Error(error) => {
                    sink.record_error(tx.tx_key, &error);
                    output.errors.push((tx.tx_key, error));
                }
            }
        }

        active_pool.merge_from(deferred);
        if use_next_slot {
            self.pending_slot_b = active_pool;
        } else {
            self.pending_slot_a = active_pool;
        }

        output.total_gas_used = gas_sink.gas_used;
        output.gas_by_sender = gas_sink.by_sender;
        output.snapshot = executor.snapshot_after_block(ctx.block_number, output.total_gas_used, &output.touched_accounts);
        self.commit_hyper_evm_snapshot(use_next_slot, output.snapshot.clone(), sink);
        output
    }

    pub fn execute_pending_transactions_with_hook<E, S, H>(
        &mut self,
        use_next_slot: bool,
        ctx: &mut EndBlockEvmContext,
        executor: &mut E,
        sink: &mut S,
        hook: &mut H,
    ) -> EvmBlockExecutionOutput
    where
        E: HyperEvmExecutor,
        S: EvmOutputSink,
        H: EvmCommitHook,
    {
        let output = self.execute_pending_evm_block(use_next_slot, ctx, executor, sink);
        hook.commit(sink, &output);
        output
    }

    pub fn execute_pending_transactions_noop_commit<E, S>(
        &mut self,
        use_next_slot: bool,
        ctx: &mut EndBlockEvmContext,
        executor: &mut E,
        sink: &mut S,
    ) -> EvmBlockExecutionOutput
    where
        E: HyperEvmExecutor,
        S: EvmOutputSink,
    {
        let mut hook = NoopEvmCommitHook;
        self.execute_pending_transactions_with_hook(use_next_slot, ctx, executor, sink, &mut hook)
    }

    fn build_prune_reference_tx(&self, use_big_pool: bool, account: &AccountCtx) -> PruneReferenceTx {
        let account_limit = if use_big_pool || account.big_block_gas_limit {
            BIG_ACCOUNT_GAS_LIMIT
        } else {
            SMALL_ACCOUNT_GAS_LIMIT
        };
        let fee_floor = if account.balance.0[0] < MIN_POOL_FEE_CAP_WEI {
            U256::from_u64(MIN_POOL_FEE_CAP_WEI)
        } else {
            U256::from_u64(account.balance.0[0].max(MIN_POOL_FEE_CAP_WEI))
        };

        PruneReferenceTx {
            sender: account.address,
            nonce: account.nonce,
            gas_limit: account_limit,
            fee_floor,
            priority_mask: fee_floor,
            sequence: account.account_key,
        }
    }

    fn commit_hyper_evm_snapshot<S>(&mut self, use_next_slot: bool, snapshot: HyperEvmSnapshot, sink: &mut S)
    where
        S: EvmOutputSink,
    {
        if use_next_slot {
            self.alternate_snapshot = snapshot.clone();
        } else {
            self.current_snapshot = snapshot.clone();
        }

        self.state_history.insert(snapshot.block_number, snapshot.clone());
        let keep_from = snapshot.block_number.saturating_sub(STATE_HISTORY_DEPTH);
        let old = self.state_history.split_off(&keep_from);
        self.state_history = old;
        sink.commit_snapshot(&snapshot);
    }
}

fn remember_unique_account(accounts: &mut Vec<Address>, account: Address) {
    if !accounts.iter().any(|existing| existing == &account) {
        accounts.push(account);
    }
}

pub fn is_absent_encoded_value(value: u64) -> bool {
    value == ABSENT_SENTINEL
}

pub fn is_vm_success_tag(tag: u8) -> bool {
    tag == VM_SUCCESS_TAG
}
