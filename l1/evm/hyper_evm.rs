use std::cmp::Ordering;
use std::collections::{BTreeMap, VecDeque};

pub type Address = [u8; 20];
pub type B256 = [u8; 32];

const RECENT_SNAPSHOT_RETENTION: u64 = 256;
const SECONDS_PER_YEAR: f64 = 31_557_600.0;
const MAX_ANNUALIZED_STEP: f64 = 1.01;

/// Vecs in the optimized binary use Rust's normal three-word representation, but
/// Hex-Rays prints it as `{ cap, ptr, len }` in several moved-out temporaries.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HyperEvmApplyResult {
    pub built_blocks: Vec<EvmBlockBuildRecord>,
    pub stale_users: Vec<Address>,
    pub drained_outputs: Vec<EvmWriterResult>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvmBlockKind {
    Small,
    Big,
}

impl EvmBlockKind {
    fn is_big(self) -> bool {
        matches!(self, Self::Big)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmBlockBuildRecord {
    pub kind: EvmBlockKind,
    pub block_number: u64,
    pub emitted_actions: Vec<GeneratedEvmAction>,
    pub outcomes: Vec<EvmActionOutcome>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyEndBlockOutputs {
    /// 72-byte rows in the recovered callers; these are dispatched as EVM/L1
    /// action outcomes by the exchange end-block path.
    pub outcomes: Vec<EvmActionOutcome>,
    /// 296-byte rows in the recovered callers; these are settled as generated
    /// EVM actions after the block has been built.
    pub generated_actions: Vec<GeneratedEvmAction>,
    /// A third Vec-like result group carried into the exchange's 304-byte output
    /// record.  The binary treats it as opaque writer/output rows until DB flush.
    pub writer_results: Vec<EvmWriterResult>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmActionOutcome {
    pub address: Address,
    pub kind: EvmEffectKind,
    pub success: bool,
    pub gas_used: u64,
    pub value_delta: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedEvmAction {
    pub address: Address,
    pub payload: Vec<u8>,
    pub value: u64,
    pub big_block_only: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmWriterResult {
    pub key: B256,
    pub value: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvmEffectKind {
    Deposit,
    Withdrawal,
    Clearinghouse,
    System,
    Unknown(u8),
}

impl EvmEffectKind {
    pub fn marker(self) -> u8 {
        match self {
            Self::Deposit => 0,
            Self::Withdrawal => 1,
            Self::Clearinghouse => 2,
            Self::System => 3,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingTransactorTx {
    pub address: Address,
    pub sequence: u64,
    pub gas_or_value: u64,
    pub kind: EvmEffectKind,
    pub payload: Vec<u8>,
}

impl PendingTransactorTx {
    fn cost_for_limit(&self) -> u64 {
        self.gas_or_value
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PendingAddressEffects {
    pub deposits: Vec<L1EvmEffect>,
    pub withdrawals: Vec<L1EvmEffect>,
    pub system: Vec<L1EvmEffect>,
}

impl PendingAddressEffects {
    pub fn mark_kind(&mut self, kind: EvmEffectKind, effect: L1EvmEffect) {
        match kind {
            EvmEffectKind::Deposit => self.deposits.push(effect),
            EvmEffectKind::Withdrawal => self.withdrawals.push(effect),
            EvmEffectKind::System | EvmEffectKind::Clearinghouse | EvmEffectKind::Unknown(_) => {
                self.system.push(effect)
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.deposits.is_empty() && self.withdrawals.is_empty() && self.system.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct L1EvmEffect {
    pub kind: EvmEffectKind,
    pub address: Address,
    pub amount: u64,
    pub aux: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClearinghouseEffect {
    pub user: Address,
    pub maturity_date: i32,
    pub amount: u64,
    pub rate_base: u64,
    pub kind: EvmEffectKind,
    pub route_to_spot: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelayedTransfer {
    pub user: Address,
    pub next_date: i32,
    pub amount: u64,
    pub kind: EvmEffectKind,
    pub route_to_spot: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmExecutionResult {
    pub outcomes: Vec<EvmActionOutcome>,
    pub generated_actions: Vec<GeneratedEvmAction>,
    pub writer_results: Vec<EvmWriterResult>,
    pub child_work: Vec<PendingTransactorTx>,
    pub gas_used: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExternalActionStatus {
    Applied,
    Rejected { code: u16 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalActionResult {
    pub status: ExternalActionStatus,
    pub writer_result: Option<EvmWriterResult>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmBlockSnapshot {
    pub block_number: u64,
    pub parent_hash: B256,
    pub block_hash: B256,
    pub gas_used: u64,
    pub total_value: u64,
    pub address_summaries: BTreeMap<Address, u64>,
    pub output_bloom: [u8; 256],
    pub outcomes: Vec<EvmActionOutcome>,
    pub generated_actions: Vec<GeneratedEvmAction>,
    pub writer_results: Vec<EvmWriterResult>,
}

impl Default for EvmBlockSnapshot {
    fn default() -> Self {
        Self {
            block_number: 0,
            parent_hash: [0; 32],
            block_hash: [0; 32],
            gas_used: 0,
            total_value: 0,
            address_summaries: BTreeMap::new(),
            output_bloom: [0; 256],
            outcomes: Vec::new(),
            generated_actions: Vec::new(),
            writer_results: Vec::new(),
        }
    }
}

/// Configuration and runtime flags recovered from the two end-block monomorphs.
#[derive(Clone, Debug)]
pub struct HyperEvmConfig {
    pub enabled: bool,
    pub initialized: bool,
    pub small_block_interval_ms: u64,
    pub last_small_bucket: u64,
    pub big_block_interval_ms: u64,
    pub last_big_bucket: u64,
    pub allow_non_contract_accounts: bool,
    pub allow_contract_accounts: bool,
    pub annualized_amount_rate: Option<f64>,
    pub freeze_mode: u32,
    pub freeze_height: u64,
    pub delayed_transfer_mode: u8,
}

impl Default for HyperEvmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            initialized: false,
            small_block_interval_ms: 1,
            last_small_bucket: 0,
            big_block_interval_ms: 1,
            last_big_bucket: 0,
            allow_non_contract_accounts: false,
            allow_contract_accounts: false,
            annualized_amount_rate: None,
            freeze_mode: 0,
            freeze_height: 0,
            delayed_transfer_mode: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EndBlockContext {
    /// Packed chrono `NaiveDate` fields are read by the binary as three integers
    /// and converted to unix milliseconds with the same civil-date arithmetic.
    pub date_bits: i32,
    pub seconds: u32,
    pub nanos: u32,
    pub height: u64,
    pub parent_hash: B256,
    pub current_hash: B256,
}

impl EndBlockContext {
    pub fn unix_millis(&self) -> u64 {
        let days = days_from_packed_date(self.date_bits) as i64;
        let seconds = self.seconds as i64 + days.saturating_mul(86_400);
        let millis = seconds
            .saturating_mul(1_000)
            .saturating_add((self.nanos / 1_000_000) as i64);
        millis.max(0) as u64
    }
}

#[derive(Clone, Debug, Default)]
pub struct HyperEvm {
    /// Observed around offset 0x20 and passed to account lookup helpers.
    pub account_state: BTreeMap<Address, AccountClass>,
    /// Offset family 0x21b8: selected for small-block pending queue.
    pub small_pending: BTreeMap<Address, VecDeque<PendingTransactorTx>>,
    /// Offset family 0x2520: selected for big-block pending queue.
    pub big_pending: BTreeMap<Address, VecDeque<PendingTransactorTx>>,
    /// Offset family 0x2570: refreshed with collected transactor work before each
    /// drain of one of the staged queues.
    pub refreshed_pending: BTreeMap<Address, VecDeque<PendingTransactorTx>>,
    /// Offset 0x1b38: current 0x338-byte block snapshot.
    pub current_snapshot: EvmBlockSnapshot,
    /// Offset 0x1e70: alternate snapshot for the small block side.
    pub small_snapshot: EvmBlockSnapshot,
    /// Offset 0x21d8: alternate snapshot for the big block side.
    pub big_snapshot: EvmBlockSnapshot,
    /// Offset 0x1b20 tree keyed by height, pruned to roughly the last 256 blocks.
    pub recent_snapshots: BTreeMap<u64, SnapshotHeader>,
    /// Offset 0x1d48 in the wrapper cluster.
    pub block_number: u64,
    /// Offset 0x1e08 in the wrapper cluster.
    pub current_hash: B256,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SnapshotHeader {
    pub block_hash: B256,
    pub parent_hash: B256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountClass {
    Contract,
    ExternallyOwned,
    Empty,
    Unknown(u8),
}

impl AccountClass {
    pub fn from_recovered_byte(value: u8) -> Self {
        match value {
            0..=3 => Self::Contract,
            4 => Self::ExternallyOwned,
            5 => Self::Empty,
            other => Self::Unknown(other),
        }
    }

    fn allowed_by(self, config: &HyperEvmConfig) -> bool {
        match self {
            Self::Contract => config.allow_contract_accounts,
            Self::ExternallyOwned | Self::Empty | Self::Unknown(_) => config.allow_non_contract_accounts,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct HyperEvmStateWrapper {
    pub evm: HyperEvm,
    pub config: HyperEvmConfig,
    pub pending_l1_effects: BTreeMap<Address, PendingAddressEffects>,
    pub clearinghouse_effects: Vec<ClearinghouseEffect>,
    pub delayed_transfers: Vec<DelayedTransfer>,
    pub queued_writer_results: Vec<EvmWriterResult>,
    pub last_amount_adjustment_date: Option<(i32, u64)>,
    pub global_freeze_reached: bool,
}

pub trait HyperEvmTransactor {
    fn collect_pending_evm_work(
        &mut self,
        kind: EvmBlockKind,
        ctx: &EndBlockContext,
    ) -> BTreeMap<Address, VecDeque<PendingTransactorTx>>;

    fn execute_transactor_tx(
        &mut self,
        tx: &PendingTransactorTx,
        ctx: &EndBlockContext,
    ) -> EvmExecutionResult;

    fn apply_l1_effect(
        &mut self,
        address: Address,
        effects: &PendingAddressEffects,
        ctx: &EndBlockContext,
    ) -> Vec<EvmWriterResult>;

    fn execute_external_action(
        &mut self,
        transfer: &DelayedTransfer,
        ctx: &EndBlockContext,
    ) -> ExternalActionResult;
}

pub trait EvmDbRecorder {
    fn record_block_output(&mut self, output: &EvmBlockSnapshot);
    fn push_writer_result(&mut self, result: EvmWriterResult);
    fn flush(&mut self) -> Vec<EvmWriterResult>;
}

pub trait EvmAccountClassifier {
    fn classify(&self, address: &Address) -> AccountClass;
}

impl EvmAccountClassifier for HyperEvm {
    fn classify(&self, address: &Address) -> AccountClass {
        self.account_state
            .get(address)
            .copied()
            .unwrap_or(AccountClass::Empty)
    }
}

impl HyperEvmStateWrapper {
    pub fn apply_l1_effects_without_db<T>(
        &mut self,
        transactor: &mut T,
        ctx: &EndBlockContext,
    ) -> HyperEvmApplyResult
    where
        T: HyperEvmTransactor,
    {
        let mut sink = DropOnlyRecorder::default();
        self.apply_l1_effects_inner(transactor, ctx, Some(&mut sink))
    }

    pub fn apply_l1_effects_with_db<T, D>(
        &mut self,
        transactor: &mut T,
        ctx: &EndBlockContext,
        db: &mut D,
    ) -> HyperEvmApplyResult
    where
        T: HyperEvmTransactor,
        D: EvmDbRecorder,
    {
        self.apply_l1_effects_inner(transactor, ctx, Some(db))
    }

    fn apply_l1_effects_inner<T>(
        &mut self,
        transactor: &mut T,
        ctx: &EndBlockContext,
        mut recorder: Option<&mut dyn EvmDbRecorder>,
    ) -> HyperEvmApplyResult
    where
        T: HyperEvmTransactor,
    {
        let mut result = HyperEvmApplyResult::default();

        if self.config.enabled {
            assert!(self.config.initialized, "HyperEVM enabled before initialization");
            result
                .built_blocks
                .extend(self.build_due_evm_blocks(transactor, ctx, &mut recorder));
        }

        self.apply_pending_address_effects(transactor, ctx, &mut recorder, &mut result);
        self.apply_clearinghouse_effects(transactor, ctx, &mut recorder, &mut result);
        self.drain_writer_results(&mut recorder, &mut result);
        self.update_freeze_latch(ctx);

        result
    }

    fn build_due_evm_blocks<T>(
        &mut self,
        transactor: &mut T,
        ctx: &EndBlockContext,
        recorder: &mut Option<&mut dyn EvmDbRecorder>,
    ) -> Vec<EvmBlockBuildRecord>
    where
        T: HyperEvmTransactor,
    {
        let now_ms = ctx.unix_millis();
        let mut built = Vec::new();

        if should_build_bucket(
            now_ms,
            self.config.small_block_interval_ms,
            &mut self.config.last_small_bucket,
        ) {
            let outputs = self
                .evm
                .execute_pending_evm_block(EvmBlockKind::Small, transactor, ctx, recorder);
            built.push(EvmBlockBuildRecord {
                kind: EvmBlockKind::Small,
                block_number: self.evm.block_number,
                emitted_actions: outputs.generated_actions,
                outcomes: outputs.outcomes,
            });
        }

        if should_build_bucket(
            now_ms,
            self.config.big_block_interval_ms,
            &mut self.config.last_big_bucket,
        ) {
            let outputs = self
                .evm
                .execute_pending_evm_block(EvmBlockKind::Big, transactor, ctx, recorder);
            built.push(EvmBlockBuildRecord {
                kind: EvmBlockKind::Big,
                block_number: self.evm.block_number,
                emitted_actions: outputs.generated_actions,
                outcomes: outputs.outcomes,
            });
        }

        built
    }

    fn apply_pending_address_effects<T>(
        &mut self,
        transactor: &mut T,
        ctx: &EndBlockContext,
        recorder: &mut Option<&mut dyn EvmDbRecorder>,
        result: &mut HyperEvmApplyResult,
    ) where
        T: HyperEvmTransactor,
    {
        let effects = std::mem::take(&mut self.pending_l1_effects);
        for (address, bucket) in effects {
            if bucket.is_empty() {
                continue;
            }

            let class = self.evm.classify(&address);
            if !class.allowed_by(&self.config) {
                self.pending_l1_effects.insert(address, bucket);
                continue;
            }

            for writer_result in transactor.apply_l1_effect(address, &bucket, ctx) {
                if let Some(recorder) = recorder.as_mut() {
                    recorder.push_writer_result(writer_result.clone());
                }
                result.drained_outputs.push(writer_result);
            }
        }
    }

    fn apply_clearinghouse_effects<T>(
        &mut self,
        transactor: &mut T,
        ctx: &EndBlockContext,
        recorder: &mut Option<&mut dyn EvmDbRecorder>,
        result: &mut HyperEvmApplyResult,
    ) where
        T: HyperEvmTransactor,
    {
        let current_date = ctx.date_bits;
        let mut pending = std::mem::take(&mut self.clearinghouse_effects);
        if let Some(rate) = self.config.annualized_amount_rate {
            adjust_clearinghouse_amounts(&mut pending, self.last_amount_adjustment_date, current_date, rate);
        }
        self.last_amount_adjustment_date = Some((current_date, ctx.height));

        let next_date = next_delayed_date(current_date, self.config.delayed_transfer_mode);
        for effect in pending {
            if effect.maturity_date >= current_date {
                self.clearinghouse_effects.push(effect);
                continue;
            }

            self.delayed_transfers.push(DelayedTransfer {
                user: effect.user,
                next_date,
                amount: effect.amount,
                kind: effect.kind,
                route_to_spot: effect.route_to_spot,
            });
        }

        let transfers = std::mem::take(&mut self.delayed_transfers);
        for transfer in transfers {
            match transactor.execute_external_action(&transfer, ctx) {
                ExternalActionResult {
                    status: ExternalActionStatus::Applied,
                    writer_result,
                } => {
                    if let Some(writer_result) = writer_result {
                        if let Some(recorder) = recorder.as_mut() {
                            recorder.push_writer_result(writer_result.clone());
                        }
                        result.drained_outputs.push(writer_result);
                    }
                }
                ExternalActionResult {
                    status: ExternalActionStatus::Rejected { .. },
                    writer_result,
                } => {
                    if let Some(writer_result) = writer_result {
                        result.drained_outputs.push(writer_result);
                    }
                    result.stale_users.push(transfer.user);
                }
            }
        }
    }

    fn drain_writer_results(
        &mut self,
        recorder: &mut Option<&mut dyn EvmDbRecorder>,
        result: &mut HyperEvmApplyResult,
    ) {
        for row in self.queued_writer_results.drain(..) {
            if let Some(recorder) = recorder.as_mut() {
                recorder.push_writer_result(row.clone());
            }
            result.drained_outputs.push(row);
        }

        if let Some(recorder) = recorder.as_mut() {
            result.drained_outputs.extend(recorder.flush());
        }
    }

    fn update_freeze_latch(&mut self, ctx: &EndBlockContext) {
        if self.config.freeze_mode == 1 {
            assert!(
                self.config.freeze_height >= ctx.height,
                "HyperEVM freeze height is behind current block"
            );
            if self.config.freeze_height == ctx.height {
                self.global_freeze_reached = true;
            }
        }
    }
}

impl HyperEvm {
    pub fn execute_pending_evm_block<T>(
        &mut self,
        kind: EvmBlockKind,
        transactor: &mut T,
        ctx: &EndBlockContext,
        recorder: &mut Option<&mut dyn EvmDbRecorder>,
    ) -> ApplyEndBlockOutputs
    where
        T: HyperEvmTransactor,
    {
        let collected = transactor.collect_pending_evm_work(kind, ctx);
        merge_pending_queues(&mut self.refreshed_pending, collected.clone());

        let staged = if kind.is_big() {
            std::mem::take(&mut self.big_pending)
        } else {
            std::mem::take(&mut self.small_pending)
        };

        if kind.is_big() {
            merge_pending_queues(&mut self.small_pending, collected);
        } else {
            merge_pending_queues(&mut self.big_pending, collected);
        }

        let mut outputs = ApplyEndBlockOutputs {
            outcomes: Vec::new(),
            generated_actions: Vec::new(),
            writer_results: Vec::new(),
        };
        let mut address_summaries = BTreeMap::new();
        let mut total_value = 0u64;
        let mut gas_used = 0u64;
        let gas_limit = recovered_gas_limit(&kind);

        for (address, mut queue) in staged {
            while let Some(tx) = queue.pop_front() {
                if !self.should_execute(&address, &tx, total_value, gas_limit) {
                    self.requeue(kind, tx);
                    continue;
                }

                let exec = transactor.execute_transactor_tx(&tx, ctx);
                total_value = saturating_add_with_recovered_overflow(total_value, tx.cost_for_limit());
                gas_used = saturating_add_with_recovered_overflow(gas_used, exec.gas_used);
                *address_summaries.entry(address).or_insert(0) = saturating_add_with_recovered_overflow(
                    *address_summaries.get(&address).unwrap_or(&0),
                    tx.cost_for_limit(),
                );

                for child in exec.child_work {
                    self.requeue(kind, child);
                }

                for row in &exec.writer_results {
                    if let Some(recorder) = recorder.as_mut() {
                        recorder.push_writer_result(row.clone());
                    }
                }

                outputs.outcomes.extend(exec.outcomes);
                outputs.generated_actions.extend(exec.generated_actions);
                outputs.writer_results.extend(exec.writer_results);
            }
        }

        self.block_number = self.block_number.saturating_add(1);
        let snapshot = build_snapshot(
            self.block_number,
            ctx,
            gas_used,
            total_value,
            address_summaries,
            &outputs,
        );

        if let Some(recorder) = recorder.as_mut() {
            recorder.record_block_output(&snapshot);
        }

        self.install_snapshot(kind, snapshot);
        outputs
    }

    fn should_execute(
        &self,
        address: &Address,
        tx: &PendingTransactorTx,
        current_value: u64,
        gas_limit: u64,
    ) -> bool {
        let class = self.classify(address);
        let has_capacity = current_value.saturating_add(tx.cost_for_limit()) <= gas_limit;
        has_capacity && !matches!(class, AccountClass::Unknown(_))
    }

    fn requeue(&mut self, kind: EvmBlockKind, tx: PendingTransactorTx) {
        let queue = if kind.is_big() {
            &mut self.big_pending
        } else {
            &mut self.small_pending
        };
        queue.entry(tx.address).or_default().push_back(tx);
    }

    fn install_snapshot(&mut self, kind: EvmBlockKind, snapshot: EvmBlockSnapshot) {
        let header = SnapshotHeader {
            block_hash: snapshot.block_hash,
            parent_hash: snapshot.parent_hash,
        };
        self.current_hash = snapshot.block_hash;
        self.current_snapshot = snapshot.clone();
        if kind.is_big() {
            self.big_snapshot = snapshot;
        } else {
            self.small_snapshot = snapshot;
        }

        self.recent_snapshots.insert(self.block_number, header);
        let first_kept = self.block_number.saturating_sub(RECENT_SNAPSHOT_RETENTION);
        self.recent_snapshots = self.recent_snapshots.split_off(&first_kept);
    }
}

fn build_snapshot(
    block_number: u64,
    ctx: &EndBlockContext,
    gas_used: u64,
    total_value: u64,
    address_summaries: BTreeMap<Address, u64>,
    outputs: &ApplyEndBlockOutputs,
) -> EvmBlockSnapshot {
    let mut output_bloom = [0u8; 256];
    for outcome in &outputs.outcomes {
        mix_address_into_bloom(&mut output_bloom, &outcome.address);
    }

    EvmBlockSnapshot {
        block_number,
        parent_hash: ctx.parent_hash,
        block_hash: derive_recovered_snapshot_hash(block_number, &ctx.current_hash, gas_used, total_value),
        gas_used,
        total_value,
        address_summaries,
        output_bloom,
        outcomes: outputs.outcomes.clone(),
        generated_actions: outputs.generated_actions.clone(),
        writer_results: outputs.writer_results.clone(),
    }
}

fn merge_pending_queues(
    dst: &mut BTreeMap<Address, VecDeque<PendingTransactorTx>>,
    src: BTreeMap<Address, VecDeque<PendingTransactorTx>>,
) {
    for (address, mut queue) in src {
        dst.entry(address).or_default().append(&mut queue);
    }
}

fn should_build_bucket(now_ms: u64, interval_ms: u64, last_bucket: &mut u64) -> bool {
    let interval = interval_ms.max(1);
    let bucket = now_ms / interval;
    match bucket.cmp(last_bucket) {
        Ordering::Greater => {
            *last_bucket = bucket;
            true
        }
        Ordering::Equal | Ordering::Less => false,
    }
}

fn recovered_gas_limit(kind: &EvmBlockKind) -> u64 {
    match kind {
        EvmBlockKind::Small => 3_000_000,
        EvmBlockKind::Big => 30_000_000,
    }
}

fn saturating_add_with_recovered_overflow(lhs: u64, rhs: u64) -> u64 {
    lhs.checked_add(rhs).unwrap_or(u64::MAX)
}

fn adjust_clearinghouse_amounts(
    rows: &mut [ClearinghouseEffect],
    last: Option<(i32, u64)>,
    current_date: i32,
    annualized_rate: f64,
) {
    if annualized_rate < 0.0 {
        panic!("negative HyperEVM annualized rate");
    }

    let elapsed_days = last
        .map(|(date, _)| current_date.saturating_sub(date).max(0) as f64)
        .unwrap_or(0.0);
    let elapsed_seconds = elapsed_days * 86_400.0;
    let multiplier = (elapsed_seconds * annualized_rate / SECONDS_PER_YEAR).clamp(0.0, MAX_ANNUALIZED_STEP);

    for row in rows {
        let add = ((row.rate_base as f64) * multiplier).clamp(0.0, u64::MAX as f64) as u64;
        row.amount = saturating_add_with_recovered_overflow(row.amount, add);
    }
}

fn next_delayed_date(current_date: i32, mode: u8) -> i32 {
    // The binary calls a chrono helper with -45 unless a mode byte is 2, in
    // which case it uses -2.  The helper returns an Option and panics if it is
    // None; saturating arithmetic preserves the same non-wrapping invariant here.
    let offset = if mode == 2 { -2 } else { -45 };
    current_date.saturating_add(offset)
}

fn days_from_packed_date(date_bits: i32) -> i32 {
    // Direct translation of the optimized chrono date-to-days sequence:
    // year bucket = date >> 13, ordinal-ish bits = (date >> 4) & 0x1ff,
    // with negative-year correction in 400-year Gregorian cycles.
    let year_bucket = date_bits >> 13;
    let mut year_minus_one = year_bucket - 1;
    let mut correction = 0;
    if year_bucket <= 0 {
        let cycles = ((1 - year_bucket) as u32 / 400 + 1) as i32;
        year_minus_one += 400 * cycles;
        correction = -146_097 * cycles;
    }
    let ordinal = ((date_bits as u32 >> 4) & 0x1ff) as i32;
    ((year_minus_one / 100) >> 2) + ((1461 * year_minus_one) >> 2) + ordinal + correction
        - 719_163
        - year_minus_one / 100
}

fn mix_address_into_bloom(bloom: &mut [u8; 256], address: &Address) {
    for (index, byte) in address.iter().enumerate() {
        let slot = (index * 13 + *byte as usize) & 0xff;
        bloom[slot] |= 1 << (byte & 7);
    }
}

fn derive_recovered_snapshot_hash(
    block_number: u64,
    parent_or_context_hash: &B256,
    gas_used: u64,
    total_value: u64,
) -> B256 {
    // [INFERENCE] The exact hash helper is outside this file's seed set.  The
    // reconstructed state wrapper only requires a deterministic 32-byte header
    // value to model the install/recent-cache behavior seen in the binary.
    let mut out = *parent_or_context_hash;
    for (i, byte) in block_number.to_le_bytes().iter().enumerate() {
        out[i] ^= *byte;
    }
    for (i, byte) in gas_used.to_le_bytes().iter().enumerate() {
        out[8 + i] ^= *byte;
    }
    for (i, byte) in total_value.to_le_bytes().iter().enumerate() {
        out[16 + i] ^= *byte;
    }
    out
}

#[derive(Default)]
struct DropOnlyRecorder {
    drained: Vec<EvmWriterResult>,
}

impl EvmDbRecorder for DropOnlyRecorder {
    fn record_block_output(&mut self, _output: &EvmBlockSnapshot) {}

    fn push_writer_result(&mut self, result: EvmWriterResult) {
        self.drained.push(result);
    }

    fn flush(&mut self) -> Vec<EvmWriterResult> {
        std::mem::take(&mut self.drained)
    }
}
