#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type Hash32 = [u8; 32];
pub type Height = u64;
pub type Round = u64;
pub type AssetId = u64;
pub type TimestampMillis = u64;

const ACTION_OK_CODE: u16 = 390;
const FEATURE_READY: u8 = 3;
const REPLAY_ONLY_MODE: u32 = 2;
const REGISTRY_SNAPSHOT_INTERVAL: Height = 2_000;
const REGISTRY_SNAPSHOT_INTERVAL_LEGACY: Height = 50;
const PERIODIC_ABCI_CHECKPOINT_INTERVAL: Height = 10_000;
const CHECKPOINT_BUCKET_SECONDS: u32 = 3 * 60 * 60;
const SECONDS_PER_DAY: u64 = 86_400;
const MILLIS_PER_SECOND: u64 = 1_000;
const MICROS_PER_MILLI: u64 = 1_000;
const UNIX_EPOCH_DAYS_FROM_CE: i32 = 719_163;
const ANNUAL_SECONDS: f64 = 31_557_600.0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExchangeDomain {
    Main,
    Alt,
}

impl Default for ExchangeDomain {
    fn default() -> Self {
        Self::Main
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaneKind {
    Primary,
    Secondary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaneMode {
    Normal,
    ReplayOnly,
    Other(u32),
}

impl LaneMode {
    #[inline]
    pub const fn from_raw(value: u32) -> Self {
        match value {
            REPLAY_ONLY_MODE => Self::ReplayOnly,
            0 | 1 => Self::Normal,
            other => Self::Other(other),
        }
    }

    #[inline]
    pub const fn raw(self) -> u32 {
        match self {
            Self::Normal => 1,
            Self::ReplayOnly => REPLAY_ONLY_MODE,
            Self::Other(value) => value,
        }
    }

    #[inline]
    pub const fn is_replay_only(self) -> bool {
        matches!(self, Self::ReplayOnly)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PackedDateTime {
    /// Chrono `NaiveDate::num_days_from_ce()` representation recovered from the
    /// packed date word used by the end-block paths.
    pub days_from_ce: i32,
    /// Seconds since midnight.  The binary panics on chrono's loose upper bound
    /// and asserts the production bound of 90_000 seconds.
    pub seconds_from_midnight: u32,
    pub micros: u32,
}

impl PackedDateTime {
    #[inline]
    pub const fn unix_millis(self) -> TimestampMillis {
        let days_since_epoch = (self.days_from_ce - UNIX_EPOCH_DAYS_FROM_CE) as i64;
        if days_since_epoch < 0 {
            return 0;
        }
        let day_millis = days_since_epoch as u64 * SECONDS_PER_DAY * MILLIS_PER_SECOND;
        day_millis
            + self.seconds_from_midnight as u64 * MILLIS_PER_SECOND
            + self.micros as u64 / MICROS_PER_MILLI
    }

    #[inline]
    pub const fn three_hour_bucket(self) -> u8 {
        (self.seconds_from_midnight / CHECKPOINT_BUCKET_SECONDS) as u8
    }

    #[inline]
    pub const fn checked_sub_days(self, days: i32) -> Option<Self> {
        match self.days_from_ce.checked_sub(days) {
            Some(days_from_ce) => Some(Self { days_from_ce, ..self }),
            None => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockHeader {
    pub height: Height,
    pub round: Round,
    pub parent_round: Round,
    pub parent_id: u64,
    pub parent_hash: u64,
    pub consensus_time: PackedDateTime,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlockBatch {
    pub header: BlockHeader,
    pub actions: Vec<BlockAction>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlockAction {
    pub index: usize,
    pub user: Address,
    pub asset: AssetId,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionResult {
    pub code: u16,
    pub user: Address,
    pub asset: AssetId,
    pub generated_effects: Vec<L1Effect>,
}

impl ActionResult {
    #[inline]
    pub const fn is_ok(&self) -> bool {
        self.code == ACTION_OK_CODE
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExecutionSummary {
    pub accepted: usize,
    pub rejected: usize,
    pub last_status: Option<u16>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ApplyBlockReturn {
    pub begin_summary: ExecutionSummary,
    pub action_summary: ExecutionSummary,
    pub end_block_outputs: ExchangeEndBlockOutputs,
    pub snapshot_records: Vec<SnapshotRecord>,
    pub freeze_state_changed: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlockFinishOutcome {
    pub action_summary: ExecutionSummary,
    pub output_records: Vec<AppliedUpdateRecord>,
    pub end_block_outputs: ExchangeEndBlockOutputs,
    pub high_watermark: Option<Height>,
    pub freeze_state_changed: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExchangeEndBlockOutputs {
    /// First returned Vec in all three recovered end-block monomorphs.
    pub bucket_guards: Vec<BucketGuardRecord>,
    /// Second returned Vec, drained from the late state queue.
    pub primary_queue: Vec<DrainedQueueItem>,
    /// Third returned Vec, transformed from a moved Vec queue and reset to cap 8.
    pub secondary_queue: Vec<DrainedQueueItem>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BucketGuardRecord {
    pub domain: ExchangeDomain,
    pub bucket: u64,
    pub height: Height,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DrainedQueueItem {
    pub user: Address,
    pub asset: AssetId,
    pub amount: i128,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AppliedUpdateRecord {
    pub height: Height,
    pub user: Address,
    pub asset: AssetId,
    pub status: u16,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SnapshotRecord {
    pub height: Height,
    pub hash: Hash32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RegistrySnapshot {
    pub height: Height,
    pub hash: Hash32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct L1Effect {
    pub domain: ExchangeDomain,
    pub user: Address,
    pub asset: AssetId,
    pub amount: i128,
    /// The decompiled merge paths add tag 2 for drained map entries and tag 3
    /// for per-user entries moved from the 0x2f0-stride user array.
    pub merge_tag: u8,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct L1EffectBatch {
    pub effects: Vec<L1Effect>,
}

impl L1EffectBatch {
    #[inline]
    pub fn push(&mut self, effect: L1Effect) {
        self.effects.push(effect);
    }

    #[inline]
    pub fn extend<I>(&mut self, effects: I)
    where
        I: IntoIterator<Item = L1Effect>,
    {
        self.effects.extend(effects);
    }

    #[inline]
    pub fn drain(&mut self) -> impl Iterator<Item = L1Effect> + '_ {
        self.effects.drain(..)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FreezeState {
    pub scheduled_height: Option<Height>,
    pub frozen: bool,
}

impl FreezeState {
    #[inline]
    pub fn assert_valid_for_height(&self, height: Height) {
        if let Some(freeze_height) = self.scheduled_height {
            assert!(
                freeze_height >= height,
                "assertion failed: freeze_height >= self.locus.context.height()"
            );
            if !self.frozen {
                assert!(freeze_height != height, "assertion failed: !self.state.is_frozen()");
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayCounter {
    value: Height,
}

impl ReplayCounter {
    #[inline]
    pub const fn new(value: Height) -> Self {
        Self { value }
    }

    #[inline]
    pub fn increment_and_assert_height(&mut self, height: Height) {
        self.value = self.value.checked_add(1).expect("replay counter overflow");
        assert_eq!(self.value, height);
    }
}

impl Default for ReplayCounter {
    fn default() -> Self {
        Self::new(0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointState {
    pub replay_counter: ReplayCounter,
    pub last_checkpoint_time: PackedDateTime,
    pub rotation_enabled: bool,
    pub pending_thread_refs: u64,
}

impl Default for CheckpointState {
    fn default() -> Self {
        Self {
            replay_counter: ReplayCounter::default(),
            last_checkpoint_time: PackedDateTime::default(),
            rotation_enabled: true,
            pending_thread_refs: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaneState {
    pub kind: LaneKind,
    /// Feature/phase byte: all block execution paths assert that it is 3 at
    /// entry.  Values below 2 switch hash-snapshot cadence from 2000 to 50.
    pub feature_tier: u8,
    pub freeze: FreezeState,
    pub mode: LaneMode,
    pub update_records: Vec<AppliedUpdateRecord>,
    pub registry_snapshots: BTreeMap<Height, RegistrySnapshot>,
    pub state_hash_snapshots: BTreeMap<Height, SnapshotRecord>,
    pub retained_snapshot_low_watermark: Option<Height>,
    pub checkpoint: CheckpointState,
}

impl LaneState {
    pub fn new(kind: LaneKind) -> Self {
        Self {
            kind,
            feature_tier: FEATURE_READY,
            freeze: FreezeState::default(),
            mode: LaneMode::Normal,
            update_records: Vec::new(),
            registry_snapshots: BTreeMap::new(),
            state_hash_snapshots: BTreeMap::new(),
            retained_snapshot_low_watermark: None,
            checkpoint: CheckpointState::default(),
        }
    }

    #[inline]
    pub fn snapshot_interval(&self) -> Height {
        if self.feature_tier < 2 {
            REGISTRY_SNAPSHOT_INTERVAL_LEGACY
        } else {
            REGISTRY_SNAPSHOT_INTERVAL
        }
    }

    #[inline]
    pub fn assert_ready(&self) {
        assert_eq!(self.feature_tier, FEATURE_READY, "assertion failed: features_ok");
    }
}

impl Default for LaneState {
    fn default() -> Self {
        Self::new(LaneKind::Secondary)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DomainEndBlockState {
    pub pending_effects: L1EffectBatch,
    pub per_user_effects: BTreeMap<Address, L1EffectBatch>,
    pub apply_small_asset_classes: bool,
    pub apply_large_asset_classes: bool,
    pub small_evm_bucket_interval_ms: TimestampMillis,
    pub small_evm_last_bucket: Option<u64>,
    pub big_evm_bucket_interval_ms: TimestampMillis,
    pub big_evm_last_bucket: Option<u64>,
    pub hyper_evm_initialized: bool,
    pub evm_bucket_path_enabled: bool,
    pub annual_rate_enabled: bool,
    pub annual_rate: f64,
    pub last_accrual_time: Option<PackedDateTime>,
    pub final_queue: Vec<DrainedQueueItem>,
    pub transformed_queue: Vec<DrainedQueueItem>,
    pub retention_mode: u8,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Exchange {
    /// Pair at the beginning of the state compared with block parent id/hash.
    pub parent_id: u64,
    pub parent_hash: u64,
    pub height: Height,
    pub parent_round: Round,
    pub current_time: PackedDateTime,
    pub chain_metadata: u64,
    pub visor_metadata: u32,
    pub primary: LaneState,
    pub secondary: LaneState,
    pub main_domain: DomainEndBlockState,
    pub alt_domain: DomainEndBlockState,
    pub generated_order_users: BTreeSet<Address>,
}

impl Default for Exchange {
    fn default() -> Self {
        Self {
            parent_id: 0,
            parent_hash: 0,
            height: 0,
            parent_round: 0,
            current_time: PackedDateTime::default(),
            chain_metadata: 0,
            visor_metadata: 0,
            primary: LaneState::new(LaneKind::Primary),
            secondary: LaneState::new(LaneKind::Secondary),
            main_domain: DomainEndBlockState::default(),
            alt_domain: DomainEndBlockState::default(),
            generated_order_users: BTreeSet::new(),
        }
    }
}

pub trait ExchangeHooks {
    fn now(&mut self) -> PackedDateTime;

    fn impl_begin_block(
        &mut self,
        lane: LaneKind,
        exchange: &mut Exchange,
        header: &BlockHeader,
        replay_only: bool,
    ) -> ExecutionSummary;

    fn impl_execute_action(
        &mut self,
        lane: LaneKind,
        exchange: &mut Exchange,
        action: &BlockAction,
    ) -> ActionResult;

    fn impl_finalize_actions(
        &mut self,
        lane: LaneKind,
        exchange: &mut Exchange,
        accepted_action_refs: &[usize],
    ) -> ExecutionSummary;

    fn impl_end_block(
        &mut self,
        lane: LaneKind,
        exchange: &mut Exchange,
    ) -> ExchangeEndBlockOutputs;

    fn build_registry_snapshot(&mut self, exchange: &Exchange) -> RegistrySnapshot;

    fn build_state_hash_snapshot(&mut self, exchange: &Exchange, lane: LaneKind) -> SnapshotRecord;

    fn link_and_log_abci_state(&mut self, exchange: &Exchange, reason: CheckpointReason);

    fn spawn_checkpoint(&mut self, exchange: &Exchange, lane: LaneKind, now: PackedDateTime);

    fn build_small_evm_block_and_apply_l1_effects(
        &mut self,
        domain: ExchangeDomain,
        exchange: &mut Exchange,
        bucket: u64,
    ) -> BucketGuardRecord;

    fn build_big_evm_block_and_apply_l1_effects(
        &mut self,
        domain: ExchangeDomain,
        exchange: &mut Exchange,
        bucket: u64,
    ) -> BucketGuardRecord;

    fn apply_l1_effect(
        &mut self,
        domain: ExchangeDomain,
        exchange: &mut Exchange,
        effect: L1Effect,
    ) -> Option<DrainedQueueItem>;

    fn finalize_l1_effects(
        &mut self,
        domain: ExchangeDomain,
        exchange: &mut Exchange,
        cutoff: PackedDateTime,
        rate_fraction: f64,
    ) -> Vec<DrainedQueueItem>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointReason {
    Freeze,
    Periodic,
    Rotation,
}

impl Exchange {
    pub fn validate_block_header(&self, header: &BlockHeader) {
        assert!(header.round > header.parent_round, "assertion failed: round > parent_round");
        assert_eq!(self.parent_round, header.parent_round);
        assert_eq!((self.parent_id, self.parent_hash), (header.parent_id, header.parent_hash));
    }

    pub fn apply_primary_block<H: ExchangeHooks>(
        &mut self,
        block: &BlockBatch,
        hooks: &mut H,
    ) -> ApplyBlockReturn {
        self.apply_block_for_lane(LaneKind::Primary, block, hooks)
    }

    pub fn apply_secondary_block<H: ExchangeHooks>(
        &mut self,
        block: &BlockBatch,
        hooks: &mut H,
    ) -> ApplyBlockReturn {
        self.apply_block_for_lane(LaneKind::Secondary, block, hooks)
    }

    pub fn apply_secondary_and_update_snapshots<H: ExchangeHooks>(
        &mut self,
        block: &BlockBatch,
        hooks: &mut H,
    ) -> ApplyBlockReturn {
        self.apply_block_for_lane(LaneKind::Secondary, block, hooks)
    }

    pub fn finish_block_apply_exchange_updates<H: ExchangeHooks>(
        &mut self,
        block: &BlockBatch,
        hooks: &mut H,
    ) -> BlockFinishOutcome {
        let applied = self.apply_block_for_lane(LaneKind::Secondary, block, hooks);
        let lane = &mut self.secondary;
        let high_watermark = applied
            .end_block_outputs
            .primary_queue
            .iter()
            .map(|_| block.header.height)
            .chain(applied.snapshot_records.iter().map(|record| record.height))
            .max();
        if let Some(height) = high_watermark {
            lane.retained_snapshot_low_watermark = Some(
                lane.retained_snapshot_low_watermark
                    .map_or(height, |previous| previous.max(height)),
            );
        }
        BlockFinishOutcome {
            action_summary: applied.action_summary,
            output_records: lane.update_records.clone(),
            end_block_outputs: applied.end_block_outputs,
            high_watermark,
            freeze_state_changed: applied.freeze_state_changed,
        }
    }

    fn apply_block_for_lane<H: ExchangeHooks>(
        &mut self,
        lane_kind: LaneKind,
        block: &BlockBatch,
        hooks: &mut H,
    ) -> ApplyBlockReturn {
        self.validate_block_header(&block.header);
        {
            let lane = self.lane(lane_kind);
            lane.freeze.assert_valid_for_height(self.height);
            lane.assert_ready();
        }

        let replay_only = self.lane(lane_kind).mode.is_replay_only();
        let begin_summary = hooks.impl_begin_block(lane_kind, self, &block.header, replay_only);

        let mut action_summary = ExecutionSummary::default();
        let mut accepted_action_refs = Vec::new();
        let mut update_records = Vec::new();
        for action in &block.actions {
            let result = hooks.impl_execute_action(lane_kind, self, action);
            action_summary.last_status = Some(result.code);
            if result.is_ok() {
                action_summary.accepted += 1;
                accepted_action_refs.push(action.index);
            } else {
                action_summary.rejected += 1;
            }
            self.merge_generated_effects(result.generated_effects);
            update_records.push(AppliedUpdateRecord {
                height: block.header.height,
                user: result.user,
                asset: result.asset,
                status: result.code,
            });
        }

        let finalize_summary = hooks.impl_finalize_actions(lane_kind, self, &accepted_action_refs);
        action_summary.accepted += finalize_summary.accepted;
        action_summary.rejected += finalize_summary.rejected;
        if finalize_summary.last_status.is_some() {
            action_summary.last_status = finalize_summary.last_status;
        }

        let end_block_outputs = hooks.impl_end_block(lane_kind, self);
        let snapshot_records = self.update_lane_snapshots(lane_kind, block.header.height, hooks);
        let freeze_state_changed = self.freeze_state_changed(lane_kind);
        let lane = self.lane_mut(lane_kind);
        lane.update_records.extend(update_records);
        if replay_only {
            lane.checkpoint.replay_counter.increment_and_assert_height(block.header.height);
        } else {
            self.checkpoint_lane(lane_kind, hooks);
        }

        ApplyBlockReturn {
            begin_summary,
            action_summary,
            end_block_outputs,
            snapshot_records,
            freeze_state_changed,
        }
    }

    pub fn end_block_main<H: ExchangeHooks>(&mut self, hooks: &mut H) -> ExchangeEndBlockOutputs {
        self.end_block_apply_l1_effects(ExchangeDomain::Main, hooks)
    }

    pub fn end_block_alt<H: ExchangeHooks>(&mut self, hooks: &mut H) -> ExchangeEndBlockOutputs {
        self.end_block_apply_l1_effects(ExchangeDomain::Alt, hooks)
    }

    pub fn end_block_apply_l1_effects<H: ExchangeHooks>(
        &mut self,
        domain: ExchangeDomain,
        hooks: &mut H,
    ) -> ExchangeEndBlockOutputs {
        let now = self.current_time;
        let (mut state, small_gate, large_gate, retention_mode, last_accrual_time, annual_rate) = {
            let state = self.domain_state_mut(domain);
            let moved = std::mem::take(state);
            let small_gate = moved.apply_small_asset_classes;
            let large_gate = moved.apply_large_asset_classes;
            let retention_mode = moved.retention_mode;
            let last_accrual_time = moved.last_accrual_time;
            let annual_rate = if moved.annual_rate_enabled { moved.annual_rate } else { 0.0 };
            (moved, small_gate, large_gate, retention_mode, last_accrual_time, annual_rate)
        };

        let mut bucket_guards = Vec::new();
        if state.evm_bucket_path_enabled {
            assert!(state.hyper_evm_initialized);
            let now_ms = now.unix_millis();
            if state.small_evm_bucket_interval_ms != 0 {
                let bucket = now_ms / state.small_evm_bucket_interval_ms;
                if state.small_evm_last_bucket != Some(bucket) {
                    state.small_evm_last_bucket = Some(bucket);
                    bucket_guards.push(
                        hooks.build_small_evm_block_and_apply_l1_effects(domain, self, bucket),
                    );
                }
            }
            if state.big_evm_bucket_interval_ms != 0 {
                let bucket = now_ms / state.big_evm_bucket_interval_ms;
                if state.big_evm_last_bucket != Some(bucket) {
                    state.big_evm_last_bucket = Some(bucket);
                    bucket_guards.push(
                        hooks.build_big_evm_block_and_apply_l1_effects(domain, self, bucket),
                    );
                }
            }
        }

        for (_, mut user_batch) in std::mem::take(&mut state.per_user_effects) {
            for mut effect in user_batch.drain() {
                effect.merge_tag = 3;
                state.pending_effects.push(effect);
            }
        }

        let mut primary_queue = Vec::new();
        for effect in state.pending_effects.drain() {
            let is_large_class = effect.asset > 3;
            if (is_large_class && !large_gate) || (!is_large_class && !small_gate) {
                continue;
            }
            if let Some(item) = hooks.apply_l1_effect(domain, self, effect) {
                primary_queue.push(item);
            }
        }

        let retention_days = if retention_mode == 2 { 2 } else { 45 };
        let cutoff = now.checked_sub_days(retention_days).unwrap_or(now);
        let rate_fraction = last_accrual_time
            .map(|last| seconds_between(last, now) as f64 / ANNUAL_SECONDS * annual_rate)
            .unwrap_or(0.0);
        primary_queue.extend(hooks.finalize_l1_effects(domain, self, cutoff, rate_fraction));
        primary_queue.extend(state.final_queue.drain(..));

        let mut secondary_queue = Vec::new();
        secondary_queue.extend(state.transformed_queue.drain(..));
        state.last_accrual_time = Some(now);
        self.replace_domain_state(domain, state);

        ExchangeEndBlockOutputs {
            bucket_guards,
            primary_queue,
            secondary_queue,
        }
    }

    pub fn maybe_checkpoint_abci_state<H: ExchangeHooks>(&mut self, hooks: &mut H) {
        self.checkpoint_lane(LaneKind::Secondary, hooks)
    }

    pub fn checkpoint_primary_state<H: ExchangeHooks>(&mut self, hooks: &mut H) {
        self.checkpoint_lane(LaneKind::Primary, hooks)
    }

    pub fn checkpoint_secondary_state<H: ExchangeHooks>(&mut self, hooks: &mut H) {
        self.checkpoint_lane(LaneKind::Secondary, hooks)
    }

    fn checkpoint_lane<H: ExchangeHooks>(&mut self, lane_kind: LaneKind, hooks: &mut H) {
        let height = self.height;
        let now = hooks.now();
        let reason = {
            let lane = self.lane(lane_kind);
            if lane.freeze.scheduled_height == Some(height) {
                Some(CheckpointReason::Freeze)
            } else if height % PERIODIC_ABCI_CHECKPOINT_INTERVAL == 0 {
                Some(CheckpointReason::Periodic)
            } else {
                None
            }
        };
        if let Some(reason) = reason {
            hooks.link_and_log_abci_state(self, reason);
        }

        let rotate = {
            let lane = self.lane(lane_kind);
            lane.checkpoint.rotation_enabled
                && (lane.checkpoint.last_checkpoint_time.days_from_ce != now.days_from_ce
                    || lane.checkpoint.last_checkpoint_time.three_hour_bucket() != now.three_hour_bucket())
        };
        if rotate {
            hooks.spawn_checkpoint(self, lane_kind, now);
            let lane = self.lane_mut(lane_kind);
            lane.checkpoint.pending_thread_refs = lane.checkpoint.pending_thread_refs.saturating_add(1);
            lane.checkpoint.last_checkpoint_time = now;
        }
    }

    fn update_lane_snapshots<H: ExchangeHooks>(
        &mut self,
        lane_kind: LaneKind,
        height: Height,
        hooks: &mut H,
    ) -> Vec<SnapshotRecord> {
        let interval = self.lane(lane_kind).snapshot_interval();
        let mut records = Vec::new();
        if height % interval == 0 {
            let registry = hooks.build_registry_snapshot(self);
            self.lane_mut(lane_kind).registry_snapshots.insert(height, registry);
        }
        if height % interval == 0 {
            let state_hash = hooks.build_state_hash_snapshot(self, lane_kind);
            records.push(state_hash.clone());
            self.lane_mut(lane_kind).state_hash_snapshots.insert(height, state_hash);
        }
        self.prune_snapshot_trees(lane_kind);
        records
    }

    fn prune_snapshot_trees(&mut self, lane_kind: LaneKind) {
        let low = self.lane(lane_kind).retained_snapshot_low_watermark;
        if let Some(low) = low {
            let lane = self.lane_mut(lane_kind);
            lane.registry_snapshots.retain(|height, _| *height >= low);
            lane.state_hash_snapshots.retain(|height, _| *height >= low);
        }
    }

    fn merge_generated_effects(&mut self, effects: Vec<L1Effect>) {
        for effect in effects {
            self.generated_order_users.insert(effect.user);
            self.domain_state_mut(effect.domain).pending_effects.push(effect);
        }
    }

    fn freeze_state_changed(&self, lane_kind: LaneKind) -> bool {
        let lane = self.lane(lane_kind);
        lane.freeze.frozen || lane.freeze.scheduled_height == Some(self.height)
    }

    #[inline]
    fn lane(&self, lane: LaneKind) -> &LaneState {
        match lane {
            LaneKind::Primary => &self.primary,
            LaneKind::Secondary => &self.secondary,
        }
    }

    #[inline]
    fn lane_mut(&mut self, lane: LaneKind) -> &mut LaneState {
        match lane {
            LaneKind::Primary => &mut self.primary,
            LaneKind::Secondary => &mut self.secondary,
        }
    }

    #[inline]
    fn domain_state_mut(&mut self, domain: ExchangeDomain) -> &mut DomainEndBlockState {
        match domain {
            ExchangeDomain::Main => &mut self.main_domain,
            ExchangeDomain::Alt => &mut self.alt_domain,
        }
    }

    #[inline]
    fn replace_domain_state(&mut self, domain: ExchangeDomain, state: DomainEndBlockState) {
        match domain {
            ExchangeDomain::Main => self.main_domain = state,
            ExchangeDomain::Alt => self.alt_domain = state,
        }
    }
}

#[inline]
pub const fn seconds_between(start: PackedDateTime, end: PackedDateTime) -> u64 {
    let start_ms = start.unix_millis();
    let end_ms = end.unix_millis();
    if end_ms <= start_ms {
        0
    } else {
        (end_ms - start_ms) / MILLIS_PER_SECOND
    }
}
