//! Recovered from `/home/ubuntu/hl/code_Mainnet/l1/src/abci/engine.rs`.
//!
//! Seeds expanded: `0x2209D40`, `0x220BED0`, `0x33084A0`, `0x37E2960`,
//! `0x42E4600`, `0x42E5D40`, `0x42E73D0`, `0x42E7980`, `0x432F310`.
//!
//! IDA names/comments/types intended but not written in this wave because the
//! shared IDA worker was queue-full: `l1_abci_engine__execute_block`,
//! `l1_abci_engine__post_execute_handoff`,
//! `l1_abci_engine__retain_unmarked_or_recent_evm_state_checkpoints`,
//! `l1_abci_engine__tar_daily_evm_state_checkpoints`,
//! `l1_abci_engine__apply_primary_block`,
//! `l1_abci_engine__apply_secondary_block`,
//! `l1_abci_engine__checkpoint_primary_state`,
//! `l1_abci_engine__checkpoint_secondary_state`, and
//! `l1_abci_engine__cleanup_checkpoint_workdir`.
//!
//! The engine code is structured around two repeated block-application lanes.
//! The low-address lane (`0x2209D40`) uses the embedded state at offsets such as
//! `+0x8f2`, `+0xb90`, and `+0x3ae8`; the high-address pair (`0x42E4600` and
//! `0x42E5D40`) are sibling monomorphs with lane-local offsets. All three feed
//! a common begin-block -> per-action execution -> finalize -> checkpoint
//! handoff sequence.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const ACTION_OK_CODE: u16 = 0x0186;
const EXECUTION_PHASE_READY: u8 = 3;
const REPLAY_MODE: u64 = 2;
const PERIODIC_SNAPSHOT_EVERY_BLOCKS: u64 = 10_000;
const EXECUTION_HOUSEKEEPING_EVERY_BLOCKS: u64 = 100;
const CHECKPOINT_MARKER_FILE: &str = "MARKED_FOR_DELETION";
const FREEZE_SNAPSHOT_LABEL: &str = "freeze";
const PERIODIC_SNAPSHOT_LABEL: &str = "periodic";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockHash(pub [u8; 32]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockHeader {
    /// `block + 0x18`; asserted greater than `parent_round`.
    pub round: u64,
    /// `block + 0x20`; must match the engine's current parent round.
    pub parent_round: u64,
    /// `block + 0x28`/`+0x30`; compared against the engine's previous id/hash pair.
    pub parent_id: u64,
    pub parent_hash: BlockHash,
    /// `block + 0x38`/`+0x40`; copied into the begin-block hook.
    pub time: AbciTimestamp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockBatch {
    /// `block + 0x08`/`+0x10` is a Vec-like action list; each binary record is
    /// 40 bytes and points at a larger action payload.
    pub actions: Vec<BlockAction>,
    pub header: BlockHeader,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockAction {
    pub index: u64,
    pub metadata: ActionMetadata,
    pub payload: ActionPayload,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ActionMetadata {
    /// The executor copies 0x18 bytes from `action + 0x30` and a u32 from
    /// `action + 0x40` before dispatching.
    pub bytes: [u8; 24],
    pub tag: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionPayload {
    /// Recovered source keeps this opaque at the engine boundary; decoding and
    /// validation happen in the action dispatcher reconstructed elsewhere.
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbciTimestamp {
    /// First word written by the time helper; comparisons use it as a date/day
    /// bucket before checking seconds-of-day.
    pub day: u32,
    /// Second word written by the time helper; accepted range is below 90_000
    /// and bucketed into three-hour windows.
    pub seconds_of_day: u32,
}

impl AbciTimestamp {
    #[inline]
    pub fn three_hour_bucket(self) -> u8 {
        (self.seconds_of_day / 3_600 / 3) as u8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreezeState {
    Open,
    Scheduled { height: u64 },
}

impl FreezeState {
    #[inline]
    pub fn assert_not_frozen_at(self, current_height: u64) {
        if let FreezeState::Scheduled { height } = self {
            assert!(height >= current_height, "freeze height regressed below current height");
            assert!(height != current_height, "assertion failed: !self.state.is_frozen()");
        }
    }

    #[inline]
    pub fn snapshot_label(self, current_height: u64) -> Option<&'static str> {
        match self {
            FreezeState::Scheduled { height } if height < current_height => {
                panic!("freeze height regressed below current height")
            }
            FreezeState::Scheduled { height } if height == current_height => Some(FREEZE_SNAPSHOT_LABEL),
            _ if periodic_snapshot_due(current_height) => Some(PERIODIC_SNAPSHOT_LABEL),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineMode {
    Live,
    CatchingUp,
    ReplayOnly,
    Other(u64),
}

impl EngineMode {
    #[inline]
    fn from_raw(raw: u64) -> Self {
        match raw {
            0 => Self::Live,
            1 => Self::CatchingUp,
            REPLAY_MODE => Self::ReplayOnly,
            other => Self::Other(other),
        }
    }

    #[inline]
    fn raw(self) -> u64 {
        match self {
            Self::Live => 0,
            Self::CatchingUp => 1,
            Self::ReplayOnly => REPLAY_MODE,
            Self::Other(other) => other,
        }
    }

    #[inline]
    fn is_replay_only(self) -> bool {
        self.raw() == REPLAY_MODE
    }
}

#[derive(Clone, Debug)]
pub struct AbciEngine {
    pub previous_parent_id: u64,
    pub previous_parent_hash: BlockHash,
    /// Offset `+0x28` in the recovered low lane.
    pub height: u64,
    /// Offset `+0x30` in the recovered low lane.
    pub parent_round: u64,
    /// Offset `+0x8f2` in the recovered low lane.
    pub phase: u8,
    /// Offset `+0xb90`/`+0xb98` in the recovered low lane.
    pub freeze_state: FreezeState,
    /// Offset `+0x3ae8` in the recovered low lane; value `2` suppresses the
    /// post-execution handoff.
    pub mode: EngineMode,
    pub min_open_height: u64,
    pub prunable_user_state: BTreeMap<ActionMetadata, u64>,
    pub primary_lane: ExecutionLane,
    pub secondary_lane: ExecutionLane,
    pub app_hash_handoff: BTreeMap<u64, HandoffRecord>,
    pub checkpoint_queue: VecDeque<u64>,
    pub last_housekeeping_time: AbciTimestamp,
    pub housekeeping_flag: u8,
    pub rotating_context: Arc<RotatingContext>,
}

#[derive(Clone, Debug)]
pub struct ExecutionLane {
    pub name: &'static str,
    pub phase: u8,
    pub freeze_state: FreezeState,
    pub mode: EngineMode,
    pub expected_counter: u64,
    pub last_snapshot_time: AbciTimestamp,
    pub housekeeping_flag: u8,
    pub rotating_context: Arc<RotatingContext>,
    pub app_hash_handoff: BTreeMap<u64, HandoffRecord>,
}

#[derive(Clone, Debug, Default)]
pub struct RotatingContext {
    pub id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteBlockReturn {
    pub candidate_summary: CandidateSummary,
    pub execution_summary: ExecutionSummary,
    /// The binary writes byte `out + 0x78` when the freeze option/tag or height
    /// differs from the entry snapshot.
    pub freeze_state_changed: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CandidateSummary {
    pub candidates_seen: usize,
    pub actions_seen: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExecutionSummary {
    pub applied: usize,
    pub non_ok_statuses: Vec<ActionStatus>,
    pub outputs: Vec<ActionOutput>,
    pub handoff_record: Option<HandoffRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionStatus {
    pub code: u16,
    pub detail: Vec<u8>,
}

impl ActionStatus {
    #[inline]
    pub fn is_ok_code(&self) -> bool {
        self.code == ACTION_OK_CODE
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedActionMetadata {
    pub index: u64,
    pub metadata: ActionMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionOutput {
    pub action_index: u64,
    pub key: ActionMetadata,
    pub records: Vec<OutputRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputRecord {
    pub key: ActionMetadata,
    pub value: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffRecord {
    pub height: u64,
    pub app_hash: BlockHash,
    pub snapshot_label: Option<&'static str>,
}

pub trait EngineHooks {
    fn begin_block(&mut self, engine: &mut AbciEngine, header: &BlockHeader, replay_only: bool);
    fn build_candidates(&mut self, engine: &AbciEngine) -> CandidateSummary;
    fn execute_action(
        &mut self,
        engine: &mut AbciEngine,
        lane: LaneId,
        metadata: &ActionMetadata,
        payload: &ActionPayload,
    ) -> ActionStatus;
    fn finalize_actions(
        &mut self,
        engine: &mut AbciEngine,
        lane: LaneId,
        indexed_metadata: &[IndexedActionMetadata],
        action_refs: &[usize],
    ) -> ExecutionSummary;
    fn current_time(&mut self) -> AbciTimestamp;
    fn emit_state_snapshot(
        &mut self,
        engine: &AbciEngine,
        lane: LaneId,
        label: &'static str,
    ) -> HandoffRecord;
    fn log_applied_block(&mut self, engine: &AbciEngine, lane: LaneId, record: &HandoffRecord);
    fn update_app_hash_handoff(
        &mut self,
        queue: &mut BTreeMap<u64, HandoffRecord>,
        height: u64,
        record: HandoffRecord,
    );
    fn rotate_housekeeping(&mut self, ctx: Arc<RotatingContext>, flag: u8);
    fn cleanup_status(&mut self, status: ActionStatus);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaneId {
    Low,
    Primary,
    Secondary,
}

/// Reconstructs seed `0x2209D40`.
pub fn execute_block<H: EngineHooks>(
    engine: &mut AbciEngine,
    block: &BlockBatch,
    hooks: &mut H,
) -> ExecuteBlockReturn {
    let entry_freeze_state = engine.freeze_state;
    validate_low_lane_header(engine, &block.header);

    let replay_only = engine.mode.is_replay_only();
    hooks.begin_block(engine, &block.header, replay_only);
    let candidate_summary = hooks.build_candidates(engine);

    let mut action_refs = Vec::with_capacity(block.actions.len());
    let mut indexed_metadata = Vec::with_capacity(block.actions.len());

    for action in &block.actions {
        action_refs.push(action.index as usize);
        indexed_metadata.push(IndexedActionMetadata {
            index: action.index,
            metadata: action.metadata.clone(),
        });

        let status = hooks.execute_action(engine, LaneId::Low, &action.metadata, &action.payload);
        if !status.is_ok_code() {
            hooks.cleanup_status(status.clone());
        }
    }

    let mut execution_summary = hooks.finalize_actions(
        engine,
        LaneId::Low,
        &indexed_metadata,
        &action_refs,
    );

    prune_completed_action_state(engine, &execution_summary.outputs);
    update_execution_handoff_state(engine, &execution_summary);

    if execution_housekeeping_due(engine.height) {
        // The low-lane body runs this periodic side-effect before post-execute;
        // its exact callee is outside this file, but it consumes the current
        // height and the finalized state snapshot.
        engine.checkpoint_queue.push_back(engine.height);
    }

    if !engine.mode.is_replay_only() {
        post_execute_handoff(engine, hooks);
        execution_summary.handoff_record = engine.app_hash_handoff.get(&engine.height).cloned();
    }

    ExecuteBlockReturn {
        candidate_summary: CandidateSummary {
            candidates_seen: candidate_summary.candidates_seen,
            actions_seen: block.actions.len(),
        },
        execution_summary,
        freeze_state_changed: engine.freeze_state != entry_freeze_state,
    }
}

/// Shared structure for seeds `0x42E4600` and `0x42E5D40`.
pub fn apply_block_on_lane<H: EngineHooks>(
    engine: &mut AbciEngine,
    lane_id: LaneId,
    block: &BlockBatch,
    hooks: &mut H,
) -> ExecuteBlockReturn {
    let entry_freeze_state = lane(engine, lane_id).freeze_state;
    validate_lane_header(engine, lane_id, &block.header);

    let replay_only = lane(engine, lane_id).mode.is_replay_only();
    hooks.begin_block(engine, &block.header, replay_only);

    let mut action_refs = Vec::with_capacity(block.actions.len());
    let mut indexed_metadata = Vec::with_capacity(block.actions.len());
    for action in &block.actions {
        action_refs.push(action.index as usize);
        indexed_metadata.push(IndexedActionMetadata {
            index: action.index,
            metadata: action.metadata.clone(),
        });
        let status = hooks.execute_action(engine, lane_id, &action.metadata, &action.payload);
        if !status.is_ok_code() {
            hooks.cleanup_status(status.clone());
        }
    }

    let mut execution_summary = hooks.finalize_actions(engine, lane_id, &indexed_metadata, &action_refs);

    if lane(engine, lane_id).mode.is_replay_only() {
        let height = engine.height;
        let lane = lane_mut(engine, lane_id);
        lane.expected_counter = lane.expected_counter.wrapping_add(1);
        assert_eq!(lane.expected_counter, height, "replay lane counter must match height");
    } else {
        match lane_id {
            LaneId::Primary => checkpoint_primary_state(engine, hooks),
            LaneId::Secondary => checkpoint_secondary_state(engine, hooks),
            LaneId::Low => post_execute_handoff(engine, hooks),
        }
        execution_summary.handoff_record = lane(engine, lane_id).app_hash_handoff.get(&engine.height).cloned();
    }

    ExecuteBlockReturn {
        candidate_summary: CandidateSummary {
            candidates_seen: indexed_metadata.len(),
            actions_seen: block.actions.len(),
        },
        execution_summary,
        freeze_state_changed: lane(engine, lane_id).freeze_state != entry_freeze_state,
    }
}

/// Reconstructs seed `0x42E4600`.
#[inline]
pub fn apply_primary_block<H: EngineHooks>(
    engine: &mut AbciEngine,
    block: &BlockBatch,
    hooks: &mut H,
) -> ExecuteBlockReturn {
    apply_block_on_lane(engine, LaneId::Primary, block, hooks)
}

/// Reconstructs seed `0x42E5D40`.
#[inline]
pub fn apply_secondary_block<H: EngineHooks>(
    engine: &mut AbciEngine,
    block: &BlockBatch,
    hooks: &mut H,
) -> ExecuteBlockReturn {
    apply_block_on_lane(engine, LaneId::Secondary, block, hooks)
}

/// Reconstructs seed `0x220BED0`.
pub fn post_execute_handoff<H: EngineHooks>(engine: &mut AbciEngine, hooks: &mut H) {
    if let Some(label) = engine.freeze_state.snapshot_label(engine.height) {
        let record = hooks.emit_state_snapshot(engine, LaneId::Low, label);
        hooks.log_applied_block(engine, LaneId::Low, &record);
        if !engine.mode.is_replay_only() {
            let height = engine.height;
            hooks.update_app_hash_handoff(&mut engine.app_hash_handoff, height, record);
        }
    }

    let now = hooks.current_time();
    if time_rotation_due(engine.last_housekeeping_time, now) {
        hooks.rotate_housekeeping(Arc::clone(&engine.rotating_context), engine.housekeeping_flag);
        engine.last_housekeeping_time = now;
    }
}

/// Reconstructs seed `0x42E73D0`.
pub fn checkpoint_primary_state<H: EngineHooks>(engine: &mut AbciEngine, hooks: &mut H) {
    checkpoint_lane_state(engine, LaneId::Primary, hooks);
}

/// Reconstructs seed `0x42E7980`.
pub fn checkpoint_secondary_state<H: EngineHooks>(engine: &mut AbciEngine, hooks: &mut H) {
    checkpoint_lane_state(engine, LaneId::Secondary, hooks);
}

fn checkpoint_lane_state<H: EngineHooks>(engine: &mut AbciEngine, lane_id: LaneId, hooks: &mut H) {
    let freeze_state = lane(engine, lane_id).freeze_state;
    if let Some(label) = freeze_state.snapshot_label(engine.height) {
        let record = hooks.emit_state_snapshot(engine, lane_id, label);
        hooks.log_applied_block(engine, lane_id, &record);
        if !lane(engine, lane_id).mode.is_replay_only() {
            let height = engine.height;
            let lane = lane_mut(engine, lane_id);
            hooks.update_app_hash_handoff(&mut lane.app_hash_handoff, height, record);
        }
    }

    let now = hooks.current_time();
    let lane = lane_mut(engine, lane_id);
    if time_rotation_due(lane.last_snapshot_time, now) {
        hooks.rotate_housekeeping(Arc::clone(&lane.rotating_context), lane.housekeeping_flag);
        lane.last_snapshot_time = now;
    }
}

fn validate_low_lane_header(engine: &AbciEngine, header: &BlockHeader) {
    engine.freeze_state.assert_not_frozen_at(engine.height);
    assert!(header.round > header.parent_round, "assertion failed: round > parent_round");
    assert_eq!(header.parent_round, engine.parent_round, "parent round mismatch");
    assert_eq!(header.parent_id, engine.previous_parent_id, "parent id mismatch");
    assert_eq!(header.parent_hash, engine.previous_parent_hash, "parent hash mismatch");
    assert_eq!(engine.phase, EXECUTION_PHASE_READY, "ABCI engine phase must be ready to execute");
}

fn validate_lane_header(engine: &AbciEngine, lane_id: LaneId, header: &BlockHeader) {
    let lane = lane(engine, lane_id);
    lane.freeze_state.assert_not_frozen_at(engine.height);
    assert!(header.round > header.parent_round, "assertion failed: round > parent_round");
    assert_eq!(header.parent_round, engine.parent_round, "parent round mismatch");
    assert_eq!(header.parent_id, engine.previous_parent_id, "parent id mismatch");
    assert_eq!(header.parent_hash, engine.previous_parent_hash, "parent hash mismatch");
    assert_eq!(lane.phase, EXECUTION_PHASE_READY, "ABCI lane phase must be ready to execute");
}

fn prune_completed_action_state(engine: &mut AbciEngine, outputs: &[ActionOutput]) {
    let mut empty_keys = Vec::new();
    for output in outputs {
        if let Some(count) = engine.prunable_user_state.get_mut(&output.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                empty_keys.push(output.key.clone());
            }
        }
    }

    for key in empty_keys {
        engine.prunable_user_state.remove(&key);
    }
}

fn update_execution_handoff_state(engine: &mut AbciEngine, summary: &ExecutionSummary) {
    if let Some(min_height) = summary.outputs.iter().map(|output| output.action_index).min() {
        if engine.mode.raw() != 0 && min_height < engine.min_open_height {
            engine.mode = EngineMode::CatchingUp;
        }
        engine.min_open_height = engine.min_open_height.min(min_height.saturating_add(1));
    }

    if !summary.outputs.is_empty() {
        engine.checkpoint_queue.push_back(engine.height.saturating_add(1));
    }
}

#[inline]
fn lane(engine: &AbciEngine, lane_id: LaneId) -> &ExecutionLane {
    match lane_id {
        LaneId::Low => &engine.secondary_lane,
        LaneId::Primary => &engine.primary_lane,
        LaneId::Secondary => &engine.secondary_lane,
    }
}

#[inline]
fn lane_mut(engine: &mut AbciEngine, lane_id: LaneId) -> &mut ExecutionLane {
    match lane_id {
        LaneId::Low => &mut engine.secondary_lane,
        LaneId::Primary => &mut engine.primary_lane,
        LaneId::Secondary => &mut engine.secondary_lane,
    }
}

#[inline]
fn periodic_snapshot_due(height: u64) -> bool {
    height != 0 && height % PERIODIC_SNAPSHOT_EVERY_BLOCKS == 0
}

#[inline]
fn execution_housekeeping_due(height: u64) -> bool {
    height != 0 && height % EXECUTION_HOUSEKEEPING_EVERY_BLOCKS == 0
}

#[inline]
fn time_rotation_due(previous: AbciTimestamp, now: AbciTimestamp) -> bool {
    previous.day != now.day || previous.three_hour_bucket() != now.three_hour_bucket()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointRecord {
    /// 24-byte Rust `PathBuf`/`String` allocation in the binary, followed by a
    /// u64 height/id at offset `+0x18`.
    pub dir: PathBuf,
    pub height: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointRetentionBounds {
    pub lower_bound: u64,
    pub upper_bound_exclusive: u64,
    pub max_height: u64,
}

/// Reconstructs seed `0x33084A0`.
pub fn retain_unmarked_or_recent_evm_state_checkpoints<F: CheckpointFs>(
    records: Vec<CheckpointRecord>,
    bounds: CheckpointRetentionBounds,
    fs: &F,
) -> Vec<CheckpointRecord> {
    let mut retained = Vec::with_capacity(records.len());
    for record in records {
        let marker_path = record.dir.join(CHECKPOINT_MARKER_FILE);
        if fs.is_regular_file(&marker_path) {
            retained.push(record);
            continue;
        }

        if record.height < bounds.lower_bound {
            fs.warn_straggler_checkpoint(&record.dir, record.height);
        }

        if record.height >= bounds.lower_bound
            && record.height < bounds.upper_bound_exclusive
            && record.height <= bounds.max_height
        {
            retained.push(record);
        }
    }
    retained
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckpointArchiveError {
    MissingPeriodicAbciStateStatusBaseDir(PathBuf),
    ListDir(PathBuf),
    CreateTar(PathBuf),
    WriteTar(PathBuf),
    RemoveWorkdir(PathBuf),
}

pub trait CheckpointFs {
    fn periodic_abci_state_status_base_dir(&self, period: u32) -> PathBuf;
    fn hourly_evm_state_dir(&self, period: u32) -> PathBuf;
    fn daily_archive_path(&self, period: u32) -> PathBuf;
    fn is_dir(&self, path: &Path) -> bool;
    fn is_regular_file(&self, path: &Path) -> bool;
    fn list_checkpoint_dirs(&self, path: &Path) -> Result<Vec<CheckpointRecord>, CheckpointArchiveError>;
    fn create_tar(&self, archive: &Path, records: &[CheckpointRecord]) -> Result<(), CheckpointArchiveError>;
    fn warn_straggler_checkpoint(&self, dir: &Path, height: u64);
    fn remove_dir_all(&self, path: &Path) -> Result<(), CheckpointArchiveError>;
    fn create_dir_all(&self, path: &Path) -> Result<(), CheckpointArchiveError>;
    fn drain_dir(&self, path: &Path) -> Result<Vec<PathBuf>, CheckpointArchiveError>;
}

/// Reconstructs seed `0x37E2960`.
pub fn tar_daily_evm_state_checkpoints<F: CheckpointFs>(
    fs: &F,
    period: u32,
    bounds: CheckpointRetentionBounds,
) -> Result<Vec<CheckpointRecord>, CheckpointArchiveError> {
    let status_base_dir = fs.periodic_abci_state_status_base_dir(period);
    if !fs.is_dir(&status_base_dir) {
        return Err(CheckpointArchiveError::MissingPeriodicAbciStateStatusBaseDir(status_base_dir));
    }

    let hourly_dir = fs.hourly_evm_state_dir(period);
    let mut records = fs.list_checkpoint_dirs(&hourly_dir)?;
    records.sort_unstable_by_key(|record| record.height);
    records = retain_unmarked_or_recent_evm_state_checkpoints(records, bounds, fs);

    let archive = fs.daily_archive_path(period);
    fs.create_tar(&archive, &records)?;
    Ok(records)
}

/// Reconstructs seed `0x432F310`.
pub fn cleanup_checkpoint_workdir<F: CheckpointFs>(
    fs: &F,
    workdir: &Path,
    force_recreate: bool,
) -> Result<(), CheckpointArchiveError> {
    if force_recreate {
        if fs.is_dir(workdir) {
            for child in fs.drain_dir(workdir)? {
                fs.remove_dir_all(&child)?;
            }
        }
        fs.remove_dir_all(workdir)?;
        fs.create_dir_all(workdir)?;
    } else if !fs.is_dir(workdir) {
        fs.create_dir_all(workdir)?;
    }
    Ok(())
}
