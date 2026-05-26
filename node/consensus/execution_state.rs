//! Reconstructed from `/home/ubuntu/hl/code_Mainnet/node/src/consensus/execution_state.rs`.
//!
//! Seed EAs: `0x28F6960`, `0x4548CC0`.
//!
//! The two seeds are the same execution-state handoff/update poll shape for two
//! state layouts.  `0x28F6960` is the compact/earlier layout and `0x4548CC0` is
//! the full layout with three copied 0x810-byte summary slabs.  Both functions
//! carry the execution-state source-path panic location through the trailing
//! timing/metric call (`0x28F7113`, `0x454A5E8`), while an inlined
//! `base/src/raw_mdg.rs` unwrap location is visible at `0x28F6A1F` and
//! `0x4548DA4`.
//!
//! IDA write status: pending.  The shared IDA server returned
//! `Server is busy (request queue full)` for the attempted renames:
//! - `node_consensus_execution_state__poll_compact_update_and_handoff` at `0x28F6960`.
//! - `node_consensus_execution_state__poll_full_update_and_handoff` at `0x4548CC0`.
//! Pending comments:
//! - `0x28F6960`: `/home/ubuntu/hl/code_Mainnet/node/src/consensus/execution_state.rs :: poll_compact_update_and_handoff — compact execution-state cursor refresh, computed-firewall-IP update, summary projection, and handoff publish.`
//! - `0x4548CC0`: `/home/ubuntu/hl/code_Mainnet/node/src/consensus/execution_state.rs :: poll_full_update_and_handoff — full execution-state cursor refresh, computed-firewall-IP update, three summary-slab copies, and watch/channel handoff publish.`
//! Pending type names: `hl_node_consensus_ExecutionStatePoller`,
//! `hl_node_consensus_ExecutionStateSummary`,
//! `hl_node_consensus_ExecutionStateHandoff`,
//! `hl_node_consensus_ExecutionStateCursor`.
//!
//! String/metric anchors used by both seeds:
//! - `firewall_ips_maybe_update` (`0x3F6A6F` in `0x28F6960`, `0x6F6017` in `0x4548CC0`).
//! - `check_computed_ips` (`0x3F6A88`, `0x6F6030`).
//! - `update_computed_ips` (`0x3F6A9A`, `0x6F6042`).
//! - `update` (`0x3F6AAD`, `0x6F6055`).
//! - `replica_cmds` is adjacent in rodata before the seed-2 strings.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::{Excluded, Unbounded};
use std::time::{Duration, Instant};

pub type Height = u64;
pub type Round = u64;
pub type ValidatorIndex = u32;
pub type L1Hash = [u8; 32];
pub type AppHash = [u8; 32];

pub const FIREWALL_IPS_MAYBE_UPDATE: &str = "firewall_ips_maybe_update";
pub const CHECK_COMPUTED_IPS: &str = "check_computed_ips";
pub const UPDATE_COMPUTED_IPS: &str = "update_computed_ips";
pub const UPDATE_SUMMARY: &str = "update";

/// Five-byte packed IP record copied by both seeds.
///
/// IDA anchors:
/// - `0x28F6F20..0x28F6FCC` copies each source item as four bytes plus one tag byte.
/// - `0x454A300..0x454A3AC` is the same loop in the full-layout seed.
///
/// [INFERENCE] The tag distinguishes IPv4/IPv6-family variants.  Only the compact
/// five-byte projection is consumed by these handoff functions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct CompactNodeIp {
    pub octets_or_index: [u8; 4],
    pub family_tag: u8,
}

impl CompactNodeIp {
    pub fn from_raw_words(word: u32, family_tag: u8) -> Self {
        Self { octets_or_index: word.to_le_bytes(), family_tag }
    }
}

/// Digest/update marker carried beside the computed-IP update path.
///
/// IDA anchors: discriminant byte at poller `+0x260`; payload copied from
/// `+0x261..+0x274` in both seeds.  The payload comes from inlined
/// `base/src/raw_mdg.rs`, so the exact field names are left inferred here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawMdgUpdateMarker {
    pub words: [u64; 2],
    pub tail: u32,
}

/// Handoff cursor owned by the poller between calls.
///
/// IDA anchors:
/// - `0x28F6DFA..0x28F6E83` updates the two last-seen keys after selecting the
///   maximum key from two 32-byte candidate arrays.
/// - `0x454A080..0x454A11D` performs the same update in the full seed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExecutionStateCursor {
    pub last_client_block_key: u64,
    pub last_validator_delta_key: u64,
    pub raw_mdg_marker: Option<RawMdgUpdateMarker>,
}

impl ExecutionStateCursor {
    pub fn observe_client_block_key(&mut self, key: u64) {
        if key > self.last_client_block_key {
            self.last_client_block_key = key;
        }
    }

    pub fn observe_validator_delta_key(&mut self, key: u64) {
        if key > self.last_validator_delta_key {
            self.last_validator_delta_key = key;
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimedValue<T> {
    pub key: u64,
    pub value: T,
}

/// State fragment returned by the B-tree/RB-tree scans in the full seed.
///
/// The binary stores each emitted item in a 32-byte stack/vector record: key at
/// `+0`, optional payload discriminant/pointer/length in the remaining words.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimedOptional<T> {
    pub key: u64,
    pub value: Option<T>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorDelta {
    pub validator: ValidatorIndex,
    pub stake: u64,
    pub jailed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientBlockSummary {
    pub round: Round,
    pub block_hash: AppHash,
    pub app_hash: Option<AppHash>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionHashes {
    pub l1_hash: L1Hash,
    pub app_hash: Option<AppHash>,
    pub state_hash: Option<AppHash>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SummarySlab {
    /// [INFERENCE] The seed copies three 0x810-byte slabs from the full state at
    /// `+0x1738`, `+0x2040`, and `+0x2948` before building the handoff.
    pub bytes: Box<[u8; 0x810]>,
}

impl SummarySlab {
    pub fn from_array(bytes: [u8; 0x810]) -> Self {
        Self { bytes: Box::new(bytes) }
    }
}

/// Execution-state summary sent from the ABCI/execution side to consensus.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionStateSummary {
    pub height: Height,
    pub round: Round,
    pub hashes: ExecutionHashes,
    pub active_node_ips: Vec<CompactNodeIp>,
    pub computed_firewall_ips: BTreeSet<CompactNodeIp>,
    pub client_blocks_after_cursor: Vec<TimedOptional<ClientBlockSummary>>,
    pub validator_deltas_after_cursor: Vec<TimedOptional<ValidatorDelta>>,
    pub pending_replica_cmds: usize,
    pub full_slabs: Option<[SummarySlab; 3]>,
}

impl ExecutionStateSummary {
    pub fn is_empty_delta(&self) -> bool {
        self.active_node_ips.is_empty()
            && self.computed_firewall_ips.is_empty()
            && self.client_blocks_after_cursor.is_empty()
            && self.validator_deltas_after_cursor.is_empty()
            && self.pending_replica_cmds == 0
    }

    pub fn max_client_block_key(&self) -> Option<u64> {
        self.client_blocks_after_cursor.iter().map(|entry| entry.key).max()
    }

    pub fn max_validator_delta_key(&self) -> Option<u64> {
        self.validator_deltas_after_cursor.iter().map(|entry| entry.key).max()
    }
}

/// Handoff object queued to the consensus side.
///
/// IDA anchors:
/// - `0x28F7026..0x28F708D` copies a 0x150-byte stack object, clones an Arc, and
///   sends it through a channel-like cell.
/// - `0x454A404..0x454A54D` copies a 0x148-byte object and pushes it through a
///   watch/notify path guarded by atomics at `+0x1C0` and `+0x110`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionStateHandoff {
    pub cursor: ExecutionStateCursor,
    pub summary: ExecutionStateSummary,
    pub updated_at: Instant,
}

impl ExecutionStateHandoff {
    pub fn apply_cursor_to(&self, cursor: &mut ExecutionStateCursor) {
        if let Some(key) = self.summary.max_client_block_key() {
            cursor.observe_client_block_key(key);
        }
        if let Some(key) = self.summary.max_validator_delta_key() {
            cursor.observe_validator_delta_key(key);
        }
        cursor.raw_mdg_marker = self.cursor.raw_mdg_marker;
    }
}

#[derive(Clone, Debug)]
pub struct ExecutionStateRead<'a> {
    pub height: Height,
    pub round: Round,
    pub hashes: ExecutionHashes,
    pub node_ips: &'a [CompactNodeIp],
    pub computed_firewall_ips: &'a BTreeSet<CompactNodeIp>,
    pub client_blocks_by_key: &'a BTreeMap<u64, Option<ClientBlockSummary>>,
    pub validator_deltas_by_key: &'a BTreeMap<u64, Option<ValidatorDelta>>,
    pub pending_replica_cmds: usize,
    pub full_slabs: Option<&'a [SummarySlab; 3]>,
}

impl<'a> ExecutionStateRead<'a> {
    /// Recovered read path for the compact seed `0x28F6960`.
    ///
    /// The compact layout has the same computed-IP update path and the final
    /// active-node-IP projection, but does not copy the three 0x810 slabs.
    pub fn read_compact(&self, cursor: &ExecutionStateCursor) -> ExecutionStateSummary {
        self.read_common(cursor, None)
    }

    /// Recovered read path for the full seed `0x4548CC0`.
    ///
    /// IDA anchors:
    /// - `0x4549303..0x45496AC` scans one ordered tree using the cursor loaded
    ///   from poller `+0x2D0`.
    /// - `0x45496CC..0x4549AC6` scans the second tree using poller `+0x2D8`.
    /// - `0x4549F08..0x4549F45` copies the three 0x810-byte summary slabs.
    pub fn read_full(&self, cursor: &ExecutionStateCursor) -> ExecutionStateSummary {
        self.read_common(cursor, self.full_slabs.cloned())
    }

    fn read_common(
        &self,
        cursor: &ExecutionStateCursor,
        full_slabs: Option<[SummarySlab; 3]>,
    ) -> ExecutionStateSummary {
        let client_blocks_after_cursor = collect_after(
            self.client_blocks_by_key,
            cursor.last_client_block_key,
        );
        let validator_deltas_after_cursor = collect_after(
            self.validator_deltas_by_key,
            cursor.last_validator_delta_key,
        );

        ExecutionStateSummary {
            height: self.height,
            round: self.round,
            hashes: self.hashes.clone(),
            active_node_ips: self.node_ips.to_vec(),
            computed_firewall_ips: self.computed_firewall_ips.clone(),
            client_blocks_after_cursor,
            validator_deltas_after_cursor,
            pending_replica_cmds: self.pending_replica_cmds,
            full_slabs,
        }
    }
}

fn collect_after<T: Clone>(
    map: &BTreeMap<u64, Option<T>>,
    last_seen_key: u64,
) -> Vec<TimedOptional<T>> {
    map.range((Excluded(last_seen_key), Unbounded))
        .map(|(&key, value)| TimedOptional { key, value: value.clone() })
        .collect()
}

#[derive(Clone, Debug)]
pub struct ExecutionStatePoller {
    /// IDA: byte at `+0x260`; zero skips the raw-mdg refresh branch.
    pub raw_mdg_marker: Option<RawMdgUpdateMarker>,
    /// IDA: double at `+0x278`; compared with elapsed time before refreshing
    /// computed firewall IPs.
    pub computed_ip_refresh_period: Duration,
    /// IDA: raw instant at `+0x280`; refreshed after `firewall_ips_maybe_update`.
    pub last_computed_ip_check: Option<Instant>,
    /// IDA: `+0x2D0` in both seeds.
    pub cursor: ExecutionStateCursor,
}

impl ExecutionStatePoller {
    pub fn new(computed_ip_refresh_period: Duration) -> Self {
        Self {
            raw_mdg_marker: None,
            computed_ip_refresh_period,
            last_computed_ip_check: None,
            cursor: ExecutionStateCursor::default(),
        }
    }

    /// Models `0x28F6960`.
    pub fn poll_compact_update_and_handoff(
        &mut self,
        now: Instant,
        state: &ExecutionStateRead<'_>,
        sink: &mut impl ExecutionStateSink,
        metrics: &mut impl ExecutionStateMetrics,
    ) {
        self.maybe_update_computed_ips(now, state, metrics);
        let summary = state.read_compact(&self.cursor);
        self.finish_update(now, summary, sink, metrics);
    }

    /// Models `0x4548CC0`.
    pub fn poll_full_update_and_handoff(
        &mut self,
        now: Instant,
        state: &ExecutionStateRead<'_>,
        sink: &mut impl ExecutionStateSink,
        metrics: &mut impl ExecutionStateMetrics,
    ) {
        self.maybe_update_computed_ips(now, state, metrics);
        let summary = state.read_full(&self.cursor);
        self.finish_update(now, summary, sink, metrics);
    }

    fn maybe_update_computed_ips(
        &mut self,
        now: Instant,
        state: &ExecutionStateRead<'_>,
        metrics: &mut impl ExecutionStateMetrics,
    ) {
        metrics.begin(FIREWALL_IPS_MAYBE_UPDATE);

        let due = match self.last_computed_ip_check {
            None => true,
            Some(last) => now.duration_since(last) > self.computed_ip_refresh_period,
        };
        self.last_computed_ip_check = Some(now);

        if !due {
            metrics.end(FIREWALL_IPS_MAYBE_UPDATE, 0);
            return;
        }

        metrics.begin(CHECK_COMPUTED_IPS);
        let raw_changed = self.raw_mdg_marker.is_some();
        let has_computed_ips = !state.computed_firewall_ips.is_empty();
        metrics.end(CHECK_COMPUTED_IPS, usize::from(has_computed_ips));

        if raw_changed || has_computed_ips {
            metrics.begin(UPDATE_COMPUTED_IPS);
            // The binary drops three optional temporary update products when no
            // update is needed (`0x28F6D0F..0x28F6D4A`) and otherwise forwards the
            // updated projection.  The high-level state reader already exposes
            // the post-update computed set, so this method records the observed
            // branch and leaves ownership with the caller's state object.
            metrics.end(UPDATE_COMPUTED_IPS, state.computed_firewall_ips.len());
        }

        metrics.end(FIREWALL_IPS_MAYBE_UPDATE, usize::from(raw_changed));
    }

    fn finish_update(
        &mut self,
        now: Instant,
        summary: ExecutionStateSummary,
        sink: &mut impl ExecutionStateSink,
        metrics: &mut impl ExecutionStateMetrics,
    ) {
        if let Some(key) = summary.max_client_block_key() {
            self.cursor.observe_client_block_key(key);
        }
        if let Some(key) = summary.max_validator_delta_key() {
            self.cursor.observe_validator_delta_key(key);
        }
        self.cursor.raw_mdg_marker = self.raw_mdg_marker;

        metrics.begin(UPDATE_SUMMARY);
        metrics.end(UPDATE_SUMMARY, summary.active_node_ips.len());

        let handoff = ExecutionStateHandoff {
            cursor: self.cursor.clone(),
            summary,
            updated_at: now,
        };
        sink.publish_execution_state(handoff);
    }
}

pub trait ExecutionStateSink {
    /// Publishes the 0x150/0x148-byte handoff object reconstructed at the seed
    /// epilogues.  The concrete binary sink is a watch/channel-like object with
    /// atomic waiter notification.
    fn publish_execution_state(&mut self, handoff: ExecutionStateHandoff);
}

pub trait ExecutionStateMetrics {
    fn begin(&mut self, name: &'static str);
    fn end(&mut self, name: &'static str, logical_count: usize);
}

#[derive(Default)]
pub struct NoopExecutionStateMetrics;

impl ExecutionStateMetrics for NoopExecutionStateMetrics {
    fn begin(&mut self, _name: &'static str) {}
    fn end(&mut self, _name: &'static str, _logical_count: usize) {}
}
