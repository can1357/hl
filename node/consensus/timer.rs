//! Reconstructed Rust for `/home/ubuntu/hl/code_Mainnet/node/src/consensus/timer.rs`.
//!
//! Confidence: medium for the timer/backoff state machine and constants; low for
//! field names inside the large consensus future frames because IDA was busy and
//! the reconstruction is grounded in local disassembly, rodata, and adjacent
//! recovered consensus files rather than Hex-Rays pseudocode.
//!
//! Seed EAs: `0x2043F70`, `0x22BF220`, `0x44A8420`, `0x44ADFA0`, `0x44B6670`.
//!
//! IDA anchors used in this source:
//! - `0x2043F70`: async timer/trace poll. It samples `Instant::now`, records the
//!   first elapsed interval, converts seconds+nanos through `1_000_000_000`, and
//!   rearms `tokio::time::Sleep` handles. The same function owns the rodata string
//!   `WARN >>> .. @@ writing .. data to ..` immediately before this source path.
//! - `0x22BF220`: second monomorph of the same poll/setup shape. It copies a
//!   `0xb08`-byte future payload, initializes the same `60.0`, `10.0`, `0.1`, and
//!   `30.0` floating-point timer constants, and arms two sleep handles.
//! - `0x44A8420`: constructor/bootstrap path. It formats `vote` and `snapshots`,
//!   creates bounded queues with capacity `0x186a0`, records `Instant::now() %
//!   10_000`, installs initial `60.0`/`30.0` timers, and builds round/request
//!   throttles used by consensus state.
//! - `0x44ADFA0`: large state transition/poll path. It dispatches state variants,
//!   increments a retry counter at `state+0x9b0`, calls the ask-peer helper once
//!   the counter reaches `2`, arms a one-second mutex-protected sleep at
//!   `state+0x8c0..0x8d8`, updates timeout stats, and prunes request/block queues.
//! - `0x44B6670`: round-window helper. It compares the incoming round against
//!   `state+0x918`, stores `round + 1` with saturating `usize::MAX` behavior,
//!   replaces round request maps under `state+0x8a0`/`state+0x930`, rearms the
//!   `state+0x8c0` and `state+0x8e0` timers, clears pending peer state at
//!   `state+0x9b8`, and returns whether the round advanced the scheduling window.
//!
//! IDA updates attempted but blocked by the shared queue:
//! - `0x44B6670` -> `node_consensus_timer__advance_round_window` plus entry
//!   comment describing the round-window/rearm behavior.
//! - Pending: rename/comment `0x2043F70` as `node_consensus_timer__poll_trace_writer`.
//! - Pending: rename/comment `0x22BF220` as `node_consensus_timer__poll_round_timer_task`.
//! - Pending: rename/comment `0x44A8420` as `node_consensus_timer__new_round_scheduler`.
//! - Pending: rename/comment `0x44ADFA0` as `node_consensus_timer__poll_round_scheduler`.
//! - Pending: declare/apply `hl_node_consensus_RoundTimer`,
//!   `hl_node_consensus_ScheduledSleep`, and `hl_node_consensus_RoundBackoff`.

#![allow(dead_code)]

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use super::types::{BlockHash, ConsensusBlock, Round, SignedTimeout, TimeoutCertificate, ValidatorIndex};

pub const NANOS_PER_SECOND: u64 = 1_000_000_000;
pub const MUTEX_WAIT_TIMEOUT: Duration = Duration::from_secs(1);
pub const ROUND_TIMEOUT: Duration = Duration::from_secs(60);
pub const ASK_PEER_DELAY: Duration = Duration::from_secs(10);
pub const TRACE_WRITE_INTERVAL: Duration = Duration::from_secs(30);
pub const BACKOFF_BASE: Duration = Duration::from_millis(100);
pub const BACKOFF_MIN_JITTER: f64 = 0.75;
pub const BACKOFF_MAX_JITTER: f64 = 1.25;
pub const BACKOFF_CAP: Duration = Duration::from_secs(32);
pub const REQUEST_THROTTLE_CAPACITY: usize = 0x186a0;
pub const REQUEST_QUEUE_PRUNE_LIMIT: usize = 100;
pub const ASK_PEER_AFTER_RETRIES: u64 = 2;

pub const TIMER_SOURCE_PATH: &str = "/home/ubuntu/hl/code_Mainnet/node/src/consensus/timer.rs";
pub const TIMER_WARN_PREFIX: &str = "WARN >>>";
pub const TIMER_WRITE_EVENT: &str = "writing";
pub const VOTE_BUCKET: &str = "vote";
pub const SNAPSHOT_BUCKET: &str = "snapshots";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstantParts {
    pub seconds: u64,
    pub nanos: u32,
}

impl InstantParts {
    #[inline]
    pub const fn new(seconds: u64, nanos: u32) -> Self {
        let carry = nanos / NANOS_PER_SECOND as u32;
        let rem = nanos % NANOS_PER_SECOND as u32;
        Self { seconds: seconds.saturating_add(carry as u64), nanos: rem }
    }

    #[inline]
    pub fn from_duration(duration: Duration) -> Self {
        Self { seconds: duration.as_secs(), nanos: duration.subsec_nanos() }
    }

    #[inline]
    pub fn checked_add_duration(self, duration: Duration) -> Self {
        let seconds = self.seconds.saturating_add(duration.as_secs());
        let nanos = self.nanos as u64 + duration.subsec_nanos() as u64;
        Self {
            seconds: seconds.saturating_add(nanos / NANOS_PER_SECOND),
            nanos: (nanos % NANOS_PER_SECOND) as u32,
        }
    }

    #[inline]
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        if self.seconds < earlier.seconds || (self.seconds == earlier.seconds && self.nanos < earlier.nanos) {
            return Duration::ZERO;
        }

        let mut seconds = self.seconds - earlier.seconds;
        let nanos = if self.nanos >= earlier.nanos {
            self.nanos - earlier.nanos
        } else {
            seconds = seconds.saturating_sub(1);
            (NANOS_PER_SECOND as u32 - earlier.nanos) + self.nanos
        };
        Duration::new(seconds, nanos)
    }
}

#[derive(Clone, Debug)]
pub struct ScheduledSleep {
    /// IDA: seconds half of the `Instant` stored at `state+0x8c0` or `state+0x8e0`.
    pub deadline: Option<InstantParts>,
    /// IDA: the future-frame byte at `state+0x8d8` / `state+0x8f8` is set after reset.
    pub armed: bool,
    pub last_reset_at: Option<InstantParts>,
}

impl ScheduledSleep {
    #[inline]
    pub const fn disarmed() -> Self {
        Self { deadline: None, armed: false, last_reset_at: None }
    }

    #[inline]
    pub fn arm_after(&mut self, now: InstantParts, delay: Duration) {
        self.deadline = Some(now.checked_add_duration(delay));
        self.last_reset_at = Some(now);
        self.armed = true;
    }

    #[inline]
    pub fn arm_at(&mut self, deadline: InstantParts, now: InstantParts) {
        self.deadline = Some(deadline);
        self.last_reset_at = Some(now);
        self.armed = true;
    }

    #[inline]
    pub fn disarm(&mut self) {
        self.deadline = None;
        self.armed = false;
    }

    #[inline]
    pub fn poll_elapsed(&mut self, now: InstantParts) -> bool {
        let Some(deadline) = self.deadline else { return false };
        let elapsed = now.seconds > deadline.seconds || (now.seconds == deadline.seconds && now.nanos >= deadline.nanos);
        if elapsed {
            self.armed = false;
        }
        elapsed
    }
}

#[derive(Clone, Debug)]
pub struct RoundBackoff {
    pub failures: u32,
    pub base: Duration,
    pub cap: Duration,
    pub multiplier: f64,
    pub min_jitter: f64,
    pub max_jitter: f64,
}

impl Default for RoundBackoff {
    fn default() -> Self {
        Self {
            failures: 0,
            base: BACKOFF_BASE,
            cap: BACKOFF_CAP,
            multiplier: BACKOFF_MAX_JITTER,
            min_jitter: BACKOFF_MIN_JITTER,
            max_jitter: BACKOFF_MAX_JITTER,
        }
    }
}

impl RoundBackoff {
    #[inline]
    pub fn reset(&mut self) {
        self.failures = 0;
    }

    #[inline]
    pub fn record_failure(&mut self) -> Duration {
        let failure_index = self.failures.min(32);
        self.failures = self.failures.saturating_add(1);
        self.delay_for_failure(failure_index)
    }

    pub fn delay_for_failure(&self, failure_index: u32) -> Duration {
        let scale = self.multiplier.powi(failure_index as i32);
        let secs = self.base.as_secs_f64() * scale;
        let capped = secs.min(self.cap.as_secs_f64());
        Duration::from_secs_f64(capped)
    }

    /// [INFERENCE] The binary materializes `0.75` and `1.25` next to the `0.1`
    /// base. This helper keeps jitter deterministic by deriving a position in
    /// that interval from the round; no random source was observed in the seeds.
    pub fn jittered_delay(&self, round: Round) -> Duration {
        let raw = self.delay_for_failure(self.failures);
        let slot = (round.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 56) as f64 / 255.0;
        let factor = self.min_jitter + (self.max_jitter - self.min_jitter) * slot;
        Duration::from_secs_f64((raw.as_secs_f64() * factor).min(self.cap.as_secs_f64()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimerConsensusInput {
    /// IDA: `0x44ADFA0` path that stores discriminant `0x0a` after arming `state+0x8d0`.
    WaitForClientBlocks,
    /// IDA: `0x44ADFA0` path that stores discriminant `0x0b` and clears `state+0xb00`.
    PeerBackstop,
    /// IDA: `0x44ADFA0` path that stores discriminant `0x0c` after finalizing a branch.
    Accepted,
    /// IDA: `0x44B6670` consumes a client-block batch for one round.
    ClientBlocks { round: Round, blocks: Vec<ClientBlockTimerEntry> },
    Vote { round: Round, block_hash: BlockHash },
    Timeout { timeout: SignedTimeout },
    TimeoutCertificate { tc: TimeoutCertificate },
    Shutdown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimerAction {
    None,
    Continue,
    AskPeer { round: Round, reason: AskPeerReason },
    BroadcastTimeout { round: Round },
    BroadcastTimeoutCertificate { round: Round },
    CommitTx { round: Round, tx_hashes: Vec<[u8; 32]> },
    DropOldRound { round: Round, next_round: Round },
    WriteTrace { record: TimerTraceRecord },
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AskPeerReason {
    WaitDuration = 0x0a,
    Backstop = 0x0b,
    Accepted = 0x0c,
    FullQueue = 0x0f,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientBlockTimerEntry {
    pub round: Round,
    pub block_hash: BlockHash,
    pub block: ConsensusBlock,
}

#[derive(Clone, Debug)]
pub struct PendingRoundRequest {
    pub round: Round,
    pub peer: ValidatorIndex,
    pub requested_at: InstantParts,
    pub attempts: u32,
}

#[derive(Clone, Debug)]
pub struct TimerTraceRecord {
    pub bucket: &'static str,
    pub round: Round,
    pub elapsed: Duration,
    pub value: u64,
}

#[derive(Clone, Debug, Default)]
pub struct TimerTraceCounters {
    pub first_samples: u64,
    pub writes: u64,
    pub elapsed_nanos: u64,
    pub active_nanos: u64,
    pub overruns: u64,
}

#[derive(Clone, Debug)]
pub struct TimerTraceWriter {
    pub first_sample_seen: bool,
    pub started_at: InstantParts,
    pub last_sample_at: InstantParts,
    pub flush_timer: ScheduledSleep,
    pub counters: TimerTraceCounters,
    pub pending: VecDeque<TimerTraceRecord>,
}

impl TimerTraceWriter {
    pub fn new(now: InstantParts) -> Self {
        let mut flush_timer = ScheduledSleep::disarmed();
        flush_timer.arm_after(now, TRACE_WRITE_INTERVAL);
        Self {
            first_sample_seen: false,
            started_at: now,
            last_sample_at: now,
            flush_timer,
            counters: TimerTraceCounters::default(),
            pending: VecDeque::new(),
        }
    }

    /// Mirrors the elapsed-nanos accounting at `0x2043F70`: first sample records
    /// creation-to-now, later non-empty drains add active elapsed time.
    pub fn push(&mut self, now: InstantParts, record: TimerTraceRecord) {
        let elapsed = now.saturating_duration_since(self.last_sample_at);
        if !self.first_sample_seen {
            self.first_sample_seen = true;
            self.counters.first_samples = self.counters.first_samples.saturating_add(1);
            self.counters.elapsed_nanos = self
                .counters
                .elapsed_nanos
                .saturating_add(now.saturating_duration_since(self.started_at).as_nanos() as u64);
        } else {
            self.counters.active_nanos = self.counters.active_nanos.saturating_add(elapsed.as_nanos() as u64);
        }
        self.last_sample_at = now;
        self.counters.writes = self.counters.writes.saturating_add(1);
        self.pending.push_back(record);
    }

    pub fn poll_flush(&mut self, now: InstantParts) -> Option<Vec<TimerTraceRecord>> {
        if !self.flush_timer.poll_elapsed(now) {
            return None;
        }
        self.flush_timer.arm_after(now, TRACE_WRITE_INTERVAL);
        if self.pending.is_empty() {
            return Some(Vec::new());
        }
        Some(self.pending.drain(..).collect())
    }
}

#[derive(Clone, Debug)]
pub struct ConsensusRoundTimer {
    /// IDA: `state+0x918`, updated to `round + 1` by `0x44B6670`.
    pub next_round_to_request: Round,
    /// IDA: `state+0x920`, observed as companion to the next-round window.
    pub highest_accepted_round: Round,
    /// IDA: `state+0x9b0`, incremented by `0x44ADFA0` before ask-peer fallback.
    pub ask_peer_retries: u64,
    /// IDA: `state+0xb01`, suppresses repeated ask-peer scheduling until the peer path completes.
    pub ask_peer_in_flight: bool,
    /// IDA: `state+0xb00`, cleared by `0x44B6670` after accepting a newer round.
    pub backstop_in_flight: bool,
    /// IDA: timer triplet `state+0x8c0..0x8d8`.
    pub wait_timer: ScheduledSleep,
    /// IDA: timer triplet `state+0x8e0..0x8f8`.
    pub backstop_timer: ScheduledSleep,
    pub backoff: RoundBackoff,
    pub requested_rounds: BTreeMap<Round, Vec<PendingRoundRequest>>,
    pub backstop_rounds: BTreeMap<Round, Vec<PendingRoundRequest>>,
    pub accepted_blocks: BTreeMap<Round, Vec<ClientBlockTimerEntry>>,
    pub trace: TimerTraceWriter,
}

impl ConsensusRoundTimer {
    pub fn new(now: InstantParts) -> Self {
        let mut wait_timer = ScheduledSleep::disarmed();
        wait_timer.arm_after(now, ASK_PEER_DELAY);
        let mut backstop_timer = ScheduledSleep::disarmed();
        backstop_timer.arm_after(now, ROUND_TIMEOUT);
        Self {
            next_round_to_request: 0,
            highest_accepted_round: 0,
            ask_peer_retries: 0,
            ask_peer_in_flight: false,
            backstop_in_flight: false,
            wait_timer,
            backstop_timer,
            backoff: RoundBackoff::default(),
            requested_rounds: BTreeMap::new(),
            backstop_rounds: BTreeMap::new(),
            accepted_blocks: BTreeMap::new(),
            trace: TimerTraceWriter::new(now),
        }
    }

    pub fn handle_input(&mut self, now: InstantParts, input: TimerConsensusInput) -> TimerAction {
        match input {
            TimerConsensusInput::WaitForClientBlocks => self.arm_wait_for_client_blocks(now),
            TimerConsensusInput::PeerBackstop => self.arm_peer_backstop(now),
            TimerConsensusInput::Accepted => {
                self.ask_peer_in_flight = false;
                TimerAction::Continue
            }
            TimerConsensusInput::ClientBlocks { round, blocks } => self.advance_round_window(now, round, blocks),
            TimerConsensusInput::Vote { round, block_hash } => {
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&block_hash[..8]);
                self.trace.push(now, TimerTraceRecord {
                    bucket: VOTE_BUCKET,
                    round,
                    elapsed: Duration::ZERO,
                    value: u64::from_be_bytes(prefix),
                });
                TimerAction::Continue
            }
            TimerConsensusInput::Timeout { timeout } => {
                TimerAction::BroadcastTimeout { round: timeout.content.round }
            }
            TimerConsensusInput::TimeoutCertificate { tc } => {
                TimerAction::BroadcastTimeoutCertificate { round: tc.round }
            }
            TimerConsensusInput::Shutdown => TimerAction::Shutdown,
        }
    }

    /// Recovered from `0x44B6670`.
    pub fn advance_round_window(
        &mut self,
        now: InstantParts,
        round: Round,
        blocks: Vec<ClientBlockTimerEntry>,
    ) -> TimerAction {
        let old_next = self.next_round_to_request;
        if round < old_next {
            self.drop_old_round(round);
            return TimerAction::DropOldRound { round, next_round: old_next };
        }

        self.next_round_to_request = round.saturating_add(1);
        self.highest_accepted_round = self.highest_accepted_round.max(round);
        self.accepted_blocks.insert(round, blocks);
        self.ask_peer_retries = 0;
        self.ask_peer_in_flight = false;
        self.backstop_in_flight = false;
        self.backoff.reset();
        self.requested_rounds.retain(|known_round, _| *known_round >= round);
        self.backstop_rounds.retain(|known_round, _| *known_round >= round);
        self.wait_timer.arm_after(now, ASK_PEER_DELAY);
        self.backstop_timer.arm_after(now, ROUND_TIMEOUT);
        self.prune_large_queues();

        TimerAction::Continue
    }

    /// Recovered from the `0x44ADFA0` state branch that increments `state+0x9b0`.
    pub fn arm_wait_for_client_blocks(&mut self, now: InstantParts) -> TimerAction {
        self.ask_peer_retries = self.ask_peer_retries.saturating_add(1);
        let delay = if self.ask_peer_retries >= ASK_PEER_AFTER_RETRIES {
            self.backoff.record_failure()
        } else {
            ASK_PEER_DELAY
        };
        self.wait_timer.arm_after(now, delay);

        if self.ask_peer_retries >= ASK_PEER_AFTER_RETRIES || !self.ask_peer_in_flight {
            self.ask_peer_in_flight = true;
            return TimerAction::AskPeer {
                round: self.next_round_to_request,
                reason: AskPeerReason::WaitDuration,
            };
        }

        TimerAction::Continue
    }

    /// Recovered from the `0x44ADFA0` branch that stores state byte `0x0b` and
    /// from `0x44B6670` rearming `state+0x8e0..0x8f8`.
    pub fn arm_peer_backstop(&mut self, now: InstantParts) -> TimerAction {
        if !self.backstop_in_flight {
            self.backstop_in_flight = true;
            self.backstop_timer.arm_after(now, ROUND_TIMEOUT);
            return TimerAction::AskPeer {
                round: self.next_round_to_request,
                reason: AskPeerReason::Backstop,
            };
        }
        TimerAction::Continue
    }

    pub fn poll(&mut self, now: InstantParts) -> TimerAction {
        if self.wait_timer.poll_elapsed(now) {
            return self.arm_wait_for_client_blocks(now);
        }
        if self.backstop_timer.poll_elapsed(now) {
            return self.arm_peer_backstop(now);
        }
        if let Some(records) = self.trace.poll_flush(now) {
            if !records.is_empty() {
                return TimerAction::WriteTrace { record: records[0].clone() };
            }
        }
        TimerAction::None
    }

    pub fn enqueue_request(&mut self, now: InstantParts, round: Round, peer: ValidatorIndex) {
        let entry = PendingRoundRequest { round, peer, requested_at: now, attempts: 0 };
        self.requested_rounds.entry(round).or_default().push(entry);
        self.prune_large_queues();
    }

    pub fn enqueue_backstop_request(&mut self, now: InstantParts, round: Round, peer: ValidatorIndex) {
        let entry = PendingRoundRequest { round, peer, requested_at: now, attempts: 0 };
        self.backstop_rounds.entry(round).or_default().push(entry);
        self.prune_large_queues();
    }

    fn drop_old_round(&mut self, round: Round) {
        self.requested_rounds.remove(&round);
        self.backstop_rounds.remove(&round);
        self.accepted_blocks.remove(&round);
    }

    /// IDA: `0x44ADFA0` prunes when vector lengths reach `0x65` and retains `0x64`.
    fn prune_large_queues(&mut self) {
        prune_map_to_limit(&mut self.requested_rounds, REQUEST_QUEUE_PRUNE_LIMIT);
        prune_map_to_limit(&mut self.backstop_rounds, REQUEST_QUEUE_PRUNE_LIMIT);
        prune_map_to_limit(&mut self.accepted_blocks, REQUEST_QUEUE_PRUNE_LIMIT);
    }
}

fn prune_map_to_limit<T>(map: &mut BTreeMap<Round, T>, limit: usize) {
    while map.len() > limit {
        let Some(first) = map.keys().next().copied() else { break };
        map.remove(&first);
    }
}

#[derive(Clone, Debug)]
pub struct ConsensusTimerRuntime {
    pub created_at: Instant,
    pub round_timer: ConsensusRoundTimer,
}

impl ConsensusTimerRuntime {
    pub fn new(created_at: Instant) -> Self {
        Self { created_at, round_timer: ConsensusRoundTimer::new(InstantParts::new(0, 0)) }
    }

    #[inline]
    pub fn parts_for(&self, now: Instant) -> InstantParts {
        InstantParts::from_duration(now.saturating_duration_since(self.created_at))
    }

    #[inline]
    pub fn poll(&mut self, now: Instant) -> TimerAction {
        let parts = self.parts_for(now);
        self.round_timer.poll(parts)
    }
}
