//! Reconstruction of `/home/ubuntu/hl/code_Mainnet/node/src/consensus/heartbeat_tracker.rs`.
//!
//! Confidence: medium for the wire/state shapes and high for the recovered branch
//! structure of the current heartbeat-ack and liveness-iterator paths that were
//! available through local disassembly notes. The central IDA queue was full for
//! this wave, so IDA writes are pending rather than claimed as applied.
//!
//! Seeds:
//! - `0x4726A50` — unresolved heartbeat/base EMA/file-mod-time shared helper.
//! - `0x488C410` — unresolved hop-1 heartbeat-tracker seed.
//! - `0x4898810` — BTree-backed liveness iterator/update path: 20-byte signer keys,
//!   200ms grace, 0.2/0.4s latency windows, 30s success window, max-round update.
//! - `0x474E510` — heartbeat-ack processing: time gate, strict 3×u32 progress
//!   comparison, status-byte-2 error storage, continuation dispatch.
//! - `0x474ECE0` — constructor from gossip heartbeat: initializes tracker state and
//!   applies validator-round entries through the heartbeat helper path.
//!
//! Pending IDA hygiene when the queue drains:
//! - rename `0x474E510` -> `node_consensus_heartbeat_tracker__process_heartbeat_ack`
//! - rename `0x474ECE0` -> `node_consensus_heartbeat_tracker__init_from_gossip_heartbeat`
//! - rename `0x4898810` -> `node_consensus_heartbeat_tracker__unresponsive_iter_next`
//! - lookup/decompile/rename/comment `0x4726A50` and `0x488C410`
//! - declare/apply `hl_node_HeartbeatTracker`, `hl_node_Heartbeat`,
//!   `hl_node_HeartbeatAck`, and the 20-byte signer key type.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use super::types::{HeartbeatSnapshot, Round, ValidatorIndex};

pub const HEARTBEAT_ACK_VARIANT: u8 = 4;
pub const HEARTBEAT_GRACE_NS: u64 = 200_000_000;
pub const NANOS_PER_SECOND: u64 = 1_000_000_000;
pub const SECONDS_PER_DAY: u64 = 86_400;
pub const FAST_LATENCY_WINDOW_SECS: f64 = 0.2;
pub const SLOW_LATENCY_WINDOW_SECS: f64 = 0.4;
pub const LAST_SUCCESS_WINDOW: Duration = Duration::from_secs(30);

/// 20-byte validator/signer identifier. Current liveness code compares these
/// keys with `memcmp(..., 20)` while traversing BTree nodes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ValidatorSigner(pub [u8; 20]);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct TimestampNs(pub u64);

impl TimestampNs {
    pub const ZERO: Self = Self(0);

    pub fn checked_add_nanos(self, nanos: u64) -> Option<Self> {
        self.0.checked_add(nanos).map(Self)
    }

    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        Duration::from_nanos(self.0.saturating_sub(earlier.0))
    }

    pub fn day_after_grace(self) -> i32 {
        let adjusted = self
            .checked_add_nanos(HEARTBEAT_GRACE_NS)
            .expect("heartbeat timestamp overflow after 200ms grace");
        let day = (adjusted.0 / NANOS_PER_SECOND) / SECONDS_PER_DAY;
        i32::try_from(day).expect("heartbeat timestamp day outside i32 chrono range")
    }
}

/// Gossip `Heartbeat` request. Serializer notes place the fields in this order:
/// `validator_to_last_msg_round`, `snapshot`, `round`, `validator`, `random_id`.
#[derive(Clone, Debug)]
pub struct Heartbeat {
    pub validator_to_last_msg_round: HashMap<ValidatorIndex, Round>,
    pub snapshot: Option<HeartbeatSnapshot>,
    pub round: Round,
    pub validator: ValidatorIndex,
    pub random_id: [u8; 16],
}

/// Wire `HeartbeatAck` request recovered from serializer `0x396A860`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeartbeatAck {
    pub round: Round,
    pub validator: ValidatorSigner,
    pub random_id: u32,
}

impl HeartbeatAck {
    /// The current ack processor compares a decoded three-u32 tuple, not just the
    /// wire `round`. When only the wire struct is available, this preserves the
    /// same lexicographic shape by using high/low round words plus `random_id`.
    pub fn progress_from_wire(self) -> AckProgress {
        AckProgress {
            high: (self.round >> 32) as u32,
            mid: self.round as u32,
            low: self.random_id,
        }
    }
}

/// Strictly-monotonic ack key. `0x474E510` accepts only tuples greater than the
/// stored tuple at tracker offsets corresponding to `+0xF8/+0xFC/+0x100`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct AckProgress {
    pub high: u32,
    pub mid: u32,
    pub low: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeartbeatAckError {
    pub validator: ValidatorSigner,
    pub progress: AckProgress,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DecodedAckStatus {
    Applied { duration_secs: f64 },
    Ignored { status: u8 },
    ErrorObject(HeartbeatAckError),
}

#[derive(Clone, Debug, PartialEq)]
pub struct DecodedHeartbeatAck {
    pub progress: AckProgress,
    pub status: DecodedAckStatus,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AckUpdate {
    Accepted,
    StaleProgress { previous: AckProgress, received: AckProgress },
    TimeGate { previous_duration_secs: f64, observed_duration_secs: f64 },
    StoredError,
}

/// Lightweight EMA used by the heartbeat liveness path. `0x4726A50` is also
/// associated with `base/src/ema_tracker.rs`; exact current decompile was blocked,
/// but the heartbeat iterator writes latency windows at 0.2s and 0.4s and stores
/// the latest f64 duration for a validator record.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EmaTracker {
    value: f64,
    initialized: bool,
    alpha: f64,
}

impl EmaTracker {
    pub fn new(alpha: f64) -> Self {
        Self { value: 0.0, initialized: false, alpha }
    }

    pub fn value(self) -> Option<f64> {
        self.initialized.then_some(self.value)
    }

    pub fn update(&mut self, sample: f64) -> f64 {
        if self.initialized {
            self.value = self.alpha.mul_add(sample, (1.0 - self.alpha) * self.value);
        } else {
            self.value = sample;
            self.initialized = true;
        }
        self.value
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LatencyClass {
    Fast,
    Slow,
    Unresponsive,
}

#[derive(Clone, Debug)]
pub struct LivenessConfig {
    pub missed_rounds_before_unresponsive: Round,
    pub fast_latency: Duration,
    pub slow_latency: Duration,
    pub last_success_window: Duration,
    pub latency_ema_alpha: f64,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        Self {
            // [INFERENCE] The exact round threshold was not recovered in current IDA.
            // The source file exposes the policy as config while preserving the
            // recovered branch: jailed validators are skipped, and stale last-round
            // entries become unresponsive candidates.
            missed_rounds_before_unresponsive: 2,
            fast_latency: Duration::from_millis(200),
            slow_latency: Duration::from_millis(400),
            last_success_window: LAST_SUCCESS_WINDOW,
            latency_ema_alpha: 0.2,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ValidatorLiveness {
    pub signer: ValidatorSigner,
    pub validator_index: Option<ValidatorIndex>,
    pub last_heartbeat_at: TimestampNs,
    pub last_msg_round: Round,
    pub last_latency_secs: Option<f64>,
    pub latency_ema: EmaTracker,
    pub last_fast_success_at: Option<TimestampNs>,
    pub last_slow_success_at: Option<TimestampNs>,
    pub last_success_deadline: Option<TimestampNs>,
    pub current_day: Option<i32>,
    pub updated_in_current_pass: bool,
}

impl ValidatorLiveness {
    pub fn new(signer: ValidatorSigner, alpha: f64) -> Self {
        Self {
            signer,
            validator_index: None,
            last_heartbeat_at: TimestampNs::ZERO,
            last_msg_round: 0,
            last_latency_secs: None,
            latency_ema: EmaTracker::new(alpha),
            last_fast_success_at: None,
            last_slow_success_at: None,
            last_success_deadline: None,
            current_day: None,
            updated_in_current_pass: false,
        }
    }

    pub fn latency_class(&self, config: &LivenessConfig, now: TimestampNs) -> LatencyClass {
        let elapsed = now.saturating_duration_since(self.last_heartbeat_at);
        if elapsed <= config.fast_latency {
            LatencyClass::Fast
        } else if elapsed <= config.slow_latency {
            LatencyClass::Slow
        } else {
            LatencyClass::Unresponsive
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LivenessSample {
    pub signer: ValidatorSigner,
    pub validator_index: Option<ValidatorIndex>,
    pub round: Round,
    pub received_at: TimestampNs,
    pub latency: Option<Duration>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LivenessSampleResult {
    Applied { advanced_round: bool, day: i32 },
    FutureDated { sample_day: i32, tracker_day: i32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnresponsiveValidator {
    pub signer: ValidatorSigner,
    pub validator_index: Option<ValidatorIndex>,
    pub last_msg_round: Round,
    pub missed_rounds: Round,
    pub jailed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeartbeatApplyResult {
    pub sender_round_advanced: bool,
    pub merged_last_msg_rounds: usize,
    pub installed_snapshot: bool,
    pub unresponsive: Vec<UnresponsiveValidator>,
}

#[derive(Clone, Debug)]
pub struct HeartbeatTracker {
    pub config: LivenessConfig,
    pub local_validator: ValidatorIndex,
    pub current_round: Round,
    pub current_day: i32,
    pub validator_to_last_msg_round: BTreeMap<ValidatorIndex, Round>,
    pub signer_to_liveness: BTreeMap<ValidatorSigner, ValidatorLiveness>,
    pub signer_to_validator: BTreeMap<ValidatorSigner, ValidatorIndex>,
    pub active_validators: BTreeSet<ValidatorIndex>,
    pub current_jailed_validators: BTreeSet<ValidatorIndex>,
    pub round_to_jailed_validators: BTreeMap<Round, BTreeSet<ValidatorIndex>>,
    pub last_snapshot: Option<HeartbeatSnapshot>,
    pub last_ack_received_at: Option<TimestampNs>,
    pub last_ack_duration_secs: f64,
    pub last_ack_progress: AckProgress,
    pub last_ack_latency_secs: Option<f64>,
    pub pending_ack_error: Option<HeartbeatAckError>,
}

impl HeartbeatTracker {
    pub fn new(local_validator: ValidatorIndex, now: TimestampNs, config: LivenessConfig) -> Self {
        Self {
            config,
            local_validator,
            current_round: 0,
            current_day: now.day_after_grace(),
            validator_to_last_msg_round: BTreeMap::new(),
            signer_to_liveness: BTreeMap::new(),
            signer_to_validator: BTreeMap::new(),
            active_validators: BTreeSet::new(),
            current_jailed_validators: BTreeSet::new(),
            round_to_jailed_validators: BTreeMap::new(),
            last_snapshot: None,
            last_ack_received_at: None,
            last_ack_duration_secs: 0.0,
            last_ack_progress: AckProgress::default(),
            last_ack_latency_secs: None,
            pending_ack_error: None,
        }
    }

    /// Recovered constructor behavior for `0x474ECE0`: build tracker state from a
    /// gossip heartbeat, initialize the current date from the wall clock, install
    /// the optional snapshot, then apply the sender and all advertised last-rounds.
    pub fn from_gossip_heartbeat(
        local_validator: ValidatorIndex,
        signer: ValidatorSigner,
        heartbeat: &Heartbeat,
        now: TimestampNs,
        config: LivenessConfig,
    ) -> Self {
        let mut tracker = Self::new(local_validator, now, config);
        tracker.apply_gossip_heartbeat(signer, heartbeat, now);
        tracker
    }

    /// Applies a gossip heartbeat after the outer authenticated handler has already
    /// established the sending validator context.
    pub fn apply_gossip_heartbeat(
        &mut self,
        signer: ValidatorSigner,
        heartbeat: &Heartbeat,
        received_at: TimestampNs,
    ) -> HeartbeatApplyResult {
        self.current_round = self.current_round.max(heartbeat.round);
        self.current_day = received_at.day_after_grace();

        let installed_snapshot = if let Some(snapshot) = heartbeat.snapshot.as_ref() {
            self.install_snapshot(snapshot.clone(), heartbeat.round);
            true
        } else {
            false
        };

        self.signer_to_validator.insert(signer, heartbeat.validator);
        let sender_round_advanced = self.update_validator_round(heartbeat.validator, heartbeat.round);
        let sample = LivenessSample {
            signer,
            validator_index: Some(heartbeat.validator),
            round: heartbeat.round,
            received_at,
            latency: Some(Duration::from_nanos(0)),
        };
        let _ = self.record_liveness_sample(sample);

        let mut merged_last_msg_rounds = 0;
        for (&validator, &round) in &heartbeat.validator_to_last_msg_round {
            if self.update_validator_round(validator, round) {
                merged_last_msg_rounds += 1;
            }
        }

        HeartbeatApplyResult {
            sender_round_advanced,
            merged_last_msg_rounds,
            installed_snapshot,
            unresponsive: self.unresponsive_validators(heartbeat.round),
        }
    }

    pub fn build_heartbeat(&self, random_id: [u8; 16]) -> Heartbeat {
        Heartbeat {
            validator_to_last_msg_round: self
                .validator_to_last_msg_round
                .iter()
                .map(|(&validator, &round)| (validator, round))
                .collect(),
            snapshot: self.last_snapshot.clone(),
            round: self.current_round,
            validator: self.local_validator,
            random_id,
        }
    }

    pub fn install_snapshot(&mut self, snapshot: HeartbeatSnapshot, round: Round) {
        self.current_jailed_validators = snapshot.validator_set_snapshot.jailed_validators.clone();
        self.active_validators = snapshot
            .validator_set_snapshot
            .stakes
            .keys()
            .copied()
            .collect();
        self.round_to_jailed_validators
            .insert(round, self.current_jailed_validators.clone());
        self.last_snapshot = Some(snapshot);
    }

    pub fn update_validator_round(&mut self, validator: ValidatorIndex, round: Round) -> bool {
        let entry = self.validator_to_last_msg_round.entry(validator).or_insert(0);
        if round > *entry {
            *entry = round;
            true
        } else {
            false
        }
    }

    /// Recovered `0x4898810` behavior at source level: process one liveness sample,
    /// reject future-day entries, update the per-signer max round, and refresh the
    /// two observed latency windows (0.2s and 0.4s) plus the 30s success deadline.
    pub fn record_liveness_sample(&mut self, sample: LivenessSample) -> LivenessSampleResult {
        let sample_day = sample.received_at.day_after_grace();
        if sample_day.cmp(&self.current_day) == Ordering::Greater {
            return LivenessSampleResult::FutureDated { sample_day, tracker_day: self.current_day };
        }

        if let Some(validator) = sample.validator_index {
            self.signer_to_validator.insert(sample.signer, validator);
        }

        let record = self
            .signer_to_liveness
            .entry(sample.signer)
            .or_insert_with(|| ValidatorLiveness::new(sample.signer, self.config.latency_ema_alpha));

        if sample.validator_index.is_some() {
            record.validator_index = sample.validator_index;
        }
        record.last_heartbeat_at = sample.received_at;
        record.current_day = Some(sample_day);
        record.updated_in_current_pass = true;

        if let Some(latency) = sample.latency {
            let latency_secs = latency.as_secs_f64();
            record.last_latency_secs = Some(latency_secs);
            record.latency_ema.update(latency_secs);
            if latency <= self.config.fast_latency {
                record.last_fast_success_at = Some(sample.received_at);
            }
            if latency <= self.config.slow_latency {
                record.last_slow_success_at = Some(sample.received_at);
            }
        }

        record.last_success_deadline = sample
            .received_at
            .checked_add_nanos(self.config.last_success_window.as_nanos() as u64);

        let advanced_round = if sample.round > record.last_msg_round {
            record.last_msg_round = sample.round;
            true
        } else {
            false
        };

        LivenessSampleResult::Applied { advanced_round, day: sample_day }
    }

    pub fn unresponsive_validators(&self, at_round: Round) -> Vec<UnresponsiveValidator> {
        let mut out = Vec::new();

        if self.active_validators.is_empty() {
            for &validator in self.validator_to_last_msg_round.keys() {
                self.push_unresponsive_candidate(&mut out, validator, at_round);
            }
        } else {
            for &validator in &self.active_validators {
                self.push_unresponsive_candidate(&mut out, validator, at_round);
            }
        }

        out
    }

    fn push_unresponsive_candidate(
        &self,
        out: &mut Vec<UnresponsiveValidator>,
        validator: ValidatorIndex,
        at_round: Round,
    ) {
        if self.current_jailed_validators.contains(&validator) {
            return;
        }

        let last = self.validator_to_last_msg_round.get(&validator).copied().unwrap_or(0);
        let missed_rounds = at_round.saturating_sub(last);
        if missed_rounds <= self.config.missed_rounds_before_unresponsive {
            return;
        }

        out.push(UnresponsiveValidator {
            signer: self.signer_for_validator(validator).unwrap_or(ValidatorSigner([0; 20])),
            validator_index: Some(validator),
            last_msg_round: last,
            missed_rounds,
            jailed: false,
        });
    }

    fn signer_for_validator(&self, validator: ValidatorIndex) -> Option<ValidatorSigner> {
        self.signer_to_validator
            .iter()
            .find_map(|(signer, &idx)| (idx == validator).then_some(*signer))
    }

    pub fn jail_unresponsive_at_round(&mut self, round: Round) -> BTreeSet<ValidatorIndex> {
        let to_jail: BTreeSet<_> = self
            .unresponsive_validators(round)
            .into_iter()
            .filter_map(|candidate| candidate.validator_index)
            .collect();
        self.current_jailed_validators.extend(to_jail.iter().copied());
        self.round_to_jailed_validators.insert(round, to_jail.clone());
        to_jail
    }

    /// Recovered `0x474E510` branch structure. The outer handler supplies already
    /// decoded ack content; this method performs the tracker mutations observed in
    /// the current binary.
    pub fn process_heartbeat_ack(
        &mut self,
        ack: HeartbeatAck,
        decoded: DecodedHeartbeatAck,
        now: TimestampNs,
    ) -> AckUpdate {
        if let Some(previous_at) = self.last_ack_received_at {
            let observed_duration_secs = now.saturating_duration_since(previous_at).as_secs_f64();
            if self.last_ack_duration_secs != 0.0
                && observed_duration_secs <= self.last_ack_duration_secs
            {
                return AckUpdate::TimeGate {
                    previous_duration_secs: self.last_ack_duration_secs,
                    observed_duration_secs,
                };
            }
        }
        self.last_ack_received_at = Some(now);

        if decoded.progress <= self.last_ack_progress {
            return AckUpdate::StaleProgress {
                previous: self.last_ack_progress,
                received: decoded.progress,
            };
        }

        match decoded.status {
            DecodedAckStatus::ErrorObject(error) => {
                self.pending_ack_error = Some(error);
                AckUpdate::StoredError
            }
            DecodedAckStatus::Applied { duration_secs } => {
                self.last_ack_progress = decoded.progress;
                self.last_ack_duration_secs = duration_secs.max(0.0);
                self.last_ack_latency_secs = Some(duration_secs);
                self.pending_ack_error = None;
                self.signer_to_liveness
                    .entry(ack.validator)
                    .or_insert_with(|| ValidatorLiveness::new(ack.validator, self.config.latency_ema_alpha))
                    .latency_ema
                    .update(duration_secs);
                AckUpdate::Accepted
            }
            DecodedAckStatus::Ignored { .. } => {
                self.last_ack_progress = decoded.progress;
                self.pending_ack_error = None;
                AckUpdate::Accepted
            }
        }
    }

    pub fn process_wire_heartbeat_ack(
        &mut self,
        ack: HeartbeatAck,
        duration_secs: f64,
        now: TimestampNs,
    ) -> AckUpdate {
        self.process_heartbeat_ack(
            ack,
            DecodedHeartbeatAck {
                progress: ack.progress_from_wire(),
                status: DecodedAckStatus::Applied { duration_secs },
            },
            now,
        )
    }
}

#[derive(Clone, Debug)]
pub struct LivenessIter<'a> {
    tracker: &'a HeartbeatTracker,
    validators: Vec<ValidatorIndex>,
    index: usize,
    round: Round,
}

impl<'a> LivenessIter<'a> {
    pub fn new(tracker: &'a HeartbeatTracker, round: Round) -> Self {
        let validators = if tracker.active_validators.is_empty() {
            tracker.validator_to_last_msg_round.keys().copied().collect()
        } else {
            tracker.active_validators.iter().copied().collect()
        };
        Self { tracker, validators, index: 0, round }
    }
}

impl Iterator for LivenessIter<'_> {
    type Item = UnresponsiveValidator;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(&validator) = self.validators.get(self.index) {
            self.index += 1;
            if self.tracker.current_jailed_validators.contains(&validator) {
                continue;
            }
            let last = self
                .tracker
                .validator_to_last_msg_round
                .get(&validator)
                .copied()
                .unwrap_or(0);
            let missed_rounds = self.round.saturating_sub(last);
            if missed_rounds <= self.tracker.config.missed_rounds_before_unresponsive {
                continue;
            }
            let signer = self
                .tracker
                .signer_for_validator(validator)
                .unwrap_or(ValidatorSigner([0; 20]));
            return Some(UnresponsiveValidator {
                signer,
                validator_index: Some(validator),
                last_msg_round: last,
                missed_rounds,
                jailed: false,
            });
        }
        None
    }
}
