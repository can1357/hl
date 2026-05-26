#![allow(dead_code)]

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Recovered timing state used by the grouped samplers.
///
/// The binary stores the clock as a 12-byte `Timespec` and overwrites the
/// caller's previous timestamp on every sample.  Keeping the shape explicit here
/// makes the update semantics visible without depending on `std::time::Instant`'s
/// private layout.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SampleClock {
    pub seconds: i64,
    pub nanos: i32,
}

impl SampleClock {
    pub fn now() -> Self {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        Self { seconds: duration.as_secs() as i64, nanos: duration.subsec_nanos() as i32 }
    }

    pub fn elapsed_since(self, earlier: Self) -> f64 {
        let mut seconds = self.seconds.saturating_sub(earlier.seconds);
        let nanos = if self.nanos >= earlier.nanos {
            self.nanos - earlier.nanos
        } else {
            seconds = seconds.saturating_sub(1);
            1_000_000_000 + self.nanos - earlier.nanos
        };
        seconds as f64 + nanos as f64 / 1_000_000_000.0
    }

    pub fn minute_of_hour(self) -> u32 {
        let seconds = self.seconds.rem_euclid(3_600) as u32;
        seconds / 60
    }

    /// Coarse local-day bucket used by the sampler report grouping.  The binary's
    /// concrete bucket comes from its local-time helper; this UTC bucket preserves
    /// the same monotone day-rollover behavior for reconstructed source.
    pub fn day_bucket(self) -> u32 {
        self.seconds.div_euclid(86_400) as u32
    }
}

#[derive(Clone, Debug)]
pub struct LatencySampler {
    pub metric_name: String,
    pub expected_secs: f64,
    pub sample_rate: f64,
    pub report_bucket: u32,
    pub samples: Vec<f64>,
    pub observations: u64,
    pub max_seen_secs: f64,
}

impl LatencySampler {
    pub fn new(metric_name: String, expected_secs: f64, now: SampleClock) -> Self {
        Self {
            metric_name,
            expected_secs,
            sample_rate: 0.01,
            report_bucket: now.day_bucket(),
            samples: Vec::new(),
            observations: 0,
            max_seen_secs: 0.0,
        }
    }

    pub fn observe(&mut self, elapsed_secs: f64, now: SampleClock) {
        self.observations = self.observations.saturating_add(1);
        if elapsed_secs > self.max_seen_secs {
            self.max_seen_secs = elapsed_secs;
        }
        self.report_bucket = now.day_bucket();

        // The recovered helper constructs base::latency_sampler with a 0.01
        // sampling factor and calls its update routine with `(1, elapsed_secs)`.
        // Keep every value here; downstream consumers can thin if needed.
        self.samples.push(elapsed_secs);
    }

    pub fn over_expected_count(&self) -> usize {
        self.samples.iter().filter(|&&value| value > self.expected_secs).count()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupedSequenceReportEntry<K> {
    pub key: K,
    pub observations: u64,
    pub over_expected: usize,
    pub max_seen_secs_bits: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupedSequenceReport<K> {
    pub bucket: u32,
    pub entries: Vec<GroupedSequenceReportEntry<K>>,
}

#[derive(Clone, Debug)]
pub struct GroupAndSeqSampler<K: Ord + Copy> {
    pub samplers: BTreeMap<K, LatencySampler>,
    pub report_interval_secs: f64,
    pub last_report_at: Option<SampleClock>,
}

impl<K: Ord + Copy> GroupAndSeqSampler<K> {
    pub fn new(report_interval_secs: f64) -> Self {
        Self { samplers: BTreeMap::new(), report_interval_secs, last_report_at: None }
    }

    pub fn record_with(
        &mut self,
        key: K,
        metric_name: impl FnOnce() -> String,
        expected_secs: f64,
        previous_step_at: &mut SampleClock,
    ) -> Vec<GroupedSequenceReport<K>> {
        let old = *previous_step_at;
        let now = SampleClock::now();
        let elapsed = now.elapsed_since(old);
        *previous_step_at = now;

        self.samplers
            .entry(key)
            .or_insert_with(|| LatencySampler::new(metric_name(), expected_secs, now))
            .observe(elapsed, now);

        if !self.should_report(now) {
            return Vec::new();
        }
        self.last_report_at = Some(now);
        self.group_reports(now)
    }

    fn should_report(&self, now: SampleClock) -> bool {
        match self.last_report_at {
            None => true,
            Some(last) => now.elapsed_since(last) > self.report_interval_secs,
        }
    }

    fn group_reports(&self, now: SampleClock) -> Vec<GroupedSequenceReport<K>> {
        let mut by_bucket: BTreeMap<u32, Vec<GroupedSequenceReportEntry<K>>> = BTreeMap::new();
        for (&key, sampler) in &self.samplers {
            by_bucket.entry(sampler.report_bucket).or_default().push(GroupedSequenceReportEntry {
                key,
                observations: sampler.observations,
                over_expected: sampler.over_expected_count(),
                max_seen_secs_bits: sampler.max_seen_secs.to_bits(),
            });
        }

        // Recovered rollover guard: the binary materializes a temporary BTreeMap
        // keyed by sampler bucket and allocates a vector of keys when either at
        // least three buckets exist, or more than one bucket exists after minute 6
        // of the hour.  That keeps stale buckets visible shortly after rollover.
        let should_emit = by_bucket.len() >= 3 || (by_bucket.len() > 1 && now.minute_of_hour() >= 6);
        if !should_emit {
            return Vec::new();
        }

        by_bucket
            .into_iter()
            .map(|(bucket, entries)| GroupedSequenceReport { bucket, entries })
            .collect()
    }
}

pub type GroupSampler = GroupAndSeqSampler<u64>;
pub type SequenceSampler = GroupAndSeqSampler<SeqTaskPhase>;

pub const GROUP_STEP_EXPECTED_SECS: f64 = 0.01;
pub const DEFAULT_SEQ_PHASE_ZERO_EXPECTED_SECS: f64 = 0.08;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum SeqTaskPhase {
    /// Called by the short wrapper that builds the client-block task vector.
    ClientBlocks = 0,
    /// [INFERENCE] First phase inside the main execution path after preparing execution inputs.
    PrepareExecution = 1,
    /// [INFERENCE] Phase after converting client blocks into execution work.
    ExecuteClientBlocks = 2,
    /// [INFERENCE] Phase after state/output materialization.
    PersistOutputs = 3,
    /// [INFERENCE] Final phase before returning the consensus execution result.
    Finalize = 4,
    /// Present in the recovered switch but not observed in the direct callers.
    PostFinalize = 5,
}

impl SeqTaskPhase {
    pub fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::ClientBlocks),
            1 => Some(Self::PrepareExecution),
            2 => Some(Self::ExecuteClientBlocks),
            3 => Some(Self::PersistOutputs),
            4 => Some(Self::Finalize),
            5 => Some(Self::PostFinalize),
            _ => None,
        }
    }

    pub fn as_raw(self) -> u8 {
        self as u8
    }

    pub fn expected_secs(self, latency_mode: u8) -> f64 {
        match self {
            Self::ClientBlocks => seq_phase_zero_expected_secs(latency_mode),
            Self::PrepareExecution => 0.03,
            Self::ExecuteClientBlocks => 0.25,
            Self::PersistOutputs => 0.05,
            Self::Finalize | Self::PostFinalize => 0.01,
        }
    }

    pub fn metric_name(self) -> String {
        format!("seq_task/{}", self.as_raw())
    }
}

pub fn seq_phase_zero_expected_secs(latency_mode: u8) -> f64 {
    // The recovered switch indexes a 22-entry f64 table by `latency_mode - 10`
    // for modes 10..=31 and falls back to 0.08 otherwise.  The visible table
    // prefix is 0.15, then a run of 0.08s values; unknown tail values are kept at
    // the binary fallback rather than guessed.
    match latency_mode {
        10 => 0.15,
        11..=31 => 0.08,
        _ => DEFAULT_SEQ_PHASE_ZERO_EXPECTED_SECS,
    }
}

pub fn record_group_step(
    sampler: &mut GroupSampler,
    group: u64,
    previous_step_at: &mut SampleClock,
) -> Vec<GroupedSequenceReport<u64>> {
    sampler.record_with(
        group,
        || format!("seq_task/{}", group),
        GROUP_STEP_EXPECTED_SECS,
        previous_step_at,
    )
}

pub fn record_seq_step(
    sampler: &mut SequenceSampler,
    phase: SeqTaskPhase,
    latency_mode: u8,
    previous_step_at: &mut SampleClock,
) -> Vec<GroupedSequenceReport<SeqTaskPhase>> {
    sampler.record_with(
        phase,
        || phase.metric_name(),
        phase.expected_secs(latency_mode),
        previous_step_at,
    )
}
