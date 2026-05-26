#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::net_utils::abci_latency_sampler::LatencySampler;

const CONSENSUS_METRIC_PREFIX: &str = "consensus/";
const HANDLE_STATE_INPUT_PREFIX: &str = "HandleStateInput::";

const HANDLE_STATE_INPUT_LAST: u8 = 0x0e;
const HANDLE_ALL_STATE_INPUTS: u8 = 0x0f;
const BLOCK_GAP: u8 = 0x10;
const WALL_CLOCK_BLOCK_GAP: u8 = 0x11;
const TX_COMMIT: u8 = 0x12;
const EXPENSIVE_STATUS: u8 = 0x13;

const DEFAULT_BUCKET_LIMIT_MULT_THRESHOLD: f64 = 1.0;
const HANDLE_INPUT_BUCKET_LIMIT_MULT_THRESHOLD: f64 = 0.25;
const SAMPLED_EVERY_N: u32 = 50;

/// Lazily-created latency samplers keyed by the compact consensus-latency id.
///
/// Recovered layout at `0x4A11410`: the field passed by callers is a 24-byte
/// `BTreeMap<u8, LatencySampler>` (`root`, `height`, `len`).  Values are base
/// latency samplers (`0x260` bytes in the binary); this reconstruction reuses
/// the same sampler abstraction already used by `net_utils::abci_latency_sampler`.
#[derive(Clone, Debug, Default)]
pub struct ConsensusLatencySamplers {
    pub samplers: BTreeMap<u8, LatencySampler>,
}

impl ConsensusLatencySamplers {
    pub fn new() -> Self {
        Self { samplers: BTreeMap::new() }
    }

    /// Record a recovered raw latency id.
    ///
    /// The binary's callers use ids `0x00..=0x13`.  `0x00..=0x0e` are formatted
    /// as `consensus/HandleStateInput::<id>`, and `0x0f..=0x13` are fixed
    /// aggregate buckets.  Invalid ids are unreachable from the observed call
    /// sites; returning `false` keeps the reconstructed API total.
    pub fn record_raw(&mut self, id: u8, elapsed_secs: f64) -> bool {
        let Some(kind) = ConsensusLatencyKind::from_raw(id) else {
            return false;
        };
        self.record(kind, elapsed_secs)
    }

    /// Recovered update path (`0x4A11410`).
    ///
    /// The original code eagerly formats the metric name before the BTreeMap
    /// lookup, then calls the base sampler's `record_sample(1, elapsed_secs)`.
    /// `HandleAllStateInputs` is additionally gated by a thread-local RNG:
    /// only one out of fifty events reaches the base sampler, whose sampled flag
    /// accounts for the `50x` count multiplier in reports.
    pub fn record(&mut self, kind: ConsensusLatencyKind, elapsed_secs: f64) -> bool {
        let options = kind.options();
        let metric_name = kind.metric_name();
        let id = kind.raw_id();

        let sampler = self.samplers.entry(id).or_insert_with(|| {
            LatencySampler::new(metric_name, options.bucket_limit_mult_threshold())
        });

        if options.sample_one_in_fifty && !sample_one_in_fifty() {
            return false;
        }

        sampler.record(elapsed_secs);
        true
    }

    #[inline]
    pub fn get(&self, kind: ConsensusLatencyKind) -> Option<&LatencySampler> {
        self.samplers.get(&kind.raw_id())
    }

    #[inline]
    pub fn get_raw(&self, id: u8) -> Option<&LatencySampler> {
        self.samplers.get(&id)
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (ConsensusLatencyKind, &LatencySampler)> + '_ {
        self.samplers.iter().filter_map(|(&id, sampler)| {
            ConsensusLatencyKind::from_raw(id).map(|kind| (kind, sampler))
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ConsensusLatencyKind {
    HandleStateInput(u8),
    HandleAllStateInputs,
    BlockGap,
    WallClockBlockGap,
    TxCommit,
    ExpensiveStatus,
}

impl ConsensusLatencyKind {
    #[inline]
    pub const fn from_raw(id: u8) -> Option<Self> {
        match id {
            0..=HANDLE_STATE_INPUT_LAST => Some(Self::HandleStateInput(id)),
            HANDLE_ALL_STATE_INPUTS => Some(Self::HandleAllStateInputs),
            BLOCK_GAP => Some(Self::BlockGap),
            WALL_CLOCK_BLOCK_GAP => Some(Self::WallClockBlockGap),
            TX_COMMIT => Some(Self::TxCommit),
            EXPENSIVE_STATUS => Some(Self::ExpensiveStatus),
            _ => None,
        }
    }

    #[inline]
    pub const fn raw_id(self) -> u8 {
        match self {
            Self::HandleStateInput(id) => id,
            Self::HandleAllStateInputs => HANDLE_ALL_STATE_INPUTS,
            Self::BlockGap => BLOCK_GAP,
            Self::WallClockBlockGap => WALL_CLOCK_BLOCK_GAP,
            Self::TxCommit => TX_COMMIT,
            Self::ExpensiveStatus => EXPENSIVE_STATUS,
        }
    }

    #[inline]
    pub const fn options(self) -> ConsensusLatencyOptions {
        match self {
            Self::HandleStateInput(_) | Self::HandleAllStateInputs | Self::ExpensiveStatus => {
                ConsensusLatencyOptions {
                    low_threshold_bucket: true,
                    sample_one_in_fifty: matches!(self, Self::HandleAllStateInputs),
                }
            }
            Self::BlockGap | Self::WallClockBlockGap | Self::TxCommit => {
                ConsensusLatencyOptions { low_threshold_bucket: false, sample_one_in_fifty: false }
            }
        }
    }

    pub fn metric_name(self) -> String {
        match self {
            Self::HandleStateInput(id) => {
                let mut name = String::with_capacity(
                    CONSENSUS_METRIC_PREFIX.len() + HANDLE_STATE_INPUT_PREFIX.len() + 3,
                );
                name.push_str(CONSENSUS_METRIC_PREFIX);
                name.push_str(HANDLE_STATE_INPUT_PREFIX);
                push_u8_decimal(&mut name, id);
                name
            }
            Self::HandleAllStateInputs => fixed_metric_name("HandleAllStateInputs"),
            Self::BlockGap => fixed_metric_name("BlockGap"),
            Self::WallClockBlockGap => fixed_metric_name("WallClockBlockGap"),
            Self::TxCommit => fixed_metric_name("TxCommit"),
            Self::ExpensiveStatus => fixed_metric_name("ExpensiveStatus"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsensusLatencyOptions {
    /// When set, the base sampler is initialized with the recovered `0.25`
    /// threshold (`src[0] = 1`, `src[1] = 0x3fd0_0000_0000_0000` at `0x4957D90`).
    pub low_threshold_bucket: bool,
    /// Recovered sampled flag at base-sampler offset `+0x25c`; record path calls
    /// the RNG modulo `50` before recording `HandleAllStateInputs`.
    pub sample_one_in_fifty: bool,
}

impl ConsensusLatencyOptions {
    #[inline]
    pub const fn bucket_limit_mult_threshold(self) -> f64 {
        if self.low_threshold_bucket {
            HANDLE_INPUT_BUCKET_LIMIT_MULT_THRESHOLD
        } else {
            DEFAULT_BUCKET_LIMIT_MULT_THRESHOLD
        }
    }

    #[inline]
    pub const fn report_weight(self) -> u32 {
        if self.sample_one_in_fifty { SAMPLED_EVERY_N } else { 1 }
    }
}

fn fixed_metric_name(suffix: &str) -> String {
    let mut name = String::with_capacity(CONSENSUS_METRIC_PREFIX.len() + suffix.len());
    name.push_str(CONSENSUS_METRIC_PREFIX);
    name.push_str(suffix);
    name
}

fn push_u8_decimal(out: &mut String, n: u8) {
    if n >= 100 {
        out.push(char::from(b'0' + n / 100));
        out.push(char::from(b'0' + (n / 10) % 10));
        out.push(char::from(b'0' + n % 10));
    } else if n >= 10 {
        out.push(char::from(b'0' + n / 10));
        out.push(char::from(b'0' + n % 10));
    } else {
        out.push(char::from(b'0' + n));
    }
}

#[inline]
fn sample_one_in_fifty() -> bool {
    rand::random_range(0..SAMPLED_EVERY_N) == 0
}
