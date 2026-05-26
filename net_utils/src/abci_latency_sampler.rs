//! Recovered from `/home/ubuntu/hl/code_Mainnet/net_utils/src/abci_latency_sampler.rs`.
//!
//! Confidence: medium-high for the public state transitions and constants, medium for
//! concrete helper type names.  The seeds are reached through a trait/vtable relocation
//! cluster at `0x5776558..0x5776568`.
//!
//! IDA/local anchors:
//! - `0x3D22AA0`: constructor.  Builds three latency samplers named
//!   `<prefix>_block_duration`, `<prefix>_backlog_from_node`, and
//!   `<prefix>_begin_block_to_commit`; copies an auxiliary block-times reporter and
//!   clears the optional last-times slot at sampler offset `+0x7d0`.
//! - `0x3D22920`: begin-block/update path.  Samples block-to-block wall duration,
//!   optionally samples backlog from the node-provided ABCI block timestamp, then stores
//!   `{ block_time, begin_block_wall_time }` at offset `+0x7d0`.
//! - `0x3D22500`: commit/report path.  Samples begin-block-to-commit duration capped
//!   at 60 seconds, rotates daily/hourly output when the wall-clock day/hour changes,
//!   and appends one JSON-line row containing height, block_time,
//!   begin_block_wall_time, and apply_duration.
//! - `0x3D2258C`, `0x3D22971`: source-location references to this file for checked
//!   time subtraction.  Adjacent strings are `block_time`,
//!   `begin_block_wall_time`, and `apply_duration`.
//!
//! The concrete metric sink and line-writer types are represented as small Rust
//! facades.  Their observed binary footprint is large (`0x260` bytes for each latency
//! sampler) but the recovered behavior below is the load-bearing logic.

use std::fmt::{self, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SOURCE_PATH: &str = "/home/ubuntu/hl/code_Mainnet/net_utils/src/abci_latency_sampler.rs";
const BLOCK_DURATION_SUFFIX: &str = "_block_duration";
const BACKLOG_FROM_NODE_SUFFIX: &str = "_backlog_from_node";
const BEGIN_BLOCK_TO_COMMIT_SUFFIX: &str = "_begin_block_to_commit";
const BLOCK_TIMES_SUFFIX: &str = "_block_times";

const APPLY_DURATION_CAP_SECS: f64 = 60.0;
const SECONDS_PER_HOUR: u32 = 3_600;
const SECONDS_PER_DAY: i64 = 86_400;
const CHRONO_SECONDS_PANIC_CUTOFF: u32 = 90_000;
const CHRONO_SECONDS_OUTER_CUTOFF: u32 = 921_600;

#[derive(Clone, Debug, Default)]
pub struct AbciLatencySampler {
    /// Offset `+0x000`, constructed from `<prefix>_block_duration` at `0x3D22B12`.
    pub block_duration: LatencySampler,
    /// Offset `+0x260`, constructed from `<prefix>_backlog_from_node` at `0x3D22B72`.
    pub backlog_from_node: LatencySampler,
    /// Offset `+0x4c0`, constructed from `<prefix>_begin_block_to_commit` at `0x3D22BC3`.
    pub begin_block_to_commit: LatencySampler,
    /// Offset `+0x720`; owns the rotating JSON-lines output for block-time rows.
    pub block_times: BlockTimesReporter,
    /// Offset `+0x7d0`; the binary tests the first word for zero as the None niche.
    pub last_times: Option<LastAbciTimes>,
}

impl AbciLatencySampler {
    /// Recovered constructor (`0x3D22AA0`).
    ///
    /// `prefix` is formatted with three metric suffixes and one reporter suffix.  The
    /// binary uses temporary `String`s and then memcopies three `0x260`-byte sampler
    /// values into the output object.
    pub fn new(
        prefix: &str,
        block_times_root: impl Into<String>,
        bucket_limit_mult_threshold: f64,
        rotate_hourly: bool,
    ) -> Self {
        let block_duration = LatencySampler::new(
            joined_metric_name(prefix, BLOCK_DURATION_SUFFIX),
            bucket_limit_mult_threshold,
        );
        let backlog_from_node = LatencySampler::new(
            joined_metric_name(prefix, BACKLOG_FROM_NODE_SUFFIX),
            bucket_limit_mult_threshold,
        );
        let begin_block_to_commit = LatencySampler::new(
            joined_metric_name(prefix, BEGIN_BLOCK_TO_COMMIT_SUFFIX),
            bucket_limit_mult_threshold,
        );
        let block_times = BlockTimesReporter::new(
            joined_metric_name(prefix, BLOCK_TIMES_SUFFIX),
            block_times_root.into(),
            rotate_hourly,
        );

        Self {
            block_duration,
            backlog_from_node,
            begin_block_to_commit,
            block_times,
            last_times: None,
        }
    }

    /// Recovered begin-block path (`0x3D22920`).
    ///
    /// The real routine obtains `Utc::now()` internally at `0x3D22932`.  This wrapper
    /// preserves that shape while `begin_block_at` exposes the timestamp for deterministic
    /// reconstruction checks.
    pub fn begin_block(&mut self, block_time: AbciTime, came_from_node: bool) {
        self.begin_block_at(block_time, came_from_node, AbciTime::now_utc_lossy());
    }

    /// Recovered begin-block path with an injected wall time.
    pub fn begin_block_at(&mut self, block_time: AbciTime, came_from_node: bool, now: AbciTime) {
        if let Some(last) = self.last_times {
            // `0x3D2293D..0x3D229C7`: use the previous begin-block wall timestamp,
            // cap the result at 60 seconds, and sample offset `+0x000`.
            if let Some(duration) = now.duration_since(last.begin_block_wall_time) {
                self.block_duration
                    .record(duration.as_secs_f64().min(APPLY_DURATION_CAP_SECS));
            }
        }

        if came_from_node {
            // `0x3D229D4..0x3D22A44`: only this conditional branch samples the
            // `_backlog_from_node` metric.  No `minsd 60.0` appears on this branch.
            if let Some(duration) = now.duration_since(block_time) {
                self.backlog_from_node.record(duration.as_secs_f64());
            }
        }

        // `0x3D22A4A..0x3D22A88`: raw 24-byte copy of the block timestamp followed by
        // the current begin-block wall timestamp into the optional slot.
        self.last_times = Some(LastAbciTimes {
            block_time,
            begin_block_wall_time: now,
        });
    }

    /// Recovered commit/report path (`0x3D22500`).
    ///
    /// The single non-`self` argument is used as the JSON row height.  The row uses the
    /// timestamp pair saved by `begin_block_at`; if begin-block was never called the
    /// binary returns immediately after fetching the wall clock.
    pub fn commit_block(&mut self, height: u64) {
        self.commit_block_at(height, AbciTime::now_utc_lossy());
    }

    /// Recovered commit/report path with an injected wall time.
    pub fn commit_block_at(&mut self, height: u64, now: AbciTime) {
        let Some(last) = self.last_times else {
            return;
        };

        // `0x3D22567..0x3D225F5`: compute current wall time minus the last
        // begin-block wall time and cap it at 60 seconds before sampling offset `+0x4c0`.
        let Some(raw_apply_duration) = now.duration_since(last.begin_block_wall_time) else {
            return;
        };
        let apply_duration = raw_apply_duration.as_secs_f64().min(APPLY_DURATION_CAP_SECS);
        self.begin_block_to_commit.record(apply_duration);

        // `0x3D22621..0x3D22808`: validate chrono's second-of-day field, then rotate
        // the reporter when the date or enabled hourly bucket changes.
        self.block_times.ensure_period(now);

        // `0x3D22812..0x3D22839`: serialize and append the block-time row.
        self.block_times.append(BlockTimeRow {
            height,
            block_time: last.block_time,
            begin_block_wall_time: last.begin_block_wall_time,
            apply_duration,
        });

        // `0x3D22854..0x3D22881`: a flag at `+0x7ca` gates an optional flush call.
        if self.block_times.flush_on_commit {
            self.block_times.flush();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LastAbciTimes {
    pub block_time: AbciTime,
    pub begin_block_wall_time: AbciTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbciTime {
    /// Recovered from the first 32-bit word of chrono's compact date/time value.
    pub day: i32,
    /// Recovered from `0x18(%rsp)` checks against `0x15f90` and division by 3600.
    pub seconds_from_midnight: u32,
    /// Recovered from the trailing 32-bit word copied with each timestamp.
    pub nanos: u32,
}

impl AbciTime {
    pub fn new(day: i32, seconds_from_midnight: u32, nanos: u32) -> Self {
        validate_chrono_seconds(seconds_from_midnight);
        Self {
            day,
            seconds_from_midnight,
            nanos,
        }
    }

    pub fn now_utc_lossy() -> Self {
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        let days = (dur.as_secs() / SECONDS_PER_DAY as u64) as i32;
        let seconds_from_midnight = (dur.as_secs() % SECONDS_PER_DAY as u64) as u32;
        Self::new(days, seconds_from_midnight, dur.subsec_nanos())
    }

    pub fn hour(self) -> u8 {
        validate_chrono_seconds(self.seconds_from_midnight);
        (self.seconds_from_midnight / SECONDS_PER_HOUR) as u8
    }

    pub fn duration_since(self, earlier: Self) -> Option<Duration> {
        let lhs = self.to_total_nanos()?;
        let rhs = earlier.to_total_nanos()?;
        lhs.checked_sub(rhs).map(Duration::from_nanos)
    }

    fn to_total_nanos(self) -> Option<u64> {
        validate_chrono_seconds(self.seconds_from_midnight);
        let days = i64::from(self.day);
        let secs = days
            .checked_mul(SECONDS_PER_DAY)?
            .checked_add(i64::from(self.seconds_from_midnight))?;
        if secs < 0 {
            return None;
        }
        let nanos = (secs as u64)
            .checked_mul(1_000_000_000)?
            .checked_add(u64::from(self.nanos))?;
        Some(nanos)
    }
}

fn validate_chrono_seconds(seconds_from_midnight: u32) {
    // `0x3D22621..0x3D22635`: the compiler emits two range checks.  Values at or
    // above 90_000 take the panic path using this source file; 921_600 is the outer
    // arithmetic sanity bound reached before that path.
    assert!(
        seconds_from_midnight < CHRONO_SECONDS_OUTER_CUTOFF,
        "chrono second field outside outer bound in {SOURCE_PATH}"
    );
    assert!(
        seconds_from_midnight < CHRONO_SECONDS_PANIC_CUTOFF,
        "chrono second field outside day bound in {SOURCE_PATH}"
    );
}

#[derive(Clone, Debug, Default)]
pub struct LatencySampler {
    pub name: String,
    pub bucket_limit_mult_threshold: f64,
    pub observations: Vec<f64>,
}

impl LatencySampler {
    pub fn new(name: String, bucket_limit_mult_threshold: f64) -> Self {
        Self {
            name,
            bucket_limit_mult_threshold,
            observations: Vec::new(),
        }
    }

    pub fn record(&mut self, seconds: f64) {
        if seconds.is_finite() && seconds >= 0.0 {
            self.observations.push(seconds);
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockTimesReporter {
    pub task_name: String,
    pub root: String,
    pub rotate_hourly: bool,
    pub last_day: Option<i32>,
    pub last_hour: Option<u8>,
    pub current_path: Option<String>,
    pub rows: Vec<String>,
    pub flush_count: u64,
    pub flush_on_commit: bool,
}

impl BlockTimesReporter {
    pub fn new(task_name: String, root: String, rotate_hourly: bool) -> Self {
        Self {
            task_name,
            root,
            rotate_hourly,
            last_day: None,
            last_hour: None,
            current_path: None,
            rows: Vec::new(),
            flush_count: 0,
            flush_on_commit: false,
        }
    }

    pub fn ensure_period(&mut self, now: AbciTime) {
        validate_chrono_seconds(now.seconds_from_midnight);
        let hour = now.hour();
        let rotate = if self.rotate_hourly {
            self.last_day != Some(now.day) || self.last_hour != Some(hour)
        } else {
            self.last_day != Some(now.day)
        };

        if rotate {
            self.current_path = Some(if self.rotate_hourly {
                // `0x3D22653..0x3D2266A` computes `seconds / 3600` via multiply by
                // `0x91a2b3c5` and shift by 43, then uses the hourly branch.
                format!("{}/hourly/{}/{}", self.root, now.day, hour)
            } else {
                format!("{}/{}", self.root, now.day)
            });
            self.last_day = Some(now.day);
            if self.rotate_hourly {
                self.last_hour = Some(hour);
            }
        }
    }

    pub fn append(&mut self, row: BlockTimeRow) {
        let mut json = String::with_capacity(128);
        let _ = write!(
            json,
            "{{\"height\":{},\"block_time\":{},\"begin_block_wall_time\":{},\"apply_duration\":{} }}",
            row.height,
            JsonTime(row.block_time),
            JsonTime(row.begin_block_wall_time),
            row.apply_duration
        );
        self.rows.push(json);
    }

    pub fn flush(&mut self) {
        self.flush_count = self.flush_count.saturating_add(1);
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BlockTimeRow {
    pub height: u64,
    pub block_time: AbciTime,
    pub begin_block_wall_time: AbciTime,
    pub apply_duration: f64,
}

struct JsonTime(AbciTime);

impl fmt::Display for JsonTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = self.0;
        write!(
            f,
            "{{\"day\":{},\"seconds_from_midnight\":{},\"nanos\":{}}}",
            t.day, t.seconds_from_midnight, t.nanos
        )
    }
}

fn joined_metric_name(prefix: &str, suffix: &str) -> String {
    let mut out = String::with_capacity(prefix.len() + suffix.len());
    out.push_str(prefix);
    out.push_str(suffix);
    out
}
