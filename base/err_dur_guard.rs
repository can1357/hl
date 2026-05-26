use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::latency_sampler::LatencySampler;

/// A compact wall-clock timestamp matching the `std::sys::pal::unix::time::Timespec::now`
/// values used by the recovered guard code.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Timespec {
    pub seconds: i64,
    pub nanos: u32,
}

impl Timespec {
    pub fn now() -> Self {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => Self {
                seconds: duration.as_secs().min(i64::MAX as u64) as i64,
                nanos: duration.subsec_nanos(),
            },
            Err(_) => Self { seconds: 0, nanos: 0 },
        }
    }

    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        if self <= earlier {
            return Duration::ZERO;
        }

        let mut seconds = (self.seconds - earlier.seconds) as u64;
        let nanos = if self.nanos >= earlier.nanos {
            self.nanos - earlier.nanos
        } else {
            seconds = seconds.saturating_sub(1);
            1_000_000_000 + self.nanos - earlier.nanos
        };
        Duration::new(seconds, nanos)
    }
}

/// Persistent state for a duration-window rate limiter.
///
/// The wrapper monomorphs at `0x2702420`, `0x4CEEC70`, and `0x4CEEE00` compute
/// `current_millis / interval_millis`, compare it with the stored bucket, and only
/// run the guarded work when the bucket advances.
#[derive(Clone, Debug)]
pub struct DurationWindow {
    interval: Duration,
    last_bucket: u64,
}

impl DurationWindow {
    pub fn new(interval: Duration) -> Self {
        Self { interval, last_bucket: 0 }
    }

    pub fn check(&mut self, now: Timespec) -> bool {
        let interval_ms = saturating_u128_to_u64(self.interval.as_millis().max(1));
        let bucket = unix_millis(now) / interval_ms;
        if bucket > self.last_bucket {
            self.last_bucket = bucket;
            true
        } else {
            false
        }
    }

    pub fn last_bucket(&self) -> u64 {
        self.last_bucket
    }
}

/// Tracks a repeated error condition across guard windows.
///
/// The recovered code has a leading `f64` threshold and two optional timestamps. When no
/// errors are produced in a guarded window, both timestamps are cleared. When errors continue,
/// the first timestamp is preserved and the latest timestamp is refreshed before the threshold
/// check.
#[derive(Clone, Debug)]
pub struct ErrDurState {
    pub max_error_duration: Duration,
    first_error_at: Option<Timespec>,
    last_error_at: Option<Timespec>,
}

impl ErrDurState {
    pub fn new(max_error_duration: Duration) -> Self {
        Self {
            max_error_duration,
            first_error_at: None,
            last_error_at: None,
        }
    }

    pub fn clear(&mut self) {
        self.first_error_at = None;
        self.last_error_at = None;
    }

    pub fn update(&mut self, now: Timespec, has_error: bool) -> Option<Duration> {
        if !has_error {
            self.clear();
            return None;
        }

        let first = *self.first_error_at.get_or_insert(now);
        self.last_error_at = Some(now);

        let elapsed = now.saturating_duration_since(first);
        (elapsed > self.max_error_duration).then_some(elapsed)
    }

    pub fn first_error_at(&self) -> Option<Timespec> {
        self.first_error_at
    }

    pub fn last_error_at(&self) -> Option<Timespec> {
        self.last_error_at
    }
}

/// Result emitted by guarded work.
///
/// The binary stores either an empty condition or a non-empty vector/string-like error payload;
/// the exact inner error type is monomorph-specific, so this reconstruction preserves the
/// guard-relevant distinction and message text.
#[derive(Clone, Debug, Default)]
pub struct GuardOutcome {
    errors: Vec<String>,
}

impl GuardOutcome {
    pub fn ok() -> Self {
        Self { errors: Vec::new() }
    }

    pub fn from_error(error: impl Into<String>) -> Self {
        Self { errors: vec![error.into()] }
    }

    pub fn from_errors(errors: Vec<String>) -> Self {
        Self { errors }
    }

    pub fn has_error(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn errors(&self) -> &[String] {
        &self.errors
    }
}

/// Rate-limits expensive work, records its duration, and escalates repeated errors.
///
/// Recovered monomorphs `0x222AF40`, `0x4713110`, and `0x4715760` start by checking a byte
/// flag at offset `0x20`; when false, they return immediately. When true, they timestamp before
/// and after the guarded work, update `ErrDurState`, call the critical-message path after the
/// repeated-error threshold, and record one elapsed-duration sample in a process-wide sampler
/// keyed by `name`.
pub struct ErrDurGuard<'a> {
    pub name: &'a str,
    pub enabled: bool,
    pub window: DurationWindow,
    pub error_state: ErrDurState,
    pub latency_bucket_limit_mult_threshold: f64,
}

impl<'a> ErrDurGuard<'a> {
    pub fn new(
        name: &'a str,
        interval: Duration,
        max_error_duration: Duration,
        latency_bucket_limit_mult_threshold: f64,
    ) -> Self {
        Self {
            name,
            enabled: true,
            window: DurationWindow::new(interval),
            error_state: ErrDurState::new(max_error_duration),
            latency_bucket_limit_mult_threshold,
        }
    }

    pub fn disabled(
        name: &'a str,
        interval: Duration,
        max_error_duration: Duration,
        latency_bucket_limit_mult_threshold: f64,
    ) -> Self {
        let mut guard = Self::new(
            name,
            interval,
            max_error_duration,
            latency_bucket_limit_mult_threshold,
        );
        guard.enabled = false;
        guard
    }

    pub fn check(&mut self) -> bool {
        self.enabled && self.window.check(Timespec::now())
    }

    pub fn update<F>(&mut self, work: F) -> bool
    where
        F: FnOnce() -> GuardOutcome,
    {
        let now = Timespec::now();
        if !self.enabled || !self.window.check(now) {
            return false;
        }

        let started = now;
        let outcome = work();
        let finished = Timespec::now();
        let elapsed = finished.saturating_duration_since(started).as_secs_f64();

        self.update_error_state(finished, &outcome);
        record_guard_duration(self.name, self.latency_bucket_limit_mult_threshold, elapsed);
        true
    }

    pub fn update_error_state(&mut self, now: Timespec, outcome: &GuardOutcome) {
        if let Some(duration) = self.error_state.update(now, outcome.has_error()) {
            emit_repeated_error_crit_msg(self.name, duration, outcome);
        }
    }
}

static LATENCY_SAMPLERS: LazyLock<Mutex<BTreeMap<String, LatencySampler>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

fn record_guard_duration(name: &str, bucket_limit_mult_threshold: f64, seconds: f64) {
    let mut samplers = LATENCY_SAMPLERS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let sampler = samplers
        .entry(name.to_owned())
        .or_insert_with(|| LatencySampler::new(name, bucket_limit_mult_threshold));
    sampler.record(seconds);
}

fn emit_repeated_error_crit_msg(name: &str, duration: Duration, outcome: &GuardOutcome) {
    let message = if outcome.errors.is_empty() {
        format!("{name} has been erroring for {:?}", duration)
    } else {
        format!("{name} has been erroring for {:?}: {:?}", duration, outcome.errors)
    };

    crate::crit_msg::crit_msg("err_dur_guard", message);
}

fn unix_millis(ts: Timespec) -> u64 {
    if ts.seconds <= 0 {
        0
    } else {
        (ts.seconds as u64)
            .saturating_mul(1_000)
            .saturating_add((ts.nanos / 1_000_000) as u64)
    }
}

fn saturating_u128_to_u64(value: u128) -> u64 {
    value.min(u64::MAX as u128) as u64
}
