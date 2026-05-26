use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const MILLIS_PER_SECOND: u64 = 1_000;
const MILLIS_PER_DAY: u64 = 86_400_000;
const NANOS_PER_MILLI: u32 = 1_000_000;
const RAW_MUTEX_WAIT_NANOS: u64 = 1_000_000_000;
const LATENCY_SAMPLER_PREFIX: &str = "bucket_guard/";
const SLOW_ABCI_ENGINE: &str = "slow_abci_engine";

static BUCKET_GUARD_LATENCIES: LazyLock<Mutex<BTreeMap<String, Vec<f64>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// A compact fixed-window cursor. Serde visitors recovered in the binary accept either
/// `{ "last_bucket": ..., "bucket_millis": ... }` or a two-element sequence and reject
/// duplicate/missing fields through serde's standard helpers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct BucketGuard {
    pub last_bucket: u64,
    pub bucket_millis: u64,
}

impl BucketGuard {
    pub const fn new(bucket_millis: u64) -> Self {
        Self {
            last_bucket: 0,
            bucket_millis,
        }
    }

    pub const fn with_last_bucket(last_bucket: u64, bucket_millis: u64) -> Self {
        Self {
            last_bucket,
            bucket_millis,
        }
    }

    pub fn current_bucket(&self) -> u64 {
        self.bucket_for_millis(utc_now_millis())
    }

    #[inline]
    pub fn bucket_for_millis(&self, utc_millis: u64) -> u64 {
        utc_millis / self.bucket_millis
    }

    /// Advance to `now_millis / bucket_millis`. Returns true only when a new bucket is seen.
    pub fn advance_to_millis(&mut self, now_millis: u64) -> bool {
        let bucket = self.bucket_for_millis(now_millis);
        if bucket > self.last_bucket {
            self.last_bucket = bucket;
            true
        } else {
            false
        }
    }

    pub fn advance_to_now(&mut self) -> bool {
        self.advance_to_millis(utc_now_millis())
    }

    pub fn next_bucket_start_millis(&self) -> u64 {
        self.last_bucket
            .saturating_add(1)
            .saturating_mul(self.bucket_millis)
    }

    pub fn last_bucket_start_millis(&self) -> u64 {
        self.last_bucket.saturating_mul(self.bucket_millis)
    }

    pub fn last_bucket_start_datetime(&self) -> NaiveDateTimeParts {
        millis_product_to_datetime(self.last_bucket, self.bucket_millis)
            .expect("called `Result::unwrap()` on an `Err` value")
    }
}

/// Same serialized shape as `BucketGuard`; it appears under the open-interest guard name in
/// serializer monomorphs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct OpenInterestBucketGuard {
    pub last_bucket: u64,
    pub bucket_millis: u64,
}

impl From<BucketGuard> for OpenInterestBucketGuard {
    fn from(value: BucketGuard) -> Self {
        Self {
            last_bucket: value.last_bucket,
            bucket_millis: value.bucket_millis,
        }
    }
}

impl From<OpenInterestBucketGuard> for BucketGuard {
    fn from(value: OpenInterestBucketGuard) -> Self {
        Self {
            last_bucket: value.last_bucket,
            bucket_millis: value.bucket_millis,
        }
    }
}

/// Configuration for callers that allow more than one item per bucket.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct BucketLimits {
    pub bucket_millis: u64,
    pub n_per_bucket: u64,
}

impl BucketLimits {
    pub const fn new(bucket_millis: u64, n_per_bucket: u64) -> Self {
        Self {
            bucket_millis,
            n_per_bucket,
        }
    }

    pub fn from_bucket_seconds(bucket_seconds: u64, n_per_bucket: u64) -> Result<Self, BucketLimitError> {
        let bucket_millis = bucket_seconds
            .checked_mul(MILLIS_PER_SECOND)
            .filter(|millis| *millis != 0)
            .ok_or(BucketLimitError::InvalidBucketSeconds)?;
        Ok(Self::new(bucket_millis, n_per_bucket))
    }

    #[inline]
    pub fn allows(self, count_in_bucket: u64) -> bool {
        count_in_bucket <= self.n_per_bucket
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BucketLimitError {
    InvalidBucketSeconds,
}

impl fmt::Display for BucketLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBucketSeconds => f.write_str("Invalid bucket seconds"),
        }
    }
}

impl std::error::Error for BucketLimitError {}

/// A fixed-window counter protected by the one-byte raw mutex shape emitted in the binary.
pub struct BucketCounter {
    lock: ByteMutex,
    pub bucket_millis: u64,
    pub last_bucket: u64,
    pub n_this_bucket: u64,
}

impl fmt::Debug for BucketCounter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BucketCounter")
            .field("bucket_millis", &self.bucket_millis)
            .field("last_bucket", &self.last_bucket)
            .field("n_this_bucket", &self.n_this_bucket)
            .finish()
    }
}

impl BucketCounter {
    pub const fn new(bucket_millis: u64) -> Self {
        Self {
            lock: ByteMutex::new(),
            bucket_millis,
            last_bucket: 0,
            n_this_bucket: 0,
        }
    }

    pub fn guard(&mut self, name: &'static str, limits: BucketLimits) -> AcquiredBucketGuard {
        let count = self.increment_now();
        AcquiredBucketGuard::new(name, limits.allows(count), 0.0, 10)
    }

    pub fn guard_at(
        &mut self,
        name: &'static str,
        limits: BucketLimits,
        utc_millis: u64,
    ) -> AcquiredBucketGuard {
        let count = self.increment_at(utc_millis);
        AcquiredBucketGuard::new(name, limits.allows(count), 0.0, 10)
    }

    pub fn increment_now(&mut self) -> u64 {
        self.increment_at(utc_now_millis())
    }

    /// Lock, roll the bucket if needed, then saturating-increment the per-bucket count.
    pub fn increment_at(&mut self, utc_millis: u64) -> u64 {
        let _guard = self.lock.lock();
        self.increment_at_locked(utc_millis, None)
    }

    /// Same accounting path used by the slow ABCI-engine poll wrappers: a bucket advance
    /// resets the count and emits a latency sample, then the count is incremented with
    /// `u64::MAX` saturation.
    pub fn increment_after_timed_work(&mut self, started: Instant) -> u64 {
        let _guard = self.lock.lock();
        self.increment_at_locked(utc_now_millis(), Some((SLOW_ABCI_ENGINE, started.elapsed())))
    }

    pub fn reset_count(&mut self) {
        let _guard = self.lock.lock();
        self.n_this_bucket = 0;
    }

    pub fn snapshot(&self) -> BucketCounterSnapshot {
        BucketCounterSnapshot {
            bucket_millis: self.bucket_millis,
            last_bucket: self.last_bucket,
            n_this_bucket: self.n_this_bucket,
        }
    }

    fn increment_at_locked(
        &mut self,
        utc_millis: u64,
        latency_on_advance: Option<(&'static str, Duration)>,
    ) -> u64 {
        let bucket = utc_millis / self.bucket_millis;
        if bucket > self.last_bucket {
            self.last_bucket = bucket;
            self.n_this_bucket = 0;
            if let Some((name, elapsed)) = latency_on_advance {
                record_bucket_guard_latency(name, elapsed.as_secs_f64());
            }
        }

        self.n_this_bucket = self.n_this_bucket.saturating_add(1);
        self.n_this_bucket
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BucketCounterSnapshot {
    pub bucket_millis: u64,
    pub last_bucket: u64,
    pub n_this_bucket: u64,
}

/// The stack object passed into the many monomorphized `run_if_acquired` wrappers.
#[derive(Clone, Copy, Debug)]
pub struct AcquiredBucketGuard {
    pub name: &'static str,
    pub bucket_limit_mult_threshold: f64,
    pub sampler_bucket_len: u64,
    pub acquired: bool,
}

impl AcquiredBucketGuard {
    pub const fn new(
        name: &'static str,
        acquired: bool,
        bucket_limit_mult_threshold: f64,
        sampler_bucket_len: u64,
    ) -> Self {
        Self {
            name,
            bucket_limit_mult_threshold,
            sampler_bucket_len,
            acquired,
        }
    }

    pub fn from_count(name: &'static str, count: u64, limits: BucketLimits) -> Self {
        Self::new(name, limits.allows(count), 0.0, 10)
    }

    pub fn from_bucket_advance(
        name: &'static str,
        current_bucket: u64,
        previous_bucket: u64,
        bucket_limit_mult_threshold: f64,
        sampler_bucket_len: u64,
    ) -> Self {
        Self::new(
            name,
            current_bucket > previous_bucket,
            bucket_limit_mult_threshold,
            sampler_bucket_len,
        )
    }

    pub fn acquired(self) -> bool {
        self.acquired
    }

    /// Runs `work` only for an acquired bucket/permit and records elapsed seconds under
    /// `bucket_guard/<name>` after successful execution.
    pub fn run_if_acquired<R>(self, work: impl FnOnce() -> R) -> Option<R> {
        if !self.acquired {
            return None;
        }

        let started = Instant::now();
        let result = work();
        self.record_elapsed(started.elapsed());
        Some(result)
    }

    /// Variant matching monomorphs that append closure-produced vectors into a caller-owned
    /// destination before recording the latency sample.
    pub fn extend_if_acquired<T>(self, out: &mut Vec<T>, work: impl FnOnce() -> Vec<T>) -> bool {
        if !self.acquired {
            return false;
        }

        let started = Instant::now();
        out.extend(work());
        self.record_elapsed(started.elapsed());
        true
    }

    pub fn record_elapsed(self, elapsed: Duration) {
        record_bucket_guard_latency(self.name, elapsed.as_secs_f64());
    }
}

#[derive(Debug)]
struct ByteMutex(AtomicU8);

impl ByteMutex {
    const fn new() -> Self {
        Self(AtomicU8::new(0))
    }

    fn lock(&self) -> ByteMutexGuard<'_> {
        if self
            .0
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            self.lock_slow(RAW_MUTEX_WAIT_NANOS);
        }
        ByteMutexGuard { mutex: self }
    }

    fn lock_slow(&self, _wait_nanos: u64) {
        while self
            .0
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::thread::yield_now();
        }
    }

    fn unlock(&self) {
        if self
            .0
            .compare_exchange(1, 0, Ordering::Release, Ordering::Relaxed)
            .is_err()
        {
            self.unlock_slow();
        }
    }

    fn unlock_slow(&self) {
        self.0.store(0, Ordering::Release);
    }
}

struct ByteMutexGuard<'a> {
    mutex: &'a ByteMutex,
}

impl Drop for ByteMutexGuard<'_> {
    fn drop(&mut self) {
        self.mutex.unlock();
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NaiveDateTimeParts {
    pub days_from_ce: i32,
    pub seconds_from_midnight: u32,
    pub nanos: u32,
}

/// Recovered helper that multiplies a bucket number by bucket width in milliseconds.
/// Arithmetic overflow saturates to `u64::MAX`; out-of-range chrono conversion returns an
/// error that callers unwrap in the observed path.
pub fn millis_product_to_datetime(
    bucket: u64,
    bucket_millis: u64,
) -> Result<NaiveDateTimeParts, DateTimeRangeError> {
    let unix_millis = bucket.checked_mul(bucket_millis).unwrap_or(u64::MAX);
    datetime_from_unix_millis(unix_millis)
}

pub fn datetime_from_unix_millis(unix_millis: u64) -> Result<NaiveDateTimeParts, DateTimeRangeError> {
    let unix_days = unix_millis / MILLIS_PER_DAY;
    let days_from_ce = unix_days
        .checked_add(719_163)
        .and_then(|days| i32::try_from(days).ok())
        .ok_or(DateTimeRangeError { millis: unix_millis })?;

    let millis_of_day = unix_millis % MILLIS_PER_DAY;
    Ok(NaiveDateTimeParts {
        days_from_ce,
        seconds_from_midnight: (millis_of_day / MILLIS_PER_SECOND) as u32,
        nanos: ((millis_of_day % MILLIS_PER_SECOND) as u32) * NANOS_PER_MILLI,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DateTimeRangeError {
    pub millis: u64,
}

impl fmt::Display for DateTimeRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unix millisecond timestamp out of range: {}", self.millis)
    }
}

impl std::error::Error for DateTimeRangeError {}

/// Debug-only helper recovered from the `FixedWindowRoller` formatting impl.
pub struct FixedWindowRoller {
    pub pattern: u32,
    pub compression: RollerCompression,
    pub count: u64,
}

impl fmt::Debug for FixedWindowRoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixedWindowRoller")
            .field("pattern", &self.pattern)
            .field("compression", &self.compression)
            .field("count", &self.count)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollerCompression {
    None,
    Exact,
    Approximate,
}

fn utc_now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn record_bucket_guard_latency(name: &str, elapsed_secs: f64) {
    let key = if name.starts_with(LATENCY_SAMPLER_PREFIX) {
        name.to_owned()
    } else {
        let mut key = String::with_capacity(LATENCY_SAMPLER_PREFIX.len() + name.len());
        key.push_str(LATENCY_SAMPLER_PREFIX);
        key.push_str(name);
        key
    };

    let mut samples = BUCKET_GUARD_LATENCIES
        .lock()
        .expect("bucket guard latency sampler mutex poisoned");
    samples.entry(key).or_default().push(elapsed_secs);
}

pub fn recorded_bucket_guard_latencies(name: &str) -> Vec<f64> {
    let key = if name.starts_with(LATENCY_SAMPLER_PREFIX) {
        name.to_owned()
    } else {
        let mut key = String::with_capacity(LATENCY_SAMPLER_PREFIX.len() + name.len());
        key.push_str(LATENCY_SAMPLER_PREFIX);
        key.push_str(name);
        key
    };

    BUCKET_GUARD_LATENCIES
        .lock()
        .expect("bucket guard latency sampler mutex poisoned")
        .get(&key)
        .cloned()
        .unwrap_or_default()
}
