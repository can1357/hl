//! Reconstructed from `/home/ubuntu/hl/code_Mainnet/net_utils/src/tcp/traffic_recorder.rs`.
//!
//! Confidence: high for the atomic byte-drain shape, waker handoff, 30 second
//! report cadence, direction strings, and trace strings; medium for field names
//! inside the counter block because the binary keeps most of this state in
//! optimized async-future frames and tracing metadata tables.
//!
//! Seed EAs: `0x3D13CD0`, `0x3D21670`.
//!
//! IDA anchors used in this source:
//! - `0x3D13CD0`: per-recorder async poll/update path. It reads the shared
//!   recorder pointer from the future, snapshots `Instant::now`, initializes a
//!   one-shot first-sample flag, atomically drains the pending byte counter with
//!   `xchg(0)`, updates multiple `Arc<AtomicU64>` counters, stores/replaces a
//!   task waker under an atomic state word, and polls a 30 second sleep before
//!   running the logging/drain path.
//! - `0x3D21670`: report task poll path for the traffic logger. It polls a
//!   30 second sleep (`0x403e000000000000`), drains the global bucket table, and
//!   emits separate `In` and `Out` reports through formatting helpers.
//! - `0x3D0EEE0`: reusable sleep future initialized from an `f64` seconds value;
//!   the traffic-recorder caller passes `30.0`.
//! - `0x3D1DA50`, `0x3D1DDE0`, `0x3D1E500`: formatting/logging helpers reached
//!   after draining buckets.
//! - rodata near `0x5BC78D`: `tcp_traffic`, `traffic_logger`, `In`, `Out`, and
//!   `profiled_rw_lock_increment`.
//!
//! IDA updates attempted but blocked by the shared queue:
//! - `0x3D13CD0` -> `net_utils_tcp_traffic_recorder__poll_connection_recorder`
//! - `0x3D21670` -> `net_utils_tcp_traffic_recorder__poll_report_task`
//! - pending comments for both function entries with the source path and purpose.

#![allow(dead_code)]

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::task::Waker;
use std::time::{Duration, Instant};

/// `0x403e000000000000` in both recovered traffic-recorder poll loops.
pub const REPORT_INTERVAL: Duration = Duration::from_secs(30);

/// Recovered tracing target at rodata `0x5BC78D`.
pub const TRACE_TARGET: &str = "tcp_traffic";

/// Recovered event name at rodata `0x5BC798`.
pub const TRACE_EVENT: &str = "traffic_logger";

/// Recovered label used by callsites that attribute lock traffic separately.
pub const PROFILED_RW_LOCK_INCREMENT: &str = "profiled_rw_lock_increment";

const NANOS_PER_SEC: u64 = 1_000_000_000;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum TrafficDirection {
    In = 0,
    Out = 1,
}

impl TrafficDirection {
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::In => "In",
            Self::Out => "Out",
        }
    }
}

impl fmt::Display for TrafficDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Key used for the global traffic buckets drained by `0x3D21670`.
///
/// The binary's concrete key is packed into tracing/formatting frames. Keeping
/// the label as a string mirrors the recovered behavior at source level: each
/// read/write site records bytes under a direction and a static task label.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TrafficKey {
    pub direction: TrafficDirection,
    pub label: &'static str,
}

impl TrafficKey {
    #[inline]
    pub const fn new(direction: TrafficDirection, label: &'static str) -> Self {
        Self { direction, label }
    }
}

/// Shared handle held by TCP read/write code.
///
/// `0x3D13CD0` drains `inner.pending_bytes` with an atomic exchange, records the
/// elapsed time since the previous sample, then arms/reuses a timer. `record_*`
/// functions below are the thin read/write-side entry points: they only add to
/// the pending counter and wake the logger if a task waker is installed.
#[derive(Clone, Debug)]
pub struct TrafficRecorder {
    inner: Arc<TrafficRecorderInner>,
}

#[derive(Debug)]
struct TrafficRecorderInner {
    key: TrafficKey,
    pending_bytes: AtomicU64,
    first_update_seen: AtomicBool,
    last_sample_time: Mutex<Instant>,
    last_drain_budget_nanos: AtomicU64,
    waker: Mutex<Option<Waker>>,
    counters: Arc<TrafficCounters>,
}

/// Counter block updated by `0x3D13CD0`.
///
/// The offset names below match observed atomic-update groups rather than a
/// confirmed Rust struct layout:
/// - stats+0x18: incremented once when a recorder is first sampled.
/// - stats+0x20 and stats+0x60: increment/add when drained bytes exceed the
///   previous per-future budget field.
/// - stats+0x28: incremented for every non-empty drain.
/// - stats+0x58: initial elapsed nanos from recorder creation to first sample.
/// - stats+0x68: elapsed nanos accumulated across non-empty drains.
/// - stats+0x30/0x38/0x40/0x48 and stats+0x70/0x78/0x80/0x88: paired
///   count/byte totals selected by timestamp comparisons; represented here by
///   per-direction buckets.
#[derive(Debug, Default)]
pub struct TrafficCounters {
    first_samples: AtomicU64,
    budget_overruns: AtomicU64,
    non_empty_drains: AtomicU64,
    first_sample_elapsed_nanos: AtomicU64,
    budget_overrun_bytes: AtomicU64,
    active_elapsed_nanos: AtomicU64,
    inbound_samples: AtomicU64,
    inbound_bytes: AtomicU64,
    outbound_samples: AtomicU64,
    outbound_bytes: AtomicU64,
}

impl TrafficCounters {
    #[inline]
    pub fn snapshot(&self) -> TrafficCountersSnapshot {
        TrafficCountersSnapshot {
            first_samples: self.first_samples.load(Ordering::Relaxed),
            budget_overruns: self.budget_overruns.load(Ordering::Relaxed),
            non_empty_drains: self.non_empty_drains.load(Ordering::Relaxed),
            first_sample_elapsed_nanos: self.first_sample_elapsed_nanos.load(Ordering::Relaxed),
            budget_overrun_bytes: self.budget_overrun_bytes.load(Ordering::Relaxed),
            active_elapsed_nanos: self.active_elapsed_nanos.load(Ordering::Relaxed),
            inbound_samples: self.inbound_samples.load(Ordering::Relaxed),
            inbound_bytes: self.inbound_bytes.load(Ordering::Relaxed),
            outbound_samples: self.outbound_samples.load(Ordering::Relaxed),
            outbound_bytes: self.outbound_bytes.load(Ordering::Relaxed),
        }
    }

    #[inline]
    fn record_direction(&self, direction: TrafficDirection, bytes: u64) {
        match direction {
            TrafficDirection::In => {
                self.inbound_samples.fetch_add(1, Ordering::Relaxed);
                self.inbound_bytes.fetch_add(bytes, Ordering::Relaxed);
            }
            TrafficDirection::Out => {
                self.outbound_samples.fetch_add(1, Ordering::Relaxed);
                self.outbound_bytes.fetch_add(bytes, Ordering::Relaxed);
            }
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrafficCountersSnapshot {
    pub first_samples: u64,
    pub budget_overruns: u64,
    pub non_empty_drains: u64,
    pub first_sample_elapsed_nanos: u64,
    pub budget_overrun_bytes: u64,
    pub active_elapsed_nanos: u64,
    pub inbound_samples: u64,
    pub inbound_bytes: u64,
    pub outbound_samples: u64,
    pub outbound_bytes: u64,
}

impl TrafficRecorder {
    #[inline]
    pub fn new(direction: TrafficDirection, label: &'static str) -> Self {
        Self::with_counters(direction, label, Arc::new(TrafficCounters::default()))
    }

    #[inline]
    pub fn with_counters(
        direction: TrafficDirection,
        label: &'static str,
        counters: Arc<TrafficCounters>,
    ) -> Self {
        Self {
            inner: Arc::new(TrafficRecorderInner {
                key: TrafficKey::new(direction, label),
                pending_bytes: AtomicU64::new(0),
                first_update_seen: AtomicBool::new(false),
                last_sample_time: Mutex::new(Instant::now()),
                last_drain_budget_nanos: AtomicU64::new(0),
                waker: Mutex::new(None),
                counters,
            }),
        }
    }

    #[inline]
    pub fn key(&self) -> TrafficKey {
        self.inner.key
    }

    #[inline]
    pub fn counters(&self) -> &Arc<TrafficCounters> {
        &self.inner.counters
    }

    /// Read/write-side increment path.
    ///
    /// This is the source-level counterpart of the producer side consumed by the
    /// `xchg(0)` at `0x3D13D92` / `0x3D14463`. The producer does not format or
    /// allocate; it only increments the pending byte count and wakes one stored
    /// logger waker.
    #[inline]
    pub fn record_bytes(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }

        self.inner.pending_bytes.fetch_add(bytes as u64, Ordering::Relaxed);

        if let Some(waker) = self.inner.waker.lock().expect("traffic recorder waker poisoned").take()
        {
            waker.wake();
        }
    }

    /// Install or replace the task waker used by the async logger.
    ///
    /// `0x3D13ED1..0x3D13F7D` performs this under a small atomic state machine;
    /// a mutex expresses the same single-waker replacement semantics directly.
    pub fn register_waker(&self, waker: &Waker) {
        let mut slot = self.inner.waker.lock().expect("traffic recorder waker poisoned");
        match &*slot {
            Some(existing) if existing.will_wake(waker) => {}
            _ => *slot = Some(waker.clone()),
        }
    }

    /// Drain pending bytes and update counters once.
    ///
    /// The first call records startup elapsed time separately, matching the
    /// stats+0x18/stats+0x58 writes. Non-empty drains update sample counters,
    /// elapsed-time totals, per-direction byte totals, and the global bucket used
    /// by the 30 second report task.
    pub fn update_once(&self, now: Instant) -> Option<TrafficSample> {
        if !self.inner.first_update_seen.swap(true, Ordering::AcqRel) {
            let first_elapsed = now
                .saturating_duration_since(*self.inner.last_sample_time.lock().expect("traffic recorder time poisoned"))
                .as_nanos()
                .min(u64::MAX as u128) as u64;
            self.inner.counters.first_samples.fetch_add(1, Ordering::Relaxed);
            self.inner
                .counters
                .first_sample_elapsed_nanos
                .fetch_add(first_elapsed, Ordering::Relaxed);
        }

        let bytes = self.inner.pending_bytes.swap(0, Ordering::AcqRel);
        if bytes == 0 {
            return None;
        }

        let previous_budget = self.inner.last_drain_budget_nanos.load(Ordering::Relaxed);
        if bytes > previous_budget {
            self.inner.counters.budget_overruns.fetch_add(1, Ordering::Relaxed);
            self.inner
                .counters
                .budget_overrun_bytes
                .fetch_add(bytes - previous_budget, Ordering::Relaxed);
        }

        let mut last_sample_time = self.inner.last_sample_time.lock().expect("traffic recorder time poisoned");
        let elapsed = now.saturating_duration_since(*last_sample_time);
        *last_sample_time = now;
        drop(last_sample_time);

        let elapsed_nanos = elapsed.as_nanos().min(u64::MAX as u128) as u64;
        self.inner
            .last_drain_budget_nanos
            .store(elapsed_nanos, Ordering::Relaxed);
        self.inner.counters.non_empty_drains.fetch_add(1, Ordering::Relaxed);
        self.inner
            .counters
            .active_elapsed_nanos
            .fetch_add(elapsed_nanos, Ordering::Relaxed);
        self.inner.counters.record_direction(self.inner.key.direction, bytes);

        let sample = TrafficSample {
            key: self.inner.key,
            bytes,
            elapsed_nanos,
        };
        global_bucket(self.inner.key).record(bytes, elapsed_nanos);
        trace_traffic_sample(&sample);
        Some(sample)
    }

    #[inline]
    pub fn pending_bytes(&self) -> u64 {
        self.inner.pending_bytes.load(Ordering::Relaxed)
    }
}

/// Connection to `tcp/read.rs`: record bytes received from a framed read.
#[inline]
pub fn record_read_bytes(recorder: &TrafficRecorder, payload_len: usize) {
    debug_assert_eq!(recorder.key().direction, TrafficDirection::In);
    recorder.record_bytes(payload_len);
}

/// Connection to `tcp/write.rs`: record raw bytes handed to the framed writer.
#[inline]
pub fn record_write_bytes(recorder: &TrafficRecorder, payload_len: usize) {
    debug_assert_eq!(recorder.key().direction, TrafficDirection::Out);
    recorder.record_bytes(payload_len);
}

/// Connection to `tcp/write.rs::TcpWriteStats` without depending on that type.
///
/// The writer records the payload length before framing/compression; callers that
/// want on-the-wire accounting should pass `header + compressed_len` instead.
#[inline]
pub fn record_write_lengths(
    recorder: &TrafficRecorder,
    raw_len: usize,
    compressed_len: Option<usize>,
    include_frame_header: bool,
) {
    let payload_len = compressed_len.unwrap_or(raw_len);
    let frame_header_len = if include_frame_header { 5 } else { 0 };
    let wire_len = payload_len.saturating_add(frame_header_len);
    record_write_bytes(recorder, wire_len);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrafficSample {
    pub key: TrafficKey,
    pub bytes: u64,
    pub elapsed_nanos: u64,
}

impl TrafficSample {
    #[inline]
    pub fn bytes_per_second(&self) -> f64 {
        if self.elapsed_nanos == 0 {
            return 0.0;
        }
        self.bytes as f64 * NANOS_PER_SEC as f64 / self.elapsed_nanos as f64
    }
}

#[derive(Debug, Default)]
struct TrafficBucket {
    bytes: AtomicU64,
    elapsed_nanos: AtomicU64,
    samples: AtomicU64,
}

impl TrafficBucket {
    #[inline]
    fn record(&self, bytes: u64, elapsed_nanos: u64) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        self.elapsed_nanos.fetch_add(elapsed_nanos, Ordering::Relaxed);
        self.samples.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn drain(&self, key: TrafficKey) -> Option<TrafficSnapshot> {
        let bytes = self.bytes.swap(0, Ordering::AcqRel);
        let elapsed_nanos = self.elapsed_nanos.swap(0, Ordering::AcqRel);
        let samples = self.samples.swap(0, Ordering::AcqRel);

        if bytes == 0 && samples == 0 {
            return None;
        }

        Some(TrafficSnapshot {
            key,
            bytes,
            elapsed_nanos,
            samples,
        })
    }
}

static BUCKETS: LazyLock<Mutex<HashMap<TrafficKey, Arc<TrafficBucket>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn global_bucket(key: TrafficKey) -> Arc<TrafficBucket> {
    let mut buckets = BUCKETS.lock().expect("traffic recorder buckets poisoned");
    buckets.entry(key).or_default().clone()
}

/// Drains all traffic buckets.
///
/// `0x3D21670` initializes three output slots, drains a global hash table under a
/// one-byte lock, formats any non-empty direction report, then frees the vector
/// of drained records. This direct representation preserves the atomic drain and
/// keeps the grouping explicit.
pub fn drain_snapshots() -> Vec<TrafficSnapshot> {
    let buckets: Vec<(TrafficKey, Arc<TrafficBucket>)> = {
        let buckets = BUCKETS.lock().expect("traffic recorder buckets poisoned");
        buckets.iter().map(|(key, bucket)| (*key, Arc::clone(bucket))).collect()
    };

    let mut snapshots = Vec::new();
    for (key, bucket) in buckets {
        if let Some(snapshot) = bucket.drain(key) {
            snapshots.push(snapshot);
        }
    }
    snapshots
}

#[derive(Clone, Debug, PartialEq)]
pub struct TrafficSnapshot {
    pub key: TrafficKey,
    pub bytes: u64,
    pub elapsed_nanos: u64,
    pub samples: u64,
}

impl TrafficSnapshot {
    #[inline]
    pub fn direction(&self) -> TrafficDirection {
        self.key.direction
    }

    #[inline]
    pub fn bytes_per_second(&self) -> f64 {
        if self.elapsed_nanos == 0 {
            return 0.0;
        }
        self.bytes as f64 * NANOS_PER_SEC as f64 / self.elapsed_nanos as f64
    }
}

impl fmt::Display for TrafficSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{TRACE_EVENT} direction={} label={} bytes={} samples={} elapsed_nanos={} bytes_per_second={:.3}",
            self.direction(),
            self.key.label,
            self.bytes,
            self.samples,
            self.elapsed_nanos,
            self.bytes_per_second(),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TrafficReport {
    pub inbound: Option<TrafficDirectionReport>,
    pub outbound: Option<TrafficDirectionReport>,
    pub snapshots: Vec<TrafficSnapshot>,
}

impl TrafficReport {
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    pub fn lines(&self) -> impl Iterator<Item = Cow<'_, str>> {
        self.snapshots.iter().map(|snapshot| Cow::Owned(snapshot.to_string()))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TrafficDirectionReport {
    pub direction: TrafficDirection,
    pub bytes: u64,
    pub samples: u64,
    pub elapsed_nanos: u64,
    pub bytes_per_second: f64,
}

impl TrafficDirectionReport {
    fn new(direction: TrafficDirection, snapshots: &[TrafficSnapshot]) -> Option<Self> {
        let mut bytes = 0_u64;
        let mut samples = 0_u64;
        let mut elapsed_nanos = 0_u64;

        for snapshot in snapshots
            .iter()
            .filter(|snapshot| snapshot.direction() == direction)
        {
            bytes = bytes.saturating_add(snapshot.bytes);
            samples = samples.saturating_add(snapshot.samples);
            elapsed_nanos = elapsed_nanos.saturating_add(snapshot.elapsed_nanos);
        }

        if bytes == 0 && samples == 0 {
            return None;
        }

        let bytes_per_second = if elapsed_nanos == 0 {
            0.0
        } else {
            bytes as f64 * NANOS_PER_SEC as f64 / elapsed_nanos as f64
        };

        Some(Self {
            direction,
            bytes,
            samples,
            elapsed_nanos,
            bytes_per_second,
        })
    }
}

impl fmt::Display for TrafficDirectionReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{TRACE_EVENT} direction={} bytes={} samples={} elapsed_nanos={} bytes_per_second={:.3}",
            self.direction,
            self.bytes,
            self.samples,
            self.elapsed_nanos,
            self.bytes_per_second,
        )
    }
}

/// IDA: `0x3D21670` body after the 30 second sleep resolves.
pub fn report_once() -> TrafficReport {
    let snapshots = drain_snapshots();
    let inbound = TrafficDirectionReport::new(TrafficDirection::In, &snapshots);
    let outbound = TrafficDirectionReport::new(TrafficDirection::Out, &snapshots);

    TrafficReport {
        inbound,
        outbound,
        snapshots,
    }
}

/// Formatting helper for callsites that want the recovered event strings in
/// plain log lines rather than structured tracing values.
pub fn format_report(report: &TrafficReport) -> String {
    let mut rendered = String::new();

    if let Some(inbound) = &report.inbound {
        rendered.push_str(&inbound.to_string());
    }
    if let Some(outbound) = &report.outbound {
        if !rendered.is_empty() {
            rendered.push('\n');
        }
        rendered.push_str(&outbound.to_string());
    }
    for snapshot in &report.snapshots {
        if !rendered.is_empty() {
            rendered.push('\n');
        }
        rendered.push_str(&snapshot.to_string());
    }

    rendered
}

/// Source-level body of one logger tick. The compiled futures loop forever:
/// sleep for 30 seconds, drain/report, reset sleep, and return `Pending`.
#[inline]
pub fn report_task_tick() -> TrafficReport {
    report_once()
}

#[inline]
fn trace_traffic_sample(_sample: &TrafficSample) {
    // The binary routes samples through `tracing` with target `tcp_traffic` and
    // event `traffic_logger`; reconstructed source keeps the side effect at the
    // report boundary to avoid depending on the tracing crate here.
}
