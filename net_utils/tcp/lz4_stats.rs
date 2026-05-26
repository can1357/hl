//! Reconstructed from `/home/ubuntu/hl/code_Mainnet/net_utils/src/tcp/lz4_stats.rs`.
//!
//! Confidence: medium-high for the data flow and counters; medium for field names.
//! Seed EAs: 0x3D12780, 0x3D21990, 0x3D230C0, 0x3D2A730.
//! IDA anchors used in this source:
//! - `net_utils_tcp_lz4_stats__record_sample` (0x3D2A730): atomic input/output/sample updates plus the `tcp_lz4` trace event.
//! - `net_utils_tcp_lz4_stats__take_one_snapshot` (0x3D230C0): drains one non-empty stats bucket with `xchg(0)` and computes `output / input`.
//! - `net_utils_tcp_lz4_stats__drain_snapshots` (0x3D2BA50): repeatedly calls `take_one_snapshot` and builds a `Vec` of 0x20-byte snapshots.
//! - `net_utils_tcp_lz4_stats__report_once` (0x3D21990): waits on the timer, drains buckets, emits per-direction reports.
//! - `net_utils_tcp_lz4_stats__report_task_poll` (0x3D12780): outer async task; sleeps for 300.0s (`0x4072c00000000000`) between reports.
//!
//! Important recovered strings: tracing target `tcp_lz4`, event/field text
//! `tcp_lz4_stats`, `lz4_stats`, and direction labels `in` / `out`.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

pub const REPORT_INTERVAL: Duration = Duration::from_secs(300);

/// Recovered tracing target at rodata 0x202455.
pub const TRACE_TARGET: &str = "tcp_lz4";

/// Recovered event name at rodata 0x5BD05F.
pub const TRACE_EVENT: &str = "tcp_lz4_stats";

/// Recovered structured field name at rodata 0x5BD068.
pub const TRACE_FIELD: &str = "lz4_stats";

/// Error text used by the TCP read side when LZ4 decoding fails.
pub const DECOMPRESS_FAILURE_LOG: &str = "tcp::read_bytes decompression failure";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Lz4Direction {
    /// Inbound TCP payload: compressed bytes read from the peer, then expanded.
    In = 0,
    /// Outbound TCP payload: uncompressed bytes produced locally, then compressed.
    Out = 1,
}

impl Lz4Direction {
    #[inline]
    pub const fn label(self) -> &'static str {
        match self {
            Lz4Direction::In => "in",
            Lz4Direction::Out => "out",
        }
    }
}

impl fmt::Display for Lz4Direction {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Key packed into the 0x20-byte snapshot record by 0x3D230C0.
///
/// The binary copies four low bytes, then a u16, then the one-byte direction
/// discriminator; this struct keeps the same logical fields instead of exposing
/// the decompiler's packed integer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Lz4StatsKey {
    pub source_id: u32,
    pub site_id: u16,
    pub direction: Lz4Direction,
}

impl Lz4StatsKey {
    #[inline]
    pub const fn new(source_id: u32, site_id: u16, direction: Lz4Direction) -> Self {
        Self {
            source_id,
            site_id,
            direction,
        }
    }

    /// Mirrors the packed key shape reconstructed at 0x3D230C0.
    #[inline]
    pub const fn packed(self) -> u64 {
        (self.source_id as u64)
            | ((self.site_id as u64) << 32)
            | ((self.direction as u64) << 48)
    }
}

/// The per-callsite handle updated from tcp/read.rs and tcp/write.rs.
///
/// ArcInner+0x10: input byte total, output byte total, and sample count.
#[derive(Clone, Debug)]
pub struct Lz4Stats {
    input_bytes: Arc<AtomicU64>,
    output_bytes: Arc<AtomicU64>,
    samples: Arc<AtomicU64>,
    key: Lz4StatsKey,
}

impl Lz4Stats {
    #[inline]
    pub fn new(source_id: u32, site_id: u16, direction: Lz4Direction) -> Self {
        Self {
            input_bytes: Arc::new(AtomicU64::new(0)),
            output_bytes: Arc::new(AtomicU64::new(0)),
            samples: Arc::new(AtomicU64::new(0)),
            key: Lz4StatsKey::new(source_id, site_id, direction),
        }
    }

    #[inline]
    pub const fn key(&self) -> Lz4StatsKey {
        self.key
    }

    /// Record one compression or decompression operation.
    ///
    /// IDA: 0x3D2A730. The binary performs three relaxed-looking atomic updates
    /// (`lock add`, `lock add`, `lock inc`) and then, when the `tcp_lz4` callsite
    /// is enabled, emits a structured event containing the direction label and
    /// the floating-point elapsed value passed in `xmm0`.
    #[inline]
    pub fn record_sample(&self, input_len: usize, output_len: usize, elapsed_secs: f64) {
        let input_len = input_len as u64;
        let output_len = output_len as u64;

        self.input_bytes.fetch_add(input_len, Ordering::Relaxed);
        self.output_bytes.fetch_add(output_len, Ordering::Relaxed);
        self.samples.fetch_add(1, Ordering::Relaxed);

        global_bucket(self.key).record(input_len, output_len, elapsed_secs);

        // [INFERENCE] The compiled binary uses the tracing callsite machinery;
        // this hook is kept side-effect free in the reconstructed source so that
        // consumers can wire it to `tracing::event!` without changing counters.
        trace_lz4_sample(self.key.direction, input_len, output_len, elapsed_secs);
    }

    /// Drains only this handle's directly-owned counters.
    ///
    /// This mirrors the `xchg(0)` pattern used by the global snapshot path while
    /// preserving the per-handle structure seen at the start of 0x3D2A730.
    pub fn take_local_snapshot(&self) -> Option<Lz4StatsSnapshot> {
        let input_bytes = self.input_bytes.swap(0, Ordering::AcqRel);
        let output_bytes = self.output_bytes.swap(0, Ordering::AcqRel);
        let samples = self.samples.swap(0, Ordering::AcqRel);
        Lz4StatsSnapshot::new(self.key, input_bytes, output_bytes, samples, 0.0)
    }
}

/// One drained reporting row. The compiled record is 0x20 bytes:
/// packed key bytes, input bytes, samples, and an f64 ratio.
#[derive(Clone, Debug, PartialEq)]
pub struct Lz4StatsSnapshot {
    pub key: Lz4StatsKey,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub samples: u64,
    pub ratio: f64,
    pub elapsed_secs: f64,
}

impl Lz4StatsSnapshot {
    #[inline]
    pub fn new(
        key: Lz4StatsKey,
        input_bytes: u64,
        output_bytes: u64,
        samples: u64,
        elapsed_secs: f64,
    ) -> Option<Self> {
        if input_bytes == 0 {
            return None;
        }

        Some(Self {
            key,
            input_bytes,
            output_bytes,
            samples,
            ratio: output_bytes as f64 / input_bytes as f64,
            elapsed_secs,
        })
    }

    #[inline]
    pub fn direction(&self) -> Lz4Direction {
        self.key.direction
    }
}

impl fmt::Display for Lz4StatsSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Reconstructs the structured data emitted by 0x3D1DDE0/0x3D1E500 after
        // 0x3D21990 drains the bucket vector. The string labels are recovered;
        // punctuation is intentionally boring Rust formatting.
        write!(
            f,
            "{TRACE_EVENT} {TRACE_FIELD}={} input_bytes={} output_bytes={} samples={} ratio={:.6} elapsed_secs={:.6}",
            self.direction(),
            self.input_bytes,
            self.output_bytes,
            self.samples,
            self.ratio,
            self.elapsed_secs,
        )
    }
}

#[derive(Debug, Default)]
struct Lz4StatsBucket {
    input_bytes: AtomicU64,
    output_bytes: AtomicU64,
    samples: AtomicU64,
    elapsed_nanos: AtomicU64,
}

impl Lz4StatsBucket {
    #[inline]
    fn record(&self, input_bytes: u64, output_bytes: u64, elapsed_secs: f64) {
        self.input_bytes.fetch_add(input_bytes, Ordering::Relaxed);
        self.output_bytes.fetch_add(output_bytes, Ordering::Relaxed);
        self.samples.fetch_add(1, Ordering::Relaxed);

        if elapsed_secs.is_finite() && elapsed_secs > 0.0 {
            let nanos = elapsed_secs.mul_add(1_000_000_000.0, 0.0) as u64;
            self.elapsed_nanos.fetch_add(nanos, Ordering::Relaxed);
        }
    }

    /// IDA: 0x3D230C0. Drains a bucket by `xchg(0)` on each counter, skips empty
    /// input totals, and computes `output_bytes as f64 / input_bytes as f64`.
    #[inline]
    fn take_snapshot(&self, key: Lz4StatsKey) -> Option<Lz4StatsSnapshot> {
        let input_bytes = self.input_bytes.swap(0, Ordering::AcqRel);
        let output_bytes = self.output_bytes.swap(0, Ordering::AcqRel);
        let samples = self.samples.swap(0, Ordering::AcqRel);
        let elapsed_nanos = self.elapsed_nanos.swap(0, Ordering::AcqRel);
        Lz4StatsSnapshot::new(
            key,
            input_bytes,
            output_bytes,
            samples,
            elapsed_nanos as f64 / 1_000_000_000.0,
        )
    }
}

static BUCKETS: LazyLock<Mutex<HashMap<Lz4StatsKey, Arc<Lz4StatsBucket>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn global_bucket(key: Lz4StatsKey) -> Arc<Lz4StatsBucket> {
    let mut buckets = BUCKETS.lock().expect("lz4 stats mutex poisoned");
    let bucket = buckets
        .entry(key)
        .or_insert_with(|| Arc::new(Lz4StatsBucket::default()));
    Arc::clone(bucket)
}

/// Connection to tcp/read.rs. For inbound LZ4, `input_len` is compressed frame
/// payload bytes and `output_len` is decompressed bincode bytes.
#[inline]
pub fn record_inbound_decompression(
    stats: &Lz4Stats,
    compressed_len: usize,
    decompressed_len: usize,
    elapsed_secs: f64,
) {
    debug_assert_eq!(stats.key.direction, Lz4Direction::In);
    stats.record_sample(compressed_len, decompressed_len, elapsed_secs);
}

/// Connection to tcp/write.rs. For outbound LZ4, `input_len` is serialized
/// bincode bytes and `output_len` is compressed frame payload bytes.
#[inline]
pub fn record_outbound_compression(
    stats: &Lz4Stats,
    uncompressed_len: usize,
    compressed_len: usize,
    elapsed_secs: f64,
) {
    debug_assert_eq!(stats.key.direction, Lz4Direction::Out);
    stats.record_sample(uncompressed_len, compressed_len, elapsed_secs);
}

/// IDA: 0x3D230C0 + 0x3D2BA50.
///
/// The compiled code walks the hash table control bytes, drains each selected
/// bucket into three output totals, and allocates/grows a `Vec` of 0x20-byte
/// records. This source keeps the same semantics with a locked `HashMap` only
/// for lookup/removal; byte counters are still atomically drained.
pub fn drain_snapshots() -> Vec<Lz4StatsSnapshot> {
    let entries: Vec<(Lz4StatsKey, Arc<Lz4StatsBucket>)> = {
        let buckets = BUCKETS.lock().expect("lz4 stats mutex poisoned");
        buckets
            .iter()
            .map(|(&key, bucket)| (key, Arc::clone(bucket)))
            .collect()
    };

    let mut snapshots = Vec::with_capacity(entries.len());
    for (key, bucket) in entries {
        if let Some(snapshot) = bucket.take_snapshot(key) {
            snapshots.push(snapshot);
        }
    }
    snapshots
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Lz4Report {
    pub inbound: Option<Lz4DirectionReport>,
    pub outbound: Option<Lz4DirectionReport>,
    pub snapshots: Vec<Lz4StatsSnapshot>,
}

impl Lz4Report {
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    pub fn lines(&self) -> impl Iterator<Item = Cow<'_, str>> {
        self.snapshots.iter().map(|snapshot| Cow::Owned(snapshot.to_string()))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Lz4DirectionReport {
    pub direction: Lz4Direction,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub samples: u64,
    pub ratio: f64,
}

impl Lz4DirectionReport {
    fn new(direction: Lz4Direction, snapshots: &[Lz4StatsSnapshot]) -> Option<Self> {
        let mut input_bytes = 0_u64;
        let mut output_bytes = 0_u64;
        let mut samples = 0_u64;

        for snapshot in snapshots
            .iter()
            .filter(|snapshot| snapshot.direction() == direction)
        {
            input_bytes = input_bytes.saturating_add(snapshot.input_bytes);
            output_bytes = output_bytes.saturating_add(snapshot.output_bytes);
            samples = samples.saturating_add(snapshot.samples);
        }

        if input_bytes == 0 {
            return None;
        }

        Some(Self {
            direction,
            input_bytes,
            output_bytes,
            samples,
            ratio: output_bytes as f64 / input_bytes as f64,
        })
    }
}

impl fmt::Display for Lz4DirectionReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{TRACE_EVENT} direction={} input_bytes={} output_bytes={} samples={} ratio={:.6}",
            self.direction,
            self.input_bytes,
            self.output_bytes,
            self.samples,
            self.ratio,
        )
    }
}

/// IDA: 0x3D21990. Drain all current buckets and prepare one report for the
/// inbound side plus one for the outbound side. The binary routes the non-empty
/// report vectors through two formatting helpers at 0x3D1DDE0 and 0x3D1E500.
pub fn report_once() -> Lz4Report {
    let snapshots = drain_snapshots();
    let inbound = Lz4DirectionReport::new(Lz4Direction::In, &snapshots);
    let outbound = Lz4DirectionReport::new(Lz4Direction::Out, &snapshots);

    Lz4Report {
        inbound,
        outbound,
        snapshots,
    }
}

/// Formatting helper for callers that want the exact recovered strings in a
/// single log line rather than structured fields.
pub fn format_report(report: &Lz4Report) -> String {
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

/// IDA: 0x3D12780. The recovered outer future repeatedly sleeps for 300 seconds,
/// then invokes the 0x3D21990 report path. This synchronous helper exposes the
/// body of one tick; async scheduling belongs in the caller.
#[inline]
pub fn report_task_tick() -> Lz4Report {
    report_once()
}

#[inline]
fn trace_lz4_sample(
    _direction: Lz4Direction,
    _input_bytes: u64,
    _output_bytes: u64,
    _elapsed_secs: f64,
) {
    // The optimized binary gates this behind tracing callsite state and returns
    // immediately when the callsite is disabled. Reconstructed as a no-op hook.
}
