//! Recovered async/logging utility helpers.
//!
//! This module is dominated by generic async poll monomorphs.  The repeated
//! bodies collapse to a small set of source-level helpers: f64-second sleeps,
//! timeout wrappers, spawn-forever supervision, scheduled observer reporting,
//! and latency/stat snapshots.

use std::collections::HashMap;
use std::fmt::{self, Debug, Display};
use core::future::{poll_fn as core_poll_fn, Future};
use std::hash::Hash;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration as StdDuration;

use tokio::task::JoinHandle;

use crate::latency_sampler::LatencySampler;
use crate::sender::CrashSender;

const NANOS_PER_SEC: u64 = 1_000_000_000;
const MICROS_PER_SEC: u64 = 1_000_000;
const STAT_REPORT_SLEEP_SECS: f64 = 60.0;
const FAST_SCHEDULED_OBSERVER_SECS: f64 = 1.0;
const SLOW_SCHEDULED_OBSERVER_SECS: f64 = 30.0;
const PER_NAME_LATENCY_ALPHA: f64 = 0.1;
const TCP_COMPRESSION_ALPHA_DEFAULT: f64 = 0.3;
const TCP_COMPRESSION_ALPHA_SPECIAL: f64 = 1.0;

const TOKIO_OK_ENDED: &str = "tokio_spawn_forever ended in an Ok variant";
const TOKIO_ERROR_PREFIX: &str = "tokio_spawn_forever error ";
const TOKIO_END_PREFIX: &str = "crashing process because tokio_spawn_forever ended";
const THREAD_OK_ENDED: &str = "crashing because thread_spawn_forever ended";
const THREAD_ERROR_PREFIX: &str = "crashing because thread_spawn_forever ended with error, err=";
const TOKIO_SPAWN_FOREVER_LABEL: &str = "tokio_spawn_forever";
const THREAD_SPAWN_FOREVER_LABEL: &str = "thread_spawn_forever";
const TOKIO_SCHEDULED_OBSERVER_LABEL: &str = "tokio_scheduled_observer";
const ASYNC_WAIT_INNER_LABEL: &str = "async_wait_inner";
const TOKIO_SPAWN_FOREVER_OUTER_PREFIX: &str = "tokio_spawn_forever_outer: ";
const CRASHER_PREFIX: &str = "Crasher: ";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeoutError {
    Elapsed,
}

impl Display for TimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeoutError::Elapsed => f.write_str("timeout elapsed"),
        }
    }
}

impl std::error::Error for TimeoutError {}

/// Convert recovered `f64` seconds into a `std::time::Duration`.
///
/// Some poll bodies inline `Duration::try_from_secs_f64(...).unwrap()`.  Other
/// hot loops multiply by 1e6, round, clamp, and split microseconds.  This helper
/// uses the checked std conversion for the sleep constructors and preserves the
/// same panic behavior for negative, NaN, or overflowing values.
pub fn duration_from_secs_f64(seconds: f64) -> StdDuration {
    StdDuration::try_from_secs_f64(seconds).unwrap()
}

pub fn duration_from_secs_f64_micros(seconds: f64) -> StdDuration {
    assert!(seconds >= 0.0);
    let micros = (seconds * MICROS_PER_SEC as f64).round().clamp(0.0, u64::MAX as f64) as u64;
    StdDuration::new(
        micros / MICROS_PER_SEC,
        ((micros % MICROS_PER_SEC) * 1_000) as u32,
    )
}

pub async fn sleep_secs_f64(seconds: f64) {
    if seconds == 0.0 {
        return;
    }
    tokio::time::sleep(duration_from_secs_f64(seconds)).await;
}

/// Explicit source-level form of the large generated sleep poll state.
pub struct SleepSecs {
    seconds: f64,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    completed: bool,
}

impl SleepSecs {
    pub fn new(seconds: f64) -> Self {
        Self { seconds, sleep: None, completed: false }
    }
}

impl Future for SleepSecs {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.completed {
            panic!("`async fn` resumed after completion");
        }
        if self.seconds == 0.0 {
            self.completed = true;
            return Poll::Ready(());
        }
        if self.sleep.is_none() {
            self.sleep = Some(Box::pin(tokio::time::sleep(duration_from_secs_f64(self.seconds))));
        }
        match self.sleep.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => {
                self.sleep = None;
                self.completed = true;
                Poll::Ready(())
            }
        }
    }
}

pub async fn periodic_sleep_then_call<F, Fut>(delay_secs: f64, mut make_future: F) -> !
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    loop {
        sleep_secs_f64(delay_secs).await;
        make_future().await;
    }
}

/// Future wrapper whose generated polls test the inner future before polling the timer.
pub struct Timeout<F> {
    label: String,
    inner: F,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl<F> Timeout<F> {
    pub fn new(label: impl Into<String>, seconds: f64, inner: F) -> Self {
        Self {
            label: label.into(),
            inner,
            sleep: Box::pin(tokio::time::sleep(duration_from_secs_f64(seconds))),
        }
    }

    pub fn label(&self) -> &str {
        &self.label
    }
}

impl<F> Future for Timeout<F>
where
    F: Future + Unpin,
{
    type Output = Result<F::Output, TimeoutError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Poll::Ready(value) = Pin::new(&mut self.inner).poll(cx) {
            return Poll::Ready(Ok(value));
        }
        if self.sleep.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(TimeoutError::Elapsed));
        }
        Poll::Pending
    }
}

pub async fn timeout<F>(label: impl Into<String>, seconds: f64, inner: F) -> Result<F::Output, TimeoutError>
where
    F: Future + Unpin,
{
    Timeout::new(label, seconds, inner).await
}

pub async fn async_wait_inner<F>(name: &str, inner: F) -> F::Output
where
    F: Future,
{
    trace_event(ASYNC_WAIT_INNER_LABEL, name);
    inner.await
}

#[derive(Clone, Debug, Default)]
pub struct CrasherToken {
    pub name: String,
}

pub fn register_tokio_spawn_forever(label: &str, task_name: &str, token: CrasherToken) {
    let display_name = format!("{CRASHER_PREFIX}{task_name}");
    register_crasher(label, display_name, token);
}

fn register_crasher(label: &str, display_name: String, token: CrasherToken) {
    trace_event(label, &display_name);
    let _ = token;
}

pub fn tokio_spawn_forever_outer<F, E>(name: impl Into<String>, future: F, crash_sender: CrashSender) -> JoinHandle<()>
where
    F: Future<Output = Result<(), E>> + Send + 'static,
    E: Debug + Send + 'static,
{
    let name = name.into();
    emit_tokio_spawn_forever_outer_event(&name);
    let token = CrasherToken { name: name.clone() };
    register_tokio_spawn_forever(TOKIO_SPAWN_FOREVER_LABEL, &name, token);
    tokio_spawn_forever(name, future, crash_sender)
}

pub fn emit_tokio_spawn_forever_outer_event(name: &str) {
    for (bucket, seconds) in [
        ("fast", FAST_SCHEDULED_OBSERVER_SECS),
        ("slow", SLOW_SCHEDULED_OBSERVER_SECS),
    ] {
        observe_tokio_scheduled(TOKIO_SCHEDULED_OBSERVER_LABEL, bucket, seconds);
    }
    trace_event(TOKIO_SPAWN_FOREVER_LABEL, &format!("{TOKIO_SPAWN_FOREVER_OUTER_PREFIX}{name}"));
}

pub fn tokio_spawn_forever<F, E>(name: impl Into<String>, future: F, crash_sender: CrashSender) -> JoinHandle<()>
where
    F: Future<Output = Result<(), E>> + Send + 'static,
    E: Debug + Send + 'static,
{
    let name = name.into();
    tokio::spawn(async move {
        let ending = match future.await {
            Ok(()) => TOKIO_OK_ENDED.to_owned(),
            Err(error) => format!("{TOKIO_ERROR_PREFIX}{error:?}"),
        };
        crash_sender.send(format!("{TOKIO_END_PREFIX}, name={name} err={ending}"));
    })
}

pub fn tokio_join_handle_forever<E>(
    name: impl Into<String>,
    join_handle: JoinHandle<Result<(), E>>,
    crash_sender: CrashSender,
) -> JoinHandle<()>
where
    E: Debug + Send + 'static,
{
    let name = name.into();
    tokio::spawn(async move {
        let ending = match join_handle.await {
            Ok(Ok(())) => TOKIO_OK_ENDED.to_owned(),
            Ok(Err(error)) => format!("{TOKIO_ERROR_PREFIX}{error:?}"),
            Err(error) => format!("{TOKIO_ERROR_PREFIX}{error:?}"),
        };
        crash_sender.send(format!("{TOKIO_END_PREFIX}, name={name} err={ending}"));
    })
}

pub fn thread_spawn_forever_named<F, E>(name: impl Into<String>, f: F, crash_sender: CrashSender) -> thread::JoinHandle<()>
where
    F: FnOnce() -> Result<(), E> + Send + 'static,
    E: Debug + Send + 'static,
{
    let name = name.into();
    trace_event(THREAD_SPAWN_FOREVER_LABEL, &name);
    thread::Builder::new()
        .name(name)
        .spawn(move || {
            let message = match panic::catch_unwind(AssertUnwindSafe(f)) {
                Ok(Ok(())) => THREAD_OK_ENDED.to_owned(),
                Ok(Err(error)) => format!("{THREAD_ERROR_PREFIX}{error:?}"),
                Err(payload) => format!("{THREAD_ERROR_PREFIX}{}", panic_payload_message(&payload)),
            };
            crash_sender.send(message);
        })
        .unwrap_or_else(|err| panic!("failed to spawn thread: {err}"))
}

fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> &str {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        message
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.as_str()
    } else {
        "non-string panic payload"
    }
}

#[derive(Debug)]
pub struct ThreadCompletionState<E> {
    finished: AtomicBool,
    result: Mutex<Option<Result<(), E>>>,
}

impl<E> ThreadCompletionState<E> {
    pub fn new() -> Self {
        Self { finished: AtomicBool::new(false), result: Mutex::new(None) }
    }

    pub fn finish(&self, result: Result<(), E>) {
        *self.result.lock().expect("thread completion mutex poisoned") = Some(result);
        self.finished.store(true, Ordering::Release);
    }

    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }

    pub fn take_result(&self) -> Option<Result<(), E>> {
        self.result.lock().expect("thread completion mutex poisoned").take()
    }
}

impl<E> Default for ThreadCompletionState<E> {
    fn default() -> Self {
        Self::new()
    }
}

pub fn thread_spawn_forever_supervised<F, E>(
    name: impl Into<String>,
    f: F,
    crash_sender: CrashSender,
) -> JoinHandle<()>
where
    F: FnOnce() -> Result<(), E> + Send + 'static,
    E: Debug + Send + 'static,
{
    let name = name.into();
    let state = Arc::new(ThreadCompletionState::new());
    let worker_state = Arc::clone(&state);
    let handle = thread::Builder::new()
        .name(name)
        .spawn(move || worker_state.finish(f()))
        .unwrap_or_else(|err| panic!("failed to spawn thread: {err}"));

    tokio::spawn(async move {
        while !state.is_finished() {
            sleep_secs_f64(1.0).await;
        }
        let _ = handle.join();
        let message = match state.take_result() {
            Some(Ok(())) | None => THREAD_OK_ENDED.to_owned(),
            Some(Err(error)) => format!("{THREAD_ERROR_PREFIX}{error:?}"),
        };
        crash_sender.send(message);
    })
}

pub struct WithTaskContext<F> {
    context: usize,
    inner: F,
    done: bool,
}

impl<F> WithTaskContext<F> {
    pub fn new(context: usize, inner: F) -> Self {
        Self { context, inner, done: false }
    }
}

thread_local! {
    static CURRENT_TASK_CONTEXT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl<F> Future for WithTaskContext<F>
where
    F: Future,
{
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.as_mut().get_unchecked_mut() };
        if this.done {
            panic!("poll called after completion");
        }
        let previous = CURRENT_TASK_CONTEXT.with(|slot| {
            let old = slot.get();
            slot.set(this.context);
            old
        });
        let result = unsafe { Pin::new_unchecked(&mut this.inner) }.poll(cx);
        CURRENT_TASK_CONTEXT.with(|slot| slot.set(previous));
        if result.is_ready() {
            this.done = true;
        }
        result
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TimespecLike {
    pub secs: u64,
    pub nanos: u32,
}

impl TimespecLike {
    pub fn total_nanos(self) -> u128 {
        u128::from(self.secs) * u128::from(NANOS_PER_SEC) + u128::from(self.nanos)
    }

    pub fn saturating_delta(self, earlier: Self) -> Self {
        let lhs = self.total_nanos();
        let rhs = earlier.total_nanos();
        nanos_to_timespec(lhs.saturating_sub(rhs))
    }

    pub fn as_seconds_f64(self) -> f64 {
        self.secs as f64 + self.nanos as f64 / NANOS_PER_SEC as f64
    }
}

fn nanos_to_timespec(nanos: u128) -> TimespecLike {
    TimespecLike {
        secs: (nanos / u128::from(NANOS_PER_SEC)) as u64,
        nanos: (nanos % u128::from(NANOS_PER_SEC)) as u32,
    }
}

#[derive(Clone, Debug, Default)]
pub struct StatSnapshot {
    pub counters: [u64; 10],
    pub timers: [TimespecLike; 8],
}

impl StatSnapshot {
    pub fn is_empty_sentinel(&self) -> bool {
        self.timers.last().is_some_and(|timer| timer.nanos == NANOS_PER_SEC as u32)
    }

    pub fn average_timer(&self, timer_index: usize, denominator: u64) -> TimespecLike {
        if denominator == 0 {
            return TimespecLike::default();
        }
        let timer = self.timers.get(timer_index).copied().unwrap_or_default();
        nanos_to_timespec(timer.total_nanos() / u128::from(denominator))
    }
}

pub trait StatSource {
    fn snapshot(&self) -> StatSnapshot;
}

pub fn snapshot_stat_deltas<S>(source: &S, previous: &mut StatSnapshot) -> StatSnapshot
where
    S: StatSource,
{
    let current = source.snapshot();
    if previous.is_empty_sentinel() {
        *previous = current.clone();
        return current;
    }

    let mut delta = StatSnapshot::default();
    for (out, (now, old)) in delta
        .counters
        .iter_mut()
        .zip(current.counters.iter().zip(previous.counters.iter()))
    {
        *out = now.saturating_sub(*old);
    }
    for (out, (now, old)) in delta
        .timers
        .iter_mut()
        .zip(current.timers.iter().zip(previous.timers.iter()))
    {
        *out = now.saturating_delta(*old);
    }
    *previous = current;
    delta
}

#[derive(Clone, Debug)]
pub struct StatSnapshotRow {
    pub name: String,
    pub counters: [u64; 10],
    pub average_seconds: f64,
    pub timer_seconds: [f64; 8],
}

pub fn build_stat_snapshot_row(name: &str, snapshot: &StatSnapshot, average_nanos: f64) -> StatSnapshotRow {
    let mut timer_seconds = [0.0; 8];
    for (out, timer) in timer_seconds.iter_mut().zip(snapshot.timers.iter()) {
        *out = timer.as_seconds_f64();
    }

    StatSnapshotRow {
        name: name.to_owned(),
        counters: snapshot.counters,
        average_seconds: average_nanos * 1.0e-9,
        timer_seconds,
    }
}

pub trait StatRowSink {
    fn write_row(&mut self, row: StatSnapshotRow);
}

pub async fn stat_report_loop<S, W>(name: String, source: S, writer: &mut W)
where
    S: StatSource,
    W: StatRowSink,
{
    let mut previous = StatSnapshot::default();
    previous.timers[7].nanos = NANOS_PER_SEC as u32;

    loop {
        let delta = snapshot_stat_deltas(&source, &mut previous);
        if delta.is_empty_sentinel() {
            return;
        }

        let count = delta.counters[2];
        let average = delta.average_timer(4, count).total_nanos() as f64;
        if name.len() >= 24 && name.starts_with("tokio_scheduled_observer") {
            record_per_name_latency(&name, count, average * 1.0e-9);
        }
        record_global_latency(count, average * 1.0e-9);
        writer.write_row(build_stat_snapshot_row(&name, &delta, average));
        sleep_secs_f64(STAT_REPORT_SLEEP_SECS).await;
    }
}

pub trait LatencySampleReceiver {
    fn poll_recv_sample(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<LatencySample>>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LatencySample {
    pub count: u64,
    pub elapsed_nanos: u64,
}

pub async fn latency_sampler_loop<R>(name: String, mut receiver: R)
where
    R: LatencySampleReceiver + Unpin,
{
    while let Some(sample) = poll_fn(|cx| Pin::new(&mut receiver).poll_recv_sample(cx)).await {
        let seconds = sample.elapsed_nanos as f64 / NANOS_PER_SEC as f64;
        if name.len() >= 24 && name.starts_with(TOKIO_SCHEDULED_OBSERVER_LABEL) {
            record_per_name_latency(&name, sample.count, seconds);
        }
        record_global_latency(sample.count, seconds);
        sleep_secs_f64(STAT_REPORT_SLEEP_SECS).await;
    }
}

fn poll_fn<T, F>(mut f: F) -> impl Future<Output = T>
where
    F: FnMut(&mut Context<'_>) -> Poll<T>,
{
    core_poll_fn(move |cx| f(cx))
}

pub fn observe_tokio_scheduled(observer: &str, bucket: &str, threshold_secs: f64) {
    let name = format!("{observer}/{bucket}");
    record_per_name_latency(&name, 1, threshold_secs);
}

fn trace_event(target: &str, message: &str) {
    let _ = (target, message);
}

static GLOBAL_LATENCY: Mutex<Option<LatencySampler>> = Mutex::new(None);
static PER_NAME_LATENCY: Mutex<Option<HashMap<String, LatencySampler>>> = Mutex::new(None);

pub fn record_global_latency(weight: u64, seconds: f64) {
    let mut guard = GLOBAL_LATENCY.lock().expect("global latency sampler mutex poisoned");
    let sampler = guard.get_or_insert_with(|| LatencySampler::new("global", 1.0));
    sampler.record_weighted(weight, seconds);
}

pub fn record_per_name_latency(name: &str, weight: u64, seconds: f64) {
    let mut guard = PER_NAME_LATENCY.lock().expect("per-name latency sampler mutex poisoned");
    let map = guard.get_or_insert_with(HashMap::new);
    let sampler = map
        .entry(name.to_owned())
        .or_insert_with(|| LatencySampler::new(name, PER_NAME_LATENCY_ALPHA));
    sampler.record_weighted(weight, seconds);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TcpCompressionKey {
    pub compressed: bool,
    pub port: u16,
}

#[derive(Debug, Default)]
pub struct AtomicCompressionTotals {
    pub uncompressed_bytes: AtomicU64,
    pub compressed_bytes: AtomicU64,
    pub packets: AtomicU64,
}

#[derive(Debug, Default)]
pub struct TcpCompressionStats {
    totals: AtomicCompressionTotals,
    samplers: Mutex<HashMap<TcpCompressionKey, LatencySampler>>,
}

impl TcpCompressionStats {
    pub fn record(&self, key: TcpCompressionKey, uncompressed_bytes: u64, compressed_bytes: u64, ratio: f64) {
        self.totals.uncompressed_bytes.fetch_add(uncompressed_bytes, Ordering::Relaxed);
        self.totals.compressed_bytes.fetch_add(compressed_bytes, Ordering::Relaxed);
        self.totals.packets.fetch_add(1, Ordering::Relaxed);

        if !sample_one_in(50) {
            return;
        }

        let label = format_tcp_compression_label(key);
        let alpha = tcp_compression_alpha(key.port);
        let mut samplers = self.samplers.lock().expect("tcp compression sampler mutex poisoned");
        let sampler = samplers
            .entry(key)
            .or_insert_with(|| LatencySampler::new(label, alpha));
        sampler.weight_is_bucket_units = true;
        sampler.record_weighted(1, ratio);
    }
}

pub fn record_tcp_compression_stats(
    stats: &TcpCompressionStats,
    compressed: bool,
    port: u16,
    uncompressed_bytes: u64,
    compressed_bytes: u64,
    ratio: f64,
) {
    stats.record(
        TcpCompressionKey { compressed, port },
        uncompressed_bytes,
        compressed_bytes,
        ratio,
    );
}

fn format_tcp_compression_label(key: TcpCompressionKey) -> String {
    let mode = if key.compressed { "compressed" } else { "plain" };
    format!("tcp_compression/{mode}/{}", key.port)
}

fn tcp_compression_alpha(port: u16) -> f64 {
    if matches!(port, 4002 | 4004) {
        TCP_COMPRESSION_ALPHA_SPECIAL
    } else {
        TCP_COMPRESSION_ALPHA_DEFAULT
    }
}

fn sample_one_in(n: u32) -> bool {
    static SAMPLE_COUNTER: AtomicU64 = AtomicU64::new(0);
    SAMPLE_COUNTER.fetch_add(1, Ordering::Relaxed) % u64::from(n) == 0
}

pub struct MemoizedSamplerMap<K> {
    inner: Mutex<HashMap<K, LatencySampler>>,
    alpha: f64,
}

impl<K> MemoizedSamplerMap<K>
where
    K: Eq + Hash + Clone + Display,
{
    pub fn new(alpha: f64) -> Self {
        Self { inner: Mutex::new(HashMap::new()), alpha }
    }

    pub fn record(&self, key: K, weight: u64, seconds: f64) {
        let mut inner = self.inner.lock().expect("sampler map mutex poisoned");
        let sampler = inner
            .entry(key.clone())
            .or_insert_with(|| LatencySampler::new(key.to_string(), self.alpha));
        sampler.record_weighted(weight, seconds);
    }
}
