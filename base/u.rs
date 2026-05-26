use std::cmp;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, ReadDir};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Small marker trait for binary decoders that advance a cursor.
pub trait DecodeFromCursor: Sized {
    type Error;
    fn decode_from_cursor(cursor: &mut DecodeCursor<'_>) -> Result<Self, Self::Error>;
}

/// Small marker trait for serializers measured by the line-496 wrappers.
pub trait EncodeToVec {
    type Error;
    fn encode_to_vec(&self) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeCursor<'a> {
    start_len: usize,
    input: &'a [u8],
}

impl<'a> DecodeCursor<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            start_len: input.len(),
            input,
        }
    }

    pub fn remaining(&self) -> usize {
        self.input.len()
    }

    pub fn consumed(&self) -> usize {
        self.start_len - self.input.len()
    }

    pub fn read_exact(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.input.len() < n {
            return None;
        }
        let (head, tail) = self.input.split_at(n);
        self.input = tail;
        Some(head)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timed<T> {
    pub value: T,
    pub elapsed: Duration,
    pub remaining: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockingSection {
    Entered,
    AlreadyAllowed,
    Disabled,
}

pub trait BlockingGuard {
    fn enter_for_blocking(&mut self) -> BlockingSection;
    fn leave_blocking(&mut self, section: BlockingSection);
}

pub trait LatencyCounter {
    fn record_read(&mut self);
    fn record_sample(&mut self, value: f64);
}

pub trait UTracingSpan {
    type Guard;

    fn enabled(&self) -> bool;
    fn enter(&self) -> Self::Guard;
}

/// Evidence: 0x13CA000 formats a base-data path ending in
/// `hyperliquid_data/n_restarts_to_page.json`, calls the usize reader at 0x144B900,
/// and returns `(n == 0) + n`, i.e. a floor of one.
pub fn read_n_restarts_to_page(root: impl AsRef<Path>) -> usize {
    let path = root
        .as_ref()
        .join("hyperliquid_data")
        .join("n_restarts_to_page.json");
    read_usize_file(&path).unwrap_or(0).max(1)
}

fn read_usize_file(path: &Path) -> io::Result<usize> {
    let bytes = fs::read(path)?;
    let s = std::str::from_utf8(&bytes)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    usize::from_str(s.trim()).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

/// Evidence: 0x13CA0E0 panics with `assertion failed: !base_dir.ends_with('/')`,
/// builds `base_dir + "/"`, parses numeric file stems, insertion-sorts small inputs
/// (<21) and otherwise dispatches to the standard sort helper before formatting paths.
pub fn collect_sorted_numbered_paths(
    read_dir: ReadDir,
    base_dir: &str,
    suffix: Option<&str>,
) -> Vec<String> {
    assert!(!base_dir.ends_with('/'));

    let suffix = suffix.unwrap_or("");
    let prefix = format!("{base_dir}/");
    let mut numbers = Vec::new();

    for entry in read_dir.filter_map(Result::ok) {
        let path = entry.path();
        let Some(path_str) = path.to_str() else { continue };
        let Some(rest) = path_str.strip_prefix(&prefix) else { continue };
        let Some(number) = rest.strip_suffix(suffix) else { continue };
        if let Ok(number) = number.parse::<u64>() {
            numbers.push(number);
        }
    }

    numbers.sort_unstable();
    numbers
        .into_iter()
        .map(|number| format!("{prefix}{number}{suffix}"))
        .collect()
}

/// Same adapter for callers that already have paths instead of a `ReadDir`.
pub fn collect_sorted_numbered_pathbufs<I>(paths: I, base_dir: &Path, suffix: Option<&OsStr>) -> Vec<PathBuf>
where
    I: IntoIterator<Item = PathBuf>,
{
    assert!(!base_dir.as_os_str().as_encoded_bytes().ends_with(b"/"));

    let suffix = suffix.and_then(OsStr::to_str).unwrap_or("");
    let mut numbers = Vec::new();
    for path in paths {
        let Some(file_name) = path.file_name().and_then(OsStr::to_str) else { continue };
        let Some(stem) = file_name.strip_suffix(suffix) else { continue };
        if let Ok(number) = stem.parse::<u64>() {
            numbers.push(number);
        }
    }
    numbers.sort_unstable();
    numbers
        .into_iter()
        .map(|number| base_dir.join(format!("{number}{suffix}")))
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpAddresses {
    pub private_ip: String,
    pub public_ips: Vec<String>,
}

/// Evidence: 0x13CA370 allocates and executes `hostname -I | awk '{print $1}'`,
/// then probes `ifconfig.me`, `api.ipify.org`, and `icanhazip.com`, de-duplicates
/// short successful outputs through a tree map/set, and records critical messages
/// when no public IP can be recovered or cached writes fail.
pub fn private_and_public_ip_addresses(cache_file: Option<&Path>) -> io::Result<IpAddresses> {
    let private_ip = run_shell_trimmed("hostname -I | awk '{print $1}'").unwrap_or_else(|_| "N/A".to_owned());

    let mut public_ips = BTreeSet::new();
    for endpoint in ["ifconfig.me", "api.ipify.org", "icanhazip.com"] {
        if let Ok(value) = run_shell_trimmed(&format!("curl -fsS --max-time 5 {endpoint}")) {
            let value = value.trim();
            if !value.is_empty() && value.len() <= 64 {
                public_ips.insert(value.to_owned());
            }
        }
    }

    if public_ips.is_empty() {
        if let Some(path) = cache_file {
            if let Ok(cached) = fs::read_to_string(path) {
                for line in cached.lines().map(str::trim).filter(|line| !line.is_empty()) {
                    public_ips.insert(line.to_owned());
                }
            }
        }
    } else if let Some(path) = cache_file {
        let mut bytes = String::new();
        for ip in &public_ips {
            bytes.push_str(ip);
            bytes.push('\n');
        }
        fs::write(path, bytes)?;
    }

    Ok(IpAddresses {
        private_ip,
        public_ips: public_ips.into_iter().collect(),
    })
}

fn run_shell_trimmed(command: &str) -> io::Result<String> {
    let output = Command::new("sh").arg("-c").arg(command).output()?;
    if !output.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "command failed"));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    Ok(text.trim().to_owned())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadPoolConfig {
    pub num_threads: usize,
}

/// Evidence: 0x13CBA40 computes available_parallelism()/4, clamps it between the two
/// requested limits, floors zero to one, constructs a Rayon builder, and unwraps result.
pub fn rayon_pool_clamped_to_available_quarter(min_threads: usize, max_threads: usize) -> ThreadPoolConfig {
    let available_quarter = thread::available_parallelism()
        .map(|n| n.get() / 4)
        .unwrap_or(1);
    let low = cmp::min(min_threads, max_threads);
    let high = cmp::max(min_threads, max_threads);
    let clamped = available_quarter.clamp(low, high).max(1);
    ThreadPoolConfig { num_threads: clamped }
}

/// Evidence: 0x13CBCE0 logs a critical message unless a global test/log state suppresses it,
/// then drops the boxed error. This source-level adapter leaves policy to the caller.
pub fn log_prune_evm_checkpoints_if_tarred_failed<E>(error: E, mut record: impl FnMut(E)) {
    record(error);
}

/// Evidence: 0x282FF50 uses default f64 schedule `[0.1, 1.0, 10.0]` when none is supplied,
/// sleeps with the duration helper, rechecks state after each sleep, and finally formats
/// the supplied description and last error.
pub fn retry_backoff_schedule<T, E>(
    description: &str,
    backoffs_secs: Option<&[f64]>,
    mut action: impl FnMut() -> Result<T, E>,
    mut on_retry: impl FnMut(&str, &E),
) -> Result<T, E> {
    let default = [0.1_f64, 1.0, 10.0];
    let schedule = backoffs_secs.unwrap_or(&default);

    match action() {
        Ok(value) => Ok(value),
        Err(mut last_err) => {
            for secs in schedule {
                on_retry(description, &last_err);
                sleep_secs_f64_clamped(*secs);
                match action() {
                    Ok(value) => return Ok(value),
                    Err(err) => last_err = err,
                }
            }
            on_retry(description, &last_err);
            Err(last_err)
        }
    }
}

pub fn sleep_secs_f64_clamped(secs: f64) {
    if secs.is_finite() && secs > 0.0 {
        thread::sleep(Duration::from_secs_f64(secs));
    }
}

/// Evidence: 0x28302F0, 0x28306A0, 0x2830A50, and 0x2830E20 are monomorphs of one
/// blocking guard pattern: check the thread-local blocking state, optionally link a parked
/// blocker into the runtime, run the closure while the TLS flag is set to blocking, then
/// restore the prior flag. Strings include `can call blocking only when running on the...`.
pub fn run_with_blocking_guard<G, R>(guard: &mut G, enable_guard: bool, f: impl FnOnce() -> R) -> R
where
    G: BlockingGuard,
{
    if !enable_guard {
        return f();
    }
    let section = guard.enter_for_blocking();
    let result = f();
    guard.leave_blocking(section);
    result
}

/// Evidence: decode wrappers at 0x28BBED0..0x28BDC00 call `Timespec::now` before and
/// after decode, subtract the cursor's remaining length from the input length, and optionally
/// enter the blocking guard before calling the real decoder.
pub fn decode_with_metrics<T, G>(
    input: &[u8],
    guard: Option<&mut G>,
    mut decode: impl FnMut(&mut DecodeCursor<'_>) -> T,
) -> Timed<T>
where
    G: BlockingGuard,
{
    let mut cursor = DecodeCursor::new(input);
    let start = Instant::now();
    let value = if let Some(guard) = guard {
        run_with_blocking_guard(guard, true, || decode(&mut cursor))
    } else {
        decode(&mut cursor)
    };
    Timed {
        value,
        elapsed: start.elapsed(),
        remaining: cursor.remaining(),
    }
}

pub fn decode_gossip_rpc_response_with_metrics<T, E, G>(
    input: &[u8],
    guard: Option<&mut G>,
) -> Timed<Result<T, E>>
where
    T: DecodeFromCursor<Error = E>,
    G: BlockingGuard,
{
    decode_with_metrics(input, guard, T::decode_from_cursor)
}

pub fn decode_tcp_id_flag_with_metrics<T, E, G>(input: &[u8], guard: Option<&mut G>) -> Timed<Result<T, E>>
where
    T: DecodeFromCursor<Error = E>,
    G: BlockingGuard,
{
    decode_with_metrics(input, guard, T::decode_from_cursor)
}

pub fn decode_u32_tagged_value_with_metrics<T, E, G>(input: &[u8], guard: Option<&mut G>) -> Timed<Result<T, E>>
where
    T: DecodeFromCursor<Error = E>,
    G: BlockingGuard,
{
    decode_with_metrics(input, guard, T::decode_from_cursor)
}

/// Evidence: 0x28BF690, 0x28BFBD0, 0x28C0110, 0x28C0650, and 0x28C0B90 all call a
/// concrete string-result decoder, then normalize several internal error variants to an
/// empty `Err` slot while freeing owned strings for variants 3, 5, and 7.
pub fn decode_string_result_with_metrics<E, G>(
    input: &[u8],
    guard: Option<&mut G>,
    mut decode: impl FnMut(&mut DecodeCursor<'_>) -> Result<String, E>,
) -> Timed<Result<String, E>>
where
    G: BlockingGuard,
{
    decode_with_metrics(input, guard, |cursor| decode(cursor))
}

/// Evidence: 0x28315F0 and 0x471E100 assert equal lengths, then zip vectors whose
/// observed element sizes are 40 and 24 bytes into 64-byte records.
pub fn zip_equal_len<A, B>(left: Vec<A>, right: Vec<B>) -> Vec<(A, B)> {
    assert_eq!(left.len(), right.len());
    left.into_iter().zip(right).collect()
}

/// Evidence: 0x4719000-style wrappers first ask a per-monomorph callsite helper for a
/// tracing span at line 496; if the flag byte is false, they call the body directly. If true,
/// they enter the span through TLS, call the body, then restore the prior thread state.
pub fn with_u_span_496<S, R>(span: Option<&S>, f: impl FnOnce() -> R) -> R
where
    S: UTracingSpan,
{
    match span {
        Some(span) if span.enabled() => {
            let _guard = span.enter();
            f()
        }
        _ => f(),
    }
}

pub fn instrumented_encode_to_vec<S, T>(span: Option<&S>, value: &T) -> Result<Vec<u8>, T::Error>
where
    S: UTracingSpan,
    T: EncodeToVec,
{
    with_u_span_496(span, || value.encode_to_vec())
}

pub fn instrumented_decode<S, T, E>(
    span: Option<&S>,
    cursor: &mut DecodeCursor<'_>,
    mut decode: impl FnMut(&mut DecodeCursor<'_>) -> Result<T, E>,
) -> Result<T, E>
where
    S: UTracingSpan,
{
    with_u_span_496(span, || decode(cursor))
}

/// Evidence: 0x4718D70, 0x4719260, 0x471B140, 0x471B610, and 0x471D930 are state
/// serialization wrappers around concrete callees 0x46CF030, 0x46CF990, 0x46CEA60,
/// 0x46CF490, and 0x46CFE90. Their source-level behavior is the same span adapter.
pub fn instrumented_state_serializer<S, R>(span: Option<&S>, serialize: impl FnOnce() -> R) -> R
where
    S: UTracingSpan,
{
    with_u_span_496(span, serialize)
}

/// Evidence: 0x4748230, 0x4748DA0, 0x4749750, and 0x474A0F0 poll an inner future/body,
/// call the `profiled_rw_lock_increment` counter at state+0x4110, call or update the
/// `slow_abci_engine_read_increment` bucket at state+0x4140, and return the poll payload
/// unchanged.
pub fn poll_profiled_read<T>(
    poll_body: impl FnOnce() -> T,
    profiled_rw_lock_increment: &mut impl LatencyCounter,
    slow_abci_engine_read_increment: &mut impl LatencyCounter,
) -> T {
    let value = poll_body();
    profiled_rw_lock_increment.record_read();
    slow_abci_engine_read_increment.record_read();
    value
}

pub struct PeriodicLockedBytesWriterState<W> {
    pub bytes: Mutex<Vec<u8>>,
    pub writer: W,
}

/// Evidence: 0x432F9C0 is a noreturn loop: nanosleep for 60s (retrying after EINTR),
/// take a byte lock at state+0x10, clone bytes from state+0x20/+0x28, unlock, call the
/// write helper at 0x144A890, panic/drop the error on failure, free the clone, repeat.
pub fn periodic_locked_bytes_writer_loop<W, E>(state: &PeriodicLockedBytesWriterState<W>) -> !
where
    W: Fn(&[u8]) -> Result<(), E>,
    E: std::fmt::Debug,
{
    loop {
        thread::sleep(Duration::from_secs(60));
        let bytes = clone_locked_bytes(&state.bytes);
        (state.writer)(&bytes).expect("periodic locked bytes write failed");
    }
}

fn clone_locked_bytes(bytes: &Mutex<Vec<u8>>) -> Vec<u8> {
    let guard: MutexGuard<'_, Vec<u8>> = bytes.lock().expect("periodic bytes mutex poisoned");
    guard.clone()
}

pub fn unix_millis_now_saturating() -> u64 {
    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}
