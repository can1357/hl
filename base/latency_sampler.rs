use std::collections::VecDeque;
use std::fmt::{self, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_BUFFER_CAP: usize = 2_000;
const DEFAULT_MIN_BUFFERED_FOR_REPORT: usize = 1_000;
const DEFAULT_BUCKET_REPORT_INTERVAL_SECS: f64 = 30.0;
const MIN_ELAPSED_SECS_FOR_FRACTION: f64 = 1.0e-15;
const SECONDS_PER_DAY: u64 = 86_400;
const SECONDS_PER_HOUR: u32 = 3_600;

/// Compact wall-clock value copied around the sampler as a 12-byte chrono value.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct SampleTime {
    pub day: i32,
    pub seconds_from_midnight: u32,
    pub nanos: u32,
}

impl SampleTime {
    pub fn now_utc_lossy() -> Self {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        let seconds = duration.as_secs();
        Self {
            day: (seconds / SECONDS_PER_DAY) as i32,
            seconds_from_midnight: (seconds % SECONDS_PER_DAY) as u32,
            nanos: duration.subsec_nanos(),
        }
    }

    pub fn elapsed_seconds_since(self, earlier: Self) -> Option<f64> {
        let lhs = self.total_nanos()?;
        let rhs = earlier.total_nanos()?;
        let nanos = lhs.checked_sub(rhs)?;
        Some(nanos as f64 / 1_000_000_000.0)
    }

    pub fn hour(self) -> u8 {
        (self.seconds_from_midnight / SECONDS_PER_HOUR) as u8
    }

    fn total_nanos(self) -> Option<u128> {
        if self.day < 0 || self.seconds_from_midnight >= SECONDS_PER_DAY as u32 {
            return None;
        }
        let seconds = u128::from(self.day as u32)
            .checked_mul(u128::from(SECONDS_PER_DAY))?
            .checked_add(u128::from(self.seconds_from_midnight))?;
        seconds
            .checked_mul(1_000_000_000)
            .and_then(|base| base.checked_add(u128::from(self.nanos)))
    }
}

#[derive(Clone, Debug)]
pub struct LatencySampler {
    pub name: String,
    pub max_buffered_samples: usize,
    pub min_buffered_for_report: usize,
    pub bucket_report_interval_secs: f64,
    pub bucket_limit_mult_threshold: f64,
    /// When set, the binary multiplies the supplied sample weight by 50 before aggregation.
    pub weight_is_bucket_units: bool,
    pub suppress_run_suffix: bool,
    rolling_samples: VecDeque<f64>,
    bucket_samples: Vec<f64>,
    total_weighted_units: u64,
    total_observations: u64,
    total_weighted_sum: f64,
    bucket_weighted_units: u64,
    bucket_observations: u64,
    bucket_weighted_sum: f64,
    bucket_max: f64,
    current_day: Option<i32>,
    last_bucket_report_time: Option<SampleTime>,
    last_full_report_time: Option<SampleTime>,
    last_bucket_report: Option<LatencyBucketReport>,
    bucket_report_liner: DailyJsonLiner<LatencyBucketReport>,
    full_report_liner: DailyJsonLiner<LatencyReport>,
}

impl LatencySampler {
    /// Recovered constructor.  The binary builds two daily JSON-line reporters and uses
    /// a 2,000-sample cap for both the rolling window and the per-bucket sample vector.
    pub fn new(name: impl Into<String>, bucket_limit_mult_threshold: f64) -> Self {
        Self::with_options(name, bucket_limit_mult_threshold, false)
    }

    pub fn with_options(
        name: impl Into<String>,
        bucket_limit_mult_threshold: f64,
        suppress_run_suffix: bool,
    ) -> Self {
        assert!(bucket_limit_mult_threshold >= 0.0, "bucket threshold must be nonnegative");

        let name = name.into();
        let bucket_report_liner = DailyJsonLiner::new(format!("{name}/bucket"), suppress_run_suffix);
        let full_report_liner = DailyJsonLiner::new(format!("{name}/full"), suppress_run_suffix);

        Self {
            name,
            max_buffered_samples: DEFAULT_BUFFER_CAP,
            min_buffered_for_report: DEFAULT_MIN_BUFFERED_FOR_REPORT,
            bucket_report_interval_secs: DEFAULT_BUCKET_REPORT_INTERVAL_SECS,
            bucket_limit_mult_threshold,
            weight_is_bucket_units: false,
            suppress_run_suffix,
            rolling_samples: VecDeque::new(),
            bucket_samples: Vec::new(),
            total_weighted_units: 0,
            total_observations: 0,
            total_weighted_sum: 0.0,
            bucket_weighted_units: 0,
            bucket_observations: 0,
            bucket_weighted_sum: 0.0,
            bucket_max: 0.0,
            current_day: None,
            last_bucket_report_time: None,
            last_full_report_time: Some(SampleTime::now_utc_lossy()),
            last_bucket_report: None,
            bucket_report_liner,
            full_report_liner,
        }
    }

    pub fn record(&mut self, seconds: f64) {
        self.record_weighted(1, seconds);
    }

    pub fn record_weighted(&mut self, sample_weight: u64, seconds: f64) {
        self.record_weighted_at(sample_weight, seconds, SampleTime::now_utc_lossy());
    }

    /// Records one latency observation and returns any reports emitted by this sample.
    pub fn record_weighted_at(
        &mut self,
        sample_weight: u64,
        seconds: f64,
        now: SampleTime,
    ) -> EmittedLatencyReports {
        if sample_weight == 0 {
            return EmittedLatencyReports::default();
        }
        assert!(seconds >= 0.0, "latency sample must be nonnegative");

        if self.current_day != Some(now.day) {
            self.reset_rolling_window_for_new_day(now.day);
        }

        let weighted_units = if self.weight_is_bucket_units {
            sample_weight.saturating_mul(50)
        } else {
            sample_weight
        };
        let weighted_seconds = seconds * weighted_units as f64;

        self.total_weighted_units = self.total_weighted_units.saturating_add(weighted_units);
        self.total_observations = self.total_observations.saturating_add(1);
        self.total_weighted_sum += weighted_seconds;

        self.push_rolling(seconds);

        self.bucket_weighted_units = self.bucket_weighted_units.saturating_add(weighted_units);
        self.bucket_observations = self.bucket_observations.saturating_add(1);
        self.bucket_weighted_sum += weighted_seconds;
        if self.bucket_samples.len() < self.max_buffered_samples {
            self.bucket_samples.push(seconds);
        }
        self.bucket_max = self.bucket_max.max(seconds);

        if let Some(last_bucket_report_time) = self.last_bucket_report_time {
            let elapsed = now
                .elapsed_seconds_since(last_bucket_report_time)
                .unwrap_or_default();
            if elapsed <= self.bucket_report_interval_secs {
                return EmittedLatencyReports::default();
            }
        }

        let bucket = self.take_bucket_report(now);
        if let Some(report) = bucket.as_ref() {
            self.last_bucket_report = Some(report.clone());
            self.bucket_report_liner.append(now, &report);
        }
        self.last_bucket_report_time = Some(now);

        let full = self.build_full_report(now);
        if let Some(report) = full.as_ref() {
            self.full_report_liner.append(now, &report);
        }
        self.last_full_report_time = Some(now);

        EmittedLatencyReports { bucket, full }
    }

    pub fn bucket_rows(&self) -> &[String] {
        self.bucket_report_liner.rows()
    }

    pub fn full_rows(&self) -> &[String] {
        self.full_report_liner.rows()
    }

    pub fn rolling_len(&self) -> usize {
        self.rolling_samples.len()
    }

    fn reset_rolling_window_for_new_day(&mut self, day: i32) {
        self.current_day = Some(day);
        self.rolling_samples.clear();
        self.total_weighted_units = 0;
        self.total_observations = 0;
        self.total_weighted_sum = 0.0;
    }

    fn push_rolling(&mut self, seconds: f64) {
        if self.rolling_samples.len() == self.max_buffered_samples {
            self.rolling_samples.pop_front();
        }
        self.rolling_samples.push_back(seconds);
    }

    fn take_bucket_report(&mut self, now: SampleTime) -> Option<LatencyBucketReport> {
        let n_orig = self.bucket_observations;
        let weighted_units = self.bucket_weighted_units;
        let weighted_sum = self.bucket_weighted_sum;
        let bucket_max = self.bucket_max;
        let mut samples = std::mem::take(&mut self.bucket_samples);

        self.bucket_weighted_units = 0;
        self.bucket_observations = 0;
        self.bucket_weighted_sum = 0.0;
        self.bucket_max = 0.0;

        if weighted_units == 0 || weighted_sum < 0.0 || samples.is_empty() {
            return None;
        }

        samples.sort_by(|a, b| a.total_cmp(b));
        let median = percentile_sorted(&samples, 50)?;
        let p95 = percentile_sorted(&samples, 95)?;
        let mean = weighted_sum / weighted_units as f64;
        let elapsed = self
            .last_full_report_time
            .and_then(|last| now.elapsed_seconds_since(last))
            .unwrap_or_default();
        let work_frac = (elapsed >= MIN_ELAPSED_SECS_FOR_FRACTION).then_some(weighted_sum / elapsed);

        Some(LatencyBucketReport {
            time: now,
            n: weighted_units,
            n_orig,
            median,
            mean,
            p95,
            max: bucket_max,
            work_frac,
        })
    }

    fn build_full_report(&self, now: SampleTime) -> Option<LatencyReport> {
        let n_buffer = self.rolling_samples.len();
        if n_buffer < 10 || self.total_weighted_units == 0 || self.total_weighted_sum < 0.0 {
            return None;
        }

        let mut samples: Vec<f64> = self.rolling_samples.iter().copied().collect();
        samples.sort_by(|a, b| a.total_cmp(b));
        let median = percentile_sorted(&samples, 50)?;
        let p90 = percentile_sorted(&samples, 90)?;
        let p95 = percentile_sorted(&samples, 95)?;
        let max = *samples.last()?;
        let raw_sum: f64 = samples.iter().sum();
        let raw_mean = raw_sum / samples.len() as f64;
        let std_dev = if samples.len() > 1 {
            let squared: f64 = samples
                .iter()
                .map(|sample| {
                    let delta = *sample - raw_mean;
                    delta * delta
                })
                .sum();
            (squared / (samples.len() - 1) as f64).sqrt()
        } else {
            0.0
        };

        let total_mean = self.total_weighted_sum / self.total_weighted_units as f64;
        let elapsed = self
            .last_full_report_time
            .and_then(|last| now.elapsed_seconds_since(last))
            .unwrap_or_default();
        let total_work = self.total_weighted_sum;
        let work_frac = (elapsed >= MIN_ELAPSED_SECS_FOR_FRACTION && total_work >= 0.0)
            .then_some(total_work / elapsed);

        let bucket_mean = self.last_bucket_report.as_ref().map(|bucket| bucket.mean);
        let bucket_work_frac = self.last_bucket_report.as_ref().and_then(|bucket| bucket.work_frac);
        let bucket_n = self.last_bucket_report.as_ref().map_or(0, |bucket| bucket.n);
        let bucket_n_orig = self.last_bucket_report.as_ref().map_or(0, |bucket| bucket.n_orig);

        Some(LatencyReport {
            time: now,
            total_n: self.total_weighted_units,
            total_mean,
            n_buffer: n_buffer as u64,
            work_frac,
            mean: raw_mean,
            med: median,
            p90,
            p95,
            max,
            std_dev,
            bucket_mean,
            bucket_work_frac,
            bucket_n,
            bucket_n_orig,
            weighted_by_bucket_units: self.weight_is_bucket_units,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct EmittedLatencyReports {
    pub bucket: Option<LatencyBucketReport>,
    pub full: Option<LatencyReport>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LatencyBucketReport {
    pub time: SampleTime,
    pub n: u64,
    pub n_orig: u64,
    pub median: f64,
    pub mean: f64,
    pub p95: f64,
    pub max: f64,
    pub work_frac: Option<f64>,
}

impl LatencyBucketReport {
    pub fn write_json(&self, out: &mut String) -> fmt::Result {
        out.push('{');
        write_json_time_field(out, "time", self.time)?;
        write!(
            out,
            ",\"n\":{},\"n_orig\":{},\"median\":{},\"mean\":{},\"p95\":{},\"max\":{}",
            self.n, self.n_orig, self.median, self.mean, self.p95, self.max
        )?;
        write_json_option_f64_field(out, "work_frac", self.work_frac)?;
        out.push('}');
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LatencyReport {
    pub time: SampleTime,
    pub total_n: u64,
    pub total_mean: f64,
    pub n_buffer: u64,
    pub work_frac: Option<f64>,
    pub mean: f64,
    pub med: f64,
    pub p90: f64,
    pub p95: f64,
    pub max: f64,
    pub std_dev: f64,
    pub bucket_mean: Option<f64>,
    pub bucket_work_frac: Option<f64>,
    pub bucket_n: u64,
    pub bucket_n_orig: u64,
    pub weighted_by_bucket_units: bool,
}

impl LatencyReport {
    pub fn write_json(&self, out: &mut String) -> fmt::Result {
        out.push('{');
        write_json_time_field(out, "time", self.time)?;
        write!(
            out,
            ",\"total_n\":{},\"total_mean\":{},\"n_buffer\":{}",
            self.total_n, self.total_mean, self.n_buffer
        )?;
        write_json_option_f64_field(out, "work_frac", self.work_frac)?;
        write!(
            out,
            ",\"mean\":{},\"med\":{},\"p90\":{},\"p95\":{},\"max\":{},\"std_dev\":{}",
            self.mean, self.med, self.p90, self.p95, self.max, self.std_dev
        )?;
        write_json_option_f64_field(out, "bucket_mean", self.bucket_mean)?;
        write_json_option_f64_field(out, "bucket_work_frac", self.bucket_work_frac)?;
        write!(
            out,
            ",\"bucket_n\":{},\"bucket_n_orig\":{}",
            self.bucket_n, self.bucket_n_orig
        )?;
        if self.weighted_by_bucket_units {
            out.push_str(",\"weighted_by_bucket_units\":true");
        }
        out.push('}');
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct DailyJsonLiner<T> {
    pub name: String,
    pub suppress_run_suffix: bool,
    pub rotate_hourly: bool,
    pub current_day: Option<i32>,
    pub current_hour: Option<u8>,
    pub rows: Vec<String>,
    _marker: std::marker::PhantomData<T>,
}

impl<T> DailyJsonLiner<T> {
    pub fn new(name: String, suppress_run_suffix: bool) -> Self {
        Self {
            name,
            suppress_run_suffix,
            rotate_hourly: false,
            current_day: None,
            current_hour: None,
            rows: Vec::new(),
            _marker: std::marker::PhantomData,
        }
    }

    pub fn rows(&self) -> &[String] {
        &self.rows
    }

    fn ensure_period(&mut self, now: SampleTime) {
        let hour = self.rotate_hourly.then_some(now.hour());
        if self.current_day != Some(now.day) || (self.rotate_hourly && self.current_hour != hour) {
            self.current_day = Some(now.day);
            self.current_hour = hour;
        }
    }
}

impl DailyJsonLiner<LatencyBucketReport> {
    pub fn append(&mut self, now: SampleTime, report: &LatencyBucketReport) {
        self.ensure_period(now);
        let mut row = String::with_capacity(160);
        let _ = report.write_json(&mut row);
        self.rows.push(row);
    }
}

impl DailyJsonLiner<LatencyReport> {
    pub fn append(&mut self, now: SampleTime, report: &LatencyReport) {
        self.ensure_period(now);
        let mut row = String::with_capacity(256);
        let _ = report.write_json(&mut row);
        self.rows.push(row);
    }
}

/// Small locked/throttled wrapper recovered from the direct caller at `0x1404c60`.
#[derive(Clone, Debug)]
pub struct ThrottledLatencySampler {
    pub sampler: LatencySampler,
    pub pending_observations: u64,
}

impl ThrottledLatencySampler {
    pub fn new(sampler: LatencySampler) -> Self {
        Self {
            sampler,
            pending_observations: 0,
        }
    }

    pub fn record_elapsed(&mut self, elapsed_seconds: f64) -> EmittedLatencyReports {
        let weight = (self.pending_observations / DEFAULT_BUFFER_CAP as u64).max(1);
        let reports = self.sampler.record_weighted_at(
            weight,
            elapsed_seconds,
            SampleTime::now_utc_lossy(),
        );

        if let Some(bucket) = reports.bucket.as_ref() {
            if bucket.n <= 20_000 && (bucket.n >= 200 || self.pending_observations <= 2_000) {
                self.pending_observations = bucket.n;
            } else {
                self.pending_observations = bucket.n;
            }
        }

        reports
    }
}

fn percentile_sorted(samples: &[f64], percentile: u64) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    let product = percentile.saturating_mul(samples.len() as u64);
    let index = (product / 100) as usize;
    samples.get(index).copied()
}

fn write_json_time_field(out: &mut String, key: &str, time: SampleTime) -> fmt::Result {
    write!(
        out,
        "\"{}\":{{\"day\":{},\"seconds_from_midnight\":{},\"nanos\":{}}}",
        key, time.day, time.seconds_from_midnight, time.nanos
    )
}

fn write_json_option_f64_field(out: &mut String, key: &str, value: Option<f64>) -> fmt::Result {
    match value {
        Some(value) => write!(out, ",\"{}\":{}", key, value),
        None => write!(out, ",\"{}\":null", key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(second: u32) -> SampleTime {
        SampleTime {
            day: 10,
            seconds_from_midnight: second,
            nanos: 0,
        }
    }

    #[test]
    fn bucket_report_uses_weighted_mean_and_sorted_percentiles() {
        let mut sampler = LatencySampler::new("lat", 1.0);
        sampler.last_full_report_time = Some(t(0));
        sampler.last_bucket_report_time = Some(t(0));
        sampler.record_weighted_at(2, 0.20, t(0));
        sampler.record_weighted_at(3, 0.40, t(1));

        let emitted = sampler.record_weighted_at(5, 0.10, t(31));
        let bucket = emitted.bucket.unwrap();

        assert_eq!(bucket.n, 10);
        assert_eq!(bucket.n_orig, 3);
        assert_eq!(bucket.median, 0.20);
        assert_eq!(bucket.p95, 0.40);
        assert!((bucket.mean - 0.21).abs() < 1.0e-12);
    }

    #[test]
    fn full_report_requires_a_populated_rolling_window() {
        let mut sampler = LatencySampler::new("lat", 1.0);
        sampler.last_full_report_time = Some(t(0));
        for i in 0..10 {
            sampler.record_weighted_at(1, i as f64 / 100.0, t(i + 1));
        }

        let emitted = sampler.record_weighted_at(1, 1.0, t(40));
        let full = emitted.full.unwrap();

        assert_eq!(full.n_buffer, 11);
        assert_eq!(full.med, 0.05);
        assert_eq!(full.p90, 0.09);
        assert_eq!(full.p95, 1.0);
    }
}
