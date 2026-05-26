use std::cmp::Ordering;
use std::collections::{BTreeMap, VecDeque};

use chrono::{Duration as ChronoDuration, NaiveDateTime};

pub type Address = [u8; 20];
pub type GlobalOrderId = u64;
pub type LocalAssetIndex = u32;

pub const TWAP_STEP_SECS_I64: i64 = 30;
pub const TWAP_STEP_SECS: f64 = 30.0;
pub const TWAP_RETRY_BUCKET_SECS: f64 = 60.0;
pub const TWAP_DEX_STRIDE: u64 = 10_000;

pub const PERP_DEX_FLOW_MIN_REFRESH_SECS: f64 = 2.5;
pub const SECONDS_PER_JULIAN_YEAR: f64 = 31_557_600.0;
pub const ACCRUAL_FACTOR_TOLERANCE: f64 = 1.01;

pub const MARK_PRICE_BUCKET_MILLIS: u64 = 600_000;
pub const MARK_PRICE_BUCKET_INTERVALS: [f64; 4] = [30.0, 100.0, 300.0, 1_000.0];
pub const MARK_PRICE_DEFAULT_DELAY_A: f64 = 0.0001;
pub const MARK_PRICE_DEFAULT_DELAY_B: f64 = 0.0003;
pub const MARK_PRICE_MIN_SAMPLE_SECS: f64 = 20.0;
pub const MARK_PRICE_MAX_SAMPLE_SECS: f64 = 100.0;
pub const MARK_PRICE_SAMPLE_SPACING_SECS: i64 = 1;
pub const PRICE_DENOMINATOR_EPSILON: f64 = 1.0e-20;
pub const MIN_BUCKET_ELAPSED_SECS: f64 = 1.0e-15;
pub const TINY_NEGATIVE_BUCKET_VALUE: f64 = -1.0e-15;

pub const MILLIS_PER_SECOND_F64: f64 = 1_000.0;
pub const LINEAR_DECAY_RATIO_TOLERANCE: f64 = 1.01;

pub const LINEAR_DECAY_BAD_TAG: u16 = 374;
pub const LINEAR_DECAY_FUTURE_START: u16 = 375;
pub const LINEAR_DECAY_INVERTED_RANGE: u16 = 191;
pub const LINEAR_DECAY_OK_TAG: u16 = 390;
pub const PERP_DEX_FLOW_THROTTLED_TAG: u16 = 120;

/// Twelve-byte chrono `NaiveDateTime` payload observed in L1 time callsites.
///
/// High-level source code used chrono; the optimized binary passes the packed
/// representation directly: packed date, seconds from midnight, nanoseconds.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NaiveDateTime12 {
    pub date: i32,
    pub seconds_from_midnight: u32,
    pub nanos: u32,
}

impl NaiveDateTime12 {
    #[inline]
    pub fn cmp_lexicographic(&self, other: &Self) -> Ordering {
        (self.date, self.seconds_from_midnight, self.nanos).cmp(&(
            other.date,
            other.seconds_from_midnight,
            other.nanos,
        ))
    }

    #[inline]
    pub fn unix_millis_saturating(self) -> u64 {
        let year_minus_one = (self.date >> 13) - 1;
        let mut adjusted_year = year_minus_one;
        let mut leap_cycle_days = 0;
        if adjusted_year < 0 {
            let cycles = ((1 - adjusted_year) as u32) / 400 + 1;
            adjusted_year += 400 * cycles as i32;
            leap_cycle_days = -146_097 * cycles as i32;
        }

        let ordinal = (self.date >> 4) & 0x1ff;
        let days_from_ce = ((adjusted_year / 100) >> 2)
            + ((1461 * adjusted_year) >> 2)
            + leap_cycle_days
            + ordinal
            - adjusted_year / 100;
        let days_since_unix_epoch = i64::from(days_from_ce - 719_163);
        let millis = i64::from(self.nanos / 1_000_000)
            + 1_000 * (i64::from(self.seconds_from_midnight) + 86_400 * days_since_unix_epoch);
        millis.max(0) as u64
    }
}

#[inline]
pub fn seconds_since_or_zero(later: NaiveDateTime, earlier: NaiveDateTime) -> f64 {
    if later < earlier {
        return 0.0;
    }
    later
        .signed_duration_since(earlier)
        .num_microseconds()
        .map(|micros| micros as f64 / 1_000_000.0)
        .unwrap_or(0.0)
}

#[inline]
pub fn naive_datetime_add_secs_f64(base: NaiveDateTime, seconds: f64) -> NaiveDateTime {
    let raw_nanos = seconds * 1_000_000_000.0;
    let total_nanos = if raw_nanos.is_nan() {
        0
    } else {
        raw_nanos.clamp(i64::MIN as f64, i64::MAX as f64) as i64
    };
    let secs = total_nanos.div_euclid(1_000_000_000);
    let nanos = total_nanos.rem_euclid(1_000_000_000);
    base.checked_add_signed(ChronoDuration::seconds(secs) + ChronoDuration::nanoseconds(nanos))
        .expect("`NaiveDateTime + TimeDelta` overflowed")
}

#[inline]
pub fn add_seconds(base: NaiveDateTime, seconds: i64) -> NaiveDateTime {
    base.checked_add_signed(ChronoDuration::seconds(seconds))
        .expect("`NaiveDateTime + TimeDelta` overflowed")
}

#[inline]
pub fn catch_up_by_interval(
    candidate: NaiveDateTime,
    floor: NaiveDateTime,
    interval_secs: f64,
) -> NaiveDateTime {
    assert!(interval_secs > 0.0);
    if candidate >= floor {
        return candidate;
    }
    let missed_intervals = (seconds_since_or_zero(floor, candidate) / interval_secs).ceil();
    assert!(missed_intervals >= 0.0);
    naive_datetime_add_secs_f64(candidate, missed_intervals * interval_secs)
}

#[inline]
pub fn advance_l1_update_time(last: NaiveDateTime, floor: NaiveDateTime) -> NaiveDateTime {
    catch_up_by_interval(add_seconds(last, TWAP_STEP_SECS_I64), floor, TWAP_STEP_SECS)
}

#[inline]
pub fn f64_to_u64_saturating(value: f64) -> u64 {
    if value.is_nan() || value <= 0.0 {
        0
    } else if value >= u64::MAX as f64 {
        u64::MAX
    } else {
        value as u64
    }
}

#[inline]
pub fn twap_retry_limit_for_duration_secs(duration_secs: f64) -> u64 {
    assert!(duration_secs >= 0.0);
    let buckets = f64_to_u64_saturating(duration_secs / TWAP_RETRY_BUCKET_SECS);
    buckets.saturating_mul(2).saturating_add(1)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TwapAdvanceDecision {
    EmitNow,
    Defer,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TwapScheduleEntry {
    pub global_order_id: GlobalOrderId,
    pub target_or_limit: u64,
    pub duration_secs: f64,
    pub _unknown_field_at_0x18: u64,
    pub side: u8,
    pub reduce_only_or_flags: u8,
    pub _unknown_field_at_0x22: u8,
    pub _unknown_field_at_0x23: u8,
    pub _unknown_field_at_0x24: u32,
    pub filled_or_progress: u64,
    pub secondary_progress: u64,
    pub slice_counter: u64,
    pub next_fire_time: NaiveDateTime,
    pub address: Address,
}

impl TwapScheduleEntry {
    #[inline]
    pub fn dex_index(&self) -> u64 {
        self.global_order_id / TWAP_DEX_STRIDE
    }

    #[inline]
    pub fn local_order_index(&self) -> u64 {
        self.global_order_id % TWAP_DEX_STRIDE
    }

    #[inline]
    pub fn has_reached_target(&self) -> bool {
        self.filled_or_progress >= self.target_or_limit
    }

    pub fn advance_time(&mut self, now: NaiveDateTime) {
        self.next_fire_time = advance_l1_update_time(self.next_fire_time, now);
        self.slice_counter = self.slice_counter.saturating_add(1);
    }

    pub fn advance_and_decide(&mut self, now: NaiveDateTime) -> TwapAdvanceDecision {
        self.advance_time(now);
        if self.has_reached_target() {
            return TwapAdvanceDecision::EmitNow;
        }
        if self.slice_counter > twap_retry_limit_for_duration_secs(self.duration_secs) {
            TwapAdvanceDecision::EmitNow
        } else {
            TwapAdvanceDecision::Defer
        }
    }
}

pub type TwapScheduleBook = BTreeMap<Address, BTreeMap<u64, TwapScheduleEntry>>;

pub fn advance_twap_schedule_entry(
    schedules: &mut TwapScheduleBook,
    address: &Address,
    order_key: u64,
    now: NaiveDateTime,
) -> Option<TwapAdvanceDecision> {
    let entry = schedules.get_mut(address)?.get_mut(&order_key)?;
    Some(entry.advance_and_decide(now))
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TimeWeightedBucket {
    pub weighted_value_seconds: f64,
    pub elapsed_seconds: f64,
    pub interval_seconds: f64,
    pub sample_count: u64,
    pub last_time: Option<NaiveDateTime>,
}

impl TimeWeightedBucket {
    pub fn new(interval_seconds: f64) -> Self {
        Self {
            weighted_value_seconds: 0.0,
            elapsed_seconds: 0.0,
            interval_seconds,
            sample_count: 0,
            last_time: None,
        }
    }

    pub fn update(&mut self, now: NaiveDateTime, value: f64) {
        let elapsed = self
            .last_time
            .map(|last| seconds_since_or_zero(now, last))
            .unwrap_or(1.0);
        if elapsed > self.interval_seconds {
            self.weighted_value_seconds = 0.0;
            self.elapsed_seconds = 0.0;
            self.interval_seconds = self.interval_seconds.max(10.0);
            self.sample_count = 0;
            self.last_time = None;
            return;
        }

        self.last_time = Some(now);
        let retain = 1.0 - 1.0 / self.interval_seconds;
        self.weighted_value_seconds = value * elapsed + retain * self.weighted_value_seconds;
        self.elapsed_seconds = elapsed + retain * self.elapsed_seconds;
        self.sample_count = self.sample_count.saturating_add(1);
    }

    pub fn valid_rate(&self) -> Option<f64> {
        if self.sample_count as f64 < self.interval_seconds || self.elapsed_seconds < MIN_BUCKET_ELAPSED_SECS {
            return None;
        }
        let mut numerator = self.weighted_value_seconds;
        if numerator < 0.0 && numerator >= TINY_NEGATIVE_BUCKET_VALUE {
            numerator = 0.0;
        }
        if numerator < 0.0 {
            return None;
        }
        Some(numerator / self.elapsed_seconds)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BucketSelectionMode {
    Min,
    Max,
}

pub fn select_valid_vty_bucket_rate(
    buckets: &[TimeWeightedBucket],
    mode: BucketSelectionMode,
) -> Option<f64> {
    let mut selected = None;
    for rate in buckets.iter().filter_map(TimeWeightedBucket::valid_rate) {
        selected = Some(match (selected, mode) {
            (None, _) => rate,
            (Some(current), BucketSelectionMode::Min) => current.min(rate),
            (Some(current), BucketSelectionMode::Max) => current.max(rate),
        });
    }
    selected
}

#[derive(Clone, Copy, Debug)]
pub struct MarkPriceSample {
    pub time: NaiveDateTime,
    pub mark_price: f64,
}

#[derive(Clone, Debug)]
pub struct MarkPriceDelayState {
    pub samples: VecDeque<MarkPriceSample>,
    pub buckets: Vec<TimeWeightedBucket>,
    pub bucket_millis: u64,
    pub max_seen_bucket: u64,
    pub delay_scalar_a: f64,
    pub delay_scalar_b: f64,
    pub sample_counter: u64,
    pub log_counter: u64,
}

impl Default for MarkPriceDelayState {
    fn default() -> Self {
        Self {
            samples: VecDeque::with_capacity(8),
            buckets: MARK_PRICE_BUCKET_INTERVALS
                .iter()
                .copied()
                .map(TimeWeightedBucket::new)
                .collect(),
            bucket_millis: MARK_PRICE_BUCKET_MILLIS,
            max_seen_bucket: 0,
            delay_scalar_a: MARK_PRICE_DEFAULT_DELAY_A,
            delay_scalar_b: MARK_PRICE_DEFAULT_DELAY_B,
            sample_counter: 0,
            log_counter: 0,
        }
    }
}

impl MarkPriceDelayState {
    pub fn record_mark_price_sample_and_update_action_delay(
        &mut self,
        now: NaiveDateTime,
        mark_price: f64,
    ) -> bool {
        if let Some(newest) = self.samples.back() {
            let earliest_next_sample = add_seconds(newest.time, MARK_PRICE_SAMPLE_SPACING_SECS);
            if now < earliest_next_sample {
                return false;
            }
        }

        if let Some(oldest) = self.samples.front().copied() {
            let elapsed = seconds_since_or_zero(now, oldest.time);
            if elapsed > MARK_PRICE_MIN_SAMPLE_SECS && elapsed <= MARK_PRICE_MAX_SAMPLE_SECS {
                let relative_move = mark_price / (oldest.mark_price + PRICE_DENOMINATOR_EPSILON) - 1.0;
                let mut value = relative_move * relative_move / elapsed;
                if value > 1.0 && value.is_finite() {
                    value = 1.0;
                }
                for bucket in &mut self.buckets {
                    bucket.update(now, value);
                }

                self.sample_counter = self.sample_counter.saturating_add(1);
                self.log_counter = self.log_counter.saturating_add(1);
                if self.sample_counter > 20 {
                    if let Some(rate) = select_valid_vty_bucket_rate(&self.buckets, BucketSelectionMode::Min) {
                        self.delay_scalar_a = rate;
                    }
                    if let Some(rate) = select_valid_vty_bucket_rate(&self.buckets, BucketSelectionMode::Max) {
                        self.delay_scalar_b = rate;
                    }
                }
            }
        }

        if self.samples.len() == self.samples.capacity() && self.samples.capacity() != 0 {
            self.samples.pop_front();
        }
        self.samples.push_back(MarkPriceSample { time: now, mark_price });

        let bucket = unix_millis_from_naive(now) / self.bucket_millis;
        let advanced = bucket > self.max_seen_bucket;
        if advanced {
            self.max_seen_bucket = bucket;
        }
        advanced
    }
}
pub fn record_mark_price_sample_and_update_action_delay(
    states: &mut BTreeMap<LocalAssetIndex, MarkPriceDelayState>,
    asset: LocalAssetIndex,
    now: NaiveDateTime,
    mark_price: f64,
) -> bool {
    states
        .entry(asset)
        .or_default()
        .record_mark_price_sample_and_update_action_delay(now, mark_price)
}

#[inline]
pub fn unix_millis_from_naive(time: NaiveDateTime) -> u64 {
    let millis = time.and_utc().timestamp_millis();
    millis.max(0) as u64
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinearDecayError {
    BadTag,
    StartsInFuture,
    InvertedRange,
}

impl LinearDecayError {
    pub fn recovered_tag(self) -> u16 {
        match self {
            LinearDecayError::BadTag => LINEAR_DECAY_BAD_TAG,
            LinearDecayError::StartsInFuture => LINEAR_DECAY_FUTURE_START,
            LinearDecayError::InvertedRange => LINEAR_DECAY_INVERTED_RANGE,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LinearMillisDecaySpec {
    pub tag: u8,
    pub starts_at: NaiveDateTime,
    pub duration_millis: u64,
    pub start_value: u64,
    pub end_value: u64,
}

pub fn linear_millis_decay_remaining(
    spec: LinearMillisDecaySpec,
    now: NaiveDateTime,
) -> Result<u64, LinearDecayError> {
    if spec.tag != 0 {
        return Err(LinearDecayError::BadTag);
    }
    if spec.starts_at > now {
        return Err(LinearDecayError::StartsInFuture);
    }
    if spec.start_value < spec.end_value {
        return Err(LinearDecayError::InvertedRange);
    }

    let elapsed_millis = f64_to_u64_saturating(
        (seconds_since_or_zero(now, spec.starts_at) * MILLIS_PER_SECOND_F64).round(),
    );
    let ratio = if spec.duration_millis == 0 {
        0.0
    } else {
        (1.0 - elapsed_millis as f64 / spec.duration_millis as f64).max(0.0)
    };
    if ratio > LINEAR_DECAY_RATIO_TOLERANCE {
        return Ok(spec.end_value);
    }

    let delta = f64_to_u64_saturating(ratio * (spec.start_value - spec.end_value) as f64);
    Ok(spec.end_value.checked_add(delta).unwrap_or(spec.end_value))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DexFlowStatus {
    Active,
    Paused,
    Deleted,
    ForceRefresh,
}

impl DexFlowStatus {
    #[inline]
    pub fn raw(self) -> u8 {
        match self {
            DexFlowStatus::Active => 0,
            DexFlowStatus::Paused => 1,
            DexFlowStatus::Deleted => 2,
            DexFlowStatus::ForceRefresh => 3,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DexFlowClock {
    pub status: DexFlowStatus,
    pub last_flow_time: NaiveDateTime,
}

impl DexFlowClock {
    pub fn record_elapsed_for_flow(&mut self, now: NaiveDateTime) -> Result<f64, u16> {
        if self.status != DexFlowStatus::ForceRefresh {
            let next_allowed = naive_datetime_add_secs_f64(self.last_flow_time, PERP_DEX_FLOW_MIN_REFRESH_SECS);
            if next_allowed > now {
                return Err(PERP_DEX_FLOW_THROTTLED_TAG);
            }
        }
        let elapsed = seconds_since_or_zero(now, self.last_flow_time);
        self.last_flow_time = now;
        Ok(elapsed)
    }
}

#[inline]
pub fn annualized_elapsed_factor(elapsed_secs: f64, configured_rate: f64) -> Option<f64> {
    let factor = elapsed_secs * configured_rate / SECONDS_PER_JULIAN_YEAR;
    if (0.0..=ACCRUAL_FACTOR_TOLERANCE).contains(&factor) {
        Some(factor)
    } else {
        None
    }
}

#[inline]
pub fn stale_cutoff_days(status_byte: u8) -> i64 {
    if status_byte == 2 { -2 } else { -45 }
}
