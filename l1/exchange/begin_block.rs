use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;

pub type UserAddress = [u8; 20];

const HOUR_ROLLOVER_SKEW_SECS: i64 = 10;
const SECONDS_PER_HOUR: u32 = 3_600;
const SECONDS_PER_DAY: i64 = 86_400;
const HOURLY_RING_SLOTS: u64 = 20;
const HOURLY_RESET_DELAY_SECS: i64 = 2;
const HOURLY_RESET_RETENTION_DAYS: i64 = 2;
const STRICT_LATENCY_THRESHOLD_SECS: f64 = 1.0;
const NORMAL_LATENCY_THRESHOLD_SECS: f64 = 5.0;
const CHRONO_UNWRAP_UPPER_BOUND_SECONDS: u32 = 0xE1000;
const ASSERTED_MAX_SECONDS_OF_DAY: u32 = 0x15F90;
const MILLIS_PER_SECOND: i64 = 1_000;
const NANOS_PER_MILLI: u32 = 1_000_000;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NaiveDateTime12 {
    pub seconds: i64,
    pub nanos: u32,
}

impl NaiveDateTime12 {
    #[inline]
    pub fn checked_add_seconds(self, seconds: i64) -> Option<Self> {
        Some(Self {
            seconds: self.seconds.checked_add(seconds)?,
            nanos: self.nanos,
        })
    }

    #[inline]
    pub fn checked_sub_seconds(self, seconds: i64) -> Option<Self> {
        self.checked_add_seconds(seconds.checked_neg()?)
    }

    #[inline]
    pub fn unix_millis_saturating(self) -> u64 {
        let millis = self
            .seconds
            .saturating_mul(MILLIS_PER_SECOND)
            .saturating_add(i64::from(self.nanos / NANOS_PER_MILLI));
        millis.max(0) as u64
    }

    #[inline]
    pub fn seconds_from_midnight(self) -> u32 {
        self.seconds.rem_euclid(SECONDS_PER_DAY) as u32
    }

    #[inline]
    pub fn hour(self) -> u32 {
        let seconds_from_midnight = self.seconds_from_midnight();
        if seconds_from_midnight >= CHRONO_UNWRAP_UPPER_BOUND_SECONDS {
            panic!("called Result::unwrap() on an Err value");
        }
        assert!(
            seconds_from_midnight < ASSERTED_MAX_SECONDS_OF_DAY,
            "assertion failed: hour <= 24"
        );
        seconds_from_midnight / SECONDS_PER_HOUR
    }
}

#[derive(Clone, Debug, Default)]
pub struct BeginBlockActivity {
    /// Five independent activity probes are observed in each builder variant.
    pub active_by_probe: [HashSet<UserAddress>; 5],
    /// Fallback/pinned set consulted when a user hashes into the expired slot.
    pub protected_users: HashSet<UserAddress>,
}

impl BeginBlockActivity {
    #[inline]
    pub fn has_open_activity(&self, user: &UserAddress) -> bool {
        self.active_by_probe.iter().any(|probe| probe.contains(user))
    }

    #[inline]
    pub fn is_protected(&self, user: &UserAddress) -> bool {
        self.protected_users.contains(user)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BeginBlockState {
    /// Current exchange timestamp, stored in the binary at the common +0x60/+0x68 chrono layout.
    pub current_time: NaiveDateTime12,
    /// Hash-table of users that can participate in the hourly reset ring.
    pub active_user_table: HashSet<UserAddress>,
    pub activity: BeginBlockActivity,
    pub hourly_ring_slot: u64,
    pub hourly_reset: HourlyResetState,
}

pub type CoreBeginBlockState = BeginBlockState;
pub type ShiftedBeginBlockState = BeginBlockState;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HourlyResetEntry {
    pub user: UserAddress,
    pub scheduled_at: NaiveDateTime12,
    pub value: u64,
}

impl HourlyResetEntry {
    #[inline]
    pub fn rescheduled(mut self, scheduled_at: NaiveDateTime12) -> Self {
        self.scheduled_at = scheduled_at;
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct HourlyResetState {
    /// First two collections are drained against the reset user set.
    pub primary_pending: BTreeMap<UserAddress, Vec<HourlyResetEntry>>,
    pub secondary_pending: BTreeMap<UserAddress, Vec<HourlyResetEntry>>,
    /// Third collection is drained against the reset set plus keys moved from the first two collections.
    pub tertiary_pending: BTreeMap<UserAddress, Vec<HourlyResetEntry>>,
    /// Timestamp-indexed records pruned with the two-day cutoff.
    pub timestamp_index: BTreeMap<u64, Vec<UserAddress>>,
    /// Per-user schedule that receives entries delayed by two seconds from the current block time.
    pub per_user_schedule: HashMap<UserAddress, Vec<HourlyResetEntry>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct BeginBlockLatencySample {
    pub elapsed_seconds: f64,
    pub threshold_seconds: f64,
    pub exceeded_threshold: bool,
}

/// Core-layout begin-block hook. The binary calls this after comparing the caller-supplied
/// timestamp with the exchange state's timestamp, both shifted backward by ten seconds.
pub fn run_core_hourly_hooks(
    state: &mut CoreBeginBlockState,
    comparison_time: NaiveDateTime12,
    strict_latency: bool,
    prior_sample: f64,
) -> f64 {
    run_hourly_hooks(
        state.current_time,
        &state.active_user_table,
        &state.activity,
        &mut state.hourly_ring_slot,
        &mut state.hourly_reset,
        comparison_time,
        strict_latency,
        prior_sample,
    )
}

/// Shifted-layout begin-block hook. High-level behavior matches the core layout; only the
/// concrete state-field offsets differ in the binary.
pub fn run_shifted_hourly_hooks(
    state: &mut ShiftedBeginBlockState,
    comparison_time: NaiveDateTime12,
    strict_latency: bool,
    prior_sample: f64,
) -> f64 {
    run_hourly_hooks(
        state.current_time,
        &state.active_user_table,
        &state.activity,
        &mut state.hourly_ring_slot,
        &mut state.hourly_reset,
        comparison_time,
        strict_latency,
        prior_sample,
    )
}

/// Alternate codegen variant of the core-layout hook; recovered control flow is identical.
pub fn run_core_hourly_hooks_alt(
    state: &mut CoreBeginBlockState,
    comparison_time: NaiveDateTime12,
    strict_latency: bool,
    prior_sample: f64,
) -> f64 {
    run_core_hourly_hooks(state, comparison_time, strict_latency, prior_sample)
}

fn run_hourly_hooks(
    current_time: NaiveDateTime12,
    active_user_table: &HashSet<UserAddress>,
    activity: &BeginBlockActivity,
    hourly_ring_slot: &mut u64,
    hourly_reset: &mut HourlyResetState,
    comparison_time: NaiveDateTime12,
    strict_latency: bool,
    prior_sample: f64,
) -> f64 {
    let comparison_hour = hour_after_rollover_skew(comparison_time);
    let current_hour = hour_after_rollover_skew(current_time);
    if comparison_hour == current_hour {
        return prior_sample;
    }

    let started = Instant::now();
    let expired_slot = advance_hourly_ring_slot(hourly_ring_slot);
    let reset_users = build_active_hourly_ring_users(active_user_table, expired_slot, activity);
    let cutoff_ms = timestamp_minus_two_days_ms(current_time);
    update_hourly_user_reset_state(hourly_reset, &reset_users, cutoff_ms, current_time);

    let threshold = if strict_latency {
        STRICT_LATENCY_THRESHOLD_SECS
    } else {
        NORMAL_LATENCY_THRESHOLD_SECS
    };
    record_latency_sample(started, threshold).elapsed_seconds
}

#[inline]
fn hour_after_rollover_skew(time: NaiveDateTime12) -> u32 {
    time.checked_sub_seconds(HOUR_ROLLOVER_SKEW_SECS)
        .expect("`NaiveDateTime - TimeDelta` overflowed")
        .hour()
}

/// Returns the expired slot value and advances the stored ring index.
///
/// The machine code special-cases `u64::MAX`: it does not wrap it to zero before the
/// modulo-20 reduction, so an all-ones sentinel advances the stored slot to 15 while
/// the expired-slot comparison still sees the all-ones value.
#[inline]
pub fn advance_hourly_ring_slot(slot: &mut u64) -> u64 {
    let expired_slot = *slot;
    let next = if expired_slot == u64::MAX {
        u64::MAX
    } else {
        expired_slot + 1
    };
    *slot = next % HOURLY_RING_SLOTS;
    expired_slot
}

pub fn build_active_hourly_ring_users(
    active_user_table: &HashSet<UserAddress>,
    expired_slot: u64,
    activity: &BeginBlockActivity,
) -> HashSet<UserAddress> {
    active_user_table
        .iter()
        .copied()
        .filter(|user| retain_user_for_expired_slot(user, expired_slot, activity))
        .collect()
}

pub fn build_active_hourly_ring_users_shifted(
    active_user_table: &HashSet<UserAddress>,
    expired_slot: u64,
    activity: &BeginBlockActivity,
) -> HashSet<UserAddress> {
    build_active_hourly_ring_users(active_user_table, expired_slot, activity)
}

pub fn build_active_hourly_ring_users_core_alt(
    active_user_table: &HashSet<UserAddress>,
    expired_slot: u64,
    activity: &BeginBlockActivity,
) -> HashSet<UserAddress> {
    build_active_hourly_ring_users(active_user_table, expired_slot, activity)
}

#[inline]
fn retain_user_for_expired_slot(
    user: &UserAddress,
    expired_slot: u64,
    activity: &BeginBlockActivity,
) -> bool {
    user_hourly_ring_slot(user) != expired_slot || activity.has_open_activity(user) || activity.is_protected(user)
}

#[inline]
pub fn user_hourly_ring_slot(user: &UserAddress) -> u64 {
    let mut tail = [0_u8; 8];
    tail.copy_from_slice(&user[12..20]);
    u64::from_le_bytes(tail) % HOURLY_RING_SLOTS
}

pub fn timestamp_minus_two_days_ms(current_time: NaiveDateTime12) -> u64 {
    current_time
        .checked_sub_seconds(SECONDS_PER_DAY * HOURLY_RESET_RETENTION_DAYS)
        .expect("`NaiveDateTime - TimeDelta` overflowed")
        .unix_millis_saturating()
}

pub fn update_hourly_user_reset_state(
    hourly_state: &mut HourlyResetState,
    reset_user_set: &HashSet<UserAddress>,
    cutoff_ms: u64,
    block_timestamp: NaiveDateTime12,
) {
    let primary = drain_matching_entries(&mut hourly_state.primary_pending, reset_user_set);
    let secondary = drain_matching_entries(&mut hourly_state.secondary_pending, reset_user_set);

    let mut tertiary_keys = reset_user_set.clone();
    tertiary_keys.extend(primary.iter().map(|entry| entry.user));
    tertiary_keys.extend(secondary.iter().map(|entry| entry.user));
    let tertiary = drain_matching_entries(&mut hourly_state.tertiary_pending, &tertiary_keys);

    let scheduled_at = block_timestamp
        .checked_add_seconds(HOURLY_RESET_DELAY_SECS)
        .expect("`NaiveDateTime + TimeDelta` overflowed");

    for entry in primary.into_iter().chain(secondary).chain(tertiary) {
        let user = entry.user;
        let entry = entry.rescheduled(scheduled_at);
        hourly_state
            .per_user_schedule
            .entry(user)
            .or_default()
            .push(entry);
        hourly_state
            .timestamp_index
            .entry(scheduled_at.unix_millis_saturating())
            .or_default()
            .push(user);
    }

    prune_hourly_reset_state(hourly_state, cutoff_ms);
}

fn drain_matching_entries(
    source: &mut BTreeMap<UserAddress, Vec<HourlyResetEntry>>,
    users: &HashSet<UserAddress>,
) -> Vec<HourlyResetEntry> {
    let keys: Vec<UserAddress> = source
        .keys()
        .filter(|user| users.contains(*user))
        .copied()
        .collect();
    let mut drained = Vec::new();
    for key in keys {
        if let Some(entries) = source.remove(&key) {
            drained.extend(entries);
        }
    }
    drained
}

pub fn prune_hourly_reset_state(hourly_state: &mut HourlyResetState, cutoff_ms: u64) {
    let stale_timestamps: Vec<u64> = hourly_state
        .timestamp_index
        .range(..=cutoff_ms)
        .map(|(timestamp, _)| *timestamp)
        .collect();

    for timestamp in stale_timestamps {
        if let Some(users) = hourly_state.timestamp_index.remove(&timestamp) {
            for user in users {
                let remove_user = if let Some(entries) = hourly_state.per_user_schedule.get_mut(&user) {
                    entries.retain(|entry| entry.scheduled_at.unix_millis_saturating() > cutoff_ms);
                    entries.is_empty()
                } else {
                    false
                };
                if remove_user {
                    hourly_state.per_user_schedule.remove(&user);
                }
            }
        }
    }
}

#[inline]
pub fn record_latency_sample(started: Instant, threshold_seconds: f64) -> BeginBlockLatencySample {
    let elapsed_seconds = started.elapsed().as_secs_f64();
    BeginBlockLatencySample {
        elapsed_seconds,
        threshold_seconds,
        exceeded_threshold: elapsed_seconds > threshold_seconds,
    }
}
