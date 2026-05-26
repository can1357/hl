use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use crate::base::latency_sampler::LatencySampler;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitDecision {
    Allowed,
    AlreadyPresent,
    Disabled,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RateLimitKey(pub Vec<u8>);

#[derive(Clone, Debug)]
pub struct RateLimiterSlot {
    pub key: RateLimitKey,
    pub expires_at: Instant,
}

#[derive(Clone, Debug, Default)]
pub struct RateLimiterStats {
    pub checks: u64,
    pub inserts: u64,
    pub duplicate_hits: u64,
    pub evictions: u64,
}

#[derive(Clone, Debug)]
pub struct RateLimiter {
    enabled: bool,
    ttl: Duration,
    recent: BTreeSet<RateLimitKey>,
    slots: Vec<RateLimiterSlot>,
    latency_sampler: Option<LatencySampler>,
    stats: RateLimiterStats,
}

impl RateLimiter {
    pub fn new(ttl: Duration) -> Self {
        Self {
            enabled: true,
            ttl,
            recent: BTreeSet::new(),
            slots: Vec::new(),
            latency_sampler: None,
            stats: RateLimiterStats::default(),
        }
    }

    pub fn with_latency_sampler(mut self, sampler: LatencySampler) -> Self {
        self.latency_sampler = Some(sampler);
        self
    }

    pub fn disable(&mut self) {
        self.enabled = false;
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn stats(&self) -> &RateLimiterStats {
        &self.stats
    }

    pub fn clear(&mut self) {
        self.recent.clear();
        self.slots.clear();
    }

    /// [INFERENCE] The seed at `0x4C8B860` performs the internal compaction step:
    /// it walks the occupied slot structures, frees temporary vectors, clears
    /// occupancy bitsets, and resets the active counters for each internal table.
    pub fn compact_expired(&mut self, now: Instant) {
        let before = self.slots.len();
        self.slots.retain(|slot| slot.expires_at > now);
        self.recent.clear();
        for slot in &self.slots {
            self.recent.insert(slot.key.clone());
        }
        self.stats.evictions = self
            .stats
            .evictions
            .saturating_add((before.saturating_sub(self.slots.len())) as u64);
    }

    /// [INFERENCE] The caller at `0x4714C10` checks an enable byte, runs compaction,
    /// copies the candidate key bytes, acquires a shared/global lock, looks for an
    /// existing key, inserts on miss, and records elapsed time in a latency sampler.
    pub fn check_or_insert(&mut self, key: &[u8], now: Instant) -> RateLimitDecision {
        if !self.enabled {
            return RateLimitDecision::Disabled;
        }

        let started_at = now;
        self.compact_expired(now);
        self.stats.checks = self.stats.checks.saturating_add(1);

        let key = RateLimitKey(key.to_vec());
        if self.recent.contains(&key) {
            self.stats.duplicate_hits = self.stats.duplicate_hits.saturating_add(1);
            self.record_latency(started_at, now);
            return RateLimitDecision::AlreadyPresent;
        }

        self.recent.insert(key.clone());
        self.slots.push(RateLimiterSlot {
            key,
            expires_at: now + self.ttl,
        });
        self.stats.inserts = self.stats.inserts.saturating_add(1);
        self.record_latency(started_at, now);
        RateLimitDecision::Allowed
    }

    fn record_latency(&mut self, started_at: Instant, finished_at: Instant) {
        let elapsed = finished_at.saturating_duration_since(started_at).as_secs_f64();
        if let Some(sampler) = self.latency_sampler.as_mut() {
            sampler.record_sample(1, elapsed);
        }
    }
}
