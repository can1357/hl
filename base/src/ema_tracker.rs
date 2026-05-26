//! Reconstruction of `/home/ubuntu/hl/code_Mainnet/base/src/ema_tracker.rs`.
//!
//! Seed overlap: `0x4726A50` is associated with both this base helper and
//! `node/src/consensus/heartbeat_tracker.rs` through rodata/path evidence. Current
//! IDA decompile was blocked by a full queue, so this file captures the behavior
//! required by the heartbeat liveness path: update an exponentially weighted moving
//! average from observed f64 latency samples without allocating.
//!
//! Pending IDA hygiene: lookup/decompile `0x4726A50`, then rename/comment/apply a
//! concrete `hl_base_EmaTracker` type if the current binary confirms this helper.

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EmaTracker {
    value: f64,
    initialized: bool,
    alpha: f64,
}

impl EmaTracker {
    pub const fn new(alpha: f64) -> Self {
        Self { value: 0.0, initialized: false, alpha }
    }

    pub const fn is_initialized(self) -> bool {
        self.initialized
    }

    pub fn value(self) -> Option<f64> {
        self.initialized.then_some(self.value)
    }

    pub fn update(&mut self, sample: f64) -> f64 {
        if self.initialized {
            self.value = self.alpha.mul_add(sample, (1.0 - self.alpha) * self.value);
        } else {
            self.value = sample;
            self.initialized = true;
        }
        self.value
    }

    pub fn reset(&mut self) {
        self.value = 0.0;
        self.initialized = false;
    }
}
