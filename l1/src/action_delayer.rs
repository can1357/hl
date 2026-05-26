use std::collections::BTreeMap;

pub type Address = [u8; 20];
pub type L1Hash = [u8; 32];
pub type Signature = Vec<u8>;
pub type ActionKind = u32;
pub type UnixSeconds = u64;

pub const MIN_ACTION_DELAY_SECONDS: f64 = 0.76;
pub const ALERT_ACTION_DELAY_SECONDS: f64 = 2.0;
pub const VTY_REFERENCE_NOTIONAL: f64 = 10_000.0;
pub const FRONTEND_ACTION_ID_START: ActionKind = 10_000;
pub const FRONTEND_ACTION_ID_END: ActionKind = 110_000;
pub const BROADCASTER_ACTION_ID_START: ActionKind = 100_000_000;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct DelayedActionId {
    pub l1_hash: L1Hash,
    pub hot_user_to_signature: BTreeMap<Address, Signature>,
    pub hard_voter_to_signature: BTreeMap<Address, Signature>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelayedAction {
    pub action_id: DelayedActionId,
    pub is_frontend: bool,
    pub expires_after: UnixSeconds,
    pub broadcaster: Address,
    pub time_referred: UnixSeconds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionDelayerMode {
    Disabled,
    Enabled,
    DeterministicVty,
    DeterministicEma,
}

impl ActionDelayerMode {
    #[inline]
    pub fn is_enabled(self) -> bool {
        !matches!(self, ActionDelayerMode::Disabled)
    }

    #[inline]
    pub fn delay_curve_byte(self) -> u8 {
        match self {
            ActionDelayerMode::Disabled | ActionDelayerMode::Enabled => 1,
            ActionDelayerMode::DeterministicVty => 2,
            ActionDelayerMode::DeterministicEma => 3,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DeterministicVty {
    pub n_per_bucket: u64,
    pub min: f64,
    pub max: f64,
}

#[derive(Clone, Debug)]
pub struct ActionDelayStatusEntry {
    pub delay_seconds: String,
    pub vty: String,
}

#[derive(Clone, Debug, Default)]
pub struct ActionDelayerStatus {
    pub current: BTreeMap<ActionKind, ActionDelayStatusEntry>,
    pub alerting: BTreeMap<ActionKind, ActionDelayStatusEntry>,
}

#[derive(Clone, Debug)]
pub struct ActionDelayer {
    pub delayed_actions: BTreeMap<DelayedActionId, DelayedAction>,
    pub user_to_n_delayed_actions: BTreeMap<Address, u64>,
    pub n_total_delayed_actions: u64,
    pub max_n_delayed_actions: u64,
    pub vty_trackers: BTreeMap<ActionKind, DeterministicVty>,
    pub status_guard: bool,
    pub delayer_mode: ActionDelayerMode,
    pub delay_scale: f64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueueDelayedActionError {
    Disabled,
    DuplicateAction,
    MaxDelayedActionsReached,
    DelayOverflow,
}

impl Default for ActionDelayer {
    fn default() -> Self {
        Self {
            delayed_actions: BTreeMap::new(),
            user_to_n_delayed_actions: BTreeMap::new(),
            n_total_delayed_actions: 0,
            max_n_delayed_actions: 0,
            vty_trackers: BTreeMap::new(),
            status_guard: false,
            delayer_mode: ActionDelayerMode::Disabled,
            delay_scale: 1.0,
        }
    }
}

impl ActionDelayer {
    #[inline]
    pub fn set_enabled(&mut self, enabled: bool) {
        self.delayer_mode = if enabled {
            ActionDelayerMode::Enabled
        } else {
            ActionDelayerMode::Disabled
        };
    }

    #[inline]
    pub fn set_max_n_delayed_actions(&mut self, max_n_delayed_actions: u64) {
        self.max_n_delayed_actions = max_n_delayed_actions;
    }

    #[inline]
    pub fn can_delay_more_actions(&self) -> bool {
        self.max_n_delayed_actions == 0 || self.n_total_delayed_actions < self.max_n_delayed_actions
    }

    pub fn queue_delayed_action(
        &mut self,
        mut action: DelayedAction,
        action_kind: ActionKind,
        now: UnixSeconds,
    ) -> Result<UnixSeconds, QueueDelayedActionError> {
        if !self.delayer_mode.is_enabled() {
            return Err(QueueDelayedActionError::Disabled);
        }
        if !self.can_delay_more_actions() {
            return Err(QueueDelayedActionError::MaxDelayedActionsReached);
        }
        if self.delayed_actions.contains_key(&action.action_id) {
            return Err(QueueDelayedActionError::DuplicateAction);
        }

        let delay = self.delay_for_action_kind(action_kind);
        let delay_seconds = ceil_nonnegative_seconds(delay * self.delay_scale);
        let expires_after = now
            .checked_add(delay_seconds)
            .ok_or(QueueDelayedActionError::DelayOverflow)?;

        action.time_referred = now;
        action.expires_after = expires_after;
        let broadcaster = action.broadcaster;
        let id = action.action_id.clone();

        self.delayed_actions.insert(id, action);
        *self.user_to_n_delayed_actions.entry(broadcaster).or_insert(0) += 1;
        self.n_total_delayed_actions += 1;
        Ok(expires_after)
    }

    pub fn release_due_actions(&mut self, now: UnixSeconds) -> Vec<DelayedAction> {
        let due_ids: Vec<_> = self
            .delayed_actions
            .iter()
            .filter_map(|(id, action)| (action.expires_after <= now).then(|| id.clone()))
            .collect();

        let mut due = Vec::with_capacity(due_ids.len());
        for id in due_ids {
            if let Some(action) = self.delayed_actions.remove(&id) {
                self.note_action_removed(action.broadcaster);
                due.push(action);
            }
        }
        due
    }

    pub fn release_oldest_actions(&mut self, n: u64) -> Vec<DelayedAction> {
        let mut candidates: Vec<_> = self
            .delayed_actions
            .iter()
            .map(|(id, action)| (action.expires_after, action.time_referred, id.clone()))
            .collect();
        candidates.sort_by_key(|(expires_after, time_referred, id)| (*expires_after, *time_referred, id.clone()));

        let mut released = Vec::new();
        for (_, _, id) in candidates.into_iter().take(n as usize) {
            if let Some(action) = self.delayed_actions.remove(&id) {
                self.note_action_removed(action.broadcaster);
                released.push(action);
            }
        }
        released
    }

    pub fn remove_delayed_action(&mut self, action_id: &DelayedActionId) -> Option<DelayedAction> {
        let action = self.delayed_actions.remove(action_id)?;
        self.note_action_removed(action.broadcaster);
        Some(action)
    }

    pub fn delay_for_action_kind(&self, action_kind: ActionKind) -> f64 {
        let vty = self
            .vty_trackers
            .get(&action_kind)
            .map(|tracker| tracker.max)
            .unwrap_or(0.0);
        deterministic_delay_seconds(self.delayer_mode.delay_curve_byte(), action_kind, vty)
    }

    pub fn build_status(&self) -> ActionDelayerStatus {
        let mut status = ActionDelayerStatus::default();
        for (&action_kind, tracker) in &self.vty_trackers {
            let delay = deterministic_delay_seconds(
                self.delayer_mode.delay_curve_byte(),
                action_kind,
                tracker.max,
            );
            if delay == MIN_ACTION_DELAY_SECONDS {
                continue;
            }

            let entry = ActionDelayStatusEntry {
                delay_seconds: format!("{delay}"),
                vty: format!("\nVty {{min: {}, max: {}}}", tracker.min, tracker.max),
            };
            if delay > ALERT_ACTION_DELAY_SECONDS {
                status.alerting.insert(action_kind, entry.clone());
            }
            status.current.insert(action_kind, entry);
        }
        status
    }

    #[inline]
    pub fn should_emit_status(&self, status: &ActionDelayerStatus) -> bool {
        status.current.len() > 2
    }

    fn note_action_removed(&mut self, broadcaster: Address) {
        if let Some(count) = self.user_to_n_delayed_actions.get_mut(&broadcaster) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.user_to_n_delayed_actions.remove(&broadcaster);
            }
        }
        self.n_total_delayed_actions = self.n_total_delayed_actions.saturating_sub(1);
    }
}

pub fn deterministic_delay_seconds(mode: u8, action_kind: ActionKind, vty_or_notional: f64) -> f64 {
    let (raw_weight, special_curve) = if mode == 2 {
        if matches!(action_kind, 3 | 4 | 11_054 | 11_137) {
            (vty_power_weight(vty_or_notional, -1.5) * 0.125, true)
        } else if action_kind == 0 {
            (vty_power_weight(vty_or_notional, -3.0) / 12.0, true)
        } else {
            (default_delay_weight(vty_or_notional), false)
        }
    } else if matches!(action_kind, 0 | 1 | 10_142 | 10_151) {
        (vty_power_weight(vty_or_notional, -1.5) * 0.125, true)
    } else if action_kind == 5 {
        (vty_power_weight(vty_or_notional, -3.0) / 12.0, true)
    } else {
        (default_delay_weight(vty_or_notional), false)
    };

    let clamped = clamp_delay_weight(raw_weight);
    let unscaled = if special_curve {
        clamped * 1.8 + MIN_ACTION_DELAY_SECONDS
    } else {
        clamped * 1.3 + MIN_ACTION_DELAY_SECONDS
    };
    let delay = if !special_curve && uses_short_delay_multiplier(action_kind) {
        unscaled * 0.2
    } else {
        unscaled * 0.65
    };
    assert!(delay >= 0.0);
    delay
}

#[inline]
fn default_delay_weight(vty_or_notional: f64) -> f64 {
    vty_power_weight(vty_or_notional, -4.0) / 20.0
}

#[inline]
fn vty_power_weight(vty_or_notional: f64, exponent: f64) -> f64 {
    (vty_or_notional / VTY_REFERENCE_NOTIONAL).powf(exponent)
}

#[inline]
fn clamp_delay_weight(weight: f64) -> f64 {
    assert!(!weight.is_nan());
    weight.max(0.0).min(1.0)
}

#[inline]
fn uses_short_delay_multiplier(action_kind: ActionKind) -> bool {
    action_kind >= BROADCASTER_ACTION_ID_START
        || (FRONTEND_ACTION_ID_START..FRONTEND_ACTION_ID_END).contains(&action_kind)
}


#[inline]
fn ceil_nonnegative_seconds(delay_seconds: f64) -> u64 {
    if delay_seconds.is_nan() || delay_seconds <= 0.0 {
        0
    } else if delay_seconds >= u64::MAX as f64 {
        u64::MAX
    } else {
        delay_seconds.ceil() as u64
    }
}
