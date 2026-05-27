//! Recovered `scheduleCancel` / dead-man-switch handler.
//!
//! Binary evidence:
//! - wrapper `sub_1E5FC40` (`UserActionTag::ScheduleCancel`, idx 18)
//! - inner helper `l1_raw_vlm__sub_daily_exchange_vlm_gate_mono_a` at `0x2721260`
//! - payload manifest in `protocol/l1_action_payloads.md`
//!
//! The action is an optional timestamp in milliseconds:
//! - `Some(deadline_ms)` arms or refreshes the per-user dead-man switch.
//! - `None` clears any existing schedule.
//!
//! The recovered source below focuses on the trigger/dead-man semantics and the
//! timer/state mutations visible in the decompiled path.

#![allow(dead_code)]

pub type TimestampMillis = u64;
pub type UserKey20 = [u8; 20];

pub const RESULT_OK: u16 = 390;
pub const ERR_TIMESTAMP_OVERFLOW: u16 = 319;
pub const ERR_DEADMAN_ALREADY_EXPIRED: u16 = 268;
pub const ERR_DEADMAN_ENTRY_REJECTED: u16 = 269;
pub const ERR_DEADMAN_VOLUME_GATE: u16 = 270;
pub const ERR_TIMESTAMP_OUT_OF_RANGE: u16 = 133;

/// Recovered wire/layout shape from the action payload serializer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScheduleCancelAction {
    /// `None` disables the dead-man switch; `Some(ms)` arms it for the supplied
    /// Unix-millis deadline.
    pub time: Option<TimestampMillis>,
}

/// Per-user dead-man-switch record stored in the exchange tree at recovered
/// state offset `+14760`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScheduleCancelEntry {
    /// [INFERENCE] The helper rejects entries whose leading counter/state word is
    /// already greater than `9` before it overwrites the deadline fields.
    pub aux_word: u64,
    /// The clear path writes `0` here; the arm path overwrites it with the
    /// day-like component derived from the requested deadline.
    pub state_day_word: u32,
    /// Low 32 bits of the raw deadline in Unix milliseconds.
    pub deadline_ms_lo: u32,
    /// High 32 bits of the raw deadline in Unix milliseconds.
    pub deadline_ms_hi: u32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ScheduleCancelError {
    TimestampOverflow,
    TimestampOutOfRange,
    VolumeGate { observed_volume_x100: u64 },
    DeadlineAlreadyExpired,
    EntryRejected,
}

impl ScheduleCancelError {
    pub const fn code(self) -> u16 {
        match self {
            Self::TimestampOverflow => ERR_TIMESTAMP_OVERFLOW,
            Self::TimestampOutOfRange => ERR_TIMESTAMP_OUT_OF_RANGE,
            Self::VolumeGate { .. } => ERR_DEADMAN_VOLUME_GATE,
            Self::DeadlineAlreadyExpired => ERR_DEADMAN_ALREADY_EXPIRED,
            Self::EntryRejected => ERR_DEADMAN_ENTRY_REJECTED,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ScheduleCancelSuccess {
    /// `true` when the user supplied `Some(deadline_ms)` and the handler stored a
    /// new deadline; `false` when the user supplied `None` and the handler only
    /// cleared the existing armed flag/state.
    pub armed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ScheduleCancelOutcome {
    Ok(ScheduleCancelSuccess),
    Err(ScheduleCancelError),
}

impl ScheduleCancelOutcome {
    pub const fn code(&self) -> u16 {
        match self {
            Self::Ok(_) => RESULT_OK,
            Self::Err(err) => err.code(),
        }
    }
}

/// Minimal state surface used by the recovered handler.
#[derive(Debug, Default)]
pub struct ScheduleCancelState {
    /// Current exchange wall-clock in Unix milliseconds.
    pub now_ms: TimestampMillis,
    /// Recovered per-user dead-man-switch tree rooted at state offset `+14760`.
    pub schedule_cancel_by_user: std::collections::BTreeMap<UserKey20, ScheduleCancelEntry>,
    /// Aggregate volume the volume-gate helper compares against `100_000_000`.
    pub volume_gate_observed_x100: u64,
}

impl ScheduleCancelState {
    pub fn apply_schedule_cancel_recovered(
        &mut self,
        user: UserKey20,
        action: ScheduleCancelAction,
    ) -> ScheduleCancelOutcome {
        if let Some(deadline_ms) = action.time {
            if deadline_ms > 0x0CCC_CCCC_CCCC_CCCB {
                return ScheduleCancelOutcome::Err(ScheduleCancelError::TimestampOverflow);
            }
        }

        let observed_volume = self.volume_gate_observed_x100;
        if observed_volume < 100_000_000 {
            return ScheduleCancelOutcome::Err(ScheduleCancelError::VolumeGate {
                observed_volume_x100: observed_volume,
            });
        }

        match action.time {
            None => {
                if let Some(entry) = self.schedule_cancel_by_user.get_mut(&user) {
                    // The clear path keeps the tree node but zeroes this first
                    // mutable 32-bit word.
                    entry.state_day_word = 0;
                }
                ScheduleCancelOutcome::Ok(ScheduleCancelSuccess { armed: false })
            }
            Some(deadline_ms) => {
                if !unix_millis_is_representable(deadline_ms) {
                    return ScheduleCancelOutcome::Err(ScheduleCancelError::TimestampOutOfRange);
                }
                if deadline_ms <= self.now_ms {
                    return ScheduleCancelOutcome::Err(ScheduleCancelError::DeadlineAlreadyExpired);
                }

                let entry = self.schedule_cancel_by_user.entry(user).or_default();
                if entry.aux_word > 9 {
                    return ScheduleCancelOutcome::Err(ScheduleCancelError::EntryRejected);
                }

                entry.state_day_word = recovered_day_from_unix_millis(deadline_ms);
                entry.deadline_ms_lo = deadline_ms as u32;
                entry.deadline_ms_hi = (deadline_ms >> 32) as u32;

                ScheduleCancelOutcome::Ok(ScheduleCancelSuccess { armed: true })
            }
        }
    }
}

/// Recovered comparison gate from the chrono conversion path.
#[inline]
pub const fn unix_millis_is_representable(deadline_ms: TimestampMillis) -> bool {
    deadline_ms / 86_400_000 >= 2_146_764_485 && deadline_ms / 86_400_000 <= 4_294_967_295
}

/// [INFERENCE] The inner helper materializes a calendar day via chrono before it
/// stores the deadline. The exact packed representation is not recovered here; a
/// simple Unix-day split keeps the observable state update shape explicit.
#[inline]
pub const fn recovered_day_from_unix_millis(deadline_ms: TimestampMillis) -> u32 {
    (deadline_ms / 86_400_000) as u32
}

/// Wrapper behavior of `sub_1E5FC40`:
/// - inner `390` success is emitted as compact result tag `13`
/// - any non-`390` error is copied into the result payload and emitted as tag `14`
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduleCancelWrapperTag {
    Ok = 13,
    Err = 14,
}
