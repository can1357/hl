#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];

pub const STATUS_OK: u16 = 390;
pub const STATUS_CHAIN_DISCRIMINANT_BLOCKED: u16 = 141;
pub const STATUS_SUB_ACCOUNT_NOT_ALLOWED: u16 = 219;
pub const STATUS_ACTIVE_FEE_TRIAL_ALREADY_RUNNING: u16 = 308;
pub const STATUS_UNSUPPORTED_FEE_TRIAL_TEMPLATE: u16 = 309;
pub const STATUS_FEE_TRIAL_HAS_NO_EFFECT: u16 = 310;
pub const STATUS_FEE_TRIAL_COOLDOWN_ACTIVE: u16 = 311;
pub const STATUS_FEE_TRIALS_DISABLED: u16 = 312;

pub const MAINNET_CHAIN_DISCRIMINANT: u8 = 3;
pub const FEE_TRIAL_DURATION_DAYS: u32 = 14;
pub const FEE_TRIAL_COOLDOWN_DAYS: u32 = 90;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct FeeRates {
    pub perp_add_base_rate: f64,
    pub perp_cross_base_rate: f64,
    pub spot_add_base_rate: f64,
    pub spot_cross_base_rate: f64,
}

impl FeeRates {
    #[inline]
    pub fn map_positive(self, mut f: impl FnMut(f64) -> f64) -> Self {
        let apply = |value: f64, f: &mut dyn FnMut(f64) -> f64| {
            if value > 0.0 {
                f(value)
            } else {
                value
            }
        };
        Self {
            perp_add_base_rate: apply(self.perp_add_base_rate, &mut f),
            perp_cross_base_rate: apply(self.perp_cross_base_rate, &mut f),
            spot_add_base_rate: apply(self.spot_add_base_rate, &mut f),
            spot_cross_base_rate: apply(self.spot_cross_base_rate, &mut f),
        }
    }

    #[inline]
    pub fn pointwise_min(self, rhs: Self) -> Self {
        Self {
            perp_add_base_rate: self.perp_add_base_rate.min(rhs.perp_add_base_rate),
            perp_cross_base_rate: self.perp_cross_base_rate.min(rhs.perp_cross_base_rate),
            spot_add_base_rate: self.spot_add_base_rate.min(rhs.spot_add_base_rate),
            spot_cross_base_rate: self.spot_cross_base_rate.min(rhs.spot_cross_base_rate),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StartFeeTrialAction {
    pub rates: FeeRates,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FeeTrialTemplate {
    pub rates: FeeRates,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CrossRateOverride {
    /// The recovery only consumes the second `f64` in each 16-byte slot.
    pub cross_rate: f64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct VolumeDiscountTier {
    pub min_volume_anchor: f64,
    pub discount: f64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FeeTrialDefaults {
    pub effective_rates: FeeRates,
    pub volume_anchor: f64,
    pub carried_discount_multiplier: f64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FeeTrialRecord {
    pub active: bool,
    pub effective_rates: FeeRates,
    pub volume_anchor: f64,
    pub requested_rates: FeeRates,
    pub previous_rates: FeeRates,
    /// Stored as `current_day + 14` by the recovered helper and later checked as
    /// `trial_end_day + 90 > current_day` before allowing another trial.
    pub trial_end_day: u32,
    pub carried_discount_multiplier: f64,
}

impl FeeTrialRecord {
    #[inline]
    pub fn current_profile_or(defaults: FeeTrialDefaults, record: Option<&Self>) -> FeeTrialDefaults {
        match record {
            Some(record) if record.active => FeeTrialDefaults {
                effective_rates: record.effective_rates,
                volume_anchor: record.volume_anchor,
                carried_discount_multiplier: record.carried_discount_multiplier,
            },
            _ => defaults,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct FeeTrialRuntime {
    pub disabled: bool,
    pub allowed_templates: Vec<FeeTrialTemplate>,
    pub cross_rate_overrides: Vec<CrossRateOverride>,
    pub volume_discount_tiers: Vec<VolumeDiscountTier>,
    pub defaults: FeeTrialDefaults,
    pub records_by_user: BTreeMap<Address, FeeTrialRecord>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ExchangeState {
    /// Byte at exchange offset `+0x8f2`; the wrapper rejects when it is `3`.
    pub chain_discriminant: u8,
    /// Sub-account membership table probed before the fee-trial helper runs.
    pub sub_account_master_by_user: BTreeMap<Address, Address>,
    /// Runtime rooted at recovered offset `+0x5d0` (`a4[93]`).
    pub fee_trial_runtime: FeeTrialRuntime,
    /// Day counter sourced from the dispatcher context at `a4[6].m128i_i32[2]`.
    pub current_day: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartFeeTrialError {
    ChainDiscriminantBlocked,
    SubAccountNotAllowed,
    ActiveTrialAlreadyRunning,
    UnsupportedFeeTrialTemplate,
    FeeTrialHasNoEffect,
    FeeTrialCooldownActive,
    FeeTrialsDisabled,
}

impl StartFeeTrialError {
    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::ChainDiscriminantBlocked => STATUS_CHAIN_DISCRIMINANT_BLOCKED,
            Self::SubAccountNotAllowed => STATUS_SUB_ACCOUNT_NOT_ALLOWED,
            Self::ActiveTrialAlreadyRunning => STATUS_ACTIVE_FEE_TRIAL_ALREADY_RUNNING,
            Self::UnsupportedFeeTrialTemplate => STATUS_UNSUPPORTED_FEE_TRIAL_TEMPLATE,
            Self::FeeTrialHasNoEffect => STATUS_FEE_TRIAL_HAS_NO_EFFECT,
            Self::FeeTrialCooldownActive => STATUS_FEE_TRIAL_COOLDOWN_ACTIVE,
            Self::FeeTrialsDisabled => STATUS_FEE_TRIALS_DISABLED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StartFeeTrialOutcome {
    pub status: u16,
    pub record: FeeTrialRecord,
}

pub fn apply_start_fee_trial(
    exchange: &mut ExchangeState,
    sender: Address,
    linked_users: &[Address],
    action: &StartFeeTrialAction,
) -> Result<StartFeeTrialOutcome, StartFeeTrialError> {
    if exchange.chain_discriminant == MAINNET_CHAIN_DISCRIMINANT {
        return Err(StartFeeTrialError::ChainDiscriminantBlocked);
    }
    if exchange.sub_account_master_by_user.contains_key(&sender) {
        return Err(StartFeeTrialError::SubAccountNotAllowed);
    }

    let runtime = &mut exchange.fee_trial_runtime;
    if runtime.disabled {
        return Err(StartFeeTrialError::FeeTrialsDisabled);
    }

    let current_profile = FeeTrialRecord::current_profile_or(
        runtime.defaults,
        runtime.records_by_user.get(&sender),
    );
    if runtime.records_by_user.get(&sender).is_some_and(|record| record.active) {
        return Err(StartFeeTrialError::ActiveTrialAlreadyRunning);
    }
    if !is_supported_fee_trial(runtime, action.rates) {
        return Err(StartFeeTrialError::UnsupportedFeeTrialTemplate);
    }
    if runtime.records_by_user.get(&sender).is_some_and(|record| {
        add_days(record.trial_end_day, FEE_TRIAL_COOLDOWN_DAYS) > exchange.current_day
    }) {
        return Err(StartFeeTrialError::FeeTrialCooldownActive);
    }

    let record = build_trial_record(runtime, current_profile, action.rates, exchange.current_day)
        .ok_or(StartFeeTrialError::FeeTrialHasNoEffect)?;

    let mut targets = BTreeSet::from([sender]);
    targets.extend(linked_users.iter().copied());
    for user in targets {
        runtime.records_by_user.insert(user, record);
    }

    Ok(StartFeeTrialOutcome {
        status: STATUS_OK,
        record,
    })
}

fn is_supported_fee_trial(runtime: &FeeTrialRuntime, rates: FeeRates) -> bool {
    if runtime.allowed_templates.iter().any(|template| template.rates == rates) {
        return true;
    }

    let add_rates_match_any_template = runtime.allowed_templates.iter().any(|template| {
        template.rates.perp_add_base_rate == rates.perp_add_base_rate
            && template.rates.spot_add_base_rate == rates.spot_add_base_rate
    });
    add_rates_match_any_template
        && rates.perp_cross_base_rate == rates.spot_cross_base_rate
        && runtime
            .cross_rate_overrides
            .iter()
            .any(|override_| override_.cross_rate == rates.perp_cross_base_rate)
}

fn build_trial_record(
    runtime: &FeeTrialRuntime,
    current: FeeTrialDefaults,
    requested: FeeRates,
    current_day: u32,
) -> Option<FeeTrialRecord> {
    let multiplier = 1.0 - resolve_volume_discount(runtime, current.volume_anchor);
    let discounted_requested = requested.map_positive(|value| value * multiplier);
    let effective_rates = current.effective_rates.pointwise_min(discounted_requested);
    if effective_rates == current.effective_rates {
        return None;
    }

    Some(FeeTrialRecord {
        active: true,
        effective_rates,
        volume_anchor: current.volume_anchor,
        requested_rates: requested,
        previous_rates: current.effective_rates,
        trial_end_day: add_days(current_day, FEE_TRIAL_DURATION_DAYS),
        carried_discount_multiplier: current.carried_discount_multiplier,
    })
}

fn resolve_volume_discount(runtime: &FeeTrialRuntime, volume_anchor: f64) -> f64 {
    let mut discount = 0.0;
    for tier in &runtime.volume_discount_tiers {
        if tier.min_volume_anchor <= volume_anchor {
            discount = tier.discount;
        } else {
            break;
        }
    }
    discount
}

#[inline]
fn add_days(day: u32, delta: u32) -> u32 {
    day.checked_add(delta).expect("fee-trial day overflow")
}
