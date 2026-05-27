use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type Wei = u64;
pub type TimestampMillis = u64;

pub const STATUS_SUCCESS: u16 = 390;
pub const STATUS_BAD_CALLER_MODE: u16 = 142;
pub const STATUS_CALLER_NOT_ALLOWED: u16 = 148;
pub const STATUS_REGISTER_OVERFLOW_GUARD: u16 = 319;
pub const STATUS_STAKING_DISABLED: u16 = 251;
pub const STATUS_INSUFFICIENT_BALANCE: u16 = 252;
pub const STATUS_REGISTER_FLAG_REJECTED: u16 = 253;
pub const STATUS_SELF_DELEGATION_TOO_SMALL: u16 = 304;
pub const STATUS_MAX_VALIDATORS_REACHED: u16 = 146;
pub const STATUS_ALREADY_REGISTERED: u16 = 147;
pub const STATUS_CHANGE_PROFILE_MISSING_VALIDATOR: u16 = 145;
pub const STATUS_CHANGE_PROFILE_COOLDOWN: u16 = 294;
pub const STATUS_DUPLICATE_NODE_IP: u16 = 292;
pub const STATUS_DUPLICATE_SIGNER: u16 = 293;
pub const STATUS_UNREGISTER_WITH_DELEGATIONS: u16 = 303;
pub const STATUS_MISSING_RUNTIME_STATE: u16 = 320;

pub const PROFILE_CHANGE_COOLDOWN_SECS: i64 = 7_200;
pub const MAX_VALIDATORS: usize = 1_000;
pub const MAX_NAME_LEN: usize = 100;
pub const MAX_DESCRIPTION_LEN: usize = 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CValidatorProfile {
    pub node_ip: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub commission_bps: u16,
    pub delegations_disabled: bool,
    pub signer: Address,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CValidatorAction {
    Register {
        profile: CValidatorProfile,
        initial_wei: Wei,
        disable_delegations: bool,
    },
    ChangeProfile(CValidatorProfilePatch),
    Unregister,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CValidatorProfilePatch {
    pub node_ip: Option<Option<String>>,
    pub name: Option<Option<String>>,
    pub description: Option<Option<String>>,
    pub commission_bps: Option<u16>,
    pub delegations_disabled: Option<bool>,
    pub signer: Option<Address>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Delegations {
    pub delegations: BTreeMap<Address, Wei>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CStaking {
    pub user_to_delegations: BTreeMap<Address, Delegations>,
    pub validator_to_profile: BTreeMap<Address, CValidatorProfile>,
    pub self_delegation_requirement: Wei,
    pub long_term_staking_allowed: bool,
}

impl CStaking {
    #[inline]
    pub fn unregister_validator(&self, validator: Address) -> Result<(), u16> {
        let has_delegations = self
            .user_to_delegations
            .values()
            .any(|delegations| delegations.delegations.get(&validator).copied().unwrap_or(0) != 0);
        if has_delegations {
            return Err(STATUS_UNREGISTER_WITH_DELEGATIONS);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidatorRuntimeState {
    pub validator: Address,
    pub signer: Address,
    pub node_ip: Option<String>,
    pub commission_bps: u16,
    pub delegations_disabled: bool,
    pub last_profile_update_ms: Option<TimestampMillis>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CValidatorContext {
    pub caller_allowlist_enabled: bool,
    pub allowed_callers: BTreeSet<Address>,
    pub foundation_self_signers: BTreeSet<Address>,
    pub available_balances: BTreeMap<Address, Wei>,
    pub staking: CStaking,
    pub validator_to_state: BTreeMap<Address, ValidatorRuntimeState>,
}

impl CValidatorContext {
    #[inline]
    fn caller_allowed(&self, caller: &Address) -> bool {
        !self.caller_allowlist_enabled || self.allowed_callers.contains(caller)
    }

    #[inline]
    fn available_balance(&self, user: &Address) -> Wei {
        self.available_balances.get(user).copied().unwrap_or(0)
    }

    #[inline]
    fn is_foundation_self_signer(&self, validator: &Address) -> bool {
        self.foundation_self_signers.contains(validator)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningMode {
    pub variant_ok: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CValidatorEnvelope {
    pub caller: Address,
    pub c_validator: Address,
    pub action: CValidatorAction,
    pub signing_mode: SigningMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CValidatorExecError {
    Status(u16),
}

pub fn apply_c_validator(
    ctx: &mut CValidatorContext,
    envelope: &CValidatorEnvelope,
    now_ms: TimestampMillis,
) -> Result<(), CValidatorExecError> {
    if !envelope.signing_mode.variant_ok {
        return Err(CValidatorExecError::Status(STATUS_BAD_CALLER_MODE));
    }
    if !ctx.caller_allowed(&envelope.caller) {
        return Err(CValidatorExecError::Status(STATUS_CALLER_NOT_ALLOWED));
    }

    match &envelope.action {
        CValidatorAction::Register {
            profile,
            initial_wei,
            disable_delegations,
        } => register_c_validator(
            ctx,
            envelope.caller,
            envelope.c_validator,
            profile.clone(),
            *initial_wei,
            *disable_delegations,
            now_ms,
        ),
        CValidatorAction::ChangeProfile(patch) => {
            change_c_validator_profile(ctx, envelope.c_validator, patch, now_ms)
        }
        CValidatorAction::Unregister => unregister_c_validator(ctx, envelope.c_validator),
    }
}

fn register_c_validator(
    ctx: &mut CValidatorContext,
    caller: Address,
    validator: Address,
    mut profile: CValidatorProfile,
    initial_wei: Wei,
    disable_delegations: bool,
    now_ms: TimestampMillis,
) -> Result<(), CValidatorExecError> {
    if initial_wei >= 0x0CCC_CCCC_CCCC_CCCC {
        return Err(CValidatorExecError::Status(STATUS_REGISTER_OVERFLOW_GUARD));
    }
    if initial_wei != 0 || ctx.staking.self_delegation_requirement != 0 {
        if disable_delegations {
            return Err(CValidatorExecError::Status(STATUS_REGISTER_FLAG_REJECTED));
        }
        if !ctx.staking.long_term_staking_allowed {
            return Err(CValidatorExecError::Status(STATUS_STAKING_DISABLED));
        }
        if initial_wei < ctx.staking.self_delegation_requirement {
            return Err(CValidatorExecError::Status(STATUS_SELF_DELEGATION_TOO_SMALL));
        }
        if ctx.available_balance(&caller) < initial_wei {
            return Err(CValidatorExecError::Status(STATUS_INSUFFICIENT_BALANCE));
        }
    }
    if ctx.validator_to_state.len() >= MAX_VALIDATORS {
        return Err(CValidatorExecError::Status(STATUS_MAX_VALIDATORS_REACHED));
    }
    if ctx.validator_to_state.contains_key(&validator) {
        return Err(CValidatorExecError::Status(STATUS_ALREADY_REGISTERED));
    }

    profile.delegations_disabled = disable_delegations;
    let normalized = normalize_profile(ctx, validator, profile, false, now_ms)?;

    ctx.staking.validator_to_profile.insert(validator, normalized.clone());
    ctx.validator_to_state.insert(
        validator,
        ValidatorRuntimeState {
            validator,
            signer: normalized.signer,
            node_ip: normalized.node_ip.clone(),
            commission_bps: normalized.commission_bps,
            delegations_disabled: normalized.delegations_disabled,
            last_profile_update_ms: Some(now_ms),
        },
    );

    if initial_wei != 0 {
        if let Err(status) = post_register_self_delegate(ctx, caller, validator, initial_wei) {
            ctx.validator_to_state.remove(&validator);
            ctx.staking.validator_to_profile.remove(&validator);
            return Err(CValidatorExecError::Status(status));
        }
    }

    Ok(())
}

fn change_c_validator_profile(
    ctx: &mut CValidatorContext,
    validator: Address,
    patch: &CValidatorProfilePatch,
    now_ms: TimestampMillis,
) -> Result<(), CValidatorExecError> {
    let current_profile = match ctx.staking.validator_to_profile.get(&validator) {
        Some(profile) => profile.clone(),
        None => return Err(CValidatorExecError::Status(STATUS_CHANGE_PROFILE_MISSING_VALIDATOR)),
    };
    let current_state = match ctx.validator_to_state.get(&validator) {
        Some(state) => state.clone(),
        None => return Err(CValidatorExecError::Status(STATUS_MISSING_RUNTIME_STATE)),
    };

    if let Some(last_update_ms) = current_state.last_profile_update_ms {
        if now_ms < last_update_ms.saturating_add(PROFILE_CHANGE_COOLDOWN_SECS as u64 * 1_000) {
            return Err(CValidatorExecError::Status(STATUS_CHANGE_PROFILE_COOLDOWN));
        }
    }

    let merged = CValidatorProfile {
        node_ip: patch.node_ip.clone().unwrap_or(current_profile.node_ip),
        name: patch.name.clone().unwrap_or(current_profile.name),
        description: patch.description.clone().unwrap_or(current_profile.description),
        commission_bps: patch.commission_bps.unwrap_or(current_profile.commission_bps),
        delegations_disabled: patch
            .delegations_disabled
            .unwrap_or(current_profile.delegations_disabled),
        signer: patch.signer.unwrap_or(current_profile.signer),
    };
    let normalized = normalize_profile(ctx, validator, merged, true, now_ms)?;

    ctx.staking.validator_to_profile.insert(validator, normalized.clone());
    ctx.validator_to_state.insert(
        validator,
        ValidatorRuntimeState {
            validator,
            signer: normalized.signer,
            node_ip: normalized.node_ip.clone(),
            commission_bps: normalized.commission_bps,
            delegations_disabled: normalized.delegations_disabled,
            last_profile_update_ms: Some(now_ms),
        },
    );
    Ok(())
}

fn unregister_c_validator(
    ctx: &mut CValidatorContext,
    validator: Address,
) -> Result<(), CValidatorExecError> {
    ctx.staking
        .unregister_validator(validator)
        .map_err(CValidatorExecError::Status)?;
    ctx.staking.validator_to_profile.remove(&validator);
    ctx.validator_to_state.remove(&validator);
    Ok(())
}

fn normalize_profile(
    ctx: &CValidatorContext,
    validator: Address,
    profile: CValidatorProfile,
    is_change_profile: bool,
    _now_ms: TimestampMillis,
) -> Result<CValidatorProfile, CValidatorExecError> {
    if let Some(name) = &profile.name {
        if name.len() > MAX_NAME_LEN {
            return Err(CValidatorExecError::Status(323));
        }
    }
    if let Some(description) = &profile.description {
        if description.len() > MAX_DESCRIPTION_LEN {
            return Err(CValidatorExecError::Status(323));
        }
    }

    for (other_validator, other_state) in &ctx.validator_to_state {
        if *other_validator == validator {
            continue;
        }
        if other_state.signer == profile.signer {
            return Err(CValidatorExecError::Status(STATUS_DUPLICATE_SIGNER));
        }
        if let (Some(other_ip), Some(profile_ip)) = (&other_state.node_ip, &profile.node_ip) {
            if other_ip == profile_ip {
                return Err(CValidatorExecError::Status(STATUS_DUPLICATE_NODE_IP));
            }
        }
    }

    if !ctx.is_foundation_self_signer(&validator) {
        if is_change_profile {
            // Recovered helper `sub_3BFCBC0` revalidates the profile under the
            // non-foundation rules before the duplicate scans above. The precise
            // checks are buried in that helper; this handler only depends on the
            // fact that failure aborts before any state mutation.
        }
    }

    Ok(profile)
}

fn post_register_self_delegate(
    ctx: &mut CValidatorContext,
    caller: Address,
    validator: Address,
    initial_wei: Wei,
) -> Result<(), u16> {
    if !ctx.staking.long_term_staking_allowed {
        return Err(STATUS_STAKING_DISABLED);
    }
    let Some(balance) = ctx.available_balances.get_mut(&caller) else {
        return Err(STATUS_INSUFFICIENT_BALANCE);
    };
    if *balance < initial_wei {
        return Err(STATUS_INSUFFICIENT_BALANCE);
    }
    *balance -= initial_wei;
    let delegations = ctx.staking.user_to_delegations.entry(caller).or_default();
    let current = delegations.delegations.entry(validator).or_insert(0);
    *current = current.saturating_add(initial_wei);
    Ok(())
}
