#![allow(dead_code)]

use core::fmt;

pub type Stake = u64;
pub type StakeTier = u8;

#[repr(transparent)]
#[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Address(pub [u8; 20]);

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The iterator is hard-bounded to four entries.  All three monomorphs advance
/// an index, stop once `index + exhausted_offset > 4`, then compute one checked
/// requirement per entry.
pub const N_STAKE_REQUIREMENT_KINDS: usize = 4;

/// Per-kind, per-tier stake multipliers recovered from the two equivalent table
/// encodings used by the spot and perp monomorphs:
///
/// - spot uses four signed offsets rooted at the rodata base;
/// - perp uses the same four absolute pointers.
///
/// The second dimension is indexed by the stake-tier byte read from the exchange
/// state (`+0x8f2` for spot/main-perp, `+0x1372` for dex-perp).  Values are raw
/// staking units.
pub const STAKE_REQUIREMENT_BY_KIND_AND_TIER: [[Stake; 4]; N_STAKE_REQUIREMENT_KINDS] = [
    [100_000, 10_000_000_000, 10_000_000_000, 50_000_000_000_000],
    [50_000, 20_000_000_000_000, 5_000_000_000, 20_000_000_000_000],
    [200_000, 50_000_000_000_000, 10_000_000_000, 50_000_000_000_000],
    [150_000, 80_000_000_000_000, 15_000_000_000, 80_000_000_000_000],
];

/// Action selector carried as a single byte by the callers.  Selectors `0..=3`
/// add one prospective object to the matching requirement kind before the table
/// multiplication; selector `4` performs a pure existing-state check.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StakeRequirementAction {
    Kind0 = 0,
    Kind1 = 1,
    Kind2 = 2,
    Kind3 = 3,
    ExistingOnly = 4,
    Other(u8),
}

impl StakeRequirementAction {
    #[inline]
    pub const fn from_byte(value: u8) -> Self {
        match value {
            0 => Self::Kind0,
            1 => Self::Kind1,
            2 => Self::Kind2,
            3 => Self::Kind3,
            4 => Self::ExistingOnly,
            other => Self::Other(other),
        }
    }

    #[inline]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Kind0 => 0,
            Self::Kind1 => 1,
            Self::Kind2 => 2,
            Self::Kind3 => 3,
            Self::ExistingOnly => 4,
            Self::Other(value) => value,
        }
    }

    #[inline]
    pub const fn prospective_kind(self) -> Option<usize> {
        match self {
            Self::Kind0 => Some(0),
            Self::Kind1 => Some(1),
            Self::Kind2 => Some(2),
            Self::Kind3 => Some(3),
            Self::ExistingOnly | Self::Other(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StakeRequirementScope {
    Spot,
    MainPerp,
    PerpDex,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StakeRequirementError {
    InvalidTier { tier: StakeTier },
    RequirementOverflow { kind: usize, tier: StakeTier, count: u64 },
    InsufficientDelegation { required: Stake, available: Stake },
    StakeLookupOverflow,
    StakeLookupRejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequirementBreakdown {
    pub per_kind: [Stake; N_STAKE_REQUIREMENT_KINDS],
    pub total: Stake,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelegationLookup {
    /// The binary tests this flag before comparing the returned stake amount.
    pub accepted: bool,
    /// Returned in the second register from the staking lookup and compared with
    /// the summed requirement.
    pub available: Stake,
}

/// State hooks needed by the recovered formula.  The binary has three concrete
/// monomorphs with different state offsets, but they all use this same shape:
/// `existing_count(kind, user)`, plus an optional one-count for the pending
/// action, then `count * table[kind][tier]`.
pub trait StakeRequirementState {
    fn stake_tier(&self, scope: StakeRequirementScope) -> StakeTier;

    /// Counts already-live or still-effective objects owned by `user` for the
    /// selected kind.  Recovered branch details:
    ///
    /// - kind 0 scans fixed-size entries, ignores state byte `3`, and has a
    ///   special state-byte `1` date check when the pending action is kind 0;
    /// - kind 1 iterates account-indexed entries, takes an amount at
    ///   `entry + 8 * user_subindex + 8`, and excludes entries blocked by the
    ///   two sorted guard maps unless a dated guard has expired;
    /// - kind 2 counts matching entries through a filtered iterator over the
    ///   map rooted near the state `+0x2b0` region;
    /// - kind 3 is boolean-like: it returns one when the user is present in the
    ///   sorted 20-byte-address tree rooted at the late-state dex registry.
    fn existing_requirement_count(
        &self,
        scope: StakeRequirementScope,
        kind: usize,
        user: &Address,
        pending_action: StakeRequirementAction,
    ) -> Result<u64, StakeRequirementError>;

    /// Looks up the user's available delegated stake.  The recovered function
    /// adds a direct delegation tree to a dynamic staking-map lookup with
    /// checked addition; overflow rejects the stake lookup rather than silently
    /// wrapping.  Some callers pass `include_inactive = false`, which also checks
    /// an auxiliary address tree before accepting the lookup.
    fn available_delegated_stake(
        &self,
        user: &Address,
        include_inactive: bool,
    ) -> Result<DelegationLookup, StakeRequirementError>;
}

#[inline]
pub fn requirement_unit(kind: usize, tier: StakeTier) -> Result<Stake, StakeRequirementError> {
    let tier_index = tier as usize;
    STAKE_REQUIREMENT_BY_KIND_AND_TIER
        .get(kind)
        .and_then(|row| row.get(tier_index))
        .copied()
        .ok_or(StakeRequirementError::InvalidTier { tier })
}

#[inline]
pub fn requirement_count(
    existing: u64,
    action: StakeRequirementAction,
    kind: usize,
) -> Result<u64, StakeRequirementError> {
    existing
        .checked_add(u64::from(action.prospective_kind() == Some(kind)))
        .ok_or(StakeRequirementError::RequirementOverflow {
            kind,
            tier: 0,
            count: u64::MAX,
        })
}

pub fn per_kind_requirements<S: StakeRequirementState>(
    state: &S,
    scope: StakeRequirementScope,
    user: &Address,
    action: StakeRequirementAction,
) -> Result<[Stake; N_STAKE_REQUIREMENT_KINDS], StakeRequirementError> {
    let tier = state.stake_tier(scope);
    let mut requirements = [0; N_STAKE_REQUIREMENT_KINDS];

    let mut kind = 0;
    while kind < N_STAKE_REQUIREMENT_KINDS {
        let existing = state.existing_requirement_count(scope, kind, user, action)?;
        let count = existing.checked_add(u64::from(action.prospective_kind() == Some(kind))).ok_or(
            StakeRequirementError::RequirementOverflow { kind, tier, count: u64::MAX },
        )?;
        let unit = requirement_unit(kind, tier)?;
        requirements[kind] = unit.checked_mul(count).ok_or(
            StakeRequirementError::RequirementOverflow { kind, tier, count },
        )?;
        kind += 1;
    }

    Ok(requirements)
}

/// Caller-side summation uses checked `u64` addition.  On overflow it invokes the
/// qty overflow hook and continues with `u64::MAX`; model that observable check
/// as saturating addition because the following delegation comparison must fail
/// unless the account has the maximum raw stake value.
pub const fn total_requirement_saturating(
    per_kind: [Stake; N_STAKE_REQUIREMENT_KINDS],
) -> Stake {
    let mut i = 0;
    let mut total = 0_u64;
    while i < N_STAKE_REQUIREMENT_KINDS {
        total = total.saturating_add(per_kind[i]);
        i += 1;
    }
    total
}

pub fn requirement_breakdown<S: StakeRequirementState>(
    state: &S,
    scope: StakeRequirementScope,
    user: &Address,
    action: StakeRequirementAction,
) -> Result<RequirementBreakdown, StakeRequirementError> {
    let per_kind = per_kind_requirements(state, scope, user, action)?;
    Ok(RequirementBreakdown {
        per_kind,
        total: total_requirement_saturating(per_kind),
    })
}

pub fn check_stake_requirement<S: StakeRequirementState>(
    state: &S,
    scope: StakeRequirementScope,
    user: &Address,
    action: StakeRequirementAction,
    include_inactive_delegation: bool,
) -> Result<RequirementBreakdown, StakeRequirementError> {
    let breakdown = requirement_breakdown(state, scope, user, action)?;
    let delegation = state.available_delegated_stake(user, include_inactive_delegation)?;

    if delegation.accepted && delegation.available >= breakdown.total {
        Ok(breakdown)
    } else {
        Err(StakeRequirementError::InsufficientDelegation {
            required: breakdown.total,
            available: delegation.available,
        })
    }
}

#[inline]
pub fn check_spot_stake_requirement<S: StakeRequirementState>(
    state: &S,
    user: &Address,
    action: StakeRequirementAction,
) -> Result<RequirementBreakdown, StakeRequirementError> {
    check_stake_requirement(state, StakeRequirementScope::Spot, user, action, false)
}

#[inline]
pub fn check_main_perp_stake_requirement<S: StakeRequirementState>(
    state: &S,
    user: &Address,
    action: StakeRequirementAction,
) -> Result<RequirementBreakdown, StakeRequirementError> {
    check_stake_requirement(state, StakeRequirementScope::MainPerp, user, action, false)
}

#[inline]
pub fn check_perp_dex_stake_requirement<S: StakeRequirementState>(
    state: &S,
    user: &Address,
    action: StakeRequirementAction,
) -> Result<RequirementBreakdown, StakeRequirementError> {
    check_stake_requirement(state, StakeRequirementScope::PerpDex, user, action, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        tier: StakeTier,
        counts: [u64; N_STAKE_REQUIREMENT_KINDS],
        available: Stake,
        accepted: bool,
    }

    impl StakeRequirementState for Fixture {
        fn stake_tier(&self, _scope: StakeRequirementScope) -> StakeTier {
            self.tier
        }

        fn existing_requirement_count(
            &self,
            _scope: StakeRequirementScope,
            kind: usize,
            _user: &Address,
            _pending_action: StakeRequirementAction,
        ) -> Result<u64, StakeRequirementError> {
            Ok(self.counts[kind])
        }

        fn available_delegated_stake(
            &self,
            _user: &Address,
            _include_inactive: bool,
        ) -> Result<DelegationLookup, StakeRequirementError> {
            Ok(DelegationLookup { accepted: self.accepted, available: self.available })
        }
    }

    #[test]
    fn pending_action_adds_one_requirement_for_matching_kind() {
        let state = Fixture { tier: 0, counts: [2, 0, 0, 0], available: 300_000, accepted: true };
        let user = Address([7; 20]);
        let breakdown = check_spot_stake_requirement(&state, &user, StakeRequirementAction::Kind0)
            .expect("fixture has enough stake");
        assert_eq!(breakdown.per_kind[0], 300_000);
        assert_eq!(breakdown.total, 300_000);
    }

    #[test]
    fn total_requirement_saturates_like_caller_sum() {
        assert_eq!(total_requirement_saturating([u64::MAX, 1, 2, 3]), u64::MAX);
    }
}
