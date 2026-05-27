//! ClaimRewards action handler.
//!
//! Reconstructed from the `ClaimRewards` dispatcher arm inside
//! `l1_exchange_end_block__dispatch_base_action_outcome` (`0x2759240`) and the
//! inlined helper it calls at `0x2710E30`.
//!
//! The wrapper itself is tiny:
//! 1. Ignore the empty `ClaimRewardsAction` payload.
//! 2. Call the staking reward balance-update helper.
//! 3. Map helper status `390` to outer outcome tag `13`.
//! 4. Map every non-`390` helper status to outer outcome tag `14` and bubble the
//!    helper error payload unchanged.
//!
//! The interesting work lives in the helper:
//! - load the caller's per-asset staking reward rows,
//! - reject missing/empty reward state,
//! - skip dust rewards below the current per-asset minimum claim threshold,
//! - move claimed amounts from `claimable` to `claimed`,
//! - apply ledger / qty deltas for every credited asset,
//! - bump one auxiliary per-user counter,
//! - emit one event per credited asset.

pub type Address = [u8; 20];
pub type AssetId = u64;
pub type Wei = u64;
pub type RawUsd8 = u64;

pub const HELPER_STATUS_OK: u16 = 390;
pub const HELPER_STATUS_NO_REWARDS: u16 = 166;
/// [INFERENCE] Returned when reward rows exist but every non-zero amount is still
/// below the helper's per-asset minimum claim threshold.
pub const HELPER_STATUS_ONLY_DUST_REWARDS: u16 = 167;

pub const OUTCOME_TAG_SUCCESS: u8 = 13;
pub const OUTCOME_TAG_ERROR: u8 = 14;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClaimRewardsAction;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RewardLot {
    pub claimable_wei: Wei,
    pub claimed_wei: Wei,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimedReward {
    pub asset: AssetId,
    pub wei: Wei,
    /// Reward notional rescaled into the spot metadata's USDC-decimal domain.
    pub quote_notional_usdc_8dp: RawUsd8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimRewardEvent {
    pub user: Address,
    pub asset: AssetId,
    pub wei: Wei,
    pub quote_notional_usdc_8dp: RawUsd8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimRewardsError {
    NoRewards,
    /// [INFERENCE] The binary distinguishes this from `NoRewards` with raw status
    /// `167`, but the exact product name for that status was not recovered.
    OnlyDustRewards,
    Unknown(u16),
}

impl ClaimRewardsError {
    #[inline]
    pub const fn status(&self) -> u16 {
        match self {
            Self::NoRewards => HELPER_STATUS_NO_REWARDS,
            Self::OnlyDustRewards => HELPER_STATUS_ONLY_DUST_REWARDS,
            Self::Unknown(status) => *status,
        }
    }

    #[inline]
    pub const fn from_status(status: u16) -> Self {
        match status {
            HELPER_STATUS_NO_REWARDS => Self::NoRewards,
            HELPER_STATUS_ONLY_DUST_REWARDS => Self::OnlyDustRewards,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BaseActionOutcome {
    Success,
    Error { status: u16, error: ClaimRewardsError },
}

impl BaseActionOutcome {
    #[inline]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Success => OUTCOME_TAG_SUCCESS,
            Self::Error { .. } => OUTCOME_TAG_ERROR,
        }
    }
}

/// State slice needed by the helper at `0x2710E30`.
///
/// The binary pulls spot metadata, mutates per-user staking reward rows, writes
/// qty/wei deltas, touches the caller's user-account record, and emits one event
/// per credited asset.  The trait keeps this file focused on the handler path
/// instead of re-implementing the unrelated storage helpers it calls.
pub trait ClaimRewardsState {
    /// Snapshot the caller's per-asset reward rows in iteration order.
    fn claimable_reward_rows(&self, user: &Address) -> Vec<(AssetId, RewardLot)>;

    /// Binary effect: zero the claimable amount and saturating-add it into the
    /// per-asset claimed total.
    fn consume_reward(&mut self, user: Address, asset: AssetId, claimed_wei: Wei);

    /// The helper converts the claimed amount into the spot metadata's USDC
    /// decimal domain before writing the qty delta row.
    fn quote_notional_usdc_8dp(&self, asset: AssetId, wei: Wei) -> RawUsd8;

    /// Per-asset minimum claim size derived from a fixed `100_000_000` raw USDC
    /// notional and current spot metadata.
    fn minimum_claim_wei(&self, asset: AssetId) -> Option<Wei>;

    /// Mirrors `l1_qtys_impl_wei__upsert_user_wei_delta(...)`.
    fn upsert_user_wei_delta(
        &mut self,
        user: Address,
        asset: AssetId,
        wei: Wei,
        quote_notional_usdc_8dp: RawUsd8,
    );

    /// Mirrors the helper's saturating add into one field of the user account
    /// returned by `get_or_create_user_account(...)`.
    ///
    /// [INFERENCE] The called helper names around `0x2710E30` suggest this field
    /// is some auxiliary reward/volume accumulator rather than spendable balance.
    fn credit_auxiliary_claim_units(&mut self, user: Address, units: u64);

    /// Raw units to credit through `credit_auxiliary_claim_units`.  The binary
    /// computes these from current asset metadata and then divides by `10_000`
    /// before adding them into the user account.
    fn auxiliary_claim_units(&self, asset: AssetId, wei: Wei) -> u64;

    /// One event is emitted for each credited asset.
    fn push_claim_reward_event(&mut self, event: ClaimRewardEvent);
}

/// Reconstructed helper body from `0x2710E30`.
///
/// The helper does not read any fields from `ClaimRewardsAction`; the action is
/// only a signal to claim the caller's currently claimable staking rewards.
pub fn apply_claim_rewards_balance_updates<S>(
    state: &mut S,
    user: Address,
) -> Result<Vec<ClaimedReward>, ClaimRewardsError>
where
    S: ClaimRewardsState,
{
    let rewards = state.claimable_reward_rows(&user);
    if rewards.is_empty() {
        return Err(ClaimRewardsError::NoRewards);
    }

    let mut saw_nonzero_reward = false;
    let mut claimed = Vec::new();

    for (asset, lot) in rewards {
        if lot.claimable_wei == 0 {
            continue;
        }
        saw_nonzero_reward = true;

        let Some(minimum_claim_wei) = state.minimum_claim_wei(asset) else {
            continue;
        };
        if lot.claimable_wei < minimum_claim_wei {
            continue;
        }

        let quote_notional_usdc_8dp = state.quote_notional_usdc_8dp(asset, lot.claimable_wei);
        state.consume_reward(user, asset, lot.claimable_wei);
        state.upsert_user_wei_delta(user, asset, lot.claimable_wei, quote_notional_usdc_8dp);

        let credited_units = state.auxiliary_claim_units(asset, lot.claimable_wei) / 10_000;
        state.credit_auxiliary_claim_units(user, credited_units);

        let reward = ClaimedReward {
            asset,
            wei: lot.claimable_wei,
            quote_notional_usdc_8dp,
        };
        state.push_claim_reward_event(ClaimRewardEvent {
            user,
            asset,
            wei: reward.wei,
            quote_notional_usdc_8dp: reward.quote_notional_usdc_8dp,
        });
        claimed.push(reward);
    }

    if claimed.is_empty() {
        return Err(if saw_nonzero_reward {
            ClaimRewardsError::OnlyDustRewards
        } else {
            ClaimRewardsError::NoRewards
        });
    }

    Ok(claimed)
}

/// Exact dispatcher-wrapper behavior recovered from `0x2759C55..0x2759C9E`.
///
/// The outer end-block dispatcher discards the helper's success payload and only
/// preserves a generic success/error envelope:
/// - helper status `390` -> outer tag `13`
/// - helper status `!= 390` -> outer tag `14`, same helper status bubbled out
#[inline]
pub fn dispatch_claim_rewards<S>(
    _action: &ClaimRewardsAction,
    user: Address,
    state: &mut S,
) -> BaseActionOutcome
where
    S: ClaimRewardsState,
{
    match apply_claim_rewards_balance_updates(state, user) {
        Ok(_) => BaseActionOutcome::Success,
        Err(error) => BaseActionOutcome::Error {
            status: error.status(),
            error,
        },
    }
}
