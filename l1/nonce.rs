#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type Nonce = u64;
pub type TimestampMillis = u64;

pub const DEFAULT_RETAINED_NONCES: usize = 100;
pub const EXPANDED_RETAINED_NONCES: usize = 400;
pub const NONCE_WINDOW_MS: TimestampMillis = 86_400_000;
pub const WITHDRAW3_NONCE_SCALE: u64 = 1_000;

/// Exact storage shape recovered from the field name `address_to_nonce_set` and
/// the lookup/insert/prune wrappers.
pub type AddressToNonceSet = BTreeMap<Address, BTreeSet<Nonce>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PendingAgentRemoval {
    pub ready_at_ms: TimestampMillis,
    pub agent_address: Address,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AgentTrackerNonceState {
    pub address_to_nonce_set: AddressToNonceSet,
    pub agent_to_user: BTreeMap<Address, Address>,
    pub user_to_pending_agent_removals: BTreeMap<Address, BTreeSet<PendingAgentRemoval>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonceError {
    /// Display case 0x5A: `Nonce already used.`
    NonceAlreadyUsed,
    /// Display case 0x5D: `Nonce mismatch.`
    NonceMismatch { action: Nonce, context: Nonce },
    /// Display case 0xC6: dynamic `Invalid nonce: ...` string built by the core validator.
    InvalidNonceBelowRetainedMinimum {
        nonce: Nonce,
        smallest_retained: Nonce,
        retained: usize,
    },
    /// Display case 0xC6: nonce is more than one day ahead of the current block time.
    InvalidNonceTooFarInFuture {
        nonce: Nonce,
        max_allowed: Nonce,
    },
    /// Display case 0xC6: nonce is more than one day behind the current block time.
    InvalidNonceTooFarInPast {
        nonce: Nonce,
        min_allowed: Nonce,
    },
    /// Display case 0xC7: `Invalid nonce: duplicate nonce <nonce>`.
    DuplicateNonce(Nonce),
    /// Recovered overflow path from `1000 * withdraw3_nonce`.
    InvalidWithdraw3NonceArithmetic,
}

impl AgentTrackerNonceState {
    #[inline]
    pub fn nonces_for_address_or_empty(&self, address: &Address) -> &BTreeSet<Nonce> {
        static EMPTY: BTreeSet<Nonce> = BTreeSet::new();
        self.address_to_nonce_set.get(address).unwrap_or(&EMPTY)
    }

    /// Mirrors `l1_nonce__validate_candidate`.
    ///
    /// Ordering is exact:
    /// 1. If the retained set is already full, reject any nonce below the current minimum.
    /// 2. Reject nonce > now + 24h.
    /// 3. Reject nonce < now - 24h.
    /// 4. Reject exact duplicates.
    /// 5. Return the retention cap to the caller.
    pub fn validate_candidate(
        now_ms: TimestampMillis,
        expanded_retention: bool,
        nonce: Nonce,
        retained: &BTreeSet<Nonce>,
    ) -> Result<usize, NonceError> {
        let cap = retained_nonce_cap(expanded_retention);

        if retained.len() >= cap {
            if let Some(&smallest_retained) = retained.first() {
                if nonce < smallest_retained {
                    return Err(NonceError::InvalidNonceBelowRetainedMinimum {
                        nonce,
                        smallest_retained,
                        retained: cap,
                    });
                }
            }
        }

        let max_allowed = now_ms.saturating_add(NONCE_WINDOW_MS);
        if nonce > max_allowed {
            return Err(NonceError::InvalidNonceTooFarInFuture { nonce, max_allowed });
        }

        let min_allowed = now_ms.saturating_sub(NONCE_WINDOW_MS);
        if nonce < min_allowed {
            return Err(NonceError::InvalidNonceTooFarInPast { nonce, min_allowed });
        }

        if retained.contains(&nonce) {
            return Err(NonceError::DuplicateNonce(nonce));
        }

        Ok(cap)
    }

    /// Mirrors `l1_nonce__check_and_remember_exchange_nonce` in the normal user
    /// action path.
    pub fn check_and_remember_exchange_nonce(
        &mut self,
        now_ms: TimestampMillis,
        expanded_retention: bool,
        signer: Address,
        nonce: Nonce,
    ) -> Result<(), NonceError> {
        let retained = self.address_to_nonce_set.entry(signer).or_default();
        let cap = Self::validate_candidate(now_ms, expanded_retention, nonce, retained)?;
        retained.insert(nonce);
        while retained.len() > cap {
            retained.pop_first();
        }
        Ok(())
    }

    /// Mirrors `l1_agent_tracker__prune_pending_agent_removals`.
    ///
    /// This is the only recovered nonce-set deletion path: once an expired pending
    /// removal address is no longer treated as a real user address, its nonce set is
    /// dropped wholesale. There is no general age-based nonce pruning here.
    pub fn prune_pending_agent_removals<F>(&mut self, now_ms: TimestampMillis, is_real_user_address: F)
    where
        F: Fn(&Address) -> bool,
    {
        let mut expired_agents = BTreeSet::<Address>::new();
        let mut empty_users = Vec::new();

        for (user, pending) in &mut self.user_to_pending_agent_removals {
            let expired: Vec<_> = pending
                .iter()
                .copied()
                .filter(|removal| removal.ready_at_ms <= now_ms)
                .collect();
            for removal in expired {
                pending.remove(&removal);
                expired_agents.insert(removal.agent_address);
            }
            if pending.is_empty() {
                empty_users.push(*user);
            }
        }

        for user in empty_users {
            self.user_to_pending_agent_removals.remove(&user);
        }

        for agent_address in expired_agents {
            self.agent_to_user.remove(&agent_address);
            if !is_real_user_address(&agent_address) {
                self.address_to_nonce_set.remove(&agent_address);
            }
        }
    }
}

#[inline]
pub const fn retained_nonce_cap(expanded_retention: bool) -> usize {
    if expanded_retention {
        EXPANDED_RETAINED_NONCES
    } else {
        DEFAULT_RETAINED_NONCES
    }
}

/// Recovered embedded-signable check used before hashing/signing the payload.
#[inline]
pub fn ensure_embedded_nonce_matches(action_nonce: Nonce, context_nonce: Nonce) -> Result<(), NonceError> {
    if action_nonce != context_nonce {
        return Err(NonceError::NonceMismatch {
            action: action_nonce,
            context: context_nonce,
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Withdraw3ReplayState {
    /// [INFERENCE] The live binary writes this into the per-user account record
    /// returned by `get_or_create_user_account(...)` after Bridge2 insertion.
    pub last_nonce_ms: Nonce,
}

impl Withdraw3ReplayState {
    /// Mirrors the leading replay guard inside
    /// `l1_action_withdraw3__apply_withdrawal_core`.
    ///
    /// The handler normalizes the raw Withdraw3 payload field with `1000 * field`
    /// first, then rejects `nonce_ms <= last_nonce_ms` with `Nonce already used.`.
    pub fn validate_nonce(&self, raw_withdraw3_nonce: u64) -> Result<Nonce, NonceError> {
        let nonce_ms = raw_withdraw3_nonce
            .checked_mul(WITHDRAW3_NONCE_SCALE)
            .ok_or(NonceError::InvalidWithdraw3NonceArithmetic)?;
        if nonce_ms <= self.last_nonce_ms {
            return Err(NonceError::NonceAlreadyUsed);
        }
        Ok(nonce_ms)
    }

    #[inline]
    pub fn remember_nonce(&mut self, nonce_ms: Nonce) {
        self.last_nonce_ms = nonce_ms;
    }
}

/// [INFERENCE] Normal user-signed Withdraw3 processing uses both nonce domains:
///
/// 1. The shared signer-scoped `address_to_nonce_set` gate used by all signed actions.
/// 2. The Withdraw3-specific per-user monotonic nonce stored in the user account.
/// 3. Bridge2 then records `(user, nonce_ms)` in `withdrawal_signatures`.
///
/// So Withdraw3 is not isolated from the general action nonce set; in the normal
/// exchange path it shares that set and then applies an additional withdraw-only
/// check.
pub fn validate_normal_user_withdraw3(
    tracker: &mut AgentTrackerNonceState,
    now_ms: TimestampMillis,
    signer: Address,
    signed_action_nonce: Nonce,
    expanded_retention: bool,
    withdraw3_state: &Withdraw3ReplayState,
    raw_withdraw3_nonce: u64,
) -> Result<Nonce, NonceError> {
    tracker.check_and_remember_exchange_nonce(now_ms, expanded_retention, signer, signed_action_nonce)?;
    withdraw3_state.validate_nonce(raw_withdraw3_nonce)
}
