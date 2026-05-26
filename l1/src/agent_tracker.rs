#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use crate::time::NaiveDateTime12;

pub type Address = [u8; 20];
pub type Nonce = u64;

pub const OK: u16 = 390;
pub const ERR_SAVE_AGENT_UNEXPECTED: u16 = 81;
pub const ERR_AGENT_ADDRESS_IS_USER: u16 = 82;
pub const ERR_EXTRA_AGENT_INVALID_NAME: u16 = 83;
pub const ERR_AGENT_VALID_UNTIL_PASSED: u16 = 85;
pub const ERR_EXTRA_AGENT_ALREADY_USED: u16 = 86;
pub const ERR_TOO_MANY_EXTRA_AGENTS: u16 = 87;
pub const ERR_EXTRA_AGENT_DOES_NOT_EXIST: u16 = 89;
pub const ERR_PENDING_AGENT_REMOVAL: u16 = 349;

/// The approval helpers add a short chrono delta of `2` before comparing and before
/// queuing a removal.  The compact time representation is normalized to milliseconds
/// here, so the same grace window is expressed as two seconds.
const AGENT_GRACE_PERIOD_MS: u64 = 2_000;

/// [INFERENCE] The optimized helper expands the caller-provided tier with
/// `2 * tier + 3` before comparing it to the current extra-agent count.
const BASE_EXTRA_AGENT_LIMIT: usize = 3;

/// Three hard-coded addresses bypass the normal dynamic extra-agent cap.
const EXTRA_AGENT_CAP_BYPASS_0: Address = [
    0x67, 0x7d, 0x83, 0x1a, 0xef, 0x53, 0x28, 0x19, 0x08, 0x52, 0xe2, 0x4f, 0x13, 0xc4,
    0x6c, 0xac, 0x05, 0xf9, 0x84, 0xe7,
];
const EXTRA_AGENT_CAP_BYPASS_1: Address = [
    0x3c, 0x83, 0xa5, 0xca, 0xe3, 0x2a, 0x05, 0xe8, 0x8c, 0xa6, 0xa0, 0x35, 0x0e, 0xdb,
    0x54, 0x01, 0x94, 0x85, 0x1a, 0x76,
];
const EXTRA_AGENT_CAP_BYPASS_2: Address = [
    0x4d, 0xbf, 0x39, 0x4d, 0xa4, 0xb3, 0x48, 0xb8, 0x8e, 0x80, 0x90, 0xd2, 0x20, 0x51,
    0xaf, 0x83, 0xe4, 0xcb, 0xae, 0xf4,
];

const EXTRA_AGENT_CAP_BYPASS: [Address; 3] = [
    EXTRA_AGENT_CAP_BYPASS_0,
    EXTRA_AGENT_CAP_BYPASS_1,
    EXTRA_AGENT_CAP_BYPASS_2,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct MainAgent {
    pub agent_address: Address,
    pub valid_until_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ExtraAgent {
    pub name: String,
    pub agent_address: Address,
    pub valid_until_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PendingAgentRemoval {
    pub ready_at_ms: u64,
    pub agent_address: Address,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AgentTracker {
    pub user_to_main_agent: BTreeMap<Address, MainAgent>,
    pub user_to_extra_agents: BTreeMap<Address, Vec<ExtraAgent>>,
    /// This table intentionally keeps recently-removed agents until
    /// `prune_pending_agent_removals` observes that their grace window expired.
    pub agent_to_user: BTreeMap<Address, Address>,
    pub address_to_nonce_set: BTreeMap<Address, BTreeSet<Nonce>>,
    pub user_to_pending_agent_removals: BTreeMap<Address, BTreeSet<PendingAgentRemoval>>,
}

impl AgentTracker {
    #[inline]
    pub fn has_pending_agent_removal(&self, user: &Address) -> bool {
        self.user_to_pending_agent_removals
            .get(user)
            .is_some_and(|pending| !pending.is_empty())
    }

    #[inline]
    pub fn user_for_agent(&self, agent: &Address) -> Option<Address> {
        self.agent_to_user.get(agent).copied()
    }

    #[inline]
    pub fn main_agent(&self, user: &Address) -> Option<&MainAgent> {
        self.user_to_main_agent.get(user)
    }

    #[inline]
    pub fn extra_agents(&self, user: &Address) -> &[ExtraAgent] {
        self.user_to_extra_agents
            .get(user)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    #[inline]
    pub fn nonce_was_used(&self, address: &Address, nonce: Nonce) -> bool {
        self.address_to_nonce_set
            .get(address)
            .is_some_and(|nonces| nonces.contains(&nonce))
    }

    #[inline]
    pub fn remember_nonce(&mut self, address: Address, nonce: Nonce) -> bool {
        self.address_to_nonce_set.entry(address).or_default().insert(nonce)
    }

    pub fn save_main_agent(
        &mut self,
        user: Address,
        new_agent_address: Option<Address>,
        valid_until: NaiveDateTime12,
        now: NaiveDateTime12,
    ) -> u16 {
        let now_ms = now.unix_millis_saturating();
        let maybe_agent_address = new_agent_address.filter(|address| !is_zero_address(address));

        match maybe_agent_address {
            None => {
                if let Some(previous) = self.user_to_main_agent.remove(&user) {
                    self.push_pending_removal(user, previous.agent_address, now_ms + AGENT_GRACE_PERIOD_MS);
                }
                OK
            }
            Some(agent_address) => {
                let valid_until_ms = valid_until.unix_millis_saturating();
                if valid_until_ms <= now_ms.saturating_add(AGENT_GRACE_PERIOD_MS) {
                    return ERR_AGENT_VALID_UNTIL_PASSED;
                }

                if let Some(owner) = self.agent_to_user.get(&agent_address) {
                    if owner != &user {
                        return ERR_SAVE_AGENT_UNEXPECTED;
                    }
                }

                if let Some(current) = self.user_to_main_agent.get(&user) {
                    if current.agent_address != agent_address {
                        // [INFERENCE] The recovered helper only behaved cleanly for first insert,
                        // clearing the slot, or refreshing the same main-agent address.
                        return ERR_SAVE_AGENT_UNEXPECTED;
                    }
                }

                self.clear_pending_removal(user, agent_address);
                self.agent_to_user.insert(agent_address, user);
                self.user_to_main_agent.insert(
                    user,
                    MainAgent {
                        agent_address,
                        valid_until_ms,
                    },
                );
                OK
            }
        }
    }

    pub fn save_extra_agent(
        &mut self,
        user: Address,
        name: &str,
        agent_address: Address,
        valid_until: NaiveDateTime12,
        now: NaiveDateTime12,
        extra_agent_quota_tier: i64,
    ) -> u16 {
        if name.is_empty() || name.len() > 16 {
            return ERR_EXTRA_AGENT_INVALID_NAME;
        }

        let now_ms = now.unix_millis_saturating();
        let valid_until_ms = valid_until.unix_millis_saturating();
        if valid_until_ms <= now_ms.saturating_add(AGENT_GRACE_PERIOD_MS) {
            return ERR_AGENT_VALID_UNTIL_PASSED;
        }

        let existing = self
            .user_to_extra_agents
            .get(&user)
            .and_then(|agents| agents.iter().position(|agent| agent.name == name));

        if let Some(index) = existing {
            let current_agent_address = self.user_to_extra_agents[&user][index].agent_address;
            if current_agent_address == agent_address {
                if self
                    .agent_to_user
                    .get(&agent_address)
                    .is_some_and(|owner| owner != &user)
                {
                    return ERR_EXTRA_AGENT_ALREADY_USED;
                }

                self.user_to_extra_agents.get_mut(&user).unwrap()[index].valid_until_ms = valid_until_ms;
                self.agent_to_user.insert(agent_address, user);
                self.clear_pending_removal(user, agent_address);
                return OK;
            }
        }

        if self.agent_to_user.contains_key(&agent_address) {
            return ERR_EXTRA_AGENT_ALREADY_USED;
        }

        let mut replaced_agent = None;
        {
            let agents = self.user_to_extra_agents.entry(user).or_default();
            match existing {
                Some(index) => {
                    let replaced = std::mem::replace(
                        &mut agents[index],
                        ExtraAgent {
                            name: name.to_owned(),
                            agent_address,
                            valid_until_ms,
                        },
                    );
                    replaced_agent = Some(replaced.agent_address);
                }
                None => {
                    if !EXTRA_AGENT_CAP_BYPASS.contains(&agent_address)
                        && agents.len() >= extra_agent_limit_from_tier(extra_agent_quota_tier)
                    {
                        return ERR_TOO_MANY_EXTRA_AGENTS;
                    }
                    agents.push(ExtraAgent {
                        name: name.to_owned(),
                        agent_address,
                        valid_until_ms,
                    });
                }
            }
        }

        if let Some(old_agent_address) = replaced_agent {
            self.push_pending_removal(user, old_agent_address, now_ms + AGENT_GRACE_PERIOD_MS);
        }
        self.agent_to_user.insert(agent_address, user);
        self.clear_pending_removal(user, agent_address);
        OK
    }

    pub fn remove_extra_agent_by_name(
        &mut self,
        user: Address,
        name: &str,
        now: NaiveDateTime12,
    ) -> u16 {
        let removed = {
            let Some(agents) = self.user_to_extra_agents.get_mut(&user) else {
                return ERR_EXTRA_AGENT_DOES_NOT_EXIST;
            };

            let Some(index) = agents.iter().position(|agent| agent.name == name) else {
                return ERR_EXTRA_AGENT_DOES_NOT_EXIST;
            };

            let removed = agents.remove(index);
            let should_drop_entry = agents.is_empty();
            (removed, should_drop_entry)
        };

        if removed.1 {
            self.user_to_extra_agents.remove(&user);
        }

        self.push_pending_removal(
            user,
            removed.0.agent_address,
            now.unix_millis_saturating().saturating_add(AGENT_GRACE_PERIOD_MS),
        );
        OK
    }

    pub fn prune_pending_agent_removals<F>(&mut self, now: NaiveDateTime12, is_real_user_address: F)
    where
        F: Fn(&Address) -> bool,
    {
        let now_ms = now.unix_millis_saturating();
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

    fn push_pending_removal(&mut self, user: Address, agent_address: Address, ready_at_ms: u64) {
        self.user_to_pending_agent_removals
            .entry(user)
            .or_default()
            .insert(PendingAgentRemoval {
                ready_at_ms,
                agent_address,
            });
    }

    fn clear_pending_removal(&mut self, user: Address, agent_address: Address) {
        let should_remove_user = {
            let Some(pending) = self.user_to_pending_agent_removals.get_mut(&user) else {
                return;
            };

            let stale: Vec<_> = pending
                .iter()
                .copied()
                .filter(|removal| removal.agent_address == agent_address)
                .collect();
            for removal in stale {
                pending.remove(&removal);
            }
            pending.is_empty()
        };

        if should_remove_user {
            self.user_to_pending_agent_removals.remove(&user);
        }
    }
}

#[inline]
fn is_zero_address(address: &Address) -> bool {
    address.iter().all(|byte| *byte == 0)
}

#[inline]
fn extra_agent_limit_from_tier(tier: i64) -> usize {
    if tier < 0 {
        usize::MAX
    } else {
        BASE_EXTRA_AGENT_LIMIT.saturating_add((tier as usize).saturating_mul(2))
    }
}
