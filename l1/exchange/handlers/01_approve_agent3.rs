#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use crate::chain_ext::{ChainExt, HlChain};

pub type Address = [u8; 20];
pub type Nonce = u64;
pub type TimestampMillis = u64;

pub const STATUS_OK: u16 = 390;
pub const ERR_SAVE_AGENT_UNEXPECTED: u16 = 81;
pub const ERR_AGENT_ADDRESS_IS_USER: u16 = 82;
pub const ERR_EXTRA_AGENT_INVALID_NAME: u16 = 83;
pub const ERR_AGENT_INVALID_NAME_INPUT: u16 = 84;
pub const ERR_AGENT_VALID_UNTIL_PASSED: u16 = 85;
pub const ERR_EXTRA_AGENT_ALREADY_USED: u16 = 86;
pub const ERR_TOO_MANY_EXTRA_AGENTS: u16 = 87;
pub const ERR_EXTRA_AGENT_DOES_NOT_EXIST: u16 = 89;
pub const ERR_PENDING_AGENT_REMOVAL: u16 = 349;
pub const ERR_STRING_TOO_LONG: u16 = 323;

const AGENT_GRACE_PERIOD_MS: u64 = 2_000;
/// [INFERENCE] The empty-name main-agent path builds this default by adding
/// seven days twice in `0x1E5F770`, then forwarding the resulting packed time.
const MAIN_AGENT_DEFAULT_VALIDITY_MS: u64 = 14 * 24 * 60 * 60 * 1_000;
/// The plain extra-agent path in `0x3342A40` adds `7_776_000` seconds.
const EXTRA_AGENT_DEFAULT_VALIDITY_MS: u64 = 90 * 24 * 60 * 60 * 1_000;
/// `0x2766F70` rejects explicit expiries beyond `0xED4E00` seconds from `now`.
const MAX_AGENT_VALIDITY_MS: u64 = 180 * 24 * 60 * 60 * 1_000;
const MAX_AGENT_NAME_INPUT_BYTES: usize = 100;
const MAX_EXTRA_AGENT_NAME_BYTES: usize = 16;
const EXTRA_AGENT_EQUITY_GATE_RAW: u64 = 10_000_000;
const EXTRA_AGENT_TIER_STEP_RAW: u64 = 10_000_000_000;
const BASE_EXTRA_AGENT_LIMIT: usize = 3;

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

/// Recovered wire layout from the JSON serializer rooted at `0x1BF18B0`.
#[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApproveAgent3Action {
    pub agent_name: String,
    pub signature_chain_idents: Vec<u8>,
    pub nonce: Nonce,
    pub agent_address: Address,
    pub hyperliquid_chain: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PendingAgentRemoval {
    pub ready_at_ms: TimestampMillis,
    pub agent_address: Address,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MainAgentApproval {
    pub agent_address: Address,
    pub valid_until_ms: Option<TimestampMillis>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ExtraAgentApproval {
    pub name: String,
    pub agent_address: Address,
    pub valid_until_ms: Option<TimestampMillis>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AgentTrackerState {
    pub user_to_main_agent: BTreeMap<Address, MainAgentApproval>,
    pub user_to_extra_agents: BTreeMap<Address, Vec<ExtraAgentApproval>>,
    pub agent_to_user: BTreeMap<Address, Address>,
    pub user_to_pending_agent_removals: BTreeMap<Address, BTreeSet<PendingAgentRemoval>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApproveAgent3MutationKind {
    ClearMain,
    SaveMain,
    RemoveExtra,
    SaveExtra,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApproveAgent3Mutation {
    pub kind: ApproveAgent3MutationKind,
    pub agent_name: Option<String>,
    pub agent_address: Option<Address>,
    pub valid_until_ms: Option<TimestampMillis>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedAgentNameInput {
    extra_agent_name: Option<String>,
    valid_until_ms: Option<TimestampMillis>,
}

/// Apply path for `ApproveAgent3` after the shared signer/nonce gate in
/// `impl_execute_action` has already accepted `action.nonce`.
///
/// Grounded pieces:
/// - `0x1E5F770` distinguishes main-agent vs extra-agent paths from the parsed
///   `agent_name` input and the all-zero/non-zero `agent_address`.
/// - `0x3342A40` normalizes `agent_name` into `(optional_name, optional_valid_until)`.
/// - `0x2766F70` rejects user-owned agent addresses, blocks all edits while the
///   caller has any pending removal, then dispatches into main-agent save,
///   extra-agent save, or extra-agent removal helpers.
///
/// [INFERENCE] The generic nonce reservation and signature-domain checks happen
/// before this handler, so the body here does not consume `signature_chain_idents`,
/// `hyperliquid_chain`, or `nonce` directly.
pub fn apply_approve_agent3<F>(
    tracker: &mut AgentTrackerState,
    user: Address,
    action: &ApproveAgent3Action,
    now_ms: TimestampMillis,
    chain: HlChain,
    user_equity_raw: u64,
    address_is_existing_user: F,
) -> Result<ApproveAgent3Mutation, u16>
where
    F: Fn(&Address) -> bool,
{
    if action.agent_name.len() > MAX_AGENT_NAME_INPUT_BYTES {
        return Err(ERR_STRING_TOO_LONG);
    }

    let parsed = parse_agent_name_input(&action.agent_name, now_ms)?;

    if let Some(valid_until_ms) = parsed.valid_until_ms {
        let min_valid_until_ms = now_ms.saturating_add(AGENT_GRACE_PERIOD_MS);
        let max_valid_until_ms = now_ms.saturating_add(MAX_AGENT_VALIDITY_MS);
        if valid_until_ms <= min_valid_until_ms || valid_until_ms > max_valid_until_ms {
            return Err(ERR_AGENT_VALID_UNTIL_PASSED);
        }
    }

    if !is_zero_address(&action.agent_address) && address_is_existing_user(&action.agent_address) {
        return Err(ERR_AGENT_ADDRESS_IS_USER);
    }

    if tracker
        .user_to_pending_agent_removals
        .get(&user)
        .is_some_and(|pending| !pending.is_empty())
    {
        return Err(ERR_PENDING_AGENT_REMOVAL);
    }

    match parsed.extra_agent_name {
        None => apply_main_agent(tracker, user, action.agent_address, parsed.valid_until_ms, now_ms),
        Some(agent_name) => apply_extra_agent(
            tracker,
            user,
            agent_name,
            action.agent_address,
            parsed.valid_until_ms,
            now_ms,
            extra_agent_quota_tier(chain, &user, user_equity_raw),
        ),
    }
}

fn apply_main_agent(
    tracker: &mut AgentTrackerState,
    user: Address,
    agent_address: Address,
    valid_until_ms: Option<TimestampMillis>,
    now_ms: TimestampMillis,
) -> Result<ApproveAgent3Mutation, u16> {
    if is_zero_address(&agent_address) {
        if let Some(previous) = tracker.user_to_main_agent.remove(&user) {
            push_pending_removal(
                tracker,
                user,
                previous.agent_address,
                now_ms.saturating_add(AGENT_GRACE_PERIOD_MS),
            );
        }
        return Ok(ApproveAgent3Mutation {
            kind: ApproveAgent3MutationKind::ClearMain,
            agent_name: None,
            agent_address: None,
            valid_until_ms: None,
        });
    }

    if let Some(owner) = tracker.agent_to_user.get(&agent_address) {
        if owner != &user {
            return Err(ERR_SAVE_AGENT_UNEXPECTED);
        }
    }

    if let Some(current) = tracker.user_to_main_agent.get(&user) {
        if current.agent_address != agent_address {
            return Err(ERR_SAVE_AGENT_UNEXPECTED);
        }
    }

    clear_pending_removal(tracker, user, agent_address);
    tracker.agent_to_user.insert(agent_address, user);
    tracker.user_to_main_agent.insert(
        user,
        MainAgentApproval {
            agent_address,
            valid_until_ms,
        },
    );

    Ok(ApproveAgent3Mutation {
        kind: ApproveAgent3MutationKind::SaveMain,
        agent_name: None,
        agent_address: Some(agent_address),
        valid_until_ms,
    })
}

fn apply_extra_agent(
    tracker: &mut AgentTrackerState,
    user: Address,
    agent_name: String,
    agent_address: Address,
    valid_until_ms: Option<TimestampMillis>,
    now_ms: TimestampMillis,
    extra_agent_quota_tier: i64,
) -> Result<ApproveAgent3Mutation, u16> {
    if agent_name.is_empty() || agent_name.len() > MAX_EXTRA_AGENT_NAME_BYTES {
        return Err(ERR_EXTRA_AGENT_INVALID_NAME);
    }

    if is_zero_address(&agent_address) {
        let removed = {
            let Some(agents) = tracker.user_to_extra_agents.get_mut(&user) else {
                return Err(ERR_EXTRA_AGENT_DOES_NOT_EXIST);
            };
            let Some(index) = agents.iter().position(|agent| agent.name == agent_name) else {
                return Err(ERR_EXTRA_AGENT_DOES_NOT_EXIST);
            };
            let removed = agents.remove(index);
            let should_drop_entry = agents.is_empty();
            (removed, should_drop_entry)
        };

        if removed.1 {
            tracker.user_to_extra_agents.remove(&user);
        }
        push_pending_removal(
            tracker,
            user,
            removed.0.agent_address,
            now_ms.saturating_add(AGENT_GRACE_PERIOD_MS),
        );

        return Ok(ApproveAgent3Mutation {
            kind: ApproveAgent3MutationKind::RemoveExtra,
            agent_name: Some(agent_name),
            agent_address: Some(removed.0.agent_address),
            valid_until_ms: None,
        });
    }

    let existing = tracker
        .user_to_extra_agents
        .get(&user)
        .and_then(|agents| agents.iter().position(|agent| agent.name == agent_name));

    if let Some(index) = existing {
        let current_agent_address = tracker.user_to_extra_agents[&user][index].agent_address;
        if current_agent_address == agent_address {
            if tracker
                .agent_to_user
                .get(&agent_address)
                .is_some_and(|owner| owner != &user)
            {
                return Err(ERR_EXTRA_AGENT_ALREADY_USED);
            }

            tracker.user_to_extra_agents.get_mut(&user).unwrap()[index].valid_until_ms = valid_until_ms;
            tracker.agent_to_user.insert(agent_address, user);
            clear_pending_removal(tracker, user, agent_address);
            return Ok(ApproveAgent3Mutation {
                kind: ApproveAgent3MutationKind::SaveExtra,
                agent_name: Some(agent_name),
                agent_address: Some(agent_address),
                valid_until_ms,
            });
        }
    }

    if tracker.agent_to_user.contains_key(&agent_address) {
        return Err(ERR_EXTRA_AGENT_ALREADY_USED);
    }

    let mut replaced_agent = None;
    {
        let agents = tracker.user_to_extra_agents.entry(user).or_default();
        match existing {
            Some(index) => {
                let replaced = std::mem::replace(
                    &mut agents[index],
                    ExtraAgentApproval {
                        name: agent_name.clone(),
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
                    return Err(ERR_TOO_MANY_EXTRA_AGENTS);
                }
                agents.push(ExtraAgentApproval {
                    name: agent_name.clone(),
                    agent_address,
                    valid_until_ms,
                });
            }
        }
    }

    if let Some(old_agent_address) = replaced_agent {
        push_pending_removal(
            tracker,
            user,
            old_agent_address,
            now_ms.saturating_add(AGENT_GRACE_PERIOD_MS),
        );
    }
    tracker.agent_to_user.insert(agent_address, user);
    clear_pending_removal(tracker, user, agent_address);

    Ok(ApproveAgent3Mutation {
        kind: ApproveAgent3MutationKind::SaveExtra,
        agent_name: Some(agent_name),
        agent_address: Some(agent_address),
        valid_until_ms,
    })
}

fn push_pending_removal(
    tracker: &mut AgentTrackerState,
    user: Address,
    agent_address: Address,
    ready_at_ms: TimestampMillis,
) {
    tracker
        .user_to_pending_agent_removals
        .entry(user)
        .or_default()
        .insert(PendingAgentRemoval {
            ready_at_ms,
            agent_address,
        });
}

fn clear_pending_removal(tracker: &mut AgentTrackerState, user: Address, agent_address: Address) {
    let should_remove_user = {
        let Some(pending) = tracker.user_to_pending_agent_removals.get_mut(&user) else {
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
        tracker.user_to_pending_agent_removals.remove(&user);
    }
}

/// [INFERENCE] `0x3342A40` treats `agent_name` as a compact command string:
/// plain `name`, `name valid_until <unix_ms>`, or `name valid_forever`.
/// The exact parser accepts Unicode whitespace and may have stricter phrase rules
/// than this source-level reconstruction.
fn parse_agent_name_input(input: &str, now_ms: TimestampMillis) -> Result<ParsedAgentNameInput, u16> {
    if input.is_empty() {
        return Ok(ParsedAgentNameInput {
            extra_agent_name: None,
            valid_until_ms: Some(now_ms.saturating_add(MAIN_AGENT_DEFAULT_VALIDITY_MS)),
        });
    }

    if let Some(prefix) = strip_keyword_suffix(input, "valid_forever") {
        return Ok(ParsedAgentNameInput {
            extra_agent_name: trimmed_name(prefix),
            valid_until_ms: None,
        });
    }

    if let Some((prefix, raw_valid_until)) = split_name_and_valid_until(input) {
        let valid_until_ms = raw_valid_until
            .trim()
            .parse::<u64>()
            .map_err(|_| ERR_AGENT_INVALID_NAME_INPUT)?;
        return Ok(ParsedAgentNameInput {
            extra_agent_name: trimmed_name(prefix),
            valid_until_ms: Some(valid_until_ms),
        });
    }

    Ok(ParsedAgentNameInput {
        extra_agent_name: Some(input.to_owned()),
        valid_until_ms: Some(now_ms.saturating_add(EXTRA_AGENT_DEFAULT_VALIDITY_MS)),
    })
}

fn split_name_and_valid_until(input: &str) -> Option<(&str, &str)> {
    let marker = "valid_until";
    let idx = input.find(marker)?;
    let prefix = &input[..idx];
    let suffix = &input[idx + marker.len()..];
    if prefix.is_empty() {
        return None;
    }
    let boundary_ok = prefix
        .chars()
        .next_back()
        .is_some_and(char::is_whitespace);
    if !boundary_ok {
        return None;
    }
    Some((prefix.trim_end(), suffix.trim()))
}

fn strip_keyword_suffix<'a>(input: &'a str, keyword: &str) -> Option<&'a str> {
    let prefix = input.strip_suffix(keyword)?;
    if prefix.is_empty() {
        return Some(prefix);
    }
    prefix
        .chars()
        .next_back()
        .is_some_and(char::is_whitespace)
        .then_some(prefix.trim_end())
}

fn trimmed_name(name: &str) -> Option<String> {
    let trimmed = name.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn is_zero_address(address: &Address) -> bool {
    address.iter().all(|byte| *byte == 0)
}

fn extra_agent_quota_tier(chain: HlChain, user: &Address, user_equity_raw: u64) -> i64 {
    if chain.is_foundation_self_signer(user) {
        10
    } else if user_equity_raw < EXTRA_AGENT_EQUITY_GATE_RAW {
        0
    } else {
        10 + (user_equity_raw / EXTRA_AGENT_TIER_STEP_RAW).min(40) as i64
    }
}

fn extra_agent_limit_from_tier(tier: i64) -> usize {
    if tier < 0 {
        usize::MAX
    } else {
        BASE_EXTRA_AGENT_LIMIT.saturating_add((tier as usize).saturating_mul(2))
    }
}
