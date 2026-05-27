#![allow(dead_code)]

use std::collections::BTreeMap;

pub type Address = [u8; 20];

pub const STATUS_SUCCESS: u16 = 390;
pub const STATUS_VAULT_NOT_REGISTERED: u16 = 7;
pub const STATUS_VAULT_ACTION_LEADER_ONLY: u16 = 17;

/// Shared wrapper shape recovered from `sub_22C5FD0`.
///
/// The outer wrapper emits compact tag `13` when the inner helper returns status
/// `390`, otherwise it copies the inner error payload into the tag-`14` variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum VaultModifyWrapperTag {
    Ok = 13,
    Err = 14,
}

/// Exact tri-state bytes consumed by the inner helper at `0x26F6A80`.
///
/// Raw value `2` means "leave the stored vault byte unchanged". Any other value
/// is written directly into the vault record after the leader check passes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum VaultModifyFlag {
    False = 0,
    True = 1,
    Keep = 2,
}

impl VaultModifyFlag {
    #[inline]
    pub const fn apply_to(self, current: bool) -> bool {
        match self {
            Self::False => false,
            Self::True => true,
            Self::Keep => current,
        }
    }
}

/// JSON/action-level field names are grounded by the serializer metadata under
/// `protocol/l1_action_payloads.md`, while the tri-state encoding is grounded by
/// the apply helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultModifyAction {
    pub vault_address: Address,
    pub allow_deposits: VaultModifyFlag,
    pub always_close_on_withdraw: VaultModifyFlag,
}

/// Minimal vault fields touched by this handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultRecord {
    pub vault_address: Address,
    pub leader: Address,
    pub allow_deposits: bool,
    pub always_close_on_withdraw: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ExchangeState {
    pub vaults_by_address: BTreeMap<Address, VaultRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultModifyErrorPayload {
    pub status: u16,
    pub missing_vault_address: Option<Address>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultModifyOutcome {
    Ok { status: u16 },
    Err(VaultModifyErrorPayload),
}

impl VaultModifyOutcome {
    #[inline]
    pub const fn wrapper_tag(self) -> VaultModifyWrapperTag {
        match self {
            Self::Ok { .. } => VaultModifyWrapperTag::Ok,
            Self::Err(_) => VaultModifyWrapperTag::Err,
        }
    }
}

/// Recovered from `sub_22C5FD0 -> sub_26F6A80`.
///
/// Observed ordering:
/// 1. Generic exchange dispatch/nonce handling happens upstream.
/// 2. Look up the vault by `action.vault_address` in the exchange vault tree.
/// 3. If not found, return status `7` and echo the missing vault address.
/// 4. Compare the caller's address against the stored vault leader.
/// 5. If the caller is not the leader, return status `17`.
/// 6. For each tri-state flag, overwrite the stored vault byte unless the raw
///    action value is `2` (`Keep`).
/// 7. Return compact success status `390`.
///
/// No additional closed-vault gate, balance movement, event emission, or nonce
/// mutation is visible in this handler body.
pub fn apply_vault_modify(
    state: &mut ExchangeState,
    leader: Address,
    action: &VaultModifyAction,
) -> VaultModifyOutcome {
    let Some(vault) = state.vaults_by_address.get_mut(&action.vault_address) else {
        return VaultModifyOutcome::Err(VaultModifyErrorPayload {
            status: STATUS_VAULT_NOT_REGISTERED,
            missing_vault_address: Some(action.vault_address),
        });
    };

    if vault.leader != leader {
        return VaultModifyOutcome::Err(VaultModifyErrorPayload {
            status: STATUS_VAULT_ACTION_LEADER_ONLY,
            missing_vault_address: None,
        });
    }

    vault.allow_deposits = action.allow_deposits.apply_to(vault.allow_deposits);
    vault.always_close_on_withdraw = action
        .always_close_on_withdraw
        .apply_to(vault.always_close_on_withdraw);

    VaultModifyOutcome::Ok {
        status: STATUS_SUCCESS,
    }
}
