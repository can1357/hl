#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

pub type Address = [u8; 20];
pub type RawUsd = u64;

pub const HANDLER_EA: u64 = 0x27E3_140;
pub const CREATE_HELPER_EA: u64 = 0x36F3_610;
pub const DERIVE_HELPER_EA: u64 = 0x36F3_C20;
pub const SUCCESS_CODE: u16 = 390;
pub const ERR_TOO_MANY_SUB_ACCOUNTS: u16 = 214;
pub const ERR_SUB_ACCOUNT_NAME_NOT_UNIQUE: u16 = 215;
pub const ERR_DUPLICATE_SUB_ACCOUNT_USER: u16 = 216;
pub const ERR_SUB_ACCOUNT_INVALID_NAME: u16 = 217;
pub const ERR_SUB_ACCOUNTS_NOT_ELIGIBLE: u16 = 221;
pub const ERR_FULL_NAME_TOO_LONG: u16 = 323;
pub const CREATE_SUB_ACCOUNT_DOMAIN: &[u8; 16] = b"createSubAccount";
pub const MIN_CREATE_EQUITY_RAW: RawUsd = 10_000_000;
pub const EQUITY_STEP_PER_EXTRA_SUB: RawUsd = 10_000_000_000;
pub const BASE_SUB_ACCOUNT_CAP: usize = 10;
pub const MAX_EXTRA_SUB_ACCOUNT_SLOTS: usize = 40;
pub const MAX_CANONICAL_NAME_LEN: usize = 16;
pub const MAX_WIRE_NAME_LEN: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSubAccountAction {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubAccountEntry {
    pub name: String,
    pub sub_account_user: Address,
    pub master: Address,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubAccounts {
    pub user_to_sub_accounts: HashMap<Address, Vec<SubAccountEntry>>,
    pub sub_account_to_master: HashMap<Address, Address>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CreateSubAccountError {
    TooManySubAccounts,
    DuplicateSubAccountUser { sub_account_user: Address },
    SubAccountNameNotUnique,
    SubAccountInvalidName,
    SubAccountsNotEligible { equity_raw: RawUsd },
    FullNameTooLong,
}

impl CreateSubAccountError {
    #[inline]
    pub const fn code(&self) -> u16 {
        match self {
            Self::TooManySubAccounts => ERR_TOO_MANY_SUB_ACCOUNTS,
            Self::SubAccountNameNotUnique => ERR_SUB_ACCOUNT_NAME_NOT_UNIQUE,
            Self::DuplicateSubAccountUser { .. } => ERR_DUPLICATE_SUB_ACCOUNT_USER,
            Self::SubAccountInvalidName => ERR_SUB_ACCOUNT_INVALID_NAME,
            Self::SubAccountsNotEligible { .. } => ERR_SUB_ACCOUNTS_NOT_ELIGIBLE,
            Self::FullNameTooLong => ERR_FULL_NAME_TOO_LONG,
        }
    }

    #[inline]
    pub fn display_equity_usd(&self) -> Option<f64> {
        match self {
            Self::SubAccountsNotEligible { equity_raw } => Some(*equity_raw as f64 / 100.0),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CreateSubAccountResult {
    Created { sub_account_user: Address },
    Rejected {
        error: CreateSubAccountError,
        derived_sub_account_user: Option<Address>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserStateSnapshot {
    pub blob: [u8; 128],
    pub has_pending_marker: bool,
}

pub trait SubAccountAddressDeriver {
    fn derive_sub_account_user(&mut self, master: &Address, next_index: u64) -> Address;
}

pub struct ExchangeCreateSubAccountCtx {
    /// Global user-account table checked by the outer handler before any equity work.
    pub known_users: HashSet<Address>,
    /// Recovered sub-account state rooted at exchange offset `+894 * 16`.
    pub sub_accounts: SubAccounts,
    /// Side effects populated after the helper returns success.
    pub registered_user_accounts: HashSet<Address>,
    pub indexed_user_entries: HashSet<Address>,
    pub pending_user_state: HashMap<Address, UserStateSnapshot>,
}

pub trait CreateSubAccountBackend {
    fn user_equity_raw(&self, master: &Address) -> RawUsd;
    fn refresh_user_snapshot(&mut self, user: &Address) -> UserStateSnapshot;
}

impl ExchangeCreateSubAccountCtx {
    pub fn insert_pending_user_state(&mut self, user: Address, snapshot: UserStateSnapshot) {
        self.pending_user_state.insert(user, snapshot);
    }

    pub fn get_or_create_user_account(&mut self, user: Address) {
        self.known_users.insert(user);
        self.registered_user_accounts.insert(user);
    }

    pub fn insert_user_entry(&mut self, user: Address) {
        self.indexed_user_entries.insert(user);
    }
}

impl SubAccounts {
    #[inline]
    pub fn sub_account_count(&self, master: &Address) -> usize {
        self.user_to_sub_accounts.get(master).map_or(0, Vec::len)
    }

    #[inline]
    pub fn max_sub_accounts_for_equity(equity_raw: RawUsd) -> usize {
        BASE_SUB_ACCOUNT_CAP
            + ((equity_raw / EQUITY_STEP_PER_EXTRA_SUB) as usize).min(MAX_EXTRA_SUB_ACCOUNT_SLOTS)
    }

    #[inline]
    pub fn validate_create_eligibility(
        &self,
        master: &Address,
        equity_raw: RawUsd,
    ) -> Result<(), CreateSubAccountError> {
        if equity_raw < MIN_CREATE_EQUITY_RAW {
            return Err(CreateSubAccountError::SubAccountsNotEligible { equity_raw });
        }

        if self.sub_account_count(master) >= Self::max_sub_accounts_for_equity(equity_raw) {
            return Err(CreateSubAccountError::TooManySubAccounts);
        }

        Ok(())
    }

    #[inline]
    pub fn validate_new_name(
        &self,
        master: &Address,
        name: &str,
    ) -> Result<(), CreateSubAccountError> {
        let len = name.len();
        if len == 0 || len > MAX_CANONICAL_NAME_LEN {
            return Err(CreateSubAccountError::SubAccountInvalidName);
        }

        if self
            .user_to_sub_accounts
            .get(master)
            .is_some_and(|entries| entries.iter().any(|entry| entry.name.as_bytes() == name.as_bytes()))
        {
            return Err(CreateSubAccountError::SubAccountNameNotUnique);
        }

        Ok(())
    }

    pub fn create_sub_account_with_address(
        &mut self,
        master: Address,
        name: String,
        equity_raw: RawUsd,
        sub_account_user: Address,
    ) -> Result<Address, CreateSubAccountError> {
        self.validate_create_eligibility(&master, equity_raw)?;

        if self.sub_account_to_master.contains_key(&sub_account_user) {
            return Err(CreateSubAccountError::DuplicateSubAccountUser { sub_account_user });
        }

        if name.len() > MAX_WIRE_NAME_LEN {
            return Err(CreateSubAccountError::FullNameTooLong);
        }

        self.validate_new_name(&master, &name)?;

        let previous = self.sub_account_to_master.insert(sub_account_user, master);
        debug_assert!(previous.is_none(), "duplicate sub-account user after precheck");
        if previous.is_some() {
            return Err(CreateSubAccountError::DuplicateSubAccountUser { sub_account_user });
        }

        self.user_to_sub_accounts
            .entry(master)
            .or_default()
            .push(SubAccountEntry {
                name,
                sub_account_user,
                master,
            });

        Ok(sub_account_user)
    }
}

/// Reconstructs `sub_27E3140`.
///
/// Observed control flow:
/// 1. Derive the next sub-account user from `(b"createSubAccount", master, current_count)`.
/// 2. Reject immediately with code `216` if the derived address already exists in the
///    exchange-wide user table.
/// 3. Compute master equity via `sub_275FEE0(exchange, master)`.
/// 4. Call `l1_sub_account__create_sub_account(...)`, which enforces:
///    - minimum equity `>= 10_000_000` raw, else `221` with `equity_raw / 100.0`;
///    - cap `10 + min(equity_raw / 10_000_000_000, 40)`, else `214`;
///    - derived-address collision in `sub_account_to_master`, else `216`;
///    - wire name length `<= 100`, else `323`;
///    - canonical name validation and per-master uniqueness, else `217`/`215`.
/// 5. On success, refresh per-user state for the master and the new sub-account.
/// 6. If those two snapshots differ, cache the sub-account snapshot in the exchange-side
///    pending-state map before user registration/index insertion.
/// 7. Register the new user account and insert it into the exchange entry index.
pub fn apply_create_sub_account<D: SubAccountAddressDeriver, B: CreateSubAccountBackend>(
    ctx: &mut ExchangeCreateSubAccountCtx,
    backend: &mut B,
    master: Address,
    action: CreateSubAccountAction,
    deriver: &mut D,
) -> CreateSubAccountResult {
    let next_index = ctx.sub_accounts.sub_account_count(&master) as u64;
    let derived_sub_account_user = deriver.derive_sub_account_user(&master, next_index);

    if ctx.known_users.contains(&derived_sub_account_user) {
        return CreateSubAccountResult::Rejected {
            error: CreateSubAccountError::DuplicateSubAccountUser {
                sub_account_user: derived_sub_account_user,
            },
            derived_sub_account_user: Some(derived_sub_account_user),
        };
    }

    let equity_raw = backend.user_equity_raw(&master);
    let created = match ctx.sub_accounts.create_sub_account_with_address(
        master,
        action.name,
        equity_raw,
        derived_sub_account_user,
    ) {
        Ok(sub_account_user) => sub_account_user,
        Err(error) => {
            return CreateSubAccountResult::Rejected {
                error,
                derived_sub_account_user: Some(derived_sub_account_user),
            };
        }
    };

    let master_snapshot = backend.refresh_user_snapshot(&master);
    let sub_account_snapshot = backend.refresh_user_snapshot(&created);
    if master_snapshot != sub_account_snapshot {
        ctx.insert_pending_user_state(created, sub_account_snapshot);
    }

    ctx.get_or_create_user_account(created);
    ctx.insert_user_entry(created);

    CreateSubAccountResult::Created {
        sub_account_user: created,
    }
}
