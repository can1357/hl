//! Recovered sub-account state and validation logic.
//!
//! Evidence recovered from the binary:
//! - persistent state serializes two fields named `user_to_sub_accounts` and
//!   `sub_account_to_master`;
//! - one sub-account list entry serializes compact fields `n`, `s`, `m`, and is
//!   laid out as `String` + sub-account address + master address (64 bytes);
//! - `createSubAccount` is the literal domain string used when deriving a new
//!   sub-account address;
//! - success is represented by compact tag `390`; sub-account error tags are a
//!   contiguous block starting at `214`.

#![allow(dead_code)]

use std::collections::HashMap;

pub type Address = [u8; 20];
pub type RawUsd = u64;

pub const CREATE_SUB_ACCOUNT_DOMAIN: &str = "createSubAccount";
pub const SUCCESS_CODE: u16 = 390;
pub const MAX_NAME_BYTES: usize = 16;
pub const MAX_WIRE_NAME_BYTES: usize = 100;
pub const MIN_CREATE_EQUITY_RAW: RawUsd = 10_000_000;
pub const SUB_ACCOUNT_CAP_EQUITY_STEP_RAW: RawUsd = 10_000_000_000;
pub const SUB_ACCOUNT_CAP_BASE: usize = 10;
pub const SUB_ACCOUNT_CAP_MAX_BONUS: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SubAccountErrorCode {
    TooManySubAccounts = 214,
    SubAccountNameNotUnique = 215,
    DuplicateSubAccountUser = 216,
    SubAccountInvalidName = 217,
    SubAccountTransferNotAllowed = 218,
    SubAccountNotAllowed = 219,
    SubAccountNotRegistered = 220,
    SubAccountsNotEligible = 221,
    SelfTransfer = 222,
    FullNameTooLong = 323,
}

impl SubAccountErrorCode {
    #[inline]
    pub const fn code(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubAccountError {
    TooManySubAccounts,
    SubAccountNameNotUnique,
    DuplicateSubAccountUser(Address),
    SubAccountInvalidName,
    SubAccountTransferNotAllowed,
    SubAccountNotAllowed,
    SubAccountNotRegistered {
        master: Address,
        sub_account_user: Address,
    },
    SubAccountsNotEligible {
        equity_raw: RawUsd,
    },
    SelfTransfer,
    FullNameTooLong,
}

impl SubAccountError {
    #[inline]
    pub const fn code(self) -> SubAccountErrorCode {
        match self {
            Self::TooManySubAccounts => SubAccountErrorCode::TooManySubAccounts,
            Self::SubAccountNameNotUnique => SubAccountErrorCode::SubAccountNameNotUnique,
            Self::DuplicateSubAccountUser(_) => SubAccountErrorCode::DuplicateSubAccountUser,
            Self::SubAccountInvalidName => SubAccountErrorCode::SubAccountInvalidName,
            Self::SubAccountTransferNotAllowed => SubAccountErrorCode::SubAccountTransferNotAllowed,
            Self::SubAccountNotAllowed => SubAccountErrorCode::SubAccountNotAllowed,
            Self::SubAccountNotRegistered { .. } => SubAccountErrorCode::SubAccountNotRegistered,
            Self::SubAccountsNotEligible { .. } => SubAccountErrorCode::SubAccountsNotEligible,
            Self::SelfTransfer => SubAccountErrorCode::SelfTransfer,
            Self::FullNameTooLong => SubAccountErrorCode::FullNameTooLong,
        }
    }

    #[inline]
    pub const fn wire_code(self) -> u16 {
        self.code().code()
    }

    #[inline]
    pub fn ineligible_equity_as_display(self) -> Option<f64> {
        match self {
            Self::SubAccountsNotEligible { equity_raw } => Some(equity_raw as f64 / 100.0),
            _ => None,
        }
    }
}

/// A persistent sub-account row.
///
/// The recovered serializer emits field keys `n`, `s`, and `m`; the in-memory
/// row is exactly 64 bytes on the target ABI: 24-byte `String`, 20-byte
/// sub-account address, 20-byte master address.
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubAccountEntry {
    pub name: String,
    pub sub_account_user: Address,
    pub master: Address,
}

impl SubAccountEntry {
    pub const STRUCT_SIZE: usize = 64;
    pub const NAME_OFFSET: usize = 0x00;
    pub const SUB_ACCOUNT_USER_OFFSET: usize = 0x18;
    pub const MASTER_OFFSET: usize = 0x2c;
    pub const SERDE_FIELD_NAME: &'static str = "n";
    pub const SERDE_FIELD_SUB_ACCOUNT: &'static str = "s";
    pub const SERDE_FIELD_MASTER: &'static str = "m";

    #[inline]
    pub fn new(name: String, sub_account_user: Address, master: Address) -> Self {
        Self {
            name,
            sub_account_user,
            master,
        }
    }
}

const _: [(); SubAccountEntry::STRUCT_SIZE] = [(); core::mem::size_of::<SubAccountEntry>()];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubAccounts {
    /// Serialized field `user_to_sub_accounts`.
    pub user_to_sub_accounts: HashMap<Address, Vec<SubAccountEntry>>,
    /// Serialized field `sub_account_to_master`.
    pub sub_account_to_master: HashMap<Address, Address>,
}

impl SubAccounts {
    pub const SERDE_FIELD_USER_TO_SUB_ACCOUNTS: &'static str = "user_to_sub_accounts";
    pub const SERDE_FIELD_SUB_ACCOUNT_TO_MASTER: &'static str = "sub_account_to_master";

    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn sub_account_count(&self, master: &Address) -> usize {
        self.user_to_sub_accounts.get(master).map_or(0, Vec::len)
    }

    #[inline]
    pub fn lookup_master(&self, sub_account_user: &Address) -> Option<Address> {
        self.sub_account_to_master.get(sub_account_user).copied()
    }

    #[inline]
    pub fn is_sub_account_user(&self, user: &Address) -> bool {
        self.sub_account_to_master.contains_key(user)
    }

    #[inline]
    pub fn sub_accounts_for(&self, master: &Address) -> &[SubAccountEntry] {
        match self.user_to_sub_accounts.get(master) {
            Some(entries) => entries.as_slice(),
            None => &[],
        }
    }

    #[inline]
    pub fn max_sub_accounts_for_equity(equity_raw: RawUsd) -> usize {
        let bonus = (equity_raw / SUB_ACCOUNT_CAP_EQUITY_STEP_RAW) as usize;
        SUB_ACCOUNT_CAP_BASE + bonus.min(SUB_ACCOUNT_CAP_MAX_BONUS)
    }

    #[inline]
    pub fn validate_create_eligibility(
        &self,
        master: &Address,
        equity_raw: RawUsd,
    ) -> Result<(), SubAccountError> {
        if equity_raw < MIN_CREATE_EQUITY_RAW {
            return Err(SubAccountError::SubAccountsNotEligible { equity_raw });
        }

        if self.sub_account_count(master) >= Self::max_sub_accounts_for_equity(equity_raw) {
            return Err(SubAccountError::TooManySubAccounts);
        }

        Ok(())
    }

    #[inline]
    pub fn validate_new_name(&self, master: &Address, name: &str) -> Result<(), SubAccountError> {
        validate_sub_account_name(name)?;
        if self
            .user_to_sub_accounts
            .get(master)
            .is_some_and(|entries| entries.iter().any(|entry| entry.name.as_bytes() == name.as_bytes()))
        {
            return Err(SubAccountError::SubAccountNameNotUnique);
        }
        Ok(())
    }

    /// Creates and records a sub-account when the caller already has the
    /// derived user address.
    ///
    /// The binary derives this address before the name checks, then rejects a
    /// collision in `sub_account_to_master` with tag `216`.
    pub fn create_sub_account_with_address(
        &mut self,
        master: Address,
        name: String,
        equity_raw: RawUsd,
        sub_account_user: Address,
    ) -> Result<Address, SubAccountError> {
        self.validate_create_eligibility(&master, equity_raw)?;

        if self.sub_account_to_master.contains_key(&sub_account_user) {
            return Err(SubAccountError::DuplicateSubAccountUser(sub_account_user));
        }

        self.validate_wire_name_len(name.as_bytes())?;
        self.validate_new_name(&master, &name)?;

        let previous = self.sub_account_to_master.insert(sub_account_user, master);
        debug_assert!(previous.is_none(), "duplicate sub-account user after precheck");
        if previous.is_some() {
            return Err(SubAccountError::DuplicateSubAccountUser(sub_account_user));
        }

        self.user_to_sub_accounts
            .entry(master)
            .or_default()
            .push(SubAccountEntry::new(name, sub_account_user, master));

        Ok(sub_account_user)
    }

    pub fn create_sub_account<D: SubAccountAddressDeriver>(
        &mut self,
        master: Address,
        name: String,
        equity_raw: RawUsd,
        deriver: &mut D,
    ) -> Result<Address, SubAccountError> {
        self.validate_create_eligibility(&master, equity_raw)?;
        let next_index = self.sub_account_count(&master) as u64;
        let sub_account_user = deriver.derive_sub_account_user(&master, next_index)?;
        self.create_sub_account_with_address(master, name, equity_raw, sub_account_user)
    }

    /// Updates the display name for an existing sub-account owned by `master`.
    /// `None` is a no-op success in the recovered function.
    pub fn modify_sub_account_name(
        &mut self,
        master: Address,
        sub_account_user: Address,
        new_name: Option<String>,
    ) -> Result<(), SubAccountError> {
        let Some(name) = new_name else {
            return Ok(());
        };

        self.validate_wire_name_len(name.as_bytes())?;
        self.validate_new_name(&master, &name)?;

        let entries = self.user_to_sub_accounts.get_mut(&master).ok_or(
            SubAccountError::SubAccountNotRegistered {
                master,
                sub_account_user,
            },
        )?;

        let entry = entries
            .iter_mut()
            .find(|entry| entry.sub_account_user == sub_account_user)
            .ok_or(SubAccountError::SubAccountNotRegistered {
                master,
                sub_account_user,
            })?;

        entry.name = name;
        Ok(())
    }

    #[inline]
    pub fn validate_transfer(
        &self,
        master: Address,
        transfer: SubAccountTransfer,
    ) -> Result<ResolvedSubAccountTransfer, SubAccountError> {
        self.resolve_transfer(master, transfer.sub_account_user, transfer.is_deposit)
            .map(|legs| ResolvedSubAccountTransfer {
                legs,
                usd: transfer.usd,
            })
    }

    /// Resolve master/sub-account transfer legs.
    ///
    /// Deposits debit the master and credit the sub-account; withdrawals debit
    /// the sub-account and credit the master.  The mapping must point from the
    /// supplied sub-account user back to the signing master.
    pub fn resolve_transfer(
        &self,
        master: Address,
        sub_account_user: Address,
        is_deposit: bool,
    ) -> Result<SubAccountTransferLegs, SubAccountError> {
        if master == sub_account_user {
            return Err(SubAccountError::SelfTransfer);
        }

        match self.lookup_master(&sub_account_user) {
            Some(mapped_master) if mapped_master == master => {}
            Some(_) => return Err(SubAccountError::SubAccountTransferNotAllowed),
            None => {
                return Err(SubAccountError::SubAccountNotRegistered {
                    master,
                    sub_account_user,
                });
            }
        }

        let (from, to) = if is_deposit {
            (master, sub_account_user)
        } else {
            (sub_account_user, master)
        };

        Ok(SubAccountTransferLegs {
            from,
            to,
            master,
            sub_account_user,
            direction: if is_deposit {
                SubAccountTransferDirection::Deposit
            } else {
                SubAccountTransferDirection::Withdraw
            },
        })
    }

    #[inline]
    fn validate_wire_name_len(&self, bytes: &[u8]) -> Result<(), SubAccountError> {
        if bytes.len() > MAX_WIRE_NAME_BYTES {
            Err(SubAccountError::FullNameTooLong)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubAccountTransfer {
    pub sub_account_user: Address,
    pub is_deposit: bool,
    pub usd: RawUsd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedSubAccountTransfer {
    pub legs: SubAccountTransferLegs,
    pub usd: RawUsd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubAccountTransferDirection {
    Deposit,
    Withdraw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubAccountTransferLegs {
    pub from: Address,
    pub to: Address,
    pub master: Address,
    pub sub_account_user: Address,
    pub direction: SubAccountTransferDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubAccountSpotTransfer<'a> {
    pub sub_account_user: Address,
    pub token: &'a str,
    pub amount: &'a str,
    pub is_deposit: bool,
}

impl<'a> SubAccountSpotTransfer<'a> {
    #[inline]
    pub fn resolve(
        self,
        accounts: &SubAccounts,
        master: Address,
    ) -> Result<ResolvedSubAccountSpotTransfer<'a>, SubAccountError> {
        accounts
            .resolve_transfer(master, self.sub_account_user, self.is_deposit)
            .map(|legs| ResolvedSubAccountSpotTransfer {
                legs,
                token: self.token,
                amount: self.amount,
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedSubAccountSpotTransfer<'a> {
    pub legs: SubAccountTransferLegs,
    pub token: &'a str,
    pub amount: &'a str,
}

pub trait SubAccountAddressDeriver {
    /// Returns the 20-byte user address for `(CREATE_SUB_ACCOUNT_DOMAIN, master,
    /// existing_sub_account_count)`.
    fn derive_sub_account_user(
        &mut self,
        master: &Address,
        existing_sub_account_count: u64,
    ) -> Result<Address, SubAccountError>;
}

#[derive(Debug, Clone, Copy)]
pub struct DigestAddressDeriver<F> {
    f: F,
}

impl<F> DigestAddressDeriver<F> {
    #[inline]
    pub const fn new(f: F) -> Self {
        Self { f }
    }
}

impl<F> SubAccountAddressDeriver for DigestAddressDeriver<F>
where
    F: FnMut(&'static str, &Address, u64) -> [u8; 32],
{
    #[inline]
    fn derive_sub_account_user(
        &mut self,
        master: &Address,
        existing_sub_account_count: u64,
    ) -> Result<Address, SubAccountError> {
        Ok(address_from_digest((self.f)(
            CREATE_SUB_ACCOUNT_DOMAIN,
            master,
            existing_sub_account_count,
        )))
    }
}

#[inline]
pub const fn address_from_digest(digest: [u8; 32]) -> Address {
    let mut address = [0_u8; 20];
    let mut i = 0;
    while i < address.len() {
        address[i] = digest[i];
        i += 1;
    }
    address
}

#[inline]
pub fn validate_sub_account_name(name: &str) -> Result<(), SubAccountError> {
    let len = name.as_bytes().len();
    if len == 0 || len > MAX_NAME_BYTES {
        Err(SubAccountError::SubAccountInvalidName)
    } else {
        Ok(())
    }
}
