#![allow(dead_code)]

use std::collections::BTreeMap;

pub type Address = [u8; 20];
pub type TokenIndex = u32;
pub type Wei = u64;

pub const HANDLER_EA: u64 = 0x1E64_420;
pub const VALIDATE_AND_APPLY_EA: u64 = 0x2717_A70;
pub const LEDGER_TRANSFER_EA: u64 = 0x2714_570;
pub const USER_LOOKUP_EA: u64 = 0x2755_400;

pub const OUTER_OK_TAG: u8 = 13;
pub const OUTER_ERR_TAG: u8 = 14;
pub const STATUS_OK: u16 = 390;
pub const STATUS_INVALID_TOKEN: u16 = 248;
pub const STATUS_SPOT_DISABLED: u16 = 249;
pub const STATUS_SUB_ACCOUNT_TRANSFER_NOT_ALLOWED: u16 = 218;
pub const STATUS_SUB_ACCOUNT_NOT_REGISTERED: u16 = 220;
pub const STATUS_SELF_TRANSFER: u16 = 222;
pub const STATUS_INSUFFICIENT_BALANCE: u16 = 247;
pub const STATUS_STRING_TOO_LONG: u16 = 323;
pub const STATUS_LEDGER_ARITHMETIC: u16 = 356;
pub const STATUS_ACCOUNT_CLASS_GATE: u16 = 367;
pub const MAX_LEDGER_STRING_LEN: usize = 100;

/// Wire payload for `UserActionTag::SubAccountSpotTransfer`.
///
/// The shared signed-action nonce gate runs before the execute-action switch, so
/// `nonce` never appears in the handler body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubAccountSpotTransferAction {
    pub sub_account_user: Address,
    pub token: String,
    pub amount: String,
    pub is_deposit: bool,
}

/// Minimal mirror of the user-profile byte consulted through `sub_2755400`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserClass {
    SpotOnly,
    Legacy,
    AbstractionOptIn,
    DexUser,
    PrivilegedDexUser,
    Other(u8),
}

impl UserClass {
    #[inline]
    pub const fn from_status_byte(byte: u8) -> Self {
        match byte {
            0 => Self::SpotOnly,
            1 => Self::Legacy,
            2 => Self::AbstractionOptIn,
            3 => Self::DexUser,
            4 => Self::PrivilegedDexUser,
            other => Self::Other(other),
        }
    }

    #[inline]
    pub const fn status_byte(self) -> u8 {
        match self {
            Self::SpotOnly => 0,
            Self::Legacy => 1,
            Self::AbstractionOptIn => 2,
            Self::DexUser => 3,
            Self::PrivilegedDexUser => 4,
            Self::Other(byte) => byte,
        }
    }
}

/// The wrapper rejects with status `367` when either leg belongs to a gated user
/// class and the corresponding exchange flag is disabled.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AccountClassGate {
    pub allow_dex_user: bool,
    pub allow_privileged_user: bool,
}

impl AccountClassGate {
    #[inline]
    pub fn permits(self, class: UserClass) -> bool {
        match class.status_byte() {
            0..=2 => true,
            3 => self.allow_dex_user,
            _ => self.allow_privileged_user,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubAccountTransferDirection {
    Deposit,
    Withdraw,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubAccountTransferLegs {
    pub from: Address,
    pub to: Address,
    pub master: Address,
    pub sub_account_user: Address,
    pub direction: SubAccountTransferDirection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubAccountError {
    SubAccountTransferNotAllowed,
    SubAccountNotRegistered {
        master: Address,
        sub_account_user: Address,
    },
    SelfTransfer,
}

impl SubAccountError {
    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::SubAccountTransferNotAllowed => STATUS_SUB_ACCOUNT_TRANSFER_NOT_ALLOWED,
            Self::SubAccountNotRegistered { .. } => STATUS_SUB_ACCOUNT_NOT_REGISTERED,
            Self::SelfTransfer => STATUS_SELF_TRANSFER,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SubAccounts {
    pub sub_account_to_master: BTreeMap<Address, Address>,
}

impl SubAccounts {
    #[inline]
    pub fn resolve_transfer(
        &self,
        master: Address,
        sub_account_user: Address,
        is_deposit: bool,
    ) -> Result<SubAccountTransferLegs, SubAccountError> {
        if master == sub_account_user {
            return Err(SubAccountError::SelfTransfer);
        }

        match self.sub_account_to_master.get(&sub_account_user).copied() {
            Some(mapped_master) if mapped_master == master => {}
            Some(_) => return Err(SubAccountError::SubAccountTransferNotAllowed),
            None => {
                return Err(SubAccountError::SubAccountNotRegistered {
                    master,
                    sub_account_user,
                });
            }
        }

        let (from, to, direction) = if is_deposit {
            (master, sub_account_user, SubAccountTransferDirection::Deposit)
        } else {
            (sub_account_user, master, SubAccountTransferDirection::Withdraw)
        };

        Ok(SubAccountTransferLegs {
            from,
            to,
            master,
            sub_account_user,
            direction,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerError {
    InvalidToken { token: String },
    SpotDisabled { token: String },
    NameTooLong,
    AmountInvalid,
    Arithmetic,
    SelfTransfer,
    InsufficientBalance,
}

impl LedgerError {
    #[inline]
    pub const fn status(&self) -> u16 {
        match self {
            Self::InvalidToken { .. } => STATUS_INVALID_TOKEN,
            Self::SpotDisabled { .. } => STATUS_SPOT_DISABLED,
            Self::NameTooLong => STATUS_STRING_TOO_LONG,
            Self::AmountInvalid | Self::Arithmetic => STATUS_LEDGER_ARITHMETIC,
            Self::SelfTransfer => STATUS_SELF_TRANSFER,
            Self::InsufficientBalance => STATUS_INSUFFICIENT_BALANCE,
        }
    }
}

pub trait SpotTransferLedger {
    fn apply_sub_account_spot_transfer(
        &mut self,
        signer: Address,
        sub_account_user: Address,
        is_deposit: bool,
        token: &str,
        amount: &str,
    ) -> Result<(), LedgerError>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SubAccountSpotTransferState {
    pub spot_disabled: bool,
    pub class_gate: AccountClassGate,
    pub user_class_by_address: BTreeMap<Address, UserClass>,
    pub sub_accounts: SubAccounts,
}

impl SubAccountSpotTransferState {
    #[inline]
    pub fn user_class(&self, user: Address) -> UserClass {
        self.user_class_by_address
            .get(&user)
            .copied()
            .unwrap_or(UserClass::SpotOnly)
    }

    #[inline]
    pub fn validate_user_class(&self, user: Address) -> Result<(), SubAccountSpotTransferError> {
        if self.class_gate.permits(self.user_class(user)) {
            Ok(())
        } else {
            Err(SubAccountSpotTransferError::AccountClassBlocked { user })
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubAccountSpotTransferError {
    AccountClassBlocked { user: Address },
    SubAccount(SubAccountError),
    Ledger(LedgerError),
}

impl SubAccountSpotTransferError {
    #[inline]
    pub const fn status(&self) -> u16 {
        match self {
            Self::AccountClassBlocked { .. } => STATUS_ACCOUNT_CLASS_GATE,
            Self::SubAccount(err) => err.status(),
            Self::Ledger(err) => err.status(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubAccountSpotTransferResult {
    Applied {
        legs: SubAccountTransferLegs,
    },
    Rejected(SubAccountSpotTransferError),
}

impl SubAccountSpotTransferResult {
    #[inline]
    pub const fn compact_tag(&self) -> u8 {
        match self {
            Self::Applied { .. } => OUTER_OK_TAG,
            Self::Rejected(_) => OUTER_ERR_TAG,
        }
    }

    #[inline]
    pub const fn status(&self) -> u16 {
        match self {
            Self::Applied { .. } => STATUS_OK,
            Self::Rejected(err) => err.status(),
        }
    }
}

/// Reconstructs `sub_1E64420` plus its immediate helper chain.
///
/// Observed order:
/// 1. Reject immediately with `249` when spot transfers are globally disabled.
/// 2. Lookup signer and sub-account profiles through `sub_2755400`.
/// 3. Reject with `367` when either profile lands in a gated class and the
///    corresponding `AccountClassGate` bit is disabled.
/// 4. Resolve `(signer, sub_account_user, is_deposit)` through the sub-account
///    map, yielding `218`, `220`, or `222` on failure.
/// 5. Enforce `token.len() <= 100` and `amount.len() <= 100`, then resolve the
///    token symbol, parse the decimal amount into token wei, and debit/credit the
///    ledger in the direction selected by `is_deposit`.
pub fn apply_sub_account_spot_transfer<L: SpotTransferLedger>(
    state: &SubAccountSpotTransferState,
    ledger: &mut L,
    signer: Address,
    action: &SubAccountSpotTransferAction,
) -> SubAccountSpotTransferResult {
    if state.spot_disabled {
        return SubAccountSpotTransferResult::Rejected(SubAccountSpotTransferError::Ledger(
            LedgerError::SpotDisabled {
                token: action.token.clone(),
            },
        ));
    }

    if let Err(err) = state.validate_user_class(signer) {
        return SubAccountSpotTransferResult::Rejected(err);
    }
    if let Err(err) = state.validate_user_class(action.sub_account_user) {
        return SubAccountSpotTransferResult::Rejected(err);
    }

    let legs = match state
        .sub_accounts
        .resolve_transfer(signer, action.sub_account_user, action.is_deposit)
    {
        Ok(legs) => legs,
        Err(err) => {
            return SubAccountSpotTransferResult::Rejected(SubAccountSpotTransferError::SubAccount(err));
        }
    };

    if action.token.len() > MAX_LEDGER_STRING_LEN || action.amount.len() > MAX_LEDGER_STRING_LEN {
        return SubAccountSpotTransferResult::Rejected(SubAccountSpotTransferError::Ledger(
            LedgerError::NameTooLong,
        ));
    }

    if let Err(err) = ledger.apply_sub_account_spot_transfer(
        signer,
        action.sub_account_user,
        action.is_deposit,
        &action.token,
        &action.amount,
    ) {
        return SubAccountSpotTransferResult::Rejected(SubAccountSpotTransferError::Ledger(err));
    }

    SubAccountSpotTransferResult::Applied { legs }
}
