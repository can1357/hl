//! Recovered vault transfer action payload.
//!
//! Binary evidence used here:
//! - derived serializers use the Rust type name `VaultTransferAction` and a
//!   three-field struct shape;
//! - field order is `vaultAddress`, `isDeposit`, `usd` in the human-readable
//!   serializer, while the in-memory layout loads `usd` from offset `+0x00`,
//!   `vaultAddress` from `+0x08`, and `isDeposit` from `+0x1c`;
//! - the compact/msgpack serializer emits the boolean as marker `0xc2 | bit`,
//!   so `false` is withdraw and `true` is deposit.

#![allow(dead_code)]

pub const VAULT_TRANSFER_ACTION_TYPE: &str = "VaultTransferAction";
pub const VAULT_TRANSFER_WIRE_TYPE: &str = "VaultTransfer";
pub const VAULT_TRANSFER_FIELD_COUNT: usize = 3;

pub const FIELD_VAULT_ADDRESS: &str = "vaultAddress";
pub const FIELD_IS_DEPOSIT: &str = "isDeposit";
pub const FIELD_USD: &str = "usd";

pub const MSGPACK_FALSE: u8 = 0xc2;
pub const MSGPACK_TRUE: u8 = 0xc3;

/// USD notional amount stored in raw 1e6 units.
///
/// The action carries this as one 64-bit word at struct offset `+0x00`; both
/// human-readable and compact serializers delegate to the qty/notional serde
/// helper for this newtype.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UsdNtl(pub u64);

impl UsdNtl {
    pub const SCALE: u64 = 1_000_000;
    pub const ZERO: Self = Self(0);

    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub const fn whole_usd(self) -> u64 {
        self.0 / Self::SCALE
    }

    #[inline]
    pub const fn fractional_micros(self) -> u32 {
        (self.0 % Self::SCALE) as u32
    }

    /// Parse a decimal USD byte string into the raw 1e6-unit integer without
    /// allocating. More than six fractional digits is rejected because it would
    /// not round-trip through the recovered raw representation.
    pub fn parse_decimal_bytes(bytes: &[u8]) -> Result<Self, AmountParseError> {
        if bytes.is_empty() {
            return Err(AmountParseError::Empty);
        }

        let mut integer = 0_u64;
        let mut fraction = 0_u64;
        let mut fraction_digits = 0_u8;
        let mut seen_dot = false;
        let mut seen_digit = false;

        for &byte in bytes {
            match byte {
                b'0'..=b'9' => {
                    let digit = u64::from(byte - b'0');
                    seen_digit = true;
                    if seen_dot {
                        if fraction_digits == 6 {
                            return Err(AmountParseError::TooManyFractionalDigits);
                        }
                        fraction = fraction
                            .checked_mul(10)
                            .and_then(|v| v.checked_add(digit))
                            .ok_or(AmountParseError::Overflow)?;
                        fraction_digits += 1;
                    } else {
                        integer = integer
                            .checked_mul(10)
                            .and_then(|v| v.checked_add(digit))
                            .ok_or(AmountParseError::Overflow)?;
                    }
                }
                b'.' if !seen_dot => seen_dot = true,
                _ => return Err(AmountParseError::InvalidByte(byte)),
            }
        }
        if !seen_digit {
            return Err(AmountParseError::Empty);
        }

        while fraction_digits < 6 {
            fraction *= 10;
            fraction_digits += 1;
        }

        integer
            .checked_mul(Self::SCALE)
            .and_then(|v| v.checked_add(fraction))
            .map(Self)
            .ok_or(AmountParseError::Overflow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmountParseError {
    Empty,
    InvalidByte(u8),
    TooManyFractionalDigits,
    Overflow,
}

pub type Address = [u8; 20];

pub const ZERO_ADDRESS: Address = [0; 20];

/// Exact recovered wire/memory shape of the signed action payload.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultTransferAction {
    /// Field key `usd`; raw notional at offset `+0x00`.
    pub usd: UsdNtl,
    /// Field key `vaultAddress`; 20-byte address at offset `+0x08`.
    pub vault_address: Address,
    /// Field key `isDeposit`; bool at offset `+0x1c`.
    pub is_deposit: bool,
}

impl VaultTransferAction {
    pub const STRUCT_SIZE: usize = 0x20;
    pub const USD_OFFSET: usize = 0x00;
    pub const VAULT_ADDRESS_OFFSET: usize = 0x08;
    pub const IS_DEPOSIT_OFFSET: usize = 0x1c;

    #[inline]
    pub const fn new(usd: UsdNtl, vault_address: Address, is_deposit: bool) -> Self {
        Self {
            usd,
            vault_address,
            is_deposit,
        }
    }

    #[inline]
    pub const fn direction(self) -> VaultTransferDirection {
        if self.is_deposit {
            VaultTransferDirection::Deposit
        } else {
            VaultTransferDirection::Withdraw
        }
    }

    #[inline]
    pub const fn msgpack_is_deposit_marker(self) -> u8 {
        MSGPACK_FALSE | self.is_deposit as u8
    }

    /// User balance delta in raw USD units: deposits debit the signer, withdraws
    /// credit the signer.
    #[inline]
    pub const fn user_delta_raw(self) -> i128 {
        let amount = self.usd.raw() as i128;
        if self.is_deposit { -amount } else { amount }
    }

    /// Vault equity delta in raw USD units: deposits credit the vault, withdraws
    /// debit the vault.
    #[inline]
    pub const fn vault_delta_raw(self) -> i128 {
        -self.user_delta_raw()
    }

    #[inline]
    pub const fn is_zero_amount(self) -> bool {
        self.usd.is_zero()
    }

    #[inline]
    pub const fn has_zero_vault_address(self) -> bool {
        let mut i = 0;
        while i < self.vault_address.len() {
            if self.vault_address[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Stateless validation recovered from action-level checks and error strings.
    #[inline]
    pub const fn validate_basic(self) -> Result<(), VaultTransferValidationError> {
        if self.usd.is_zero() {
            return match self.direction() {
                VaultTransferDirection::Deposit => Err(VaultTransferValidationError::DepositZero),
                VaultTransferDirection::Withdraw => Err(VaultTransferValidationError::WithdrawZero),
            };
        }
        if self.has_zero_vault_address() {
            return Err(VaultTransferValidationError::InvalidVaultTransfer);
        }
        Ok(())
    }

    /// Apply the state-dependent gates visible in the vault-transfer validation
    /// monomorphs: deposits require an accepting vault, withdraws require
    /// withdraw allowance and remaining limit, and both directions require the
    /// address to resolve to a vault rather than a normal user.
    pub fn validate_with_vault(
        self,
        vault: VaultTransferVaultView,
    ) -> Result<(), VaultTransferValidationError> {
        self.validate_basic()?;

        if matches!(vault.kind, VaultAddressKind::User) {
            return Err(VaultTransferValidationError::VaultAddressIsAlreadyUser);
        }
        if !vault.kind.is_vault() {
            return Err(VaultTransferValidationError::InvalidVaultTransfer);
        }

        match self.direction() {
            VaultTransferDirection::Deposit => {
                if !vault.allow_deposits {
                    return Err(VaultTransferValidationError::VaultTransferNotAllowed);
                }
            }
            VaultTransferDirection::Withdraw => {
                if !vault.allow_withdrawals {
                    return Err(VaultTransferValidationError::VaultTransferNotAllowed);
                }
                if let Some(remaining) = vault.remaining_withdraw_raw {
                    if self.usd.raw() > remaining {
                        return Err(VaultTransferValidationError::VaultWithdrawOverDailyLimit);
                    }
                }
            }
        }

        if vault.would_be_liquidatable_after_transfer {
            return match self.direction() {
                VaultTransferDirection::Deposit => {
                    Err(VaultTransferValidationError::VaultDepositLiquidatable)
                }
                VaultTransferDirection::Withdraw => {
                    Err(VaultTransferValidationError::VaultWithdrawLiquidatable)
                }
            };
        }

        Ok(())
    }
}

const _: [(); VaultTransferAction::STRUCT_SIZE] = [(); core::mem::size_of::<VaultTransferAction>()];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultTransferDirection {
    Deposit,
    Withdraw,
}

impl VaultTransferDirection {
    #[inline]
    pub const fn is_deposit(self) -> bool {
        matches!(self, Self::Deposit)
    }

    #[inline]
    pub const fn from_is_deposit(is_deposit: bool) -> Self {
        if is_deposit { Self::Deposit } else { Self::Withdraw }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultTransferField {
    VaultAddress,
    IsDeposit,
    Usd,
}

impl VaultTransferField {
    pub const FIELD_NAMES: [&'static str; VAULT_TRANSFER_FIELD_COUNT] = [
        FIELD_VAULT_ADDRESS,
        FIELD_IS_DEPOSIT,
        FIELD_USD,
    ];

    #[inline]
    pub const fn from_index(index: u64) -> Option<Self> {
        match index {
            0 => Some(Self::VaultAddress),
            1 => Some(Self::IsDeposit),
            2 => Some(Self::Usd),
            _ => None,
        }
    }

    #[inline]
    pub const fn as_index(self) -> u8 {
        match self {
            Self::VaultAddress => 0,
            Self::IsDeposit => 1,
            Self::Usd => 2,
        }
    }

    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VaultAddress => FIELD_VAULT_ADDRESS,
            Self::IsDeposit => FIELD_IS_DEPOSIT,
            Self::Usd => FIELD_USD,
        }
    }

    #[inline]
    pub fn from_name(name: &[u8]) -> Option<Self> {
        match name {
            b"vaultAddress" => Some(Self::VaultAddress),
            b"isDeposit" => Some(Self::IsDeposit),
            b"usd" => Some(Self::Usd),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultAddressKind {
    Missing,
    User,
    Vault,
    ChildVault,
    ParentVault,
}

impl VaultAddressKind {
    #[inline]
    pub const fn is_vault(self) -> bool {
        matches!(self, Self::Vault | Self::ChildVault | Self::ParentVault)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultTransferVaultView {
    pub kind: VaultAddressKind,
    pub allow_deposits: bool,
    pub allow_withdrawals: bool,
    pub remaining_withdraw_raw: Option<u64>,
    pub would_be_liquidatable_after_transfer: bool,
}

impl VaultTransferVaultView {
    #[inline]
    pub const fn normal_vault() -> Self {
        Self {
            kind: VaultAddressKind::Vault,
            allow_deposits: true,
            allow_withdrawals: true,
            remaining_withdraw_raw: None,
            would_be_liquidatable_after_transfer: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultTransferValidationError {
    DepositZero,
    WithdrawZero,
    InvalidVaultTransfer,
    VaultAddressIsAlreadyUser,
    VaultTransferNotAllowed,
    VaultWithdrawOverDailyLimit,
    VaultDepositLiquidatable,
    VaultWithdrawLiquidatable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultTransferEffect {
    pub direction: VaultTransferDirection,
    pub user_delta_raw: i128,
    pub vault_delta_raw: i128,
}

impl From<VaultTransferAction> for VaultTransferEffect {
    #[inline]
    fn from(action: VaultTransferAction) -> Self {
        Self {
            direction: action.direction(),
            user_delta_raw: action.user_delta_raw(),
            vault_delta_raw: action.vault_delta_raw(),
        }
    }
}
