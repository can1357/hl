use std::collections::BTreeMap;

pub type Address = [u8; 20];
pub type RawUsd = u64;
pub type SignedNtl = i64;
pub type TimestampNanos = i64;

const CREATE_VAULT_MIN_INITIAL_USD: RawUsd = 10_000_000_000;
const CREATE_VAULT_RESERVE_USD: RawUsd = 10_000_000_000;
const VAULT_TRANSFER_MIN_DEPOSIT_USD: RawUsd = 5_000_000;
const VAULT_DISTRIBUTE_MIN_USD: RawUsd = 10_000_000;
const VAULT_TRANSFER_THROTTLE_NANOS: TimestampNanos = 300_000_000;
const RAW_USD_OVERFLOW_CUTOFF: RawUsd = 0x0ccc_cccc_cccc_cccc;
const ACCOUNT_NTL_CLAMP: u64 = 0x0147_ae14_7ae1_47ae;
const CREATE_EVENT_TAG: u64 = 0x8000_0000_0000_0003;
const DEPOSIT_EVENT_TAG: u64 = 0x8000_0000_0000_0004;
const WITHDRAW_EVENT_TAG: u64 = 0x8000_0000_0000_0005;
const DISTRIBUTE_EVENT_TAG: u64 = 0x8000_0000_0000_0006;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultDomain {
    Main,
    Alt,
}

#[derive(Clone, Debug, Default)]
pub struct ExchangeVaultState {
    pub domain: VaultDomain,
    pub network_kind: u8,
    pub last_vault_transfer_time: TimestampNanos,
    pub mark_px: f64,
    pub vaults: BTreeMap<Address, Vault>,
    pub account_totals: BTreeMap<Address, AccountTotals>,
    pub balances: BTreeMap<Address, RawUsd>,
    pub events: Vec<VaultEvent>,
}

impl Default for VaultDomain {
    fn default() -> Self {
        Self::Main
    }
}

impl ExchangeVaultState {
    /// Recovered create-vault transition.  The binary has two state-layout
    /// variants plus a lower-address monomorph; all follow this shape: check the
    /// creator reserve, reject duplicate names, return duplicate-address success
    /// with code `0`, insert a 0xb0-byte vault record, initialize clearinghouse
    /// accounting with a fixed reserve, and emit tag `0x8000_0000_0000_0003`.
    pub fn apply_create_vault(&mut self, action: CreateVaultAction) -> VaultResult {
        if !action.parent_conversion {
            let Some(required) = action.initial_usd.checked_add(CREATE_VAULT_RESERVE_USD) else {
                return VaultResult::err(VaultError::CreateInitialPlusReserveOverflow {
                    attempted: action.initial_usd.saturating_add(CREATE_VAULT_RESERVE_USD),
                });
            };

            if self.balance_of(&action.leader) < required {
                return VaultResult::err(VaultError::CreateInsufficientBalance);
            }
            if action.initial_usd < CREATE_VAULT_MIN_INITIAL_USD {
                return VaultResult::err(VaultError::InitialVaultDepositTooSmall);
            }
        }

        if self.vaults.values().any(|vault| vault.name == action.name) {
            return VaultResult::err(VaultError::VaultNameNotUnique);
        }

        if self.vaults.contains_key(&action.vault_address) {
            return VaultResult::ok_with_address(VaultStatus::DuplicateVaultAddress, action.vault_address);
        }

        if let Err(error) = validate_create_vault_fields(&action) {
            return VaultResult::err(error);
        }

        let mut vault = Vault::new(
            action.vault_address,
            action.leader,
            action.name,
            action.description,
            action.initial_usd,
        );
        vault.parent_conversion = action.parent_conversion;
        vault.allow_deposits = true;
        vault.always_close_on_withdraw = false;

        self.vaults.insert(action.vault_address, vault);

        if action.parent_conversion {
            self.link_parent_conversion(action.leader, action.vault_address);
        } else {
            if let Err(error) = self.debit_balance(action.leader, CREATE_VAULT_RESERVE_USD) {
                return VaultResult::err(error);
            }
            self.credit_balance(action.vault_address, CREATE_VAULT_RESERVE_USD);
            self.apply_scaled_ntl(action.leader, -(CREATE_VAULT_RESERVE_USD as i128));
        }

        if let Err(error) = self.apply_initial_deposit(action.leader, action.vault_address, action.initial_usd) {
            return VaultResult::err(error);
        }
        self.events.push(VaultEvent::Create {
            tag: CREATE_EVENT_TAG,
            leader: action.leader,
            vault: action.vault_address,
            initial_usd: action.initial_usd,
        });
        VaultResult::ok_with_address(VaultStatus::Applied, action.vault_address)
    }

    /// Recovered vault-transfer transition.  The decompiled variants reject a
    /// transfer too soon after the previous one (`31`), reject raw amount overflow
    /// (`319`), locate the user/vault relation in the vault BTree, reject closed
    /// vaults (`8`), then split into deposit and withdrawal helpers.
    pub fn apply_vault_transfer(
        &mut self,
        now: TimestampNanos,
        user: Address,
        action: VaultTransferAction,
    ) -> VaultResult {
        if self.last_vault_transfer_time.saturating_add(VAULT_TRANSFER_THROTTLE_NANOS) > now {
            return VaultResult::err(VaultError::VaultTransferThrottled);
        }
        self.last_vault_transfer_time = now;

        if action.usd >= RAW_USD_OVERFLOW_CUTOFF {
            return VaultResult::err(VaultError::AmountOverflow { amount: action.usd });
        }

        if !self.vaults.contains_key(&action.vault_address) {
            return VaultResult::err_with_address(VaultError::VaultNotRegistered, action.vault_address);
        }
        if matches!(self.vaults.get(&user).map(|vault| vault.kind), Some(VaultKind::Parent | VaultKind::Child))
            && !self.is_parent_or_child(user, action.vault_address)
        {
            return VaultResult::err_with_address(VaultError::InvalidVaultTransfer, user);
        }
        if self.vaults.get(&action.vault_address).is_some_and(|vault| vault.closed) {
            return VaultResult::err(VaultError::VaultClosed);
        }

        if action.is_deposit {
            self.deposit_into_vault(now, user, action.vault_address, action.usd)
        } else {
            self.withdraw_from_vault(now, user, action.vault_address, action.usd)
        }
    }

    /// Recovered distribution transition.  The wrapper rejects the same raw-USD
    /// overflow cutoff as transfers, validates that the signer is the vault
    /// leader, optionally enforces a minimum explicit distribution amount, then
    /// delegates to the vault module helper that prorates depositor ledger rows
    /// and emits one distribution event for each affected account.
    pub fn apply_vault_distribute(
        &mut self,
        leader: Address,
        action: VaultDistributeAction,
    ) -> VaultResult {
        if action.usd >= RAW_USD_OVERFLOW_CUTOFF {
            return VaultResult::err(VaultError::AmountOverflow { amount: action.usd });
        }
        if !self.vaults.contains_key(&action.vault_address) {
            return VaultResult::err_with_address(VaultError::VaultNotRegistered, action.vault_address);
        }
        let Some(vault) = self.vaults.get(&action.vault_address) else {
            return VaultResult::err_with_address(VaultError::VaultNotRegistered, action.vault_address);
        };
        if vault.closed {
            return VaultResult::err(VaultError::VaultClosed);
        }
        if vault.leader != leader {
            return VaultResult::err(VaultError::VaultActionLeaderOnly);
        }

        let requested = action.usd;
        let total_ntl = self.vault_total_ntl(action.vault_address);
        let amount = if requested != 0 {
            if requested < VAULT_DISTRIBUTE_MIN_USD {
                return VaultResult::err(VaultError::VaultMinimumDistribution);
            }
            if requested > total_ntl {
                return VaultResult::err(VaultError::VaultWithdrawInsufficientEquity);
            }
            requested
        } else {
            let on_chain_balance = self.balance_of(&action.vault_address);
            if total_ntl != on_chain_balance {
                return VaultResult::err(VaultError::VaultWithdrawZeroBalance);
            }
            total_ntl
        };

        if total_ntl == 0 || self.balance_of(&action.vault_address) < amount {
            return VaultResult::err(VaultError::InsufficientSpotBalance);
        }

        let changes = match self.compute_distribution_changes(action.vault_address, amount, total_ntl) {
            Ok(changes) => changes,
            Err(error) => return VaultResult::err(error),
        };
        if let Err(error) = self.debit_balance(action.vault_address, amount) {
            return VaultResult::err(error);
        }
        for change in changes {
            if change.user_ledger_change <= 0 {
                continue;
            }
            self.credit_balance(change.user, change.user_ledger_change as RawUsd);
            self.apply_scaled_ntl(change.user, change.user_ledger_change as i128);
            self.events.push(VaultEvent::Distribute {
                tag: DISTRIBUTE_EVENT_TAG,
                vault: action.vault_address,
                user: change.user,
                user_ledger_change: change.user_ledger_change,
            });
        }
        VaultResult::ok(VaultStatus::Applied)
    }

    /// Recovered action layout has exactly three fields: vault address,
    /// `allowDeposits`, and `alwaysCloseOnWithdraw`.  The state mutation is a
    /// leader-only write to the corresponding vault record flags.  The flag names
    /// are grounded in the local action serializer and in the transfer/withdrawal
    /// paths that read the vault-record booleans.
    pub fn apply_vault_modify(&mut self, leader: Address, action: VaultModifyAction) -> VaultResult {
        let vault = match self.vault_mut(action.vault_address) {
            Ok(vault) => vault,
            Err(error) => return VaultResult::err(error),
        };
        if vault.closed {
            return VaultResult::err(VaultError::VaultClosed);
        }
        if vault.leader != leader {
            return VaultResult::err(VaultError::VaultActionLeaderOnly);
        }
        vault.allow_deposits = action.allow_deposits;
        vault.always_close_on_withdraw = action.always_close_on_withdraw;
        self.events.push(VaultEvent::Modify {
            vault: action.vault_address,
            allow_deposits: action.allow_deposits,
            always_close_on_withdraw: action.always_close_on_withdraw,
        });
        VaultResult::ok(VaultStatus::Applied)
    }

    fn deposit_into_vault(
        &mut self,
        now: TimestampNanos,
        user: Address,
        vault_address: Address,
        usd: RawUsd,
    ) -> VaultResult {
        if usd < VAULT_TRANSFER_MIN_DEPOSIT_USD {
            return VaultResult::err(VaultError::DepositTooSmall);
        }
        if !self.vaults.get(&vault_address).is_some_and(|vault| vault.allow_deposits) {
            return VaultResult::err(VaultError::VaultDisallowsDeposits);
        }
        if self.balance_of(&user) < usd {
            return VaultResult::err(VaultError::InsufficientSpotBalance);
        }

        if let Err(error) = self.debit_balance(user, usd) {
            return VaultResult::err(error);
        }
        self.credit_balance(vault_address, usd);
        self.apply_scaled_ntl(user, -(usd as i128));
        self.apply_scaled_ntl(vault_address, usd as i128);

        let vault = match self.vault_mut(vault_address) {
            Ok(vault) => vault,
            Err(error) => return VaultResult::err(error),
        };
        let depositor = vault.depositor_mut(user);
        depositor.principal = depositor.principal.saturating_add(usd as SignedNtl);
        depositor.last_deposit_time = now;
        vault.equity = vault.equity.saturating_add(usd as SignedNtl);

        self.events.push(VaultEvent::Transfer {
            tag: DEPOSIT_EVENT_TAG,
            user,
            vault: vault_address,
            is_deposit: true,
            usd,
        });
        VaultResult::ok(VaultStatus::Applied)
    }

    fn withdraw_from_vault(
        &mut self,
        now: TimestampNanos,
        user: Address,
        vault_address: Address,
        requested_usd: RawUsd,
    ) -> VaultResult {
        let (equity, lockup_until, always_close_on_withdraw, leader, leader_commission_bps) = {
            let vault = match self.vault(vault_address) {
                Ok(vault) => vault,
                Err(error) => return VaultResult::err(error),
            };
            let Some(depositor) = vault.depositors.get(&user) else {
                return VaultResult::err(VaultError::VaultWithdrawZeroBalance);
            };
            (
                vault.equity,
                depositor.lockup_until,
                vault.always_close_on_withdraw,
                vault.leader,
                vault.leader_commission_bps,
            )
        };

        if now < lockup_until {
            return VaultResult::err(VaultError::VaultWithdrawLockup);
        }
        if equity <= 0 {
            return VaultResult::err(VaultError::VaultWithdrawInsufficientEquity);
        }

        let user_equity = self.user_vault_equity(vault_address, user);
        if user_equity <= 0 {
            return VaultResult::err(VaultError::VaultWithdrawZeroBalance);
        }
        let amount = if requested_usd == 0 || always_close_on_withdraw {
            user_equity as RawUsd
        } else {
            requested_usd.min(user_equity as RawUsd)
        };
        if amount == 0 || (amount as SignedNtl) > equity {
            return VaultResult::err(VaultError::VaultWithdrawInsufficientEquity);
        }
        if self.balance_of(&vault_address) < amount {
            return VaultResult::err(VaultError::VaultWithdrawTooMuchValueInChildVaults);
        }

        if let Err(error) = self.debit_balance(vault_address, amount) {
            return VaultResult::err(error);
        }
        self.credit_balance(user, amount);
        self.apply_scaled_ntl(vault_address, -(amount as i128));
        self.apply_scaled_ntl(user, amount as i128);

        let vault = match self.vault_mut(vault_address) {
            Ok(vault) => vault,
            Err(error) => return VaultResult::err(error),
        };
        vault.equity = vault.equity.saturating_sub(amount as SignedNtl);
        if let Some(depositor) = vault.depositors.get_mut(&user) {
            let principal_debit = (amount as SignedNtl).min(depositor.principal.max(0));
            depositor.principal = depositor.principal.saturating_sub(principal_debit);
            depositor.withdrawn = depositor.withdrawn.saturating_add(amount as SignedNtl);
            if depositor.principal <= 0 || always_close_on_withdraw {
                depositor.closed = true;
            }
        }
        let leader_commission = if leader != user {
            leader_commission_bps.apply(amount)
        } else {
            0
        };
        if leader_commission != 0 && self.balance_of(&user) >= leader_commission {
            if let Err(error) = self.debit_balance(user, leader_commission) {
                return VaultResult::err(error);
            }
            self.credit_balance(leader, leader_commission);
        }

        self.events.push(VaultEvent::Transfer {
            tag: WITHDRAW_EVENT_TAG,
            user,
            vault: vault_address,
            is_deposit: false,
            usd: amount,
        });
        if leader_commission != 0 {
            self.events.push(VaultEvent::LeaderCommission {
                vault: vault_address,
                leader,
                user,
                usd: leader_commission,
            });
        }
        VaultResult::ok(VaultStatus::Applied)
    }

    fn apply_initial_deposit(&mut self, leader: Address, vault_address: Address, usd: RawUsd) -> Result<(), VaultError> {
        if usd == 0 {
            return Ok(());
        }
        if self.balance_of(&leader) < usd {
            return Err(VaultError::InsufficientSpotBalance);
        }
        self.debit_balance(leader, usd)?;
        self.credit_balance(vault_address, usd);
        self.apply_scaled_ntl(leader, -(usd as i128));
        self.apply_scaled_ntl(vault_address, usd as i128);
        let vault = self.vault_mut(vault_address)?;
        vault.equity = vault.equity.saturating_add(usd as SignedNtl);
        let depositor = vault.depositor_mut(leader);
        depositor.principal = depositor.principal.saturating_add(usd as SignedNtl);
        Ok(())
    }

    fn compute_distribution_changes(
        &mut self,
        vault_address: Address,
        amount: RawUsd,
        total_ntl: RawUsd,
    ) -> Result<Vec<DistributionChange>, VaultError> {
        let vault = self.vault_mut(vault_address)?;
        let mut changes = Vec::new();
        let mut distributed = 0_u64;
        for (&user, depositor) in vault.depositors.iter_mut() {
            if depositor.closed || depositor.principal <= 0 {
                continue;
            }
            let share = prorata(amount, depositor.principal as RawUsd, total_ntl);
            if share == 0 {
                continue;
            }
            let commission = vault.leader_commission_bps.apply(share);
            let user_change = share.saturating_sub(commission);
            depositor.principal = depositor.principal.saturating_sub(user_change as SignedNtl);
            depositor.withdrawn = depositor.withdrawn.saturating_add(user_change as SignedNtl);
            distributed = distributed.saturating_add(share);
            changes.push(DistributionChange {
                user,
                user_ledger_change: user_change as SignedNtl,
                leader_commission: commission as SignedNtl,
            });
        }
        vault.equity = vault.equity.saturating_sub(distributed as SignedNtl);
        if vault.equity == 0 {
            vault.closed = true;
        }
        Ok(changes)
    }

    fn link_parent_conversion(&mut self, parent: Address, child: Address) {
        if let Some(parent_vault) = self.vaults.get_mut(&parent) {
            parent_vault.kind = VaultKind::Parent;
            parent_vault.child_vaults.push(child);
        }
        if let Some(child_vault) = self.vaults.get_mut(&child) {
            child_vault.kind = VaultKind::Child;
            child_vault.parent = Some(parent);
        }
    }

    fn is_parent_or_child(&self, first: Address, second: Address) -> bool {
        self.vaults
            .get(&first)
            .is_some_and(|vault| vault.parent == Some(second) || vault.child_vaults.contains(&second))
            || self
                .vaults
                .get(&second)
                .is_some_and(|vault| vault.parent == Some(first) || vault.child_vaults.contains(&first))
    }

    fn vault(&self, address: Address) -> Result<&Vault, VaultError> {
        self.vaults.get(&address).ok_or(VaultError::VaultNotRegistered)
    }

    fn vault_mut(&mut self, address: Address) -> Result<&mut Vault, VaultError> {
        self.vaults.get_mut(&address).ok_or(VaultError::VaultNotRegistered)
    }

    fn balance_of(&self, address: &Address) -> RawUsd {
        self.balances.get(address).copied().unwrap_or(0)
    }

    fn credit_balance(&mut self, address: Address, amount: RawUsd) {
        let balance = self.balances.entry(address).or_default();
        *balance = balance.saturating_add(amount);
    }

    fn debit_balance(&mut self, address: Address, amount: RawUsd) -> Result<(), VaultError> {
        let balance = self.balances.entry(address).or_default();
        if *balance < amount {
            return Err(VaultError::InsufficientSpotBalance);
        }
        *balance -= amount;
        Ok(())
    }

    fn apply_scaled_ntl(&mut self, address: Address, raw_delta: i128) {
        let scaled = clamp_scaled_ntl(raw_delta, self.mark_px);
        let account = self.account_totals.entry(address).or_default();
        account.total_ntl = saturating_add_i64(account.total_ntl, scaled);
        account.usdc_ntl = saturating_add_i64(account.usdc_ntl, scaled);
    }

    fn vault_total_ntl(&self, vault_address: Address) -> RawUsd {
        let Some(vault) = self.vaults.get(&vault_address) else {
            return 0;
        };
        let own = vault.equity.max(0) as RawUsd;
        vault.child_vaults.iter().fold(own, |acc, child| {
            acc.saturating_add(self.vaults.get(child).map_or(0, |child_vault| child_vault.equity.max(0) as RawUsd))
        })
    }

    fn user_vault_equity(&self, vault_address: Address, user: Address) -> SignedNtl {
        self.vaults
            .get(&vault_address)
            .and_then(|vault| vault.depositors.get(&user))
            .map_or(0, |depositor| depositor.principal.saturating_sub(depositor.withdrawn))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateVaultAction {
    pub leader: Address,
    pub vault_address: Address,
    pub name: String,
    pub description: String,
    pub initial_usd: RawUsd,
    pub parent_conversion: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultTransferAction {
    pub usd: RawUsd,
    pub vault_address: Address,
    pub is_deposit: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultDistributeAction {
    pub usd: RawUsd,
    pub vault_address: Address,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultModifyAction {
    pub vault_address: Address,
    pub allow_deposits: bool,
    pub always_close_on_withdraw: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Vault {
    pub address: Address,
    pub leader: Address,
    pub kind: VaultKind,
    pub name: String,
    pub description: String,
    pub allow_deposits: bool,
    pub always_close_on_withdraw: bool,
    pub parent_conversion: bool,
    pub closed: bool,
    pub equity: SignedNtl,
    pub leader_commission_bps: Bps,
    pub parent: Option<Address>,
    pub child_vaults: Vec<Address>,
    pub depositors: BTreeMap<Address, VaultDepositor>,
}

impl Vault {
    fn new(address: Address, leader: Address, name: String, description: String, _initial_usd: RawUsd) -> Self {
        let depositors = BTreeMap::new();
        Self {
            address,
            leader,
            kind: VaultKind::Normal,
            name,
            description,
            allow_deposits: true,
            always_close_on_withdraw: false,
            parent_conversion: false,
            closed: false,
            equity: 0,
            leader_commission_bps: Bps(0),
            parent: None,
            child_vaults: Vec::new(),
            depositors,
        }
    }

    fn depositor_mut(&mut self, address: Address) -> &mut VaultDepositor {
        self.depositors.entry(address).or_default()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VaultDepositor {
    pub principal: SignedNtl,
    pub withdrawn: SignedNtl,
    pub lockup_until: TimestampNanos,
    pub last_deposit_time: TimestampNanos,
    pub closed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultKind {
    Normal,
    Parent,
    Child,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AccountTotals {
    pub total_ntl: SignedNtl,
    pub usdc_ntl: SignedNtl,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Bps(pub u32);

impl Bps {
    fn apply(self, amount: RawUsd) -> RawUsd {
        ((amount as u128 * self.0 as u128) / 10_000) as RawUsd
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum VaultEvent {
    Create {
        tag: u64,
        leader: Address,
        vault: Address,
        initial_usd: RawUsd,
    },
    Transfer {
        tag: u64,
        user: Address,
        vault: Address,
        is_deposit: bool,
        usd: RawUsd,
    },
    Distribute {
        tag: u64,
        vault: Address,
        user: Address,
        user_ledger_change: SignedNtl,
    },
    LeaderCommission {
        vault: Address,
        leader: Address,
        user: Address,
        usd: RawUsd,
    },
    Modify {
        vault: Address,
        allow_deposits: bool,
        always_close_on_withdraw: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DistributionChange {
    pub user: Address,
    pub user_ledger_change: SignedNtl,
    pub leader_commission: SignedNtl,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultResult {
    pub status: VaultStatus,
    pub error: Option<VaultError>,
    pub address: Option<Address>,
}

impl VaultResult {
    fn ok(status: VaultStatus) -> Self {
        Self { status, error: None, address: None }
    }

    fn ok_with_address(status: VaultStatus, address: Address) -> Self {
        Self { status, error: None, address: Some(address) }
    }

    fn err(error: VaultError) -> Self {
        Self { status: VaultStatus::Rejected, error: Some(error), address: None }
    }

    fn err_with_address(error: VaultError, address: Address) -> Self {
        Self { status: VaultStatus::Rejected, error: Some(error), address: Some(address) }
    }
}

impl From<Result<(), VaultError>> for VaultResult {
    fn from(result: Result<(), VaultError>) -> Self {
        match result {
            Ok(()) => Self::ok(VaultStatus::Applied),
            Err(error) => Self::err(error),
        }
    }
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultStatus {
    Applied,
    DuplicateVaultAddress,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VaultError {
    CreateInitialPlusReserveOverflow { attempted: RawUsd },
    CreateInsufficientBalance,
    InitialVaultDepositTooSmall,
    VaultNameTooShort,
    VaultNameTooLong,
    VaultDescriptionTooShort,
    VaultDescriptionTooLong,
    VaultNameNotUnique,
    VaultNotRegistered,
    VaultClosed,
    VaultTransferThrottled,
    AmountOverflow { amount: RawUsd },
    DepositTooSmall,
    VaultDisallowsDeposits,
    InvalidVaultTransfer,
    VaultWithdrawZeroBalance,
    VaultWithdrawLockup,
    VaultWithdrawTooMuchValueInChildVaults,
    VaultWithdrawInsufficientEquity,
    VaultActionLeaderOnly,
    VaultMinimumDistribution,
    InsufficientSpotBalance,
}

impl VaultError {
    pub fn recovered_code(&self) -> u16 {
        match self {
            Self::CreateInitialPlusReserveOverflow { .. } => 190,
            Self::CreateInsufficientBalance => 325,
            Self::InitialVaultDepositTooSmall => 326,
            Self::VaultNameNotUnique => 26,
            Self::VaultNotRegistered => 7,
            Self::VaultClosed => 8,
            Self::VaultTransferThrottled => 31,
            Self::AmountOverflow { .. } => 319,
            Self::DepositTooSmall => 41,
            Self::InvalidVaultTransfer => 25,
            Self::VaultWithdrawZeroBalance => 18,
            Self::VaultWithdrawLockup => 11,
            Self::VaultWithdrawTooMuchValueInChildVaults => 13,
            Self::VaultWithdrawInsufficientEquity => 14,
            Self::VaultActionLeaderOnly => 17,
            Self::VaultMinimumDistribution => 19,
            Self::InsufficientSpotBalance => 51,
            Self::VaultNameTooShort
            | Self::VaultNameTooLong
            | Self::VaultDescriptionTooShort
            | Self::VaultDescriptionTooLong
            | Self::VaultDisallowsDeposits => 0,
        }
    }
}

fn validate_create_vault_fields(action: &CreateVaultAction) -> Result<(), VaultError> {
    if action.name.len() < 3 {
        return Err(VaultError::VaultNameTooShort);
    }
    if action.name.len() > 50 {
        return Err(VaultError::VaultNameTooLong);
    }
    if action.description.len() < 10 {
        return Err(VaultError::VaultDescriptionTooShort);
    }
    if action.description.len() > 250 {
        return Err(VaultError::VaultDescriptionTooLong);
    }
    Ok(())
}

fn prorata(amount: RawUsd, numerator: RawUsd, denominator: RawUsd) -> RawUsd {
    if denominator == 0 {
        return 0;
    }
    ((amount as u128 * numerator as u128) / denominator as u128) as RawUsd
}

fn clamp_scaled_ntl(raw_delta: i128, mark_px: f64) -> SignedNtl {
    let raw = raw_delta as f64 * mark_px;
    let clamped = if raw.is_finite() {
        raw.clamp(i64::MIN as f64, i64::MAX as f64)
    } else {
        0.0
    };
    let scaled = (clamped as i128 / 10_000).clamp(-(ACCOUNT_NTL_CLAMP as i128), ACCOUNT_NTL_CLAMP as i128);
    scaled as SignedNtl
}

fn saturating_add_i64(lhs: SignedNtl, rhs: SignedNtl) -> SignedNtl {
    lhs.checked_add(rhs).unwrap_or_else(|| if rhs.is_negative() { SignedNtl::MIN } else { SignedNtl::MAX })
}
