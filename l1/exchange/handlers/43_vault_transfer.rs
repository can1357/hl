use std::collections::BTreeMap;

pub type Address = [u8; 20];
pub type RawUsd = u64;
pub type SignedNtl = i64;
pub type TimestampNanos = i64;
pub type SettlementAsset = u64;
pub type RequiredKey = u64;

const OK: u16 = 390;
const ERR_REQUIRED_SET_MISS: u16 = 368;
const VAULT_TRANSFER_THROTTLE_NANOS: TimestampNanos = 300_000_000;
const VAULT_TRANSFER_MIN_DEPOSIT_USD: RawUsd = 5_000_000;
const RAW_USD_OVERFLOW_CUTOFF: RawUsd = 0x0ccc_cccc_cccc_cccc;
const DEPOSIT_EVENT_TAG: u64 = 0x8000_0000_0000_0004;
const WITHDRAW_EVENT_TAG: u64 = 0x8000_0000_0000_0005;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultTransferAction {
    pub usd: RawUsd,
    pub vault_address: Address,
    pub is_deposit: bool,
}

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
    pub const fn status_byte(self) -> u8 {
        match self {
            Self::SpotOnly => 0,
            Self::Legacy => 1,
            Self::AbstractionOptIn => 2,
            Self::DexUser => 3,
            Self::PrivilegedDexUser => 4,
            Self::Other(value) => value,
        }
    }

    pub const fn is_privileged(self) -> bool {
        self.status_byte() >= 4
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultTransferRouting {
    pub inner_action_count: u32,
    pub dex_arg_is_resolved: bool,
    pub dex_abstraction_enabled: bool,
    pub disable_low_class_direct_path: bool,
    pub disable_privileged_direct_path: bool,
    pub required_key: RequiredKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionResult {
    pub code: u16,
    pub address: Option<Address>,
}

impl ActionResult {
    pub const fn ok() -> Self {
        Self { code: OK, address: None }
    }

    pub const fn code(code: u16) -> Self {
        Self { code, address: None }
    }

    pub const fn code_with_address(code: u16, address: Address) -> Self {
        Self {
            code,
            address: Some(address),
        }
    }

    pub const fn is_ok(&self) -> bool {
        self.code == OK
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandlerOutput {
    Applied,
    Rejected(ActionResult),
}

impl HandlerOutput {
    fn from_action_result(result: ActionResult) -> Self {
        if result.is_ok() {
            Self::Applied
        } else {
            Self::Rejected(result)
        }
    }
}

pub trait VaultTransferBackend {
    fn user_class(&self, user: Address) -> UserClass;
    fn settlement_asset(&self, key: RequiredKey) -> Result<SettlementAsset, ActionResult>;
    fn recheck_user_settlement(
        &mut self,
        user: Address,
        settlement_asset: SettlementAsset,
        enter_spot: bool,
        dex_or_settlement: RequiredKey,
        settle_to_spot: bool,
    ) -> ActionResult;
    fn pre_mutation(
        &mut self,
        user: Address,
        settlement_asset: SettlementAsset,
        enter_spot: bool,
        dex_or_settlement: RequiredKey,
        privileged: bool,
    );
    fn finalize_privileged(
        &mut self,
        user: Address,
        settlement_asset: SettlementAsset,
        enter_spot: bool,
        dex_or_settlement: RequiredKey,
    );
    fn consume_required_key(&mut self, user: Address, key: RequiredKey) -> bool;
    fn propagate_soft_failure(&mut self, result: &ActionResult);
    fn propagate_hard_failure(&mut self, result: &ActionResult);
}

pub fn execute_vault_transfer<B: VaultTransferBackend>(
    backend: &mut B,
    state: &mut ExchangeVaultState,
    now: TimestampNanos,
    user: Address,
    action: VaultTransferAction,
    routing: VaultTransferRouting,
) -> HandlerOutput {
    let class = backend.user_class(user);
    let status = class.status_byte();
    let direct = status < 2
        || (status < 4 && routing.disable_low_class_direct_path)
        || (status >= 4 && routing.disable_privileged_direct_path)
        || (status == 2
            && (routing.inner_action_count < 2
                || routing.dex_arg_is_resolved
                || !routing.dex_abstraction_enabled
                || routing.required_key == 0));

    if direct {
        return HandlerOutput::from_action_result(apply_direct(state, now, user, action));
    }

    if status == 2 {
        let settlement_asset = match backend.settlement_asset(routing.required_key) {
            Ok(asset) => asset,
            Err(err) => return HandlerOutput::Rejected(err),
        };
        let pre = backend.recheck_user_settlement(user, settlement_asset, true, 0, true);
        if !pre.is_ok() {
            backend.propagate_soft_failure(&pre);
            return HandlerOutput::Rejected(pre);
        }

        let result = apply_direct(state, now, user, action);
        if routing.dex_abstraction_enabled {
            let post = backend.recheck_user_settlement(
                user,
                settlement_asset,
                true,
                routing.required_key,
                settlement_asset == 0,
            );
            if !post.is_ok() {
                backend.propagate_soft_failure(&post);
                return HandlerOutput::Rejected(post);
            }
        }
        return HandlerOutput::from_action_result(result);
    }

    if !backend.consume_required_key(user, routing.required_key) {
        return HandlerOutput::Rejected(ActionResult::code(ERR_REQUIRED_SET_MISS));
    }

    let settlement_asset = match backend.settlement_asset(routing.required_key) {
        Ok(asset) => asset,
        Err(err) => return HandlerOutput::Rejected(err),
    };
    backend.pre_mutation(
        user,
        settlement_asset,
        true,
        routing.required_key,
        class.is_privileged(),
    );

    let result = apply_direct(state, now, user, action);
    if class.is_privileged() {
        backend.finalize_privileged(user, settlement_asset, true, routing.required_key);
        return HandlerOutput::from_action_result(result);
    }

    let post = backend.recheck_user_settlement(
        user,
        settlement_asset,
        true,
        routing.required_key,
        false,
    );
    if !post.is_ok() {
        backend.propagate_hard_failure(&post);
        return HandlerOutput::Rejected(post);
    }

    HandlerOutput::from_action_result(result)
}

fn apply_direct(
    state: &mut ExchangeVaultState,
    now: TimestampNanos,
    user: Address,
    action: VaultTransferAction,
) -> ActionResult {
    let result = state.apply_vault_transfer(now, user, action);
    match result.error {
        None => ActionResult::ok(),
        Some(error) => {
            if let Some(address) = result.address {
                ActionResult::code_with_address(error.recovered_code(), address)
            } else {
                ActionResult::code(error.recovered_code())
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ExchangeVaultState {
    pub last_vault_transfer_time: TimestampNanos,
    pub mark_px: f64,
    pub balances: BTreeMap<Address, RawUsd>,
    pub account_totals: BTreeMap<Address, AccountTotals>,
    pub vaults: BTreeMap<Address, Vault>,
    pub events: Vec<VaultEvent>,
}

impl ExchangeVaultState {
    pub fn apply_vault_transfer(
        &mut self,
        now: TimestampNanos,
        user: Address,
        action: VaultTransferAction,
    ) -> VaultResult {
        if self
            .last_vault_transfer_time
            .saturating_add(VAULT_TRANSFER_THROTTLE_NANOS)
            > now
        {
            return VaultResult::err(VaultError::VaultTransferThrottled);
        }
        self.last_vault_transfer_time = now;

        if action.usd >= RAW_USD_OVERFLOW_CUTOFF {
            return VaultResult::err(VaultError::AmountOverflow { amount: action.usd });
        }
        if !self.vaults.contains_key(&action.vault_address) {
            return VaultResult::err_with_address(
                VaultError::VaultNotRegistered,
                action.vault_address,
            );
        }
        if matches!(self.vaults.get(&user).map(|vault| vault.kind), Some(VaultKind::Parent | VaultKind::Child))
            && !self.is_parent_or_child(user, action.vault_address)
        {
            return VaultResult::err_with_address(VaultError::InvalidVaultTransfer, user);
        }
        if self
            .vaults
            .get(&action.vault_address)
            .is_some_and(|vault| vault.closed)
        {
            return VaultResult::err(VaultError::VaultClosed);
        }

        if action.is_deposit {
            self.deposit_into_vault(now, user, action.vault_address, action.usd)
        } else {
            self.withdraw_from_vault(now, user, action.vault_address, action.usd)
        }
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
        if !self
            .vaults
            .get(&vault_address)
            .is_some_and(|vault| vault.allow_deposits)
        {
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
        let depositor = vault.depositors.entry(user).or_default();
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
        VaultResult::ok()
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
        VaultResult::ok()
    }

    fn is_parent_or_child(&self, first: Address, second: Address) -> bool {
        self.vaults
            .get(&first)
            .is_some_and(|vault| {
                vault.parent == Some(second) || vault.child_vaults.contains(&second)
            })
            || self.vaults.get(&second).is_some_and(|vault| {
                vault.parent == Some(first) || vault.child_vaults.contains(&first)
            })
    }

    fn vault(&self, address: Address) -> Result<&Vault, VaultError> {
        self.vaults.get(&address).ok_or(VaultError::VaultNotRegistered)
    }

    fn vault_mut(&mut self, address: Address) -> Result<&mut Vault, VaultError> {
        self.vaults
            .get_mut(&address)
            .ok_or(VaultError::VaultNotRegistered)
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
        let scaled = raw_delta.clamp(i64::MIN as i128, i64::MAX as i128) as SignedNtl;
        let account = self.account_totals.entry(address).or_default();
        account.total_ntl = account.total_ntl.saturating_add(scaled);
        account.usdc_ntl = account.usdc_ntl.saturating_add(scaled);
    }

    fn user_vault_equity(&self, vault_address: Address, user: Address) -> SignedNtl {
        self.vaults
            .get(&vault_address)
            .and_then(|vault| vault.depositors.get(&user))
            .map_or(0, |depositor| {
                depositor.principal.saturating_sub(depositor.withdrawn)
            })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AccountTotals {
    pub total_ntl: SignedNtl,
    pub usdc_ntl: SignedNtl,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Vault {
    pub leader: Address,
    pub kind: VaultKind,
    pub allow_deposits: bool,
    pub always_close_on_withdraw: bool,
    pub closed: bool,
    pub equity: SignedNtl,
    pub leader_commission_bps: Bps,
    pub parent: Option<Address>,
    pub child_vaults: Vec<Address>,
    pub depositors: BTreeMap<Address, VaultDepositor>,
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
pub struct Bps(pub u32);

impl Bps {
    fn apply(self, amount: RawUsd) -> RawUsd {
        ((amount as u128 * self.0 as u128) / 10_000) as RawUsd
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum VaultEvent {
    Transfer {
        tag: u64,
        user: Address,
        vault: Address,
        is_deposit: bool,
        usd: RawUsd,
    },
    LeaderCommission {
        vault: Address,
        leader: Address,
        user: Address,
        usd: RawUsd,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultResult {
    pub error: Option<VaultError>,
    pub address: Option<Address>,
}

impl VaultResult {
    fn ok() -> Self {
        Self {
            error: None,
            address: None,
        }
    }

    fn err(error: VaultError) -> Self {
        Self {
            error: Some(error),
            address: None,
        }
    }

    fn err_with_address(error: VaultError, address: Address) -> Self {
        Self {
            error: Some(error),
            address: Some(address),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VaultError {
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
    InsufficientSpotBalance,
}

impl VaultError {
    pub const fn recovered_code(&self) -> u16 {
        match self {
            Self::VaultNotRegistered => 7,
            Self::VaultClosed => 8,
            Self::VaultTransferThrottled => 31,
            Self::AmountOverflow { .. } => 319,
            Self::DepositTooSmall => 41,
            Self::VaultDisallowsDeposits => 0,
            Self::InvalidVaultTransfer => 25,
            Self::VaultWithdrawZeroBalance => 18,
            Self::VaultWithdrawLockup => 11,
            Self::VaultWithdrawTooMuchValueInChildVaults => 13,
            Self::VaultWithdrawInsufficientEquity => 14,
            Self::InsufficientSpotBalance => 51,
        }
    }
}
