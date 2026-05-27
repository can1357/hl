use std::collections::BTreeMap;

pub type Address = [u8; 20];
pub type RawUsd = u64;
pub type SignedNtl = i64;

pub const RAW_USD_OVERFLOW_CUTOFF: RawUsd = 0x0ccc_cccc_cccc_cccc;
pub const VAULT_DISTRIBUTE_MIN_USD: RawUsd = 10_000_000;
pub const DISTRIBUTE_EVENT_TAG: u64 = 0x8000_0000_0000_0006;
pub const ACCOUNT_NTL_CLAMP: u64 = 0x0147_ae14_7ae1_47ae;

pub const STATUS_OK: u16 = 390;
pub const STATUS_VAULT_NOT_REGISTERED: u16 = 7;
pub const STATUS_VAULT_CLOSED: u16 = 8;
pub const STATUS_VAULT_ACTION_LEADER_ONLY: u16 = 17;
pub const STATUS_VAULT_WITHDRAW_ZERO_BALANCE: u16 = 18;
pub const STATUS_VAULT_MINIMUM_DISTRIBUTION: u16 = 19;
pub const STATUS_VAULT_WITHDRAW_INSUFFICIENT_EQUITY: u16 = 14;
pub const STATUS_INSUFFICIENT_SPOT_BALANCE: u16 = 51;
pub const STATUS_AMOUNT_OVERFLOW: u16 = 319;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultDistributeAction {
    pub usd: RawUsd,
    pub vault_address: Address,
}

#[derive(Clone, Debug, Default)]
pub struct ExchangeVaultState {
    pub mark_px: f64,
    pub vaults: BTreeMap<Address, Vault>,
    pub balances: BTreeMap<Address, RawUsd>,
    pub account_totals: BTreeMap<Address, AccountTotals>,
    pub events: Vec<VaultEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Vault {
    pub leader: Address,
    pub closed: bool,
    pub equity: SignedNtl,
    pub leader_commission_bps: Bps,
    pub child_vaults: Vec<Address>,
    pub depositors: BTreeMap<Address, VaultDepositor>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VaultDepositor {
    pub principal: SignedNtl,
    pub withdrawn: SignedNtl,
    pub closed: bool,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DistributionChange {
    pub user: Address,
    pub user_ledger_change: SignedNtl,
    pub leader_commission: SignedNtl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DistributionOutcome {
    pub distributed_amount: RawUsd,
    pub explicit_request: bool,
    pub vault_closed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WrappedVaultDistributeResult {
    Applied,
    Rejected(VaultDistributeError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultDistributeError {
    AmountOverflow { amount: RawUsd },
    VaultNotRegistered { vault: Address },
    VaultClosed { vault: Address },
    VaultActionLeaderOnly { vault: Address, leader: Address },
    VaultMinimumDistribution { requested: RawUsd, minimum: RawUsd },
    VaultWithdrawInsufficientEquity { requested: RawUsd, available: RawUsd },
    VaultWithdrawZeroBalance {
        vault: Address,
        total_ntl: RawUsd,
        on_chain_balance: RawUsd,
    },
    InsufficientSpotBalance { vault: Address, available: RawUsd, required: RawUsd },
}

impl VaultDistributeError {
    pub const fn status(self: &Self) -> u16 {
        match self {
            Self::AmountOverflow { .. } => STATUS_AMOUNT_OVERFLOW,
            Self::VaultNotRegistered { .. } => STATUS_VAULT_NOT_REGISTERED,
            Self::VaultClosed { .. } => STATUS_VAULT_CLOSED,
            Self::VaultActionLeaderOnly { .. } => STATUS_VAULT_ACTION_LEADER_ONLY,
            Self::VaultMinimumDistribution { .. } => STATUS_VAULT_MINIMUM_DISTRIBUTION,
            Self::VaultWithdrawInsufficientEquity { .. } => STATUS_VAULT_WITHDRAW_INSUFFICIENT_EQUITY,
            Self::VaultWithdrawZeroBalance { .. } => STATUS_VAULT_WITHDRAW_ZERO_BALANCE,
            Self::InsufficientSpotBalance { .. } => STATUS_INSUFFICIENT_SPOT_BALANCE,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VaultEvent {
    Distribute {
        tag: u64,
        vault: Address,
        user: Address,
        user_ledger_change: SignedNtl,
    },
}

/// Wrapper at `0x1E60020`.
///
/// The binary copies the payload into stack locals, rejects `usd >= 0x0ccc_cccc_cccc_cccc`,
/// calls the inner vault helper, then maps `390` to outer variant `13` and everything else to
/// outer variant `14` with the inner status payload forwarded unchanged.
pub fn wrap_vault_distribute_action(
    state: &mut ExchangeVaultState,
    leader: Address,
    action: VaultDistributeAction,
) -> WrappedVaultDistributeResult {
    if action.usd >= RAW_USD_OVERFLOW_CUTOFF {
        return WrappedVaultDistributeResult::Rejected(VaultDistributeError::AmountOverflow {
            amount: action.usd,
        });
    }

    match state.apply_vault_distribute(leader, action) {
        Ok(()) => WrappedVaultDistributeResult::Applied,
        Err(error) => WrappedVaultDistributeResult::Rejected(error),
    }
}

impl ExchangeVaultState {
    /// Recovered inner helper `l1_exchange_impl_vault__apply_vault_distribute` (`0x26F6110`).
    ///
    /// Validation and mutation flow:
    /// - require the vault row to exist and not be closed;
    /// - require the signer to be the vault leader;
    /// - if `usd != 0`, enforce the `10 USDC` minimum and cap by current vault equity;
    /// - if `usd == 0`, require the vault accounting total to equal its spot balance and
    ///   distribute the full withdrawable amount;
    /// - reject empty / underfunded vaults;
    /// - prorate the requested amount across open positive-principal depositors, subtracting the
    ///   configured leader commission from each participant share;
    /// - debit the vault balance, credit user balances, update account totals, emit one event per
    ///   credited user, and mark the vault closed when equity reaches zero.
    pub fn apply_vault_distribute(
        &mut self,
        leader: Address,
        action: VaultDistributeAction,
    ) -> Result<(), VaultDistributeError> {
        let Some(vault) = self.vaults.get(&action.vault_address) else {
            return Err(VaultDistributeError::VaultNotRegistered {
                vault: action.vault_address,
            });
        };
        if vault.closed {
            return Err(VaultDistributeError::VaultClosed {
                vault: action.vault_address,
            });
        }
        if vault.leader != leader {
            return Err(VaultDistributeError::VaultActionLeaderOnly {
                vault: action.vault_address,
                leader,
            });
        }

        let total_ntl = self.vault_total_ntl(action.vault_address);
        let requested = action.usd;
        let amount = if requested != 0 {
            if requested < VAULT_DISTRIBUTE_MIN_USD {
                return Err(VaultDistributeError::VaultMinimumDistribution {
                    requested,
                    minimum: VAULT_DISTRIBUTE_MIN_USD,
                });
            }
            if requested > total_ntl {
                return Err(VaultDistributeError::VaultWithdrawInsufficientEquity {
                    requested,
                    available: total_ntl,
                });
            }
            requested
        } else {
            let on_chain_balance = self.balance_of(&action.vault_address);
            if total_ntl != on_chain_balance {
                return Err(VaultDistributeError::VaultWithdrawZeroBalance {
                    vault: action.vault_address,
                    total_ntl,
                    on_chain_balance,
                });
            }
            total_ntl
        };

        let available_balance = self.balance_of(&action.vault_address);
        if total_ntl == 0 || available_balance < amount {
            return Err(VaultDistributeError::InsufficientSpotBalance {
                vault: action.vault_address,
                available: available_balance,
                required: amount,
            });
        }

        let changes = self.compute_distribution_changes(action.vault_address, amount, total_ntl)?;
        self.debit_balance(action.vault_address, amount);
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
        Ok(())
    }

    fn compute_distribution_changes(
        &mut self,
        vault_address: Address,
        amount: RawUsd,
        total_ntl: RawUsd,
    ) -> Result<Vec<DistributionChange>, VaultDistributeError> {
        let vault = self
            .vaults
            .get_mut(&vault_address)
            .ok_or(VaultDistributeError::VaultNotRegistered { vault: vault_address })?;

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

    fn vault_total_ntl(&self, vault_address: Address) -> RawUsd {
        let Some(vault) = self.vaults.get(&vault_address) else {
            return 0;
        };
        let own = vault.equity.max(0) as RawUsd;
        vault.child_vaults.iter().fold(own, |acc, child| {
            acc.saturating_add(self.vaults.get(child).map_or(0, |child_vault| child_vault.equity.max(0) as RawUsd))
        })
    }

    fn balance_of(&self, user: &Address) -> RawUsd {
        self.balances.get(user).copied().unwrap_or(0)
    }

    fn debit_balance(&mut self, user: Address, amount: RawUsd) {
        let balance = self.balances.entry(user).or_default();
        *balance = balance.saturating_sub(amount);
    }

    fn credit_balance(&mut self, user: Address, amount: RawUsd) {
        let balance = self.balances.entry(user).or_default();
        *balance = balance.saturating_add(amount);
    }

    fn apply_scaled_ntl(&mut self, user: Address, raw_delta: i128) {
        let scaled = clamp_scaled_ntl(raw_delta, self.mark_px);
        let totals = self.account_totals.entry(user).or_default();
        totals.total_ntl = totals.total_ntl.saturating_add(scaled);
        totals.usdc_ntl = totals.usdc_ntl.saturating_add(scaled);
    }
}

fn prorata(amount: RawUsd, principal: RawUsd, total_ntl: RawUsd) -> RawUsd {
    if amount == 0 || principal == 0 || total_ntl == 0 {
        return 0;
    }
    ((amount as u128 * principal as u128) / total_ntl as u128) as RawUsd
}

fn clamp_scaled_ntl(raw_delta: i128, mark_px: f64) -> SignedNtl {
    let scaled = (raw_delta as f64 * mark_px).round();
    scaled.clamp(-(ACCOUNT_NTL_CLAMP as f64), ACCOUNT_NTL_CLAMP as f64) as SignedNtl
}
