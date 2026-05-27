use std::collections::BTreeMap;

pub type Address = [u8; 20];
pub type RawUsd = u64;
pub type SignedUsd = i64;

const CREATE_VAULT_RESERVE_USD: RawUsd = 10_000_000_000;
const CREATE_VAULT_MIN_INITIAL_USD: RawUsd = 10_000_000_000;
const GENERIC_VAULT_DEPOSIT_MIN_USD: RawUsd = 100_000_000;
const RAW_USD_OVERFLOW_CUTOFF: RawUsd = 0x0ccc_cccc_cccc_cccc;
const CREATE_VAULT_EVENT_TAG: u64 = 0x8000_0000_0000_0003;
const ACCOUNT_NTL_CLAMP: i64 = 0x0147_ae14_7ae1_47ae;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateVaultAction {
    pub leader: Address,
    pub vault_address: Address,
    pub name: String,
    pub description: String,
    pub initial_usd: RawUsd,
    pub parent_conversion: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateVaultError {
    InitialPlusReserveOverflow { attempted: RawUsd },
    InsufficientAvailableBalance,
    InitialDepositTooSmall,
    AmountOverflow { amount: RawUsd },
    VaultNameTooShort,
    VaultNameTooLong { len: usize },
    VaultDescriptionTooShort,
    VaultDescriptionTooLong { len: usize },
    VaultNameNotUnique,
    InitialDepositRejected(VaultDepositError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateVaultStatus {
    Applied,
    DuplicateVaultAddress,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateVaultResult {
    pub status: CreateVaultStatus,
    pub vault_address: Address,
    pub error: Option<CreateVaultError>,
}

#[derive(Clone, Debug, Default)]
pub struct ExchangeState {
    pub balances: BTreeMap<Address, RawUsd>,
    pub vaults_by_address: BTreeMap<Address, VaultState>,
    pub account_totals: BTreeMap<Address, AccountTotals>,
    pub mark_px: f64,
    pub events: Vec<ExchangeEvent>,
}

#[derive(Clone, Debug)]
pub struct VaultState {
    pub vault_address: Address,
    pub leader: Address,
    pub name: String,
    pub description: String,
    pub equity: SignedUsd,
    pub distribution_fee_fraction: f64,
    pub deposit_lockup_secs: u64,
    pub settlement_asset: u16,
    pub parent_conversion: bool,
    pub depositors: BTreeMap<Address, DepositorLedger>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AccountTotals {
    pub total_ntl: SignedUsd,
    pub usdc_ntl: SignedUsd,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DepositorLedger {
    pub principal: SignedUsd,
    pub withdrawn: SignedUsd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultDepositError {
    AmountOverflow { amount: RawUsd },
    DepositTooSmall,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExchangeEvent {
    CreateVault {
        tag: u64,
        leader: Address,
        vault: Address,
        initial_usd: RawUsd,
    },
}

impl ExchangeState {
    pub fn apply_create_vault(
        &mut self,
        action: CreateVaultAction,
        leader_available_balance: RawUsd,
        leader_lockup_profile_secs: u64,
    ) -> CreateVaultResult {
        if !action.parent_conversion {
            let Some(required) = action.initial_usd.checked_add(CREATE_VAULT_RESERVE_USD) else {
                return CreateVaultResult::err(
                    action.vault_address,
                    CreateVaultError::InitialPlusReserveOverflow {
                        attempted: action.initial_usd.saturating_add(CREATE_VAULT_RESERVE_USD),
                    },
                );
            };
            if leader_available_balance < required {
                return CreateVaultResult::err(
                    action.vault_address,
                    CreateVaultError::InsufficientAvailableBalance,
                );
            }
            if action.initial_usd < CREATE_VAULT_MIN_INITIAL_USD {
                return CreateVaultResult::err(
                    action.vault_address,
                    CreateVaultError::InitialDepositTooSmall,
                );
            }
        }

        if self
            .vaults_by_address
            .values()
            .any(|existing| existing.name == action.name)
        {
            return CreateVaultResult::err(action.vault_address, CreateVaultError::VaultNameNotUnique);
        }

        if self.vaults_by_address.contains_key(&action.vault_address) {
            return CreateVaultResult::duplicate(action.vault_address);
        }

        let provisional = match build_vault_entry(&action, leader_lockup_profile_secs) {
            Ok(vault) => vault,
            Err(error) => return CreateVaultResult::err(action.vault_address, error),
        };

        self.vaults_by_address.insert(action.vault_address, provisional);

        if action.parent_conversion {
            self.link_parent_conversion(action.leader, action.vault_address);
        } else {
            self.debit_balance(action.leader, CREATE_VAULT_RESERVE_USD);
            self.credit_balance(action.vault_address, CREATE_VAULT_RESERVE_USD);
            self.apply_scaled_ntl(action.leader, -(CREATE_VAULT_RESERVE_USD as i128));
        }

        self.events.push(ExchangeEvent::CreateVault {
            tag: CREATE_VAULT_EVENT_TAG,
            leader: action.leader,
            vault: action.vault_address,
            initial_usd: action.initial_usd,
        });

        CreateVaultResult::ok(action.vault_address)
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

    fn link_parent_conversion(&mut self, _leader: Address, _vault: Address) {}
}

fn build_vault_entry(
    action: &CreateVaultAction,
    leader_lockup_profile_secs: u64,
) -> Result<VaultState, CreateVaultError> {
    validate_create_vault_fields(action)?;

    let mut vault = VaultState {
        vault_address: action.vault_address,
        leader: action.leader,
        name: action.name.clone(),
        description: action.description.clone(),
        equity: 0,
        distribution_fee_fraction: if action.parent_conversion { 0.0 } else { 0.10 },
        deposit_lockup_secs: leader_lockup_profile_secs,
        settlement_asset: 256,
        parent_conversion: action.parent_conversion,
        depositors: BTreeMap::new(),
    };

    apply_initial_deposit(&mut vault, action.leader, action.initial_usd)
        .map_err(CreateVaultError::InitialDepositRejected)?;

    Ok(vault)
}

fn validate_create_vault_fields(action: &CreateVaultAction) -> Result<(), CreateVaultError> {
    if action.initial_usd >= RAW_USD_OVERFLOW_CUTOFF {
        return Err(CreateVaultError::AmountOverflow {
            amount: action.initial_usd,
        });
    }
    if action.name.len() < 3 {
        return Err(CreateVaultError::VaultNameTooShort);
    }
    if action.name.len() > 50 {
        return Err(CreateVaultError::VaultNameTooLong {
            len: action.name.len(),
        });
    }
    if action.description.len() < 10 {
        return Err(CreateVaultError::VaultDescriptionTooShort);
    }
    if action.description.len() > 250 {
        return Err(CreateVaultError::VaultDescriptionTooLong {
            len: action.description.len(),
        });
    }
    Ok(())
}

fn apply_initial_deposit(
    vault: &mut VaultState,
    leader: Address,
    initial_usd: RawUsd,
) -> Result<(), VaultDepositError> {
    if initial_usd >= RAW_USD_OVERFLOW_CUTOFF {
        return Err(VaultDepositError::AmountOverflow {
            amount: initial_usd,
        });
    }
    if initial_usd <= GENERIC_VAULT_DEPOSIT_MIN_USD {
        return Err(VaultDepositError::DepositTooSmall);
    }

    let scaled = clamp_scaled_ntl(initial_usd as i128, 1.0);
    vault.equity = vault.equity.saturating_add(scaled);

    let depositor = vault.depositors.entry(leader).or_default();
    depositor.principal = depositor.principal.saturating_add(scaled);

    Ok(())
}

fn clamp_scaled_ntl(raw_delta: i128, mark_px: f64) -> SignedUsd {
    let raw = raw_delta as f64 * mark_px;
    let clamped = if raw.is_finite() {
        raw.clamp(i64::MIN as f64, i64::MAX as f64)
    } else {
        0.0
    };
    ((clamped as i128) / 10_000)
        .clamp(-(ACCOUNT_NTL_CLAMP as i128), ACCOUNT_NTL_CLAMP as i128) as SignedUsd
}

impl CreateVaultResult {
    fn ok(vault_address: Address) -> Self {
        Self {
            status: CreateVaultStatus::Applied,
            vault_address,
            error: None,
        }
    }

    fn duplicate(vault_address: Address) -> Self {
        Self {
            status: CreateVaultStatus::DuplicateVaultAddress,
            vault_address,
            error: None,
        }
    }

    fn err(vault_address: Address, error: CreateVaultError) -> Self {
        Self {
            status: CreateVaultStatus::Rejected,
            vault_address,
            error: Some(error),
        }
    }
}
