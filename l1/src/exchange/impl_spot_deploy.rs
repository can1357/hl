//! Recovered spot-deploy application logic.
//!
//! The current binary has three monomorphs for the hyperliquidity deployment path.
//! They share the same control flow: parse `startPx_1`, parse `orderSz_1`, install
//! the hyperliquidity order ladder, reserve the required USDC from the signer, and
//! credit the protocol USDC account used by spot books.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Token = u64;
pub type Spot = u64;
pub type Wei = u64;
pub type RawPx = u64;
pub type RawSz = u64;
pub type Time = u64;

pub const USDC_TOKEN: Token = 0;
pub const PROTOCOL_USDC_ACCOUNT: Address = Address([0xff; 20]);
pub const MAX_HYPERLIQUIDITY_ORDERS: u64 = 4_000;
pub const MIN_HYPERLIQUIDITY_ORDERS: u64 = 10;
pub const HYPERLIQUIDITY_PRICE_RATIO: f64 = 1.003;
pub const MAX_START_MARKET_CAP_USDC: u64 = 10_000_000;
pub const MIN_END_MARKET_CAP_USDC: u64 = 1_000_000_000;
pub const MAX_END_MARKET_CAP_USDC: u64 = 100_000_000_000;
pub const MAX_REGISTER_HYPERLIQUIDITY_BALANCE: Wei = 0x68db_8bac_710cb;
pub const MAX_RAW_HYPERLIQUIDITY_VALUE: u64 = 0x1999_9999_9999_9999;
pub const MAX_HYPERLIQUIDITY_PRICE_RAW: u64 = 0x38d7_ea4c_68000;

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Address(pub [u8; 20]);

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TokenId(pub [u8; 16]);

#[derive(Clone, Debug)]
pub enum SpotDeployAction {
    RegisterToken(RegisterToken),
    RegisterToken2(RegisterToken),
    MaxGas { token: Token, max_gas: u64 },
    UserGenesis(UserGenesis),
    ExistingTokenAndWei { token: Token, entries: Vec<ExistingTokenAndWei> },
    BlacklistUsers { token: Token, users: Vec<Address> },
    Genesis(Genesis),
    RegisterSpot(RegisterSpot),
    RegisterHyperliquidity(RegisterHyperliquidity),
    RequestEvmContract(RequestEvmContract),
    SetFullName { token: Token, full_name: String },
    SetDeployerTradingFeeShare { token: Token, share: u64 },
    EnableFreezePrivilege { token: Token },
    FreezeUser { token: Token, user: Address, freeze: bool },
    RevokeFreezePrivilege { token: Token },
    EnableQuoteToken { token: Token },
    EnableAlignedQuoteToken { token: Token, enabled: bool },
}

#[derive(Clone, Debug)]
pub struct RegisterToken {
    pub token_id: TokenId,
    pub spec: TokenSpec,
    pub max_supply: Wei,
    pub full_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct TokenSpec {
    pub name: String,
    pub sz_decimals: u8,
    pub wei_decimals: u8,
}

#[derive(Clone, Debug)]
pub struct UserGenesis {
    pub token: Token,
    pub users: Vec<UserAndWei>,
}

#[derive(Clone, Debug)]
pub struct UserAndWei {
    pub user: Address,
    pub wei: String,
}

#[derive(Clone, Debug)]
pub struct ExistingTokenAndWei {
    pub token: Token,
    pub wei: String,
}

#[derive(Clone, Debug)]
pub struct Genesis {
    pub token: Token,
    pub no_hyperliquidity: bool,
}

#[derive(Clone, Debug)]
pub struct RegisterSpot {
    pub name: String,
    pub tokens: [Token; 2],
}

#[derive(Clone, Debug)]
pub struct RegisterHyperliquidity {
    pub spot: Spot,
    pub start_px_1: String,
    pub order_sz_1: String,
    pub n_orders_1: u64,
    pub n_seeded_levels: u64,
}

#[derive(Clone, Debug)]
pub struct RequestEvmContract {
    pub token: Token,
    pub address: Address,
    pub evm_extra_wei_decimals: i8,
}

#[derive(Clone, Debug)]
pub struct TokenInfo {
    pub spec: TokenSpec,
    pub max_supply: Wei,
    pub full_name: Option<String>,
    pub spot_indices: Vec<Spot>,
    pub deployer_trading_fee_share: u64,
    pub max_gas: u64,
    pub deployer: Option<Address>,
    pub freeze_privilege_enabled: bool,
    pub frozen_users: BTreeSet<Address>,
    pub blacklist_users: BTreeSet<Address>,
    pub evm_contract: Option<(Address, i8)>,
    pub genesis_users: Vec<UserAndWei>,
    pub genesis_existing_tokens: Vec<ExistingTokenAndWei>,
    pub genesis_finalized: bool,
}

#[derive(Clone, Debug)]
pub struct SpotInfo {
    pub name: String,
    pub tokens: [Token; 2],
}

#[derive(Clone, Debug, Default)]
pub struct DeployState {
    pub spot_infos: Vec<SpotInfo>,
    pub token_infos: Vec<TokenInfo>,
    pub token_id_to_token: BTreeMap<TokenId, Token>,
    pub canonical_pairs: BTreeMap<[Token; 2], Spot>,
    pub quote_tokens: BTreeSet<Token>,
    pub aligned_quote_tokens: BTreeMap<Token, AlignedQuoteToken>,
    pub pending_evm_contract_requests: BTreeMap<Token, (Address, i8)>,
    pub protected_users: BTreeSet<Address>,
    pub clearinghouse: ClearinghouseState,
    pub hyperliquidity: HyperliquidityState,
    pub events: Vec<SpotDeployEvent>,
}

#[derive(Clone, Debug, Default)]
pub struct ClearinghouseState {
    pub available_usdc: BTreeMap<Address, Wei>,
    pub token_ntl: BTreeMap<(Token, Address), Wei>,
    pub deployer_rebate_scale: f64,
}

#[derive(Clone, Debug, Default)]
pub struct HyperliquidityState {
    pub by_spot: BTreeMap<Spot, HyperliquidityBook>,
    pub known_base_token_hold: BTreeSet<Token>,
}

#[derive(Clone, Debug, Default)]
pub struct HyperliquidityBook {
    pub max_supply: Option<Wei>,
    pub levels: Vec<HyperliquidityLevel>,
    pub base_balance: Wei,
    pub usdc_seeded: Wei,
}

#[derive(Clone, Debug)]
pub struct HyperliquidityLevel {
    pub price: RawPx,
    pub size: RawSz,
    pub initially_seeded: bool,
}

#[derive(Clone, Debug)]
pub struct AlignedQuoteToken {
    pub active: bool,
    pub first_enabled_time: Time,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SpotDeployEvent {
    UsdcTransfer { user: Address, delta: f64 },
    FreezeUser { token: Token, user: Address, freeze: bool },
    RegisterHyperliquidity { spot: Spot, usdc_reserved: Wei },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SpotDeployError {
    InvalidStartPx,
    InvalidOrderSz,
    TokenAlreadyExists,
    InvalidTokenSpec,
    TokenNotFound,
    SpotNotFound,
    DuplicateSpot,
    InvalidSpotTokens,
    DeployerMismatch,
    TooManyHyperliquidityOrders,
    CannotSeedMoreLevelsThanExist,
    HyperliquidityAlreadyExists,
    HyperliquidityAlreadyHasTokenHold,
    HyperliquidityMissingMaxSupply,
    TooFewHyperliquidityOrders,
    HyperliquidityConfigurationInvalid,
    ZeroHyperliquidityOrderSize,
    HyperliquidityStartingOrderValueTooSmall,
    InsufficientUsdcForSeedingHyperliquidity,
    HyperliquidityPriceInvalid,
    HyperliquidityMarketCapOutOfRange,
    HyperliquidityStartingPriceTooSmall,
    HyperliquidityIncorrectBalance,
    QuoteTokenMustBeUsdcForHyperliquidity,
    CouldNotConvertUsdcBalance,
    TooManyGenesisUsersOrAnchorTokens,
    GenesisUserProtected,
    InvalidWei,
    BlacklistUpdateCannotIncludeGenesisBalances,
    GenesisBalanceForBlacklistedUser,
    TooManyBlacklistUsers,
    EvmContractAlreadySet,
    InvalidEvmExtraWeiDecimals,
    FreezePrivilegeNotEnabled,
    CannotRevokeFreezePrivilegeWithFrozenUsers,
    QuoteTokenNotEnabled,
    QuoteTokenNotDisabled,
}

impl SpotDeployError {
    pub const fn code(&self) -> u16 {
        match self {
            SpotDeployError::InvalidStartPx => 169,
            SpotDeployError::InvalidOrderSz => 170,
            SpotDeployError::DeployerMismatch => 234,
            SpotDeployError::CouldNotConvertUsdcBalance => 223,
            _ => 223,
        }
    }

    pub const fn message(&self) -> &'static str {
        match self {
            SpotDeployError::InvalidStartPx => "invalid startPx_1",
            SpotDeployError::InvalidOrderSz => "invalid orderSz_1",
            SpotDeployError::TokenAlreadyExists => "token already exists",
            SpotDeployError::InvalidTokenSpec => "invalid token spec",
            SpotDeployError::TokenNotFound => "token not found",
            SpotDeployError::SpotNotFound => "spot not found",
            SpotDeployError::DuplicateSpot => "duplicate spot asset",
            SpotDeployError::InvalidSpotTokens => "invalid spot tokens",
            SpotDeployError::DeployerMismatch => "deployer mismatch",
            SpotDeployError::TooManyHyperliquidityOrders => "too many Hyperliquidity orders",
            SpotDeployError::CannotSeedMoreLevelsThanExist => "cannot seed more levels than exist",
            SpotDeployError::HyperliquidityAlreadyExists => "Hyperliquidity already exists",
            SpotDeployError::HyperliquidityAlreadyHasTokenHold => "Hyperliquidity already has token hold",
            SpotDeployError::HyperliquidityMissingMaxSupply => "Hyperliquidity missing max supply",
            SpotDeployError::TooFewHyperliquidityOrders => "too few Hyperliquidity orders",
            SpotDeployError::HyperliquidityConfigurationInvalid => "Hyperliquidity configuration invalid",
            SpotDeployError::ZeroHyperliquidityOrderSize => "zero Hyperliquidity order size",
            SpotDeployError::HyperliquidityStartingOrderValueTooSmall => "Hyperliquidity starting order value must be at least 1 USDC",
            SpotDeployError::InsufficientUsdcForSeedingHyperliquidity => "insufficient usdc for seeding hyperliquidity",
            SpotDeployError::HyperliquidityPriceInvalid => "Hyperliquidity price is invalid",
            SpotDeployError::HyperliquidityMarketCapOutOfRange => "market cap must be in range [1B, 100B] USDC at Hyperliquidity end price and [0, 10M] USDC at Hyperliquidity start price",
            SpotDeployError::HyperliquidityStartingPriceTooSmall => "Hyperliquidity starting price too small",
            SpotDeployError::HyperliquidityIncorrectBalance => "Hyperliquidity has incorrect balance",
            SpotDeployError::QuoteTokenMustBeUsdcForHyperliquidity => "quote token must be USDC for Hyperliquidity",
            SpotDeployError::CouldNotConvertUsdcBalance => "Could not convert USDC balance",
            SpotDeployError::TooManyGenesisUsersOrAnchorTokens => "at most 10000 genesis users and 2 anchor tokens are allowed",
            SpotDeployError::GenesisUserProtected => "vaults and subaccounts are not allowed in genesis",
            SpotDeployError::InvalidWei => "invalid wei",
            SpotDeployError::BlacklistUpdateCannotIncludeGenesisBalances => "cannot update blacklist users when either user_and_wei or existing_token_and_wei is non-empty",
            SpotDeployError::GenesisBalanceForBlacklistedUser => "cannot update token genesis balance for blacklisted user(s)",
            SpotDeployError::TooManyBlacklistUsers => "blacklist users to update exceeds 1000",
            SpotDeployError::EvmContractAlreadySet => "evm contract already set",
            SpotDeployError::InvalidEvmExtraWeiDecimals => "EVM extra wei decimals must be between -2 and 18",
            SpotDeployError::FreezePrivilegeNotEnabled => "freeze privilege not enabled",
            SpotDeployError::CannotRevokeFreezePrivilegeWithFrozenUsers => "cannot revoke token freeze privilege when there are frozen users",
            SpotDeployError::QuoteTokenNotEnabled => "token is not quote token",
            SpotDeployError::QuoteTokenNotDisabled => "quote token not disabled",
        }
    }
}

impl DeployState {
    pub fn apply_spot_deploy(
        &mut self,
        signer: Address,
        action: SpotDeployAction,
        now: Time,
    ) -> Result<(), SpotDeployError> {
        match action {
            SpotDeployAction::RegisterToken(action) | SpotDeployAction::RegisterToken2(action) => {
                self.register_token(signer, action)
            }
            SpotDeployAction::MaxGas { token, max_gas } => {
                self.token_mut_for_deployer(token, signer)?.max_gas = max_gas;
                Ok(())
            }
            SpotDeployAction::UserGenesis(action) => self.apply_user_genesis(action.token, action.users),
            SpotDeployAction::ExistingTokenAndWei { token, entries } => self.apply_existing_token_genesis(token, entries),
            SpotDeployAction::BlacklistUsers { token, users } => self.apply_blacklist_update(token, users),
            SpotDeployAction::Genesis(action) => self.finalize_genesis(action.token, action.no_hyperliquidity),
            SpotDeployAction::RegisterSpot(action) => self.register_spot(action).map(|_| ()),
            SpotDeployAction::RegisterHyperliquidity(action) => self.register_hyperliquidity(signer, action),
            SpotDeployAction::RequestEvmContract(action) => self.request_evm_contract(action),
            SpotDeployAction::SetFullName { token, full_name } => {
                self.token_mut_for_deployer(token, signer)?.full_name = Some(full_name);
                Ok(())
            }
            SpotDeployAction::SetDeployerTradingFeeShare { token, share } => {
                self.token_mut_for_deployer(token, signer)?.deployer_trading_fee_share = share;
                Ok(())
            }
            SpotDeployAction::EnableFreezePrivilege { token } => {
                let token = self.token_mut_for_deployer(token, signer)?;
                token.freeze_privilege_enabled = true;
                token.frozen_users.clear();
                Ok(())
            }
            SpotDeployAction::FreezeUser { token, user, freeze } => self.apply_freeze_update(token, signer, user, freeze),
            SpotDeployAction::RevokeFreezePrivilege { token } => self.revoke_freeze_privilege(token, signer),
            SpotDeployAction::EnableQuoteToken { token } => self.enable_quote_token(token, now),
            SpotDeployAction::EnableAlignedQuoteToken { token, enabled } => self.set_aligned_quote_token(token, enabled, now),
        }
    }

    pub fn register_token(&mut self, signer: Address, action: RegisterToken) -> Result<(), SpotDeployError> {
        validate_token_spec(&action.spec)?;
        if self.token_id_to_token.contains_key(&action.token_id) {
            return Err(SpotDeployError::TokenAlreadyExists);
        }
        let index = self.token_infos.len() as Token;
        self.token_id_to_token.insert(action.token_id, index);
        self.token_infos.push(TokenInfo {
            spec: action.spec,
            max_supply: action.max_supply,
            full_name: action.full_name,
            spot_indices: Vec::new(),
            deployer_trading_fee_share: 100_000,
            max_gas: 0,
            deployer: Some(signer),
            freeze_privilege_enabled: false,
            frozen_users: BTreeSet::new(),
            blacklist_users: BTreeSet::new(),
            evm_contract: None,
            genesis_users: Vec::new(),
            genesis_existing_tokens: Vec::new(),
            genesis_finalized: false,
        });
        Ok(())
    }

    pub fn register_spot(&mut self, action: RegisterSpot) -> Result<Spot, SpotDeployError> {
        let [base, quote] = action.tokens;
        if base == quote || base == USDC_TOKEN || !self.quote_token_is_enabled(quote) {
            return Err(SpotDeployError::InvalidSpotTokens);
        }
        self.token(base)?;
        self.token(quote)?;
        if self.canonical_pairs.contains_key(&[base, quote]) || self.canonical_pairs.contains_key(&[quote, base]) {
            return Err(SpotDeployError::DuplicateSpot);
        }
        let spot = self.spot_infos.len() as Spot;
        self.spot_infos.push(SpotInfo { name: action.name, tokens: action.tokens });
        self.canonical_pairs.insert(action.tokens, spot);
        self.token_mut(base)?.spot_indices.push(spot);
        Ok(spot)
    }

    pub fn register_hyperliquidity(
        &mut self,
        signer: Address,
        action: RegisterHyperliquidity,
    ) -> Result<(), SpotDeployError> {
        let start_px = self.parse_nonzero_start_px(action.spot, &action.start_px_1)?;
        let base = self.spot(action.spot)?.tokens[0];
        let order_sz = parse_decimal_to_scaled_u64(&action.order_sz_1, self.token(base)?.spec.sz_decimals)
            .ok_or(SpotDeployError::InvalidOrderSz)?;
        let available_usdc = self.clearinghouse.available_usdc.get(&signer).copied().unwrap_or(0);
        if available_usdc > MAX_REGISTER_HYPERLIQUIDITY_BALANCE {
            return Err(SpotDeployError::CouldNotConvertUsdcBalance);
        }

        let params = HyperliquidityParams {
            spot: action.spot,
            start_px,
            order_sz,
            n_orders: action.n_orders_1,
            n_seeded_levels: action.n_seeded_levels,
            available_usdc_x100: available_usdc.saturating_mul(100),
        };
        let used_usdc_x100 = self.install_hyperliquidity_orders(params)?;
        let usdc_to_reserve = div_ceil_100(used_usdc_x100);

        if usdc_to_reserve != 0 {
            self.debit_user_usdc_for_hyperliquidity(signer, usdc_to_reserve)?;
            *self
                .clearinghouse
                .token_ntl
                .entry((USDC_TOKEN, PROTOCOL_USDC_ACCOUNT))
                .or_insert(0) += usdc_to_reserve;
            self.events.push(SpotDeployEvent::UsdcTransfer {
                user: signer,
                delta: -(usdc_to_reserve as f64) / 1_000_000.0,
            });
        }
        self.events.push(SpotDeployEvent::RegisterHyperliquidity { spot: action.spot, usdc_reserved: usdc_to_reserve });
        Ok(())
    }

    fn parse_nonzero_start_px(&self, spot: Spot, input: &str) -> Result<RawPx, SpotDeployError> {
        let [base, quote] = self.spot(spot)?.tokens;
        let base_sz_decimals = self.token(base)?.spec.sz_decimals;
        let quote_wei_decimals = self.token(quote)?.spec.wei_decimals;
        if quote_wei_decimals < base_sz_decimals {
            return Err(SpotDeployError::InvalidStartPx);
        }
        let px_decimals = quote_wei_decimals - base_sz_decimals;
        let raw = parse_decimal_to_scaled_u64(input, px_decimals).ok_or(SpotDeployError::InvalidStartPx)?;
        if raw == 0 {
            return Err(SpotDeployError::InvalidStartPx);
        }
        Ok(raw)
    }

    fn install_hyperliquidity_orders(&mut self, params: HyperliquidityParams) -> Result<Wei, SpotDeployError> {
        if params.n_orders > MAX_HYPERLIQUIDITY_ORDERS {
            return Err(SpotDeployError::TooManyHyperliquidityOrders);
        }
        if params.n_seeded_levels > params.n_orders {
            return Err(SpotDeployError::CannotSeedMoreLevelsThanExist);
        }
        let [base, quote] = self.spot(params.spot)?.tokens;
        if quote != USDC_TOKEN {
            return Err(SpotDeployError::QuoteTokenMustBeUsdcForHyperliquidity);
        }
        if self.hyperliquidity.by_spot.contains_key(&params.spot) {
            return Err(SpotDeployError::HyperliquidityAlreadyExists);
        }
        if self.hyperliquidity.known_base_token_hold.contains(&base) {
            return Err(SpotDeployError::HyperliquidityAlreadyHasTokenHold);
        }
        if params.n_orders < MIN_HYPERLIQUIDITY_ORDERS {
            return Err(SpotDeployError::TooFewHyperliquidityOrders);
        }
        if params.order_sz == 0 {
            return Err(SpotDeployError::ZeroHyperliquidityOrderSize);
        }
        let max_supply = self.token(base)?.max_supply;
        if max_supply == 0 {
            return Err(SpotDeployError::HyperliquidityMissingMaxSupply);
        }
        if max_supply.checked_mul(params.order_sz).is_none_or(|v| v > MAX_RAW_HYPERLIQUIDITY_VALUE) {
            return Err(SpotDeployError::HyperliquidityConfigurationInvalid);
        }
        let ending_multiplier = pow_ratio(HYPERLIQUIDITY_PRICE_RATIO, params.n_orders);
        let end_px = ceil_f64_to_u64((params.start_px as f64) * ending_multiplier)
            .ok_or(SpotDeployError::HyperliquidityConfigurationInvalid)?;
        if end_px > MAX_HYPERLIQUIDITY_PRICE_RAW {
            return Err(SpotDeployError::HyperliquidityConfigurationInvalid);
        }
        if params.start_px.checked_mul(params.order_sz).is_none_or(|v| v < 1_000_000) {
            return Err(SpotDeployError::HyperliquidityStartingOrderValueTooSmall);
        }

        let start_market_cap = raw_market_cap_usdc(params.start_px, max_supply)?;
        let end_market_cap = raw_market_cap_usdc(end_px, max_supply)?;
        if start_market_cap > MAX_START_MARKET_CAP_USDC
            || end_market_cap < MIN_END_MARKET_CAP_USDC
            || end_market_cap > MAX_END_MARKET_CAP_USDC
        {
            return Err(SpotDeployError::HyperliquidityMarketCapOutOfRange);
        }

        let mut used_usdc_x100 = 0u64;
        let mut levels = Vec::with_capacity(params.n_orders as usize);
        let mut px = params.start_px;
        for level in 0..params.n_orders {
            if px == 0 || px > MAX_HYPERLIQUIDITY_PRICE_RAW {
                return Err(SpotDeployError::HyperliquidityPriceInvalid);
            }
            let initially_seeded = level < params.n_seeded_levels;
            if initially_seeded {
                let notional = px.checked_mul(params.order_sz).ok_or(SpotDeployError::HyperliquidityConfigurationInvalid)?;
                used_usdc_x100 = used_usdc_x100
                    .checked_add(notional / 10_000)
                    .ok_or(SpotDeployError::HyperliquidityConfigurationInvalid)?;
            }
            levels.push(HyperliquidityLevel { price: px, size: params.order_sz, initially_seeded });
            px = ceil_f64_to_u64((px as f64) * HYPERLIQUIDITY_PRICE_RATIO)
                .ok_or(SpotDeployError::HyperliquidityPriceInvalid)?;
        }
        if used_usdc_x100 > params.available_usdc_x100 {
            return Err(SpotDeployError::InsufficientUsdcForSeedingHyperliquidity);
        }
        if levels.first().is_some_and(|level| level.price == levels.last().map(|last| last.price).unwrap_or(0)) {
            return Err(SpotDeployError::HyperliquidityStartingPriceTooSmall);
        }

        self.hyperliquidity.by_spot.insert(
            params.spot,
            HyperliquidityBook { max_supply: Some(max_supply), levels, base_balance: 0, usdc_seeded: div_ceil_100(used_usdc_x100) },
        );
        self.hyperliquidity.known_base_token_hold.insert(base);
        Ok(used_usdc_x100)
    }

    fn debit_user_usdc_for_hyperliquidity(&mut self, signer: Address, amount: Wei) -> Result<(), SpotDeployError> {
        let available = self.clearinghouse.available_usdc.entry(signer).or_insert(0);
        if *available < amount {
            return Err(SpotDeployError::InsufficientUsdcForSeedingHyperliquidity);
        }
        *available -= amount;
        Ok(())
    }

    fn apply_user_genesis(&mut self, token: Token, users: Vec<UserAndWei>) -> Result<(), SpotDeployError> {
        if users.len() > 10_000 {
            return Err(SpotDeployError::TooManyGenesisUsersOrAnchorTokens);
        }
        for entry in &users {
            if self.protected_users.contains(&entry.user) {
                return Err(SpotDeployError::GenesisUserProtected);
            }
            parse_plain_wei(&entry.wei)?;
            if self.token(token)?.blacklist_users.contains(&entry.user) {
                return Err(SpotDeployError::GenesisBalanceForBlacklistedUser);
            }
        }
        self.token_mut(token)?.genesis_users.extend(users);
        Ok(())
    }

    fn apply_existing_token_genesis(&mut self, token: Token, entries: Vec<ExistingTokenAndWei>) -> Result<(), SpotDeployError> {
        if entries.len() > 2 {
            return Err(SpotDeployError::TooManyGenesisUsersOrAnchorTokens);
        }
        for entry in &entries {
            parse_plain_wei(&entry.wei)?;
        }
        self.token_mut(token)?.genesis_existing_tokens.extend(entries);
        Ok(())
    }

    fn apply_blacklist_update(&mut self, token: Token, users: Vec<Address>) -> Result<(), SpotDeployError> {
        if users.len() > 1_000 {
            return Err(SpotDeployError::TooManyBlacklistUsers);
        }
        let token = self.token_mut(token)?;
        if !token.genesis_users.is_empty() || !token.genesis_existing_tokens.is_empty() {
            return Err(SpotDeployError::BlacklistUpdateCannotIncludeGenesisBalances);
        }
        token.blacklist_users.extend(users);
        Ok(())
    }

    fn finalize_genesis(&mut self, token: Token, no_hyperliquidity: bool) -> Result<(), SpotDeployError> {
        if !no_hyperliquidity && self.token(token)?.max_supply == 0 {
            return Err(SpotDeployError::HyperliquidityMissingMaxSupply);
        }
        self.token_mut(token)?.genesis_finalized = true;
        Ok(())
    }

    fn request_evm_contract(&mut self, action: RequestEvmContract) -> Result<(), SpotDeployError> {
        if !(-2..=18).contains(&action.evm_extra_wei_decimals) {
            return Err(SpotDeployError::InvalidEvmExtraWeiDecimals);
        }
        if self.token(action.token)?.evm_contract.is_some() {
            return Err(SpotDeployError::EvmContractAlreadySet);
        }
        self.pending_evm_contract_requests.insert(action.token, (action.address, action.evm_extra_wei_decimals));
        Ok(())
    }

    fn apply_freeze_update(
        &mut self,
        token: Token,
        signer: Address,
        user: Address,
        freeze: bool,
    ) -> Result<(), SpotDeployError> {
        let token_info = self.token_mut_for_deployer(token, signer)?;
        if !token_info.freeze_privilege_enabled {
            return Err(SpotDeployError::FreezePrivilegeNotEnabled);
        }
        if freeze {
            token_info.frozen_users.insert(user);
        } else {
            token_info.frozen_users.remove(&user);
        }
        self.events.push(SpotDeployEvent::FreezeUser { token, user, freeze });
        Ok(())
    }

    fn revoke_freeze_privilege(&mut self, token: Token, signer: Address) -> Result<(), SpotDeployError> {
        let token_info = self.token_mut_for_deployer(token, signer)?;
        if !token_info.frozen_users.is_empty() {
            return Err(SpotDeployError::CannotRevokeFreezePrivilegeWithFrozenUsers);
        }
        token_info.freeze_privilege_enabled = false;
        Ok(())
    }

    fn enable_quote_token(&mut self, token: Token, _now: Time) -> Result<(), SpotDeployError> {
        let info = self.token(token)?;
        if info.spec.wei_decimals != 8 || info.deployer_trading_fee_share != 0 {
            return Err(SpotDeployError::QuoteTokenNotEnabled);
        }
        if !self.token_has_usdc_pair(token) {
            return Err(SpotDeployError::QuoteTokenNotEnabled);
        }
        self.quote_tokens.insert(token);
        Ok(())
    }

    fn set_aligned_quote_token(&mut self, token: Token, enabled: bool, now: Time) -> Result<(), SpotDeployError> {
        if enabled {
            if !self.quote_tokens.contains(&token) {
                return Err(SpotDeployError::QuoteTokenNotEnabled);
            }
            self.aligned_quote_tokens
                .entry(token)
                .and_modify(|info| info.active = true)
                .or_insert(AlignedQuoteToken { active: true, first_enabled_time: now });
        } else {
            let Some(info) = self.aligned_quote_tokens.get_mut(&token) else {
                return Err(SpotDeployError::QuoteTokenNotDisabled);
            };
            info.active = false;
        }
        Ok(())
    }

    fn token(&self, token: Token) -> Result<&TokenInfo, SpotDeployError> {
        self.token_infos.get(token as usize).ok_or(SpotDeployError::TokenNotFound)
    }

    fn token_mut(&mut self, token: Token) -> Result<&mut TokenInfo, SpotDeployError> {
        self.token_infos.get_mut(token as usize).ok_or(SpotDeployError::TokenNotFound)
    }

    fn token_mut_for_deployer(&mut self, token: Token, signer: Address) -> Result<&mut TokenInfo, SpotDeployError> {
        let token_info = self.token_mut(token)?;
        if token_info.deployer != Some(signer) {
            return Err(SpotDeployError::DeployerMismatch);
        }
        Ok(token_info)
    }

    fn spot(&self, spot: Spot) -> Result<&SpotInfo, SpotDeployError> {
        self.spot_infos.get(spot as usize).ok_or(SpotDeployError::SpotNotFound)
    }

    fn quote_token_is_enabled(&self, token: Token) -> bool {
        token == USDC_TOKEN || self.quote_tokens.contains(&token)
    }

    fn token_has_usdc_pair(&self, token: Token) -> bool {
        self.token(token)
            .ok()
            .is_some_and(|info| info.spot_indices.iter().any(|spot| self.spot(*spot).ok().is_some_and(|s| s.tokens[1] == USDC_TOKEN)))
    }
}

#[derive(Clone, Copy, Debug)]
struct HyperliquidityParams {
    spot: Spot,
    start_px: RawPx,
    order_sz: RawSz,
    n_orders: u64,
    n_seeded_levels: u64,
    available_usdc_x100: Wei,
}

fn validate_token_spec(spec: &TokenSpec) -> Result<(), SpotDeployError> {
    if spec.name.len() > 100 || spec.sz_decimals > spec.wei_decimals || spec.wei_decimals > 10 {
        return Err(SpotDeployError::InvalidTokenSpec);
    }
    Ok(())
}

fn parse_decimal_to_scaled_u64(input: &str, decimals: u8) -> Option<u64> {
    if input.is_empty() || input.as_bytes()[0] == b'+' || input.as_bytes()[0] == b'-' {
        return None;
    }
    let mut value = 0u64;
    let mut scale_seen = 0u8;
    let mut after_dot = false;
    for &byte in input.as_bytes() {
        match byte {
            b'0'..=b'9' => {
                if after_dot {
                    if scale_seen == decimals {
                        if byte != b'0' {
                            return None;
                        }
                        continue;
                    }
                    scale_seen += 1;
                }
                value = value.checked_mul(10)?.checked_add((byte - b'0') as u64)?;
            }
            b'.' if !after_dot => after_dot = true,
            _ => return None,
        }
    }
    while scale_seen < decimals {
        value = value.checked_mul(10)?;
        scale_seen += 1;
    }
    Some(value)
}

fn parse_plain_wei(input: &str) -> Result<Wei, SpotDeployError> {
    if input.is_empty() || input.len() > 100 || matches!(input.as_bytes()[0], b'+' | b'-') {
        return Err(SpotDeployError::InvalidWei);
    }
    let mut value = 0u64;
    for &byte in input.as_bytes() {
        if !byte.is_ascii_digit() {
            return Err(SpotDeployError::InvalidWei);
        }
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add((byte - b'0') as u64))
            .ok_or(SpotDeployError::InvalidWei)?;
    }
    Ok(value)
}

fn pow_ratio(ratio: f64, exponent: u64) -> f64 {
    let mut acc = 1.0;
    let mut i = 0;
    while i < exponent {
        acc *= ratio;
        i += 1;
    }
    acc
}

fn ceil_f64_to_u64(value: f64) -> Option<u64> {
    if !value.is_finite() || value < 0.0 || value > u64::MAX as f64 {
        None
    } else {
        Some(value.ceil() as u64)
    }
}

fn raw_market_cap_usdc(price: RawPx, supply: Wei) -> Result<u64, SpotDeployError> {
    let raw = (price as u128)
        .checked_mul(supply as u128)
        .ok_or(SpotDeployError::HyperliquidityConfigurationInvalid)?;
    let usdc = raw / 100_000_000;
    if usdc > u64::MAX as u128 {
        return Err(SpotDeployError::HyperliquidityMarketCapOutOfRange);
    }
    Ok(usdc as u64)
}

fn div_ceil_100(value: u64) -> u64 {
    value / 100 + u64::from(value % 100 != 0)
}
