use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type Token = u64;
pub type Spot = u64;
pub type Wei = u64;
pub type RawPx = u64;
pub type RawSz = u64;
pub type Time = u64;

pub const STATUS_SUCCESS: u16 = 390;
pub const STATUS_SPOT_DISABLED: u16 = 249;
pub const STATUS_SIGNER_MODE_REJECTED: u16 = 367;
pub const STATUS_TOKEN_OR_SPOT_NOT_FOUND: u16 = 234;
pub const STATUS_GENERIC_SPOT_DEPLOY_ERROR: u16 = 223;
pub const STATUS_OVERFLOW_GUARD: u16 = 319;
pub const STATUS_NAME_TOO_LONG: u16 = 323;

pub const USDC_TOKEN: Token = 0;
pub const MAX_DEPLOYER_TRADING_FEE_SHARE: u64 = 100_000;
pub const MAX_TOKEN_NAME_LEN: usize = 100;
pub const MAX_TOKEN_FULL_NAME_LEN: usize = 100;
pub const MAX_BLACKLIST_USERS_TO_UPDATE: usize = 1_000;
pub const MAX_GENESIS_USERS: usize = 10_000;
pub const MAX_ANCHOR_TOKENS: usize = 2;
pub const MAX_FROZEN_USERS: usize = 1_000;
pub const MAX_TOKEN_MAX_SUPPLY: Wei = 0x0ccc_cccc_cccc_cccc;
pub const MAX_REGISTER_HYPERLIQUIDITY_BALANCE: Wei = 0x68db_8bac_710cb;
pub const MAX_HYPERLIQUIDITY_ORDERS: u64 = 4_000;
pub const MIN_HYPERLIQUIDITY_ORDERS: u64 = 10;
pub const HYPERLIQUIDITY_PRICE_RATIO: f64 = 1.003;
pub const MAX_RAW_HYPERLIQUIDITY_VALUE: u64 = 0x1999_9999_9999_9999;
pub const MAX_HYPERLIQUIDITY_PRICE_RAW: RawPx = 0x38d7_ea4c_68000;
pub const MAX_START_MARKET_CAP_USDC: u64 = 10_000_000;
pub const MIN_END_MARKET_CAP_USDC: u64 = 1_000_000_000;
pub const MAX_END_MARKET_CAP_USDC: u64 = 100_000_000_000;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TokenId(pub [u8; 16]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenSpec {
    pub name: String,
    pub sz_decimals: u8,
    pub wei_decimals: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterToken {
    pub token_id: TokenId,
    pub spec: TokenSpec,
    pub max_supply: Wei,
    pub full_name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserAndWei {
    pub user: Address,
    pub wei: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExistingTokenAndWei {
    pub token: Token,
    pub wei: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisBatch {
    pub token: Token,
    pub user_and_wei: Vec<UserAndWei>,
    pub existing_token_and_wei: Vec<ExistingTokenAndWei>,
    pub blacklist_users: Option<Vec<Address>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecimalTokenMutation {
    pub token: Token,
    pub decimal: String,
    pub flag: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterSpot {
    pub name: String,
    pub tokens: [Token; 2],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterHyperliquidity {
    pub spot: Spot,
    pub start_px_1: String,
    pub order_sz_1: String,
    pub n_orders_1: u64,
    pub n_seeded_levels: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestEvmContract {
    pub token: Token,
    pub address: Address,
    pub evm_extra_wei_decimals: i8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForwardedRegisterAction {
    pub raw_kind: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SpotDeployAction {
    /// Nested case 0.
    RegisterToken(RegisterToken),
    /// Nested case 1.
    RegisterToken2(RegisterToken),
    /// Nested case 2. The handler forwards this branch into a separate deploy-action adapter.
    ForwardedRegisterAction(ForwardedRegisterAction),
    /// Nested case 3. This branch batches user genesis balances, anchor-token balances, and
    /// blacklist-only updates through one shared validator.
    ApplyGenesisBatch(GenesisBatch),
    /// Nested case 4. The helper parses a decimal string and mutates token state through a
    /// dedicated downstream routine.
    DecimalTokenMutation(DecimalTokenMutation),
    /// Nested case 5.
    RegisterSpot(RegisterSpot),
    /// Nested case 6.
    RegisterHyperliquidity(RegisterHyperliquidity),
    /// Nested case 7.
    RequestEvmContract(RequestEvmContract),
    /// Nested case 8.
    SetFullName { token: Token, full_name: String },
    /// Nested case 9.
    SetDeployerTradingFeeShare { token: Token, share: u64 },
    /// Nested case 10.
    EnableFreezePrivilege { token: Token },
    /// Nested case 11.
    FreezeUser { token: Token, user: Address, freeze: bool },
    /// Nested case 12.
    RevokeFreezePrivilege { token: Token },
    /// Nested case 13.
    EnableQuoteToken { token: Token },
    /// Nested case 14.
    DisableQuoteToken { token: Token },
    /// Nested case 15.
    EnableAlignedQuoteToken { token: Token },
    /// Nested case 16.
    DisableAlignedQuoteToken { token: Token },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerClass {
    Unknown,
    L1,
    L2,
    L3,
    L4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpotDeployEnvelope {
    pub signer: Address,
    pub signer_class: SignerClass,
    pub signer_gate_l4_enabled: bool,
    pub signer_gate_l3_enabled: bool,
    pub spot_deploy_disabled: bool,
    pub now: Time,
    pub action: SpotDeployAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SpotDeploySuccess {
    Applied,
    CreatedToken(Token),
    CreatedSpot(Spot),
    Forwarded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpotDeployFailure {
    pub status: u16,
    pub message: Option<&'static str>,
}

impl SpotDeployFailure {
    pub const fn status(status: u16) -> Self {
        Self { status, message: None }
    }

    pub const fn with_message(status: u16, message: &'static str) -> Self {
        Self {
            status,
            message: Some(message),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SpotDeployState {
    pub token_infos: Vec<TokenInfo>,
    pub token_id_to_token: BTreeMap<TokenId, Token>,
    pub spot_infos: Vec<SpotInfo>,
    pub canonical_spots: BTreeMap<[Token; 2], Spot>,
    pub quote_token_status: BTreeMap<Token, QuoteTokenStatus>,
    pub aligned_quote_tokens: BTreeMap<Token, AlignedQuoteTokenInfo>,
    pub pending_evm_contract_requests: BTreeMap<Token, PendingEvmContract>,
    pub protected_users: BTreeSet<Address>,
    pub available_usdc: BTreeMap<Address, Wei>,
    pub hyperliquidity_books: BTreeMap<Spot, HyperliquidityBook>,
    pub hyperliquidity_base_tokens: BTreeSet<Token>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenInfo {
    pub spec: TokenSpec,
    pub max_supply: Wei,
    pub full_name: Option<String>,
    pub deployer_trading_fee_share: u64,
    pub freeze_privilege_enabled: bool,
    pub frozen_users: BTreeSet<Address>,
    pub blacklist_users: BTreeSet<Address>,
    pub evm_contract: Option<EvmContractInfo>,
    pub deployer: Option<Address>,
    pub spot_indices: Vec<Spot>,
    pub user_genesis_balances: Vec<UserAndWei>,
    pub existing_token_genesis_balances: Vec<ExistingTokenAndWei>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpotInfo {
    pub name: String,
    pub tokens: [Token; 2],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuoteTokenStatus {
    Active,
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvmContractInfo {
    pub address: Address,
    pub evm_extra_wei_decimals: i8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingEvmContract {
    pub address: Address,
    pub evm_extra_wei_decimals: i8,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AlignedQuoteTokenInfo {
    pub first_enabled_time: Time,
    pub active: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HyperliquidityBook {
    pub order_sz: RawSz,
    pub levels: Vec<HyperliquidityLevel>,
    pub usdc_seeded: Wei,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HyperliquidityLevel {
    pub price: RawPx,
    pub seeded: bool,
}

pub trait SpotDeployExternal {
    fn apply_forwarded_register_action(
        &mut self,
        state: &mut SpotDeployState,
        signer: Address,
        action: &ForwardedRegisterAction,
    ) -> Result<SpotDeploySuccess, SpotDeployFailure>;

    fn apply_decimal_token_mutation(
        &mut self,
        state: &mut SpotDeployState,
        signer: Address,
        action: &DecimalTokenMutation,
    ) -> Result<(), SpotDeployFailure>;

    fn disable_quote_token(
        &mut self,
        state: &mut SpotDeployState,
        token: Token,
    ) -> Result<(), SpotDeployFailure>;

    fn remove_user_orders_for_freeze(&mut self, token: Token, user: Address, spots: &[Spot]);
}

pub fn execute_spot_deploy<E: SpotDeployExternal>(
    state: &mut SpotDeployState,
    envelope: &SpotDeployEnvelope,
    external: &mut E,
) -> Result<SpotDeploySuccess, SpotDeployFailure> {
    if envelope.spot_deploy_disabled {
        return Err(SpotDeployFailure::status(STATUS_SPOT_DISABLED));
    }

    let signer_mode_allowed = match envelope.signer_class {
        SignerClass::Unknown => false,
        SignerClass::L1 | SignerClass::L2 => true,
        SignerClass::L3 => envelope.signer_gate_l3_enabled,
        SignerClass::L4 => envelope.signer_gate_l4_enabled,
    };
    if !signer_mode_allowed {
        return Err(SpotDeployFailure::status(STATUS_SIGNER_MODE_REJECTED));
    }

    match &envelope.action {
        SpotDeployAction::RegisterToken(action) | SpotDeployAction::RegisterToken2(action) => {
            let token = state.register_token(envelope.signer, action.clone())?;
            Ok(SpotDeploySuccess::CreatedToken(token))
        }
        SpotDeployAction::ForwardedRegisterAction(action) => {
            external.apply_forwarded_register_action(state, envelope.signer, action)
        }
        SpotDeployAction::ApplyGenesisBatch(action) => {
            state.apply_genesis_batch(action)?;
            Ok(SpotDeploySuccess::Applied)
        }
        SpotDeployAction::DecimalTokenMutation(action) => {
            external.apply_decimal_token_mutation(state, envelope.signer, action)?;
            Ok(SpotDeploySuccess::Applied)
        }
        SpotDeployAction::RegisterSpot(action) => {
            let spot = state.register_spot(action.clone())?;
            Ok(SpotDeploySuccess::CreatedSpot(spot))
        }
        SpotDeployAction::RegisterHyperliquidity(action) => {
            state.register_hyperliquidity(envelope.signer, action.clone())?;
            Ok(SpotDeploySuccess::Applied)
        }
        SpotDeployAction::RequestEvmContract(action) => {
            state.request_evm_contract(action.clone())?;
            Ok(SpotDeploySuccess::Applied)
        }
        SpotDeployAction::SetFullName { token, full_name } => {
            state.set_full_name(envelope.signer, *token, full_name.clone())?;
            Ok(SpotDeploySuccess::Applied)
        }
        SpotDeployAction::SetDeployerTradingFeeShare { token, share } => {
            state.set_deployer_trading_fee_share(envelope.signer, *token, *share)?;
            Ok(SpotDeploySuccess::Applied)
        }
        SpotDeployAction::EnableFreezePrivilege { token } => {
            state.enable_freeze_privilege(envelope.signer, *token)?;
            Ok(SpotDeploySuccess::Applied)
        }
        SpotDeployAction::FreezeUser { token, user, freeze } => {
            state.apply_freeze_update(envelope.signer, *token, *user, *freeze, external)?;
            Ok(SpotDeploySuccess::Applied)
        }
        SpotDeployAction::RevokeFreezePrivilege { token } => {
            state.revoke_freeze_privilege(envelope.signer, *token)?;
            Ok(SpotDeploySuccess::Applied)
        }
        SpotDeployAction::EnableQuoteToken { token } => {
            state.enable_quote_token(*token, envelope.now)?;
            Ok(SpotDeploySuccess::Applied)
        }
        SpotDeployAction::DisableQuoteToken { token } => {
            external.disable_quote_token(state, *token)?;
            Ok(SpotDeploySuccess::Applied)
        }
        SpotDeployAction::EnableAlignedQuoteToken { token } => {
            state.set_aligned_quote_token_enabled(*token, true, envelope.now)?;
            Ok(SpotDeploySuccess::Applied)
        }
        SpotDeployAction::DisableAlignedQuoteToken { token } => {
            state.set_aligned_quote_token_enabled(*token, false, envelope.now)?;
            Ok(SpotDeploySuccess::Applied)
        }
    }
}

impl SpotDeployState {
    fn register_token(&mut self, signer: Address, action: RegisterToken) -> Result<Token, SpotDeployFailure> {
        if self.token_id_to_token.contains_key(&action.token_id) {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "duplicate token id"));
        }
        if action.spec.name.len() > MAX_TOKEN_NAME_LEN || action.spec.sz_decimals > action.spec.wei_decimals || action.spec.wei_decimals > 10 {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "must have szDecimals <= weiDecimals <= 10"));
        }
        if action.max_supply >= MAX_TOKEN_MAX_SUPPLY {
            return Err(SpotDeployFailure::with_message(STATUS_OVERFLOW_GUARD, "max supply too large"));
        }
        if action.full_name.as_ref().is_some_and(|name| name.len() > MAX_TOKEN_FULL_NAME_LEN) {
            return Err(SpotDeployFailure::with_message(STATUS_NAME_TOO_LONG, "full name too long"));
        }
        let token = self.token_infos.len() as Token;
        self.token_id_to_token.insert(action.token_id, token);
        self.token_infos.push(TokenInfo {
            spec: action.spec,
            max_supply: action.max_supply,
            full_name: action.full_name,
            deployer_trading_fee_share: MAX_DEPLOYER_TRADING_FEE_SHARE,
            freeze_privilege_enabled: false,
            frozen_users: BTreeSet::new(),
            blacklist_users: BTreeSet::new(),
            evm_contract: None,
            deployer: Some(signer),
            spot_indices: Vec::new(),
            user_genesis_balances: Vec::new(),
            existing_token_genesis_balances: Vec::new(),
        });
        Ok(token)
    }

    fn apply_genesis_batch(&mut self, action: &GenesisBatch) -> Result<(), SpotDeployFailure> {
        self.require_token(action.token)?;
        if action.user_and_wei.len() > MAX_GENESIS_USERS || action.existing_token_and_wei.len() > MAX_ANCHOR_TOKENS {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "at most 10000 genesis users and 2 anchor tokens are allowed"));
        }
        if let Some(users) = &action.blacklist_users {
            if users.len() > MAX_BLACKLIST_USERS_TO_UPDATE {
                return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "blacklist users to update exceeds 1000"));
            }
            if !action.user_and_wei.is_empty() || !action.existing_token_and_wei.is_empty() {
                return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "cannot update blacklist users when either user_and_wei or existing_token_and_wei is non-empty"));
            }
            self.token_mut(action.token)?.blacklist_users.extend(users.iter().copied());
            return Ok(());
        }
        for entry in &action.user_and_wei {
            if self.protected_users.contains(&entry.user) {
                return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "vaults and subaccounts are not allowed in genesis"));
            }
            parse_decimal_u64(&entry.wei)?;
        }
        for entry in &action.existing_token_and_wei {
            parse_decimal_u64(&entry.wei)?;
        }
        {
            let token = self.token(action.token)?;
            if action.user_and_wei.iter().any(|entry| token.blacklist_users.contains(&entry.user)) {
                return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "cannot update token genesis balance for blacklisted user(s)"));
            }
        }
        let token = self.token_mut(action.token)?;
        token.user_genesis_balances.extend(action.user_and_wei.clone());
        token.existing_token_genesis_balances.extend(action.existing_token_and_wei.clone());
        Ok(())
    }

    fn register_spot(&mut self, action: RegisterSpot) -> Result<Spot, SpotDeployFailure> {
        let [base, quote] = action.tokens;
        if base == quote {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "cannot use same base and quote token"));
        }
        if base == USDC_TOKEN {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "cannot use USDC as base token"));
        }
        self.require_token(base)?;
        self.require_token(quote)?;
        if quote != USDC_TOKEN && !matches!(self.quote_token_status.get(&quote), Some(QuoteTokenStatus::Active)) {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "token is not quote token"));
        }
        if self.canonical_spots.contains_key(&[base, quote]) || self.canonical_spots.contains_key(&[quote, base]) {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "duplicate spot asset"));
        }
        let spot = self.spot_infos.len() as Spot;
        self.spot_infos.push(SpotInfo { name: action.name, tokens: action.tokens });
        self.canonical_spots.insert(action.tokens, spot);
        self.token_mut(base)?.spot_indices.push(spot);
        Ok(spot)
    }

    fn register_hyperliquidity(&mut self, signer: Address, action: RegisterHyperliquidity) -> Result<(), SpotDeployFailure> {
        let spot_info = self.spot(action.spot)?;
        let [base, quote] = spot_info.tokens;
        if quote != USDC_TOKEN {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "quote token must be USDC for Hyperliquidity"));
        }
        if self.hyperliquidity_books.contains_key(&action.spot) {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "Hyperliquidity already exists"));
        }
        if self.hyperliquidity_base_tokens.contains(&base) {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "Hyperliquidity already has token hold"));
        }
        let base_info = self.token(base)?;
        let quote_info = self.token(quote)?;
        if quote_info.spec.wei_decimals < base_info.spec.sz_decimals {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "invalid startPx_1"));
        }
        let start_px = parse_decimal_scaled(
            &action.start_px_1,
            quote_info.spec.wei_decimals - base_info.spec.sz_decimals,
            "invalid startPx_1",
        )?;
        if start_px == 0 {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "invalid startPx_1"));
        }
        let order_sz = parse_decimal_scaled(&action.order_sz_1, base_info.spec.sz_decimals, "invalid orderSz_1")?;
        let available_usdc = self.available_usdc.get(&signer).copied().unwrap_or(0);
        if available_usdc > MAX_REGISTER_HYPERLIQUIDITY_BALANCE {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "Could not convert USDC balance"));
        }
        if action.n_orders_1 > MAX_HYPERLIQUIDITY_ORDERS {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "too many Hyperliquidity orders"));
        }
        if action.n_seeded_levels > action.n_orders_1 {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "cannot seed more levels than exist"));
        }
        if action.n_orders_1 < MIN_HYPERLIQUIDITY_ORDERS {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "too few Hyperliquidity orders"));
        }
        if order_sz == 0 {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "zero Hyperliquidity order size"));
        }
        if base_info.max_supply == 0 {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "Hyperliquidity missing max supply"));
        }
        if base_info.max_supply.checked_mul(order_sz).is_none_or(|value| value > MAX_RAW_HYPERLIQUIDITY_VALUE) {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "Hyperliquidity configuration invalid"));
        }

        let mut levels = Vec::with_capacity(action.n_orders_1 as usize);
        let mut used_usdc_x100 = 0u64;
        let mut price = start_px;
        for idx in 0..action.n_orders_1 {
            if price == 0 || price > MAX_HYPERLIQUIDITY_PRICE_RAW {
                return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "Hyperliquidity price is invalid"));
            }
            let seeded = idx < action.n_seeded_levels;
            if seeded {
                let notional = price
                    .checked_mul(order_sz)
                    .ok_or(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "Hyperliquidity configuration invalid"))?;
                used_usdc_x100 = used_usdc_x100
                    .checked_add(notional / 10_000)
                    .ok_or(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "Hyperliquidity configuration invalid"))?;
            }
            levels.push(HyperliquidityLevel { price, seeded });
            price = ceil_scaled_price(price, HYPERLIQUIDITY_PRICE_RATIO).ok_or(SpotDeployFailure::with_message(
                STATUS_GENERIC_SPOT_DEPLOY_ERROR,
                "Hyperliquidity price is invalid",
            ))?;
        }
        let first = levels.first().map(|level| level.price).unwrap_or(0);
        let last = levels.last().map(|level| level.price).unwrap_or(0);
        if first == last {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "Hyperliquidity starting price too small"));
        }
        if first.checked_mul(order_sz).is_none_or(|value| value < 1_000_000) {
            return Err(SpotDeployFailure::with_message(
                STATUS_GENERIC_SPOT_DEPLOY_ERROR,
                "Hyperliquidity starting order value must be at least 1 USDC",
            ));
        }
        let start_cap = raw_market_cap_usdc(first, base_info.max_supply)?;
        let end_cap = raw_market_cap_usdc(last, base_info.max_supply)?;
        if start_cap > MAX_START_MARKET_CAP_USDC || end_cap < MIN_END_MARKET_CAP_USDC || end_cap > MAX_END_MARKET_CAP_USDC {
            return Err(SpotDeployFailure::with_message(
                STATUS_GENERIC_SPOT_DEPLOY_ERROR,
                "market cap must be in range [1B, 100B] USDC at Hyperliquidity end price and [0, 10M] USDC at Hyperliquidity start price",
            ));
        }
        if used_usdc_x100 > available_usdc.saturating_mul(100) {
            return Err(SpotDeployFailure::with_message(
                STATUS_GENERIC_SPOT_DEPLOY_ERROR,
                "insufficient usdc for seeding hyperliquidity",
            ));
        }
        let reserved = div_ceil_100(used_usdc_x100);
        let available = self.available_usdc.entry(signer).or_insert(0);
        if *available < reserved {
            return Err(SpotDeployFailure::with_message(
                STATUS_GENERIC_SPOT_DEPLOY_ERROR,
                "insufficient usdc for seeding hyperliquidity",
            ));
        }
        *available -= reserved;
        self.hyperliquidity_books.insert(
            action.spot,
            HyperliquidityBook {
                order_sz,
                levels,
                usdc_seeded: reserved,
            },
        );
        self.hyperliquidity_base_tokens.insert(base);
        Ok(())
    }

    fn request_evm_contract(&mut self, action: RequestEvmContract) -> Result<(), SpotDeployFailure> {
        self.require_token(action.token)?;
        if self
            .token_infos
            .iter()
            .any(|info| info.evm_contract.as_ref().is_some_and(|evm| evm.address == action.address))
        {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "Address is already used as EVM contract"));
        }
        if self.token(action.token)?.evm_contract.is_some() {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "evm contract already set"));
        }
        if !(-2..=18).contains(&action.evm_extra_wei_decimals) {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "EVM extra wei decimals must be between -2 and 18"));
        }
        self.pending_evm_contract_requests.insert(
            action.token,
            PendingEvmContract {
                address: action.address,
                evm_extra_wei_decimals: action.evm_extra_wei_decimals,
            },
        );
        Ok(())
    }

    fn set_full_name(&mut self, signer: Address, token: Token, full_name: String) -> Result<(), SpotDeployFailure> {
        if full_name.len() > MAX_TOKEN_FULL_NAME_LEN {
            return Err(SpotDeployFailure::with_message(STATUS_NAME_TOO_LONG, "full name too long"));
        }
        let token_info = self.token_mut_for_deployer(token, signer)?;
        token_info.full_name = Some(full_name);
        Ok(())
    }

    fn set_deployer_trading_fee_share(&mut self, signer: Address, token: Token, share: u64) -> Result<(), SpotDeployFailure> {
        if share > MAX_DEPLOYER_TRADING_FEE_SHARE {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "deployer trading fee share must be <= 100000"));
        }
        self.token_mut_for_deployer(token, signer)?.deployer_trading_fee_share = share;
        Ok(())
    }

    fn enable_freeze_privilege(&mut self, signer: Address, token: Token) -> Result<(), SpotDeployFailure> {
        let token = self.token_mut_for_deployer(token, signer)?;
        token.freeze_privilege_enabled = true;
        token.frozen_users.clear();
        Ok(())
    }

    fn apply_freeze_update<E: SpotDeployExternal>(
        &mut self,
        signer: Address,
        token: Token,
        user: Address,
        freeze: bool,
        external: &mut E,
    ) -> Result<(), SpotDeployFailure> {
        let token_info = self.token_mut_for_deployer(token, signer)?;
        if !token_info.freeze_privilege_enabled {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "already revoked token freeze privilege"));
        }
        if !freeze {
            token_info.frozen_users.remove(&user);
            return Ok(());
        }
        if token_info.frozen_users.len() >= MAX_FROZEN_USERS {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "number of frozen users capped at 1000"));
        }
        token_info.frozen_users.insert(user);
        let spots = token_info.spot_indices.clone();
        external.remove_user_orders_for_freeze(token, user, &spots);
        Ok(())
    }

    fn revoke_freeze_privilege(&mut self, signer: Address, token: Token) -> Result<(), SpotDeployFailure> {
        let token_info = self.token_mut_for_deployer(token, signer)?;
        if token_info.freeze_privilege_enabled && !token_info.frozen_users.is_empty() {
            return Err(SpotDeployFailure::with_message(
                STATUS_GENERIC_SPOT_DEPLOY_ERROR,
                "cannot revoke token freeze privilege when there are frozen users",
            ));
        }
        token_info.freeze_privilege_enabled = false;
        token_info.frozen_users.clear();
        Ok(())
    }

    fn enable_quote_token(&mut self, token: Token, now: Time) -> Result<(), SpotDeployFailure> {
        let info = self.token(token)?;
        if info.spec.wei_decimals != 8 || !self.token_has_usdc_pair(token) {
            return Err(SpotDeployFailure::with_message(239, "invalid quote token"));
        }
        if info.deployer_trading_fee_share != 0 {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "quote token deployer trading fee share must be 0"));
        }
        if matches!(self.quote_token_status.get(&token), Some(QuoteTokenStatus::Disabled)) {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "quote token not allowed"));
        }
        self.quote_token_status.insert(token, QuoteTokenStatus::Active);
        self.aligned_quote_tokens.entry(token).or_insert(AlignedQuoteTokenInfo {
            first_enabled_time: now,
            active: false,
        });
        Ok(())
    }

    fn set_aligned_quote_token_enabled(&mut self, token: Token, enabled: bool, now: Time) -> Result<(), SpotDeployFailure> {
        if enabled {
            if !matches!(self.quote_token_status.get(&token), Some(QuoteTokenStatus::Active)) {
                return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "token is not quote token"));
            }
            let info = self.aligned_quote_tokens.entry(token).or_insert(AlignedQuoteTokenInfo {
                first_enabled_time: now,
                active: false,
            });
            info.active = true;
            if info.first_enabled_time == 0 {
                info.first_enabled_time = now;
            }
            Ok(())
        } else {
            if !matches!(self.quote_token_status.get(&token), Some(QuoteTokenStatus::Disabled)) {
                return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "quote token not disabled"));
            }
            if let Some(info) = self.aligned_quote_tokens.get_mut(&token) {
                info.active = false;
            }
            Ok(())
        }
    }

    fn token(&self, token: Token) -> Result<&TokenInfo, SpotDeployFailure> {
        self.token_infos
            .get(token as usize)
            .ok_or_else(|| SpotDeployFailure::status(STATUS_TOKEN_OR_SPOT_NOT_FOUND))
    }

    fn token_mut(&mut self, token: Token) -> Result<&mut TokenInfo, SpotDeployFailure> {
        self.token_infos
            .get_mut(token as usize)
            .ok_or_else(|| SpotDeployFailure::status(STATUS_TOKEN_OR_SPOT_NOT_FOUND))
    }

    fn token_mut_for_deployer(&mut self, token: Token, signer: Address) -> Result<&mut TokenInfo, SpotDeployFailure> {
        let token_info = self.token_mut(token)?;
        if token_info.deployer != Some(signer) {
            return Err(SpotDeployFailure::with_message(STATUS_TOKEN_OR_SPOT_NOT_FOUND, "deployer mismatch"));
        }
        Ok(token_info)
    }

    fn require_token(&self, token: Token) -> Result<(), SpotDeployFailure> {
        self.token(token).map(|_| ())
    }

    fn spot(&self, spot: Spot) -> Result<&SpotInfo, SpotDeployFailure> {
        self.spot_infos
            .get(spot as usize)
            .ok_or_else(|| SpotDeployFailure::status(STATUS_TOKEN_OR_SPOT_NOT_FOUND))
    }

    fn token_has_usdc_pair(&self, token: Token) -> bool {
        self.token_infos
            .get(token as usize)
            .is_some_and(|info| info.spot_indices.iter().any(|spot| self.spot_infos[*spot as usize].tokens[1] == USDC_TOKEN))
    }
}

fn parse_decimal_u64(input: &str) -> Result<u64, SpotDeployFailure> {
    if input.is_empty() || input.len() > 100 || matches!(input.as_bytes()[0], b'+' | b'-') {
        return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "invalid wei"));
    }
    let mut value = 0u64;
    for byte in input.bytes() {
        if !byte.is_ascii_digit() {
            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "invalid wei"));
        }
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add((byte - b'0') as u64))
            .ok_or_else(|| SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "invalid wei"))?;
    }
    Ok(value)
}

fn parse_decimal_scaled(input: &str, decimals: u8, message: &'static str) -> Result<u64, SpotDeployFailure> {
    if input.is_empty() || matches!(input.as_bytes()[0], b'+' | b'-') {
        return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, message));
    }
    let mut value = 0u64;
    let mut seen_fraction = false;
    let mut scale = 0u8;
    for byte in input.bytes() {
        match byte {
            b'0'..=b'9' => {
                if seen_fraction {
                    if scale == decimals {
                        if byte != b'0' {
                            return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, message));
                        }
                        continue;
                    }
                    scale += 1;
                }
                value = value
                    .checked_mul(10)
                    .and_then(|v| v.checked_add((byte - b'0') as u64))
                    .ok_or_else(|| SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, message))?;
            }
            b'.' if !seen_fraction => seen_fraction = true,
            _ => return Err(SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, message)),
        }
    }
    while scale < decimals {
        value = value
            .checked_mul(10)
            .ok_or_else(|| SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, message))?;
        scale += 1;
    }
    Ok(value)
}

fn ceil_scaled_price(price: RawPx, ratio: f64) -> Option<RawPx> {
    let value = (price as f64) * ratio;
    if !value.is_finite() || value < 0.0 || value > u64::MAX as f64 {
        None
    } else {
        Some(value.ceil() as u64)
    }
}

fn raw_market_cap_usdc(price: RawPx, supply: Wei) -> Result<u64, SpotDeployFailure> {
    let raw = (price as u128)
        .checked_mul(supply as u128)
        .ok_or_else(|| SpotDeployFailure::with_message(STATUS_GENERIC_SPOT_DEPLOY_ERROR, "Hyperliquidity configuration invalid"))?;
    let usdc = raw / 100_000_000;
    if usdc > u64::MAX as u128 {
        return Err(SpotDeployFailure::with_message(
            STATUS_GENERIC_SPOT_DEPLOY_ERROR,
            "market cap must be in range [1B, 100B] USDC at Hyperliquidity end price and [0, 10M] USDC at Hyperliquidity start price",
        ));
    }
    Ok(usdc as u64)
}

fn div_ceil_100(value: u64) -> u64 {
    value / 100 + u64::from(value % 100 != 0)
}
