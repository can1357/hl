use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub type Token = u64;
pub type Spot = u64;
pub type Wei = u64;
pub type Px = u64;
pub type Time = u64;

pub const USDC_TOKEN: Token = 0;
pub const FIRST_NON_USDC_SPOT_TOKEN: Token = 1;
pub const MAX_SPOTS: usize = 10_000;
pub const MAX_TOKEN_NAME_LEN: usize = 100;
pub const MAX_TOKEN_FULL_NAME_LEN: usize = 100;
pub const MAX_N_FROZEN_USERS: usize = 1_000;
pub const MAX_BLACKLIST_USERS_TO_UPDATE: usize = 1_000;
pub const MAX_GENESIS_USERS: usize = 10_000;
pub const MAX_ANCHOR_TOKENS: usize = 2;
pub const MAX_DECIMAL_STRING_LEN: usize = 100;
pub const MAX_DEPLOYER_TRADING_FEE_SHARE: u64 = 100_000;
pub const MAX_TOKEN_MAX_SUPPLY: Wei = 0x0ccc_cccc_cccc_cccc;

#[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct Address(pub [u8; 20]);

impl Address {
    pub const ZERO: Self = Self([0; 20]);

    pub const fn is_zero(&self) -> bool {
        let mut i = 0;
        while i < 20 {
            if self.0[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct TokenId(pub [u8; 16]);

impl fmt::Debug for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct TokenName(String);

impl TokenName {
    pub fn new(name: String) -> Result<Self, SpotMetaError> {
        if name.len() > MAX_TOKEN_NAME_LEN {
            return Err(SpotMetaError::NameTooLong);
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<&str> for TokenName {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Display for TokenName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenSpec {
    pub name: TokenName,
    pub sz_decimals: u8,
    pub wei_decimals: u8,
}

impl TokenSpec {
    pub fn validate(&self) -> Result<(), SpotMetaError> {
        if self.name.as_str().len() > MAX_TOKEN_NAME_LEN {
            return Err(SpotMetaError::NameTooLong);
        }
        if self.sz_decimals > self.wei_decimals || self.wei_decimals > 10 {
            // Recovered diagnostic at 0x599ADE, used by token creation at 0x4d72500/0x4d727c0.
            return Err(SpotMetaError::InvalidDecimals);
        }
        Ok(())
    }

    pub fn unit_scale(&self) -> u64 {
        pow10_u64((self.wei_decimals - self.sz_decimals) as u32)
            .expect("szDecimals <= weiDecimals and exponent fits u64")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmContractInfo {
    pub address: Address,
    pub evm_extra_wei_decimals: i8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserAndWei {
    pub user: Address,
    pub wei: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExistingTokenAndWei {
    pub token: Token,
    pub wei: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlacklistUpdate {
    pub users: Vec<Address>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlignedQuoteTokenInfo {
    pub evm_minted_supply: Wei,
    pub daily_wei_owed: Vec<Wei>,
    pub first_aligned_time: Time,
    pub active: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlignedQuoteTokenConfig {
    pub cross_scale: u64,
    pub add_rebate_scale: u64,
    pub vlm_contribution_scale: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum QuoteTokenStatus {
    Active = 0,
    Disabled = 1,
    Unknown(u8),
}

impl QuoteTokenStatus {
    pub const fn from_byte(value: u8) -> Self {
        match value {
            0 => Self::Active,
            1 => Self::Disabled,
            other => Self::Unknown(other),
        }
    }

    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::Disabled => 1,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpotInfo {
    pub name: String,
    pub tokens: [Token; 2],
}

impl SpotInfo {
    pub const fn base(&self) -> Token {
        self.tokens[0]
    }

    pub const fn quote(&self) -> Token {
        self.tokens[1]
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenInfo {
    pub spec: TokenSpec,
    pub full_name: Option<String>,
    pub max_supply: Wei,
    pub spot_indices: Vec<Spot>,
    pub deployer_trading_fee_share: u64,
    pub max_supply_after_genesis: Wei,
    pub hyperliquidity_genesis_balance: f64,
    pub total_genesis_balance_wei: Wei,
    pub user_genesis_balances: Vec<UserAndWei>,
    pub existing_token_genesis_balances: Vec<ExistingTokenAndWei>,
    pub blacklist_users: BTreeSet<Address>,
    pub freeze_privilege_enabled: bool,
    pub frozen_users: BTreeSet<Address>,
    pub evm_contract: Option<EvmContractInfo>,
    pub deployer: Option<Address>,
    pub is_canonical: bool,
}

impl TokenInfo {
    pub fn new(spec: TokenSpec, max_supply: Wei, full_name: Option<String>) -> Result<Self, SpotMetaError> {
        spec.validate()?;
        if max_supply >= MAX_TOKEN_MAX_SUPPLY {
            return Err(SpotMetaError::MaxSupplyTooLarge(max_supply));
        }
        if full_name.as_ref().is_some_and(|name| name.len() > MAX_TOKEN_FULL_NAME_LEN) {
            return Err(SpotMetaError::FullNameTooLong);
        }
        Ok(Self {
            spec,
            full_name,
            max_supply,
            spot_indices: Vec::new(),
            deployer_trading_fee_share: MAX_DEPLOYER_TRADING_FEE_SHARE,
            max_supply_after_genesis: max_supply,
            hyperliquidity_genesis_balance: 0.0,
            total_genesis_balance_wei: 0,
            user_genesis_balances: Vec::new(),
            existing_token_genesis_balances: Vec::new(),
            blacklist_users: BTreeSet::new(),
            freeze_privilege_enabled: false,
            frozen_users: BTreeSet::new(),
            evm_contract: None,
            deployer: None,
            is_canonical: true,
        })
    }

    pub fn wei_decimals(&self) -> u8 {
        self.spec.wei_decimals
    }

    pub fn sz_decimals(&self) -> u8 {
        self.spec.sz_decimals
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SpotMeta {
    pub spot_infos: Vec<SpotInfo>,
    pub token_infos: Vec<TokenInfo>,
    pub token_id_to_token: BTreeMap<TokenId, Token>,
    pub canonical_tokens2: BTreeMap<[Token; 2], Spot>,
    pub allow_duplicate_token_names: bool,
    pub token_to_approx_usdc_pxs: BTreeMap<Token, Px>,
    pub liquid_base_tokens: BTreeSet<Token>,
    pub token_name_to_canonical_deployer: BTreeMap<TokenName, Address>,
    pub token_to_first_time_enabled_as_quote: BTreeMap<Token, Time>,
    pub quote_token_to_aligned_quote_token_info: BTreeMap<Token, AlignedQuoteTokenInfo>,
    pub liquid_quote_tokens: BTreeSet<Token>,
    pub quote_token_to_status: BTreeMap<Token, QuoteTokenStatus>,
    pub pending_evm_contract_requests: BTreeMap<Token, PendingEvmContract>,
    pub usdc_evm_escrow_balance: Wei,
}

impl SpotMeta {
    pub fn token(&self, token: Token) -> &TokenInfo {
        self.token_infos.get(token as usize).expect("token index in bounds")
    }

    pub fn token_mut(&mut self, token: Token) -> &mut TokenInfo {
        self.token_infos.get_mut(token as usize).expect("token index in bounds")
    }

    pub fn create_token_from_spec(
        &mut self,
        token_id: TokenId,
        spec: TokenSpec,
        max_supply: Wei,
        full_name: Option<String>,
    ) -> Result<Token, SpotMetaError> {
        if self.token_id_to_token.contains_key(&token_id) {
            return Err(SpotMetaError::DuplicateTokenId);
        }
        let index = self.token_infos.len() as Token;
        let token = TokenInfo::new(spec, max_supply, full_name)?;
        self.token_id_to_token.insert(token_id, index);
        self.token_infos.push(token);
        Ok(index)
    }

    pub fn token_name_string(&self, token: Token) -> String {
        // 0x375fd30 synthesizes literal USDC for token 0; non-zero tokens clone record +56/+64.
        if token == USDC_TOKEN {
            "USDC".to_owned()
        } else {
            self.token(token).spec.name.as_str().to_owned()
        }
    }

    pub fn register_spot_pair(&mut self, name: String, tokens: [Token; 2]) -> Result<Spot, SpotMetaError> {
        // 0x375eeb0 caps spot ids at 9_999 and stores 32-byte records: base, quote, compact name.
        let spot = self.spot_infos.len();
        if spot >= MAX_SPOTS {
            return Err(SpotMetaError::TooManySpots);
        }
        let [base, quote] = tokens;
        if base == quote {
            return Err(SpotMetaError::CannotUseSameBaseAndQuote);
        }
        if base == USDC_TOKEN {
            return Err(SpotMetaError::CannotUseUsdcAsBaseToken);
        }
        if !self.quote_token_is_enabled_for_pair(quote) {
            return Err(SpotMetaError::TokenIsNotQuoteToken);
        }
        if self.spot_infos.iter().any(|spot_info| {
            let existing = spot_info.tokens;
            existing == [base, quote] || existing == [quote, base]
        }) {
            return Err(SpotMetaError::DuplicateSpotAsset);
        }
        if spot == 0 && (base != FIRST_NON_USDC_SPOT_TOKEN || self.token(base).spec.name.as_str() != "PURR") {
            return Err(SpotMetaError::UnexpectedFirstSpotAsset);
        }

        let spot = spot as Spot;
        self.spot_infos.push(SpotInfo { name, tokens });
        self.token_mut(base).spot_indices.push(spot);
        self.canonical_tokens2.insert(tokens, spot);
        Ok(spot)
    }

    pub fn token_has_spot_pair_with_quote(&self, base: Token, quote: Token) -> bool {
        // 0x375e430 scans base token spot_indices and compares each spot record's quote token.
        self.token(base)
            .spot_indices
            .iter()
            .any(|&spot| self.spot_infos[spot as usize].quote() == quote)
    }

    pub fn token_has_usdc_pair(&self, token: Token) -> bool {
        // 0x3760070 is the same scan hard-coded to quote token 0.
        self.token_has_spot_pair_with_quote(token, USDC_TOKEN)
    }

    pub fn token_has_only_quote_pair(&self, token: Token, quote: Token) -> bool {
        // 0x37604d0 returns true for no pairs, or exactly one pair with the requested quote.
        let spots = &self.token(token).spot_indices;
        match spots.as_slice() {
            [] => true,
            [spot] => self.spot_infos[*spot as usize].quote() == quote,
            _ => false,
        }
    }

    pub fn quote_token_is_enabled_for_pair(&self, token: Token) -> bool {
        token == USDC_TOKEN || matches!(self.quote_token_to_status.get(&token), Some(QuoteTokenStatus::Active))
    }

    pub fn wei_scale_to_usdc_decimals(&self, token: Token) -> u64 {
        // 0x375fb50 computes 10^(USDC.weiDecimals - token.szDecimals), panicking on underflow/overflow.
        let usdc_wei = self.token(USDC_TOKEN).wei_decimals();
        let token_sz = self.token(token).sz_decimals();
        let exponent = usdc_wei.checked_sub(token_sz).expect("USDC weiDecimals >= token szDecimals");
        pow10_u64(exponent as u32).expect("decimal exponent fits u64")
    }

    pub fn scaled_wei_mul_fits_u64(&self, token: Token, amount: Wei) -> bool {
        // 0x37606b0 checks amount * 10^(weiDecimals - szDecimals) with a u128 multiply.
        let token = self.token(token);
        let exponent = token.wei_decimals().checked_sub(token.sz_decimals()).expect("weiDecimals >= szDecimals");
        let Some(scale) = pow10_u64(exponent as u32) else {
            panic!("decimal scale overflow")
        };
        (scale as u128 * amount as u128) <= u64::MAX as u128
    }

    pub fn enable_quote_token_registry(
        &mut self,
        token: Token,
        first_enabled_time: Time,
        allow_previously_disabled: bool,
    ) -> Result<(), SpotMetaError> {
        // 0x375fe00 requires 8 wei decimals, a USDC spot, and zero deployer fee share.
        let info = self.token(token);
        if info.wei_decimals() != 8 || !self.token_has_usdc_pair(token) {
            return Err(SpotMetaError::InvalidQuoteToken);
        }
        if info.deployer_trading_fee_share != 0 {
            return Err(SpotMetaError::QuoteTokenDeployerFeeShareMustBeZero);
        }
        if !allow_previously_disabled && matches!(self.quote_token_to_status.get(&token), Some(QuoteTokenStatus::Disabled)) {
            return Err(SpotMetaError::QuoteTokenNotAllowed);
        }
        self.quote_token_to_status.insert(token, QuoteTokenStatus::Active);
        self.token_to_first_time_enabled_as_quote.entry(token).or_insert(first_enabled_time);
        Ok(())
    }

    pub fn set_aligned_quote_token_enabled(
        &mut self,
        token: Token,
        enabled: bool,
        time: Time,
    ) -> Result<(), SpotMetaError> {
        // 0x274db00: enabling requires quote-token registry membership; disabling requires Disabled status.
        if enabled {
            if !matches!(self.quote_token_to_status.get(&token), Some(QuoteTokenStatus::Active)) {
                return Err(SpotMetaError::TokenIsNotQuoteToken);
            }
            let info = self.quote_token_to_aligned_quote_token_info.entry(token).or_insert_with(|| AlignedQuoteTokenInfo {
                evm_minted_supply: 0,
                daily_wei_owed: Vec::new(),
                first_aligned_time: time,
                active: false,
            });
            info.active = true;
            if info.first_aligned_time == 0 {
                info.first_aligned_time = time;
            }
            Ok(())
        } else {
            if !matches!(self.quote_token_to_status.get(&token), Some(QuoteTokenStatus::Disabled)) {
                return Err(SpotMetaError::QuoteTokenNotDisabled);
            }
            if let Some(info) = self.quote_token_to_aligned_quote_token_info.get_mut(&token) {
                info.active = false;
            }
            Ok(())
        }
    }

    pub fn request_token_evm_contract(
        &mut self,
        token: Token,
        address: Address,
        evm_extra_wei_decimals: i8,
    ) -> Result<(), SpotMetaError> {
        // 0x4d64ba0 rejects duplicate addresses, already-bound tokens, and deltas outside [-2, 18].
        if self.token_infos.iter().any(|info| info.evm_contract.as_ref().is_some_and(|evm| evm.address == address)) {
            return Err(SpotMetaError::AddressAlreadyUsedAsEvmContract);
        }
        if self.token(token).evm_contract.is_some() {
            return Err(SpotMetaError::EvmContractAlreadySet);
        }
        if !(-2..=18).contains(&evm_extra_wei_decimals) {
            return Err(SpotMetaError::InvalidEvmExtraWeiDecimals);
        }
        self.pending_evm_contract_requests.insert(token, PendingEvmContract { address, evm_extra_wei_decimals });
        Ok(())
    }

    pub fn finalize_token_evm_contract(&mut self, token: Token, proof: StorageSlotProof) -> Result<(), SpotMetaError> {
        // 0x4d64de0 removes a pending request after checking first/custom storage-slot proofs.
        let pending = self
            .pending_evm_contract_requests
            .get(&token)
            .copied()
            .ok_or(SpotMetaError::PendingEvmContractNotFound)?;
        if self.token_infos.iter().any(|info| info.evm_contract.as_ref().is_some_and(|evm| evm.address == pending.address)) {
            return Err(SpotMetaError::AddressAlreadyUsedAsEvmContract);
        }
        if self.token(token).evm_contract.is_some() {
            return Err(SpotMetaError::EvmContractAlreadySet);
        }
        if !proof.valid_for(pending.address, token) {
            return Err(match proof.kind {
                StorageSlotProofKind::FirstSlot => SpotMetaError::FirstStorageSlotProofMismatch,
                StorageSlotProofKind::CustomSlot => SpotMetaError::CustomStorageSlotProofMismatch,
            });
        }
        self.token_mut(token).evm_contract = Some(EvmContractInfo {
            address: pending.address,
            evm_extra_wei_decimals: pending.evm_extra_wei_decimals,
        });
        self.pending_evm_contract_requests.remove(&token);
        Ok(())
    }

    pub fn set_usdc_evm_contract(&mut self, address: Address, escrow_balance: Wei) -> Result<(), SpotMetaError> {
        // 0x4d6a340 treats zero address as unsetting USDC's EVM contract and moves escrow balances back.
        if address.is_zero() {
            if self.usdc_evm_escrow_balance > escrow_balance {
                return Err(SpotMetaError::UnableToUnsetUsdcEvmContract);
            }
            self.token_mut(USDC_TOKEN).evm_contract = None;
            self.usdc_evm_escrow_balance = 0;
            return Ok(());
        }
        if self.token_infos.iter().any(|info| info.evm_contract.as_ref().is_some_and(|evm| evm.address == address)) {
            return Err(SpotMetaError::AddressAlreadyUsedAsEvmContract);
        }
        if self.usdc_evm_escrow_balance != 0 {
            return Err(SpotMetaError::MustUnsetUsdcEvmContractFirst);
        }
        self.token_mut(USDC_TOKEN).evm_contract = Some(EvmContractInfo {
            address,
            evm_extra_wei_decimals: -2,
        });
        self.usdc_evm_escrow_balance = u64::MAX / 2;
        Ok(())
    }

    pub fn enable_token_freeze_privilege(&mut self, token: Token) {
        // 0x274f9a0 clears the frozen-user set and sets lifecycle_state/freeze flag to 1.
        let token = self.token_mut(token);
        token.freeze_privilege_enabled = true;
        token.frozen_users.clear();
    }

    pub fn apply_user_freeze_update<H: FreezeHooks>(
        &mut self,
        token: Token,
        user: Address,
        freeze: bool,
        hooks: &mut H,
    ) -> Result<(), SpotMetaError> {
        // 0x274b550 adds/removes from a per-token BTreeSet. On freeze it clones spot_indices,
        // removes user orders from each affected book, emits book deltas, and forwards events.
        let token_info = self.token_mut(token);
        if !token_info.freeze_privilege_enabled {
            return Err(SpotMetaError::AlreadyRevokedTokenFreezePrivilege);
        }
        if !freeze {
            token_info.frozen_users.remove(&user);
            return Ok(());
        }
        if token_info.frozen_users.len() >= MAX_N_FROZEN_USERS {
            return Err(SpotMetaError::TooManyFrozenUsers);
        }
        token_info.frozen_users.insert(user);
        let affected_spots = token_info.spot_indices.clone();
        for spot in affected_spots {
            hooks.remove_user_orders_for_freeze(spot, user);
            hooks.emit_freeze_book_delta(spot, user);
        }
        Ok(())
    }

    pub fn revoke_token_freeze_privilege(&mut self, token: Token) -> Result<(), SpotMetaError> {
        // 0x27506c0 refuses revocation while frozen_users is non-empty.
        let token_info = self.token_mut(token);
        if token_info.freeze_privilege_enabled && !token_info.frozen_users.is_empty() {
            return Err(SpotMetaError::CannotRevokeTokenFreezePrivilegeWithFrozenUsers);
        }
        token_info.freeze_privilege_enabled = false;
        token_info.frozen_users.clear();
        Ok(())
    }

    pub fn validate_genesis_blacklist_update(
        &self,
        token: Token,
        user_and_wei: &[UserAndWei],
        existing_token_and_wei: &[ExistingTokenAndWei],
        blacklist_update: Option<&BlacklistUpdate>,
    ) -> Result<(), SpotMetaError> {
        // 0x371fda0 separates blacklist-only updates from genesis-balance updates.
        if let Some(update) = blacklist_update {
            if update.users.len() > MAX_BLACKLIST_USERS_TO_UPDATE {
                return Err(SpotMetaError::BlacklistUsersToUpdateExceedsLimit);
            }
            if !user_and_wei.is_empty() || !existing_token_and_wei.is_empty() {
                return Err(SpotMetaError::BlacklistUpdateCannotIncludeGenesisBalances);
            }
            return Ok(());
        }
        let blacklist = &self.token(token).blacklist_users;
        if user_and_wei.iter().any(|entry| blacklist.contains(&entry.user)) {
            return Err(SpotMetaError::GenesisBalanceForBlacklistedUser);
        }
        Ok(())
    }

    pub fn apply_user_genesis(
        &mut self,
        token: Token,
        user_and_wei: Vec<UserAndWei>,
        existing_token_and_wei: Vec<ExistingTokenAndWei>,
        blacklist_update: Option<BlacklistUpdate>,
        protected_users: &BTreeSet<Address>,
    ) -> Result<(), SpotMetaError> {
        // 0x274e430 rejects vault/subaccount users, string amounts longer than 100 bytes,
        // more than 10_000 users, and more than 2 anchor-token entries.
        if user_and_wei.len() > MAX_GENESIS_USERS || existing_token_and_wei.len() > MAX_ANCHOR_TOKENS {
            return Err(SpotMetaError::TooManyGenesisUsersOrAnchorTokens);
        }
        for entry in &user_and_wei {
            if protected_users.contains(&entry.user) {
                return Err(SpotMetaError::VaultsAndSubaccountsNotAllowedInGenesis);
            }
            parse_decimal_wei(&entry.wei)?;
        }
        for entry in &existing_token_and_wei {
            parse_decimal_wei(&entry.wei)?;
        }
        self.validate_genesis_blacklist_update(token, &user_and_wei, &existing_token_and_wei, blacklist_update.as_ref())?;
        if let Some(update) = blacklist_update {
            self.token_mut(token).blacklist_users.extend(update.users);
        } else {
            let total = user_and_wei
                .iter()
                .try_fold(0u64, |acc, entry| acc.checked_add(parse_decimal_wei(&entry.wei)?).ok_or(SpotMetaError::InvalidWei))?;
            let token_info = self.token_mut(token);
            token_info.total_genesis_balance_wei = token_info
                .total_genesis_balance_wei
                .checked_add(total)
                .ok_or(SpotMetaError::InvalidWei)?;
            token_info.user_genesis_balances.extend(user_and_wei);
            token_info.existing_token_genesis_balances.extend(existing_token_and_wei);
        }
        Ok(())
    }

    pub fn to_api(&self, include_debug_details: bool) -> SpotMetaResponse {
        // 0x2a28430 serializes a two-field map: universe, then tokens.
        let universe = self
            .spot_infos
            .iter()
            .enumerate()
            .map(|(index, spot)| SpotPairMeta {
                name: spot.name.clone(),
                tokens: spot.tokens,
                index: index as u64,
                is_canonical: self.canonical_tokens2.get(&spot.tokens).copied() == Some(index as u64),
            })
            .collect();
        let tokens = self
            .token_infos
            .iter()
            .enumerate()
            .map(|(index, token)| {
                let token_id = self.token_id_to_token.iter().find_map(|(token_id, &mapped)| (mapped == index as u64).then_some(*token_id));
                SpotTokenDetails {
                    name: if index == 0 { TokenName::from("USDC") } else { token.spec.name.clone() },
                    sz_decimals: token.spec.sz_decimals,
                    wei_decimals: token.spec.wei_decimals,
                    index: index as u64,
                    token_id: token_id.unwrap_or_default().to_string(),
                    is_canonical: token.is_canonical,
                    evm_contract: token.evm_contract.as_ref().map(|info| info.address),
                    full_name: token.full_name.clone(),
                    deployer_trading_fee_share: token.deployer_trading_fee_share as f64 / MAX_DEPLOYER_TRADING_FEE_SHARE as f64,
                    debug_details: include_debug_details.then(|| SpotTokenDebugDetails {
                        max_supply: token.max_supply,
                        deployer: token.deployer,
                        evm_extra_wei_decimals: token.evm_contract.as_ref().map(|info| info.evm_extra_wei_decimals),
                        n_spots: token.spot_indices.len() as u64,
                    }),
                }
            })
            .collect();
        SpotMetaResponse { universe, tokens }
    }
}

pub trait FreezeHooks {
    fn remove_user_orders_for_freeze(&mut self, spot: Spot, user: Address);
    fn emit_freeze_book_delta(&mut self, spot: Spot, user: Address);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingEvmContract {
    pub address: Address,
    pub evm_extra_wei_decimals: i8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageSlotProofKind {
    FirstSlot,
    CustomSlot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageSlotProof {
    pub kind: StorageSlotProofKind,
    pub contract: Address,
    pub token: Token,
    pub matched_storage_value: bool,
}

impl StorageSlotProof {
    pub fn valid_for(self, contract: Address, token: Token) -> bool {
        self.contract.0 == contract.0 && self.token == token && self.matched_storage_value
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotMetaResponse {
    pub universe: Vec<SpotPairMeta>,
    pub tokens: Vec<SpotTokenDetails>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotPairMeta {
    pub name: String,
    pub tokens: [Token; 2],
    pub index: u64,
    pub is_canonical: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotTokenDetails {
    pub name: TokenName,
    pub sz_decimals: u8,
    pub wei_decimals: u8,
    pub index: u64,
    pub token_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_contract: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    pub deployer_trading_fee_share: f64,
    pub is_canonical: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_details: Option<SpotTokenDebugDetails>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotTokenDebugDetails {
    pub max_supply: Wei,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployer: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_extra_wei_decimals: Option<i8>,
    pub n_spots: u64,
}

pub fn token_spec_unit_scale(spec: &TokenSpec) -> u64 {
    spec.unit_scale()
}

pub fn evm_amount_to_internal_wei(amount: Wei, evm_extra_wei_decimals: i8) -> Result<Wei, SpotMetaError> {
    // The EVM paths use a signed decimal delta at token record +209.
    if evm_extra_wei_decimals >= 0 {
        let scale = pow10_u64(evm_extra_wei_decimals as u32).ok_or(SpotMetaError::InvalidEvmExtraWeiDecimals)?;
        amount.checked_mul(scale).ok_or(SpotMetaError::InvalidWei)
    } else {
        let divisor = pow10_u64((-evm_extra_wei_decimals) as u32).ok_or(SpotMetaError::InvalidEvmExtraWeiDecimals)?;
        if amount % divisor != 0 {
            return Err(SpotMetaError::NonIntegralTokenAmount);
        }
        Ok(amount / divisor)
    }
}

pub fn parse_decimal_wei(input: &str) -> Result<Wei, SpotMetaError> {
    // 0x274e430 parses unsigned decimal strings, rejects sign-only/sign-prefixed and len > 100.
    if input.is_empty() || input.len() > MAX_DECIMAL_STRING_LEN {
        return Err(SpotMetaError::InvalidWei);
    }
    let bytes = input.as_bytes();
    if bytes[0] == b'+' || bytes[0] == b'-' {
        return Err(SpotMetaError::InvalidWei);
    }
    let mut value = 0u64;
    for &byte in bytes {
        let digit = byte.wrapping_sub(b'0');
        if digit > 9 {
            return Err(SpotMetaError::InvalidWei);
        }
        value = value.checked_mul(10).and_then(|v| v.checked_add(digit as u64)).ok_or(SpotMetaError::InvalidWei)?;
    }
    Ok(value)
}

pub fn pow10_u64(exponent: u32) -> Option<u64> {
    let mut acc = 1u64;
    let mut i = 0;
    while i < exponent {
        acc = acc.checked_mul(10)?;
        i += 1;
    }
    Some(acc)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SpotMetaError {
    NameTooLong,
    FullNameTooLong,
    InvalidDecimals,
    MaxSupplyTooLarge(Wei),
    DuplicateTokenId,
    TooManySpots,
    CannotUseSameBaseAndQuote,
    CannotUseUsdcAsBaseToken,
    TokenIsNotQuoteToken,
    DuplicateSpotAsset,
    UnexpectedFirstSpotAsset,
    InvalidQuoteToken,
    QuoteTokenDeployerFeeShareMustBeZero,
    QuoteTokenNotAllowed,
    QuoteTokenNotDisabled,
    AddressAlreadyUsedAsEvmContract,
    EvmContractAlreadySet,
    InvalidEvmExtraWeiDecimals,
    PendingEvmContractNotFound,
    FirstStorageSlotProofMismatch,
    CustomStorageSlotProofMismatch,
    UnableToUnsetUsdcEvmContract,
    MustUnsetUsdcEvmContractFirst,
    AlreadyRevokedTokenFreezePrivilege,
    TooManyFrozenUsers,
    CannotRevokeTokenFreezePrivilegeWithFrozenUsers,
    BlacklistUsersToUpdateExceedsLimit,
    BlacklistUpdateCannotIncludeGenesisBalances,
    GenesisBalanceForBlacklistedUser,
    TooManyGenesisUsersOrAnchorTokens,
    VaultsAndSubaccountsNotAllowedInGenesis,
    InvalidWei,
    NonIntegralTokenAmount,
}

impl SpotMetaError {
    pub const fn code(&self) -> u16 {
        match self {
            SpotMetaError::InvalidQuoteToken => 239,
            SpotMetaError::FullNameTooLong => 323,
            SpotMetaError::MaxSupplyTooLarge(_) => 319,
            _ => 223,
        }
    }

    pub const fn message(&self) -> &'static str {
        match self {
            SpotMetaError::NameTooLong => "name too long",
            SpotMetaError::FullNameTooLong => "full name too long",
            SpotMetaError::InvalidDecimals => "must have szDecimals <= weiDecimals <= 10",
            SpotMetaError::MaxSupplyTooLarge(_) => "max supply too large",
            SpotMetaError::DuplicateTokenId => "duplicate token id",
            SpotMetaError::TooManySpots => "too many spots",
            SpotMetaError::CannotUseSameBaseAndQuote => "cannot use same base and quote token",
            SpotMetaError::CannotUseUsdcAsBaseToken => "cannot use USDC as base token",
            SpotMetaError::TokenIsNotQuoteToken => "token is not quote token",
            SpotMetaError::DuplicateSpotAsset => "duplicate spot asset",
            SpotMetaError::UnexpectedFirstSpotAsset => "unexpected first spot asset",
            SpotMetaError::InvalidQuoteToken => "invalid quote token",
            SpotMetaError::QuoteTokenDeployerFeeShareMustBeZero => "quote token deployer trading fee share must be 0",
            SpotMetaError::QuoteTokenNotAllowed => "quote token not allowed",
            SpotMetaError::QuoteTokenNotDisabled => "quote token not disabled",
            SpotMetaError::AddressAlreadyUsedAsEvmContract => "Address is already used as EVM contract",
            SpotMetaError::EvmContractAlreadySet => "evm contract already set",
            SpotMetaError::InvalidEvmExtraWeiDecimals => "EVM extra wei decimals must be between -2 and 18",
            SpotMetaError::PendingEvmContractNotFound => "pending evm contract not found",
            SpotMetaError::FirstStorageSlotProofMismatch => "first storage slot proof mismatch",
            SpotMetaError::CustomStorageSlotProofMismatch => "custom storage slot proof mismatch",
            SpotMetaError::UnableToUnsetUsdcEvmContract => "Unable to unset USDC EVM contract",
            SpotMetaError::MustUnsetUsdcEvmContractFirst => "Must unset USDC EVM contract first",
            SpotMetaError::AlreadyRevokedTokenFreezePrivilege => "already revoked token freeze privilege",
            SpotMetaError::TooManyFrozenUsers => "number of frozen users capped at {MAX_N_FROZEN_USERS}",
            SpotMetaError::CannotRevokeTokenFreezePrivilegeWithFrozenUsers => "cannot revoke token freeze privilege when there are frozen users",
            SpotMetaError::BlacklistUsersToUpdateExceedsLimit => "blacklist users to update exceeds 1000",
            SpotMetaError::BlacklistUpdateCannotIncludeGenesisBalances => "cannot update blacklist users when either user_and_wei or existing_token_and_wei is non-empty",
            SpotMetaError::GenesisBalanceForBlacklistedUser => "cannot update token genesis balance for blacklisted user(s), either remove blacklisted user(s) from user_and_wei or remove the relevant user(s) from the blacklist",
            SpotMetaError::TooManyGenesisUsersOrAnchorTokens => "at most 10000 genesis users and 2 anchor tokens are allowed",
            SpotMetaError::VaultsAndSubaccountsNotAllowedInGenesis => "vaults and subaccounts are not allowed in genesis",
            SpotMetaError::InvalidWei => "invalid wei",
            SpotMetaError::NonIntegralTokenAmount => "non-integral token amount",
        }
    }
}

impl fmt::Display for SpotMetaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}
