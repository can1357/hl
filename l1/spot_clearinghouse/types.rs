use std::collections::{BTreeMap, BTreeSet, HashMap};

pub type Token = u64;
pub type Spot = u64;
pub type Wei = u64;
pub type Px = u64;
pub type Sz = u64;
pub type Time = u64;

pub const USDC_TOKEN: Token = 0;
pub const DEPLOYER_SHARE_DENOMINATOR: f64 = 100_000.0;
pub const MAX_DEPLOYER_SHARE_FACTOR: f64 = 1.01;
pub const SPOT_PRICE_SCALE: u128 = 100_000_000;
pub const SENTINEL_SWEEP_USER: Address = Address([0xee; 20]);

#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Address(pub [u8; 20]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpotClearinghouseError {
    UnknownSpot,
    UnknownToken,
    InvalidDecimals,
    ArithmeticOverflow,
    InsufficientBalance,
    NormalizationFailed,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SpotInfo {
    pub base_token: Token,
    pub quote_token: Token,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuoteTokenStatus {
    Active,
    Disabled,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AlignedQuoteTokenInfo {
    pub active: bool,
    pub evm_minted_supply: Wei,
    pub first_aligned_time: Time,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TokenInfo {
    pub wei_decimals: u8,
    pub sz_decimals: u8,
    pub deployer_trading_fee_share_scaled: u64,
    pub deployer: Option<Address>,
    pub aligned_quote: AlignedQuoteTokenInfo,
}

impl TokenInfo {
    #[inline]
    pub fn sz_to_wei_scale(self) -> Result<u64, SpotClearinghouseError> {
        let exponent = self
            .wei_decimals
            .checked_sub(self.sz_decimals)
            .ok_or(SpotClearinghouseError::InvalidDecimals)?;
        pow10_u64(exponent).ok_or(SpotClearinghouseError::InvalidDecimals)
    }

    #[inline]
    pub fn deployer_share(self, amount: Wei) -> Wei {
        let Some(_deployer) = self.deployer else {
            return 0;
        };
        if !self.aligned_quote.active {
            return 0;
        }
        deployer_share_for_amount(amount, self.deployer_trading_fee_share_scaled)
    }
}

#[derive(Clone, Debug, Default)]
pub struct SpotMetaState {
    pub spot_infos: Vec<SpotInfo>,
    pub token_infos: Vec<TokenInfo>,
    pub liquid_base_tokens: BTreeSet<Token>,
    pub quote_token_to_status: BTreeMap<Token, QuoteTokenStatus>,
    pub quote_token_to_aligned_quote_token_info: BTreeMap<Token, AlignedQuoteTokenInfo>,
    pub current_time_or_block: f64,
}

impl SpotMetaState {
    #[inline]
    pub fn spot_pair(&self, spot: Spot) -> Option<SpotInfo> {
        self.spot_infos.get(spot as usize).copied()
    }

    #[inline]
    pub fn token_info(&self, token: Token) -> Option<TokenInfo> {
        self.token_infos.get(token as usize).copied()
    }

    pub fn token_class(&self, token: Token) -> SpotTokenClass {
        if self.liquid_base_tokens.contains(&token) {
            SpotTokenClass::LiquidBase
        } else if self.quote_token_to_status.contains_key(&token)
            || self.quote_token_to_aligned_quote_token_info.contains_key(&token)
        {
            SpotTokenClass::QuoteOrAligned
        } else {
            SpotTokenClass::Plain
        }
    }

    pub fn spot_base_token_wei_for_fill(
        &self,
        spot: Spot,
        _px: Px,
        sz: Sz,
    ) -> Result<Wei, SpotClearinghouseError> {
        let pair = self.spot_pair(spot).ok_or(SpotClearinghouseError::UnknownSpot)?;
        let token = self.token_info(pair.base_token).ok_or(SpotClearinghouseError::UnknownToken)?;
        let scale = token.sz_to_wei_scale()?;
        sz.checked_mul(scale).ok_or(SpotClearinghouseError::ArithmeticOverflow)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpotTokenClass {
    Plain,
    LiquidBase,
    QuoteOrAligned,
}

/// Two-word spot token balance stored in each user's token map.
///
/// The hot paths treat the first word as the checked total/free bucket and the
/// second as a reserved/held bucket: direct debits reduce only spendable value;
/// matched-fill consumption subtracts the filled amount from both words and
/// clamps the second word to zero on underflow.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SpotTokenBalance {
    pub total: Wei,
    pub reserved: Wei,
}

impl SpotTokenBalance {
    #[inline]
    pub const fn new(total: Wei, reserved: Wei) -> Self {
        Self { total, reserved }
    }

    #[inline]
    pub const fn spendable(self) -> Wei {
        self.total.saturating_sub(self.reserved)
    }

    #[inline]
    pub fn can_debit(self, amount: Wei) -> bool {
        self.spendable() >= amount
    }

    pub fn credit_total(&mut self, amount: Wei) -> Result<(), SpotClearinghouseError> {
        self.total = self
            .total
            .checked_add(amount)
            .ok_or(SpotClearinghouseError::ArithmeticOverflow)?;
        Ok(())
    }

    /// Debit at most the spendable portion.  This matches the direct debit path:
    /// if `amount + reserved` would exceed `total`, only `total - reserved` is
    /// removed and `reserved` is preserved.
    pub fn debit_spendable(&mut self, amount: Wei) -> Result<Wei, SpotClearinghouseError> {
        let debited = amount.min(self.spendable());
        self.total = self
            .total
            .checked_sub(debited)
            .ok_or(SpotClearinghouseError::InsufficientBalance)?;
        Ok(debited)
    }

    /// Consume a filled reserved amount: total is checked, reserved saturates.
    pub fn consume_reserved(&mut self, amount: Wei) -> Result<(), SpotClearinghouseError> {
        self.total = self
            .total
            .checked_sub(amount)
            .ok_or(SpotClearinghouseError::InsufficientBalance)?;
        self.reserved = self.reserved.saturating_sub(amount);
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SpotPosition {
    pub user: Address,
    pub token: Token,
    pub balance: SpotTokenBalance,
}

impl SpotPosition {
    #[inline]
    pub const fn new(user: Address, token: Token, balance: SpotTokenBalance) -> Self {
        Self { user, token, balance }
    }

    #[inline]
    pub const fn spendable_wei(self) -> Wei {
        self.balance.spendable()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WeiBalanceRow {
    pub total: Wei,
    pub available: Wei,
    pub notional: u64,
}

impl WeiBalanceRow {
    pub fn credit_saturating(&mut self, amount: Wei) {
        self.total = self.total.saturating_add(amount);
        self.available = self.available.saturating_add(amount);
    }

    pub fn debit_checked_available_saturating(
        &mut self,
        amount: Wei,
    ) -> Result<(), SpotClearinghouseError> {
        self.total = self
            .total
            .checked_sub(amount)
            .ok_or(SpotClearinghouseError::InsufficientBalance)?;
        self.available = self.available.saturating_sub(amount);
        Ok(())
    }

    pub fn debit_and_rescale_notional(
        &mut self,
        amount: Wei,
    ) -> Result<(), SpotClearinghouseError> {
        let old_total = self.total;
        self.debit_checked_available_saturating(amount)?;
        if old_total == 0 || self.notional == 0 {
            self.notional = 0;
        } else {
            let scaled = (self.notional as u128) * (self.total as u128) / (old_total as u128);
            self.notional = scaled.min(u64::MAX as u128) as u64;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct QtysWei {
    pub balances: HashMap<Address, BTreeMap<Token, WeiBalanceRow>>,
    pub user_token_index: BTreeMap<Address, BTreeSet<Token>>,
}

impl QtysWei {
    pub fn entry_mut(&mut self, user: Address, token: Token) -> &mut WeiBalanceRow {
        self.user_token_index.entry(user).or_default().insert(token);
        self.balances.entry(user).or_default().entry(token).or_default()
    }

    pub fn upsert_user_wei_delta(
        &mut self,
        user: Address,
        token: Token,
        is_debit: bool,
        amount: Wei,
        update_notional: bool,
    ) -> Result<(), SpotClearinghouseError> {
        let entry = self.entry_mut(user, token);
        if is_debit {
            if update_notional && token != USDC_TOKEN {
                entry.debit_and_rescale_notional(amount)
            } else {
                entry.debit_checked_available_saturating(amount)
            }
        } else {
            entry.credit_saturating(amount);
            Ok(())
        }
    }

    /// Walk a caller-provided ordered user set, clear each selected user's row for
    /// `token`, and credit the aggregate to the recovered sentinel account.
    pub fn sweep_user_asset_balances_to_sentinel<I>(
        &mut self,
        token: Token,
        users: I,
    ) -> Result<Wei, SpotClearinghouseError>
    where
        I: IntoIterator<Item = Address>,
    {
        let mut swept = 0u64;
        for user in users {
            let row = self.entry_mut(user, token);
            swept = swept
                .checked_add(row.total)
                .ok_or(SpotClearinghouseError::ArithmeticOverflow)?;
            row.total = 0;
            row.available = 0;
            row.notional = 0;
        }
        self.upsert_user_wei_delta(SENTINEL_SWEEP_USER, token, false, swept, false)?;
        Ok(swept)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NormalizedWeiTransfer {
    pub user: Address,
    pub wei: Wei,
}

pub fn normalize_wei_transfers(
    transfers: &mut [NormalizedWeiTransfer],
    target_total: Wei,
) -> Result<(), SpotClearinghouseError> {
    if transfers.is_empty() {
        return Err(SpotClearinghouseError::NormalizationFailed);
    }
    let mut total = 0u64;
    for transfer in transfers.iter() {
        total = total
            .checked_add(transfer.wei)
            .ok_or(SpotClearinghouseError::ArithmeticOverflow)?;
    }
    if total == 0 {
        return Err(SpotClearinghouseError::NormalizationFailed);
    }
    if target_total >= total {
        transfers[0].wei = transfers[0]
            .wei
            .checked_add(target_total - total)
            .ok_or(SpotClearinghouseError::ArithmeticOverflow)?;
        return Ok(());
    }

    let mut excess = total - target_total;
    for transfer in transfers.iter_mut() {
        if excess == 0 {
            break;
        }
        let reduction = transfer.wei.min(excess);
        transfer.wei -= reduction;
        excess -= reduction;
    }
    if excess == 0 {
        Ok(())
    } else {
        Err(SpotClearinghouseError::NormalizationFailed)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SpotBalanceSnapshot {
    pub token: Token,
    pub balance: SpotTokenBalance,
    pub delta: Wei,
    pub class: SpotTokenClassByte,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum SpotTokenClassByte {
    #[default]
    Plain = 0,
    LiquidBase = 1,
    QuoteOrAligned = 2,
}

impl From<SpotTokenClass> for SpotTokenClassByte {
    fn from(value: SpotTokenClass) -> Self {
        match value {
            SpotTokenClass::Plain => Self::Plain,
            SpotTokenClass::LiquidBase => Self::LiquidBase,
            SpotTokenClass::QuoteOrAligned => Self::QuoteOrAligned,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SpotLedgerSide {
    pub user: Address,
    pub receive_token: Token,
    pub pay_token: Token,
    pub receive_wei: Wei,
    pub pay_wei: Wei,
    pub ledger_sequence_or_time: Time,
    pub is_taker_side: bool,
    pub token_class: SpotTokenClassByte,
    pub quote_pair_flag: u8,
    pub post_receive: SpotBalanceSnapshot,
    pub post_pay: SpotBalanceSnapshot,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SpotFillPartySettlement {
    pub ledger_side: SpotLedgerSide,
    pub post_balance_a: SpotBalanceSnapshot,
    pub post_balance_b: SpotBalanceSnapshot,
    pub user: Address,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SpotFillSettlement {
    pub party0: SpotFillPartySettlement,
    pub party1: SpotFillPartySettlement,
    pub px: Px,
    pub spot: Spot,
    pub sz: Sz,
    pub ledger_sequence_or_time: Time,
    pub side_flag: u8,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RestingSpotOrderReserve {
    pub context_user: Address,
    pub user: Address,
    pub spot: Spot,
    pub amount: Wei,
    pub secondary_amount: Wei,
    pub is_buy: bool,
    pub result: SpotLedgerSide,
}

#[derive(Clone, Debug, Default)]
pub struct SpotClearinghouseState {
    pub meta: SpotMetaState,
    pub user_balances: HashMap<Address, BTreeMap<Token, SpotTokenBalance>>,
    pub user_token_index: BTreeMap<Address, BTreeSet<Token>>,
    pub token_supply_deltas: BTreeMap<Token, Wei>,
}

impl SpotClearinghouseState {
    pub fn balance_entry_mut(&mut self, user: Address, token: Token) -> &mut SpotTokenBalance {
        self.user_token_index.entry(user).or_default().insert(token);
        self.user_balances.entry(user).or_default().entry(token).or_default()
    }

    pub fn balance_entry(&self, user: Address, token: Token) -> SpotTokenBalance {
        self.user_balances
            .get(&user)
            .and_then(|tokens| tokens.get(&token))
            .copied()
            .unwrap_or_default()
    }

    pub fn position(&self, user: Address, token: Token) -> SpotPosition {
        SpotPosition::new(user, token, self.balance_entry(user, token))
    }

    pub fn credit_user_token(
        &mut self,
        user: Address,
        token: Token,
        amount: Wei,
    ) -> Result<SpotBalanceSnapshot, SpotClearinghouseError> {
        let class = self.meta.token_class(token).into();
        let balance = {
            let entry = self.balance_entry_mut(user, token);
            entry.credit_total(amount)?;
            *entry
        };
        Ok(SpotBalanceSnapshot {
            token,
            balance,
            delta: amount,
            class,
        })
    }

    pub fn consume_user_reserved(
        &mut self,
        user: Address,
        token: Token,
        amount: Wei,
    ) -> Result<SpotBalanceSnapshot, SpotClearinghouseError> {
        let class = self.meta.token_class(token).into();
        let entry = self.balance_entry_mut(user, token);
        entry.consume_reserved(amount)?;
        Ok(SpotBalanceSnapshot {
            token,
            balance: *entry,
            delta: amount,
            class,
        })
    }

    pub fn debit_user_spot_balance(
        &mut self,
        user: Address,
        token: Token,
        amount: Wei,
    ) -> Result<Wei, SpotClearinghouseError> {
        let debited = self.balance_entry_mut(user, token).debit_spendable(amount)?;
        let credited_to_deployer = self.credit_deployer_share(token, debited)?;
        self.add_token_supply_delta(token, debited.saturating_sub(credited_to_deployer))?;
        Ok(debited)
    }

    pub fn reserve_resting_spot_order(
        &mut self,
        taker_side: bool,
        enabled: bool,
        order: &mut RestingSpotOrderReserve,
    ) -> Result<(), SpotClearinghouseError> {
        if !enabled || order.amount == 0 {
            return Ok(());
        }
        let pair = self.meta.spot_pair(order.spot).ok_or(SpotClearinghouseError::UnknownSpot)?;
        let (pay_token, receive_token, pay_wei, receive_wei) = if order.is_buy {
            (pair.quote_token, pair.base_token, order.amount, order.secondary_amount)
        } else {
            (pair.base_token, pair.quote_token, order.amount, order.secondary_amount)
        };
        let debited = self.balance_entry_mut(order.user, pay_token).debit_spendable(pay_wei)?;
        let pay_snapshot = SpotBalanceSnapshot {
            token: pay_token,
            balance: self.balance_entry(order.user, pay_token),
            delta: debited,
            class: self.meta.token_class(pay_token).into(),
        };
        let deployer_credit = self.credit_deployer_share(pay_token, debited)?;
        self.add_token_supply_delta(pay_token, debited.saturating_sub(deployer_credit))?;
        order.result = SpotLedgerSide {
            user: order.user,
            receive_token,
            pay_token,
            receive_wei,
            pay_wei: debited,
            ledger_sequence_or_time: 0,
            is_taker_side: taker_side,
            token_class: self.meta.token_class(pay_token).into(),
            quote_pair_flag: 0,
            post_receive: SpotBalanceSnapshot {
                token: receive_token,
                balance: self.balance_entry(order.user, receive_token),
                delta: receive_wei,
                class: self.meta.token_class(receive_token).into(),
            },
            post_pay: pay_snapshot,
        };
        Ok(())
    }

    pub fn settle_matched_spot_fill(
        &mut self,
        taker_side: u8,
        fill: &mut SpotFillSettlement,
        ledger_out: &mut Vec<SpotLedgerSide>,
    ) -> Result<(), SpotClearinghouseError> {
        let pair = self.meta.spot_pair(fill.spot).ok_or(SpotClearinghouseError::UnknownSpot)?;
        let base_wei = self.meta.spot_base_token_wei_for_fill(fill.spot, fill.px, fill.sz)?;
        let quote_wei = fill
            .px
            .checked_mul(fill.sz)
            .ok_or(SpotClearinghouseError::ArithmeticOverflow)?;

        if !self.balance_entry(fill.party0.user, pair.quote_token).can_debit(quote_wei) {
            return Err(SpotClearinghouseError::InsufficientBalance);
        }
        if !self.balance_entry(fill.party1.user, pair.base_token).can_debit(base_wei) {
            return Err(SpotClearinghouseError::InsufficientBalance);
        }

        let side0 = self.apply_fill_side(
            fill.party0.user,
            pair.base_token,
            base_wei,
            pair.quote_token,
            quote_wei,
            fill.ledger_sequence_or_time,
            fill.side_flag == 0,
            taker_side,
        )?;
        fill.party0.ledger_side = side0.clone();
        fill.party0.post_balance_a = side0.post_receive;
        fill.party0.post_balance_b = side0.post_pay;
        ledger_out.push(side0);

        let side1 = self.apply_fill_side(
            fill.party1.user,
            pair.quote_token,
            quote_wei,
            pair.base_token,
            base_wei,
            fill.ledger_sequence_or_time,
            fill.side_flag == 1,
            taker_side,
        )?;
        fill.party1.ledger_side = side1.clone();
        fill.party1.post_balance_a = side1.post_receive;
        fill.party1.post_balance_b = side1.post_pay;
        ledger_out.push(side1);

        self.adjust_pair_supply_delta(pair.base_token, base_wei, quote_wei)?;
        self.adjust_pair_supply_delta(pair.quote_token, quote_wei, base_wei)?;
        Ok(())
    }

    fn apply_fill_side(
        &mut self,
        user: Address,
        receive_token: Token,
        receive_wei: Wei,
        pay_token: Token,
        pay_wei: Wei,
        ledger_sequence_or_time: Time,
        is_taker_side: bool,
        taker_side: u8,
    ) -> Result<SpotLedgerSide, SpotClearinghouseError> {
        let post_receive = self.credit_user_token(user, receive_token, receive_wei)?;
        let post_pay = self.consume_user_reserved(user, pay_token, pay_wei)?;
        Ok(SpotLedgerSide {
            user,
            receive_token,
            pay_token,
            receive_wei,
            pay_wei,
            ledger_sequence_or_time,
            is_taker_side,
            token_class: self.meta.token_class(pay_token).into(),
            quote_pair_flag: taker_side,
            post_receive,
            post_pay,
        })
    }

    fn credit_deployer_share(
        &mut self,
        token: Token,
        amount: Wei,
    ) -> Result<Wei, SpotClearinghouseError> {
        let Some(info) = self.meta.token_info(token) else {
            return Err(SpotClearinghouseError::UnknownToken);
        };
        let credit = info.deployer_share(amount);
        if credit == 0 {
            return Ok(0);
        }
        if let Some(deployer) = info.deployer {
            self.balance_entry_mut(deployer, token).credit_total(credit)?;
        }
        Ok(credit)
    }

    fn adjust_pair_supply_delta(
        &mut self,
        token: Token,
        gross: Wei,
        offset: Wei,
    ) -> Result<(), SpotClearinghouseError> {
        if gross >= offset {
            let amount = gross - offset;
            let deployer_credit = self.credit_deployer_share(token, amount)?;
            self.add_token_supply_delta(token, amount.saturating_sub(deployer_credit))
        } else {
            self.sub_token_supply_delta(token, offset - gross);
            Ok(())
        }
    }

    fn add_token_supply_delta(
        &mut self,
        token: Token,
        amount: Wei,
    ) -> Result<(), SpotClearinghouseError> {
        let entry = self.token_supply_deltas.entry(token).or_default();
        *entry = (*entry)
            .checked_add(amount)
            .ok_or(SpotClearinghouseError::ArithmeticOverflow)?;
        Ok(())
    }

    fn sub_token_supply_delta(&mut self, token: Token, amount: Wei) {
        let entry = self.token_supply_deltas.entry(token).or_default();
        *entry = (*entry).saturating_sub(amount);
    }
}

#[inline]
pub fn quote_wei_for_fill(px: Px, sz: Sz) -> Option<Wei> {
    px.checked_mul(sz)
}

#[inline]
pub fn spot_notional_from_px_sz(px: Px, sz: Sz, scale: u128) -> Option<u64> {
    if scale == 0 {
        return None;
    }
    let product = (px as u128).checked_mul(sz as u128)?;
    let raw = product / scale;
    if raw <= u64::MAX as u128 {
        Some(raw as u64)
    } else {
        None
    }
}

pub fn deployer_share_for_amount(amount: Wei, share_scaled_1e5: u64) -> Wei {
    let factor = (share_scaled_1e5 as f64) / DEPLOYER_SHARE_DENOMINATOR;
    if !(0.0..=MAX_DEPLOYER_SHARE_FACTOR).contains(&factor) {
        return 0;
    }
    saturating_f64_to_u64((amount as f64) * factor)
}

pub fn saturating_f64_to_u64(value: f64) -> u64 {
    if !value.is_finite() || value <= 0.0 {
        return 0;
    }
    if value >= u64::MAX as f64 {
        return u64::MAX;
    }
    value as u64
}

pub const fn pow10_u64(exp: u8) -> Option<u64> {
    let mut i = 0;
    let mut value = 1u64;
    while i < exp {
        if value > u64::MAX / 10 {
            return None;
        }
        value *= 10;
        i += 1;
    }
    Some(value)
}
