#![allow(dead_code)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

pub type Token = u64;
pub type Spot = u64;
pub type Wei = u64;
pub type Px = u64;
pub type Sz = u64;
pub type OrderId = u64;

pub const INTERNAL_OK: u8 = 39;
pub const ERR_MISSING_OUTCOME_MARKET: u8 = 4;
pub const ERR_INVALID_TOKEN: u8 = 0;
pub const ERR_INCONSISTENT_PAIR: u8 = 15;
pub const ERR_INVALID_SETTLEMENT_SPLIT: u8 = 18;
pub const ERR_INSUFFICIENT_RESIDUAL_BALANCE: u8 = 20;
pub const ERR_ARITHMETIC: u8 = 21;

const DEPLOYER_SHARE_DENOMINATOR: f64 = 100_000.0;
const MAX_DEPLOYER_SHARE_FACTOR: f64 = 1.01;
const MAX_SAFE_GENERATED_PRODUCT: u128 = 0x7fff_ffff_ffff_fffe;
const GENERATED_ROW_SIDE_TAG: u8 = 50;
const GENERATED_ORDER_ROW_TAG: u8 = 10;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Address(pub [u8; 20]);

impl Address {
    pub const ZERO: Self = Self([0; 20]);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SpotSide {
    Bid = 0,
    Ask = 1,
}

impl SpotSide {
    #[inline]
    pub const fn opposite(self) -> Self {
        match self {
            Self::Bid => Self::Ask,
            Self::Ask => Self::Bid,
        }
    }

    #[inline]
    pub const fn as_index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SpotTokenBalance {
    pub total: Wei,
    pub hold: Wei,
}

impl SpotTokenBalance {
    #[inline]
    pub const fn available(self) -> Wei {
        self.total.saturating_sub(self.hold)
    }

    pub fn debit_available(&mut self, amount: Wei) -> Result<Wei, SpotOutcomeError> {
        let debited = amount.min(self.available());
        self.hold = self
            .hold
            .checked_add(debited)
            .ok_or(SpotOutcomeError::status(ERR_ARITHMETIC))?;
        self.total = self
            .total
            .checked_sub(debited)
            .ok_or(SpotOutcomeError::status(ERR_INSUFFICIENT_RESIDUAL_BALANCE))?;
        self.hold = self.hold.saturating_sub(debited);
        Ok(debited)
    }

    pub fn consume_hold(&mut self, amount: Wei) -> Result<(), SpotOutcomeError> {
        self.total = self
            .total
            .checked_sub(amount)
            .ok_or(SpotOutcomeError::status(ERR_INSUFFICIENT_RESIDUAL_BALANCE))?;
        self.hold = self.hold.saturating_sub(amount);
        Ok(())
    }

    pub fn credit(&mut self, amount: Wei) -> Result<(), SpotOutcomeError> {
        self.total = self
            .total
            .checked_add(amount)
            .ok_or(SpotOutcomeError::status(ERR_ARITHMETIC))?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TokenInfo {
    pub exists: bool,
    pub deployer: Option<Address>,
    pub deployer_trading_fee_share_scaled: u64,
    pub aligned_quote_active: bool,
}

impl TokenInfo {
    #[inline]
    pub fn deployer_share(self, amount: Wei) -> Wei {
        if self.deployer.is_none() || !self.aligned_quote_active {
            return 0;
        }
        let factor = (self.deployer_trading_fee_share_scaled as f64) / DEPLOYER_SHARE_DENOMINATOR;
        if !(0.0..=MAX_DEPLOYER_SHARE_FACTOR).contains(&factor) {
            return 0;
        }
        saturating_f64_to_u64((amount as f64) * factor)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SpotPairInfo {
    pub base_token: Token,
    pub quote_token: Token,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeMarketKind {
    Single,
    Paired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpotOutcomeMarket {
    pub spot: Spot,
    pub kind: OutcomeMarketKind,
    pub token_a: Token,
    pub token_b: Token,
    pub settlement_token: Token,
    pub residual_token: Token,
    /// Recovered slot read immediately before the settlement-price multiply.
    pub total_notional: Wei,
    /// Token amount converted through spot metadata before the second multiply.
    pub converted_base_amount: Wei,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettlementSplit {
    pub win: Wei,
    pub lose: Wei,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementClaim {
    pub user: Address,
    pub token: Token,
    pub amount: Wei,
    pub side: SpotSide,
    pub oid: OrderId,
    pub flags: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutcomeMakerLeg {
    pub user: Address,
    pub token: Token,
    pub amount: Wei,
    pub side: SpotSide,
    pub oid: OrderId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedSpotOutcomeOrder {
    pub row_tag: u8,
    pub user: Address,
    pub spot: Spot,
    pub side: SpotSide,
    pub oid: OrderId,
    pub px: Px,
    pub sz: Sz,
    pub debit_token: Token,
    pub debit_wei: Wei,
    pub credit_token: Token,
    pub credit_wei: Wei,
    pub maker_legs: Vec<OutcomeMakerLeg>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpotSettlementOutcome {
    pub row_tag: u8,
    pub market_id: Spot,
    pub user: Address,
    pub token: Token,
    pub amount: Wei,
    pub scaled_amount: Wei,
    pub side: SpotSide,
    pub flags: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpotLedgerRow {
    pub user: Address,
    pub debit_token: Token,
    pub debit_wei: Wei,
    pub credit_token: Token,
    pub credit_wei: Wei,
    pub row_tag: u8,
    pub status: u8,
}

#[derive(Clone, Debug, Default)]
pub struct SpotOutcomeState {
    pub spot_pairs: BTreeMap<Spot, SpotPairInfo>,
    pub tokens: BTreeMap<Token, TokenInfo>,
    pub outcome_markets: BTreeMap<Spot, SpotOutcomeMarket>,
    pub user_balances: BTreeMap<Address, BTreeMap<Token, SpotTokenBalance>>,
    pub user_token_index: BTreeMap<Address, BTreeSet<Token>>,
    pub token_supply_deltas: BTreeMap<Token, Wei>,
    pub settlement_claims: BTreeMap<Spot, Vec<SettlementClaim>>,
    pub residual_balances: BTreeMap<Token, Wei>,
    pub generated_orders: Vec<GeneratedSpotOutcomeOrder>,
    pub settlement_rows: Vec<SpotSettlementOutcome>,
    pub ledger_rows: Vec<SpotLedgerRow>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpotOutcomeError {
    pub status: u8,
}

impl SpotOutcomeError {
    #[inline]
    pub const fn status(status: u8) -> Self {
        Self { status }
    }
}

impl SpotOutcomeState {
    #[inline]
    pub fn token_is_active(&self, token: Token) -> bool {
        self.tokens.get(&token).is_some_and(|info| info.exists)
    }

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

    /// Debits the spendable user balance and accounts for aligned quote-token deployer share.
    ///
    /// The recovered routine first clamps the debit to `total - hold`, then credits a
    /// deployer share when the token's aligned-quote bit is active, and finally adds the
    /// net debit to the per-token supply delta map.
    pub fn debit_user_spot_balance(
        &mut self,
        user: Address,
        token: Token,
        requested_wei: Wei,
    ) -> Result<Wei, SpotOutcomeError> {
        let debited = self.balance_entry_mut(user, token).debit_available(requested_wei)?;
        let deployer_credit = self.credit_deployer_share(token, debited)?;
        self.add_supply_delta(token, debited.saturating_sub(deployer_credit))?;
        Ok(debited)
    }

    /// Applies generated spot outcome rows and settles their maker legs.
    ///
    /// The binary uses an internal success byte of 39. Non-39 statuses stop the batch;
    /// successful batches debit the initiating user's spot balance once after all rows
    /// have been emitted.
    pub fn apply_generated_spot_outcome_batch(
        &mut self,
        market_id: Spot,
        initiator: Address,
        orders: &[GeneratedSpotOutcomeOrder],
    ) -> u8 {
        let Some(market) = self.outcome_markets.get(&market_id).cloned() else {
            return ERR_MISSING_OUTCOME_MARKET;
        };
        if !self.outcome_tokens_match_pair(&market) {
            return ERR_INCONSISTENT_PAIR;
        }

        let mut initiator_debit = 0u64;
        for order in orders {
            if order.row_tag != GENERATED_ORDER_ROW_TAG {
                return ERR_INVALID_TOKEN;
            }
            if order.spot != market.spot {
                return ERR_INCONSISTENT_PAIR;
            }
            if !safe_generated_product(order.sz, order.px) {
                return ERR_INVALID_SETTLEMENT_SPLIT;
            }

            for leg in &order.maker_legs {
                if !self.token_is_active(leg.token) {
                    return ERR_INVALID_TOKEN;
                }
                if leg.amount == 0 {
                    continue;
                }
                if let Err(err) = self.consume_maker_leg(order, leg) {
                    return err.status;
                }
            }

            initiator_debit = match initiator_debit.checked_add(order.debit_wei) {
                Some(value) => value,
                None => return ERR_ARITHMETIC,
            };
            self.generated_orders.push(order.clone());
        }

        if initiator_debit != 0 {
            match self.debit_user_spot_balance(initiator, market.settlement_token, initiator_debit) {
                Ok(_) => {}
                Err(err) => return err.status,
            }
        }
        INTERNAL_OK
    }

    /// Sets a settlement price and builds the per-user settlement outcome rows.
    ///
    /// This mirrors the recovered wrapper: missing markets return status 4, mismatched
    /// outcome-pair metadata returns 15, invalid split arithmetic returns 18, inactive
    /// spot tokens return 0, and residual insufficiency in the generated rows returns 20.
    pub fn settle_outcome_market(
        &mut self,
        market_id: Spot,
        generated_user: Address,
        settlement_price: f64,
    ) -> Result<Vec<SpotSettlementOutcome>, SpotOutcomeError> {
        let Some(market) = self.outcome_markets.get(&market_id).cloned() else {
            return Err(SpotOutcomeError::status(ERR_MISSING_OUTCOME_MARKET));
        };
        if !valid_settlement_price(settlement_price) {
            return Err(SpotOutcomeError::status(ERR_INVALID_SETTLEMENT_SPLIT));
        }
        if !self.outcome_tokens_match_pair(&market) {
            return Err(SpotOutcomeError::status(ERR_INCONSISTENT_PAIR));
        }
        if !self.token_is_active(market.token_a) || !self.token_is_active(market.token_b) {
            return Err(SpotOutcomeError::status(ERR_INVALID_TOKEN));
        }

        let notional = split_amount(market.total_notional, settlement_price)?;
        let converted = split_amount(market.converted_base_amount, settlement_price)?;
        let claims = self.settlement_claims.remove(&market_id).unwrap_or_default();
        let rows = self.build_settlement_outcomes(
            market_id,
            generated_user,
            &market,
            notional,
            converted,
            claims,
        )?;
        self.settlement_rows.extend(rows.iter().cloned());
        Ok(rows)
    }

    pub fn build_settlement_outcomes(
        &mut self,
        market_id: Spot,
        generated_user: Address,
        market: &SpotOutcomeMarket,
        notional: SettlementSplit,
        converted: SettlementSplit,
        claims: Vec<SettlementClaim>,
    ) -> Result<Vec<SpotSettlementOutcome>, SpotOutcomeError> {
        let mut rows = Vec::new();
        let mut grouped: BTreeMap<Address, Vec<(Token, Wei)>> = BTreeMap::new();
        let mut residual_debit = 0u64;

        for claim in claims {
            let (token, base_amount, multiplier) = match claim.side {
                SpotSide::Bid => (market.token_a, notional.win, converted.win),
                SpotSide::Ask => (market.token_b, notional.lose, converted.lose),
            };
            if !self.token_is_active(token) {
                return Err(SpotOutcomeError::status(ERR_INVALID_TOKEN));
            }
            let scaled_amount = scaled_claim_amount(claim.amount, multiplier)?;
            if scaled_amount == 0 && base_amount == 0 {
                continue;
            }

            let row = SpotSettlementOutcome {
                row_tag: GENERATED_ROW_SIDE_TAG,
                market_id,
                user: claim.user,
                token,
                amount: claim.amount,
                scaled_amount,
                side: claim.side,
                flags: claim.flags,
            };
            rows.push(row);
            grouped.entry(claim.user).or_default().push((token, scaled_amount));
            if token == market.residual_token {
                residual_debit = residual_debit
                    .checked_add(scaled_amount)
                    .ok_or(SpotOutcomeError::status(ERR_ARITHMETIC))?;
            }
        }

        let residual_available = self.residual_balances.get(&market.residual_token).copied().unwrap_or_default();
        if residual_debit > residual_available {
            return Err(SpotOutcomeError::status(ERR_INSUFFICIENT_RESIDUAL_BALANCE));
        }
        self.residual_balances.insert(market.residual_token, residual_available - residual_debit);

        for (user, credits) in grouped {
            for (token, amount) in credits {
                self.credit_user_token(user, token, amount)?;
                self.ledger_rows.push(SpotLedgerRow {
                    user,
                    debit_token: market.residual_token,
                    debit_wei: if token == market.residual_token { amount } else { 0 },
                    credit_token: token,
                    credit_wei: amount,
                    row_tag: GENERATED_ROW_SIDE_TAG,
                    status: INTERNAL_OK,
                });
            }
        }

        if generated_user != Address::ZERO {
            self.user_token_index.entry(generated_user).or_default().insert(market.residual_token);
        }
        Ok(rows)
    }

    fn consume_maker_leg(
        &mut self,
        order: &GeneratedSpotOutcomeOrder,
        leg: &OutcomeMakerLeg,
    ) -> Result<(), SpotOutcomeError> {
        self.balance_entry_mut(leg.user, leg.token).consume_hold(leg.amount)?;
        self.credit_user_token(order.user, order.credit_token, order.credit_wei)?;
        self.ledger_rows.push(SpotLedgerRow {
            user: leg.user,
            debit_token: leg.token,
            debit_wei: leg.amount,
            credit_token: order.credit_token,
            credit_wei: order.credit_wei,
            row_tag: GENERATED_ORDER_ROW_TAG,
            status: INTERNAL_OK,
        });
        Ok(())
    }

    fn outcome_tokens_match_pair(&self, market: &SpotOutcomeMarket) -> bool {
        self.spot_pairs.get(&market.spot).is_some_and(|pair| {
            let direct = pair.base_token == market.token_a && pair.quote_token == market.token_b;
            let inverse = pair.base_token == market.token_b && pair.quote_token == market.token_a;
            direct || inverse
        })
    }

    fn credit_user_token(
        &mut self,
        user: Address,
        token: Token,
        amount: Wei,
    ) -> Result<(), SpotOutcomeError> {
        if amount == 0 {
            self.user_token_index.entry(user).or_default().insert(token);
            return Ok(());
        }
        self.balance_entry_mut(user, token).credit(amount)
    }

    fn credit_deployer_share(&mut self, token: Token, amount: Wei) -> Result<Wei, SpotOutcomeError> {
        let info = self
            .tokens
            .get(&token)
            .copied()
            .ok_or(SpotOutcomeError::status(ERR_INVALID_TOKEN))?;
        let credit = info.deployer_share(amount);
        if credit == 0 {
            return Ok(0);
        }
        if let Some(deployer) = info.deployer {
            self.balance_entry_mut(deployer, token).credit(credit)?;
        }
        Ok(credit)
    }

    fn add_supply_delta(&mut self, token: Token, amount: Wei) -> Result<(), SpotOutcomeError> {
        let entry = self.token_supply_deltas.entry(token).or_default();
        *entry = entry
            .checked_add(amount)
            .ok_or(SpotOutcomeError::status(ERR_ARITHMETIC))?;
        Ok(())
    }
}

#[inline]
pub fn valid_settlement_price(price: f64) -> bool {
    price.is_finite() && (0.0..=1.0).contains(&price)
}

pub fn split_amount(amount: Wei, settlement_price: f64) -> Result<SettlementSplit, SpotOutcomeError> {
    if !valid_settlement_price(settlement_price) {
        return Err(SpotOutcomeError::status(ERR_INVALID_SETTLEMENT_SPLIT));
    }
    let win = saturating_f64_to_u64((amount as f64) * settlement_price);
    match amount.cmp(&win) {
        Ordering::Less => Err(SpotOutcomeError::status(ERR_INVALID_SETTLEMENT_SPLIT)),
        _ => Ok(SettlementSplit { win, lose: amount - win }),
    }
}

pub fn scaled_claim_amount(amount: Wei, multiplier: Wei) -> Result<Wei, SpotOutcomeError> {
    let product = (amount as u128)
        .checked_mul(multiplier as u128)
        .ok_or(SpotOutcomeError::status(ERR_ARITHMETIC))?;
    if product > MAX_SAFE_GENERATED_PRODUCT {
        return Err(SpotOutcomeError::status(ERR_INVALID_SETTLEMENT_SPLIT));
    }
    Ok(product as Wei)
}

#[inline]
pub fn safe_generated_product(sz: Sz, px: Px) -> bool {
    (sz as u128).saturating_mul(px as u128) <= MAX_SAFE_GENERATED_PRODUCT
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
