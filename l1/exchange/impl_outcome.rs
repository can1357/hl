#![allow(dead_code)]

use std::cmp::min;
use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type AssetId = u64;
pub type MarketId = u64;
pub type OrderId = u64;
pub type RawPx = u64;
pub type RawSz = u64;
pub type RawWei = u64;

pub const OK: u16 = 390;
pub const DIRTY_REJECT: u16 = 320;
pub const DIRECT_NO_FILL: u16 = 196;
pub const ALT_NO_FILL: u16 = 370;
pub const INVALID_SETTLEMENT_PRICE: u16 = 379;
pub const MISSING_OUTCOME_ORDER: u16 = 381;
pub const COLLATERAL_MARKET_MISMATCH: u16 = 234;
pub const COLLATERAL_DEPLOY_REJECTED: u16 = 172;

const INTERNAL_OK: u8 = 39;
const GENERATED_CONTINUATION_DIRTY: u16 = 391;
const OUTCOME_THRESHOLD_BIAS: u64 = 1_000;
const MAX_SAFE_GENERATED_PRODUCT: u128 = 0x7fff_ffff_ffff_fffe;
const ONE_DOT_ZERO: &str = "1.0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeSide {
    Main,
    Mirror,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeClass {
    Ordinary,
    DirtyReject,
    Outcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeMarketKind {
    Single,
    Paired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Buy,
    Sell,
}

impl Side {
    #[inline]
    pub const fn is_buy(self) -> bool {
        matches!(self, Self::Buy)
    }

    #[inline]
    pub const fn opposite(self) -> Self {
        match self {
            Self::Buy => Self::Sell,
            Self::Sell => Self::Buy,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeInForce {
    Alo,
    Ioc,
    Gtc,
    FrontendMarket,
    LiquidationMarket,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderFlags {
    pub tif: TimeInForce,
    pub reduce_only: bool,
    pub cloid: Option<[u8; 16]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutcomeOrder {
    pub user: Address,
    pub asset: AssetId,
    pub side: Side,
    pub limit_px: RawPx,
    pub sz: RawSz,
    pub oid: OrderId,
    pub expires_at: u64,
    pub flags: OrderFlags,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionResult {
    pub code: u16,
    pub reason: u64,
    pub api_asset: Option<i64>,
    pub market_id: Option<MarketId>,
    pub user: Option<Address>,
    pub message: Option<&'static str>,
    pub generated_orders: Vec<GeneratedOutcomeOrder>,
}

impl ActionResult {
    pub fn ok() -> Self {
        Self {
            code: OK,
            reason: 0,
            api_asset: None,
            market_id: None,
            user: None,
            message: None,
            generated_orders: Vec::new(),
        }
    }

    pub fn code(code: u16) -> Self {
        Self { code, ..Self::ok() }
    }

    pub fn no_fill(code: u16, api_asset: i64) -> Self {
        Self { code, api_asset: Some(api_asset), ..Self::ok() }
    }

    pub fn invalid_settlement_price() -> Self {
        Self { code: INVALID_SETTLEMENT_PRICE, message: Some("invalid settlement price"), ..Self::ok() }
    }

    pub fn missing_outcome_order() -> Self {
        Self { code: MISSING_OUTCOME_ORDER, reason: 8, ..Self::ok() }
    }

    pub fn is_ok(&self) -> bool {
        self.code == OK
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedOutcomeOrder {
    pub variant: u8,
    pub user: Address,
    pub asset: AssetId,
    pub linked_asset: AssetId,
    pub side: Side,
    pub oid: OrderId,
    pub sz: RawSz,
    pub px: RawPx,
    pub maker_legs: Vec<OutcomeMakerLeg>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutcomeMakerLeg {
    pub asset: AssetId,
    pub sz: RawSz,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutcomeLink {
    pub kind: OutcomeMarketKind,
    pub linked_asset: AssetId,
    pub linked_market: MarketId,
    pub expires_after: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutcomeScalar {
    pub low: u64,
    pub high: u64,
}

impl OutcomeScalar {
    /// The deploy path computes a midpoint, rounds it, clamps it into the u64
    /// range, and stores at the recovered spot metadata mark-price slot (+120).
    pub fn rounded_mid_mark(self) -> u64 {
        let mid = ((self.low as f64 + self.high as f64) * 0.5).round().max(0.0);
        let capped = mid.min(u64::MAX as f64);
        let raw = capped as u64;
        if raw == 0 { 1 } else { raw }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutcomeDeployment {
    pub primary_market: MarketId,
    pub linked_market: MarketId,
    pub primary_asset: AssetId,
    pub linked_asset: AssetId,
    pub collateral_token: u64,
    pub scalar: OutcomeScalar,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeployParamsA {
    pub raw_words: [u128; 4],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeployParamsB {
    pub raw_words: [u128; 3],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutableLevel {
    pub maker: Address,
    pub asset: AssetId,
    pub px: RawPx,
    pub sz: RawSz,
}

impl ExecutableLevel {
    pub fn crosses(self, order: &OutcomeOrder) -> bool {
        match order.side {
            Side::Buy => self.px <= order.limit_px,
            Side::Sell => self.px >= order.limit_px,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct OutcomeMetadata {
    pub classes: BTreeMap<AssetId, OutcomeClass>,
    pub scalars: BTreeMap<AssetId, OutcomeScalar>,
    pub links: BTreeMap<AssetId, OutcomeLink>,
}

impl OutcomeMetadata {
    pub fn classify(&self, asset: AssetId) -> OutcomeClass {
        self.classes.get(&asset).copied().unwrap_or(OutcomeClass::Ordinary)
    }

    pub fn scalar(&self, asset: AssetId) -> Option<OutcomeScalar> {
        self.scalars.get(&asset).copied()
    }

    pub fn link(&self, asset: AssetId) -> Option<OutcomeLink> {
        self.links.get(&asset).copied()
    }
}

#[derive(Clone, Debug, Default)]
pub struct BookMetadata {
    pub active_orders: BTreeMap<(AssetId, OrderId), OutcomeOrder>,
    pub spot_mark_px: BTreeMap<AssetId, u64>,
}

#[derive(Clone, Debug, Default)]
pub struct ClearinghouseSlot {
    pub market_id: MarketId,
    pub asset: Option<AssetId>,
    pub kind: u32,
}

#[derive(Clone, Debug, Default)]
pub struct ExchangeOutcomeState {
    pub dirty: bool,
    pub outcomes: OutcomeMetadata,
    pub books: BookMetadata,
    pub clearinghouses: Vec<ClearinghouseSlot>,
    pub generated_users_main: BTreeSet<Address>,
    pub generated_users_mirror: BTreeSet<Address>,
    pub emitted: Vec<GeneratedOutcomeOrder>,
}

impl ExchangeOutcomeState {
    pub fn apply_order_with_outcome_logic<H: OutcomeHooks>(
        &mut self,
        hooks: &mut H,
        order: OutcomeOrder,
        use_alt_no_fill_code: bool,
    ) -> ActionResult {
        match self.outcomes.classify(order.asset) {
            OutcomeClass::Ordinary => {
                let result = hooks.apply_normal_order(self, order);
                return self.normalize_direct_order_result(hooks, result, order.asset, use_alt_no_fill_code);
            }
            OutcomeClass::DirtyReject => return self.mark_dirty_for_user(Some(order.user), OutcomeSide::Main),
            OutcomeClass::Outcome => {}
        }

        let Some(scalar) = self.outcomes.scalar(order.asset) else {
            return self.mark_dirty_for_user(Some(order.user), OutcomeSide::Main);
        };
        if scalar.high <= OUTCOME_THRESHOLD_BIAS {
            return self.mark_dirty_for_user(Some(order.user), OutcomeSide::Main);
        }

        let max_expiry = scalar.high - OUTCOME_THRESHOLD_BIAS;
        let mut capped = order;
        capped.expires_at = min(order.expires_at, max_expiry);

        let Some(link) = self.outcomes.link(capped.asset) else {
            return self.mark_dirty_for_user(Some(capped.user), OutcomeSide::Main);
        };
        if link.kind != OutcomeMarketKind::Paired || link.expires_after <= capped.expires_at {
            return self.mark_dirty_for_user(Some(capped.user), OutcomeSide::Main);
        }

        let complement_asset = match capped.side {
            Side::Buy => link.linked_asset,
            Side::Sell => capped.asset,
        };

        let mut remaining = capped.sz;
        let mut matched = 0u64;
        let mut maker_legs = Vec::new();

        while remaining != 0 {
            let Some(level) = hooks.next_executable_outcome_level(self, complement_asset, capped.side, capped.limit_px, capped.expires_at) else {
                break;
            };
            if !level.crosses(&capped) {
                break;
            }

            let take = min(remaining, level.sz);
            if take == 0 {
                break;
            }
            if !safe_scaled_product(take, capped.limit_px) {
                return self.mark_dirty_for_user(Some(capped.user), OutcomeSide::Main);
            }

            hooks.consume_outcome_level(self, level, take);
            let status = hooks.apply_internal_outcome_leg(self, &capped, level, take);
            if status != INTERNAL_OK {
                return self.result_from_internal_status(Some(capped.user), status, OutcomeSide::Main);
            }

            maker_legs.push(OutcomeMakerLeg { asset: level.asset, sz: take });
            matched = matched.saturating_add(take);
            remaining -= take;
        }

        if matched == 0 {
            return self.mark_dirty_for_user(Some(capped.user), OutcomeSide::Main);
        }

        let generated = GeneratedOutcomeOrder {
            variant: 1,
            user: capped.user,
            asset: capped.asset,
            linked_asset: link.linked_asset,
            side: capped.side,
            oid: capped.oid,
            sz: matched,
            px: capped.limit_px,
            maker_legs,
        };

        let result = hooks.apply_generated_outcome_order(self, &generated);
        if result.code == GENERATED_CONTINUATION_DIRTY {
            return self.mark_dirty_for_user(Some(capped.user), OutcomeSide::Main);
        }
        if !result.is_ok() {
            return result;
        }

        self.emitted.push(generated.clone());
        ActionResult { generated_orders: vec![generated], ..ActionResult::ok() }
    }

    pub fn cancel_outcome_order<H: OutcomeHooks>(
        &mut self,
        hooks: &mut H,
        market_id: MarketId,
        order_id: OrderId,
    ) -> ActionResult {
        let validated = hooks.validate_outcome_order_chain(self, market_id, order_id);
        if !validated.is_ok() {
            return validated;
        }

        let Some(order) = self.books.active_orders.get(&(market_id, order_id)).copied() else {
            return ActionResult::missing_outcome_order();
        };

        let mut last_status = INTERNAL_OK;
        for level in hooks.cancel_unwind_levels(self, market_id, order_id) {
            last_status = hooks.apply_internal_outcome_leg(self, &order, level, level.sz);
            if last_status != INTERNAL_OK {
                break;
            }
        }

        if last_status != INTERNAL_OK {
            self.dirty = true;
            hooks.record_mutation_fault(self);
            return ActionResult::code(DIRTY_REJECT);
        }

        self.books.active_orders.remove(&(market_id, order_id));
        hooks.apply_cancel_book_batch(self, market_id, order_id);
        ActionResult::ok()
    }

    pub fn settle_outcome_market<H: OutcomeHooks>(
        &mut self,
        hooks: &mut H,
        side: OutcomeSide,
        generated_user: Address,
        market_id: MarketId,
        mut scratch: Vec<OutcomeMakerLeg>,
        settlement_price: f64,
    ) -> ActionResult {
        if !valid_settlement_price(settlement_price) {
            scratch.clear();
            return ActionResult::invalid_settlement_price();
        }

        let link = match hooks.lookup_settlement_link(self, market_id) {
            Ok(link) => link,
            Err(result) => {
                scratch.clear();
                return result;
            }
        };

        let mut status = hooks.settle_market_side(self, side, market_id, &mut scratch, settlement_price);
        if link.kind == OutcomeMarketKind::Paired && status == INTERNAL_OK {
            let mut empty = Vec::new();
            status = hooks.settle_market_side(self, side, link.linked_market, &mut empty, 0.0);
        }

        scratch.clear();
        self.result_from_internal_status(Some(generated_user), status, side)
    }

    pub fn set_settlement_price_side_a<H: OutcomeHooks>(
        &mut self,
        hooks: &mut H,
        generated_user: Address,
        market_id: MarketId,
        scratch: Vec<OutcomeMakerLeg>,
        settlement_price: f64,
    ) -> ActionResult {
        self.settle_outcome_market(hooks, OutcomeSide::Main, generated_user, market_id, scratch, settlement_price)
    }

    pub fn set_settlement_price_side_b<H: OutcomeHooks>(
        &mut self,
        hooks: &mut H,
        generated_user: Address,
        market_id: MarketId,
        scratch: Vec<OutcomeMakerLeg>,
        settlement_price: f64,
    ) -> ActionResult {
        self.settle_outcome_market(hooks, OutcomeSide::Mirror, generated_user, market_id, scratch, settlement_price)
    }

    pub fn settle_outcome_market_order_chain<H: OutcomeHooks>(
        &mut self,
        hooks: &mut H,
        side: OutcomeSide,
        user_or_asset: AssetId,
        market_id: MarketId,
    ) -> ActionResult {
        let validated = hooks.validate_outcome_order_chain(self, user_or_asset, market_id);
        if !validated.is_ok() {
            return validated;
        }
        if !hooks.has_open_outcome_order(self, user_or_asset, market_id) {
            return ActionResult::missing_outcome_order();
        }

        let mut saw_leaf = false;
        for level in hooks.settlement_chain_levels(self, user_or_asset, market_id) {
            saw_leaf = true;
            let status = hooks.apply_settlement_chain_leaf(self, side, user_or_asset, market_id, level);
            if status != INTERNAL_OK {
                self.dirty = true;
                hooks.record_mutation_fault(self);
                return ActionResult::code(DIRTY_REJECT);
            }
        }

        if !saw_leaf {
            self.dirty = true;
            hooks.record_mutation_fault(self);
            return ActionResult::code(DIRTY_REJECT);
        }

        let generated = GeneratedOutcomeOrder {
            variant: 7,
            user: [0; 20],
            asset: user_or_asset,
            linked_asset: market_id,
            side: Side::Buy,
            oid: 0,
            sz: 0,
            px: 0,
            maker_legs: Vec::new(),
        };
        hooks.apply_settlement_book_batch(self, side, generated.clone());
        self.emitted.push(generated);
        ActionResult::ok()
    }

    pub fn deploy_outcome_market<H: OutcomeHooks>(
        &mut self,
        hooks: &mut H,
        side: OutcomeSide,
        user: Address,
        deploy_params_a: DeployParamsA,
        market_id: MarketId,
        deploy_params_b: DeployParamsB,
    ) -> ActionResult {
        let deployment = match hooks.validate_outcome_deploy(self, side, user, &deploy_params_a, market_id, &deploy_params_b) {
            Ok(deployment) => deployment,
            Err(result) => return result,
        };

        let primary = self.ensure_outcome_side(hooks, side, user, market_id, deployment.primary_market, deployment.primary_asset, deployment.scalar);
        if !primary.is_ok() {
            return self.fail_deploy(user, side, primary);
        }

        let linked = self.ensure_outcome_side(hooks, side, user, market_id, deployment.linked_market, deployment.linked_asset, deployment.scalar);
        if !linked.is_ok() {
            return self.fail_deploy(user, side, linked);
        }

        hooks.apply_deployment_book_batch(self, side, deployment.clone());
        ActionResult { market_id: Some(deployment.primary_market), ..ActionResult::ok() }
    }

    pub fn deploy_or_convert_outcome_side_a<H: OutcomeHooks>(
        &mut self,
        hooks: &mut H,
        user: Address,
        deploy_params_a: DeployParamsA,
        market_id: MarketId,
        deploy_params_b: DeployParamsB,
    ) -> ActionResult {
        self.deploy_outcome_market(hooks, OutcomeSide::Main, user, deploy_params_a, market_id, deploy_params_b)
    }

    pub fn deploy_or_convert_outcome_side_b<H: OutcomeHooks>(
        &mut self,
        hooks: &mut H,
        user: Address,
        deploy_params_a: DeployParamsA,
        market_id: MarketId,
        deploy_params_b: DeployParamsB,
    ) -> ActionResult {
        self.deploy_outcome_market(hooks, OutcomeSide::Mirror, user, deploy_params_a, market_id, deploy_params_b)
    }

    fn normalize_direct_order_result<H: OutcomeHooks>(
        &mut self,
        hooks: &H,
        result: DirectOrderResult,
        asset: AssetId,
        use_alt_no_fill_code: bool,
    ) -> ActionResult {
        match result {
            DirectOrderResult::Accepted(mut action) => {
                if action.code == GENERATED_CONTINUATION_DIRTY {
                    self.mark_dirty_for_user(None, OutcomeSide::Main)
                } else {
                    action.code = OK;
                    action
                }
            }
            DirectOrderResult::NoFillSentinel => {
                let code = if use_alt_no_fill_code { ALT_NO_FILL } else { DIRECT_NO_FILL };
                ActionResult::no_fill(code, hooks.encode_wire_asset_id(asset))
            }
        }
    }

    pub fn result_from_internal_status(&mut self, maybe_user: Option<Address>, status: u8, side: OutcomeSide) -> ActionResult {
        if status == INTERNAL_OK {
            ActionResult::ok()
        } else {
            self.mark_dirty_for_user(maybe_user, side)
        }
    }

    pub fn record_generated_market_order_user_on_failure(
        &mut self,
        maybe_user: Option<Address>,
        leaf_status: u8,
        side: OutcomeSide,
    ) -> ActionResult {
        self.result_from_internal_status(maybe_user, leaf_status, side)
    }

    fn ensure_outcome_side<H: OutcomeHooks>(
        &mut self,
        hooks: &mut H,
        side: OutcomeSide,
        user: Address,
        requested_market: MarketId,
        market: MarketId,
        asset: AssetId,
        scalar: OutcomeScalar,
    ) -> ActionResult {
        match self.clearinghouses.get(market as usize) {
            Some(slot) if slot.kind != 0 => {
                if slot.asset != Some(asset) || slot.market_id != requested_market {
                    return ActionResult { code: COLLATERAL_MARKET_MISMATCH, market_id: Some(market), ..ActionResult::ok() };
                }
            }
            _ => {
                let collateral = hooks.deploy_outcome_collateral(self, side, user, market, asset);
                if !collateral.is_ok() {
                    return collateral;
                }
                let hyper = hooks.register_outcome_hyperliquidity(self, side, user, asset, ONE_DOT_ZERO, ONE_DOT_ZERO);
                if !hyper.is_ok() {
                    return hyper;
                }
                if (market as usize) >= self.clearinghouses.len() {
                    self.clearinghouses.resize_with(market as usize + 1, ClearinghouseSlot::default);
                }
                self.clearinghouses[market as usize] = ClearinghouseSlot { market_id: requested_market, asset: Some(asset), kind: 1 };
            }
        }

        self.books.spot_mark_px.insert(asset, scalar.rounded_mid_mark());
        ActionResult::ok()
    }

    fn fail_deploy(&mut self, user: Address, side: OutcomeSide, result: ActionResult) -> ActionResult {
        self.dirty = true;
        self.insert_generated_user(side, user);
        if result.code == OK { ActionResult::code(DIRTY_REJECT) } else { result }
    }

    fn mark_dirty_for_user(&mut self, maybe_user: Option<Address>, side: OutcomeSide) -> ActionResult {
        self.dirty = true;
        if let Some(user) = maybe_user {
            self.insert_generated_user(side, user);
        }
        ActionResult::code(DIRTY_REJECT)
    }

    fn insert_generated_user(&mut self, side: OutcomeSide, user: Address) {
        if user == [0; 20] {
            return;
        }
        match side {
            OutcomeSide::Main => {
                self.generated_users_main.insert(user);
            }
            OutcomeSide::Mirror => {
                self.generated_users_mirror.insert(user);
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectOrderResult {
    Accepted(ActionResult),
    NoFillSentinel,
}

pub trait OutcomeHooks {
    fn encode_wire_asset_id(&self, asset: AssetId) -> i64;
    fn apply_normal_order(&mut self, state: &mut ExchangeOutcomeState, order: OutcomeOrder) -> DirectOrderResult;
    fn next_executable_outcome_level(
        &mut self,
        state: &ExchangeOutcomeState,
        asset: AssetId,
        taker_side: Side,
        limit_px: RawPx,
        expires_at: u64,
    ) -> Option<ExecutableLevel>;
    fn consume_outcome_level(&mut self, state: &mut ExchangeOutcomeState, level: ExecutableLevel, sz: RawSz);
    fn apply_internal_outcome_leg(
        &mut self,
        state: &mut ExchangeOutcomeState,
        order: &OutcomeOrder,
        level: ExecutableLevel,
        sz: RawSz,
    ) -> u8;
    fn apply_generated_outcome_order(
        &mut self,
        state: &mut ExchangeOutcomeState,
        generated: &GeneratedOutcomeOrder,
    ) -> ActionResult;
    fn validate_outcome_order_chain(&self, state: &ExchangeOutcomeState, market_id: MarketId, order_id: OrderId) -> ActionResult;
    fn cancel_unwind_levels(&self, state: &ExchangeOutcomeState, market_id: MarketId, order_id: OrderId) -> Vec<ExecutableLevel>;
    fn apply_cancel_book_batch(&mut self, state: &mut ExchangeOutcomeState, market_id: MarketId, order_id: OrderId);
    fn lookup_settlement_link(&self, state: &ExchangeOutcomeState, market_id: MarketId) -> Result<OutcomeLink, ActionResult>;
    fn settle_market_side(
        &mut self,
        state: &mut ExchangeOutcomeState,
        side: OutcomeSide,
        market_id: MarketId,
        scratch: &mut Vec<OutcomeMakerLeg>,
        settlement_price: f64,
    ) -> u8;
    fn has_open_outcome_order(&self, state: &ExchangeOutcomeState, user_or_asset: AssetId, market_id: MarketId) -> bool;
    fn settlement_chain_levels(&self, state: &ExchangeOutcomeState, user_or_asset: AssetId, market_id: MarketId) -> Vec<ExecutableLevel>;
    fn apply_settlement_chain_leaf(
        &mut self,
        state: &mut ExchangeOutcomeState,
        side: OutcomeSide,
        user_or_asset: AssetId,
        market_id: MarketId,
        level: ExecutableLevel,
    ) -> u8;
    fn apply_settlement_book_batch(&mut self, state: &mut ExchangeOutcomeState, side: OutcomeSide, generated: GeneratedOutcomeOrder);
    fn validate_outcome_deploy(
        &self,
        state: &ExchangeOutcomeState,
        side: OutcomeSide,
        user: Address,
        params_a: &DeployParamsA,
        market_id: MarketId,
        params_b: &DeployParamsB,
    ) -> Result<OutcomeDeployment, ActionResult>;
    fn deploy_outcome_collateral(
        &mut self,
        state: &mut ExchangeOutcomeState,
        side: OutcomeSide,
        user: Address,
        market: MarketId,
        asset: AssetId,
    ) -> ActionResult;
    fn register_outcome_hyperliquidity(
        &mut self,
        state: &mut ExchangeOutcomeState,
        side: OutcomeSide,
        user: Address,
        asset: AssetId,
        start_px_1: &str,
        order_sz_1: &str,
    ) -> ActionResult;
    fn apply_deployment_book_batch(&mut self, state: &mut ExchangeOutcomeState, side: OutcomeSide, deployment: OutcomeDeployment);
    fn record_mutation_fault(&mut self, state: &mut ExchangeOutcomeState);
}

#[inline]
pub fn valid_settlement_price(price: f64) -> bool {
    price.is_finite() && price >= 0.0 && price <= 1.0
}

#[inline]
pub fn safe_scaled_product(sz: RawSz, px: RawPx) -> bool {
    (sz as u128).saturating_mul(px as u128) <= MAX_SAFE_GENERATED_PRODUCT
}
