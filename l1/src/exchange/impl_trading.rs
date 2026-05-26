#![allow(dead_code)]

use std::collections::{BTreeMap, VecDeque};

pub type Address = [u8; 20];
pub type AssetId = u64;
pub type DexId = u64;
pub type OrderId = u64;
pub type RawPx = u64;
pub type RawSz = u64;
pub type RawNtl = u64;
pub type ScaledVlm = u64;

pub const ASSETS_PER_DEX: u64 = 10_000;
pub const USER_ACTION_BASE_LIMIT: u64 = 1_000;
pub const USER_ACTION_PRIVILEGED_LIMIT: u64 = 10_000;
pub const USER_ACTION_VOLUME_STEP: u64 = 500_000_000;
pub const USER_ACTION_MAX_VOLUME_BONUS: u64 = 4_000;
pub const MAX_LIMIT_PX: RawPx = 1_000_000_000_000_000;
pub const MAX_MATCH_NOTIONAL: RawNtl = 0x7fff_ffff_ffff_fffe;
pub const MIN_ORDER_NOTIONAL: RawNtl = 0x0098_967f;
pub const PERP_NOTIONAL_PRODUCT_SCALE: u64 = 1_000_000;
pub const SPOT_NOTIONAL_PRODUCT_SCALE: u64 = 100_000_000;

pub const STATUS_SPOT_MARKET_MISSING: u16 = 98;
pub const STATUS_ACTION_CAP: u16 = 195;
pub const STATUS_INTERNAL_UNWRAP: u16 = 321;
pub const STATUS_SUCCESS: u16 = 390;
pub const STATUS_MODIFY: u16 = 391;
pub const STATUS_MODIFY_REPLACED: u16 = 392;
pub const STATUS_QUEUE_MASK: u16 = 0x8003;
pub const STATUS_POST_ONLY_CROSSES: u16 = 0x8006;
pub const STATUS_IOC_NOT_MARKETABLE: u16 = 0x8008;
pub const STATUS_AVAILABLE_SIZE: u16 = 0x8012;
pub const STATUS_NO_VALID_CROSS: u16 = 0x8013;
pub const STATUS_INDEX_ROUTE: u16 = 0x8014;
pub const STATUS_MISSING_REPLACE_SLOT: u16 = 0x8015;
pub const STATUS_DUPLICATE_ORDER: u16 = 0x8017;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExchangeDomain {
    MainBook,
    AltBook,
    PerDex,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MarketKind {
    Perp,
    Spot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Buy,
    Sell,
}

impl Side {
    #[inline]
    pub const fn opposite(self) -> Self {
        match self {
            Self::Buy => Self::Sell,
            Self::Sell => Self::Buy,
        }
    }

    #[inline]
    pub const fn signed_qty(self, sz: RawSz) -> i64 {
        match self {
            Self::Buy => -(sz as i64),
            Self::Sell => sz as i64,
        }
    }

    #[inline]
    pub const fn crosses(self, limit_px: RawPx, maker_px: RawPx) -> bool {
        match self {
            Self::Buy => maker_px <= limit_px,
            Self::Sell => maker_px >= limit_px,
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
    Other(u8),
}

impl TimeInForce {
    #[inline]
    pub const fn must_be_marketable(self) -> bool {
        matches!(self, Self::Ioc | Self::FrontendMarket | Self::LiquidationMarket)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderRequest {
    pub user: Address,
    pub oid: OrderId,
    pub asset: AssetId,
    pub side: Side,
    pub limit_px: RawPx,
    pub sz: RawSz,
    pub reduce_only: bool,
    pub tif: TimeInForce,
    pub cloid: Option<u128>,
    pub timestamp: u64,
    pub builder_nonce: u64,
    pub order_kind: u64,
    pub is_position_tpsl: bool,
    pub use_user_price_qty_lookup: bool,
    pub allow_trigger_cleanup: bool,
    pub owned_fill_vec: bool,
}

impl OrderRequest {
    #[inline]
    pub const fn eligible_for_expanded_cap(&self) -> bool {
        self.order_kind == 2 && !self.reduce_only
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferRequest {
    pub user: Address,
    pub asset: AssetId,
    pub side: Side,
    pub px: RawPx,
    pub sz: RawSz,
    pub account_kind: u8,
    pub exempt_flags: u8,
}

impl TransferRequest {
    #[inline]
    pub const fn eligible_for_expanded_cap(&self) -> bool {
        self.account_kind == 2 && (self.exempt_flags & 1) == 0
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AssetContext {
    pub tick_sz: RawPx,
    pub oracle_px: RawPx,
    pub min_order_sz: RawSz,
    pub max_order_sz: RawSz,
    pub price_limit_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestingOrder {
    pub user: Address,
    pub oid: OrderId,
    pub asset: AssetId,
    pub side: Side,
    pub px: RawPx,
    pub resting_sz: RawSz,
    pub original_sz: RawSz,
    pub reduce_only: bool,
    pub tif: TimeInForce,
    pub cloid: Option<u128>,
    pub timestamp: u64,
    pub builder_nonce: u64,
    pub order_kind: u64,
}

impl RestingOrder {
    fn from_request(request: &OrderRequest, resting_sz: RawSz) -> Self {
        Self {
            user: request.user,
            oid: request.oid,
            asset: request.asset,
            side: request.side,
            px: request.limit_px,
            resting_sz,
            original_sz: request.sz,
            reduce_only: request.reduce_only,
            tif: request.tif,
            cloid: request.cloid,
            timestamp: request.timestamp,
            builder_nonce: request.builder_nonce,
            order_kind: request.order_kind,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fill {
    pub id: u64,
    pub taker: Address,
    pub maker: Address,
    pub taker_oid: OrderId,
    pub maker_oid: OrderId,
    pub asset: AssetId,
    pub px: RawPx,
    pub sz: RawSz,
    pub ntl: RawNtl,
    pub taker_side: Side,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedSzDelta {
    pub user: Address,
    pub asset: AssetId,
    pub delta: i64,
    pub px: RawPx,
    pub ntl: RawNtl,
    pub is_taker: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TradingEvent {
    Fill(Fill),
    Rest { user: Address, oid: OrderId, asset: AssetId, px: RawPx, sz: RawSz },
    Cancel { user: Address, oid: OrderId, code: u8 },
    MakerStatus { user: Address, oid: OrderId, code: u8 },
    BestBidAsk { asset: AssetId, best_bid: Option<RawPx>, best_ask: Option<RawPx> },
    Telemetry(OrderTelemetry),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderTelemetry {
    pub user: Address,
    pub market: MarketKind,
    pub success: bool,
    pub status: u16,
    pub notional_scaled: RawNtl,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TradingResult {
    pub status: u16,
    pub remaining_sz: RawSz,
    pub fills: Vec<Fill>,
    pub deltas: Vec<SignedSzDelta>,
    pub events: Vec<TradingEvent>,
    pub rested_oid: Option<OrderId>,
}

impl TradingResult {
    #[inline]
    pub fn rejected(status: u16) -> Self {
        Self {
            status,
            remaining_sz: 0,
            fills: Vec::new(),
            deltas: Vec::new(),
            events: Vec::new(),
            rested_oid: None,
        }
    }

    #[inline]
    pub fn ok(remaining_sz: RawSz) -> Self {
        Self {
            status: STATUS_SUCCESS,
            remaining_sz,
            fills: Vec::new(),
            deltas: Vec::new(),
            events: Vec::new(),
            rested_oid: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModifyRequest {
    pub old_user: Address,
    pub old_oid: OrderId,
    pub replacement: OrderRequest,
    pub require_existing_slot: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModifyResult {
    pub status: u16,
    pub inner_status: u16,
    pub old_order: Option<RestingOrder>,
    pub replacement: TradingResult,
}

#[derive(Clone, Debug, Default)]
pub struct PriceLevel {
    pub queue: VecDeque<OrderId>,
}

#[derive(Clone, Debug, Default)]
pub struct OrderBook {
    pub bids: BTreeMap<RawPx, PriceLevel>,
    pub asks: BTreeMap<RawPx, PriceLevel>,
    pub orders: BTreeMap<OrderId, RestingOrder>,
    pub user_oids: BTreeMap<(Address, OrderId), OrderId>,
    pub user_price_qty: BTreeMap<(Address, OrderId), i64>,
    pub best_bid: Option<RawPx>,
    pub best_ask: Option<RawPx>,
}

impl OrderBook {
    fn side_levels(&self, side: Side) -> &BTreeMap<RawPx, PriceLevel> {
        match side {
            Side::Buy => &self.bids,
            Side::Sell => &self.asks,
        }
    }

    fn side_levels_mut(&mut self, side: Side) -> &mut BTreeMap<RawPx, PriceLevel> {
        match side {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        }
    }

    fn best_crossable_px(&self, side: Side, limit_px: RawPx) -> Option<RawPx> {
        match side {
            Side::Buy => self.asks.keys().next().copied().filter(|px| *px <= limit_px),
            Side::Sell => self.bids.keys().next_back().copied().filter(|px| *px >= limit_px),
        }
    }

    fn is_marketable(&self, side: Side, limit_px: RawPx) -> bool {
        self.best_crossable_px(side, limit_px).is_some()
    }

    fn level_snapshot(&self, side: Side, px: RawPx) -> Vec<OrderId> {
        self.side_levels(side)
            .get(&px)
            .map(|level| level.queue.iter().copied().collect())
            .unwrap_or_default()
    }

    fn insert_resting(&mut self, order: RestingOrder) {
        let oid = order.oid;
        let user = order.user;
        let side = order.side;
        let px = order.px;
        let signed_qty = side.signed_qty(order.resting_sz);
        self.orders.insert(oid, order);
        self.user_oids.insert((user, oid), oid);
        self.user_price_qty.insert((user, oid), signed_qty);
        self.side_levels_mut(side).entry(px).or_default().queue.push_back(oid);
        self.refresh_best_bid_ask();
    }

    fn remove_order(&mut self, user: Address, oid: OrderId, code: u8) -> Option<(RestingOrder, TradingEvent)> {
        let indexed = self.user_oids.remove(&(user, oid))?;
        let order = self.orders.remove(&indexed)?;
        self.user_price_qty.remove(&(order.user, order.oid));
        if let Some(level) = self.side_levels_mut(order.side).get_mut(&order.px) {
            level.queue.retain(|queued_oid| *queued_oid != order.oid);
        }
        self.remove_empty_levels(order.side, order.px);
        self.refresh_best_bid_ask();
        Some((order.clone(), TradingEvent::Cancel { user: order.user, oid: order.oid, code }))
    }

    fn update_resting_sz(&mut self, oid: OrderId, new_sz: RawSz) {
        if let Some(order) = self.orders.get_mut(&oid) {
            order.resting_sz = new_sz;
            self.user_price_qty.insert((order.user, order.oid), order.side.signed_qty(new_sz));
        }
    }

    fn remove_empty_levels(&mut self, side: Side, px: RawPx) {
        let remove = self.side_levels(side).get(&px).map(|level| level.queue.is_empty()).unwrap_or(false);
        if remove {
            self.side_levels_mut(side).remove(&px);
        }
    }

    fn refresh_best_bid_ask(&mut self) {
        self.best_bid = self.bids.keys().next_back().copied();
        self.best_ask = self.asks.keys().next().copied();
    }
}

#[derive(Clone, Debug, Default)]
pub struct PerDexState {
    pub books: BTreeMap<AssetId, OrderBook>,
    pub asset_contexts: BTreeMap<AssetId, AssetContext>,
    pub user_scaled_vlm: BTreeMap<Address, ScaledVlm>,
}

#[derive(Clone, Debug, Default)]
pub struct ExchangeState {
    pub main: PerDexState,
    pub alt: PerDexState,
    pub per_dex: Vec<PerDexState>,
    pub spot_books: BTreeMap<AssetId, OrderBook>,
    pub spot_contexts: BTreeMap<AssetId, AssetContext>,
    pub special_spot_allowlist: BTreeMap<AssetId, ()>,
    pub base_user_scaled_vlm: BTreeMap<Address, ScaledVlm>,
    pub user_action_count: BTreeMap<Address, u64>,
    pub submitted_order_count: u64,
    pub successful_order_count: u64,
    pub submitted_transfer_count: u64,
    pub successful_transfer_count: u64,
    pub next_fill_id: u64,
    pub emitted_events: Vec<TradingEvent>,
}

impl ExchangeState {
    pub fn check_cap_and_execute_perp_order_main(
        &mut self,
        request: OrderRequest,
        ctx: &AssetContext,
    ) -> TradingResult {
        self.check_cap_and_execute_perp_order(ExchangeDomain::MainBook, request, ctx)
    }

    pub fn check_cap_and_execute_perp_order_per_dex(
        &mut self,
        request: OrderRequest,
        ctx: &AssetContext,
    ) -> TradingResult {
        self.check_cap_and_execute_perp_order(ExchangeDomain::PerDex, request, ctx)
    }

    pub fn check_cap_and_execute_spot_order_main(
        &mut self,
        request: OrderRequest,
        ctx: &AssetContext,
    ) -> TradingResult {
        self.check_cap_and_execute_spot_order(ExchangeDomain::MainBook, request, ctx)
    }

    pub fn check_cap_and_execute_spot_order_per_dex(
        &mut self,
        request: OrderRequest,
        ctx: &AssetContext,
    ) -> TradingResult {
        self.check_cap_and_execute_spot_order(ExchangeDomain::PerDex, request, ctx)
    }

    pub fn process_perp_transfer_with_volume_accounting(
        &mut self,
        transfer: TransferRequest,
    ) -> TradingResult {
        self.submitted_transfer_count = self.submitted_transfer_count.saturating_add(1);
        if !self.check_user_action_cap(transfer.user, transfer.eligible_for_expanded_cap()) {
            return TradingResult::rejected(STATUS_ACTION_CAP);
        }

        let Some((dex, _local_asset)) = split_asset(transfer.asset) else {
            return TradingResult::rejected(STATUS_INTERNAL_UNWRAP);
        };
        if dex as usize >= self.per_dex.len() {
            return TradingResult::rejected(STATUS_INTERNAL_UNWRAP);
        }

        let ntl = match checked_notional(transfer.sz, transfer.px) {
            Some(value) => value / PERP_NOTIONAL_PRODUCT_SCALE,
            None => return TradingResult::rejected(STATUS_QUEUE_MASK),
        };
        self.successful_transfer_count = self.successful_transfer_count.saturating_add(1);
        let mut result = TradingResult::ok(0);
        result.events.push(TradingEvent::Telemetry(OrderTelemetry {
            user: transfer.user,
            market: MarketKind::Perp,
            success: true,
            status: STATUS_SUCCESS,
            notional_scaled: ntl,
        }));
        result
    }

    pub fn process_spot_transfer_with_volume_accounting(
        &mut self,
        transfer: TransferRequest,
    ) -> TradingResult {
        self.submitted_transfer_count = self.submitted_transfer_count.saturating_add(1);
        if !self.check_user_action_cap(transfer.user, transfer.eligible_for_expanded_cap()) {
            return TradingResult::rejected(STATUS_ACTION_CAP);
        }
        if !self.spot_market_exists(transfer.asset) {
            return TradingResult::rejected(STATUS_SPOT_MARKET_MISSING);
        }

        let ntl = match checked_notional(transfer.sz, transfer.px) {
            Some(value) => value / SPOT_NOTIONAL_PRODUCT_SCALE,
            None => return TradingResult::rejected(STATUS_QUEUE_MASK),
        };
        self.successful_transfer_count = self.successful_transfer_count.saturating_add(1);
        let mut result = TradingResult::ok(0);
        result.events.push(TradingEvent::Telemetry(OrderTelemetry {
            user: transfer.user,
            market: MarketKind::Spot,
            success: true,
            status: STATUS_SUCCESS,
            notional_scaled: ntl,
        }));
        result
    }

    fn check_cap_and_execute_perp_order(
        &mut self,
        domain: ExchangeDomain,
        request: OrderRequest,
        ctx: &AssetContext,
    ) -> TradingResult {
        self.submitted_order_count = self.submitted_order_count.saturating_add(1);
        if !self.check_user_action_cap(request.user, request.eligible_for_expanded_cap()) {
            return TradingResult::rejected(STATUS_ACTION_CAP);
        }

        let Some((dex, local_asset)) = split_asset(request.asset) else {
            return TradingResult::rejected(STATUS_INTERNAL_UNWRAP);
        };
        let asset = if matches!(domain, ExchangeDomain::PerDex) { local_asset } else { request.asset };
        let result = self.execute_perp_order(domain, dex, asset, request, ctx);
        self.after_order_execution(MarketKind::Perp, &result);
        result
    }

    fn check_cap_and_execute_spot_order(
        &mut self,
        _domain: ExchangeDomain,
        request: OrderRequest,
        ctx: &AssetContext,
    ) -> TradingResult {
        self.submitted_order_count = self.submitted_order_count.saturating_add(1);
        if !self.check_user_action_cap(request.user, request.eligible_for_expanded_cap()) {
            return TradingResult::rejected(STATUS_ACTION_CAP);
        }
        if !self.spot_market_exists(request.asset) {
            return TradingResult::rejected(STATUS_SPOT_MARKET_MISSING);
        }

        let result = self.execute_spot_order(request, ctx);
        self.after_order_execution(MarketKind::Spot, &result);
        result
    }

    pub fn cancel_order(
        &mut self,
        domain: ExchangeDomain,
        asset: AssetId,
        user: Address,
        oid: OrderId,
    ) -> TradingResult {
        let book = match self.book_mut(domain, asset) {
            Some(book) => book,
            None => return TradingResult::rejected(STATUS_INTERNAL_UNWRAP),
        };
        let mut result = TradingResult::ok(0);
        match book.remove_order(user, oid, 13) {
            Some((_order, event)) => result.events.push(event),
            None => result.status = STATUS_MISSING_REPLACE_SLOT,
        }
        book.refresh_best_bid_ask();
        if let Some(event) = best_bid_ask_event(asset, book) {
            result.events.push(event);
        }
        result
    }

    pub fn replace_order_after_existing_lookup_main_book(
        &mut self,
        modify: ModifyRequest,
        ctx: &AssetContext,
    ) -> ModifyResult {
        self.replace_order_after_existing_lookup(ExchangeDomain::MainBook, modify, ctx)
    }

    pub fn replace_order_after_existing_lookup_alt_book(
        &mut self,
        modify: ModifyRequest,
        ctx: &AssetContext,
    ) -> ModifyResult {
        self.replace_order_after_existing_lookup(ExchangeDomain::AltBook, modify, ctx)
    }

    pub fn replace_order_after_existing_lookup(
        &mut self,
        domain: ExchangeDomain,
        modify: ModifyRequest,
        ctx: &AssetContext,
    ) -> ModifyResult {
        let asset = modify.replacement.asset;
        let removed = {
            let Some(book) = self.book_mut(domain, asset) else {
                return ModifyResult {
                    status: STATUS_MODIFY,
                    inner_status: STATUS_INTERNAL_UNWRAP,
                    old_order: None,
                    replacement: TradingResult::rejected(STATUS_INTERNAL_UNWRAP),
                };
            };
            book.remove_order(modify.old_user, modify.old_oid, 13)
        };

        let Some((old_order, cancel_event)) = removed else {
            let inner = if modify.require_existing_slot { STATUS_MISSING_REPLACE_SLOT } else { STATUS_AVAILABLE_SIZE };
            return ModifyResult {
                status: STATUS_MODIFY,
                inner_status: inner,
                old_order: None,
                replacement: TradingResult::rejected(inner),
            };
        };

        let mut replacement = self.check_cap_and_execute_perp_order(domain, modify.replacement.clone(), ctx);
        replacement.events.insert(0, cancel_event);
        if replacement.status != STATUS_SUCCESS {
            if let Some(book) = self.book_mut(domain, asset) {
                book.insert_resting(old_order.clone());
            }
            return ModifyResult {
                status: STATUS_MODIFY,
                inner_status: replacement.status,
                old_order: Some(old_order),
                replacement,
            };
        }

        ModifyResult {
            status: STATUS_MODIFY_REPLACED,
            inner_status: replacement.status,
            old_order: Some(old_order),
            replacement,
        }
    }

    pub fn apply_trade_outcome_main_book(
        &mut self,
        asset: AssetId,
        fills: Vec<Fill>,
    ) -> TradingResult {
        self.apply_trade_outcome(ExchangeDomain::MainBook, asset, fills)
    }

    pub fn apply_trade_outcome_alt_book(
        &mut self,
        asset: AssetId,
        fills: Vec<Fill>,
    ) -> TradingResult {
        self.apply_trade_outcome(ExchangeDomain::AltBook, asset, fills)
    }

    pub fn process_perp_dex_order(
        &mut self,
        dex: DexId,
        asset: AssetId,
        request: OrderRequest,
        ctx: &AssetContext,
    ) -> TradingResult {
        let result = self.execute_perp_order(ExchangeDomain::PerDex, dex, asset, request, ctx);
        if result.status != STATUS_SUCCESS {
            return result;
        }
        self.apply_trade_outcome(ExchangeDomain::PerDex, asset, result.fills.clone())
    }

    fn execute_perp_order(
        &mut self,
        domain: ExchangeDomain,
        dex: DexId,
        asset: AssetId,
        mut request: OrderRequest,
        ctx: &AssetContext,
    ) -> TradingResult {
        if matches!(domain, ExchangeDomain::PerDex) && dex as usize >= self.per_dex.len() {
            return TradingResult::rejected(STATUS_INTERNAL_UNWRAP);
        }
        request.asset = asset;
        let mut result = if matches!(domain, ExchangeDomain::PerDex) {
            let Some(dex_state) = self.per_dex.get_mut(dex as usize) else {
                return TradingResult::rejected(STATUS_INTERNAL_UNWRAP);
            };
            let book = dex_state.books.entry(asset).or_default();
            execute_book_order(book, request, ctx)
        } else {
            let Some(book) = self.book_mut(domain, asset) else {
                return TradingResult::rejected(STATUS_INTERNAL_UNWRAP);
            };
            execute_book_order(book, request, ctx)
        };
        self.assign_fill_ids(&mut result);
        result
    }

    fn execute_spot_order(&mut self, request: OrderRequest, ctx: &AssetContext) -> TradingResult {
        let mut result = {
            let book = self.spot_books.entry(request.asset).or_default();
            execute_book_order(book, request, ctx)
        };
        self.assign_fill_ids(&mut result);
        result
    }

    fn apply_trade_outcome(
        &mut self,
        domain: ExchangeDomain,
        asset: AssetId,
        fills: Vec<Fill>,
    ) -> TradingResult {
        let mut result = TradingResult::ok(0);
        for mut fill in fills {
            if fill.id == 0 {
                fill.id = self.allocate_fill_id();
            }
            let maker_delta = fill.taker_side.opposite().signed_qty(fill.sz);
            let taker_delta = fill.taker_side.signed_qty(fill.sz);
            result.deltas.push(SignedSzDelta {
                user: fill.maker,
                asset,
                delta: maker_delta,
                px: fill.px,
                ntl: fill.ntl,
                is_taker: false,
            });
            result.deltas.push(SignedSzDelta {
                user: fill.taker,
                asset,
                delta: taker_delta,
                px: fill.px,
                ntl: fill.ntl,
                is_taker: true,
            });
            result.events.push(TradingEvent::Fill(fill.clone()));
            result.fills.push(fill);
        }

        if let Some(book) = self.book_mut(domain, asset) {
            book.refresh_best_bid_ask();
            if let Some(event) = best_bid_ask_event(asset, book) {
                result.events.push(event);
            }
        }
        result
    }

    fn check_user_action_cap(&mut self, user: Address, eligible_for_expanded_cap: bool) -> bool {
        let current = self.user_action_count.get(&user).copied().unwrap_or(0);
        if current < USER_ACTION_BASE_LIMIT {
            self.user_action_count.insert(user, current + 1);
            return true;
        }
        if !eligible_for_expanded_cap {
            return false;
        }

        let cap = if is_vault_privileged(user) {
            USER_ACTION_PRIVILEGED_LIMIT
        } else {
            let total = self.total_scaled_vlm_for_user(user);
            USER_ACTION_BASE_LIMIT + (total / USER_ACTION_VOLUME_STEP).min(USER_ACTION_MAX_VOLUME_BONUS)
        };
        if current >= cap {
            false
        } else {
            self.user_action_count.insert(user, current + 1);
            true
        }
    }

    fn total_scaled_vlm_for_user(&self, user: Address) -> ScaledVlm {
        let mut total = self.base_user_scaled_vlm.get(&user).copied().unwrap_or(0);
        total = total.saturating_add(self.main.user_scaled_vlm.get(&user).copied().unwrap_or(0));
        total = total.saturating_add(self.alt.user_scaled_vlm.get(&user).copied().unwrap_or(0));
        for dex in &self.per_dex {
            total = total.saturating_add(dex.user_scaled_vlm.get(&user).copied().unwrap_or(0));
        }
        total
    }

    fn spot_market_exists(&self, asset: AssetId) -> bool {
        self.special_spot_allowlist.contains_key(&asset)
            || self.spot_contexts.contains_key(&asset)
            || self.spot_books.contains_key(&asset)
    }

    fn after_order_execution(&mut self, market: MarketKind, result: &TradingResult) {
        if result.status == STATUS_SUCCESS {
            self.successful_order_count = self.successful_order_count.saturating_add(1);
        }
        if let Some(fill) = result.fills.last() {
            self.emitted_events.push(TradingEvent::Telemetry(OrderTelemetry {
                user: fill.taker,
                market,
                success: result.status == STATUS_SUCCESS,
                status: result.status,
                notional_scaled: match market {
                    MarketKind::Perp => fill.ntl / PERP_NOTIONAL_PRODUCT_SCALE,
                    MarketKind::Spot => fill.ntl / SPOT_NOTIONAL_PRODUCT_SCALE,
                },
            }));
        }
    }

    fn book_mut(&mut self, domain: ExchangeDomain, asset: AssetId) -> Option<&mut OrderBook> {
        match domain {
            ExchangeDomain::MainBook => Some(self.main.books.entry(asset).or_default()),
            ExchangeDomain::AltBook => Some(self.alt.books.entry(asset).or_default()),
            ExchangeDomain::PerDex => {
                let (dex, local_asset) = split_asset(asset)?;
                self.per_dex.get_mut(dex as usize).map(|state| state.books.entry(local_asset).or_default())
            }
        }
    }

    fn allocate_fill_id(&mut self) -> u64 {
        let id = self.next_fill_id;
        self.next_fill_id = self.next_fill_id.saturating_add(1);
        id
    }
    fn assign_fill_ids(&mut self, result: &mut TradingResult) {
        let mut replacements = Vec::new();
        for fill in &mut result.fills {
            if fill.id == 0 {
                fill.id = self.allocate_fill_id();
                replacements.push((fill.taker_oid, fill.maker_oid, fill.id));
            }
        }
        for event in &mut result.events {
            if let TradingEvent::Fill(fill) = event {
                for (taker_oid, maker_oid, id) in &replacements {
                    if fill.id == 0 && fill.taker_oid == *taker_oid && fill.maker_oid == *maker_oid {
                        fill.id = *id;
                        break;
                    }
                }
            }
        }
    }
}

fn execute_book_order(
    book: &mut OrderBook,
    request: OrderRequest,
    ctx: &AssetContext,
) -> TradingResult {
    if book.orders.contains_key(&request.oid) || book.user_oids.contains_key(&(request.user, request.oid)) {
        return TradingResult::rejected(STATUS_DUPLICATE_ORDER);
    }
    if request.limit_px == 0 || request.limit_px > MAX_LIMIT_PX || !valid_tick(request.limit_px, ctx.tick_sz) {
        return TradingResult::rejected(STATUS_QUEUE_MASK);
    }
    let mut remaining_sz = request.sz;
    if remaining_sz == 0 {
        return TradingResult::rejected(STATUS_AVAILABLE_SIZE);
    }
    if !valid_order_size(ctx, remaining_sz) {
        return TradingResult::rejected(STATUS_AVAILABLE_SIZE);
    }
    if !valid_notional(ctx, remaining_sz, request.limit_px) {
        return TradingResult::rejected(STATUS_QUEUE_MASK);
    }

    let marketable = book.is_marketable(request.side, request.limit_px);
    if request.tif == TimeInForce::Alo && marketable {
        return TradingResult::rejected(STATUS_POST_ONLY_CROSSES);
    }
    if request.tif.must_be_marketable() && !marketable {
        return TradingResult::rejected(STATUS_IOC_NOT_MARKETABLE);
    }

    let mut result = TradingResult::ok(remaining_sz);
    while remaining_sz != 0 {
        let Some(level_px) = book.best_crossable_px(request.side, request.limit_px) else {
            break;
        };
        if ctx.price_limit_enabled && ctx.oracle_px != 0 && !price_level_inside_oracle_band(request.side, level_px, ctx.oracle_px) {
            if result.fills.is_empty() {
                return TradingResult::rejected(STATUS_NO_VALID_CROSS);
            }
            break;
        }

        let resting_oids = book.level_snapshot(request.side.opposite(), level_px);
        if resting_oids.is_empty() {
            book.remove_empty_levels(request.side.opposite(), level_px);
            continue;
        }

        for maker_oid in resting_oids {
            if remaining_sz == 0 || !request.side.crosses(request.limit_px, level_px) {
                break;
            }
            let Some(maker) = book.orders.get(&maker_oid).cloned() else {
                continue;
            };
            if maker.user == request.user || both_vault_privileged(maker.user, request.user) {
                result.events.push(TradingEvent::MakerStatus { user: maker.user, oid: maker.oid, code: 9 });
                continue;
            }

            let match_sz = remaining_sz.min(maker.resting_sz).min(max_order_sz(ctx));
            if match_sz == 0 {
                result.events.push(TradingEvent::MakerStatus { user: maker.user, oid: maker.oid, code: 10 });
                continue;
            }
            let Some(ntl) = checked_notional(match_sz, maker.px) else {
                return TradingResult::rejected(STATUS_QUEUE_MASK);
            };

            let fill = Fill {
                id: 0,
                taker: request.user,
                maker: maker.user,
                taker_oid: request.oid,
                maker_oid: maker.oid,
                asset: request.asset,
                px: maker.px,
                sz: match_sz,
                ntl,
                taker_side: request.side,
            };
            remaining_sz -= match_sz;
            result.fills.push(fill.clone());
            result.events.push(TradingEvent::Fill(fill));
            result.deltas.push(SignedSzDelta {
                user: maker.user,
                asset: request.asset,
                delta: maker.side.signed_qty(match_sz),
                px: maker.px,
                ntl,
                is_taker: false,
            });
            result.deltas.push(SignedSzDelta {
                user: request.user,
                asset: request.asset,
                delta: request.side.signed_qty(match_sz),
                px: maker.px,
                ntl,
                is_taker: true,
            });

            let maker_remaining = maker.resting_sz - match_sz;
            if maker_remaining == 0 {
                if let Some((_removed, event)) = book.remove_order(maker.user, maker.oid, 5) {
                    result.events.push(event);
                }
            } else {
                book.update_resting_sz(maker.oid, maker_remaining);
            }
        }
        book.remove_empty_levels(request.side.opposite(), level_px);
    }

    result.remaining_sz = remaining_sz;
    if remaining_sz == 0 {
        if request.allow_trigger_cleanup {
            result.events.push(TradingEvent::Cancel { user: request.user, oid: request.oid, code: 1 });
        }
        push_bbo_event(book, request.asset, &mut result.events);
        return result;
    }

    if request.tif.must_be_marketable() || request.tif == TimeInForce::Alo && marketable {
        push_bbo_event(book, request.asset, &mut result.events);
        return result;
    }

    book.insert_resting(RestingOrder::from_request(&request, remaining_sz));
    result.rested_oid = Some(request.oid);
    result.events.push(TradingEvent::Rest {
        user: request.user,
        oid: request.oid,
        asset: request.asset,
        px: request.limit_px,
        sz: remaining_sz,
    });
    push_bbo_event(book, request.asset, &mut result.events);
    result
}

fn push_bbo_event(book: &OrderBook, asset: AssetId, events: &mut Vec<TradingEvent>) {
    if let Some(event) = best_bid_ask_event(asset, book) {
        events.push(event);
    }
}

fn best_bid_ask_event(asset: AssetId, book: &OrderBook) -> Option<TradingEvent> {
    Some(TradingEvent::BestBidAsk { asset, best_bid: book.best_bid, best_ask: book.best_ask })
}

#[inline]
fn split_asset(asset: AssetId) -> Option<(DexId, AssetId)> {
    Some((asset / ASSETS_PER_DEX, asset % ASSETS_PER_DEX))
}

#[inline]
fn valid_tick(px: RawPx, tick: RawPx) -> bool {
    tick != 0 && px % tick == 0
}

#[inline]
fn checked_notional(sz: RawSz, px: RawPx) -> Option<RawNtl> {
    sz.checked_mul(px).filter(|ntl| *ntl <= MAX_MATCH_NOTIONAL)
}

fn valid_notional(ctx: &AssetContext, sz: RawSz, px: RawPx) -> bool {
    match (checked_notional(sz, px), checked_notional(sz, ctx.oracle_px)) {
        (Some(limit_ntl), Some(oracle_ntl)) => {
            limit_ntl <= MAX_MATCH_NOTIONAL && oracle_ntl <= MAX_MATCH_NOTIONAL && oracle_ntl > MIN_ORDER_NOTIONAL
        }
        _ => false,
    }
}

#[inline]
fn valid_order_size(ctx: &AssetContext, sz: RawSz) -> bool {
    sz >= ctx.min_order_sz && (ctx.max_order_sz == 0 || sz <= ctx.max_order_sz)
}

#[inline]
fn max_order_sz(ctx: &AssetContext) -> RawSz {
    if ctx.max_order_sz == 0 { RawSz::MAX } else { ctx.max_order_sz }
}

fn price_level_inside_oracle_band(side: Side, px: RawPx, oracle_px: RawPx) -> bool {
    // [INFERENCE] The binary gates crossings through a global price-limit flag and
    // an oracle context helper.  The branch only allows matching while the level is
    // on the same side of the oracle anchor and rejects the first fill with status 0x8013.
    match side {
        Side::Buy => px <= oracle_px.saturating_mul(5) / 4,
        Side::Sell => px.saturating_mul(4) >= oracle_px.saturating_mul(3),
    }
}

#[inline]
fn both_vault_privileged(a: Address, b: Address) -> bool {
    is_vault_privileged(a) && is_vault_privileged(b)
}

#[inline]
fn is_vault_privileged(user: Address) -> bool {
    user[0] != 0 && user[19] == 0
}
