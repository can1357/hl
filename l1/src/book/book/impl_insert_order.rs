use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub type OrderId = u64;
pub type Px = u64;
pub type Sz = u64;
pub type Ntl = u64;

const ASSET_DIVISOR: u64 = 10_000;
const BOOK_STRIDE_BYTES: usize = 752;
const RESTING_ORDER_SLOT_BYTES: usize = 248;
const MAX_LIMIT_PX: Px = 1_000_000_000_000_000;
const MAX_NOTIONAL: Ntl = 0x7fff_ffff_ffff_fffe;
const MIN_NOTIONAL_FLOOR: Ntl = 0x0098_967f;

const STATUS_PRICE_OR_TICK: InsertStatus = InsertStatus(0x8000_0000_0000_0000);
const STATUS_NOTIONAL: InsertStatus = InsertStatus(0x8000_0000_0000_0001);
const STATUS_QUEUE_MASK: InsertStatus = InsertStatus(0x8000_0000_0000_0003);
const STATUS_NO_USER_PRICE_QTY: InsertStatus = InsertStatus(0x8000_0000_0000_0005);
const STATUS_POST_ONLY_CROSSES: InsertStatus = InsertStatus(0x8000_0000_0000_0006);
const STATUS_TIF_NOT_MARKETABLE: InsertStatus = InsertStatus(0x8000_0000_0000_0008);
const STATUS_AVAILABLE_SIZE: InsertStatus = InsertStatus(0x8000_0000_0000_0012);
const STATUS_NO_VALID_CROSS: InsertStatus = InsertStatus(0x8000_0000_0000_0013);
const STATUS_INDEX_ROUTE: InsertStatus = InsertStatus(0x8000_0000_0000_0014);
const STATUS_SLOT_EMPTY_FOR_REPLACE: InsertStatus = InsertStatus(0x8000_0000_0000_0015);
const STATUS_SLOT_MISSING: InsertStatus = InsertStatus(0x8000_0000_0000_0016);
const STATUS_DUPLICATE_ORDER: InsertStatus = InsertStatus(0x8000_0000_0000_0017);
const STATUS_OK: InsertStatus = InsertStatus(0x8000_0000_0000_0018);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UserKey20 {
    pub bytes: [u8; 20],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InsertStatus(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Buy,
    Sell,
}

impl Side {
    #[inline]
    pub fn opposite(self) -> Self {
        match self {
            Self::Buy => Self::Sell,
            Self::Sell => Self::Buy,
        }
    }

    #[inline]
    pub fn signed_price_key(self, px: Px) -> i64 {
        // The binary stores one side as `px` and the other as `-px`; the sign is
        // used only to merge side and price into a B-tree key.  The public side
        // naming here keeps normal book semantics: bids are buy, asks are sell.
        match self {
            Self::Buy => -(px as i64),
            Self::Sell => px as i64,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertTif {
    AddLiquidityOnly,
    ImmediateOrCancel,
    Normal,
    FrontendMarket,
    LiquidationMarket,
    Other(u8),
}

impl InsertTif {
    #[inline]
    pub fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::AddLiquidityOnly,
            1 => Self::ImmediateOrCancel,
            2 => Self::Normal,
            3 => Self::FrontendMarket,
            4 => Self::LiquidationMarket,
            other => Self::Other(other),
        }
    }

    #[inline]
    fn must_be_marketable(self) -> bool {
        matches!(self, Self::ImmediateOrCancel | Self::FrontendMarket | Self::LiquidationMarket)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestingMatchReason {
    MakerLiquidityExhausted,
    MissingUserPriceQuantity,
    SelfCrossOrVaultCross,
    DirectRemainingSize,
}

impl RestingMatchReason {
    #[inline]
    fn maker_event_code(self) -> Option<u8> {
        match self {
            Self::MakerLiquidityExhausted => Some(10),
            Self::MissingUserPriceQuantity => Some(9),
            Self::SelfCrossOrVaultCross | Self::DirectRemainingSize => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InsertOrderArgs {
    pub oid: OrderId,
    pub user: UserKey20,
    pub side: Side,
    pub limit_px: Px,
    pub sz: Sz,
    pub remaining_override: Option<Sz>,
    pub tif: InsertTif,
    pub reduce_only: bool,
    pub cloid: Option<u128>,
    pub timestamp: u64,
    pub builder_nonce: u64,
    pub order_kind: u64,
    pub is_position_tpsl: bool,
    pub use_user_price_qty_lookup: bool,
    pub allow_trigger_cleanup: bool,
    pub is_replace: bool,
    pub replace_slot_required: bool,
    pub raw_accounting_key: u32,
}

impl InsertOrderArgs {
    #[inline]
    fn remaining_sz(&self) -> Sz {
        self.remaining_override.unwrap_or(self.sz)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestingOrder {
    /// Slot status at `+0`; the recovered code treats value `2` as vacant/dead.
    pub status: SlotStatus,
    /// `+0x10`/`+0x18` in the 248-byte slot are the linked queue neighbors.
    pub prev_key: Option<usize>,
    pub next_key: Option<usize>,
    pub oid: OrderId,
    pub user: UserKey20,
    pub side: Side,
    pub px: Px,
    pub resting_sz: Sz,
    pub orig_sz: Sz,
    pub reduce_only: bool,
    pub is_position_tpsl: bool,
    pub tif: InsertTif,
    pub cloid: Option<u128>,
    pub timestamp: u64,
    pub builder_nonce: u64,
    pub raw_accounting_key: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotStatus {
    Empty,
    Occupied,
    Removed,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Level {
    /// Recovered `Level` begins with first key; last key is adjacent.
    pub first_key: Option<usize>,
    pub last_key: Option<usize>,
    pub queue: VecDeque<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FillRecord {
    pub taker: UserKey20,
    pub maker: UserKey20,
    pub taker_oid: OrderId,
    pub maker_oid: OrderId,
    pub px: Px,
    pub sz: Sz,
    pub ntl: Ntl,
    pub taker_side: Side,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BookEvent {
    Fill(FillRecord),
    MakerUserEvent { user: UserKey20, oid: OrderId, code: u8 },
    RemoveOrder { user: UserKey20, oid: OrderId, code: u8 },
    RestOrder { user: UserKey20, oid: OrderId, slot: usize, px: Px, sz: Sz },
    BestBidAsk { best_bid: Option<Px>, best_ask: Option<Px> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InsertOutcome {
    pub status: InsertStatus,
    pub remaining_sz: Sz,
    pub resting_slot: Option<usize>,
    pub fills: Vec<FillRecord>,
    pub events: Vec<BookEvent>,
    pub best_bid: Option<Px>,
    pub best_ask: Option<Px>,
}

impl InsertOutcome {
    #[inline]
    fn error(status: InsertStatus) -> Self {
        Self {
            status,
            remaining_sz: 0,
            resting_slot: None,
            fills: Vec::new(),
            events: Vec::new(),
            best_bid: None,
            best_ask: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchResult {
    pub status: InsertStatus,
    pub variant: u64,
    pub fill: Option<FillRecord>,
    pub matched_sz: Sz,
    pub remaining_requested_sz: Sz,
    pub reason: RestingMatchReason,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AssetContext {
    pub tick_sz: Px,
    pub oracle_px: Px,
    pub min_order_sz: Sz,
    pub max_order_sz: Sz,
    pub price_limit_enabled: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InsertContext {
    /// Equivalent to the state bytes at `+0x8f2`/`+0x1372` used by match helpers.
    pub global_price_flag: u8,
    pub timestamp_or_block: u64,
    pub seq_or_subblock: u32,
    pub allow_vault_self_cross: bool,
    pub sentinel_notional_exempt_user: Option<UserKey20>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Book {
    pub book_asset: u64,
    pub local_market_id: u64,
    pub orders: Vec<RestingOrder>,
    pub active_oids: BTreeSet<OrderId>,
    pub user_oid_index: BTreeMap<(UserKey20, OrderId), usize>,
    /// User/price signed quantity tree at recovered book offset `+0xf8`/`+248`.
    pub user_price_qty: BTreeMap<(UserKey20, OrderId), i64>,
    pub bids: BTreeMap<Px, Level>,
    pub asks: BTreeMap<Px, Level>,
    pub best_bid: Option<Px>,
    pub best_ask: Option<Px>,
}

impl Book {
    pub fn insert_order_indexed_px(
        &mut self,
        args: InsertOrderArgs,
        asset: &AssetContext,
        ctx: &InsertContext,
    ) -> InsertOutcome {
        self.insert_order_recovered(args, asset, ctx, InsertFlavor::IndexedPx)
    }

    pub fn insert_order_direct_px(
        &mut self,
        args: InsertOrderArgs,
        asset: &AssetContext,
        ctx: &InsertContext,
    ) -> InsertOutcome {
        self.insert_order_recovered(args, asset, ctx, InsertFlavor::DirectPx)
    }

    pub fn insert_order_perp_direct(
        &mut self,
        args: InsertOrderArgs,
        asset: &AssetContext,
        ctx: &InsertContext,
    ) -> InsertOutcome {
        self.insert_order_recovered(args, asset, ctx, InsertFlavor::PerpDirect)
    }

    pub fn insert_order_perp_wrapped(
        &mut self,
        args: InsertOrderArgs,
        asset: &AssetContext,
        ctx: &InsertContext,
    ) -> InsertOutcome {
        self.insert_order_recovered(args, asset, ctx, InsertFlavor::PerpWrapped)
    }

    pub fn insert_order_spot_direct(
        &mut self,
        args: InsertOrderArgs,
        asset: &AssetContext,
        ctx: &InsertContext,
    ) -> InsertOutcome {
        self.insert_order_recovered(args, asset, ctx, InsertFlavor::SpotDirect)
    }

    pub fn insert_order_spot_wrapped(
        &mut self,
        args: InsertOrderArgs,
        asset: &AssetContext,
        ctx: &InsertContext,
    ) -> InsertOutcome {
        self.insert_order_recovered(args, asset, ctx, InsertFlavor::SpotWrapped)
    }

    fn insert_order_recovered(
        &mut self,
        args: InsertOrderArgs,
        asset: &AssetContext,
        ctx: &InsertContext,
        flavor: InsertFlavor,
    ) -> InsertOutcome {
        let (book_asset, slot_index) = split_order_id(args.oid);
        debug_assert_eq!(BOOK_STRIDE_BYTES, 752);
        debug_assert_eq!(RESTING_ORDER_SLOT_BYTES, 248);

        if self.active_oids.contains(&args.oid) || self.user_oid_index.contains_key(&(args.user, args.oid)) {
            return InsertOutcome::error(STATUS_DUPLICATE_ORDER);
        }

        if args.is_replace {
            match self.orders.get(slot_index as usize) {
                Some(order) if order.status == SlotStatus::Occupied => {}
                Some(_) if args.replace_slot_required => return InsertOutcome::error(STATUS_SLOT_EMPTY_FOR_REPLACE),
                Some(_) => return InsertOutcome::error(STATUS_SLOT_MISSING),
                None => return InsertOutcome::error(STATUS_SLOT_MISSING),
            }
        } else if book_asset != self.book_asset && !matches!(flavor, InsertFlavor::IndexedPx) {
            return InsertOutcome::error(STATUS_INDEX_ROUTE);
        }

        let marketable = self.is_marketable(args.side, args.limit_px);
        if args.tif == InsertTif::AddLiquidityOnly && marketable {
            return InsertOutcome::error(STATUS_POST_ONLY_CROSSES);
        }
        if args.tif.must_be_marketable() && !marketable {
            return InsertOutcome::error(STATUS_TIF_NOT_MARKETABLE);
        }

        if args.limit_px > MAX_LIMIT_PX || !valid_tick(args.limit_px, asset.tick_sz) {
            return InsertOutcome::error(STATUS_PRICE_OR_TICK);
        }

        let remaining_from_lookup = self.initial_remaining_from_user_price_qty(&args);
        let mut remaining_sz = match remaining_from_lookup {
            Ok(sz) => sz,
            Err(status) => return InsertOutcome::error(status),
        };

        if let Err(status) = self.validate_notional(&args, asset, remaining_sz, ctx) {
            return InsertOutcome::error(status);
        }
        if let Err(status) = validate_order_sz_limits(asset, remaining_sz) {
            return InsertOutcome::error(status);
        }

        let mut outcome = InsertOutcome {
            status: STATUS_OK,
            remaining_sz,
            resting_slot: None,
            fills: Vec::new(),
            events: Vec::new(),
            best_bid: self.best_bid,
            best_ask: self.best_ask,
        };

        while remaining_sz != 0 {
            let Some(level_px) = self.next_crossable_level(args.side, args.limit_px) else {
                break;
            };
            if !price_level_allowed(asset, args.side, level_px, ctx.global_price_flag) {
                if outcome.fills.is_empty() {
                    return InsertOutcome::error(STATUS_NO_VALID_CROSS);
                }
                break;
            }

            let resting_indices = self.level_queue_snapshot(args.side.opposite(), level_px);
            if resting_indices.is_empty() {
                self.remove_empty_level(args.side.opposite(), level_px);
                continue;
            }

            for resting_index in resting_indices {
                if remaining_sz == 0 || !self.crosses(args.side, args.limit_px, level_px) {
                    break;
                }

                if !self.is_live_order_index(resting_index) {
                    panic!("resting order queue referenced an empty slot");
                }

                let match_result = self.match_resting_order(
                    &args,
                    ctx,
                    asset,
                    resting_index,
                    level_px,
                    remaining_sz,
                );

                if let Some(fill) = match_result.fill.clone() {
                    self.apply_fill_to_resting(resting_index, fill.sz);
                    remaining_sz = remaining_sz.saturating_sub(fill.sz);
                    outcome.fills.push(fill.clone());
                    outcome.events.push(BookEvent::Fill(fill));

                    if self.orders[resting_index].resting_sz == 0 {
                        let removed = self.remove_resting_index(resting_index, 5);
                        outcome.events.extend(removed);
                    }
                }

                if let Some(code) = match_result.reason.maker_event_code() {
                    let maker = self.orders[resting_index].user;
                    let maker_oid = self.orders[resting_index].oid;
                    outcome.events.push(BookEvent::MakerUserEvent { user: maker, oid: maker_oid, code });
                }

                if match_result.status != STATUS_OK {
                    if outcome.fills.is_empty() {
                        return InsertOutcome::error(match_result.status);
                    }
                    if match_result.status.0 > 0 {
                        outcome.status = match_result.status;
                    }
                    break;
                }
            }

            self.remove_empty_level(args.side.opposite(), level_px);
            if !self.crosses(args.side, args.limit_px, level_px) {
                break;
            }
        }

        outcome.remaining_sz = remaining_sz;
        if remaining_sz == 0 {
            if args.allow_trigger_cleanup {
                outcome.events.push(BookEvent::RemoveOrder { user: args.user, oid: args.oid, code: 1 });
            }
            self.recompute_best_bid_ask(&mut outcome);
            return outcome;
        }

        if args.tif.must_be_marketable() || args.tif == InsertTif::AddLiquidityOnly && marketable {
            if outcome.fills.is_empty() {
                return InsertOutcome::error(STATUS_TIF_NOT_MARKETABLE);
            }
            self.recompute_best_bid_ask(&mut outcome);
            return outcome;
        }

        let slot = match self.rest_residual_order(args, remaining_sz, asset, ctx) {
            Ok(slot) => slot,
            Err(status) => {
                if outcome.fills.is_empty() {
                    return InsertOutcome::error(status);
                }
                outcome.status = status;
                self.recompute_best_bid_ask(&mut outcome);
                return outcome;
            }
        };
        outcome.resting_slot = Some(slot);
        outcome.events.push(BookEvent::RestOrder {
            user: self.orders[slot].user,
            oid: self.orders[slot].oid,
            slot,
            px: self.orders[slot].px,
            sz: self.orders[slot].resting_sz,
        });
        self.recompute_best_bid_ask(&mut outcome);
        outcome
    }

    fn initial_remaining_from_user_price_qty(&self, args: &InsertOrderArgs) -> Result<Sz, InsertStatus> {
        if !args.use_user_price_qty_lookup {
            let sz = args.remaining_sz();
            return if sz == 0 { Err(STATUS_NO_USER_PRICE_QTY) } else { Ok(sz) };
        }

        let signed = *self.user_price_qty.get(&(args.user, args.oid)).unwrap_or(&0);
        if signed == 0 || !signed_qty_side_matches(args.side, signed) {
            return Err(STATUS_NO_USER_PRICE_QTY);
        }
        let available = signed.unsigned_abs();
        let desired = args.remaining_sz();
        Ok(available.min(desired))
    }

    fn validate_notional(
        &self,
        args: &InsertOrderArgs,
        asset: &AssetContext,
        sz: Sz,
        ctx: &InsertContext,
    ) -> Result<(), InsertStatus> {
        let limit_ntl = checked_notional(sz, args.limit_px).ok_or(STATUS_NOTIONAL)?;
        let oracle_ntl = checked_notional(sz, asset.oracle_px).ok_or(STATUS_NOTIONAL)?;
        if limit_ntl > MAX_NOTIONAL || oracle_ntl > MAX_NOTIONAL {
            return Err(STATUS_NOTIONAL);
        }
        if oracle_ntl <= MIN_NOTIONAL_FLOOR && Some(args.user) != ctx.sentinel_notional_exempt_user {
            return Err(STATUS_NOTIONAL);
        }
        Ok(())
    }

    #[inline]
    fn is_marketable(&self, side: Side, limit_px: Px) -> bool {
        match side {
            Side::Buy => self.best_ask.is_some_and(|ask| ask <= limit_px),
            Side::Sell => self.best_bid.is_some_and(|bid| bid >= limit_px),
        }
    }

    #[inline]
    fn crosses(&self, side: Side, limit_px: Px, level_px: Px) -> bool {
        match side {
            Side::Buy => level_px <= limit_px,
            Side::Sell => level_px >= limit_px,
        }
    }

    fn next_crossable_level(&self, side: Side, limit_px: Px) -> Option<Px> {
        match side {
            Side::Buy => self.asks.keys().next().copied().filter(|px| *px <= limit_px),
            Side::Sell => self.bids.keys().next_back().copied().filter(|px| *px >= limit_px),
        }
    }

    fn level_queue_snapshot(&self, side: Side, px: Px) -> Vec<usize> {
        let levels = match side {
            Side::Buy => &self.bids,
            Side::Sell => &self.asks,
        };
        levels.get(&px).map(|level| level.queue.iter().copied().collect()).unwrap_or_default()
    }

    fn match_resting_order(
        &mut self,
        incoming: &InsertOrderArgs,
        ctx: &InsertContext,
        asset: &AssetContext,
        resting_index: usize,
        level_px: Px,
        requested_sz: Sz,
    ) -> MatchResult {
        if requested_sz == 0 {
            return MatchResult {
                status: STATUS_OK,
                variant: 2,
                fill: None,
                matched_sz: 0,
                remaining_requested_sz: 0,
                reason: RestingMatchReason::DirectRemainingSize,
            };
        }

        let resting = &self.orders[resting_index];
        if incoming.user == resting.user || (!ctx.allow_vault_self_cross && both_vault_privileged(incoming.user, resting.user)) {
            return MatchResult {
                status: STATUS_OK,
                variant: 2,
                fill: None,
                matched_sz: 0,
                remaining_requested_sz: requested_sz,
                reason: RestingMatchReason::SelfCrossOrVaultCross,
            };
        }

        let (mut match_sz, reason) = if incoming.use_user_price_qty_lookup {
            match self.lookup_signed_qty_for_match(incoming, resting.side, requested_sz) {
                Some((sz, reason)) if sz != 0 => (sz, reason),
                _ => {
                    return MatchResult {
                        status: STATUS_OK,
                        variant: 2,
                        fill: None,
                        matched_sz: 0,
                        remaining_requested_sz: requested_sz,
                        reason: RestingMatchReason::MissingUserPriceQuantity,
                    };
                }
            }
        } else {
            let sz = incoming.remaining_sz().min(requested_sz);
            if sz == 0 {
                return MatchResult {
                    status: STATUS_OK,
                    variant: 2,
                    fill: None,
                    matched_sz: 0,
                    remaining_requested_sz: requested_sz,
                    reason: RestingMatchReason::DirectRemainingSize,
                };
            }
            (sz, RestingMatchReason::DirectRemainingSize)
        };

        let taker_cap = compute_max_order_sz(asset, incoming.user, incoming.side, level_px, ctx);
        if taker_cap == 0 {
            return MatchResult {
                status: STATUS_OK,
                variant: 2,
                fill: None,
                matched_sz: 0,
                remaining_requested_sz: requested_sz,
                reason: RestingMatchReason::MakerLiquidityExhausted,
            };
        }
        match_sz = match_sz.min(taker_cap);

        let maker_cap = compute_max_order_sz(asset, resting.user, resting.side, level_px, ctx);
        if maker_cap == 0 {
            return MatchResult {
                status: STATUS_AVAILABLE_SIZE,
                variant: 2,
                fill: None,
                matched_sz: 0,
                remaining_requested_sz: 0,
                reason: RestingMatchReason::MakerLiquidityExhausted,
            };
        }
        match_sz = match_sz.min(maker_cap).min(resting.resting_sz).min(requested_sz);
        if match_sz == 0 {
            return MatchResult {
                status: STATUS_OK,
                variant: 2,
                fill: None,
                matched_sz: 0,
                remaining_requested_sz: requested_sz,
                reason: RestingMatchReason::MakerLiquidityExhausted,
            };
        }

        let ntl = match checked_notional(match_sz, resting.px) {
            Some(ntl) if ntl <= MAX_NOTIONAL => ntl,
            _ => panic!("match notional overflow"),
        };

        let queue_mask = self.queue_fill_record(resting.side, resting.px, match_sz);
        if queue_mask & 0x0101 == 0x0101 {
            let fill = FillRecord {
                taker: incoming.user,
                maker: resting.user,
                taker_oid: incoming.oid,
                maker_oid: resting.oid,
                px: resting.px,
                sz: match_sz,
                ntl,
                taker_side: incoming.side,
            };
            return MatchResult {
                status: STATUS_OK,
                variant: 0,
                fill: Some(fill),
                matched_sz: match_sz,
                remaining_requested_sz: requested_sz.saturating_sub(match_sz),
                reason,
            };
        }

        let side_bit = match resting.side {
            Side::Buy => 0x0001,
            Side::Sell => 0x0100,
        };
        let opposite_bit = match resting.side {
            Side::Buy => 0x0100,
            Side::Sell => 0x0001,
        };
        if queue_mask & side_bit == 0 {
            MatchResult {
                status: STATUS_QUEUE_MASK,
                variant: 2,
                fill: None,
                matched_sz: 0,
                remaining_requested_sz: 0,
                reason: RestingMatchReason::MakerLiquidityExhausted,
            }
        } else if queue_mask & opposite_bit != 0 {
            MatchResult {
                status: STATUS_OK,
                variant: 2,
                fill: None,
                matched_sz: 0,
                remaining_requested_sz: requested_sz,
                reason,
            }
        } else {
            MatchResult {
                status: STATUS_QUEUE_MASK,
                variant: 2,
                fill: None,
                matched_sz: 0,
                remaining_requested_sz: 0,
                reason,
            }
        }
    }

    fn lookup_signed_qty_for_match(
        &self,
        incoming: &InsertOrderArgs,
        resting_side: Side,
        requested_sz: Sz,
    ) -> Option<(Sz, RestingMatchReason)> {
        let signed = *self.user_price_qty.get(&(incoming.user, incoming.oid))?;
        if signed == 0 || !signed_qty_side_matches(resting_side.opposite(), signed) {
            return None;
        }
        let available = signed.unsigned_abs().min(incoming.remaining_sz());
        let sz = available.min(requested_sz);
        let reason = if available < incoming.remaining_sz() {
            if sz >= requested_sz {
                RestingMatchReason::SelfCrossOrVaultCross
            } else {
                RestingMatchReason::MissingUserPriceQuantity
            }
        } else {
            RestingMatchReason::DirectRemainingSize
        };
        Some((sz, reason))
    }

    fn queue_fill_record(&self, resting_side: Side, _px: Px, _match_sz: Sz) -> u16 {
        // Recovered helper returns a bit mask where clean success has both low
        // bit and bit 8 set.  The in-source model has no external queue failure,
        // so it returns the success mask after all invariants above pass.
        match resting_side {
            Side::Buy | Side::Sell => 0x0101,
        }
    }

    fn apply_fill_to_resting(&mut self, resting_index: usize, fill_sz: Sz) {
        let order = &mut self.orders[resting_index];
        order.resting_sz = order.resting_sz.saturating_sub(fill_sz);
    }

    fn rest_residual_order(
        &mut self,
        args: InsertOrderArgs,
        remaining_sz: Sz,
        asset: &AssetContext,
        ctx: &InsertContext,
    ) -> Result<usize, InsertStatus> {
        if !price_level_allowed(asset, args.side, args.limit_px, ctx.global_price_flag) {
            return Err(STATUS_NO_VALID_CROSS);
        }
        let slot = self.allocate_order_slot();
        let order = RestingOrder {
            status: SlotStatus::Occupied,
            prev_key: None,
            next_key: None,
            oid: args.oid,
            user: args.user,
            side: args.side,
            px: args.limit_px,
            resting_sz: remaining_sz,
            orig_sz: args.sz,
            reduce_only: args.reduce_only,
            is_position_tpsl: args.is_position_tpsl,
            tif: args.tif,
            cloid: args.cloid,
            timestamp: args.timestamp,
            builder_nonce: args.builder_nonce,
            raw_accounting_key: args.raw_accounting_key,
        };
        self.orders[slot] = order;
        self.link_into_price_level(args.side, args.limit_px, slot);
        self.active_oids.insert(args.oid);
        self.user_oid_index.insert((args.user, args.oid), slot);
        self.user_price_qty.insert((args.user, args.oid), signed_qty(args.side, remaining_sz));
        Ok(slot)
    }

    fn allocate_order_slot(&mut self) -> usize {
        if let Some(index) = self.orders.iter().position(|order| order.status != SlotStatus::Occupied) {
            index
        } else {
            self.orders.push(RestingOrder::empty());
            self.orders.len() - 1
        }
    }

    fn link_into_price_level(&mut self, side: Side, px: Px, slot: usize) {
        let prior_last = match side {
            Side::Buy => self.bids.get(&px).and_then(|level| level.last_key),
            Side::Sell => self.asks.get(&px).and_then(|level| level.last_key),
        };

        if let Some(last) = prior_last {
            self.orders[last].next_key = Some(slot);
            self.orders[slot].prev_key = Some(last);
        }

        let levels = match side {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        };
        let level = levels.entry(px).or_default();
        if prior_last.is_none() {
            level.first_key = Some(slot);
        }
        level.last_key = Some(slot);
        level.queue.push_back(slot);
    }

    fn remove_resting_index(&mut self, index: usize, event_code: u8) -> Vec<BookEvent> {
        if !self.is_live_order_index(index) {
            return Vec::new();
        }
        let order = self.orders[index].clone();
        self.unlink_from_price_level(order.side, order.px, index);
        self.active_oids.remove(&order.oid);
        self.user_oid_index.remove(&(order.user, order.oid));
        self.user_price_qty.remove(&(order.user, order.oid));
        self.orders[index].status = SlotStatus::Removed;
        self.orders[index].prev_key = None;
        self.orders[index].next_key = None;
        vec![BookEvent::RemoveOrder { user: order.user, oid: order.oid, code: event_code }]
    }

    fn unlink_from_price_level(&mut self, side: Side, px: Px, slot: usize) {
        let (prev, next) = (self.orders[slot].prev_key, self.orders[slot].next_key);
        if let Some(prev) = prev {
            self.orders[prev].next_key = next;
        }
        if let Some(next) = next {
            self.orders[next].prev_key = prev;
        }
        let levels = match side {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        };
        if let Some(level) = levels.get_mut(&px) {
            if level.first_key == Some(slot) {
                level.first_key = next;
            }
            if level.last_key == Some(slot) {
                level.last_key = prev;
            }
            level.queue.retain(|idx| *idx != slot);
            if level.queue.is_empty() {
                levels.remove(&px);
            }
        }
    }

    fn remove_empty_level(&mut self, side: Side, px: Px) {
        let levels = match side {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        };
        let remove = levels.get(&px).map(|level| level.queue.is_empty()).unwrap_or(false);
        if remove {
            levels.remove(&px);
        }
    }

    fn is_live_order_index(&self, index: usize) -> bool {
        matches!(self.orders.get(index), Some(order) if order.status == SlotStatus::Occupied)
    }

    fn recompute_best_bid_ask(&mut self, outcome: &mut InsertOutcome) {
        self.best_bid = self.bids.keys().next_back().copied();
        self.best_ask = self.asks.keys().next().copied();
        outcome.best_bid = self.best_bid;
        outcome.best_ask = self.best_ask;
        outcome.events.push(BookEvent::BestBidAsk { best_bid: self.best_bid, best_ask: self.best_ask });
    }
}

impl RestingOrder {
    fn empty() -> Self {
        Self {
            status: SlotStatus::Empty,
            prev_key: None,
            next_key: None,
            oid: 0,
            user: UserKey20 { bytes: [0; 20] },
            side: Side::Buy,
            px: 0,
            resting_sz: 0,
            orig_sz: 0,
            reduce_only: false,
            is_position_tpsl: false,
            tif: InsertTif::Normal,
            cloid: None,
            timestamp: 0,
            builder_nonce: 0,
            raw_accounting_key: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InsertFlavor {
    IndexedPx,
    DirectPx,
    PerpDirect,
    PerpWrapped,
    SpotDirect,
    SpotWrapped,
}

#[inline]
fn split_order_id(oid: OrderId) -> (u64, u64) {
    (oid / ASSET_DIVISOR, oid % ASSET_DIVISOR)
}

#[inline]
fn valid_tick(px: Px, tick: Px) -> bool {
    tick != 0 && px % tick == 0
}

#[inline]
fn checked_notional(sz: Sz, px: Px) -> Option<Ntl> {
    sz.checked_mul(px).filter(|ntl| *ntl <= MAX_NOTIONAL)
}

#[inline]
fn signed_qty(side: Side, sz: Sz) -> i64 {
    match side {
        Side::Buy => -(sz as i64),
        Side::Sell => sz as i64,
    }
}

#[inline]
fn signed_qty_side_matches(side: Side, qty: i64) -> bool {
    match side {
        Side::Buy => qty < 0,
        Side::Sell => qty > 0,
    }
}

fn validate_order_sz_limits(asset: &AssetContext, sz: Sz) -> Result<(), InsertStatus> {
    if sz < asset.min_order_sz || asset.max_order_sz != 0 && sz > asset.max_order_sz {
        Err(STATUS_AVAILABLE_SIZE)
    } else {
        Ok(())
    }
}

fn price_level_allowed(asset: &AssetContext, _side: Side, _px: Px, global_price_flag: u8) -> bool {
    !asset.price_limit_enabled || global_price_flag != 0
}

fn compute_max_order_sz(
    asset: &AssetContext,
    _user: UserKey20,
    _side: Side,
    _px: Px,
    _ctx: &InsertContext,
) -> Sz {
    if asset.max_order_sz == 0 {
        u64::MAX
    } else {
        asset.max_order_sz
    }
}

fn both_vault_privileged(a: UserKey20, b: UserKey20) -> bool {
    is_vault_privileged(a) && is_vault_privileged(b)
}

fn is_vault_privileged(user: UserKey20) -> bool {
    // The binary calls a dedicated predicate before suppressing self-crosses.
    // The recovered source keeps the predicate deterministic: vault group keys
    // are represented by a nonzero high marker byte and zero low routing byte.
    user.bytes[0] != 0 && user.bytes[19] == 0
}
