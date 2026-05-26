use std::collections::{BTreeMap, HashMap, HashSet};

pub type Oid = u64;
pub type Asset = u64;
pub type Px = i64;
pub type Sz = i64;
pub type User = [u8; 20];

pub const OID_SLOT_MODULUS: Oid = 10_000;
pub const MAX_LIMIT_PX: Px = 1_000_000_000_000_000;
pub const MAX_NOTIONAL: i128 = 0x7fff_ffff_ffff_fffe;
pub const ERR_CLEAN_MATCH_QUEUE: u64 = 0x8000_0000_0000_0003;
pub const ERR_POST_ONLY_CROSSES: u64 = 0x8000_0000_0000_0006;
pub const ERR_IOC_NOT_MARKETABLE: u64 = 0x8000_0000_0000_0008;
pub const ERR_DUPLICATE_ORDER: u64 = 0x8000_0000_0000_0017;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Side {
    Bid,
    Ask,
}

impl Side {
    #[inline]
    pub fn from_is_buy(is_buy: bool) -> Self {
        if is_buy { Self::Bid } else { Self::Ask }
    }

    #[inline]
    pub fn opposite(self) -> Self {
        match self {
            Self::Bid => Self::Ask,
            Self::Ask => Self::Bid,
        }
    }

    #[inline]
    pub fn tree_key(self, px: Px) -> Px {
        // The recovered side BTree stores bids under -px and asks under +px, so the
        // first BTree key is the best price on both sides.
        match self {
            Self::Bid => -px,
            Self::Ask => px,
        }
    }

    #[inline]
    pub fn px_from_tree_key(self, key: Px) -> Px {
        match self {
            Self::Bid => -key,
            Self::Ask => key,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SideMap<T> {
    pub bid: T,
    pub ask: T,
}

impl<T> SideMap<T> {
    #[inline]
    pub fn get(&self, side: Side) -> &T {
        match side {
            Side::Bid => &self.bid,
            Side::Ask => &self.ask,
        }
    }

    #[inline]
    pub fn get_mut(&mut self, side: Side) -> &mut T {
        match side {
            Side::Bid => &mut self.bid,
            Side::Ask => &mut self.ask,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct BookOrderKey {
    pub oid: Oid,
}

impl BookOrderKey {
    #[inline]
    pub const fn new(oid: Oid) -> Self {
        Self { oid }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookLevel {
    pub first: Option<Oid>,
    pub last: Option<Oid>,
    pub total_sz: Sz,
}

impl BookLevel {
    #[inline]
    pub const fn empty() -> Self {
        Self { first: None, last: None, total_sz: 0 }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.first.is_none()
    }
}

impl Default for BookLevel {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookOrder {
    pub oid: Oid,
    pub user: User,
    pub side: Side,
    pub limit_px: Px,
    pub resting_sz: Sz,
    pub prev: Option<Oid>,
    pub next: Option<Oid>,
    pub parent: Option<Oid>,
    pub peer: Option<Oid>,
    pub child_oids: Vec<Oid>,
    pub reduce_only: bool,
    pub is_trigger: bool,
    pub cloid: Option<[u8; 16]>,
}

impl BookOrder {
    #[inline]
    pub fn key(&self) -> BookOrderKey {
        BookOrderKey::new(self.oid)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InsertOrderArgs {
    pub oid: Oid,
    pub user: User,
    pub side: Side,
    pub limit_px: Px,
    pub sz: Sz,
    pub post_only: bool,
    pub immediate_or_cancel: bool,
    pub reduce_only: bool,
    pub is_trigger: bool,
    pub parent: Option<Oid>,
    pub peer: Option<Oid>,
    pub cloid: Option<[u8; 16]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetContext {
    pub asset: Asset,
    pub tick_size: Px,
    pub oracle_px: Px,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InsertContext {
    pub enforce_oid_asset: bool,
    pub allow_market_rest: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InsertOutcome {
    Rested { oid: Oid, px: Px, sz: Sz },
    Rejected { code: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemovedOrder {
    pub order: BookOrder,
    pub became_empty_level: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemoveOutcome {
    Removed(RemovedOrder),
    NotFound,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BestBidAsk {
    pub bid: Px,
    pub ask: Px,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopOrders<'a> {
    pub bid: Option<&'a BookOrder>,
    pub ask: Option<&'a BookOrder>,
}

#[derive(Clone, Debug, Default)]
pub struct Book {
    // Recovered binary layout uses a 0xf8-byte slab element; discriminant value 2
    // is the vacant/free variant.  This source representation keeps the same
    // semantics with an Option slab plus indexes.
    orders: Vec<Option<BookOrder>>,
    free_indexes: Vec<usize>,
    order_by_oid: HashMap<Oid, usize>,
    user_orders: BTreeMap<User, BTreeMap<Oid, usize>>,
    bids: BTreeMap<Px, BookLevel>,
    asks: BTreeMap<Px, BookLevel>,
    asset: Asset,
    total_resting_sz: Sz,
    mark_px: Px,
    oracle_px: Px,
}

impl Book {
    pub fn new(asset: Asset) -> Self {
        Self { asset, ..Self::default() }
    }

    #[inline]
    pub fn asset(&self) -> Asset {
        self.asset
    }

    #[inline]
    pub fn mark_px(&self) -> Px {
        self.mark_px
    }

    #[inline]
    pub fn set_mark_px(&mut self, px: Px) {
        self.mark_px = px;
    }

    #[inline]
    pub fn oracle_px(&self) -> Px {
        self.oracle_px
    }

    #[inline]
    pub fn set_oracle_px(&mut self, px: Px) {
        self.oracle_px = px;
    }

    #[inline]
    pub fn total_resting_sz(&self) -> Sz {
        self.total_resting_sz
    }

    #[inline]
    pub fn bids(&self) -> &BTreeMap<Px, BookLevel> {
        &self.bids
    }

    #[inline]
    pub fn asks(&self) -> &BTreeMap<Px, BookLevel> {
        &self.asks
    }

    #[inline]
    pub fn levels(&self, side: Side) -> &BTreeMap<Px, BookLevel> {
        match side {
            Side::Bid => &self.bids,
            Side::Ask => &self.asks,
        }
    }

    #[inline]
    fn levels_mut(&mut self, side: Side) -> &mut BTreeMap<Px, BookLevel> {
        match side {
            Side::Bid => &mut self.bids,
            Side::Ask => &mut self.asks,
        }
    }

    pub fn best_bid_ask(&self) -> BestBidAsk {
        // The decompiled helper returns zero for a missing side and abs(first_key)
        // for present sides.
        BestBidAsk {
            bid: self.bids.keys().next().map(|key| Side::Bid.px_from_tree_key(*key)).unwrap_or(0),
            ask: self.asks.keys().next().map(|key| Side::Ask.px_from_tree_key(*key)).unwrap_or(0),
        }
    }

    pub fn top_order(&self, side: Side) -> Option<&BookOrder> {
        let level = self.levels(side).values().next()?;
        self.order_by_oid(level.first?)
    }

    pub fn top_orders_side_map(&self) -> TopOrders<'_> {
        TopOrders { bid: self.top_order(Side::Bid), ask: self.top_order(Side::Ask) }
    }

    pub fn top_orders_as_side_map(&self) -> SideMap<Option<&BookOrder>> {
        SideMap { bid: self.top_order(Side::Bid), ask: self.top_order(Side::Ask) }
    }

    #[inline]
    pub fn order_by_oid(&self, oid: Oid) -> Option<&BookOrder> {
        self.index_for_oid(oid).and_then(|index| self.order_at(index))
    }

    #[inline]
    pub fn order_by_oid_mut(&mut self, oid: Oid) -> Option<&mut BookOrder> {
        let index = self.index_for_oid(oid)?;
        self.order_at_mut(index)
    }

    pub fn find_order_by_user_oid(&self, user: &User, oid: Oid) -> Option<&BookOrder> {
        let index = *self.user_orders.get(user)?.get(&oid)?;
        let order = self.order_at(index)?;
        if order.oid == oid && &order.user == user { Some(order) } else { None }
    }

    pub fn find_order_by_user_oid_mut(&mut self, user: &User, oid: Oid) -> Option<&mut BookOrder> {
        let index = *self.user_orders.get(user)?.get(&oid)?;
        let matches = self.order_at(index).map(|order| order.oid == oid && &order.user == user).unwrap_or(false);
        if matches { self.order_at_mut(index) } else { None }
    }

    pub fn insert_order_indexed_px(
        &mut self,
        args: InsertOrderArgs,
        asset: &AssetContext,
        ctx: &InsertContext,
    ) -> InsertOutcome {
        self.insert_order(args, asset, ctx)
    }

    pub fn insert_order_direct_px(
        &mut self,
        args: InsertOrderArgs,
        asset: &AssetContext,
        ctx: &InsertContext,
    ) -> InsertOutcome {
        self.insert_order(args, asset, ctx)
    }

    pub fn insert_order_perp_direct(
        &mut self,
        args: InsertOrderArgs,
        asset: &AssetContext,
        ctx: &InsertContext,
    ) -> InsertOutcome {
        self.insert_order(args, asset, ctx)
    }

    pub fn insert_order_perp_wrapped(
        &mut self,
        args: InsertOrderArgs,
        asset: &AssetContext,
        ctx: &InsertContext,
    ) -> InsertOutcome {
        self.insert_order(args, asset, ctx)
    }

    pub fn insert_order_spot_direct(
        &mut self,
        args: InsertOrderArgs,
        asset: &AssetContext,
        ctx: &InsertContext,
    ) -> InsertOutcome {
        self.insert_order(args, asset, ctx)
    }

    pub fn insert_order_spot_wrapped(
        &mut self,
        args: InsertOrderArgs,
        asset: &AssetContext,
        ctx: &InsertContext,
    ) -> InsertOutcome {
        self.insert_order(args, asset, ctx)
    }

    pub fn insert_order(
        &mut self,
        args: InsertOrderArgs,
        asset: &AssetContext,
        ctx: &InsertContext,
    ) -> InsertOutcome {
        if self.reject_duplicate(args.user, args.oid) {
            return InsertOutcome::Rejected { code: ERR_DUPLICATE_ORDER };
        }
        if !self.validate_oid_asset(args.oid, asset, ctx) {
            return InsertOutcome::Rejected { code: ERR_CLEAN_MATCH_QUEUE };
        }
        if !valid_price(args.limit_px, asset.tick_size) || args.sz <= 0 {
            return InsertOutcome::Rejected { code: ERR_CLEAN_MATCH_QUEUE };
        }
        if !valid_notional(args.sz, args.limit_px) || !valid_notional(args.sz, asset.oracle_px) {
            return InsertOutcome::Rejected { code: ERR_CLEAN_MATCH_QUEUE };
        }
        if args.post_only && self.crosses(args.side, args.limit_px) {
            return InsertOutcome::Rejected { code: ERR_POST_ONLY_CROSSES };
        }
        if args.immediate_or_cancel && !ctx.allow_market_rest && !self.crosses(args.side, args.limit_px) {
            return InsertOutcome::Rejected { code: ERR_IOC_NOT_MARKETABLE };
        }

        let oid = args.oid;
        let px = args.limit_px;
        let sz = args.sz;
        self.insert_resting_order(args);
        InsertOutcome::Rested { oid, px, sz }
    }

    pub fn remove_order(&mut self, user: &User, oid: Oid) -> RemoveOutcome {
        let Some(index) = self.user_orders.get(user).and_then(|orders| orders.get(&oid).copied()) else {
            return RemoveOutcome::NotFound;
        };
        let Some(order) = self.order_at(index) else {
            self.remove_user_oid(user, oid);
            self.order_by_oid.remove(&oid);
            return RemoveOutcome::NotFound;
        };
        if order.oid != oid || &order.user != user {
            return RemoveOutcome::NotFound;
        }
        let removed = self.remove_order_at(index);
        RemoveOutcome::Removed(removed)
    }

    pub fn remove_order_by_oid(&mut self, oid: Oid) -> RemoveOutcome {
        let Some(index) = self.index_for_oid(oid) else {
            return RemoveOutcome::NotFound;
        };
        let Some(order) = self.order_at(index) else {
            self.order_by_oid.remove(&oid);
            return RemoveOutcome::NotFound;
        };
        let user = order.user;
        self.remove_order(&user, oid)
    }

    pub fn update_order_sz(&mut self, user: &User, oid: Oid, new_sz: Sz) -> RemoveOutcome {
        if new_sz <= 0 {
            return self.remove_order(user, oid);
        }

        let Some(index) = self.user_orders.get(user).and_then(|orders| orders.get(&oid).copied()) else {
            return RemoveOutcome::NotFound;
        };
        let (side, key, old_sz) = match self.order_at(index) {
            Some(order) if order.oid == oid && &order.user == user => {
                (order.side, order.side.tree_key(order.limit_px), order.resting_sz)
            }
            _ => return RemoveOutcome::NotFound,
        };
        let delta = new_sz - old_sz;
        self.order_at_mut(index).expect("checked order slot").resting_sz = new_sz;
        let level = self.levels_mut(side).get_mut(&key).expect("checked price level");
        level.total_sz = level.total_sz.checked_add(delta).expect("price-level size overflow");
        self.total_resting_sz = self.total_resting_sz.checked_add(delta).expect("book size overflow");
        RemoveOutcome::NotFound
    }

    pub fn check_debug_invariants(&self) {
        let bbo = self.best_bid_ask();
        if bbo.bid != 0 && bbo.ask != 0 && bbo.ask - 1 < bbo.bid {
            panic!("crossed book: bbo={bbo:?} top_orders={:?}", self.top_orders_side_map());
        }

        let mut seen = HashSet::with_capacity(self.order_by_oid.len());
        let mut summed_resting_sz: Sz = 0;
        for (index, slot) in self.orders.iter().enumerate() {
            let Some(order) = slot else { continue };
            if !seen.insert(order.oid) {
                panic!("duplicate live oid {}", order.oid);
            }
            if self.order_by_oid.get(&order.oid).copied() != Some(index) {
                panic!("oid index mismatch for {}", order.oid);
            }
            if self.user_orders.get(&order.user).and_then(|orders| orders.get(&order.oid)).copied() != Some(index) {
                panic!("user index mismatch for {}", order.oid);
            }
            if order.resting_sz <= 0 {
                panic!("non-positive resting size for {}", order.oid);
            }
            summed_resting_sz = summed_resting_sz.checked_add(order.resting_sz).expect("book size overflow");
            self.check_relation_links(order);
        }
        if summed_resting_sz != self.total_resting_sz {
            panic!("total resting size mismatch: slab={summed_resting_sz} book={}", self.total_resting_sz);
        }
        if seen.len() != self.order_by_oid.len() {
            panic!("oid hash contains dead entries");
        }
        self.check_side_invariants(Side::Bid);
        self.check_side_invariants(Side::Ask);
    }

    fn insert_resting_order(&mut self, args: InsertOrderArgs) {
        let key = args.side.tree_key(args.limit_px);
        let prev = self.levels(args.side).get(&key).and_then(|level| level.last);
        let order = BookOrder {
            oid: args.oid,
            user: args.user,
            side: args.side,
            limit_px: args.limit_px,
            resting_sz: args.sz,
            prev,
            next: None,
            parent: args.parent,
            peer: args.peer,
            child_oids: Vec::new(),
            reduce_only: args.reduce_only,
            is_trigger: args.is_trigger,
            cloid: args.cloid,
        };

        let index = self.alloc_order_slot(order);
        self.order_by_oid.insert(args.oid, index);
        self.user_orders.entry(args.user).or_default().insert(args.oid, index);

        if let Some(parent_oid) = args.parent {
            if let Some(parent) = self.order_by_oid_mut(parent_oid) {
                if !parent.child_oids.contains(&args.oid) {
                    parent.child_oids.push(args.oid);
                }
            }
        }
        if let Some(peer_oid) = args.peer {
            if let Some(peer) = self.order_by_oid_mut(peer_oid) {
                peer.peer = Some(args.oid);
            }
        }
        if let Some(prev_oid) = prev {
            self.order_by_oid_mut(prev_oid).expect("level tail points at live order").next = Some(args.oid);
        }

        let level = self.levels_mut(args.side).entry(key).or_insert_with(BookLevel::empty);
        if level.first.is_none() {
            level.first = Some(args.oid);
        }
        level.last = Some(args.oid);
        level.total_sz = level.total_sz.checked_add(args.sz).expect("price-level size overflow");
        self.total_resting_sz = self.total_resting_sz.checked_add(args.sz).expect("book size overflow");
    }

    fn remove_order_at(&mut self, index: usize) -> RemovedOrder {
        let mut order = self.orders[index].take().expect("remove live order");
        self.free_indexes.push(index);

        for child_oid in order.child_oids.drain(..) {
            if let Some(child) = self.order_by_oid_mut(child_oid) {
                if child.parent == Some(order.oid) {
                    child.parent = None;
                }
            }
        }
        if let Some(parent_oid) = order.parent.take() {
            if let Some(parent) = self.order_by_oid_mut(parent_oid) {
                parent.child_oids.retain(|&child_oid| child_oid != order.oid);
            }
        }
        if let Some(peer_oid) = order.peer.take() {
            if let Some(peer) = self.order_by_oid_mut(peer_oid) {
                if peer.peer == Some(order.oid) {
                    peer.peer = None;
                }
            }
        }

        let became_empty_level = self.unlink_from_level(&order);
        self.order_by_oid.remove(&order.oid);
        self.remove_user_oid(&order.user, order.oid);
        self.total_resting_sz = self.total_resting_sz.checked_sub(order.resting_sz).expect("book size underflow");
        RemovedOrder { order, became_empty_level }
    }

    fn unlink_from_level(&mut self, order: &BookOrder) -> bool {
        let key = order.side.tree_key(order.limit_px);
        if let Some(prev_oid) = order.prev {
            let prev = self.order_by_oid_mut(prev_oid).expect("price-level prev points at live order");
            prev.next = order.next;
        }
        if let Some(next_oid) = order.next {
            let next = self.order_by_oid_mut(next_oid).expect("price-level next points at live order");
            next.prev = order.prev;
        }

        let levels = self.levels_mut(order.side);
        let level = levels.get_mut(&key).expect("removed order has a price level");
        if level.first == Some(order.oid) {
            level.first = order.next;
        }
        if level.last == Some(order.oid) {
            level.last = order.prev;
        }
        level.total_sz = level.total_sz.checked_sub(order.resting_sz).expect("price-level size underflow");
        let remove_level = level.first.is_none();
        if remove_level {
            levels.remove(&key);
        }
        remove_level
    }

    fn check_relation_links(&self, order: &BookOrder) {
        if let Some(parent_oid) = order.parent {
            let parent = self.order_by_oid(parent_oid).expect("parent link points at missing order");
            if !parent.child_oids.contains(&order.oid) {
                panic!("parent {} does not contain child {}", parent_oid, order.oid);
            }
        }
        if let Some(peer_oid) = order.peer {
            let peer = self.order_by_oid(peer_oid).expect("peer link points at missing order");
            if peer.peer != Some(order.oid) {
                panic!("peer link is not reciprocal: {} -> {}", order.oid, peer_oid);
            }
        }
        for &child_oid in &order.child_oids {
            let child = self.order_by_oid(child_oid).expect("child link points at missing order");
            if child.parent != Some(order.oid) {
                panic!("child link is not reciprocal: {} -> {}", order.oid, child_oid);
            }
        }
    }

    fn check_side_invariants(&self, side: Side) {
        for (&key, level) in self.levels(side) {
            let expected_px = side.px_from_tree_key(key);
            let mut oid = level.first;
            let mut prev = None;
            let mut last = None;
            let mut level_sz: Sz = 0;
            let mut visited = HashSet::new();
            while let Some(current_oid) = oid {
                if !visited.insert(current_oid) {
                    panic!("cycle in {:?} level {}", side, expected_px);
                }
                let order = self.order_by_oid(current_oid).expect("price-level link points at missing order");
                if order.side != side || order.limit_px != expected_px {
                    panic!("order {} is in wrong price level", order.oid);
                }
                if order.prev != prev {
                    panic!("prev link mismatch at order {}", order.oid);
                }
                level_sz = level_sz.checked_add(order.resting_sz).expect("price-level size overflow");
                prev = Some(current_oid);
                last = Some(current_oid);
                oid = order.next;
            }
            if level.last != last {
                panic!("price-level tail mismatch at {:?} {}", side, expected_px);
            }
            if level_sz != level.total_sz {
                panic!("price-level size mismatch at {:?} {}", side, expected_px);
            }
        }
    }

    #[inline]
    fn index_for_oid(&self, oid: Oid) -> Option<usize> {
        self.order_by_oid.get(&oid).copied()
    }

    #[inline]
    fn order_at(&self, index: usize) -> Option<&BookOrder> {
        self.orders.get(index)?.as_ref()
    }

    #[inline]
    fn order_at_mut(&mut self, index: usize) -> Option<&mut BookOrder> {
        self.orders.get_mut(index)?.as_mut()
    }

    fn alloc_order_slot(&mut self, order: BookOrder) -> usize {
        if let Some(index) = self.free_indexes.pop() {
            self.orders[index] = Some(order);
            index
        } else {
            let index = self.orders.len();
            self.orders.push(Some(order));
            index
        }
    }

    fn remove_user_oid(&mut self, user: &User, oid: Oid) {
        if let Some(orders) = self.user_orders.get_mut(user) {
            orders.remove(&oid);
            if orders.is_empty() {
                self.user_orders.remove(user);
            }
        }
    }

    fn reject_duplicate(&self, user: User, oid: Oid) -> bool {
        self.order_by_oid.contains_key(&oid)
            || self.user_orders.get(&user).and_then(|orders| orders.get(&oid)).is_some()
    }

    fn validate_oid_asset(&self, oid: Oid, asset: &AssetContext, ctx: &InsertContext) -> bool {
        if ctx.enforce_oid_asset && oid / OID_SLOT_MODULUS != asset.asset {
            return false;
        }
        if ctx.enforce_oid_asset && asset.asset != self.asset {
            return false;
        }
        true
    }

    fn crosses(&self, side: Side, px: Px) -> bool {
        let bbo = self.best_bid_ask();
        match side {
            Side::Bid => bbo.ask != 0 && px >= bbo.ask,
            Side::Ask => bbo.bid != 0 && px <= bbo.bid,
        }
    }
}

#[inline]
fn valid_price(px: Px, tick_size: Px) -> bool {
    px > 0 && px <= MAX_LIMIT_PX && tick_size > 0 && px % tick_size == 0
}

#[inline]
fn valid_notional(sz: Sz, px: Px) -> bool {
    if sz <= 0 || px <= 0 {
        return false;
    }
    match (sz as i128).checked_mul(px as i128) {
        Some(notional) => notional <= MAX_NOTIONAL,
        None => false,
    }
}
