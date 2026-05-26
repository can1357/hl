use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const ASSETS_PER_BOOK_GROUP: u64 = 10_000;
pub const BOOK_STATE_STRIDE: usize = 0xd8;
pub const DEX_BOOK_COLLECTION_STRIDE: usize = 0x138;
pub const MARKET_META_STRIDE: usize = 0x2f0;
pub const ASSET_META_STRIDE: usize = 0x30;
pub const RAW_ASSET_STATE_STRIDE: usize = 0x60;
pub const LARGE_SWEEP_NOTIONAL_THRESHOLD: u128 = 0x98967f;
pub const DEFAULT_IMPACT_NOTIONAL: u64 = 10_000;

pub type AssetId = u64;
pub type LocalAssetIndex = usize;
pub type DexIndex = usize;
pub type Oid = u64;
pub type User = [u8; 20];
pub type RawPx = u64;
pub type RawSz = u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum BookDomain {
    MainPerp,
    PerpDex,
    Spot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Side {
    Bid,
    Ask,
}

impl Side {
    pub fn index(self) -> usize {
        match self {
            Side::Bid => 0,
            Side::Ask => 1,
        }
    }

    pub fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Side::Bid),
            1 => Some(Side::Ask),
            _ => None,
        }
    }

    pub fn level_key(self, px: RawPx) -> i128 {
        match self {
            Side::Bid => -(px as i128),
            Side::Ask => px as i128,
        }
    }

    pub fn px_from_key(self, key: i128) -> RawPx {
        match self {
            Side::Bid => (-key) as RawPx,
            Side::Ask => key as RawPx,
        }
    }

    pub fn opposite(self) -> Self {
        match self {
            Side::Bid => Side::Ask,
            Side::Ask => Side::Bid,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedAssetId {
    pub dex: DexIndex,
    pub local: LocalAssetIndex,
}

impl PackedAssetId {
    pub fn split(asset_id: AssetId) -> Self {
        Self {
            dex: (asset_id / ASSETS_PER_BOOK_GROUP) as DexIndex,
            local: (asset_id % ASSETS_PER_BOOK_GROUP) as LocalAssetIndex,
        }
    }

    pub fn pack(self) -> AssetId {
        self.dex as AssetId * ASSETS_PER_BOOK_GROUP + self.local as AssetId
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BookSelection {
    One(AssetId),
    All,
}

#[derive(Clone, Debug)]
pub struct Books {
    pub main_perp_markets: Vec<MarketMeta>,
    pub main_perp_collections: Vec<DexBookCollection>,
    pub main_perp_books: Vec<Book>,
    pub perp_dex_markets: Vec<MarketMeta>,
    pub perp_dex_collections: Vec<DexBookCollection>,
    pub perp_dex_books: Vec<Book>,
    pub spot_collections: Vec<DexBookCollection>,
    pub user_order_stats: HashMap<User, UserOrderStats>,
    pub registered_main_perp_assets: BTreeSet<AssetId>,
    pub registered_perp_dex_assets: BTreeSet<AssetId>,
    pub volume_accumulator: VolumeAccumulator,
}

impl Books {
    pub fn new(main_perp_markets: Vec<MarketMeta>, perp_dex_markets: Vec<MarketMeta>, spot_markets: Vec<MarketMeta>) -> Self {
        let main_perp_collections = Self::build_domain_collections(BookDomain::MainPerp, &main_perp_markets);
        let perp_dex_collections = Self::build_domain_collections(BookDomain::PerpDex, &perp_dex_markets);
        let spot_collections = Self::build_domain_collections(BookDomain::Spot, &spot_markets);
        let main_perp_books = flatten_collections(&main_perp_collections);
        let perp_dex_books = flatten_collections(&perp_dex_collections);

        Self {
            main_perp_markets,
            main_perp_collections,
            main_perp_books,
            perp_dex_markets,
            perp_dex_collections,
            perp_dex_books,
            spot_collections,
            user_order_stats: HashMap::new(),
            registered_main_perp_assets: BTreeSet::new(),
            registered_perp_dex_assets: BTreeSet::new(),
            volume_accumulator: VolumeAccumulator::default(),
        }
    }

    fn build_domain_collections(domain: BookDomain, markets: &[MarketMeta]) -> Vec<DexBookCollection> {
        markets
            .iter()
            .enumerate()
            .map(|(dex, meta)| {
                debug_assert_eq!(dex as u64, meta.dex_index);
                DexBookCollection::from_market(domain, meta)
            })
            .collect()
    }

    /// IDA: `0x4CAA7A0` uses `asset / 10000`, `asset % 10000`, descriptor stride `0x138`, book stride `0xd8`.
    pub fn main_perp_book_for_packed_asset(&self, asset_id: AssetId) -> Option<&Book> {
        let PackedAssetId { dex, local } = PackedAssetId::split(asset_id);
        self.main_perp_collections.get(dex)?.book(local)
    }

    pub fn main_perp_book_for_packed_asset_mut(&mut self, asset_id: AssetId) -> Option<&mut Book> {
        let PackedAssetId { dex, local } = PackedAssetId::split(asset_id);
        self.main_perp_collections.get_mut(dex)?.book_mut(local)
    }

    /// IDA: `0x4CAA6D0` mirrors the main-perp packed selector using the perp-dex descriptor vector.
    pub fn perp_dex_book_for_packed_asset(&self, asset_id: AssetId) -> Option<&Book> {
        let PackedAssetId { dex, local } = PackedAssetId::split(asset_id);
        self.perp_dex_collections.get(dex)?.book(local)
    }

    pub fn perp_dex_book_for_packed_asset_mut(&mut self, asset_id: AssetId) -> Option<&mut Book> {
        let PackedAssetId { dex, local } = PackedAssetId::split(asset_id);
        self.perp_dex_collections.get_mut(dex)?.book_mut(local)
    }

    pub fn spot_book_for_asset(&self, asset_id: AssetId) -> Option<&Book> {
        let PackedAssetId { dex, local } = PackedAssetId::split(asset_id);
        self.spot_collections.get(dex)?.book(local)
    }

    pub fn spot_book_for_asset_mut(&mut self, asset_id: AssetId) -> Option<&mut Book> {
        let PackedAssetId { dex, local } = PackedAssetId::split(asset_id);
        self.spot_collections.get_mut(dex)?.book_mut(local)
    }

    pub fn book(&self, domain: BookDomain, asset_id: AssetId) -> Option<&Book> {
        match domain {
            BookDomain::MainPerp => self.main_perp_book_for_packed_asset(asset_id),
            BookDomain::PerpDex => self.perp_dex_book_for_packed_asset(asset_id),
            BookDomain::Spot => self.spot_book_for_asset(asset_id),
        }
    }

    pub fn book_mut(&mut self, domain: BookDomain, asset_id: AssetId) -> Option<&mut Book> {
        match domain {
            BookDomain::MainPerp => self.main_perp_book_for_packed_asset_mut(asset_id),
            BookDomain::PerpDex => self.perp_dex_book_for_packed_asset_mut(asset_id),
            BookDomain::Spot => self.spot_book_for_asset_mut(asset_id),
        }
    }

    /// IDA: `0x24FB450`/`0x24FB4E0` return a 40-byte view over a selected collection book.
    pub fn collection_view(&mut self, domain: BookDomain, asset_id: AssetId) -> Option<BookView<'_>> {
        let PackedAssetId { dex, local } = PackedAssetId::split(asset_id);
        let collection = match domain {
            BookDomain::MainPerp => self.main_perp_collections.get_mut(dex)?,
            BookDomain::PerpDex => self.perp_dex_collections.get_mut(dex)?,
            BookDomain::Spot => self.spot_collections.get_mut(dex)?,
        };
        collection.view(local)
    }

    /// IDA: iterator wrappers `0x4C63F20`, `0x4C641C0`, `0x4C64300`, `0x4C64080` dispatch either one local book or all books.
    pub fn for_each_selected_book_mut<F>(&mut self, domain: BookDomain, selection: BookSelection, mut f: F)
    where
        F: FnMut(&mut Book),
    {
        match selection {
            BookSelection::One(asset_id) => {
                if let Some(book) = self.book_mut(domain, asset_id) {
                    f(book);
                }
            }
            BookSelection::All => match domain {
                BookDomain::MainPerp => {
                    for collection in &mut self.main_perp_collections {
                        for book in &mut collection.books {
                            f(book);
                        }
                    }
                }
                BookDomain::PerpDex => {
                    for collection in &mut self.perp_dex_collections {
                        for book in &mut collection.books {
                            f(book);
                        }
                    }
                }
                BookDomain::Spot => {
                    for collection in &mut self.spot_collections {
                        for book in &mut collection.books {
                            f(book);
                        }
                    }
                }
            },
        }
    }

    /// IDA: `0x2703080` has a single-book/all-books branch and calls the book update helper for every selected book.
    pub fn apply_book_snapshot_update(&mut self, domain: BookDomain, selection: BookSelection, update: &BookSnapshotUpdate, events: &mut Vec<BookEvent>) {
        self.for_each_selected_book_mut(domain, selection, |book| book.apply_snapshot_update(update, events));
    }

    /// IDA: `0x27031B0` mirrors snapshot dispatch and emits per-user order records.
    pub fn apply_user_book_update(&mut self, domain: BookDomain, selection: BookSelection, update: &BookSnapshotUpdate, user_events: &mut Vec<UserBookEvent>) {
        self.for_each_selected_book_mut(domain, selection, |book| {
            let mut events = Vec::new();
            book.apply_snapshot_update(update, &mut events);
            for event in events {
                if let Some(user) = event.user() {
                    user_events.push(UserBookEvent { user, asset: book.asset_id, event });
                }
            }
        });
    }

    /// IDA: `0x4CF0850` inserts packed asset ids into the main-perp clearinghouse set and initializes missing book state.
    pub fn ensure_main_perp_book_registered(&mut self, asset_id: AssetId) -> Option<&mut Book> {
        if self.registered_main_perp_assets.insert(asset_id) {
            if let Some(book) = self.main_perp_book_for_packed_asset_mut(asset_id) {
                book.registered = true;
                book.reset_runtime_caches();
            }
        }
        self.main_perp_book_for_packed_asset_mut(asset_id)
    }

    /// IDA: `0x4CF0D10` is the perp-dex mirror of the main-perp registration path.
    pub fn ensure_perp_dex_book_registered(&mut self, asset_id: AssetId) -> Option<&mut Book> {
        if self.registered_perp_dex_assets.insert(asset_id) {
            if let Some(book) = self.perp_dex_book_for_packed_asset_mut(asset_id) {
                book.registered = true;
                book.reset_runtime_caches();
            }
        }
        self.perp_dex_book_for_packed_asset_mut(asset_id)
    }

    /// IDA: `0x1E82600` validates metadata dex id/local index and scales mark/mid values by asset decimals.
    pub fn asset_ctx_prices(&self, domain: BookDomain, asset_id: AssetId) -> Option<AssetCtxPrices> {
        let PackedAssetId { dex, local } = PackedAssetId::split(asset_id);
        let meta = self.market_meta(domain, dex)?;
        if meta.dex_index != dex as u64 {
            return None;
        }
        let asset_meta = meta.assets.get(local)?;
        let raw = meta.raw_states.get(local)?;
        let book = self.book(domain, asset_id)?;
        let scale = asset_meta.px_scale();

        Some(AssetCtxPrices {
            mark_px: raw.mark_px.map(|px| format_scaled(px, scale)),
            oracle_px: raw.oracle_px.map(|px| format_scaled(px, scale)),
            mid_px: book.mid_px().map(|px| format_scaled(px, scale)),
            impact_pxs: book.impact_pxs(DEFAULT_IMPACT_NOTIONAL).map(|[bid, ask]| [format_scaled(bid, scale), format_scaled(ask, scale)]),
        })
    }

    pub fn perp_asset_ctx(&self, domain: BookDomain, asset_id: AssetId) -> Option<AssetCtx> {
        let PackedAssetId { dex, local } = PackedAssetId::split(asset_id);
        let meta = self.market_meta(domain, dex)?;
        let raw = meta.raw_states.get(local)?;
        let prices = self.asset_ctx_prices(domain, asset_id)?;
        Some(AssetCtx {
            day_ntl_vlm: raw.day_ntl_vlm.to_string(),
            funding: raw.funding.to_string(),
            impact_pxs: prices.impact_pxs,
            mark_px: prices.mark_px.unwrap_or_else(|| "0".to_owned()),
            mid_px: prices.mid_px,
            open_interest: raw.open_interest.to_string(),
            oracle_px: prices.oracle_px.unwrap_or_else(|| "0".to_owned()),
            premium: raw.premium.to_string(),
            prev_day_px: raw.prev_day_px.to_string(),
        })
    }

    pub fn spot_asset_ctx(&self, asset_id: AssetId) -> Option<SpotAssetCtx> {
        let PackedAssetId { dex, local } = PackedAssetId::split(asset_id);
        let meta = self.market_meta(BookDomain::Spot, dex)?;
        let raw = meta.raw_states.get(local)?;
        let prices = self.asset_ctx_prices(BookDomain::Spot, asset_id)?;
        Some(SpotAssetCtx {
            day_ntl_vlm: raw.day_ntl_vlm.to_string(),
            mark_px: prices.mark_px.unwrap_or_else(|| "0".to_owned()),
            mid_px: prices.mid_px,
            prev_day_px: raw.prev_day_px.to_string(),
        })
    }

    pub fn l2_book(&self, domain: BookDomain, asset_id: AssetId, max_levels: usize, now_ms: u64) -> Option<L2BookData> {
        let book = self.book(domain, asset_id)?;
        Some(L2BookData {
            coin: book.display_name.clone(),
            levels: [book.l2_levels(Side::Bid, max_levels), book.l2_levels(Side::Ask, max_levels)],
            time: now_ms,
        })
    }

    /// IDA: `0x4CDF580` aggregates across first descriptor and direct book vectors, using midpoint and metadata scaling.
    pub fn recompute_volume_accumulator(&mut self) {
        let mut total_mid_ntl = 0_u128;
        let mut active_books = 0_u64;

        for book in self.iter_all_books() {
            if let Some(mid) = book.mid_px() {
                let resting = book.total_resting_sz();
                total_mid_ntl = total_mid_ntl.saturating_add(u128::from(mid).saturating_mul(u128::from(resting)));
                active_books = active_books.saturating_add(1);
            }
        }

        self.volume_accumulator.total_mid_notional = total_mid_ntl;
        self.volume_accumulator.active_books = active_books;
    }

    pub fn iter_all_books(&self) -> impl Iterator<Item = &Book> {
        self.main_perp_collections
            .iter()
            .chain(self.perp_dex_collections.iter())
            .chain(self.spot_collections.iter())
            .flat_map(|collection| collection.books.iter())
    }

    pub fn iter_all_books_mut(&mut self) -> impl Iterator<Item = &mut Book> {
        self.main_perp_collections
            .iter_mut()
            .chain(self.perp_dex_collections.iter_mut())
            .chain(self.spot_collections.iter_mut())
            .flat_map(|collection| collection.books.iter_mut())
    }

    pub fn direct_execute_order(&mut self, domain: BookDomain, order: NewOrder, now_ms: u64) -> OrderExecutionResult {
        let asset_id = order.asset_id;
        let Some(book) = self.book_mut(domain, asset_id) else {
            return OrderExecutionResult::Rejected(OrderRejectReason::UnknownAsset);
        };
        book.execute_order(order, now_ms)
    }

    /// IDA: `0x4CDCD60`/`0x4CDC540` sweep candidate matches whose raw notional exceeds `0x98967f`.
    pub fn sweep_large_matches(&mut self, domain: BookDomain, candidates: &[MatchCandidate], events: &mut Vec<BookEvent>) {
        for candidate in candidates {
            let notional = u128::from(candidate.px).saturating_mul(u128::from(candidate.sz));
            if notional <= LARGE_SWEEP_NOTIONAL_THRESHOLD {
                continue;
            }
            if let Some(book) = self.book_mut(domain, candidate.asset_id) {
                book.remove_liquidity(candidate.side.opposite(), candidate.sz, events);
            }
        }
    }

    pub fn settle_user_book_effects(&mut self, domain: BookDomain, user: User, desired_sz: RawSz, events: &mut Vec<BookEvent>) -> RawSz {
        let mut remaining = desired_sz;
        for book in self.iter_domain_books_mut(domain) {
            if remaining == 0 {
                break;
            }
            let removed = book.cancel_user_until(user, remaining, events);
            remaining = remaining.saturating_sub(removed);
        }
        desired_sz - remaining
    }

    fn iter_domain_books_mut(&mut self, domain: BookDomain) -> Box<dyn Iterator<Item = &mut Book> + '_> {
        match domain {
            BookDomain::MainPerp => Box::new(self.main_perp_collections.iter_mut().flat_map(|collection| collection.books.iter_mut())),
            BookDomain::PerpDex => Box::new(self.perp_dex_collections.iter_mut().flat_map(|collection| collection.books.iter_mut())),
            BookDomain::Spot => Box::new(self.spot_collections.iter_mut().flat_map(|collection| collection.books.iter_mut())),
        }
    }

    fn market_meta(&self, domain: BookDomain, dex: DexIndex) -> Option<&MarketMeta> {
        match domain {
            BookDomain::MainPerp => self.main_perp_markets.get(dex),
            BookDomain::PerpDex => self.perp_dex_markets.get(dex),
            BookDomain::Spot => self.spot_collections.get(dex).map(|collection| &collection.meta),
        }
    }
}

fn flatten_collections(collections: &[DexBookCollection]) -> Vec<Book> {
    collections.iter().flat_map(|collection| collection.books.iter().cloned()).collect()
}

#[derive(Clone, Debug)]
pub struct DexBookCollection {
    pub domain: BookDomain,
    pub dex_index: DexIndex,
    pub meta: MarketMeta,
    pub books: Vec<Book>,
    pub helper_state: CollectionHelperState,
}

impl DexBookCollection {
    pub fn from_market(domain: BookDomain, meta: &MarketMeta) -> Self {
        let dex_index = meta.dex_index as DexIndex;
        let books = meta
            .assets
            .iter()
            .enumerate()
            .map(|(local, asset)| Book::new(domain, dex_index, local, asset.clone()))
            .collect();
        Self {
            domain,
            dex_index,
            meta: meta.clone(),
            books,
            helper_state: CollectionHelperState::default(),
        }
    }

    pub fn book(&self, local: LocalAssetIndex) -> Option<&Book> {
        self.books.get(local)
    }

    pub fn book_mut(&mut self, local: LocalAssetIndex) -> Option<&mut Book> {
        self.books.get_mut(local)
    }

    pub fn view(&mut self, local: LocalAssetIndex) -> Option<BookView<'_>> {
        let meta = self.meta.assets.get(local)?.clone();
        let book = self.books.get_mut(local)?;
        Some(BookView {
            domain: self.domain,
            dex_index: self.dex_index,
            local_index: local,
            meta,
            book,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct CollectionHelperState {
    pub touched_assets: BTreeSet<AssetId>,
    pub last_update_ms: u64,
}

pub struct BookView<'a> {
    pub domain: BookDomain,
    pub dex_index: DexIndex,
    pub local_index: LocalAssetIndex,
    pub meta: AssetMeta,
    pub book: &'a mut Book,
}

impl BookView<'_> {
    pub fn asset_id(&self) -> AssetId {
        PackedAssetId { dex: self.dex_index, local: self.local_index }.pack()
    }
}

#[derive(Clone, Debug)]
pub struct MarketMeta {
    pub dex_index: u64,
    pub name: String,
    pub assets: Vec<AssetMeta>,
    pub raw_states: Vec<RawAssetState>,
}

#[derive(Clone, Debug)]
pub struct AssetMeta {
    pub name: String,
    pub sz_decimals: u8,
    pub px_decimals: u8,
    pub is_only_isolated: bool,
}

impl AssetMeta {
    pub fn px_scale(&self) -> u64 {
        decimal_scale(self.px_decimals.min(18))
    }

    pub fn sz_scale(&self) -> u64 {
        decimal_scale(self.sz_decimals.min(18))
    }
}

#[derive(Clone, Debug, Default)]
pub struct RawAssetState {
    pub mark_px: Option<RawPx>,
    pub oracle_px: Option<RawPx>,
    pub open_interest: u64,
    pub day_ntl_vlm: u64,
    pub prev_day_px: u64,
    pub premium: i64,
    pub funding: i64,
}

#[derive(Clone, Debug)]
pub struct Book {
    pub domain: BookDomain,
    pub dex_index: DexIndex,
    pub local_index: LocalAssetIndex,
    pub asset_id: AssetId,
    pub display_name: String,
    pub meta: AssetMeta,
    pub bids: BTreeMap<i128, BookLevel>,
    pub asks: BTreeMap<i128, BookLevel>,
    pub orders: HashMap<Oid, BookOrder>,
    pub user_to_oids: HashMap<User, BTreeSet<Oid>>,
    pub top_cache: [Option<Oid>; 2],
    pub mark_px: Option<RawPx>,
    pub oracle_px: Option<RawPx>,
    pub impact_state: ImpactState,
    pub registered: bool,
}

impl Book {
    pub fn new(domain: BookDomain, dex_index: DexIndex, local_index: LocalAssetIndex, meta: AssetMeta) -> Self {
        Self {
            domain,
            dex_index,
            local_index,
            asset_id: PackedAssetId { dex: dex_index, local: local_index }.pack(),
            display_name: meta.name.clone(),
            meta,
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            orders: HashMap::new(),
            user_to_oids: HashMap::new(),
            top_cache: [None, None],
            mark_px: None,
            oracle_px: None,
            impact_state: ImpactState::default(),
            registered: false,
        }
    }

    pub fn reset_runtime_caches(&mut self) {
        self.top_cache = [self.top_order(Side::Bid).map(|order| order.oid), self.top_order(Side::Ask).map(|order| order.oid)];
        self.impact_state.reset();
    }

    pub fn levels(&self, side: Side) -> &BTreeMap<i128, BookLevel> {
        match side {
            Side::Bid => &self.bids,
            Side::Ask => &self.asks,
        }
    }

    pub fn levels_mut(&mut self, side: Side) -> &mut BTreeMap<i128, BookLevel> {
        match side {
            Side::Bid => &mut self.bids,
            Side::Ask => &mut self.asks,
        }
    }

    /// IDA: top order helpers `0x49E3930` and `0x4A06F70` select side trees and clone the first order.
    pub fn top_order(&self, side: Side) -> Option<&BookOrder> {
        let level = match side {
            Side::Bid => self.bids.iter().next(),
            Side::Ask => self.asks.iter().next(),
        }?;
        self.orders.get(&level.1.first_oid)
    }

    pub fn top_orders_side_map(&self) -> SideMap<Option<BookOrder>> {
        SideMap {
            bid: self.top_order(Side::Bid).cloned(),
            ask: self.top_order(Side::Ask).cloned(),
        }
    }

    pub fn best_px(&self, side: Side) -> Option<RawPx> {
        self.levels(side).keys().next().map(|key| side.px_from_key(*key))
    }

    pub fn mid_px(&self) -> Option<RawPx> {
        let bid = self.best_px(Side::Bid)?;
        let ask = self.best_px(Side::Ask)?;
        Some((bid & ask) + ((bid ^ ask) >> 1))
    }

    pub fn total_resting_sz(&self) -> RawSz {
        self.orders.values().fold(0_u64, |acc, order| acc.saturating_add(order.resting_sz))
    }

    pub fn l2_levels(&self, side: Side, max_levels: usize) -> Vec<L2Level> {
        self.levels(side)
            .iter()
            .take(max_levels)
            .filter_map(|(key, level)| {
                let px = side.px_from_key(*key);
                let mut sz = 0_u64;
                let mut n = 0_u64;
                for oid in &level.oids {
                    if let Some(order) = self.orders.get(oid) {
                        sz = sz.saturating_add(order.resting_sz);
                        n = n.saturating_add(1);
                    }
                }
                (n != 0).then(|| L2Level { px: format_scaled(px, self.meta.px_scale()), sz: format_scaled(sz, self.meta.sz_scale()), n })
            })
            .collect()
    }

    pub fn impact_pxs(&self, notional: u64) -> Option<[RawPx; 2]> {
        let bid = self.impact_px(Side::Bid, notional)?;
        let ask = self.impact_px(Side::Ask, notional)?;
        Some([bid, ask])
    }

    pub fn impact_px(&self, side: Side, target_notional: u64) -> Option<RawPx> {
        let mut accumulated = 0_u128;
        for (key, level) in self.levels(side) {
            let px = side.px_from_key(*key);
            for oid in &level.oids {
                let order = self.orders.get(oid)?;
                accumulated = accumulated.saturating_add(u128::from(px).saturating_mul(u128::from(order.resting_sz)));
                if accumulated >= u128::from(target_notional) {
                    return Some(px);
                }
            }
        }
        None
    }

    pub fn find_order_by_user_oid(&self, user: &User, oid: Oid) -> Option<&BookOrder> {
        let order = self.orders.get(&oid)?;
        (&order.user == user).then_some(order)
    }

    pub fn find_order_by_user_oid_mut(&mut self, user: &User, oid: Oid) -> Option<&mut BookOrder> {
        let matches = self.orders.get(&oid).is_some_and(|order| &order.user == user);
        matches.then(|| self.orders.get_mut(&oid)).flatten()
    }

    pub fn insert_order(&mut self, order: BookOrder, events: &mut Vec<BookEvent>) -> Result<(), BookInsertError> {
        if self.orders.contains_key(&order.oid) {
            return Err(BookInsertError::DuplicateOid);
        }

        let key = order.side.level_key(order.limit_px);
        let side = order.side;
        let oid = order.oid;
        let user = order.user;
        self.levels_mut(side).entry(key).or_default().insert(oid);
        self.user_to_oids.entry(user).or_default().insert(oid);
        self.orders.insert(oid, order);
        self.top_cache[side.index()] = self.top_order(side).map(|order| order.oid);
        events.push(BookEvent::Inserted { asset: self.asset_id, oid, user });
        Ok(())
    }

    /// IDA book removal helpers unlink oid/user indices and delete empty level records.
    pub fn remove_order(&mut self, user: User, oid: Oid, events: &mut Vec<BookEvent>, emit_flag: bool) -> bool {
        let Some(order) = self.orders.remove(&oid) else {
            return false;
        };
        if order.user != user {
            self.orders.insert(oid, order);
            return false;
        }

        let key = order.side.level_key(order.limit_px);
        let should_remove_level = if let Some(level) = self.levels_mut(order.side).get_mut(&key) {
            level.remove(oid);
            level.oids.is_empty()
        } else {
            false
        };
        if should_remove_level {
            self.levels_mut(order.side).remove(&key);
        }
        if let Some(oids) = self.user_to_oids.get_mut(&user) {
            oids.remove(&oid);
            if oids.is_empty() {
                self.user_to_oids.remove(&user);
            }
        }
        self.top_cache[order.side.index()] = self.top_order(order.side).map(|top| top.oid);
        if emit_flag {
            events.push(BookEvent::Removed { asset: self.asset_id, oid, user, remaining_sz: order.resting_sz });
        }
        true
    }

    pub fn cancel_user_until(&mut self, user: User, mut max_sz: RawSz, events: &mut Vec<BookEvent>) -> RawSz {
        let Some(oids) = self.user_to_oids.get(&user).cloned() else {
            return 0;
        };
        let mut cancelled = 0_u64;
        for oid in oids {
            if max_sz == 0 {
                break;
            }
            if let Some(order) = self.orders.get(&oid) {
                let take = order.resting_sz.min(max_sz);
                max_sz -= take;
                cancelled = cancelled.saturating_add(take);
            }
            self.remove_order(user, oid, events, true);
        }
        cancelled
    }

    pub fn apply_snapshot_update(&mut self, update: &BookSnapshotUpdate, events: &mut Vec<BookEvent>) {
        self.mark_px = update.mark_px.or(self.mark_px);
        self.oracle_px = update.oracle_px.or(self.oracle_px);
        if update.clear_first {
            self.bids.clear();
            self.asks.clear();
            self.orders.clear();
            self.user_to_oids.clear();
            self.top_cache = [None, None];
            events.push(BookEvent::Cleared { asset: self.asset_id });
        }
        for order in &update.upserts {
            if self.orders.contains_key(&order.oid) {
                self.remove_order(order.user, order.oid, events, false);
            }
            let _ = self.insert_order(order.clone(), events);
        }
        for cancel in &update.cancels {
            self.remove_order(cancel.user, cancel.oid, events, true);
        }
    }

    pub fn execute_order(&mut self, order: NewOrder, now_ms: u64) -> OrderExecutionResult {
        let mut remaining = order.sz;
        let mut fills = Vec::new();
        let cross_side = order.side.opposite();

        while remaining != 0 {
            let Some(best_px) = self.best_px(cross_side) else { break };
            let crosses = match order.side {
                Side::Bid => best_px <= order.limit_px,
                Side::Ask => best_px >= order.limit_px,
            };
            if !crosses {
                break;
            }

            let key = cross_side.level_key(best_px);
            let Some(oid) = self.levels(cross_side).get(&key).and_then(|level| level.oids.first().copied()) else { break };
            let Some(resting) = self.orders.get_mut(&oid) else { break };
            let fill_sz = resting.resting_sz.min(remaining);
            resting.resting_sz -= fill_sz;
            remaining -= fill_sz;
            fills.push(Fill { maker_oid: oid, taker_oid: order.oid, px: best_px, sz: fill_sz, maker: resting.user, taker: order.user, time: now_ms });
            if resting.resting_sz == 0 {
                let user = resting.user;
                self.remove_order(user, oid, &mut Vec::new(), false);
            }
        }

        if remaining != 0 && order.post_to_book {
            let mut events = Vec::new();
            let resting = BookOrder {
                oid: order.oid,
                user: order.user,
                side: order.side,
                limit_px: order.limit_px,
                resting_sz: remaining,
                reduce_only: order.reduce_only,
                cloid: order.cloid,
                timestamp_ms: now_ms,
                child_oids: Vec::new(),
            };
            if let Err(reason) = self.insert_order(resting, &mut events) {
                return OrderExecutionResult::Rejected(OrderRejectReason::Insert(reason));
            }
        }

        OrderExecutionResult::Accepted { fills, resting_sz: remaining }
    }

    pub fn remove_liquidity(&mut self, side: Side, mut sz: RawSz, events: &mut Vec<BookEvent>) -> RawSz {
        let mut removed = 0_u64;
        while sz != 0 {
            let Some(px) = self.best_px(side) else { break };
            let key = side.level_key(px);
            let Some(oid) = self.levels(side).get(&key).and_then(|level| level.oids.first().copied()) else { break };
            let Some(order) = self.orders.get(&oid).cloned() else { break };
            let take = order.resting_sz.min(sz);
            sz -= take;
            removed = removed.saturating_add(take);
            if take == order.resting_sz {
                self.remove_order(order.user, oid, events, true);
            } else if let Some(order_mut) = self.orders.get_mut(&oid) {
                order_mut.resting_sz -= take;
                events.push(BookEvent::Reduced { asset: self.asset_id, oid, remaining_sz: order_mut.resting_sz });
            }
        }
        removed
    }
}

#[derive(Clone, Debug, Default)]
pub struct BookLevel {
    pub first_oid: Oid,
    pub last_oid: Oid,
    pub oids: BTreeSet<Oid>,
}

impl BookLevel {
    pub fn insert(&mut self, oid: Oid) {
        self.oids.insert(oid);
        self.first_oid = self.oids.first().copied().unwrap_or(0);
        self.last_oid = self.oids.last().copied().unwrap_or(0);
    }

    pub fn remove(&mut self, oid: Oid) {
        self.oids.remove(&oid);
        self.first_oid = self.oids.first().copied().unwrap_or(0);
        self.last_oid = self.oids.last().copied().unwrap_or(0);
    }
}

#[derive(Clone, Debug)]
pub struct BookOrder {
    pub oid: Oid,
    pub user: User,
    pub side: Side,
    pub limit_px: RawPx,
    pub resting_sz: RawSz,
    pub reduce_only: bool,
    pub cloid: Option<u128>,
    pub timestamp_ms: u64,
    pub child_oids: Vec<Oid>,
}

#[derive(Clone, Debug)]
pub struct NewOrder {
    pub asset_id: AssetId,
    pub oid: Oid,
    pub user: User,
    pub side: Side,
    pub limit_px: RawPx,
    pub sz: RawSz,
    pub reduce_only: bool,
    pub cloid: Option<u128>,
    pub post_to_book: bool,
}

#[derive(Clone, Debug)]
pub struct CancelRequest {
    pub user: User,
    pub oid: Oid,
}

#[derive(Clone, Debug, Default)]
pub struct BookSnapshotUpdate {
    pub clear_first: bool,
    pub mark_px: Option<RawPx>,
    pub oracle_px: Option<RawPx>,
    pub upserts: Vec<BookOrder>,
    pub cancels: Vec<CancelRequest>,
}

#[derive(Clone, Debug)]
pub enum BookEvent {
    Inserted { asset: AssetId, oid: Oid, user: User },
    Removed { asset: AssetId, oid: Oid, user: User, remaining_sz: RawSz },
    Reduced { asset: AssetId, oid: Oid, remaining_sz: RawSz },
    Cleared { asset: AssetId },
}

impl BookEvent {
    pub fn user(&self) -> Option<User> {
        match *self {
            BookEvent::Inserted { user, .. } | BookEvent::Removed { user, .. } => Some(user),
            BookEvent::Reduced { .. } | BookEvent::Cleared { .. } => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct UserBookEvent {
    pub user: User,
    pub asset: AssetId,
    pub event: BookEvent,
}

#[derive(Clone, Debug)]
pub struct MatchCandidate {
    pub asset_id: AssetId,
    pub side: Side,
    pub px: RawPx,
    pub sz: RawSz,
}

#[derive(Clone, Debug)]
pub struct Fill {
    pub maker_oid: Oid,
    pub taker_oid: Oid,
    pub px: RawPx,
    pub sz: RawSz,
    pub maker: User,
    pub taker: User,
    pub time: u64,
}

#[derive(Clone, Debug)]
pub enum OrderExecutionResult {
    Accepted { fills: Vec<Fill>, resting_sz: RawSz },
    Rejected(OrderRejectReason),
}

#[derive(Clone, Debug)]
pub enum OrderRejectReason {
    UnknownAsset,
    Insert(BookInsertError),
}

#[derive(Clone, Debug)]
pub enum BookInsertError {
    DuplicateOid,
    MissingParent,
    InvalidLevel,
    InsufficientLiquidity,
    Other(u16),
}

#[derive(Clone, Debug, Default)]
pub struct SideMap<T> {
    pub bid: T,
    pub ask: T,
}

#[derive(Clone, Debug, Default)]
pub struct ImpactState {
    pub ewma_notional: f64,
    pub ewma_weight: f64,
    pub window_seconds: f64,
    pub samples: u64,
    pub last_update_ms: Option<u64>,
}

impl ImpactState {
    pub fn reset(&mut self) {
        self.ewma_notional = 0.0;
        self.ewma_weight = 0.0;
        self.window_seconds = self.window_seconds.max(10.0);
        self.samples = 0;
        self.last_update_ms = None;
    }

    /// IDA: `0x1E83350` clamps the window to at least 10 seconds and uses elapsed seconds for EWMA weight.
    pub fn observe(&mut self, notional: f64, now_ms: u64) {
        let elapsed = self
            .last_update_ms
            .map(|last| now_ms.saturating_sub(last) as f64 / 1000.0)
            .unwrap_or(1.0);
        self.last_update_ms = Some(now_ms);
        let window = self.window_seconds.max(10.0);
        let alpha = (elapsed / window).clamp(0.0, 1.0);
        self.ewma_notional = self.ewma_notional * (1.0 - alpha) + notional * alpha;
        self.ewma_weight = self.ewma_weight * (1.0 - alpha) + alpha;
        self.window_seconds = window;
        self.samples = self.samples.saturating_add(1);
    }

    pub fn normalized(&self) -> Option<f64> {
        (self.ewma_weight > 1e-15).then_some(self.ewma_notional / self.ewma_weight)
    }
}

#[derive(Clone, Debug, Default)]
pub struct VolumeAccumulator {
    pub total_mid_notional: u128,
    pub active_books: u64,
}

#[derive(Clone, Debug, Default)]
pub struct UserOrderStats {
    pub accepted: u64,
    pub rejected: u64,
    pub cancelled: u64,
}

#[derive(Clone, Debug)]
pub struct L2Level {
    pub px: String,
    pub sz: String,
    pub n: u64,
}

#[derive(Clone, Debug)]
pub struct L2BookData {
    pub coin: String,
    pub levels: [Vec<L2Level>; 2],
    pub time: u64,
}

#[derive(Clone, Debug)]
pub struct AssetCtxPrices {
    pub mark_px: Option<String>,
    pub oracle_px: Option<String>,
    pub mid_px: Option<String>,
    pub impact_pxs: Option<[String; 2]>,
}

#[derive(Clone, Debug)]
pub struct AssetCtx {
    pub day_ntl_vlm: String,
    pub funding: String,
    pub impact_pxs: Option<[String; 2]>,
    pub mark_px: String,
    pub mid_px: Option<String>,
    pub open_interest: String,
    pub oracle_px: String,
    pub premium: String,
    pub prev_day_px: String,
}

#[derive(Clone, Debug)]
pub struct SpotAssetCtx {
    pub day_ntl_vlm: String,
    pub mark_px: String,
    pub mid_px: Option<String>,
    pub prev_day_px: String,
}

fn decimal_scale(decimals: u8) -> u64 {
    let mut scale = 1_u64;
    for _ in 0..decimals {
        scale = scale.saturating_mul(10);
    }
    scale
}

pub fn format_scaled(value: u64, scale: u64) -> String {
    if scale <= 1 {
        return value.to_string();
    }
    let whole = value / scale;
    let mut frac = (value % scale).to_string();
    let width = scale.ilog10() as usize;
    if frac.len() < width {
        let zeros = "0".repeat(width - frac.len());
        frac.insert_str(0, &zeros);
    }
    while frac.ends_with('0') {
        frac.pop();
    }
    if frac.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{frac}")
    }
}

pub fn compare_user_key(a: &User, b: &User) -> Ordering {
    a.as_slice().cmp(b.as_slice())
}
