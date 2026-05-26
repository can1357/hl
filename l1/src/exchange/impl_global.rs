use std::collections::BTreeSet;

pub type Address = [u8; 20];
pub type AssetId = u64;
pub type DexId = u64;
pub type RawPx = u64;
pub type RawSz = u64;
pub type RawNtl = u64;
pub type TimestampMillis = u64;

const ASSETS_PER_DEX: u64 = 10_000;
const GENERATED_ORDER_NOTIONAL_LIMIT: RawNtl = 100_000_000_000;
const GENERATED_ORDER_NOTIONAL_LIMIT_KIND_2: RawNtl = 10_000_000_000;
const MAX_SAFE_GENERATED_NOTIONAL: RawNtl = 0x7fff_ffff_ffff_fffe;
const GENERATED_ORDER_TIF: u8 = 1;
const GENERATED_ORDER_KIND: u8 = 4;
const GENERATED_ORDER_REPRICE_ON_POSITIVE_DELTA: f64 = 0.8;
const GENERATED_ORDER_REPRICE_ON_NEGATIVE_DELTA: f64 = 1.2;
const GENERATED_ORDER_CAP_SCALE: f64 = 0.2;
const GENERATED_REJECTED_STATUS: u64 = 0x8000_0000_0000_000a;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExchangeDomain {
    Main,
    Alt,
    PerDex,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertGeneratedStatus {
    Applied,
    Rejected(u64),
    MissingDex,
    MissingAsset,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeneratedOrderRequest {
    pub user: Address,
    /// Encoded as `dex * 10_000 + asset`; every recovered path splits the id by
    /// division and remainder with `0x2710` before indexing per-dex arrays.
    pub asset: AssetId,
    pub signed_sz_delta: i64,
    pub action_time_millis: TimestampMillis,
}

#[derive(Clone, Debug, Default)]
pub struct ExchangeGlobalState {
    pub status: u32,
    pub network_kind: u8,
    pub now_millis: TimestampMillis,
    pub main: PerpDexCollection,
    pub alt: PerpDexCollection,
    pub per_dex: PerpDexCollection,
    pub generated_order_user_set: BTreeSet<Address>,
    pub emitted_events: Vec<PerpMetaEvent>,
}

impl ExchangeGlobalState {
    /// Recovered at `0x4cff8f0`: main exchange-state variant of the generated
    /// market-order path.
    pub fn insert_generated_market_order_main(
        &mut self,
        request: GeneratedOrderRequest,
    ) -> InsertGeneratedStatus {
        self.insert_generated_market_order(ExchangeDomain::Main, request)
    }

    /// Recovered at `0x4cff140`: alt exchange-state variant.  The control flow is
    /// identical to the main variant; only the state offsets and downstream order
    /// flow helper differ.
    pub fn insert_generated_market_order_alt(
        &mut self,
        request: GeneratedOrderRequest,
    ) -> InsertGeneratedStatus {
        self.insert_generated_market_order(ExchangeDomain::Alt, request)
    }

    /// Recovered at `0x270e6a0`: per-dex exchange variant called from the per-dex
    /// timestep loop.
    pub fn insert_generated_market_order_per_dex(
        &mut self,
        request: GeneratedOrderRequest,
    ) -> InsertGeneratedStatus {
        self.insert_generated_market_order(ExchangeDomain::PerDex, request)
    }

    pub fn insert_generated_market_order(
        &mut self,
        domain: ExchangeDomain,
        mut request: GeneratedOrderRequest,
    ) -> InsertGeneratedStatus {
        if request.signed_sz_delta == 0 {
            return InsertGeneratedStatus::Rejected(GENERATED_REJECTED_STATUS);
        }

        let cap_result = {
            let network_kind = self.network_kind;
            let now_millis = self.now_millis;
            let Some(collection) = self.collection(domain) else {
                return InsertGeneratedStatus::MissingDex;
            };
            generated_order_cap_adjustment(collection, network_kind, now_millis, request)
        };

        match cap_result {
            CapAdjustment::None => {}
            CapAdjustment::Scaled { user, signed_sz_delta } => {
                self.generated_order_user_set.insert(user);
                request.signed_sz_delta = signed_sz_delta;
            }
            CapAdjustment::Overflow => return InsertGeneratedStatus::ArithmeticOverflow,
            CapAdjustment::MissingDex => return InsertGeneratedStatus::MissingDex,
            CapAdjustment::MissingAsset => return InsertGeneratedStatus::MissingAsset,
        }

        let user_context = (self.status == 1).then(|| UserContext::from_state(self.network_kind));
        let mut event_vec = Vec::new();
        let insert_result = {
            let Some(collection) = self.collection_mut(domain) else {
                return InsertGeneratedStatus::MissingDex;
            };
            collection.build_and_insert_generated_market_order(request, user_context, &mut event_vec)
        };

        if let GeneratedInsertResult::Accepted { fills, post_batches } = &insert_result {
            self.emitted_events.extend(fills.iter().map(|fill| PerpMetaEvent::Fill(fill.clone())));
            self.drain_post_insert_batches(post_batches);
        }

        let apply_result = {
            let Some(collection) = self.collection_mut(domain) else {
                return InsertGeneratedStatus::MissingDex;
            };
            collection.apply_generated_order_events(request.asset / ASSETS_PER_DEX, event_vec)
        };
        if apply_result != InsertGeneratedStatus::Applied {
            return apply_result;
        }

        match insert_result {
            GeneratedInsertResult::Accepted { .. } => InsertGeneratedStatus::Applied,
            GeneratedInsertResult::Rejected(status) => InsertGeneratedStatus::Rejected(status),
            GeneratedInsertResult::MissingDex => InsertGeneratedStatus::MissingDex,
            GeneratedInsertResult::MissingAsset => InsertGeneratedStatus::MissingAsset,
            GeneratedInsertResult::ArithmeticOverflow => InsertGeneratedStatus::ArithmeticOverflow,
        }
    }

    fn collection(&self, domain: ExchangeDomain) -> Option<&PerpDexCollection> {
        Some(match domain {
            ExchangeDomain::Main => &self.main,
            ExchangeDomain::Alt => &self.alt,
            ExchangeDomain::PerDex => &self.per_dex,
        })
    }

    fn collection_mut(&mut self, domain: ExchangeDomain) -> Option<&mut PerpDexCollection> {
        Some(match domain {
            ExchangeDomain::Main => &mut self.main,
            ExchangeDomain::Alt => &mut self.alt,
            ExchangeDomain::PerDex => &mut self.per_dex,
        })
    }

    fn drain_post_insert_batches(&mut self, batches: &[BookEventBatch]) {
        for batch in batches {
            for event in &batch.events {
                self.emitted_events.push(PerpMetaEvent::Book(event.clone()));
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct PerpDexCollection {
    pub dexs: Vec<PerpDexState>,
    pub generated_gate: GeneratedOrderGate,
}

impl PerpDexCollection {
    fn dex(&self, dex: DexId) -> Option<&PerpDexState> {
        self.dexs.get(dex as usize)
    }

    fn dex_mut(&mut self, dex: DexId) -> Option<&mut PerpDexState> {
        self.dexs.get_mut(dex as usize)
    }

    fn build_and_insert_generated_market_order(
        &mut self,
        request: GeneratedOrderRequest,
        user_context: Option<UserContext>,
        emitted_order_events: &mut Vec<OrderFlowEvent>,
    ) -> GeneratedInsertResult {
        let dex_id = request.asset / ASSETS_PER_DEX;
        let local_asset = request.asset % ASSETS_PER_DEX;
        let Some(dex) = self.dex_mut(dex_id) else {
            return GeneratedInsertResult::MissingDex;
        };
        let Some(book) = dex.books.get_mut(local_asset as usize) else {
            return GeneratedInsertResult::MissingAsset;
        };
        let Some(reference) = book.transfer_params.reference_px() else {
            return GeneratedInsertResult::Rejected(GENERATED_REJECTED_STATUS);
        };

        let positive_delta = request.signed_sz_delta >= 0;
        let abs_sz = request.signed_sz_delta.unsigned_abs();
        let px = round_generated_order_px(reference, book.tick_size, positive_delta);
        if px == 0 {
            return GeneratedInsertResult::Rejected(GENERATED_REJECTED_STATUS);
        }

        let order = GeneratedOrderArgs {
            user: request.user,
            asset: request.asset,
            side_positive_delta: positive_delta,
            sz: round_generated_order_sz(abs_sz, book.size_increment),
            limit_px: px,
            timestamp_millis: request.action_time_millis,
            tif: GENERATED_ORDER_TIF,
            order_kind: GENERATED_ORDER_KIND,
            user_context,
        };

        book.insert_generated_order(order, emitted_order_events)
    }

    fn apply_generated_order_events(
        &mut self,
        dex_id: DexId,
        events: Vec<OrderFlowEvent>,
    ) -> InsertGeneratedStatus {
        let Some(dex) = self.dex_mut(dex_id) else {
            return InsertGeneratedStatus::MissingDex;
        };
        for event in events {
            match event {
                OrderFlowEvent::Skip => {}
                OrderFlowEvent::BookOnly(book_event) => dex.meta_events.push(PerpMetaEvent::Book(book_event)),
                OrderFlowEvent::Position(position) => {
                    dex.apply_position_update(position);
                }
                OrderFlowEvent::FundingAndVolume(update) => {
                    dex.apply_funding_and_volume_update(update);
                }
                OrderFlowEvent::Api(event) => dex.meta_events.push(event),
            }
        }
        InsertGeneratedStatus::Applied
    }
}

fn generated_order_cap_adjustment(
    collection: &PerpDexCollection,
    network_kind: u8,
    now_millis: TimestampMillis,
    request: GeneratedOrderRequest,
) -> CapAdjustment {
    if collection.generated_gate.status != 1 {
        return CapAdjustment::None;
    }
    let eligible_at = request.action_time_millis.saturating_add(collection.generated_gate.delay_millis);
    if eligible_at > now_millis {
        return CapAdjustment::None;
    }

    let dex_id = request.asset / ASSETS_PER_DEX;
    let local_asset = request.asset % ASSETS_PER_DEX;
    let Some(dex) = collection.dex(dex_id) else {
        return CapAdjustment::MissingDex;
    };
    let Some(asset) = dex.assets.get(local_asset as usize) else {
        return CapAdjustment::MissingAsset;
    };

    let abs_sz = request.signed_sz_delta.unsigned_abs();
    let Some(notional) = asset.mark_px.checked_mul(abs_sz) else {
        return CapAdjustment::Overflow;
    };
    if notional > MAX_SAFE_GENERATED_NOTIONAL {
        return CapAdjustment::Overflow;
    }

    let limit = if network_kind == 2 {
        GENERATED_ORDER_NOTIONAL_LIMIT_KIND_2
    } else {
        GENERATED_ORDER_NOTIONAL_LIMIT
    };
    if notional < limit {
        return CapAdjustment::None;
    }

    CapAdjustment::Scaled {
        user: request.user,
        signed_sz_delta: scale_generated_delta_to_twenty_percent(request.signed_sz_delta),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapAdjustment {
    None,
    Scaled { user: Address, signed_sz_delta: i64 },
    MissingDex,
    MissingAsset,
    Overflow,
}

#[derive(Clone, Debug, Default)]
pub struct GeneratedOrderGate {
    pub status: u32,
    pub delay_millis: u64,
}

#[derive(Clone, Debug, Default)]
pub struct PerpDexState {
    pub dex: DexId,
    pub assets: Vec<PerpAssetState>,
    pub books: Vec<PerpBookState>,
    pub positions: Vec<PositionState>,
    pub meta_events: Vec<PerpMetaEvent>,
}

impl PerpDexState {
    fn apply_position_update(&mut self, update: PositionUpdate) {
        if let Some(position) = self.positions.iter_mut().find(|position| {
            position.user == update.user && position.asset == update.asset && position.side == update.side
        }) {
            position.raw_sz = update.new_raw_sz;
            position.last_update_millis = update.timestamp_millis;
        } else {
            self.positions.push(PositionState {
                user: update.user,
                asset: update.asset,
                side: update.side,
                raw_sz: update.new_raw_sz,
                last_update_millis: update.timestamp_millis,
            });
        }
        self.meta_events.push(PerpMetaEvent::Position(update));
    }

    fn apply_funding_and_volume_update(&mut self, update: FundingAndVolumeUpdate) {
        self.meta_events.push(PerpMetaEvent::FundingAndVolume(update));
    }
}

#[derive(Clone, Debug, Default)]
pub struct PerpAssetState {
    pub mark_px: RawPx,
}

#[derive(Clone, Debug, Default)]
pub struct PerpBookState {
    pub asset: AssetId,
    pub tick_size: RawPx,
    pub size_increment: RawSz,
    pub transfer_params: TransferParams,
    pub resting: Vec<RestingOrder>,
}

impl PerpBookState {
    fn insert_generated_order(
        &mut self,
        order: GeneratedOrderArgs,
        emitted_order_events: &mut Vec<OrderFlowEvent>,
    ) -> GeneratedInsertResult {
        let mut fills = Vec::new();
        let mut remaining = order.sz;

        for resting in &mut self.resting {
            if remaining == 0 {
                break;
            }
            if !resting.crosses(order.limit_px, order.side_positive_delta) {
                continue;
            }
            let fill_sz = remaining.min(resting.remaining_sz);
            remaining -= fill_sz;
            resting.remaining_sz -= fill_sz;

            let fill = FillEvent {
                taker: order.user,
                maker: resting.user,
                asset: order.asset,
                px: resting.px,
                sz: fill_sz,
                taker_positive_delta: order.side_positive_delta,
                timestamp_millis: order.timestamp_millis,
            };
            fills.push(fill.clone());
            emitted_order_events.push(OrderFlowEvent::BookOnly(BookEvent::Fill(fill.clone())));
            emitted_order_events.push(OrderFlowEvent::Position(PositionUpdate::from_fill(&fill)));
        }

        self.resting.retain(|order| order.remaining_sz != 0);

        let post_batches = if fills.is_empty() {
            Vec::new()
        } else {
            vec![BookEventBatch { events: fills.iter().cloned().map(BookEvent::Fill).collect() }]
        };

        GeneratedInsertResult::Accepted { fills, post_batches }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransferParams {
    pub lower_px: RawPx,
    pub upper_px: RawPx,
}

impl TransferParams {
    fn reference_px(self) -> Option<RawPx> {
        if self.lower_px == 0 || self.upper_px == 0 {
            return None;
        }
        let half_xor = (self.lower_px ^ self.upper_px) >> 1;
        let common = self.lower_px & self.upper_px;
        let midpoint = common.checked_add(half_xor)?;
        (midpoint != 0).then_some(midpoint)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedOrderArgs {
    pub user: Address,
    pub asset: AssetId,
    pub side_positive_delta: bool,
    pub sz: RawSz,
    pub limit_px: RawPx,
    pub timestamp_millis: TimestampMillis,
    pub tif: u8,
    pub order_kind: u8,
    pub user_context: Option<UserContext>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GeneratedInsertResult {
    Accepted { fills: Vec<FillEvent>, post_batches: Vec<BookEventBatch> },
    Rejected(u64),
    MissingDex,
    MissingAsset,
    ArithmeticOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestingOrder {
    pub user: Address,
    pub px: RawPx,
    pub remaining_sz: RawSz,
    pub positive_delta_side: bool,
}

impl RestingOrder {
    fn crosses(&self, incoming_px: RawPx, incoming_positive_delta: bool) -> bool {
        if incoming_positive_delta == self.positive_delta_side {
            return false;
        }
        if incoming_positive_delta {
            self.px >= incoming_px
        } else {
            self.px <= incoming_px
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrderFlowEvent {
    Skip,
    BookOnly(BookEvent),
    Position(PositionUpdate),
    FundingAndVolume(FundingAndVolumeUpdate),
    Api(PerpMetaEvent),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BookEvent {
    Fill(FillEvent),
    MakerUser { user: Address, code: u8 },
    RemoveOrder { user: Address, code: u8 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookEventBatch {
    pub events: Vec<BookEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PerpMetaEvent {
    Book(BookEvent),
    Fill(FillEvent),
    Position(PositionUpdate),
    FundingAndVolume(FundingAndVolumeUpdate),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FillEvent {
    pub taker: Address,
    pub maker: Address,
    pub asset: AssetId,
    pub px: RawPx,
    pub sz: RawSz,
    pub taker_positive_delta: bool,
    pub timestamp_millis: TimestampMillis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PositionUpdate {
    pub user: Address,
    pub asset: AssetId,
    pub side: bool,
    pub new_raw_sz: RawSz,
    pub timestamp_millis: TimestampMillis,
}

impl PositionUpdate {
    fn from_fill(fill: &FillEvent) -> Self {
        Self {
            user: fill.taker,
            asset: fill.asset,
            side: fill.taker_positive_delta,
            new_raw_sz: fill.sz,
            timestamp_millis: fill.timestamp_millis,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FundingAndVolumeUpdate {
    pub asset: AssetId,
    pub user: Address,
    pub volume_ntl: RawNtl,
    pub timestamp_millis: TimestampMillis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PositionState {
    pub user: Address,
    pub asset: AssetId,
    pub side: bool,
    pub raw_sz: RawSz,
    pub last_update_millis: TimestampMillis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserContext {
    pub network_kind: u8,
}

impl UserContext {
    fn from_state(network_kind: u8) -> Self {
        Self { network_kind }
    }
}

fn round_generated_order_px(reference_px: RawPx, tick_size: RawPx, positive_delta: bool) -> RawPx {
    if tick_size == 0 {
        return 0;
    }
    let multiplier = if positive_delta {
        GENERATED_ORDER_REPRICE_ON_POSITIVE_DELTA
    } else {
        GENERATED_ORDER_REPRICE_ON_NEGATIVE_DELTA
    };
    let rounded = clamp_nonnegative_f64_to_u64((reference_px as f64 * multiplier).round());
    let units = rounded / tick_size;
    let units = if positive_delta {
        units.saturating_add(u64::from(rounded % tick_size != 0))
    } else {
        units
    };
    tick_size.saturating_mul(units).max(u64::from(units != 0))
}

fn round_generated_order_sz(raw_sz: RawSz, increment: RawSz) -> RawSz {
    if increment == 0 {
        return raw_sz;
    }
    let units = raw_sz / increment + u64::from(raw_sz % increment != 0);
    increment.saturating_mul(units).max(u64::from(units != 0))
}

fn scale_generated_delta_to_twenty_percent(delta: i64) -> i64 {
    // The optimized code casts through a signed 32-bit integer and then stores the
    // low 32 bits in a 64-bit slot.  Preserve that truncation rather than using a
    // mathematically nicer rounded signed value.
    let scaled = (delta as i32 as f64) * GENERATED_ORDER_CAP_SCALE;
    let clamped = if scaled.is_finite() {
        scaled.clamp(i64::MIN as f64, i64::MAX as f64)
    } else {
        0.0
    };
    (clamped as i32 as u32) as i64
}

fn clamp_nonnegative_f64_to_u64(value: f64) -> u64 {
    if !value.is_finite() || value <= 0.0 {
        0
    } else if value > u64::MAX as f64 {
        u64::MAX
    } else {
        value as u64
    }
}
