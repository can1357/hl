#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type MarketId = u64;
pub type AssetId = u64;
pub type RawPx = u64;
pub type RawSz = u64;
pub type RawQuote = u64;
pub type OrderId = u64;

const GENERATED_ORDER_ROW_BYTES: usize = 552;
const GENERATED_TEMPLATE_BYTES: usize = 496;
const GENERATED_CLOID_SENTINEL: [u8; 20] = [0xbb; 20];
const GENERATED_ORDER_TIF: u8 = 2;
const GENERATED_ORDER_VARIANT: u8 = 1;
const GENERATED_SIDE_BUY: bool = true;
const ONE_E18: u64 = 1_000_000_000_000_000_000;
const MAX_SAFE_GENERATED_PRODUCT: u128 = 0x7fff_ffff_ffff_fffe;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoleOrderBuildStatus {
    Built,
    Noop,
    InvalidMarket,
    InvalidMetadataScale,
    ProductOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BoleAction {
    /// First word of the 24-byte recovered action tuple.  A zero market id is an
    /// explicit no-op before any exchange state is read.
    pub market_id: MarketId,
    /// Second word of the action tuple.  The generated row builder treats this
    /// as the quote cap and divides it by the token decimal scale.
    pub quote_cap: RawQuote,
    /// Third word of the action tuple.  The binary multiplies this f64 by the
    /// Bole reference price, rounds, saturates to u64, then clamps to at least 1.
    pub price_multiplier: f64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpotMarketMeta {
    pub asset: AssetId,
    pub base_decimals: u8,
    pub quote_decimals: u8,
    pub clearinghouses: &'static [usize],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClearinghouseSlot {
    pub market_id: MarketId,
    /// The recovered path only accepts slots whose word at offset +8 is zero.
    /// Non-zero slots are skipped, not rejected.
    pub occupied_marker: u64,
    pub api_asset: AssetId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedOrderTemplate {
    pub user: Address,
    pub cloid: [u8; 20],
    pub oid: OrderId,
    pub tif: u8,
    pub reduce_only: bool,
    pub grouping: u8,
}

impl GeneratedOrderTemplate {
    pub fn bole(user: Address, oid: OrderId) -> Self {
        Self {
            user,
            cloid: GENERATED_CLOID_SENTINEL,
            oid,
            tif: GENERATED_ORDER_TIF,
            reduce_only: false,
            grouping: GENERATED_ORDER_TIF,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedBoleOrder {
    pub row_variant: u8,
    pub user: Address,
    pub cloid: [u8; 20],
    pub clearinghouse: usize,
    pub market_id: MarketId,
    pub api_asset: AssetId,
    pub side_is_buy: bool,
    pub oid: OrderId,
    pub px: RawPx,
    pub sz: RawSz,
    pub notional: u64,
    pub quote_cap: RawQuote,
    pub decimal_scale: u64,
    pub reference_px: RawPx,
}

impl GeneratedBoleOrder {
    pub const fn encoded_len() -> usize {
        GENERATED_ORDER_ROW_BYTES
    }

    pub const fn template_len() -> usize {
        GENERATED_TEMPLATE_BYTES
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoleBuildOutcome {
    pub status: BoleOrderBuildStatus,
    pub order: Option<GeneratedBoleOrder>,
}

impl BoleBuildOutcome {
    pub const fn noop() -> Self {
        Self { status: BoleOrderBuildStatus::Noop, order: None }
    }

    pub const fn invalid_market() -> Self {
        Self { status: BoleOrderBuildStatus::InvalidMarket, order: None }
    }

    pub const fn invalid_scale() -> Self {
        Self { status: BoleOrderBuildStatus::InvalidMetadataScale, order: None }
    }

    pub const fn product_overflow() -> Self {
        Self { status: BoleOrderBuildStatus::ProductOverflow, order: None }
    }

    pub fn built(order: GeneratedBoleOrder) -> Self {
        Self { status: BoleOrderBuildStatus::Built, order: Some(order) }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ExchangeBoleState {
    pub next_order_id: OrderId,
    pub user: Address,
    pub spot_markets: Vec<SpotMarketMeta>,
    pub clearinghouses: Vec<ClearinghouseSlot>,
    pub bole_reference_px: BTreeMap<MarketId, RawPx>,
    pub generated_users: BTreeSet<Address>,
    pub generated_orders: Vec<GeneratedBoleOrder>,
}

impl ExchangeBoleState {
    /// Recovered filter-map wrapper: iterate 24-byte action triples, call the
    /// single-action builder, drop tag-2/no-op rows, and append concrete 552-byte
    /// generated-order rows in the same order as successful actions.
    pub fn collect_generated_bole_orders(&mut self, actions: &[BoleAction]) -> Vec<GeneratedBoleOrder> {
        let mut out = Vec::new();
        for action in actions.iter().copied() {
            let outcome = self.try_build_generated_bole_order(action);
            if let Some(order) = outcome.order {
                self.generated_users.insert(order.user);
                self.generated_orders.push(order.clone());
                out.push(order);
            }
        }
        out
    }

    /// Build the generated Bole order for one action.  The recovered code:
    ///
    /// 1. Treats `market_id == 0` as no-op.
    /// 2. Bounds-checks the spot market table.
    /// 3. Iterates the market's clearinghouse list and skips every slot whose
    ///    associated marker word is non-zero.
    /// 4. Looks up a BTreeMap keyed by the action market id; missing entries are
    ///    no-op.
    /// 5. Saturating-increments the exchange order id.
    /// 6. Rounds `price_multiplier * reference_px`, saturates to u64, and clamps
    ///    the generated price to at least one.
    /// 7. Delegates the row fill to the same generated-order helper used by the
    ///    spot outcome settlement path.
    pub fn try_build_generated_bole_order(&mut self, action: BoleAction) -> BoleBuildOutcome {
        if action.market_id == 0 {
            return BoleBuildOutcome::noop();
        }

        let Some(market) = self.spot_markets.get(action.market_id as usize) else {
            return BoleBuildOutcome::invalid_market();
        };

        for &clearinghouse_index in market.clearinghouses {
            let Some(slot) = self.clearinghouses.get(clearinghouse_index) else {
                return BoleBuildOutcome::invalid_market();
            };
            if slot.occupied_marker != 0 {
                continue;
            }

            let Some(&reference_px) = self.bole_reference_px.get(&action.market_id) else {
                return BoleBuildOutcome::noop();
            };

            let oid = self.next_order_id;
            self.next_order_id = self.next_order_id.saturating_add(1);
            let template = GeneratedOrderTemplate::bole(self.user, oid);
            let generated_px = rounded_price_from_multiplier(action.price_multiplier, reference_px);

            let order = match build_generated_order_row(
                market,
                slot,
                &template,
                GENERATED_SIDE_BUY,
                generated_px,
                action.quote_cap,
                reference_px,
            ) {
                Ok(order) => order,
                Err(BoleOrderBuildStatus::InvalidMetadataScale) => return BoleBuildOutcome::invalid_scale(),
                Err(_) => return BoleBuildOutcome::product_overflow(),
            };

            return BoleBuildOutcome::built(order);
        }

        BoleBuildOutcome::noop()
    }
}

/// Shared generated-order row construction recovered from the spot outcome
/// helper called by the Bole path.  It computes the decimal scale from the two
/// metadata bytes, chooses `sz = min(1e18 / px, quote_cap / decimal_scale)`, and
/// rejects the row if `sz * px` exceeds the signed-positive product ceiling.
pub fn build_generated_order_row(
    market: &SpotMarketMeta,
    slot: &ClearinghouseSlot,
    template: &GeneratedOrderTemplate,
    side_is_buy: bool,
    px: RawPx,
    quote_cap: RawQuote,
    reference_px: RawPx,
) -> Result<GeneratedBoleOrder, BoleOrderBuildStatus> {
    let decimal_scale = decimal_scale(market.base_decimals, market.quote_decimals)
        .ok_or(BoleOrderBuildStatus::InvalidMetadataScale)?;
    let px = px.max(1);
    let by_notional = ONE_E18 / px;
    let by_quote_cap = quote_cap / decimal_scale;
    let sz = by_notional.min(by_quote_cap);
    let product = (sz as u128)
        .checked_mul(px as u128)
        .ok_or(BoleOrderBuildStatus::ProductOverflow)?;
    if product > MAX_SAFE_GENERATED_PRODUCT {
        return Err(BoleOrderBuildStatus::ProductOverflow);
    }

    Ok(GeneratedBoleOrder {
        row_variant: GENERATED_ORDER_VARIANT,
        user: template.user,
        cloid: template.cloid,
        clearinghouse: slot.market_id as usize,
        market_id: market.asset,
        api_asset: slot.api_asset,
        side_is_buy,
        oid: template.oid,
        px,
        sz,
        notional: product as u64,
        quote_cap,
        decimal_scale,
        reference_px,
    })
}

/// Decimal-scale reconstruction for the helper's bit-decomposed multiply-by-10
/// sequence.  The helper panics if quote decimals are below base decimals or if
/// the difference cannot be represented by the recovered 10^n fast path.
pub fn decimal_scale(base_decimals: u8, quote_decimals: u8) -> Option<u64> {
    let diff = quote_decimals.checked_sub(base_decimals)?;
    pow10_u64(diff)
}

pub fn rounded_price_from_multiplier(multiplier: f64, reference_px: RawPx) -> RawPx {
    let value = (multiplier * (reference_px as f64)).round();
    saturating_rounded_f64_to_u64(value).max(1)
}

pub fn saturating_rounded_f64_to_u64(value: f64) -> u64 {
    if !value.is_finite() || value <= 0.0 {
        return 0;
    }
    if value >= u64::MAX as f64 {
        return u64::MAX;
    }
    value as u64
}

fn pow10_u64(exp: u8) -> Option<u64> {
    let mut value = 1_u64;
    for _ in 0..exp {
        value = value.checked_mul(10)?;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEARINGHOUSE_IDS: &[usize] = &[0];

    fn state() -> ExchangeBoleState {
        let mut state = ExchangeBoleState {
            next_order_id: 7,
            user: [0x11; 20],
            spot_markets: vec![
                SpotMarketMeta { asset: 0, base_decimals: 0, quote_decimals: 0, clearinghouses: &[] },
                SpotMarketMeta { asset: 42, base_decimals: 2, quote_decimals: 5, clearinghouses: CLEARINGHOUSE_IDS },
            ],
            clearinghouses: vec![ClearinghouseSlot { market_id: 3, occupied_marker: 0, api_asset: 1001 }],
            bole_reference_px: BTreeMap::new(),
            generated_users: BTreeSet::new(),
            generated_orders: Vec::new(),
        };
        state.bole_reference_px.insert(1, 10_000);
        state
    }

    #[test]
    fn builds_generated_order_from_reference_price() {
        let mut state = state();
        let out = state.try_build_generated_bole_order(BoleAction {
            market_id: 1,
            quote_cap: 1_000_000,
            price_multiplier: 0.5,
        });
        let order = out.order.unwrap();
        assert_eq!(out.status, BoleOrderBuildStatus::Built);
        assert_eq!(order.px, 5_000);
        assert_eq!(order.sz, 1_000);
        assert_eq!(order.reference_px, 10_000);
        assert_eq!(order.oid, 7);
        assert_eq!(state.next_order_id, 8);
    }

    #[test]
    fn zero_market_is_noop_without_incrementing_order_id() {
        let mut state = state();
        let out = state.try_build_generated_bole_order(BoleAction {
            market_id: 0,
            quote_cap: u64::MAX,
            price_multiplier: 1.0,
        });
        assert_eq!(out.status, BoleOrderBuildStatus::Noop);
        assert_eq!(state.next_order_id, 7);
    }
}
