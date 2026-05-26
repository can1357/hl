#![allow(dead_code)]

pub type Spot = u64;
pub type Token = u64;
pub type Wei = u64;
pub type RawPx = u64;
pub type RawSz = u64;

pub const USDC_TOKEN: Token = 0;
pub const MAX_HYPERLIQUIDITY_ORDERS: u64 = 4_000;
pub const MIN_HYPERLIQUIDITY_ORDERS: u64 = 10;
pub const HYPERLIQUIDITY_PRICE_RATIO: f64 = 1.003;
pub const MAX_RAW_HYPERLIQUIDITY_VALUE: u64 = 0x1999_9999_9999_9999;
pub const MAX_HYPERLIQUIDITY_PRICE_RAW: RawPx = 0x38d7_ea4c_68000;
pub const MIN_END_MARKET_CAP_USDC: u64 = 1_000_000_000;
pub const MAX_END_MARKET_CAP_USDC: u64 = 100_000_000_000;
pub const MAX_START_MARKET_CAP_USDC: u64 = 10_000_000;

const MARKET_CAP_LOWER_SCALE: u64 = 70_000_000;
const MARKET_CAP_UPPER_SCALE: u64 = 130_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisterHyperliquidityParams {
    pub start_px: RawPx,
    pub spot: Spot,
    pub order_sz: RawSz,
    pub n_orders: u64,
    pub n_seeded_levels: u64,
    /// The caller passes the user's available USDC multiplied by 100.
    pub available_usdc_x100: Wei,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HyperliquidityOrders {
    pub by_spot: std::collections::BTreeMap<Spot, HyperliquidityBook>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HyperliquidityBook {
    pub order_sz: RawSz,
    pub levels: Vec<HyperliquidityLevel>,
    pub base_balance: Wei,
    pub usdc_seeded: Wei,
}

/// One generated level in the hyperliquidity ladder.
///
/// The binary stores this as a 24-byte record.  The recovered helper writes zero
/// at offset 0 and the level price at offset 0x10; the middle word is not used
/// by the recovered validation path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct HyperliquidityLevel {
    pub _unknown_field_at_0: u64,
    pub _unknown_field_at_8: u64,
    pub price: RawPx,
}

impl HyperliquidityLevel {
    pub const fn with_price(price: RawPx) -> Self {
        Self {
            _unknown_field_at_0: 0,
            _unknown_field_at_8: 0,
            price,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedHyperliquidityOrders {
    pub levels: Vec<HyperliquidityLevel>,
    pub order_sz: RawSz,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HyperliquidityError {
    TooManyOrders,
    CannotSeedMoreLevelsThanExist,
    TooFewOrders,
    ZeroOrderSize,
    ConfigurationInvalid,
    PriceInvalid,
    StartingPriceTooSmall,
    StartingOrderValueTooSmall,
    InsufficientUsdcForSeeding,
    MarketCapOutOfRange,
    IncorrectBalance,
}

/// Builds the deterministic price ladder used by register-hyperliquidity.
///
/// Recovered control flow:
/// - snap `start_px` down to the spot tick size and clamp zero to one;
/// - push exactly `n_orders` 24-byte records;
/// - after each push compute `round(price * 1.003)`, clamp to `u64`, snap it
///   down to the current tick size, and clamp zero to one.
///
/// The caller validates the returned first/last prices and seeded notional.
pub fn build_order_ladder<F>(
    spot: Spot,
    start_px: RawPx,
    order_sz: RawSz,
    n_orders: u64,
    mut tick_size_for_price: F,
) -> GeneratedHyperliquidityOrders
where
    F: FnMut(Spot, RawPx) -> RawPx,
{
    let mut price = snap_down_to_tick_at_least_one(start_px, tick_size_for_price(spot, start_px));
    let mut levels = Vec::with_capacity(n_orders as usize);

    for _ in 0..n_orders {
        levels.push(HyperliquidityLevel::with_price(price));

        let rounded = round_scaled_price(price, HYPERLIQUIDITY_PRICE_RATIO);
        price = snap_down_to_tick_at_least_one(rounded, tick_size_for_price(spot, rounded));
    }

    GeneratedHyperliquidityOrders { levels, order_sz }
}

/// Sums `order_sz * level.price` for the initially seeded prefix.
///
/// The machine code returns the sum in `rdx` and rejects multiplication
/// overflow, accumulation overflow, and products above `0x7fff_ffff_ffff_fffe`.
pub fn sum_seeded_notional_x100(
    levels: &[HyperliquidityLevel],
    n_seeded_levels: u64,
    order_sz: RawSz,
) -> Option<Wei> {
    let mut acc = 0u64;
    let seeded = core::cmp::min(n_seeded_levels as usize, levels.len());

    for level in &levels[..seeded] {
        let product = order_sz.checked_mul(level.price)?;
        if product > i64::MAX as u64 - 1 {
            return None;
        }
        acc = acc.checked_add(product)?;
    }

    Some(acc)
}

/// Checks the market-cap window helper recovered at 0x3262600.
///
/// Bounds are scaled before comparison: lower by 70_000_000 and upper by
/// 130_000_000.  Any checked-multiply overflow rejects the value.
pub fn market_cap_in_scaled_range(lower: u64, upper: u64, value: u64) -> bool {
    let Some(low) = lower.checked_mul(MARKET_CAP_LOWER_SCALE) else {
        return false;
    };
    let Some(high) = upper.checked_mul(MARKET_CAP_UPPER_SCALE) else {
        return false;
    };

    value >= low && value <= high
}
pub fn validate_market_cap_windows<F>(
    first_price: RawPx,
    last_price: RawPx,
    token_name: &str,
    mut market_cap_for_price: F,
) -> Result<(), HyperliquidityError>
where
    F: FnMut(RawPx) -> Option<u64>,
{
    const WINDOWS: [(u64, u64); 2] = [
        (MIN_END_MARKET_CAP_USDC, MAX_END_MARKET_CAP_USDC),
        (0, MAX_START_MARKET_CAP_USDC),
    ];

    for (price, (lower, upper)) in [last_price, first_price].iter().copied().zip(WINDOWS) {
        if price == 0 || price > MAX_HYPERLIQUIDITY_PRICE_RAW {
            return Err(HyperliquidityError::PriceInvalid);
        }

        if market_cap_for_price(price).is_some_and(|value| market_cap_in_scaled_range(lower, upper, value)) {
            continue;
        }

        // The binary has a special fallback for the canonical HYPE token name.
        if token_name == "HYPE" {
            continue;
        }

        return Err(HyperliquidityError::MarketCapOutOfRange);
    }

    Ok(())
}

pub fn validate_ladder_shape(
    params: RegisterHyperliquidityParams,
    max_supply: Wei,
    levels: &[HyperliquidityLevel],
) -> Result<Wei, HyperliquidityError> {
    if params.n_orders > MAX_HYPERLIQUIDITY_ORDERS {
        return Err(HyperliquidityError::TooManyOrders);
    }
    if params.n_seeded_levels > params.n_orders {
        return Err(HyperliquidityError::CannotSeedMoreLevelsThanExist);
    }
    if params.n_orders < MIN_HYPERLIQUIDITY_ORDERS {
        return Err(HyperliquidityError::TooFewOrders);
    }
    if params.order_sz == 0 {
        return Err(HyperliquidityError::ZeroOrderSize);
    }
    if params.n_orders.checked_mul(params.order_sz).is_none_or(|v| v > MAX_RAW_HYPERLIQUIDITY_VALUE) {
        return Err(HyperliquidityError::ConfigurationInvalid);
    }

    let Some(first) = levels.first().map(|level| level.price) else {
        return Err(HyperliquidityError::StartingPriceTooSmall);
    };
    let Some(last) = levels.last().map(|level| level.price) else {
        return Err(HyperliquidityError::StartingPriceTooSmall);
    };

    if first == last {
        return Err(HyperliquidityError::StartingPriceTooSmall);
    }
    if first == 0 || last == 0 || last > MAX_HYPERLIQUIDITY_PRICE_RAW {
        return Err(HyperliquidityError::PriceInvalid);
    }
    if params.order_sz.checked_mul(first).is_none_or(|v| v < 1_000_000) {
        return Err(HyperliquidityError::StartingOrderValueTooSmall);
    }

    let start_cap = raw_market_cap_usdc(first, max_supply)?;
    let end_cap = raw_market_cap_usdc(last, max_supply)?;
    if start_cap > MAX_START_MARKET_CAP_USDC
        || end_cap < MIN_END_MARKET_CAP_USDC
        || end_cap > MAX_END_MARKET_CAP_USDC
    {
        return Err(HyperliquidityError::MarketCapOutOfRange);
    }

    let used_usdc_x100 = sum_seeded_notional_x100(levels, params.n_seeded_levels, params.order_sz)
        .ok_or(HyperliquidityError::ConfigurationInvalid)?;
    if used_usdc_x100 > params.available_usdc_x100 {
        return Err(HyperliquidityError::InsufficientUsdcForSeeding);
    }

    Ok(used_usdc_x100)
}

pub fn snap_down_to_tick_at_least_one(price: RawPx, tick_size: RawPx) -> RawPx {
    let snapped = match tick_size {
        0 => u64::MAX,
        tick => price.checked_div(tick).and_then(|q| q.checked_mul(tick)).unwrap_or(u64::MAX),
    };
    snapped.max(1)
}

pub fn round_scaled_price(price: RawPx, ratio: f64) -> RawPx {
    let rounded = ((price as f64) * ratio).round();
    f64_to_u64_saturating(rounded).max(1)
}

pub fn ceil_scaled_price(price: RawPx, ratio: f64, exponent: u64) -> Option<RawPx> {
    let mut multiplier = 1.0;
    for _ in 0..exponent {
        multiplier *= ratio;
    }
    f64_to_u64_checked((price as f64) * multiplier, true)
}

pub fn raw_market_cap_usdc(price: RawPx, supply: Wei) -> Result<u64, HyperliquidityError> {
    let raw = (price as u128)
        .checked_mul(supply as u128)
        .ok_or(HyperliquidityError::ConfigurationInvalid)?;
    let usdc = raw / 100_000_000;
    if usdc > u64::MAX as u128 {
        return Err(HyperliquidityError::MarketCapOutOfRange);
    }
    Ok(usdc as u64)
}

pub const fn div_ceil_100(value: u64) -> u64 {
    value / 100 + if value % 100 == 0 { 0 } else { 1 }
}

fn f64_to_u64_saturating(value: f64) -> u64 {
    if !value.is_finite() {
        return if value.is_sign_negative() { 0 } else { u64::MAX };
    }
    if value <= 0.0 {
        0
    } else if value >= u64::MAX as f64 {
        u64::MAX
    } else {
        value as u64
    }
}

fn f64_to_u64_checked(value: f64, ceil: bool) -> Option<u64> {
    if !value.is_finite() || value < 0.0 || value > u64::MAX as f64 {
        return None;
    }
    let value = if ceil { value.ceil() } else { value.round() };
    Some(value as u64)
}
