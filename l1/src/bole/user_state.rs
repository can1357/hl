use std::collections::BTreeMap;
use std::convert::TryFrom;

pub const PRICE_SIZE_SCALE: u128 = 100_000_000_000_000;
pub const RETRY_FACTORS: [Option<f64>; 3] = [None, Some(0.99), Some(0.90)];
pub const STATUS_HEALTH_TIER_FAILED: u8 = 1;
pub const STATUS_ZERO_OR_UNDERFLOW: u8 = 2;
pub const STATUS_ARITHMETIC: u8 = 3;
pub const STATUS_INSUFFICIENT_BALANCE: u8 = 5;
pub const STATUS_CAP_EXCEEDED: u8 = 6;
pub const STATUS_ASSET_MISSING: u8 = 9;
pub const STATUS_GENERIC_VALIDATION: u8 = 10;
pub const STATUS_BALANCE_OK_SENTINEL: u8 = 11;
pub const STATUS_CROSS_STATE_MISMATCH: u8 = 16;
pub const STATUS_CROSS_STATE_OK_SENTINEL: u8 = 17;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UserKey(pub [u8; 20]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoleStatus {
    HealthTierFailed,
    ZeroOrUnderflow,
    Arithmetic,
    InsufficientBalance,
    CapExceeded,
    AssetMissing,
    GenericValidation,
    CrossStateMismatch,
    Recovered(u8),
}

impl BoleStatus {
    pub const fn code(self) -> u8 {
        match self {
            Self::HealthTierFailed => STATUS_HEALTH_TIER_FAILED,
            Self::ZeroOrUnderflow => STATUS_ZERO_OR_UNDERFLOW,
            Self::Arithmetic => STATUS_ARITHMETIC,
            Self::InsufficientBalance => STATUS_INSUFFICIENT_BALANCE,
            Self::CapExceeded => STATUS_CAP_EXCEEDED,
            Self::AssetMissing => STATUS_ASSET_MISSING,
            Self::GenericValidation => STATUS_GENERIC_VALIDATION,
            Self::CrossStateMismatch => STATUS_CROSS_STATE_MISMATCH,
            Self::Recovered(code) => code,
        }
    }

    pub const fn from_code(code: u8) -> Self {
        match code {
            STATUS_HEALTH_TIER_FAILED => Self::HealthTierFailed,
            STATUS_ZERO_OR_UNDERFLOW => Self::ZeroOrUnderflow,
            STATUS_ARITHMETIC => Self::Arithmetic,
            STATUS_INSUFFICIENT_BALANCE => Self::InsufficientBalance,
            STATUS_CAP_EXCEEDED => Self::CapExceeded,
            STATUS_ASSET_MISSING => Self::AssetMissing,
            STATUS_GENERIC_VALIDATION => Self::GenericValidation,
            STATUS_CROSS_STATE_MISMATCH => Self::CrossStateMismatch,
            other => Self::Recovered(other),
        }
    }

    pub const fn from_balance_sentinel(code: u8) -> Result<(), Self> {
        if code == STATUS_BALANCE_OK_SENTINEL {
            Ok(())
        } else if code == STATUS_INSUFFICIENT_BALANCE {
            Err(Self::InsufficientBalance)
        } else {
            Err(Self::GenericValidation)
        }
    }

    pub const fn from_cross_state_sentinel(code: u8) -> Result<(), Self> {
        if code == STATUS_CROSS_STATE_OK_SENTINEL {
            Ok(())
        } else if code == STATUS_CROSS_STATE_MISMATCH {
            Err(Self::CrossStateMismatch)
        } else {
            Err(Self::GenericValidation)
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BoleExposureLane {
    pub base_qty: u64,
    pub quote_or_scaled_qty: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BoleUserExposureEntry {
    pub lanes: [BoleExposureLane; 2],
}

impl BoleUserExposureEntry {
    #[inline]
    pub fn lane(&self, slot: usize) -> BoleExposureLane {
        self.lanes[slot & 1]
    }

    #[inline]
    pub fn lane_mut(&mut self, slot: usize) -> &mut BoleExposureLane {
        &mut self.lanes[slot & 1]
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoleAssetEntry {
    pub kind_or_flags: u64,
    pub packed_flags_at_08: u64,
    pub field_10: u64,
    pub total_a: u64,
    pub total_b: u64,
    pub capacity_or_margin: u64,
    pub field_30: u64,
    pub field_38: u64,
    pub lane0_total: u64,
    pub field_48: u64,
    pub field_50: u64,
    pub lane0_denominator: u64,
    pub lane1_total: u64,
    pub field_68: u64,
    pub field_70: u64,
    pub lane1_denominator: u64,
    pub _unknown_field_at_80: [u8; 32],
    pub timestamp_or_accrual_at_a0: u64,
    pub timestamp_like_at_a8: u32,
    pub _unknown_field_at_ac: u32,
}

impl Default for BoleAssetEntry {
    fn default() -> Self {
        Self {
            kind_or_flags: 0,
            packed_flags_at_08: 0,
            field_10: 0,
            total_a: 0,
            total_b: 0,
            capacity_or_margin: 0,
            field_30: 0,
            field_38: 0,
            lane0_total: 0,
            field_48: 0,
            field_50: 0,
            lane0_denominator: 0,
            lane1_total: 0,
            field_68: 0,
            field_70: 0,
            lane1_denominator: 0,
            _unknown_field_at_80: [0; 32],
            timestamp_or_accrual_at_a0: 0,
            timestamp_like_at_a8: 0,
            _unknown_field_at_ac: 0,
        }
    }
}

impl BoleAssetEntry {
    #[inline]
    pub const fn total_before_update(self) -> Option<u64> {
        self.total_a.checked_add(self.total_b)
    }

    #[inline]
    pub const fn denominator(self, slot: usize) -> u64 {
        if (slot & 1) == 0 {
            self.lane0_denominator
        } else {
            self.lane1_denominator
        }
    }

    #[inline]
    pub fn selected_total_mut(&mut self, slot: usize) -> &mut u64 {
        if (slot & 1) == 0 {
            &mut self.lane0_total
        } else {
            &mut self.lane1_total
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BoleUserConfig {
    pub header_0: u64,
    pub header_8: u64,
    pub header_10: u64,
    pub exposures: BTreeMap<u64, BoleUserExposureEntry>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BoleState {
    pub default_config: BoleUserConfig,
    pub user_overrides: BTreeMap<UserKey, BoleUserConfig>,
    pub assets: BTreeMap<u64, BoleAssetEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoleApplyDeltaReq {
    pub asset: u64,
    pub amount: u64,
    pub min_health_tier: u8,
    pub risk_mode: u8,
    pub user_key: UserKey,
    pub op_kind: u8,
    pub force_exact_amount: bool,
    pub cap_amount: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoleBorrowLendArgs {
    pub asset: u64,
    pub qty: u64,
    pub min_health_tier: u8,
    pub risk_mode: u8,
    pub user_key: UserKey,
    pub side_flag: u8,
    pub scale_down_flag: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoleUpdate {
    pub asset: u64,
    pub user_key: UserKey,
    pub asset_entry: BoleAssetEntry,
    pub user_config: BoleUserConfig,
    pub changed_amount: u64,
    pub increased_total: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoleApplyResult {
    Applied(BoleUpdate),
    Noop,
    Error(BoleStatus),
}

impl BoleApplyResult {
    #[inline]
    pub const fn is_retryable_error(&self) -> bool {
        matches!(self, Self::Error(_))
    }

    #[inline]
    pub fn changed_amount(&self) -> u64 {
        match self {
            Self::Applied(update) => update.changed_amount,
            Self::Noop | Self::Error(_) => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BoleHealthTotals {
    pub tier: u8,
    pub total_a: u64,
    pub total_b: u64,
    pub total_c: u64,
    pub total_d: u64,
    pub total_e: u64,
}

pub trait BoleRiskHooks {
    fn derive_amount(
        &mut self,
        cfg: &BoleUserConfig,
        asset: u64,
        op_kind: u8,
        cap_amount: u64,
        risk_mode: u8,
    ) -> Result<u64, BoleStatus>;

    fn validate_asset_capacity(&mut self, asset: &BoleAssetEntry) -> Result<u64, BoleStatus>;

    fn recompute_health(
        &mut self,
        cfg: &BoleUserConfig,
        asset: u64,
        risk_mode: u8,
    ) -> Result<BoleHealthTotals, BoleStatus>;

    fn sufficient_balance(
        &mut self,
        cfg: &BoleUserConfig,
        asset: &BoleAssetEntry,
        asset_id: u64,
        slot: usize,
        decreasing: bool,
    ) -> u8;

    fn validate_cross_state(
        &mut self,
        old_cfg: &BoleUserConfig,
        new_cfg: &BoleUserConfig,
        available: u64,
        asset_id: u64,
        slot: usize,
        decreasing: bool,
        asset: &BoleAssetEntry,
    ) -> u8;

    fn post_process_update(
        &mut self,
        update: &mut BoleUpdate,
        pre_total: u64,
    );

    fn address_volume_limit(&mut self, _user_key: UserKey, _asset: u64) -> Option<(u64, u64)> {
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SlotMode {
    slot: usize,
    opposite_slot: usize,
    decreasing: bool,
    round_amount_to_qty_up: bool,
    round_qty_to_amount_up: bool,
}

#[inline]
fn slot_mode(op_kind: u8) -> SlotMode {
    let shifted = if op_kind < 8 { 0x0c_u8 >> op_kind } else { 0 };
    SlotMode {
        slot: (op_kind & 1) as usize,
        opposite_slot: ((op_kind ^ 1) & 1) as usize,
        decreasing: (shifted & 1) != 0,
        round_amount_to_qty_up: ((shifted ^ op_kind ^ 1) & 1) != 0,
        round_qty_to_amount_up: (op_kind & 1) == 0,
    }
}

#[inline]
fn scale_retry_amount(amount: u64, factor: Option<f64>) -> Result<u64, BoleStatus> {
    let Some(factor) = factor else {
        return Ok(amount);
    };
    if !(0.0..=1.01).contains(&factor) {
        return Err(BoleStatus::ZeroOrUnderflow);
    }
    let scaled = (amount as f64) * factor;
    if !scaled.is_finite() {
        return Ok(u64::MAX);
    }
    if scaled <= 0.0 {
        Ok(0)
    } else if scaled >= u64::MAX as f64 {
        Ok(u64::MAX)
    } else {
        Ok(scaled as u64)
    }
}

#[inline]
fn mul_div_floor_u64(lhs: u64, rhs: u64, divisor: u128) -> Result<u64, BoleStatus> {
    if divisor == 0 {
        return Err(BoleStatus::CapExceeded);
    }
    let value = (lhs as u128)
        .checked_mul(rhs as u128)
        .ok_or(BoleStatus::Arithmetic)?
        / divisor;
    u64::try_from(value).map_err(|_| BoleStatus::Arithmetic)
}

#[inline]
fn mul_div_ceil_u64(lhs: u64, rhs: u64, divisor: u128) -> Result<u64, BoleStatus> {
    if divisor == 0 {
        return Err(BoleStatus::CapExceeded);
    }
    let product = (lhs as u128)
        .checked_mul(rhs as u128)
        .ok_or(BoleStatus::Arithmetic)?;
    let rounded = product / divisor + u128::from(product % divisor != 0);
    u64::try_from(rounded).map_err(|_| BoleStatus::Arithmetic)
}

#[inline]
fn amount_to_qty(amount: u64, denominator: u64, round_up: bool) -> Result<u64, BoleStatus> {
    if denominator == 0 {
        return Err(BoleStatus::CapExceeded);
    }
    if round_up {
        mul_div_ceil_u64(amount, PRICE_SIZE_SCALE as u64, denominator as u128)
    } else {
        mul_div_floor_u64(amount, PRICE_SIZE_SCALE as u64, denominator as u128)
    }
}

#[inline]
fn qty_to_amount(qty: u64, denominator: u64, round_up: bool) -> Result<u64, BoleStatus> {
    if round_up {
        mul_div_ceil_u64(qty, denominator, PRICE_SIZE_SCALE)
    } else {
        mul_div_floor_u64(qty, denominator, PRICE_SIZE_SCALE)
    }
}

#[inline]
fn checked_add_assign(slot: &mut u64, value: u64) -> Result<(), BoleStatus> {
    *slot = slot.checked_add(value).ok_or(BoleStatus::Arithmetic)?;
    Ok(())
}

#[inline]
fn checked_sub_assign(slot: &mut u64, value: u64) -> Result<(), BoleStatus> {
    *slot = slot.checked_sub(value).ok_or(BoleStatus::InsufficientBalance)?;
    Ok(())
}

impl BoleState {
    pub fn config_for_user(&self, user: UserKey) -> &BoleUserConfig {
        self.user_overrides
            .get(&user)
            .unwrap_or(&self.default_config)
    }

    pub fn config_for_user_mut(&mut self, user: UserKey) -> &mut BoleUserConfig {
        if self.user_overrides.contains_key(&user) {
            self.user_overrides.get_mut(&user).unwrap()
        } else {
            &mut self.default_config
        }
    }

    pub fn try_apply_user_asset_delta_with_retry<H: BoleRiskHooks>(
        &mut self,
        req: BoleApplyDeltaReq,
        hooks: &mut H,
    ) -> BoleApplyResult {
        let mut last = BoleApplyResult::Error(BoleStatus::GenericValidation);
        for factor in RETRY_FACTORS {
            let amount = if req.force_exact_amount {
                req.amount
            } else {
                match hooks.derive_amount(
                    self.config_for_user(req.user_key),
                    req.asset,
                    req.op_kind,
                    req.cap_amount,
                    req.risk_mode,
                ) {
                    Ok(amount) => amount,
                    Err(status) => return BoleApplyResult::Error(status),
                }
            };
            let amount = match scale_retry_amount(amount, factor) {
                Ok(amount) => amount,
                Err(status) => return BoleApplyResult::Error(status),
            };
            let attempt = self.try_apply_user_asset_delta_once(req, amount, hooks);
            let should_retry = !req.force_exact_amount && attempt.is_retryable_error();
            last = attempt;
            if !should_retry {
                break;
            }
        }

        if let BoleApplyResult::Applied(update) = &last {
            if update.increased_total {
                if let Some((used, limit)) = hooks.address_volume_limit(update.user_key, update.asset) {
                    if update.changed_amount.checked_add(used).map_or(true, |sum| sum > limit) {
                        return BoleApplyResult::Error(BoleStatus::InsufficientBalance);
                    }
                }
            }
        }
        last
    }

    pub fn try_apply_user_asset_delta_once<H: BoleRiskHooks>(
        &mut self,
        req: BoleApplyDeltaReq,
        amount: u64,
        hooks: &mut H,
    ) -> BoleApplyResult {
        if amount == 0 {
            return BoleApplyResult::Noop;
        }

        let Some(mut asset_entry) = self.assets.get(&req.asset).copied() else {
            return BoleApplyResult::Error(BoleStatus::GenericValidation);
        };
        let old_asset_entry = asset_entry;
        let pre_total = match old_asset_entry.total_before_update() {
            Some(total) => total,
            None => return BoleApplyResult::Error(BoleStatus::Arithmetic),
        };
        let available = match hooks.validate_asset_capacity(&old_asset_entry) {
            Ok(available) => available,
            Err(_) => return BoleApplyResult::Error(BoleStatus::GenericValidation),
        };
        let old_config = self.config_for_user(req.user_key).clone();
        let result = {
            let cfg = self.config_for_user_mut(req.user_key);
            apply_delta_to_config_and_asset(
                cfg,
                &old_config,
                &mut asset_entry,
                req,
                amount,
                available,
                pre_total,
                hooks,
            )
        };

        match result {
            Ok(mut update) => {
                hooks.post_process_update(&mut update, pre_total);
                let post_total = match update.asset_entry.total_before_update() {
                    Some(total) => total,
                    None => return BoleApplyResult::Error(BoleStatus::Arithmetic),
                };
                let increased_total = post_total >= pre_total;
                let observed_delta = if increased_total {
                    post_total - pre_total
                } else {
                    pre_total - post_total
                };
                if observed_delta != update.changed_amount {
                    return BoleApplyResult::Error(BoleStatus::CrossStateMismatch);
                }
                if req.op_kind.wrapping_sub(1) < 2 && req.cap_amount < update.changed_amount {
                    return BoleApplyResult::Error(BoleStatus::CapExceeded);
                }
                update.increased_total = increased_total;
                self.assets.insert(req.asset, update.asset_entry);
                BoleApplyResult::Applied(update)
            }
            Err(status) => BoleApplyResult::Error(status),
        }
    }

    pub fn apply_user_wei_delta_two_tiers<H: BoleRiskHooks>(
        &mut self,
        req: BoleApplyDeltaReq,
        hooks: &mut H,
    ) -> BoleApplyResult {
        self.try_apply_user_asset_delta_with_retry(req, hooks)
    }

    pub fn simulate_user_wei_capacity_three_tiers<H: BoleRiskHooks>(
        &self,
        req: BoleApplyDeltaReq,
        hooks: &mut H,
    ) -> BoleApplyResult {
        let mut scratch = self.clone();
        scratch.try_apply_user_asset_delta_with_retry(req, hooks)
    }

    pub fn apply_user_wei_delta_direct<H: BoleRiskHooks>(
        &mut self,
        req: BoleApplyDeltaReq,
        hooks: &mut H,
    ) -> BoleApplyResult {
        let amount = if req.force_exact_amount {
            req.amount
        } else {
            match hooks.derive_amount(
                self.config_for_user(req.user_key),
                req.asset,
                req.op_kind,
                req.cap_amount,
                req.risk_mode,
            ) {
                Ok(amount) => amount,
                Err(status) => return BoleApplyResult::Error(status),
            }
        };
        self.try_apply_user_asset_delta_once(req, amount, hooks)
    }

    pub fn apply_borrow_lend_with_retry_mode0<H: BoleRiskHooks>(
        &mut self,
        mut args: BoleBorrowLendArgs,
        hooks: &mut H,
    ) -> BoleApplyResult {
        args.risk_mode = 0;
        self.apply_borrow_lend_with_retry(args, hooks)
    }

    pub fn apply_borrow_lend_with_retry_mode3<H: BoleRiskHooks>(
        &mut self,
        mut args: BoleBorrowLendArgs,
        hooks: &mut H,
    ) -> BoleApplyResult {
        args.risk_mode = 3;
        self.apply_borrow_lend_with_retry(args, hooks)
    }

    pub fn apply_borrow_lend_with_retry<H: BoleRiskHooks>(
        &mut self,
        args: BoleBorrowLendArgs,
        hooks: &mut H,
    ) -> BoleApplyResult {
        let mut last = BoleApplyResult::Error(BoleStatus::GenericValidation);
        for factor in RETRY_FACTORS {
            let qty = match scale_retry_amount(args.qty, factor) {
                Ok(qty) => qty,
                Err(status) => return BoleApplyResult::Error(status),
            };
            let attempt = self.apply_borrow_lend_inner(args, qty, hooks);
            let should_retry = attempt.is_retryable_error();
            last = attempt;
            if !should_retry {
                break;
            }
        }
        last
    }

    pub fn apply_borrow_lend_inner<H: BoleRiskHooks>(
        &mut self,
        args: BoleBorrowLendArgs,
        qty: u64,
        hooks: &mut H,
    ) -> BoleApplyResult {
        if qty == 0 {
            return BoleApplyResult::Noop;
        }
        let Some(mut asset_entry) = self.assets.get(&args.asset).copied() else {
            return BoleApplyResult::Error(BoleStatus::GenericValidation);
        };
        let pre_total = match asset_entry.total_before_update() {
            Some(total) => total,
            None => return BoleApplyResult::Error(BoleStatus::Arithmetic),
        };
        let available = match hooks.validate_asset_capacity(&asset_entry) {
            Ok(available) => available,
            Err(_) => return BoleApplyResult::Error(BoleStatus::GenericValidation),
        };
        let req = BoleApplyDeltaReq {
            asset: args.asset,
            amount: qty,
            min_health_tier: args.min_health_tier,
            risk_mode: args.risk_mode,
            user_key: args.user_key,
            op_kind: args.side_flag,
            force_exact_amount: true,
            cap_amount: u64::MAX,
        };
        let old_config = self.config_for_user(args.user_key).clone();
        let result = {
            let cfg = self.config_for_user_mut(args.user_key);
            apply_borrow_lend_to_config_and_asset(
                cfg,
                &old_config,
                &mut asset_entry,
                req,
                qty,
                available,
                pre_total,
                args.scale_down_flag,
                hooks,
            )
        };
        match result {
            Ok(mut update) => {
                hooks.post_process_update(&mut update, pre_total);
                self.assets.insert(args.asset, update.asset_entry);
                BoleApplyResult::Applied(update)
            }
            Err(status) => BoleApplyResult::Error(status),
        }
    }
}

fn apply_delta_to_config_and_asset<H: BoleRiskHooks>(
    cfg: &mut BoleUserConfig,
    old_config: &BoleUserConfig,
    asset_entry: &mut BoleAssetEntry,
    req: BoleApplyDeltaReq,
    amount: u64,
    available: u64,
    pre_total: u64,
    hooks: &mut H,
) -> Result<BoleUpdate, BoleStatus> {
    let mode = slot_mode(req.op_kind);
    let denominator = asset_entry.denominator(mode.slot);
    let mut qty = amount_to_qty(amount, denominator, mode.round_amount_to_qty_up)?;
    let entry = cfg.exposures.entry(req.asset).or_default();
    let lane = entry.lane_mut(mode.slot);
    let original_lane_qty = lane.quote_or_scaled_qty;
    let changed_amount;

    if mode.decreasing {
        if original_lane_qty <= qty {
            qty = original_lane_qty;
            changed_amount = qty_to_amount(qty, denominator, mode.round_qty_to_amount_up)?;
            if qty != 0 && changed_amount == 0 {
                return Err(BoleStatus::ZeroOrUnderflow);
            }
        } else {
            changed_amount = amount;
        }
        checked_sub_assign(&mut lane.quote_or_scaled_qty, qty)?;
        checked_sub_assign(asset_entry.selected_total_mut(mode.slot), qty)?;
        checked_add_assign(&mut asset_entry.total_a, changed_amount)?;
    } else {
        checked_add_assign(&mut lane.quote_or_scaled_qty, qty)?;
        checked_add_assign(asset_entry.selected_total_mut(mode.slot), qty)?;
        checked_sub_assign(&mut asset_entry.total_a, amount)?;
        changed_amount = amount;
    }

    let health = hooks.recompute_health(cfg, req.asset, req.risk_mode)?;
    if health.tier < req.min_health_tier {
        return Err(BoleStatus::HealthTierFailed);
    }
    BoleStatus::from_balance_sentinel(hooks.sufficient_balance(
        cfg,
        asset_entry,
        req.asset,
        mode.slot,
        mode.decreasing,
    ))?;
    BoleStatus::from_cross_state_sentinel(hooks.validate_cross_state(
        old_config,
        cfg,
        available,
        req.asset,
        mode.opposite_slot,
        mode.decreasing,
        asset_entry,
    ))?;

    let post_total = asset_entry
        .total_before_update()
        .ok_or(BoleStatus::Arithmetic)?;
    let increased_total = post_total >= pre_total;
    Ok(BoleUpdate {
        asset: req.asset,
        user_key: req.user_key,
        asset_entry: *asset_entry,
        user_config: cfg.clone(),
        changed_amount,
        increased_total,
    })
}

fn apply_borrow_lend_to_config_and_asset<H: BoleRiskHooks>(
    cfg: &mut BoleUserConfig,
    old_config: &BoleUserConfig,
    asset_entry: &mut BoleAssetEntry,
    req: BoleApplyDeltaReq,
    qty: u64,
    available: u64,
    pre_total: u64,
    scale_down: bool,
    hooks: &mut H,
) -> Result<BoleUpdate, BoleStatus> {
    let slot = ((req.op_kind ^ 1) & 1) as usize;
    let entry = cfg.exposures.entry(req.asset).or_default();
    let lane = entry.lane_mut(slot);
    let original_qty = lane.quote_or_scaled_qty;
    let applied_qty = if scale_down {
        let market_qty = *asset_entry.selected_total_mut(slot);
        if market_qty == 0 {
            return Err(BoleStatus::CapExceeded);
        }
        mul_div_floor_u64(original_qty, qty, market_qty as u128)?
    } else {
        qty
    };

    if scale_down {
        lane.quote_or_scaled_qty = applied_qty;
    } else {
        checked_add_assign(&mut lane.quote_or_scaled_qty, applied_qty)?;
    }
    checked_add_assign(asset_entry.selected_total_mut(slot), applied_qty)?;

    let health = hooks.recompute_health(cfg, req.asset, req.risk_mode)?;
    if health.tier < req.min_health_tier {
        return Err(BoleStatus::HealthTierFailed);
    }
    BoleStatus::from_balance_sentinel(hooks.sufficient_balance(
        cfg,
        asset_entry,
        req.asset,
        slot,
        scale_down,
    ))?;
    BoleStatus::from_cross_state_sentinel(hooks.validate_cross_state(
        old_config,
        cfg,
        available,
        req.asset,
        slot,
        scale_down,
        asset_entry,
    ))?;

    let post_total = asset_entry
        .total_before_update()
        .ok_or(BoleStatus::Arithmetic)?;
    Ok(BoleUpdate {
        asset: req.asset,
        user_key: req.user_key,
        asset_entry: *asset_entry,
        user_config: cfg.clone(),
        changed_amount: original_qty,
        increased_total: post_total >= pre_total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct AcceptHooks;

    impl BoleRiskHooks for AcceptHooks {
        fn derive_amount(
            &mut self,
            _cfg: &BoleUserConfig,
            _asset: u64,
            _op_kind: u8,
            cap_amount: u64,
            _risk_mode: u8,
        ) -> Result<u64, BoleStatus> {
            Ok(cap_amount)
        }

        fn validate_asset_capacity(&mut self, _asset: &BoleAssetEntry) -> Result<u64, BoleStatus> {
            Ok(u64::MAX)
        }

        fn recompute_health(
            &mut self,
            _cfg: &BoleUserConfig,
            _asset: u64,
            _risk_mode: u8,
        ) -> Result<BoleHealthTotals, BoleStatus> {
            Ok(BoleHealthTotals { tier: u8::MAX, ..BoleHealthTotals::default() })
        }

        fn sufficient_balance(
            &mut self,
            _cfg: &BoleUserConfig,
            _asset: &BoleAssetEntry,
            _asset_id: u64,
            _slot: usize,
            _decreasing: bool,
        ) -> u8 {
            STATUS_BALANCE_OK_SENTINEL
        }

        fn validate_cross_state(
            &mut self,
            _old_cfg: &BoleUserConfig,
            _new_cfg: &BoleUserConfig,
            _available: u64,
            _asset_id: u64,
            _slot: usize,
            _decreasing: bool,
            _asset: &BoleAssetEntry,
        ) -> u8 {
            STATUS_CROSS_STATE_OK_SENTINEL
        }

        fn post_process_update(&mut self, _update: &mut BoleUpdate, _pre_total: u64) {}
    }

    #[test]
    fn retry_factor_scales_like_recovered_double_path() {
        assert_eq!(scale_retry_amount(1000, None), Ok(1000));
        assert_eq!(scale_retry_amount(1000, Some(0.99)), Ok(990));
        assert_eq!(scale_retry_amount(1000, Some(0.90)), Ok(900));
        assert_eq!(scale_retry_amount(1000, Some(1.02)), Err(BoleStatus::ZeroOrUnderflow));
    }

    #[test]
    fn zero_amount_is_noop() {
        let mut state = BoleState::default();
        let mut hooks = AcceptHooks;
        let req = BoleApplyDeltaReq {
            asset: 1,
            amount: 0,
            min_health_tier: 0,
            risk_mode: 0,
            user_key: UserKey([0; 20]),
            op_kind: 0,
            force_exact_amount: true,
            cap_amount: u64::MAX,
        };
        assert_eq!(state.try_apply_user_asset_delta_once(req, 0, &mut hooks), BoleApplyResult::Noop);
    }
}
