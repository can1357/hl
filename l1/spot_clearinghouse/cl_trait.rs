

use crate::spot_meta::{Address, Px, SpotMeta, Token, Wei};

use super::types::{
    SpotBalance, SpotClearinghouseState, SpotExecContext, SpotFillLedgerSide,
    SpotFillPartySettlement, SpotFillSettlement, SpotOrder, SpotOrderAction, SpotOutcome,
    SpotTokenClass,
};

pub const SPOT_OUTCOME_SUCCESS: u16 = 390;
pub const SPOT_OUTCOME_INTERNAL_DIRECT_FAILED: u16 = 391;
pub const SPOT_OUTCOME_REJECTED_WITH_CODE: u16 = 225;
pub const SPOT_REJECT_DIRECT_REPLACE_FAILED: u8 = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SpotSide {
    Bid = 0,
    Ask = 1,
}

impl SpotSide {
    #[inline]
    pub const fn from_bit(bit: u8) -> Self {
        if bit & 1 == 0 { Self::Bid } else { Self::Ask }
    }

    #[inline]
    pub const fn as_index(self) -> usize {
        self as usize
    }

    #[inline]
    pub const fn opposite(self) -> Self {
        match self {
            Self::Bid => Self::Ask,
            Self::Ask => Self::Bid,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FillQuantityAccumulator {
    /// Quantity added to the first optional fill leg, when the leg exists.
    pub leg0_present: bool,
    pub leg0_wei: Wei,
    /// Quantity added to the second optional fill leg, when the leg exists.
    pub leg1_present: bool,
    pub leg1_wei: Wei,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SpotExecutionFlavor {
    pub batch_input: bool,
    pub perp_dex_state: bool,
    pub use_main_book_for_replace: bool,
}

/// Interface used by the book/exchange code when a resting or matched spot order has to
/// mutate clearinghouse balances. The binary calls the first two methods through table
/// slots referenced from the book insert code; the four execute wrappers below are thin
/// monomorphized adapters around the same direct/replace order path.
pub trait SpotClearinghouseCl {
    fn spot_state(&self) -> &SpotClearinghouseState;
    fn spot_state_mut(&mut self) -> &mut SpotClearinghouseState;
    fn spot_meta(&self) -> &SpotMeta;

    fn settle_matched_spot_fill(
        &mut self,
        taker_side: SpotSide,
        fill: &mut SpotFillSettlement,
        ledger_out: &mut Vec<SpotFillLedgerSide>,
    ) -> bool;

    fn reserve_resting_spot_order(
        &mut self,
        side: SpotSide,
        raw_accounting_key: u32,
        order: &mut SpotOrder,
        ledger_out: &mut Vec<SpotFillLedgerSide>,
    ) -> bool;
}

pub fn settle_matched_spot_fill(
    state: &mut SpotClearinghouseState,
    meta: &SpotMeta,
    taker_side: SpotSide,
    fill: &mut SpotFillSettlement,
    ledger_out: &mut Vec<SpotFillLedgerSide>,
) -> bool {
    let Some(spot_info) = state.spot_infos.get(fill.spot as usize) else {
        panic!("spot index in bounds");
    };
    let [base_token, quote_token] = spot_info.tokens;

    let Some(base_wei) = meta.spot_base_token_wei_for_fill(fill.spot, fill.px, fill.sz) else {
        return false;
    };
    let Some(quote_wei) = fill.sz.checked_mul(fill.px) else {
        return false;
    };

    let maker_side = taker_side.opposite();
    let debit = [
        DebitLeg { user: fill.party0.user, token: if taker_side == SpotSide::Bid { quote_token } else { base_token }, wei: if taker_side == SpotSide::Bid { quote_wei } else { base_wei } },
        DebitLeg { user: fill.party1.user, token: if maker_side == SpotSide::Bid { quote_token } else { base_token }, wei: if maker_side == SpotSide::Bid { quote_wei } else { base_wei } },
    ];

    for leg in debit {
        if !balance_covers(state, leg.user, leg.token, leg.wei) {
            return false;
        }
    }

    let mut totals = [0u64; 4];
    let tokens = [base_token, quote_token];
    settle_one_party(
        state,
        meta,
        &tokens,
        taker_side,
        fill.px,
        fill.ledger_sequence_or_time,
        true,
        fill.side_flag == taker_side.as_index() as u8,
        &mut fill.party0,
        ledger_out,
        &mut totals,
    );
    settle_one_party(
        state,
        meta,
        &tokens,
        maker_side,
        fill.px,
        fill.ledger_sequence_or_time,
        false,
        fill.side_flag == maker_side.as_index() as u8,
        &mut fill.party1,
        ledger_out,
        &mut totals,
    );

    // The recovered code updates aggregate token deltas after both parties have been
    // applied. When a subtraction underflows it logs and clamps rather than wrapping.
    update_supply_delta(state, base_token, totals[0], totals[2]);
    update_supply_delta(state, quote_token, totals[1], totals[3]);
    true
}

pub fn reserve_resting_spot_order(
    state: &mut SpotClearinghouseState,
    meta: &SpotMeta,
    side: SpotSide,
    raw_accounting_key: u32,
    order: &mut SpotOrder,
    ledger_out: &mut Vec<SpotFillLedgerSide>,
) -> bool {
    if order.sz == 0 || order.user == Address::ZERO {
        return false;
    }

    let Some(spot_info) = state.spot_infos.get(order.spot as usize) else {
        panic!("spot index in bounds");
    };
    let [base_token, quote_token] = spot_info.tokens;
    let Some(base_wei) = meta.spot_base_token_wei_for_fill(order.spot, order.limit_px, order.sz) else {
        return false;
    };
    let Some(quote_wei) = order.sz.checked_mul(order.limit_px) else {
        return false;
    };

    let (reserved_token, reserved_wei) = match side {
        SpotSide::Bid => (quote_token, quote_wei),
        SpotSide::Ask => (base_token, base_wei),
    };

    let balance = balance_entry_mut(state, order.user, reserved_token);
    if balance.total < reserved_wei || balance.available() < reserved_wei {
        return false;
    }
    balance.hold = balance.hold.checked_add(reserved_wei).expect("spot balance hold overflow");

    state.user_token_index.entry(order.user).or_default().insert(reserved_token);

    let class = classify_token(state, meta, reserved_token);
    let quote_status = state.quote_token_class.get(&quote_token).copied().unwrap_or_default();
    let ledger = SpotFillLedgerSide::resting_order_reserve(
        order.user,
        raw_accounting_key,
        order.spot,
        side,
        class,
        quote_status,
        order.limit_px,
        order.sz,
        reserved_token,
        reserved_wei,
    );

    let mut accum = [0u64; 4];
    accumulate_fill_side_quantities(&mut accum, [base_token, quote_token], side, order.limit_px, &ledger, meta);
    order.reserved_token = Some(reserved_token);
    order.reserved_wei = reserved_wei;
    order.last_reserve_ledger = Some(ledger.clone());
    ledger_out.push(ledger);

    update_supply_delta(state, base_token, accum[0], accum[2]);
    update_supply_delta(state, quote_token, accum[1], accum[3]);
    true
}

pub fn accumulate_fill_side_quantities(
    accum: &mut [Wei; 4],
    spot_tokens: [Token; 2],
    side: SpotSide,
    px_or_divisor: Px,
    fill: &SpotFillLedgerSide,
    meta: &SpotMeta,
) -> FillQuantityAccumulator {
    let mut out = FillQuantityAccumulator::default();

    if let Some(mut leg0) = fill.leg0_wei {
        if side == SpotSide::Bid {
            accum[1] = checked_add(accum[1], leg0);
        } else {
            leg0 = meta
                .convert_spot_token_wei(leg0, spot_tokens[0], px_or_divisor, false)
                .expect("spot token conversion succeeds");
            accum[0] = checked_add(accum[0], leg0);
        }
        out.leg0_present = true;
        out.leg0_wei = leg0;
    }

    if let Some(mut leg1) = fill.leg1_wei {
        if side == SpotSide::Ask {
            leg1 = meta
                .convert_spot_token_wei(leg1, spot_tokens[0], px_or_divisor, false)
                .expect("spot token conversion succeeds");
            accum[2] = checked_add(accum[2], leg1);
        } else {
            accum[3] = checked_add(accum[3], leg1);
        }
        out.leg1_present = true;
        out.leg1_wei = leg1;
    }

    let side_slot = 2 + side.as_index();
    if let Some(fee) = fill.fee_wei {
        accum[side_slot] = checked_add(accum[side_slot], fee);
    }
    if let Some(rebate) = fill.rebate_wei {
        accum[side_slot] = checked_add(accum[side_slot], rebate);
    }
    if let Some(extra) = fill.aligned_quote_wei {
        accum[side_slot] = checked_add(accum[side_slot], extra);
    }

    out
}

pub fn execute_main_spot_user_order<C: SpotOrderExecutor>(
    executor: &mut C,
    order: &SpotOrder,
    action: &SpotOrderAction,
    ctx: &SpotExecContext,
) -> SpotOutcome {
    execute_spot_order_adapter(
        executor,
        order,
        action,
        ctx,
        SpotExecutionFlavor { batch_input: false, perp_dex_state: false, use_main_book_for_replace: false },
    )
}

pub fn execute_perp_dex_batch_order<C: SpotOrderExecutor>(
    executor: &mut C,
    order: &SpotOrder,
    action: &SpotOrderAction,
    ctx: &SpotExecContext,
) -> SpotOutcome {
    execute_spot_order_adapter(
        executor,
        order,
        action,
        ctx,
        SpotExecutionFlavor { batch_input: true, perp_dex_state: true, use_main_book_for_replace: true },
    )
}

pub fn execute_perp_dex_user_order<C: SpotOrderExecutor>(
    executor: &mut C,
    order: &SpotOrder,
    action: &SpotOrderAction,
    ctx: &SpotExecContext,
) -> SpotOutcome {
    execute_spot_order_adapter(
        executor,
        order,
        action,
        ctx,
        SpotExecutionFlavor { batch_input: false, perp_dex_state: true, use_main_book_for_replace: true },
    )
}

pub fn execute_main_spot_batch_order<C: SpotOrderExecutor>(
    executor: &mut C,
    order: &SpotOrder,
    action: &SpotOrderAction,
    ctx: &SpotExecContext,
) -> SpotOutcome {
    execute_spot_order_adapter(
        executor,
        order,
        action,
        ctx,
        SpotExecutionFlavor { batch_input: true, perp_dex_state: false, use_main_book_for_replace: false },
    )
}

pub trait SpotOrderExecutor {
    fn state(&self) -> &SpotClearinghouseState;
    fn state_mut(&mut self) -> &mut SpotClearinghouseState;
    fn preprocess_main_spot_order(&mut self, order: &SpotOrder, action: &SpotOrderAction) -> SpotOutcome;
    fn preprocess_perp_dex_order(&mut self, order: &SpotOrder, action: &SpotOrderAction) -> SpotOutcome;
    fn execute_direct_against_book(
        &mut self,
        order: &SpotOrder,
        action: &SpotOrderAction,
        opposite_book: u64,
        ctx: &SpotExecContext,
        from_wrapper_fallback: bool,
    ) -> SpotOutcome;
    fn replace_order_after_existing_lookup_main_book(
        &mut self,
        order: &SpotOrder,
        action: &SpotOrderAction,
        ctx: &SpotExecContext,
    ) -> SpotOutcome;
    fn replace_order_after_existing_lookup_alt_book(
        &mut self,
        order: &SpotOrder,
        action: &SpotOrderAction,
        ctx: &SpotExecContext,
    ) -> SpotOutcome;
}

pub fn execute_spot_order_adapter<C: SpotOrderExecutor>(
    executor: &mut C,
    order: &SpotOrder,
    action: &SpotOrderAction,
    ctx: &SpotExecContext,
    flavor: SpotExecutionFlavor,
) -> SpotOutcome {
    let preprocess = if ctx.tag > 1 {
        SpotOutcome::direct_fallback(false)
    } else if flavor.perp_dex_state {
        executor.preprocess_perp_dex_order(order, action)
    } else {
        executor.preprocess_main_spot_order(order, action)
    };

    if ctx.tag > 1 || preprocess.is_direct_fallback() || preprocess.status() == 3 {
        let opposite_book = executor
            .state()
            .spot_books
            .get(order.spot as usize)
            .expect("spot book index in bounds")
            .book_for_side(order.side.opposite());
        return executor.execute_direct_against_book(
            order,
            action,
            opposite_book,
            &ctx.with_direct_tag(2),
            preprocess.direct_flag(),
        );
    }

    let mut replace_ctx = ctx.clone_for_replace(order, action, preprocess);
    replace_ctx.normalize_existing_order_bits();

    let outcome = if flavor.use_main_book_for_replace {
        executor.replace_order_after_existing_lookup_main_book(order, action, &replace_ctx)
    } else {
        executor.replace_order_after_existing_lookup_alt_book(order, action, &replace_ctx)
    };

    if outcome.status_code() == SPOT_OUTCOME_INTERNAL_DIRECT_FAILED {
        executor.state_mut().direct_execute_guard = false;
        return SpotOutcome::rejected_with_code(
            SPOT_OUTCOME_REJECTED_WITH_CODE,
            SPOT_REJECT_DIRECT_REPLACE_FAILED,
        );
    }

    outcome
}

#[derive(Clone, Copy)]
struct DebitLeg {
    user: Address,
    token: Token,
    wei: Wei,
}

fn settle_one_party(
    state: &mut SpotClearinghouseState,
    meta: &SpotMeta,
    tokens: &[Token; 2],
    side: SpotSide,
    px: Px,
    ledger_sequence_or_time: u64,
    is_taker: bool,
    is_aggressing_side: bool,
    party: &mut SpotFillPartySettlement,
    ledger_out: &mut Vec<SpotFillLedgerSide>,
    totals: &mut [Wei; 4],
) {
    let receive_token = if side == SpotSide::Bid { tokens[0] } else { tokens[1] };
    let debit_token = if side == SpotSide::Bid { tokens[1] } else { tokens[0] };
    let token_class = classify_token(state, meta, receive_token);
    let quote_class = state.quote_token_class.get(&tokens[1]).copied().unwrap_or_default();

    let ledger_side = SpotFillLedgerSide::matched_fill(
        party.user,
        side,
        token_class,
        quote_class,
        ledger_sequence_or_time,
        is_taker,
        is_aggressing_side,
        party.raw_accounting_key,
        party.pre_fill_snapshot,
    );

    let added = accumulate_fill_side_quantities(totals, *tokens, side, px, &ledger_side, meta);
    let receive_delta = if added.leg0_present { added.leg0_wei } else { 0 };
    let debit_delta = if added.leg1_present { added.leg1_wei } else { 0 };

    apply_balance_delta(state, party.user, receive_token, receive_delta, 0);
    apply_balance_delta(state, party.user, debit_token, 0, debit_delta);
    state.user_token_index.entry(party.user).or_default().insert(receive_token);
    state.user_token_index.entry(party.user).or_default().insert(debit_token);

    party.post_balance_a = state.user_balances.get(&party.user).and_then(|m| m.get(&receive_token)).copied().unwrap_or_default();
    party.post_balance_b = state.user_balances.get(&party.user).and_then(|m| m.get(&debit_token)).copied().unwrap_or_default();
    ledger_out.push(ledger_side);
}

#[inline]
fn balance_covers(state: &SpotClearinghouseState, user: Address, token: Token, wei: Wei) -> bool {
    if wei == 0 {
        return true;
    }
    state
        .user_balances
        .get(&user)
        .and_then(|by_token| by_token.get(&token))
        .is_some_and(|balance| balance.available() >= wei)
}

#[inline]
fn balance_entry_mut(state: &mut SpotClearinghouseState, user: Address, token: Token) -> &mut SpotBalance {
    state
        .user_balances
        .entry(user)
        .or_default()
        .entry(token)
        .or_default()
}

fn apply_balance_delta(
    state: &mut SpotClearinghouseState,
    user: Address,
    credit_token: Token,
    credit_wei: Wei,
    debit_wei: Wei,
) {
    let balance = balance_entry_mut(state, user, credit_token);
    if debit_wei != 0 {
        assert!(balance.total >= debit_wei, "spot balance underflow");
        balance.total -= debit_wei;
        balance.hold = balance.hold.saturating_sub(debit_wei);
    }
    if credit_wei != 0 {
        balance.total = checked_add(balance.total, credit_wei);
    }
}

fn classify_token(state: &SpotClearinghouseState, meta: &SpotMeta, token: Token) -> SpotTokenClass {
    if state.liquid_base_tokens.contains(&token) {
        SpotTokenClass::LiquidBase
    } else if meta.token_has_usdc_pair(token) {
        SpotTokenClass::HasUsdcPair
    } else {
        SpotTokenClass::Other
    }
}

fn update_supply_delta(state: &mut SpotClearinghouseState, token: Token, before: Wei, after: Wei) {
    if before >= after {
        let delta = before - after;
        let entry = state.token_supply_deltas.entry(token).or_default();
        *entry = entry.saturating_sub(delta);
    } else {
        let delta = after - before;
        let entry = state.token_supply_deltas.entry(token).or_default();
        *entry = entry.saturating_add(delta);
    }
}

#[inline]
fn checked_add(lhs: Wei, rhs: Wei) -> Wei {
    lhs.checked_add(rhs).expect("spot wei addition overflow")
}
