#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::spot_meta::{self, SpotMeta};

use super::types::{
    Address, AlignedQuoteTokenInfo, QuoteTokenStatus, SpotClearinghouseError,
    SpotClearinghouseState, SpotInfo, SpotMetaState, SpotPosition, SpotTokenBalance, Time, Token,
    TokenInfo, Wei,
};

pub const STATUS_OK: u16 = 390;
pub const STATUS_ERROR: u16 = 250;
pub const MAX_PROPORTIONAL_FACTOR: f64 = 1.01;

#[derive(Clone, Debug, Default)]
pub struct SpotClearinghouse {
    pub meta: SpotMeta,
    pub state: SpotClearinghouseState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExistingTokenBalanceRow {
    pub user: Address,
    pub wei: Wei,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExistingTokenDistribution {
    pub rows: Vec<ExistingTokenBalanceRow>,
    pub total_wei: Wei,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpotClearinghouseStatus {
    pub code: u16,
    pub message: Option<String>,
}

impl SpotClearinghouseStatus {
    #[inline]
    pub const fn ok() -> Self {
        Self { code: STATUS_OK, message: None }
    }

    #[inline]
    pub fn error(message: impl Into<String>) -> Self {
        Self { code: STATUS_ERROR, message: Some(message.into()) }
    }

    #[inline]
    pub const fn is_ok(&self) -> bool {
        self.code == STATUS_OK
    }
}

impl SpotClearinghouse {
    pub fn new(meta: SpotMeta) -> Self {
        let state = SpotClearinghouseState {
            meta: snapshot_spot_meta(&meta),
            ..SpotClearinghouseState::default()
        };
        Self { meta, state }
    }

    #[inline]
    pub fn spot_state(&self) -> &SpotClearinghouseState {
        &self.state
    }

    #[inline]
    pub fn spot_state_mut(&mut self) -> &mut SpotClearinghouseState {
        &mut self.state
    }

    #[inline]
    pub fn spot_meta(&self) -> &SpotMeta {
        &self.meta
    }

    pub fn refresh_meta_snapshot(&mut self) {
        self.state.meta = snapshot_spot_meta(&self.meta);
    }

    pub fn balance(&self, user: Address, token: Token) -> SpotTokenBalance {
        self.state.balance_entry(user, token)
    }

    pub fn position(&self, user: Address, token: Token) -> SpotPosition {
        self.state.position(user, token)
    }

    pub fn credit_user_token(
        &mut self,
        user: Address,
        token: Token,
        amount: Wei,
    ) -> Result<(), SpotClearinghouseError> {
        self.state.credit_user_token(user, token, amount).map(|_| ())
    }

    pub fn debit_user_spot_balance(
        &mut self,
        user: Address,
        token: Token,
        amount: Wei,
    ) -> Result<Wei, SpotClearinghouseError> {
        self.state.debit_user_spot_balance(user, token, amount)
    }

    pub fn set_balance(&mut self, user: Address, token: Token, balance: SpotTokenBalance) {
        self.state.user_token_index.entry(user).or_default().insert(token);
        self.state.user_balances.entry(user).or_default().insert(token, balance);
    }

    pub fn users_with_token(&self, token: Token) -> Vec<Address> {
        let mut users = Vec::new();
        for (user, tokens) in &self.state.user_token_index {
            if tokens.contains(&token) {
                users.push(*user);
            }
        }
        users
    }

    pub fn existing_token_rows_for_users(
        &self,
        token: Token,
        users: impl IntoIterator<Item = Address>,
    ) -> Vec<ExistingTokenBalanceRow> {
        let mut rows = Vec::new();
        for user in users {
            let wei = self.balance(user, token).total;
            if wei != 0 {
                rows.push(ExistingTokenBalanceRow { user, wei });
            }
        }
        rows
    }

    pub fn distribute_existing_token_balances(
        &self,
        rows: Vec<ExistingTokenBalanceRow>,
        target_wei_to_distribute: Wei,
        minimum_marginal_wei: Wei,
        reduction_factor: f64,
    ) -> Result<ExistingTokenDistribution, SpotClearinghouseStatus> {
        distribute_existing_token_balances(
            rows,
            target_wei_to_distribute,
            minimum_marginal_wei,
            reduction_factor,
        )
    }
}

/// Recovered proportional distribution used when a token genesis references
/// existing token balances.
///
/// The hot closure walks 32-byte address/wei rows in place. For every source row
/// it computes `row_wei / source_total * target_total`, asserts that the ratio is
/// in `0.0..=1.01`, filters rows below the caller-provided marginal threshold,
/// and fails with status 250 if the accepted marginal total overflows.
pub fn distribute_existing_token_balances(
    rows: Vec<ExistingTokenBalanceRow>,
    target_wei_to_distribute: Wei,
    minimum_marginal_wei: Wei,
    reduction_factor: f64,
) -> Result<ExistingTokenDistribution, SpotClearinghouseStatus> {
    let source_total = checked_sum_existing_rows(&rows).ok_or_else(|| {
        SpotClearinghouseStatus::error("total balance of token is zero")
    })?;
    if source_total == 0 {
        return Err(SpotClearinghouseStatus::error("total balance of token is zero"));
    }

    let mut accepted = Vec::with_capacity(rows.len());
    let mut accepted_total = 0u64;

    for row in rows {
        let factor = (row.wei as f64) / (source_total as f64);
        assert!((0.0..=MAX_PROPORTIONAL_FACTOR).contains(&factor));

        let marginal_wei = saturating_f64_to_u64((target_wei_to_distribute as f64) * factor);
        if marginal_wei < minimum_marginal_wei {
            continue;
        }

        accepted_total = accepted_total.checked_add(marginal_wei).ok_or_else(|| {
            SpotClearinghouseStatus::error(format!(
                "error while computing existing token balances total_wei={accepted_total} marginal_wei={marginal_wei}"
            ))
        })?;
        accepted.push(ExistingTokenBalanceRow { wei: marginal_wei, ..row });
    }

    if accepted.is_empty() {
        return Err(SpotClearinghouseStatus::error("no user has wei after distributing"));
    }

    normalize_existing_distribution(
        &mut accepted,
        &mut accepted_total,
        target_wei_to_distribute,
        reduction_factor,
    )?;

    Ok(ExistingTokenDistribution { rows: accepted, total_wei: accepted_total })
}

fn normalize_existing_distribution(
    rows: &mut [ExistingTokenBalanceRow],
    current_total: &mut Wei,
    target_wei_to_distribute: Wei,
    reduction_factor: f64,
) -> Result<(), SpotClearinghouseStatus> {
    if *current_total < target_wei_to_distribute {
        let remainder = target_wei_to_distribute - *current_total;
        rows[0].wei = rows[0].wei.checked_add(remainder).ok_or_else(|| {
            SpotClearinghouseStatus::error("BUG: distributing to existing token final_allocation_check overflow")
        })?;
        *current_total = target_wei_to_distribute;
        return Ok(());
    }

    if *current_total > target_wei_to_distribute {
        let mut excess = *current_total - target_wei_to_distribute;
        if (0.0..=MAX_PROPORTIONAL_FACTOR).contains(&reduction_factor) {
            for row in rows.iter_mut() {
                if excess == 0 {
                    break;
                }
                let maximum_row_reduction = saturating_f64_to_u64((row.wei as f64) * reduction_factor).min(row.wei);
                let reduction = maximum_row_reduction.min(excess);
                row.wei -= reduction;
                excess -= reduction;
            }
        }
        if excess != 0 {
            return Err(SpotClearinghouseStatus::error(format!(
                "could not distribute remainder={excess} to match exactly"
            )));
        }
        *current_total = target_wei_to_distribute;
    }

    let final_total = checked_sum_existing_rows(rows).ok_or_else(|| {
        SpotClearinghouseStatus::error("BUG: distributing to existing token final_allocation_check overflow")
    })?;
    if final_total != target_wei_to_distribute {
        return Err(SpotClearinghouseStatus::error(format!(
            "BUG: distributing to existing token final_allocation_check={final_total} target_wei_to_distribute={target_wei_to_distribute}"
        )));
    }
    *current_total = final_total;
    Ok(())
}

fn checked_sum_existing_rows(rows: &[ExistingTokenBalanceRow]) -> Option<Wei> {
    let mut total = 0u64;
    for row in rows {
        total = total.checked_add(row.wei)?;
    }
    Some(total)
}

pub fn snapshot_spot_meta(meta: &SpotMeta) -> SpotMetaState {
    SpotMetaState {
        spot_infos: meta
            .spot_infos
            .iter()
            .map(|spot| SpotInfo { base_token: spot.tokens[0], quote_token: spot.tokens[1] })
            .collect(),
        token_infos: meta
            .token_infos
            .iter()
            .enumerate()
            .map(|(token, info)| snapshot_token_info(token as Token, info, meta))
            .collect(),
        liquid_base_tokens: meta.liquid_base_tokens.iter().copied().collect::<BTreeSet<_>>(),
        quote_token_to_status: meta
            .quote_token_to_status
            .iter()
            .map(|(token, status)| (*token, snapshot_quote_status(*status)))
            .collect::<BTreeMap<_, _>>(),
        quote_token_to_aligned_quote_token_info: meta
            .quote_token_to_aligned_quote_token_info
            .iter()
            .map(|(token, info)| (*token, snapshot_aligned_quote_info(info)))
            .collect::<BTreeMap<_, _>>(),
        current_time_or_block: 0.0,
    }
}

fn snapshot_token_info(token: Token, info: &spot_meta::TokenInfo, meta: &SpotMeta) -> TokenInfo {
    let aligned_quote = meta
        .quote_token_to_aligned_quote_token_info
        .get(&token)
        .map(snapshot_aligned_quote_info)
        .unwrap_or_default();

    TokenInfo {
        wei_decimals: info.wei_decimals(),
        sz_decimals: info.sz_decimals(),
        deployer_trading_fee_share_scaled: info.deployer_trading_fee_share,
        deployer: info.deployer.map(|address| Address(address.0)),
        aligned_quote,
    }
}

fn snapshot_quote_status(status: spot_meta::QuoteTokenStatus) -> QuoteTokenStatus {
    match status {
        spot_meta::QuoteTokenStatus::Active => QuoteTokenStatus::Active,
        spot_meta::QuoteTokenStatus::Disabled | spot_meta::QuoteTokenStatus::Unknown(_) => {
            QuoteTokenStatus::Disabled
        }
    }
}

fn snapshot_aligned_quote_info(info: &spot_meta::AlignedQuoteTokenInfo) -> AlignedQuoteTokenInfo {
    AlignedQuoteTokenInfo {
        active: info.active,
        evm_minted_supply: info.evm_minted_supply,
        first_aligned_time: info.first_aligned_time as Time,
    }
}

pub fn build_user_balance_index(
    balances: &HashMap<Address, BTreeMap<Token, SpotTokenBalance>>,
) -> BTreeMap<Address, BTreeSet<Token>> {
    let mut index = BTreeMap::new();
    for (user, by_token) in balances {
        let tokens = by_token.keys().copied().collect::<BTreeSet<_>>();
        if !tokens.is_empty() {
            index.insert(*user, tokens);
        }
    }
    index
}

pub fn saturating_f64_to_u64(value: f64) -> u64 {
    if !value.is_finite() || value <= 0.0 {
        return 0;
    }
    if value >= u64::MAX as f64 {
        return u64::MAX;
    }
    value as u64
}
