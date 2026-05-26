use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::handle_request::{InfoRequestRouter, RouteError, RouteResponse};
use crate::request::{Address, Coin, Dex, InfoRequest, Outcome, Question, Token};

#[derive(Clone, Debug)]
pub struct AbciStateInfoHandler<S> {
    pub state: S,
}

impl<S> AbciStateInfoHandler<S> {
    pub fn new(state: S) -> Self {
        Self { state }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbciStateEndpoint {
    FileSnapshot,
    WebData2,
    WebData3,
    Meta,
    SpotMeta,
    OutcomeMeta,
    ClearinghouseState,
    SpotClearinghouseState,
    OpenOrders,
    ExchangeStatus,
    FrontendOpenOrders,
    Liquidatable,
    ActiveAssetData,
    MaxMarketOrderNtls,
    VaultSummaries,
    UserVaultEquities,
    LeadingVaults,
    ExtraAgents,
    SubAccounts,
    SubAccounts2,
    UserFees,
    UserRateLimit,
    SpotDeployState,
    SpotPairDeployAuctionStatus,
    PerpDeployAuctionStatus,
    Votes,
    Delegations,
    DelegatorSummary,
    MaxBuilderFee,
    UserToMultiSigSigners,
    UserRole,
    PerpsAtOpenInterestCap,
    PerpDexLimits,
    ValidatorL1Votes,
    MarginTable,
    PerpDexs,
    AllPerpMetas,
    AlignedQuoteTokenInfo,
    UserDexAbstraction,
    PerpDexStatus,
    BorrowLendUserState,
    BorrowLendReserveState,
    AllBorrowLendReserveStates,
    UserAbstraction,
    PerpAnnotation,
    PerpCategories,
    PerpConciseAnnotations,
    SettledOutcome,
    SettledQuestion,
    ApprovedBuilders,
    GossipPriorityAuctionStatus,
}

impl AbciStateEndpoint {
    pub fn from_request(request: &InfoRequest) -> Self {
        match request {
            InfoRequest::FileSnapshot { .. } => Self::FileSnapshot,
            InfoRequest::WebData2 { .. } => Self::WebData2,
            InfoRequest::WebData3 { .. } => Self::WebData3,
            InfoRequest::Meta { .. } => Self::Meta,
            InfoRequest::SpotMeta { .. } => Self::SpotMeta,
            InfoRequest::OutcomeMeta => Self::OutcomeMeta,
            InfoRequest::ClearinghouseState { .. } => Self::ClearinghouseState,
            InfoRequest::SpotClearinghouseState { .. } => Self::SpotClearinghouseState,
            InfoRequest::OpenOrders { .. } => Self::OpenOrders,
            InfoRequest::ExchangeStatus => Self::ExchangeStatus,
            InfoRequest::FrontendOpenOrders { .. } => Self::FrontendOpenOrders,
            InfoRequest::Liquidatable => Self::Liquidatable,
            InfoRequest::ActiveAssetData { .. } => Self::ActiveAssetData,
            InfoRequest::MaxMarketOrderNtls => Self::MaxMarketOrderNtls,
            InfoRequest::VaultSummaries { .. } => Self::VaultSummaries,
            InfoRequest::UserVaultEquities { .. } => Self::UserVaultEquities,
            InfoRequest::LeadingVaults { .. } => Self::LeadingVaults,
            InfoRequest::ExtraAgents { .. } => Self::ExtraAgents,
            InfoRequest::SubAccounts { .. } => Self::SubAccounts,
            InfoRequest::SubAccounts2 { .. } => Self::SubAccounts2,
            InfoRequest::UserFees { .. } => Self::UserFees,
            InfoRequest::UserRateLimit { .. } => Self::UserRateLimit,
            InfoRequest::SpotDeployState { .. } => Self::SpotDeployState,
            InfoRequest::SpotPairDeployAuctionStatus => Self::SpotPairDeployAuctionStatus,
            InfoRequest::PerpDeployAuctionStatus => Self::PerpDeployAuctionStatus,
            InfoRequest::Votes { .. } => Self::Votes,
            InfoRequest::Delegations { .. } => Self::Delegations,
            InfoRequest::DelegatorSummary { .. } => Self::DelegatorSummary,
            InfoRequest::MaxBuilderFee { .. } => Self::MaxBuilderFee,
            InfoRequest::UserToMultiSigSigners { .. } => Self::UserToMultiSigSigners,
            InfoRequest::UserRole { .. } => Self::UserRole,
            InfoRequest::PerpsAtOpenInterestCap { .. } => Self::PerpsAtOpenInterestCap,
            InfoRequest::PerpDexLimits { .. } => Self::PerpDexLimits,
            InfoRequest::ValidatorL1Votes => Self::ValidatorL1Votes,
            InfoRequest::MarginTable { .. } => Self::MarginTable,
            InfoRequest::PerpDexs => Self::PerpDexs,
            InfoRequest::AllPerpMetas => Self::AllPerpMetas,
            InfoRequest::AlignedQuoteTokenInfo { .. } => Self::AlignedQuoteTokenInfo,
            InfoRequest::UserDexAbstraction { .. } => Self::UserDexAbstraction,
            InfoRequest::PerpDexStatus { .. } => Self::PerpDexStatus,
            InfoRequest::BorrowLendUserState { .. } => Self::BorrowLendUserState,
            InfoRequest::BorrowLendReserveState { .. } => Self::BorrowLendReserveState,
            InfoRequest::AllBoleReserveStates => Self::AllBorrowLendReserveStates,
            InfoRequest::UserAbstraction { .. } => Self::UserAbstraction,
            InfoRequest::PerpAnnotation { .. } => Self::PerpAnnotation,
            InfoRequest::PerpCategories => Self::PerpCategories,
            InfoRequest::PerpConciseAnnotations => Self::PerpConciseAnnotations,
            InfoRequest::SettledOutcome { .. } => Self::SettledOutcome,
            InfoRequest::SettledQuestion { .. } => Self::SettledQuestion,
            InfoRequest::ApprovedBuilders { .. } => Self::ApprovedBuilders,
            InfoRequest::GossipPriorityAuctionStatus => Self::GossipPriorityAuctionStatus,
        }
    }
}

#[allow(async_fn_in_trait)]
pub trait AbciStateInfoBackend {
    async fn file_snapshot(&self, request: InfoRequest, out_path: String, include_height_in_output: bool, request_json: Value) -> Result<RouteResponse, RouteError>;
    async fn web_data2(&self, user: Address) -> Result<Value, RouteError>;
    async fn web_data3(&self, user: Address) -> Result<Value, RouteError>;
    async fn meta(&self, dex: Option<Dex>) -> Result<PerpMetaResponse, RouteError>;
    async fn spot_meta(&self, include_debug_details: bool) -> Result<SpotMetaResponse, RouteError>;
    async fn outcome_meta(&self) -> Result<OutcomeMetaResponse, RouteError>;
    async fn clearinghouse_state(&self, user: Address, dex: Option<Dex>) -> Result<ClearinghouseStateResponse, RouteError>;
    async fn spot_clearinghouse_state(&self, user: Address, ignore_portfolio_margin: bool) -> Result<SpotClearinghouseStateResponse, RouteError>;
    async fn open_orders(&self, user: Address, dex: Option<Dex>) -> Result<Vec<OpenOrder>, RouteError>;
    async fn exchange_status(&self) -> Result<Value, RouteError>;
    async fn frontend_open_orders(&self, user: Address, dex: Option<Dex>) -> Result<Vec<FrontendOpenOrder>, RouteError>;
    async fn liquidatable(&self) -> Result<Value, RouteError>;
    async fn active_asset_data(&self, user: Address, coin: Coin) -> Result<ActiveAssetData, RouteError>;
    async fn max_market_order_ntls(&self) -> Result<Value, RouteError>;
    async fn vault_summaries(&self, leader: Address) -> Result<Vec<VaultSummary>, RouteError>;
    async fn user_vault_equities(&self, user: Address) -> Result<Vec<UserVaultEquity>, RouteError>;
    async fn leading_vaults(&self, user: Address) -> Result<Value, RouteError>;
    async fn extra_agents(&self, user: Address) -> Result<Value, RouteError>;
    async fn sub_accounts(&self, user: Address, dex: Option<Dex>) -> Result<Vec<SubAccount>, RouteError>;
    async fn sub_accounts2(&self, user: Address) -> Result<Vec<SubAccount2>, RouteError>;
    async fn user_fees(&self, user: Address) -> Result<UserFeesResponse, RouteError>;
    async fn user_rate_limit(&self, user: Address) -> Result<UserRateLimit, RouteError>;
    async fn spot_deploy_state(&self, user: Address) -> Result<Value, RouteError>;
    async fn spot_pair_deploy_auction_status(&self) -> Result<Value, RouteError>;
    async fn perp_deploy_auction_status(&self) -> Result<Value, RouteError>;
    async fn votes(&self, user: Address) -> Result<Value, RouteError>;
    async fn delegations(&self, user: Address) -> Result<Vec<StakingDelegation>, RouteError>;
    async fn delegator_summary(&self, user: Address) -> Result<DelegatorSummary, RouteError>;
    async fn max_builder_fee(&self, user: Address, builder: Address) -> Result<u64, RouteError>;
    async fn user_to_multi_sig_signers(&self, user: Address) -> Result<Option<MultiSigSigners>, RouteError>;
    async fn user_role(&self, user: Address) -> Result<UserRoleResponse, RouteError>;
    async fn perps_at_open_interest_cap(&self, dex: Option<Dex>) -> Result<Option<OpenInterestCapResponse>, RouteError>;
    async fn perp_dex_limits(&self, dex: Option<Dex>) -> Result<PerpDexLimits, RouteError>;
    async fn validator_l1_votes(&self) -> Result<Value, RouteError>;
    async fn margin_table(&self, dex: Option<Dex>, id: u32) -> Result<RawMarginTable, RouteError>;
    async fn perp_dexs(&self) -> Result<Vec<Dex>, RouteError>;
    async fn all_perp_metas(&self) -> Result<Vec<PerpMetaResponse>, RouteError>;
    async fn aligned_quote_token_info(&self, token: Token) -> Result<Value, RouteError>;
    async fn user_dex_abstraction(&self, user: Address) -> Result<Value, RouteError>;
    async fn perp_dex_status(&self, dex: Option<Dex>) -> Result<Value, RouteError>;
    async fn borrow_lend_user_state(&self, user: Address) -> Result<Value, RouteError>;
    async fn borrow_lend_reserve_state(&self, token: Token) -> Result<Value, RouteError>;
    async fn all_borrow_lend_reserve_states(&self) -> Result<Value, RouteError>;
    async fn user_abstraction(&self, user: Address) -> Result<Value, RouteError>;
    async fn perp_annotation(&self, coin: Coin) -> Result<PerpAnnotation, RouteError>;
    async fn perp_categories(&self) -> Result<Vec<PerpCategory>, RouteError>;
    async fn perp_concise_annotations(&self) -> Result<Value, RouteError>;
    async fn settled_outcome(&self, outcome: Outcome) -> Result<Value, RouteError>;
    async fn settled_question(&self, question: Question) -> Result<Value, RouteError>;
    async fn approved_builders(&self, user: Address) -> Result<Value, RouteError>;
    async fn gossip_priority_auction_status(&self) -> Result<Value, RouteError>;
}

fn json_response<T: Serialize>(value: T) -> Result<RouteResponse, RouteError> {
    RouteResponse::json(value)
}

#[allow(async_fn_in_trait)]
impl<S> InfoRequestRouter for AbciStateInfoHandler<S>
where
    S: AbciStateInfoBackend + Sync,
{
    async fn file_snapshot(&self, request: InfoRequest, out_path: String, include_height_in_output: bool, request_json: Value) -> Result<RouteResponse, RouteError> {
        self.state.file_snapshot(request, out_path, include_height_in_output, request_json).await
    }

    async fn web_data2(&self, user: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.web_data2(user).await?) }
    async fn web_data3(&self, user: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.web_data3(user).await?) }
    async fn meta(&self, dex: Option<Dex>) -> Result<RouteResponse, RouteError> { json_response(self.state.meta(dex).await?) }
    async fn spot_meta(&self, include_debug_details: bool) -> Result<RouteResponse, RouteError> { json_response(self.state.spot_meta(include_debug_details).await?) }
    async fn outcome_meta(&self) -> Result<RouteResponse, RouteError> { json_response(self.state.outcome_meta().await?) }
    async fn clearinghouse_state(&self, user: Address, dex: Option<Dex>) -> Result<RouteResponse, RouteError> { json_response(self.state.clearinghouse_state(user, dex).await?) }
    async fn spot_clearinghouse_state(&self, user: Address, ignore_portfolio_margin: bool) -> Result<RouteResponse, RouteError> { json_response(self.state.spot_clearinghouse_state(user, ignore_portfolio_margin).await?) }
    async fn open_orders(&self, user: Address, dex: Option<Dex>) -> Result<RouteResponse, RouteError> { json_response(self.state.open_orders(user, dex).await?) }
    async fn exchange_status(&self) -> Result<RouteResponse, RouteError> { json_response(self.state.exchange_status().await?) }
    async fn frontend_open_orders(&self, user: Address, dex: Option<Dex>) -> Result<RouteResponse, RouteError> { json_response(self.state.frontend_open_orders(user, dex).await?) }
    async fn liquidatable(&self) -> Result<RouteResponse, RouteError> { json_response(self.state.liquidatable().await?) }
    async fn active_asset_data(&self, user: Address, coin: Coin) -> Result<RouteResponse, RouteError> { json_response(self.state.active_asset_data(user, coin).await?) }
    async fn max_market_order_ntls(&self) -> Result<RouteResponse, RouteError> { json_response(self.state.max_market_order_ntls().await?) }
    async fn vault_summaries(&self, leader: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.vault_summaries(leader).await?) }
    async fn user_vault_equities(&self, user: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.user_vault_equities(user).await?) }
    async fn leading_vaults(&self, user: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.leading_vaults(user).await?) }
    async fn extra_agents(&self, user: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.extra_agents(user).await?) }
    async fn sub_accounts(&self, user: Address, dex: Option<Dex>) -> Result<RouteResponse, RouteError> { json_response(self.state.sub_accounts(user, dex).await?) }
    async fn sub_accounts2(&self, user: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.sub_accounts2(user).await?) }
    async fn user_fees(&self, user: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.user_fees(user).await?) }
    async fn user_rate_limit(&self, user: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.user_rate_limit(user).await?) }
    async fn spot_deploy_state(&self, user: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.spot_deploy_state(user).await?) }
    async fn spot_pair_deploy_auction_status(&self) -> Result<RouteResponse, RouteError> { json_response(self.state.spot_pair_deploy_auction_status().await?) }
    async fn perp_deploy_auction_status(&self) -> Result<RouteResponse, RouteError> { json_response(self.state.perp_deploy_auction_status().await?) }
    async fn votes(&self, user: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.votes(user).await?) }
    async fn delegations(&self, user: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.delegations(user).await?) }
    async fn delegator_summary(&self, user: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.delegator_summary(user).await?) }
    async fn max_builder_fee(&self, user: Address, builder: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.max_builder_fee(user, builder).await?) }
    async fn user_to_multi_sig_signers(&self, user: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.user_to_multi_sig_signers(user).await?) }
    async fn user_role(&self, user: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.user_role(user).await?) }
    async fn perps_at_open_interest_cap(&self, dex: Option<Dex>) -> Result<RouteResponse, RouteError> { json_response(self.state.perps_at_open_interest_cap(dex).await?) }
    async fn perp_dex_limits(&self, dex: Option<Dex>) -> Result<RouteResponse, RouteError> { json_response(self.state.perp_dex_limits(dex).await?) }
    async fn validator_l1_votes(&self) -> Result<RouteResponse, RouteError> { json_response(self.state.validator_l1_votes().await?) }
    async fn margin_table(&self, dex: Option<Dex>, id: u32) -> Result<RouteResponse, RouteError> { json_response(self.state.margin_table(dex, id).await?) }
    async fn perp_dexs(&self) -> Result<RouteResponse, RouteError> { json_response(self.state.perp_dexs().await?) }
    async fn all_perp_metas(&self) -> Result<RouteResponse, RouteError> { json_response(self.state.all_perp_metas().await?) }
    async fn aligned_quote_token_info(&self, token: Token) -> Result<RouteResponse, RouteError> { json_response(self.state.aligned_quote_token_info(token).await?) }
    async fn user_dex_abstraction(&self, user: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.user_dex_abstraction(user).await?) }
    async fn perp_dex_status(&self, dex: Option<Dex>) -> Result<RouteResponse, RouteError> { json_response(self.state.perp_dex_status(dex).await?) }
    async fn borrow_lend_user_state(&self, user: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.borrow_lend_user_state(user).await?) }
    async fn borrow_lend_reserve_state(&self, token: Token) -> Result<RouteResponse, RouteError> { json_response(self.state.borrow_lend_reserve_state(token).await?) }
    async fn all_borrow_lend_reserve_states(&self) -> Result<RouteResponse, RouteError> { json_response(self.state.all_borrow_lend_reserve_states().await?) }
    async fn user_abstraction(&self, user: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.user_abstraction(user).await?) }
    async fn perp_annotation(&self, coin: Coin) -> Result<RouteResponse, RouteError> { json_response(self.state.perp_annotation(coin).await?) }
    async fn perp_categories(&self) -> Result<RouteResponse, RouteError> { json_response(self.state.perp_categories().await?) }
    async fn perp_concise_annotations(&self) -> Result<RouteResponse, RouteError> { json_response(self.state.perp_concise_annotations().await?) }
    async fn settled_outcome(&self, outcome: Outcome) -> Result<RouteResponse, RouteError> { json_response(self.state.settled_outcome(outcome).await?) }
    async fn settled_question(&self, question: Question) -> Result<RouteResponse, RouteError> { json_response(self.state.settled_question(question).await?) }
    async fn approved_builders(&self, user: Address) -> Result<RouteResponse, RouteError> { json_response(self.state.approved_builders(user).await?) }
    async fn gossip_priority_auction_status(&self) -> Result<RouteResponse, RouteError> { json_response(self.state.gossip_priority_auction_status().await?) }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClearinghouseStateResponse {
    pub clearinghouse_state: UserState,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub leading_vaults: Vec<LeadingVault>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_vault_equity: Option<String>,
    pub open_orders: Vec<FrontendOpenOrder>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_valid_until: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cum_ledger: Vec<Value>,
    pub meta: PerpMetaResponse,
    pub asset_ctxs: Vec<AssetCtx>,
    pub server_time: u64,
    pub is_vault: bool,
    pub user: Address,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub twap_states: Vec<TwapState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spot_state: Option<SpotUserState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spot_asset_ctxs: Option<Vec<SpotAssetCtx>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opt_out_of_spot_dusting: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub perps_at_open_interest_cap: Option<OpenInterestCapResponse>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserStateWithPerpDexStates {
    pub user_state: UserState,
    pub perp_dex_states: BTreeMap<Dex, UserState>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserState {
    pub margin_summary: MarginSummary,
    pub cross_margin_summary: MarginSummary,
    pub cross_maintenance_margin_used: String,
    pub withdrawable: String,
    pub asset_positions: Vec<AssetPosition>,
    pub time: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MarginSummary {
    pub account_value: String,
    pub total_margin_used: String,
    pub total_ntl_pos: String,
    pub total_raw_usd: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetPosition {
    pub position: PositionSummary,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PositionSummary {
    pub coin: Coin,
    pub szi: String,
    pub entry_px: Option<String>,
    pub position_value: String,
    pub unrealized_pnl: String,
    pub return_on_equity: String,
    pub liquidation_px: Option<String>,
    pub margin_used: String,
    pub max_leverage: u32,
    pub leverage: Leverage,
    pub cum_funding: CumFunding,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Leverage {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_usd: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CumFunding {
    pub all_time: String,
    pub since_open: String,
    pub since_change: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotClearinghouseStateResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portfolio_margin: Option<bool>,
    pub balances: Vec<SpotBalance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_escrows: Option<Vec<EvmEscrow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portfolio_margin_data: Option<PortfolioMarginData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_to_portfolio_margin_data: Option<BTreeMap<Token, PortfolioMarginData>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_to_available_after_maintenance: Option<BTreeMap<Token, String>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotBalance {
    pub coin: Token,
    pub token: u32,
    pub total: String,
    pub hold: String,
    pub entry_ntl: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmEscrow {
    pub address: Address,
    pub balance: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortfolioMarginData {
    pub available: String,
    pub maintenance_margin_used: String,
    pub account_value: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawOpenOrder {
    pub coin: Coin,
    pub side: String,
    pub limit_px: String,
    pub sz: String,
    pub oid: u64,
    pub timestamp: u64,
    pub orig_sz: String,
    pub reduce_only: Option<bool>,
    pub cloid: Option<String>,
}

pub type OpenOrder = RawOpenOrder;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FrontendOpenOrder {
    pub coin: Coin,
    pub side: String,
    pub limit_px: String,
    pub sz: String,
    pub oid: u64,
    pub timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger_condition: Option<String>,
    pub is_trigger: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger_px: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<FrontendOpenOrder>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_position_tpsl: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reduce_only: Option<bool>,
    pub order_type: OrderType,
    pub orig_sz: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloid: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum OrderType {
    Limit { limit: TifOrder },
    Trigger { trigger: TriggerOrder },
    Raw(Value),
}

#[derive(Clone, Debug, Serialize)]
pub struct TifOrder {
    pub tif: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TriggerOrder {
    pub is_market: bool,
    pub trigger_px: String,
    pub tpsl: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Fill {
    pub coin: Coin,
    pub px: String,
    pub sz: String,
    pub side: String,
    pub time: u64,
    pub start_position: String,
    pub dir: String,
    pub closed_pnl: String,
    pub hash: String,
    pub oid: u64,
    pub crossed: bool,
    pub fee: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder_fee: Option<String>,
    pub tid: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub liquidation: Option<FillLiquidation>,
    pub fee_token: Token,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_trial_escrow: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub twap_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployer_fee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority_gas: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FillLiquidation {
    pub liquidated_user: Address,
    pub mark_px: String,
    pub method: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserFunding {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub coin: Coin,
    pub usdc: String,
    pub szi: String,
    pub funding_rate: String,
    pub time: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FundingHistoryEntry {
    pub coin: Coin,
    pub funding_rate: String,
    pub premium: String,
    pub time: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Trade {
    pub coin: Coin,
    pub side: String,
    pub px: String,
    pub sz: String,
    pub time: u64,
    pub hash: String,
    pub tid: u64,
    pub users: Vec<Address>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Candle {
    #[serde(rename = "t")]
    pub open_time: u64,
    #[serde(rename = "T")]
    pub close_time: u64,
    #[serde(rename = "s")]
    pub coin: Coin,
    #[serde(rename = "i")]
    pub interval: String,
    #[serde(rename = "o")]
    pub open: String,
    #[serde(rename = "c")]
    pub close: String,
    #[serde(rename = "h")]
    pub high: String,
    #[serde(rename = "l")]
    pub low: String,
    #[serde(rename = "v")]
    pub volume: String,
    #[serde(rename = "n")]
    pub n_trades: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserRateLimit {
    pub cum_vlm: String,
    pub n_requests_used: u64,
    pub n_requests_cap: u64,
    pub n_requests_surplus: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserFeesResponse {
    pub daily_user_vlm: Vec<DailyUserVlm>,
    pub fee_schedule: FeeSchedule,
    pub user_cross_rate: String,
    pub user_add_rate: String,
    pub user_spot_cross_rate: String,
    pub user_spot_add_rate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_referral_discount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trial: Option<FeeTrial>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_trial_escrow: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_trial_available_timestamp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staking_link: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_staking_discount: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DailyUserVlm {
    pub date: String,
    pub user_cross: String,
    pub user_add: String,
    pub exchange: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeSchedule {
    pub cross: String,
    pub add: String,
    pub spot_cross: String,
    pub spot_add: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tiers: Vec<FeeTier>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeTier {
    pub ntl_cutoff: String,
    pub cross: String,
    pub add: String,
    pub spot_cross: String,
    pub spot_add: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeTrial {
    pub expires_at: u64,
    pub maker: String,
    pub taker: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultSummary {
    pub name: String,
    pub vault_address: Address,
    pub leader: Address,
    pub tvl: String,
    pub is_closed: bool,
    pub relationship: String,
    pub create_time_millis: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserVaultEquity {
    pub vault_address: Address,
    pub equity: String,
    pub locked_until_timestamp: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LeadingVault {
    pub vault_address: Address,
    pub equity: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubAccount {
    pub name: String,
    pub sub_account_user: Address,
    pub master: Address,
    pub clearinghouse_state: UserState,
    pub spot_state: SpotUserState,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubAccount2 {
    pub name: String,
    pub sub_account_user: Address,
    pub master: Address,
    pub dex_to_clearinghouse_state: BTreeMap<Dex, UserState>,
    pub spot_state: SpotUserState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abstraction: Option<Value>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiSigSigners {
    pub authorized_users: Vec<Address>,
    pub threshold: u32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "role", content = "data")]
pub enum UserRoleResponse {
    #[serde(rename = "missing")]
    Missing,
    #[serde(rename = "user")]
    User,
    #[serde(rename = "agent")]
    Agent { user: Address, valid_until: u64 },
    #[serde(rename = "subAccount")]
    SubAccount { master: Address, name: String },
    #[serde(rename = "vault")]
    Vault { leader: Address },
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StakingDelegation {
    pub validator: Address,
    pub amount: String,
    pub locked_until_timestamp: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegatorSummary {
    pub delegated: String,
    pub undelegated: String,
    pub total_pending_withdrawal: String,
    pub n_pending_withdrawals: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PerpMetaResponse {
    pub universe: Vec<PerpAssetMeta>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub margin_tables: Vec<RawMarginTable>,
    pub collateral_token: u32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PerpAssetMeta {
    pub name: Coin,
    pub sz_decimals: u32,
    pub max_leverage: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_isolated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub margin_table_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_delisted: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotMetaResponse {
    pub universe: Vec<SpotPairMeta>,
    pub tokens: Vec<SpotTokenMeta>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotPairMeta {
    pub name: String,
    pub tokens: [u32; 2],
    pub index: u32,
    pub is_canonical: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotTokenMeta {
    pub name: Token,
    pub sz_decimals: u32,
    pub wei_decimals: u32,
    pub index: u32,
    pub token_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_contract: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeMetaResponse {
    pub outcomes: Vec<String>,
    pub questions: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotAssetCtx {
    pub day_ntl_vlm: String,
    pub mark_px: String,
    pub mid_px: Option<String>,
    pub prev_day_px: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveAssetData {
    pub user: Address,
    pub coin: Coin,
    pub leverage: Leverage,
    pub max_trade_szs: [String; 2],
    pub available_to_trade: [String; 2],
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawMarginTable {
    pub description: String,
    pub margin_tiers: Vec<RawMarginTier>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawMarginTier {
    pub lower_bound: String,
    pub max_leverage: u32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenInterestCapResponse {
    pub total_oi_cap: String,
    pub oi_sz_cap_per_perp: String,
    pub max_transfer_ntl: String,
    pub coin_to_oi_cap: BTreeMap<Coin, String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PerpDexLimits {
    pub asset_to_streaming_oi_cap: BTreeMap<Coin, String>,
    pub sub_deployers: Vec<Address>,
    pub last_deployer_fee_scale_change_time: u64,
    pub asset_to_funding_multiplier: BTreeMap<Coin, String>,
    pub asset_to_funding_interest_rate: BTreeMap<Coin, String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PredictedFunding {
    pub is_aligned: bool,
    pub first_aligned_time: u64,
    pub evm_minted_supply: String,
    pub daily_amount_owed: Vec<String>,
    pub predicted_rate: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PerpDexStatus {
    pub name: String,
    pub full_name: String,
    pub deployer: Address,
    pub oracle_updater: Address,
    pub fee_recipient: Address,
    pub asset_to_streaming_oi_cap: BTreeMap<Coin, String>,
    pub sub_deployers: Vec<Address>,
    pub deployer_fee_scale: String,
    pub last_deployer_fee_scale_change_time: u64,
    pub asset_to_funding_multiplier: BTreeMap<Coin, String>,
    pub asset_to_funding_interest_rate: BTreeMap<Coin, String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PerpAnnotation {
    pub category: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keywords: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PerpCategory {
    pub category: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keywords: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotUserState {
    pub balances: Vec<SpotBalance>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwapState {
    pub coin: Coin,
    pub side: String,
    pub sz: String,
    pub executed_sz: String,
    pub executed_ntl: String,
    pub minutes: u32,
    pub reduce_only: bool,
    pub randomize: bool,
    pub timestamp: u64,
}
