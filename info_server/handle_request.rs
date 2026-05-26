use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Extension};
use axum::response::{IntoResponse, Response};
use axum::Json;
use http::header::{CONTENT_TYPE, HeaderValue};
use http::StatusCode;
use serde::Serialize;
use serde_json::{json, Value};

use crate::request::{Address, Coin, Dex, InfoRequest, Outcome, Question, Token};

const ROUTE_TIMEOUT: Duration = Duration::from_millis(14);

pub async fn handle_request<R>(
    Extension(router): Extension<R>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    Json(request): Json<InfoRequest>,
) -> Response
where
    R: InfoRequestRouter,
{
    handle_info_request(&router, client_addr, request).await
}

pub async fn handle_info_request<R>(
    router: &R,
    client_addr: SocketAddr,
    request: InfoRequest,
) -> Response
where
    R: InfoRequestRouter,
{
    let method = request.method_name();
    let started_at = Instant::now();

    // The poll state first clones the request and runs serde_json serialization.
    // Serialization failure is treated as an internal server error before route dispatch.
    let request_json = match serde_json::to_value(&request) {
        Ok(value) => value,
        Err(error) => {
            router.record_info_request(method, started_at.elapsed(), false, StatusCode::INTERNAL_SERVER_ERROR);
            return build_http_response(
                RouteResponse::error_json(json!({ "error": error.to_string() })),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    let response = match tokio::time::timeout(
        ROUTE_TIMEOUT,
        dispatch_info_request(router, client_addr, request, request_json),
    )
    .await
    {
        Ok(Ok(route_response)) => build_http_response(route_response, StatusCode::OK),
        Ok(Err(error)) => {
            let (route_response, status) = route_error_into_response(error);
            build_http_response(route_response, status)
        }
        Err(_) => build_http_response(RouteResponse::Null, StatusCode::INTERNAL_SERVER_ERROR),
    };

    router.record_info_request(method, started_at.elapsed(), true, response.status());
    response
}

pub async fn dispatch_info_request<R>(
    router: &R,
    client_addr: SocketAddr,
    request: InfoRequest,
    request_json: Value,
) -> Result<RouteResponse, RouteError>
where
    R: InfoRequestRouter,
{
    match request {
        InfoRequest::FileSnapshot { request, out_path, include_height_in_output } => {
            if !client_addr.ip().is_loopback() {
                router.critical("not writing snapshot to file because request was not from localhost:", &client_addr);
                return Err(RouteError::FileSnapshotFromNonLocalhost { client_addr });
            }

            router.file_snapshot(*request, out_path, include_height_in_output, request_json).await
        }
        InfoRequest::WebData2 { user } => router.web_data2(user).await,
        InfoRequest::WebData3 { user } => router.web_data3(user).await,
        InfoRequest::Meta { dex } => router.meta(dex).await,
        InfoRequest::SpotMeta { include_debug_details } => router.spot_meta(include_debug_details).await,
        InfoRequest::OutcomeMeta => router.outcome_meta().await,
        InfoRequest::ClearinghouseState { user, dex } => router.clearinghouse_state(user, dex).await,
        InfoRequest::SpotClearinghouseState { user, ignore_portfolio_margin } => {
            router.spot_clearinghouse_state(user, ignore_portfolio_margin).await
        }
        InfoRequest::OpenOrders { user, dex } => router.open_orders(user, dex).await,
        InfoRequest::ExchangeStatus => router.exchange_status().await,
        InfoRequest::FrontendOpenOrders { user, dex } => router.frontend_open_orders(user, dex).await,
        InfoRequest::Liquidatable => router.liquidatable().await,
        InfoRequest::ActiveAssetData { user, coin } => router.active_asset_data(user, coin).await,
        InfoRequest::MaxMarketOrderNtls => router.max_market_order_ntls().await,
        InfoRequest::VaultSummaries { leader } => router.vault_summaries(leader).await,
        InfoRequest::UserVaultEquities { user } => router.user_vault_equities(user).await,
        InfoRequest::LeadingVaults { user } => router.leading_vaults(user).await,
        InfoRequest::ExtraAgents { user } => router.extra_agents(user).await,
        InfoRequest::SubAccounts { user, dex } => router.sub_accounts(user, dex).await,
        InfoRequest::SubAccounts2 { user } => router.sub_accounts2(user).await,
        InfoRequest::UserFees { user } => router.user_fees(user).await,
        InfoRequest::UserRateLimit { user } => router.user_rate_limit(user).await,
        InfoRequest::SpotDeployState { user } => router.spot_deploy_state(user).await,
        InfoRequest::SpotPairDeployAuctionStatus => router.spot_pair_deploy_auction_status().await,
        InfoRequest::PerpDeployAuctionStatus => router.perp_deploy_auction_status().await,
        InfoRequest::Votes { user } => router.votes(user).await,
        InfoRequest::Delegations { user } => router.delegations(user).await,
        InfoRequest::DelegatorSummary { user } => router.delegator_summary(user).await,
        InfoRequest::MaxBuilderFee { user, builder } => router.max_builder_fee(user, builder).await,
        InfoRequest::UserToMultiSigSigners { user } => router.user_to_multi_sig_signers(user).await,
        InfoRequest::UserRole { user } => router.user_role(user).await,
        InfoRequest::PerpsAtOpenInterestCap { dex } => router.perps_at_open_interest_cap(dex).await,
        InfoRequest::PerpDexLimits { dex } => router.perp_dex_limits(dex).await,
        InfoRequest::ValidatorL1Votes => router.validator_l1_votes().await,
        InfoRequest::MarginTable { id, dex } => router.margin_table(dex, id).await,
        InfoRequest::PerpDexs => router.perp_dexs().await,
        InfoRequest::AllPerpMetas => router.all_perp_metas().await,
        InfoRequest::AlignedQuoteTokenInfo { token } => router.aligned_quote_token_info(token).await,
        InfoRequest::UserDexAbstraction { user } => router.user_dex_abstraction(user).await,
        InfoRequest::PerpDexStatus { dex } => router.perp_dex_status(dex).await,
        InfoRequest::BorrowLendUserState { user } => router.borrow_lend_user_state(user).await,
        InfoRequest::BorrowLendReserveState { token } => router.borrow_lend_reserve_state(token).await,
        InfoRequest::AllBoleReserveStates => router.all_borrow_lend_reserve_states().await,
        InfoRequest::UserAbstraction { user } => router.user_abstraction(user).await,
        InfoRequest::PerpAnnotation { coin } => router.perp_annotation(coin).await,
        InfoRequest::PerpCategories => router.perp_categories().await,
        InfoRequest::PerpConciseAnnotations => router.perp_concise_annotations().await,
        InfoRequest::SettledOutcome { outcome } => router.settled_outcome(outcome).await,
        InfoRequest::SettledQuestion { question } => router.settled_question(question).await,
        InfoRequest::ApprovedBuilders { user } => router.approved_builders(user).await,
        InfoRequest::GossipPriorityAuctionStatus => router.gossip_priority_auction_status().await,
    }
}

pub fn build_http_response(route_response: RouteResponse, status: StatusCode) -> Response {
    match route_response {
        RouteResponse::Json(value) => (status, [(CONTENT_TYPE, "application/json")], value.to_string()).into_response(),
        RouteResponse::Bytes { bytes, content_type } => {
            let mut response = (status, bytes).into_response();
            response.headers_mut().insert(CONTENT_TYPE, content_type.unwrap_or_else(|| HeaderValue::from_static("application/json")));
            response
        }
        RouteResponse::Response(mut response) => {
            if !response.headers().contains_key(CONTENT_TYPE) {
                response.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            }
            *response.status_mut() = status;
            response
        }
        RouteResponse::Null => (status, [(CONTENT_TYPE, "application/json")], "null").into_response(),
    }
}

pub fn json_rejection_response(rejection: JsonRejectionKind) -> Response {
    let status = match rejection {
        JsonRejectionKind::Data => StatusCode::UNPROCESSABLE_ENTITY,
        JsonRejectionKind::Syntax => StatusCode::BAD_REQUEST,
        JsonRejectionKind::MissingContentType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        JsonRejectionKind::BytesBody => StatusCode::PAYLOAD_TOO_LARGE,
        JsonRejectionKind::Other => StatusCode::BAD_REQUEST,
    };

    let message = match rejection {
        JsonRejectionKind::Data => "Failed to deserialize the JSON body into the target type",
        JsonRejectionKind::Syntax => "Failed to parse the request body as JSON",
        JsonRejectionKind::MissingContentType => "Expected request with `Content-Type: application/json`",
        JsonRejectionKind::BytesBody | JsonRejectionKind::Other => "Failed to buffer the request body",
    };

    (status, [(CONTENT_TYPE, "text/plain; charset=utf-8")], message).into_response()
}

pub fn missing_extension_response(extension_type: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("Missing request extension: {extension_type}"),
    )
        .into_response()
}

pub fn route_error_into_response(error: RouteError) -> (RouteResponse, StatusCode) {
    match error {
        RouteError::AlreadyResponse(response) => (RouteResponse::Response(response), StatusCode::OK),
        RouteError::Json(value) => (RouteResponse::Json(value), StatusCode::OK),
        RouteError::FileSnapshotFromNonLocalhost { client_addr } => (
            RouteResponse::error_json(json!({
                "error": "fileSnapshot is only allowed from localhost",
                "client": client_addr.to_string(),
            })),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        RouteError::Internal(message) => (
            RouteResponse::error_json(json!({ "error": message })),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    }
}


pub enum RouteResponse {
    Json(Value),
    Bytes { bytes: Vec<u8>, content_type: Option<HeaderValue> },
    Response(Response),
    Null,
}

impl RouteResponse {
    pub fn json<T: Serialize>(value: T) -> Result<Self, RouteError> {
        serde_json::to_value(value)
            .map(Self::Json)
            .map_err(|error| RouteError::Internal(error.to_string()))
    }

    pub fn error_json(value: Value) -> Self {
        Self::Json(value)
    }
}


pub enum RouteError {
    AlreadyResponse(Response),
    Json(Value),
    FileSnapshotFromNonLocalhost { client_addr: SocketAddr },
    Internal(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsonRejectionKind {
    Data,
    Syntax,
    MissingContentType,
    BytesBody,
    Other,
}

#[allow(async_fn_in_trait)]
pub trait InfoRequestRouter {
    fn record_info_request(&self, _method: &'static str, _elapsed: Duration, _completed: bool, _status: StatusCode) {}
    fn critical(&self, _message: &str, _client_addr: &SocketAddr) {}

    async fn file_snapshot(
        &self,
        request: InfoRequest,
        out_path: String,
        include_height_in_output: bool,
        request_json: Value,
    ) -> Result<RouteResponse, RouteError>;


    async fn web_data2(&self, user: Address) -> Result<RouteResponse, RouteError>;
    async fn web_data3(&self, user: Address) -> Result<RouteResponse, RouteError>;
    async fn meta(&self, dex: Option<Dex>) -> Result<RouteResponse, RouteError>;
    async fn spot_meta(&self, include_debug_details: bool) -> Result<RouteResponse, RouteError>;
    async fn outcome_meta(&self) -> Result<RouteResponse, RouteError>;
    async fn clearinghouse_state(&self, user: Address, dex: Option<Dex>) -> Result<RouteResponse, RouteError>;
    async fn spot_clearinghouse_state(&self, user: Address, ignore_portfolio_margin: bool) -> Result<RouteResponse, RouteError>;
    async fn open_orders(&self, user: Address, dex: Option<Dex>) -> Result<RouteResponse, RouteError>;
    async fn exchange_status(&self) -> Result<RouteResponse, RouteError>;
    async fn frontend_open_orders(&self, user: Address, dex: Option<Dex>) -> Result<RouteResponse, RouteError>;
    async fn liquidatable(&self) -> Result<RouteResponse, RouteError>;
    async fn active_asset_data(&self, user: Address, coin: Coin) -> Result<RouteResponse, RouteError>;
    async fn max_market_order_ntls(&self) -> Result<RouteResponse, RouteError>;
    async fn vault_summaries(&self, leader: Address) -> Result<RouteResponse, RouteError>;
    async fn user_vault_equities(&self, user: Address) -> Result<RouteResponse, RouteError>;
    async fn leading_vaults(&self, user: Address) -> Result<RouteResponse, RouteError>;
    async fn extra_agents(&self, user: Address) -> Result<RouteResponse, RouteError>;
    async fn sub_accounts(&self, user: Address, dex: Option<Dex>) -> Result<RouteResponse, RouteError>;
    async fn sub_accounts2(&self, user: Address) -> Result<RouteResponse, RouteError>;
    async fn user_fees(&self, user: Address) -> Result<RouteResponse, RouteError>;
    async fn user_rate_limit(&self, user: Address) -> Result<RouteResponse, RouteError>;
    async fn spot_deploy_state(&self, user: Address) -> Result<RouteResponse, RouteError>;
    async fn spot_pair_deploy_auction_status(&self) -> Result<RouteResponse, RouteError>;
    async fn perp_deploy_auction_status(&self) -> Result<RouteResponse, RouteError>;
    async fn votes(&self, user: Address) -> Result<RouteResponse, RouteError>;
    async fn delegations(&self, user: Address) -> Result<RouteResponse, RouteError>;
    async fn delegator_summary(&self, user: Address) -> Result<RouteResponse, RouteError>;
    async fn max_builder_fee(&self, user: Address, builder: Address) -> Result<RouteResponse, RouteError>;
    async fn user_to_multi_sig_signers(&self, user: Address) -> Result<RouteResponse, RouteError>;
    async fn user_role(&self, user: Address) -> Result<RouteResponse, RouteError>;
    async fn perps_at_open_interest_cap(&self, dex: Option<Dex>) -> Result<RouteResponse, RouteError>;
    async fn perp_dex_limits(&self, dex: Option<Dex>) -> Result<RouteResponse, RouteError>;
    async fn validator_l1_votes(&self) -> Result<RouteResponse, RouteError>;
    async fn margin_table(&self, dex: Option<Dex>, id: u32) -> Result<RouteResponse, RouteError>;
    async fn perp_dexs(&self) -> Result<RouteResponse, RouteError>;
    async fn all_perp_metas(&self) -> Result<RouteResponse, RouteError>;
    async fn aligned_quote_token_info(&self, token: Token) -> Result<RouteResponse, RouteError>;
    async fn user_dex_abstraction(&self, user: Address) -> Result<RouteResponse, RouteError>;
    async fn perp_dex_status(&self, dex: Option<Dex>) -> Result<RouteResponse, RouteError>;
    async fn borrow_lend_user_state(&self, user: Address) -> Result<RouteResponse, RouteError>;
    async fn borrow_lend_reserve_state(&self, token: Token) -> Result<RouteResponse, RouteError>;
    async fn all_borrow_lend_reserve_states(&self) -> Result<RouteResponse, RouteError>;
    async fn user_abstraction(&self, user: Address) -> Result<RouteResponse, RouteError>;
    async fn perp_annotation(&self, coin: Coin) -> Result<RouteResponse, RouteError>;
    async fn perp_categories(&self) -> Result<RouteResponse, RouteError>;
    async fn perp_concise_annotations(&self) -> Result<RouteResponse, RouteError>;
    async fn settled_outcome(&self, outcome: Outcome) -> Result<RouteResponse, RouteError>;
    async fn settled_question(&self, question: Question) -> Result<RouteResponse, RouteError>;
    async fn approved_builders(&self, user: Address) -> Result<RouteResponse, RouteError>;
    async fn gossip_priority_auction_status(&self) -> Result<RouteResponse, RouteError>;
}

impl InfoRequest {
    pub fn method_name(&self) -> &'static str {
        match self {
            Self::FileSnapshot { .. } => "fileSnapshot",
            Self::WebData2 { .. } => "webData2",
            Self::WebData3 { .. } => "webData3",
            Self::Meta { .. } => "meta",
            Self::SpotMeta { .. } => "spotMeta",
            Self::OutcomeMeta => "outcomeMeta",
            Self::ClearinghouseState { .. } => "clearinghouseState",
            Self::SpotClearinghouseState { .. } => "spotClearinghouseState",
            Self::OpenOrders { .. } => "openOrders",
            Self::ExchangeStatus => "exchangeStatus",
            Self::FrontendOpenOrders { .. } => "frontendOpenOrders",
            Self::Liquidatable => "liquidatable",
            Self::ActiveAssetData { .. } => "activeAssetData",
            Self::MaxMarketOrderNtls => "maxMarketOrderNtls",
            Self::VaultSummaries { .. } => "vaultSummaries",
            Self::UserVaultEquities { .. } => "userVaultEquities",
            Self::LeadingVaults { .. } => "leadingVaults",
            Self::ExtraAgents { .. } => "extraAgents",
            Self::SubAccounts { .. } => "subAccounts",
            Self::SubAccounts2 { .. } => "subAccounts2",
            Self::UserFees { .. } => "userFees",
            Self::UserRateLimit { .. } => "userRateLimit",
            Self::SpotDeployState { .. } => "spotDeployState",
            Self::SpotPairDeployAuctionStatus => "spotPairDeployAuctionStatus",
            Self::PerpDeployAuctionStatus => "perpDeployAuctionStatus",
            Self::Votes { .. } => "votes",
            Self::Delegations { .. } => "delegations",
            Self::DelegatorSummary { .. } => "delegatorSummary",
            Self::MaxBuilderFee { .. } => "maxBuilderFee",
            Self::UserToMultiSigSigners { .. } => "userToMultiSigSigners",
            Self::UserRole { .. } => "userRole",
            Self::PerpsAtOpenInterestCap { .. } => "perpsAtOpenInterestCap",
            Self::PerpDexLimits { .. } => "perpDexLimits",
            Self::ValidatorL1Votes => "validatorL1Votes",
            Self::MarginTable { .. } => "marginTable",
            Self::PerpDexs => "perpDexs",
            Self::AllPerpMetas => "allPerpMetas",
            Self::AlignedQuoteTokenInfo { .. } => "alignedQuoteTokenInfo",
            Self::UserDexAbstraction { .. } => "userDexAbstraction",
            Self::PerpDexStatus { .. } => "perpDexStatus",
            Self::BorrowLendUserState { .. } => "borrowLendUserState",
            Self::BorrowLendReserveState { .. } => "borrowLendReserveState",
            Self::AllBoleReserveStates => "allBorrowLendReserveStates",
            Self::UserAbstraction { .. } => "userAbstraction",
            Self::PerpAnnotation { .. } => "perpAnnotation",
            Self::PerpCategories => "perpCategories",
            Self::PerpConciseAnnotations => "perpConciseAnnotations",
            Self::SettledOutcome { .. } => "settledOutcome",
            Self::SettledQuestion { .. } => "settledQuestion",
            Self::ApprovedBuilders { .. } => "approvedBuilders",
            Self::GossipPriorityAuctionStatus => "gossipPriorityAuctionStatus",
        }
    }
}
