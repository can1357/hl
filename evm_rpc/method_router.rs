use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http::{Response, StatusCode};
use serde::Serialize;
use serde_json::Value;

use crate::evm_rpc::{
    JsonRpcRequest, JsonRpcResponse, MethodKind, RpcErrorObject, JSONRPC_BATCH_LIMIT,
    JSONRPC_VERSION,
};

pub const APPLICATION_JSON: &str = "application/json";
pub const MAX_BATCH_REQUESTS: usize = 20;

const PARSE_ERROR_MESSAGE: &str = "Parse error";
const INVALID_REQUEST_MESSAGE: &str = "Invalid Request";
const METHOD_NOT_FOUND_MESSAGE: &str = "Method not found";
const BATCH_LIMIT_MESSAGE: &str = "The batch request exceeded its limit of 20 requests";

#[derive(Clone, Debug)]
pub enum RouteEntry {
    Dynamic(MethodKind),
    StaticNetVersion(String),
    StaticWeb3ClientVersion(String),
}

#[async_trait::async_trait]
pub trait RoutedMethodHandler: Send + Sync {
    async fn dispatch_method(&self, method: MethodKind, request: &JsonRpcRequest) -> JsonRpcResponse<Value>;
}

#[derive(Clone)]
pub struct MethodRouter<H> {
    handler: Arc<H>,
    routes: BTreeMap<&'static str, RouteEntry>,
}

impl<H> MethodRouter<H>
where
    H: RoutedMethodHandler + 'static,
{
    pub fn new_router_service(
        handler: Arc<H>,
        net_version: Option<impl Into<String>>,
        web3_client_version: Option<impl Into<String>>,
    ) -> Self {
        let mut routes = build_route_table();
        if let Some(net_version) = net_version {
            routes.insert("net_version", RouteEntry::StaticNetVersion(net_version.into()));
        }
        if let Some(web3_client_version) = web3_client_version {
            routes.insert(
                "web3_clientVersion",
                RouteEntry::StaticWeb3ClientVersion(web3_client_version.into()),
            );
        }
        Self { handler, routes }
    }

    /// Recovered HTTP JSON-RPC entry point.
    ///
    /// The router parses the body as JSON, accepts either a single request object
    /// or a batch array, rejects empty batches as invalid requests, and rejects
    /// batches larger than twenty requests with error code `-32010`.
    pub async fn route_http_json_rpc(&self, body: Bytes) -> Response<Bytes> {
        let started_at = Instant::now();
        let payload = match serde_json::from_slice::<Value>(&body) {
            Ok(payload) => payload,
            Err(_) => {
                return json_response(JsonRpcResponse::<Value>::error(
                    Value::Null,
                    RpcErrorObject::new(-32700, PARSE_ERROR_MESSAGE),
                ));
            }
        };

        let response = match payload {
            Value::Array(batch) => self.route_batch(batch).await,
            value => self.route_one(value).await,
        };

        let _elapsed = started_at.elapsed();
        json_response(response)
    }

    pub async fn route_one(&self, value: Value) -> Value {
        self.route_jsonrpc_value(value).await
    }

    pub async fn route_batch(&self, requests: Vec<Value>) -> Value {
        if requests.is_empty() {
            return serde_json::to_value(JsonRpcResponse::<Value>::error(
                Value::Null,
                RpcErrorObject::new(-32600, INVALID_REQUEST_MESSAGE),
            ))
            .expect("serializing invalid-request batch response cannot fail");
        }

        if requests.len() > MAX_BATCH_REQUESTS {
            return serde_json::to_value(JsonRpcResponse::<Value>::error(
                Value::Null,
                RpcErrorObject::new(JSONRPC_BATCH_LIMIT, BATCH_LIMIT_MESSAGE),
            ))
            .expect("serializing batch-limit response cannot fail");
        }

        let mut replies = Vec::with_capacity(requests.len());
        for request in requests {
            replies.push(self.route_jsonrpc_value(request).await);
        }
        Value::Array(replies)
    }

    pub async fn route_jsonrpc_value(&self, value: Value) -> Value {
        let request = match JsonRpcRequest::from_value(value) {
            Ok(request) => request,
            Err(error) => {
                return serde_json::to_value(JsonRpcResponse::<Value>::error(error.id, error.error))
                    .expect("serializing JSON-RPC decode error cannot fail");
            }
        };

        let response = match self.routes.get(request.method.as_str()) {
            Some(RouteEntry::Dynamic(method)) => self.handler.dispatch_method(*method, &request).await,
            Some(RouteEntry::StaticNetVersion(value)) => {
                if !request_has_no_params(&request) {
                    JsonRpcResponse::error(
                        request.id.clone(),
                        RpcErrorObject::new(-32602, "expected no params"),
                    )
                } else {
                    JsonRpcResponse::success(request.id.clone(), Value::String(value.clone()))
                }
            }
            Some(RouteEntry::StaticWeb3ClientVersion(value)) => {
                if !request_has_no_params(&request) {
                    JsonRpcResponse::error(
                        request.id.clone(),
                        RpcErrorObject::new(-32602, "expected no params"),
                    )
                } else {
                    JsonRpcResponse::success(request.id.clone(), Value::String(value.clone()))
                }
            }
            None => JsonRpcResponse::error(
                request.id.clone(),
                RpcErrorObject::new(-32601, METHOD_NOT_FOUND_MESSAGE),
            ),
        };

        serde_json::to_value(response).expect("serializing JSON-RPC response cannot fail")
    }
}

pub fn build_route_table() -> BTreeMap<&'static str, RouteEntry> {
    let mut routes = BTreeMap::new();
    routes.insert("eth_blockNumber", RouteEntry::Dynamic(MethodKind::BlockNumber));
    routes.insert("eth_call", RouteEntry::Dynamic(MethodKind::Call));
    routes.insert("eth_chainId", RouteEntry::Dynamic(MethodKind::ChainId));
    routes.insert("eth_estimateGas", RouteEntry::Dynamic(MethodKind::EstimateGas));
    routes.insert("eth_feeHistory", RouteEntry::Dynamic(MethodKind::FeeHistory));
    routes.insert("eth_gasPrice", RouteEntry::Dynamic(MethodKind::GasPrice));
    routes.insert("eth_getBalance", RouteEntry::Dynamic(MethodKind::GetBalance));
    routes.insert("eth_getBlockByHash", RouteEntry::Dynamic(MethodKind::GetBlockByHash));
    routes.insert("eth_getBlockByNumber", RouteEntry::Dynamic(MethodKind::GetBlockByNumber));
    routes.insert("eth_getBlockReceipts", RouteEntry::Dynamic(MethodKind::GetBlockReceipts));
    routes.insert(
        "eth_getBlockTransactionCountByHash",
        RouteEntry::Dynamic(MethodKind::GetBlockTransactionCountByHash),
    );
    routes.insert(
        "eth_getBlockTransactionCountByNumber",
        RouteEntry::Dynamic(MethodKind::GetBlockTransactionCountByNumber),
    );
    routes.insert("eth_getCode", RouteEntry::Dynamic(MethodKind::GetCode));
    routes.insert("eth_getLogs", RouteEntry::Dynamic(MethodKind::GetLogs));
    routes.insert("eth_getStorageAt", RouteEntry::Dynamic(MethodKind::GetStorageAt));
    routes.insert(
        "eth_getTransactionByBlockHashAndIndex",
        RouteEntry::Dynamic(MethodKind::GetTransactionByBlockHashAndIndex),
    );
    routes.insert(
        "eth_getTransactionByBlockNumberAndIndex",
        RouteEntry::Dynamic(MethodKind::GetTransactionByBlockNumberAndIndex),
    );
    routes.insert("eth_getTransactionByHash", RouteEntry::Dynamic(MethodKind::GetTransactionByHash));
    routes.insert("eth_getTransactionCount", RouteEntry::Dynamic(MethodKind::GetTransactionCount));
    routes.insert("eth_getTransactionReceipt", RouteEntry::Dynamic(MethodKind::GetTransactionReceipt));
    routes.insert(
        "eth_maxPriorityFeePerGas",
        RouteEntry::Dynamic(MethodKind::MaxPriorityFeePerGas),
    );
    routes.insert("eth_syncing", RouteEntry::Dynamic(MethodKind::Syncing));
    routes.insert("eth_bigBlockGasPrice", RouteEntry::Dynamic(MethodKind::BigBlockGasPrice));
    routes.insert(
        "eth_getSystemTxsByBlockHash",
        RouteEntry::Dynamic(MethodKind::GetSystemTxsByBlockHash),
    );
    routes.insert(
        "eth_getSystemTxsByBlockNumber",
        RouteEntry::Dynamic(MethodKind::GetSystemTxsByBlockNumber),
    );
    routes.insert("eth_usingBigBlocks", RouteEntry::Dynamic(MethodKind::UsingBigBlocks));
    routes
}

fn request_has_no_params(request: &JsonRpcRequest) -> bool {
    match &request.params {
        Value::Null => true,
        Value::Array(values) => values.is_empty(),
        Value::Object(map) => map.is_empty(),
        _ => false,
    }
}

fn json_response(value: impl Serialize) -> Response<Bytes> {
    let body = serde_json::to_vec(&value).expect("serializing JSON-RPC HTTP response cannot fail");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .body(Bytes::from(body))
        .expect("building JSON-RPC HTTP response cannot fail")
}
