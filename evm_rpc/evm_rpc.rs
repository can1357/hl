use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http::{Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Number, Value};

use crate::evm_write_forwarder::EvmRpcWriteForwarder;

pub const JSONRPC_VERSION: &str = "2.0";
pub const APPLICATION_JSON: &str = "application/json";
pub const MAX_BATCH_REQUESTS: usize = 20;

pub const JSONRPC_PARSE_ERROR: i64 = -32700;
pub const JSONRPC_INVALID_REQUEST: i64 = -32600;
pub const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
pub const JSONRPC_INVALID_PARAMS: i64 = -32602;
pub const JSONRPC_INTERNAL_ERROR: i64 = -32603;
pub const JSONRPC_BATCH_LIMIT: i64 = -32010;

const PARSE_ERROR_MESSAGE: &str = "Parse error";
const INVALID_REQUEST_MESSAGE: &str = "Invalid Request";
const METHOD_NOT_FOUND_MESSAGE: &str = "Method not found";
const BATCH_LIMIT_MESSAGE: &str = "The batch request exceeded its limit of 20 requests";

#[derive(Clone)]
pub struct EvmRpcServer {
    store: Arc<dyn EvmRpcStore>,
    write_forwarder: Option<Arc<EvmRpcWriteForwarder>>,
    routes: BTreeMap<&'static str, MethodKind>,
}

impl EvmRpcServer {
    pub fn new(store: Arc<dyn EvmRpcStore>) -> Self {
        Self { store, write_forwarder: None, routes: build_route_table() }
    }

    pub fn with_write_forwarder(mut self, forwarder: Arc<EvmRpcWriteForwarder>) -> Self {
        self.write_forwarder = Some(forwarder);
        self
    }

    /// Recovered HTTP entry point. The poll state machine at `0x202ec80` always
    /// produces status 200 with an `application/json` body once JSON-RPC routing
    /// has completed; transport-level failures are handled by the embedding HTTP
    /// server before this handler is reached.
    pub async fn handle_http_json_rpc(&self, body: Bytes) -> Response<Bytes> {
        let started_at = Instant::now();
        let body_value = match serde_json::from_slice::<Value>(&body) {
            Ok(value) => value,
            Err(_) => return json_response(JsonRpcResponse::error(Value::Null, RpcErrorObject::parse_error())),
        };

        let response = match body_value {
            Value::Array(requests) => self.handle_batch(requests).await,
            value => self.handle_one_value(value).await,
        };

        // The binary samples `Timespec::now()` before routing the request and
        // stores the elapsed timing alongside the response accounting state. The
        // logging sink is outside this file; retaining the measurement point here
        // preserves the recovered control-flow without fabricating a sink name.
        let _elapsed = started_at.elapsed();
        json_response(response)
    }

    async fn handle_batch(&self, requests: Vec<Value>) -> Value {
        if requests.is_empty() {
            return serde_json::to_value(JsonRpcResponse::<Value>::error(
                Value::Null,
                RpcErrorObject::invalid_request(),
            ))
            .expect("serializing JSON-RPC error response cannot fail");
        }

        if requests.len() > MAX_BATCH_REQUESTS {
            return serde_json::to_value(JsonRpcResponse::<Value>::error(
                Value::Null,
                RpcErrorObject::new(JSONRPC_BATCH_LIMIT, BATCH_LIMIT_MESSAGE),
            ))
            .expect("serializing JSON-RPC batch-limit error response cannot fail");
        }

        let mut replies = Vec::with_capacity(requests.len());
        for request in requests {
            replies.push(self.route_jsonrpc_value(request).await);
        }
        Value::Array(replies)
    }

    async fn handle_one_value(&self, value: Value) -> Value {
        self.route_jsonrpc_value(value).await
    }

    /// Recovered single-request dispatch. `0x2027610` first tries to preserve the
    /// incoming id for malformed requests, then hashes the exact method string in
    /// the route table. A miss emits `-32601` without falling through to any
    /// default method.
    async fn route_jsonrpc_value(&self, value: Value) -> Value {
        let request = match JsonRpcRequest::from_value(value) {
            Ok(request) => request,
            Err(error) => {
                return serde_json::to_value(JsonRpcResponse::<Value>::error(error.id, error.error))
                    .expect("serializing JSON-RPC request error cannot fail");
            }
        };

        let response = match self.routes.get(request.method.as_str()).copied() {
            Some(kind) => self.dispatch(kind, &request).await,
            None => JsonRpcResponse::error(request.id.clone(), RpcErrorObject::method_not_found()),
        };

        serde_json::to_value(response).expect("serializing JSON-RPC response cannot fail")
    }

    async fn dispatch(&self, method: MethodKind, request: &JsonRpcRequest) -> JsonRpcResponse<Value> {
        let id = request.id.clone();
        let result = match method {
            MethodKind::BlockNumber => self.eth_block_number(request).await,
            MethodKind::Call => self.eth_call(request).await,
            MethodKind::ChainId => self.eth_chain_id(request).await,
            MethodKind::EstimateGas => self.eth_estimate_gas(request).await,
            MethodKind::FeeHistory => self.eth_fee_history(request).await,
            MethodKind::GasPrice => self.eth_gas_price(request).await,
            MethodKind::GetBalance => self.eth_get_balance(request).await,
            MethodKind::GetBlockByHash => self.eth_get_block_by_hash(request).await,
            MethodKind::GetBlockByNumber => self.eth_get_block_by_number(request).await,
            MethodKind::GetBlockReceipts => self.eth_get_block_receipts(request).await,
            MethodKind::GetBlockTransactionCountByHash => {
                self.eth_get_block_transaction_count_by_hash(request).await
            }
            MethodKind::GetBlockTransactionCountByNumber => {
                self.eth_get_block_transaction_count_by_number(request).await
            }
            MethodKind::GetCode => self.eth_get_code(request).await,
            MethodKind::GetLogs => self.eth_get_logs(request).await,
            MethodKind::GetStorageAt => self.eth_get_storage_at(request).await,
            MethodKind::GetTransactionByBlockHashAndIndex => {
                self.eth_get_transaction_by_block_hash_and_index(request).await
            }
            MethodKind::GetTransactionByBlockNumberAndIndex => {
                self.eth_get_transaction_by_block_number_and_index(request).await
            }
            MethodKind::GetTransactionByHash => self.eth_get_transaction_by_hash(request).await,
            MethodKind::GetTransactionCount => self.eth_get_transaction_count(request).await,
            MethodKind::GetTransactionReceipt => self.eth_get_transaction_receipt(request).await,
            MethodKind::MaxPriorityFeePerGas => self.eth_max_priority_fee_per_gas(request).await,
            MethodKind::Syncing => self.eth_syncing(request).await,
            MethodKind::BigBlockGasPrice => self.eth_big_block_gas_price(request).await,
            MethodKind::GetSystemTxsByBlockHash => self.eth_get_system_txs_by_block_hash(request).await,
            MethodKind::GetSystemTxsByBlockNumber => self.eth_get_system_txs_by_block_number(request).await,
            MethodKind::UsingBigBlocks => self.eth_using_big_blocks(request).await,
            MethodKind::SendRawTransaction => self.eth_send_raw_transaction(request).await,
        };

        match result {
            Ok(value) => JsonRpcResponse::success(id, value),
            Err(error) => JsonRpcResponse::error(id, error.into_object()),
        }
    }

    async fn eth_block_number(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        no_params(request)?;
        Ok(hex_quantity(self.store.latest_block_number().await?))
    }

    async fn eth_chain_id(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        no_params(request)?;
        Ok(hex_quantity(self.store.chain_id()))
    }

    async fn eth_syncing(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        no_params(request)?;
        Ok(Value::Bool(false))
    }

    async fn eth_gas_price(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        no_params(request)?;
        Ok(hex_quantity(self.store.gas_price().await?))
    }

    async fn eth_max_priority_fee_per_gas(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        no_params(request)?;
        Ok(hex_quantity(self.store.max_priority_fee_per_gas().await?))
    }

    async fn eth_big_block_gas_price(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        no_params(request)?;
        Ok(hex_quantity(self.store.big_block_gas_price().await?))
    }

    async fn eth_using_big_blocks(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        no_params(request)?;
        Ok(Value::Bool(self.store.using_big_blocks().await?))
    }

    async fn eth_get_balance(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let address = parse_address(param(request, 0, "address")?)?;
        let block = parse_optional_block(param_opt(request, 1, "block")?)?;
        Ok(hex_quantity_u256(self.store.balance(address, block).await?))
    }

    async fn eth_get_transaction_count(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let address = parse_address(param(request, 0, "address")?)?;
        let block = parse_optional_block(param_opt(request, 1, "block")?)?;
        Ok(hex_quantity(self.store.transaction_count(address, block).await?))
    }

    async fn eth_get_code(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let address = parse_address(param(request, 0, "address")?)?;
        let block = parse_optional_block(param_opt(request, 1, "block")?)?;
        Ok(Value::String(self.store.code(address, block).await?))
    }

    async fn eth_get_storage_at(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let address = parse_address(param(request, 0, "address")?)?;
        let slot = parse_b256(param(request, 1, "position")?)?;
        let block = parse_optional_block(param_opt(request, 2, "block")?)?;
        Ok(Value::String(self.store.storage_at(address, slot, block).await?))
    }

    async fn eth_call(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let call = parse_call_request(param(request, 0, "request")?)?;
        let block = parse_optional_block(param_opt(request, 1, "block")?)?;
        self.store.call(call, block).await
    }

    async fn eth_estimate_gas(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let call = parse_call_request(param(request, 0, "request")?)?;
        let block = parse_optional_block(param_opt(request, 1, "block")?)?;
        Ok(hex_quantity(self.store.estimate_gas(call, block).await?))
    }

    async fn eth_fee_history(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let raw_count = parse_u64(param(request, 0, "block_count")?)?;
        let block_count = raw_count.min(5);
        let newest_block = parse_block_number_or_tag(param(request, 1, "newest_block")?)?;
        let reward_percentiles = parse_optional_reward_percentiles(param_opt(request, 2, "reward_percentiles")?)?;
        if let Some(percentiles) = &reward_percentiles {
            validate_reward_percentiles(percentiles)?;
        }
        self.store.fee_history(block_count, newest_block, reward_percentiles).await
    }

    async fn eth_get_block_by_number(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let number = parse_block_number_or_tag(param(request, 0, "number")?)?;
        let full = parse_bool(param(request, 1, "full")?)?;
        self.store.block_by_number(number, full).await
    }

    async fn eth_get_block_by_hash(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let hash = parse_b256(param(request, 0, "hash")?)?;
        let full = parse_bool(param(request, 1, "full")?)?;
        self.store.block_by_hash(hash, full).await
    }

    async fn eth_get_block_receipts(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let block = parse_block_id(param(request, 0, "block")?)?;
        self.store.block_receipts(block).await
    }

    async fn eth_get_block_transaction_count_by_number(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let number = parse_block_number_or_tag(param(request, 0, "number")?)?;
        Ok(nullable_hex_quantity(self.store.block_transaction_count_by_number(number).await?))
    }

    async fn eth_get_block_transaction_count_by_hash(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let hash = parse_b256(param(request, 0, "hash")?)?;
        Ok(nullable_hex_quantity(self.store.block_transaction_count_by_hash(hash).await?))
    }

    async fn eth_get_transaction_by_block_number_and_index(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let number = parse_block_number_or_tag(param(request, 0, "number")?)?;
        let index = parse_index(param(request, 1, "index")?)?;
        self.store.transaction_by_block_number_and_index(number, index).await
    }

    async fn eth_get_transaction_by_block_hash_and_index(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let hash = parse_b256(param(request, 0, "hash")?)?;
        let index = parse_index(param(request, 1, "index")?)?;
        self.store.transaction_by_block_hash_and_index(hash, index).await
    }

    async fn eth_get_transaction_by_hash(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let hash = parse_b256(param(request, 0, "hash")?)?;
        self.store.transaction_by_hash(hash).await
    }

    async fn eth_get_transaction_receipt(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let hash = parse_b256(param(request, 0, "hash")?)?;
        self.store.transaction_receipt(hash).await
    }

    async fn eth_get_logs(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let filter = parse_filter(param(request, 0, "filter")?)?;
        self.store.logs(filter).await
    }

    async fn eth_get_system_txs_by_block_number(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let number = parse_block_number_or_tag(param(request, 0, "number")?)?;
        self.store.system_txs_by_block_number(number).await
    }

    async fn eth_get_system_txs_by_block_hash(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let hash = parse_b256(param(request, 0, "hash")?)?;
        self.store.system_txs_by_block_hash(hash).await
    }

    async fn eth_send_raw_transaction(&self, request: &JsonRpcRequest) -> Result<Value, RpcError> {
        let Some(forwarder) = &self.write_forwarder else {
            return Err(RpcError::method_not_found());
        };
        // `eth_sendRawTransaction` is recovered in the write-forwarder unit, but
        // the public router keeps it in the same JSON-RPC namespace.
        let raw = parse_hex_string(param(request, 0, "raw_transaction")?, "raw_transaction")?;
        match forwarder.forward_raw_transaction(raw).await {
            Ok(forwarded) => Ok(Value::String(forwarded.tx_hash)),
            Err(error) => Err(RpcError::internal(error.to_string())),
        }
    }
}

pub fn build_route_table() -> BTreeMap<&'static str, MethodKind> {
    let mut routes = BTreeMap::new();
    routes.insert("eth_blockNumber", MethodKind::BlockNumber);
    routes.insert("eth_call", MethodKind::Call);
    routes.insert("eth_chainId", MethodKind::ChainId);
    routes.insert("eth_estimateGas", MethodKind::EstimateGas);
    routes.insert("eth_feeHistory", MethodKind::FeeHistory);
    routes.insert("eth_gasPrice", MethodKind::GasPrice);
    routes.insert("eth_getBalance", MethodKind::GetBalance);
    routes.insert("eth_getBlockByHash", MethodKind::GetBlockByHash);
    routes.insert("eth_getBlockByNumber", MethodKind::GetBlockByNumber);
    routes.insert("eth_getBlockReceipts", MethodKind::GetBlockReceipts);
    routes.insert("eth_getBlockTransactionCountByHash", MethodKind::GetBlockTransactionCountByHash);
    routes.insert("eth_getBlockTransactionCountByNumber", MethodKind::GetBlockTransactionCountByNumber);
    routes.insert("eth_getCode", MethodKind::GetCode);
    routes.insert("eth_getLogs", MethodKind::GetLogs);
    routes.insert("eth_getStorageAt", MethodKind::GetStorageAt);
    routes.insert("eth_getTransactionByBlockHashAndIndex", MethodKind::GetTransactionByBlockHashAndIndex);
    routes.insert("eth_getTransactionByBlockNumberAndIndex", MethodKind::GetTransactionByBlockNumberAndIndex);
    routes.insert("eth_getTransactionByHash", MethodKind::GetTransactionByHash);
    routes.insert("eth_getTransactionCount", MethodKind::GetTransactionCount);
    routes.insert("eth_getTransactionReceipt", MethodKind::GetTransactionReceipt);
    routes.insert("eth_maxPriorityFeePerGas", MethodKind::MaxPriorityFeePerGas);
    routes.insert("eth_syncing", MethodKind::Syncing);
    routes.insert("eth_bigBlockGasPrice", MethodKind::BigBlockGasPrice);
    routes.insert("eth_getSystemTxsByBlockHash", MethodKind::GetSystemTxsByBlockHash);
    routes.insert("eth_getSystemTxsByBlockNumber", MethodKind::GetSystemTxsByBlockNumber);
    routes.insert("eth_usingBigBlocks", MethodKind::UsingBigBlocks);
    routes
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MethodKind {
    BlockNumber,
    Call,
    ChainId,
    EstimateGas,
    FeeHistory,
    GasPrice,
    GetBalance,
    GetBlockByHash,
    GetBlockByNumber,
    GetBlockReceipts,
    GetBlockTransactionCountByHash,
    GetBlockTransactionCountByNumber,
    GetCode,
    GetLogs,
    GetStorageAt,
    GetTransactionByBlockHashAndIndex,
    GetTransactionByBlockNumberAndIndex,
    GetTransactionByHash,
    GetTransactionCount,
    GetTransactionReceipt,
    MaxPriorityFeePerGas,
    Syncing,
    BigBlockGasPrice,
    GetSystemTxsByBlockHash,
    GetSystemTxsByBlockNumber,
    UsingBigBlocks,
    SendRawTransaction,
}

#[async_trait::async_trait]
pub trait EvmRpcStore: Send + Sync {
    fn chain_id(&self) -> u64;
    async fn latest_block_number(&self) -> Result<u64, RpcError>;
    async fn gas_price(&self) -> Result<u64, RpcError>;
    async fn max_priority_fee_per_gas(&self) -> Result<u64, RpcError>;
    async fn big_block_gas_price(&self) -> Result<u64, RpcError>;
    async fn using_big_blocks(&self) -> Result<bool, RpcError>;
    async fn balance(&self, address: Address, block: Option<BlockId>) -> Result<U256Hex, RpcError>;
    async fn transaction_count(&self, address: Address, block: Option<BlockId>) -> Result<u64, RpcError>;
    async fn code(&self, address: Address, block: Option<BlockId>) -> Result<String, RpcError>;
    async fn storage_at(&self, address: Address, slot: B256, block: Option<BlockId>) -> Result<String, RpcError>;
    async fn call(&self, call: CallRequest, block: Option<BlockId>) -> Result<Value, RpcError>;
    async fn estimate_gas(&self, call: CallRequest, block: Option<BlockId>) -> Result<u64, RpcError>;
    async fn fee_history(&self, block_count: u64, newest_block: BlockNumberOrTag, reward_percentiles: Option<Vec<f64>>) -> Result<Value, RpcError>;
    async fn block_by_number(&self, number: BlockNumberOrTag, full_transactions: bool) -> Result<Value, RpcError>;
    async fn block_by_hash(&self, hash: B256, full_transactions: bool) -> Result<Value, RpcError>;
    async fn block_receipts(&self, block: BlockId) -> Result<Value, RpcError>;
    async fn block_transaction_count_by_number(&self, number: BlockNumberOrTag) -> Result<Option<u64>, RpcError>;
    async fn block_transaction_count_by_hash(&self, hash: B256) -> Result<Option<u64>, RpcError>;
    async fn transaction_by_block_number_and_index(&self, number: BlockNumberOrTag, index: u64) -> Result<Value, RpcError>;
    async fn transaction_by_block_hash_and_index(&self, hash: B256, index: u64) -> Result<Value, RpcError>;
    async fn transaction_by_hash(&self, hash: B256) -> Result<Value, RpcError>;
    async fn transaction_receipt(&self, hash: B256) -> Result<Value, RpcError>;
    async fn logs(&self, filter: LogFilter) -> Result<Value, RpcError>;
    async fn system_txs_by_block_number(&self, number: BlockNumberOrTag) -> Result<Value, RpcError>;
    async fn system_txs_by_block_hash(&self, hash: B256) -> Result<Value, RpcError>;
}

#[derive(Clone, Debug)]
pub struct JsonRpcRequest {
    pub jsonrpc: Option<String>,
    pub method: String,
    pub params: Value,
    pub id: Value,
}

impl JsonRpcRequest {
    fn from_value(value: Value) -> Result<Self, RequestDecodeError> {
        let id = extract_id_for_error(&value);
        let Value::Object(mut object) = value else {
            return Err(RequestDecodeError::new(id, RpcErrorObject::invalid_request()));
        };

        let method = match object.remove("method") {
            Some(Value::String(method)) if !method.is_empty() => method,
            _ => return Err(RequestDecodeError::new(id, RpcErrorObject::invalid_request())),
        };

        if let Some(version) = object.remove("jsonrpc") {
            if version != Value::String(JSONRPC_VERSION.to_owned()) {
                return Err(RequestDecodeError::new(id, RpcErrorObject::invalid_request()));
            }
        }

        let params = object.remove("params").unwrap_or(Value::Array(Vec::new()));
        let id = object.remove("id").unwrap_or(Value::Null);
        Ok(Self { jsonrpc: Some(JSONRPC_VERSION.to_owned()), method, params, id })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct JsonRpcResponse<T = Value> {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcErrorObject>,
    pub id: Value,
}

impl<T> JsonRpcResponse<T> {
    pub fn success(id: Value, result: T) -> Self {
        Self { jsonrpc: JSONRPC_VERSION, result: Some(result), error: None, id }
    }

    pub fn error(id: Value, error: RpcErrorObject) -> Self {
        Self { jsonrpc: JSONRPC_VERSION, result: None, error: Some(error), id }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct RpcErrorObject {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcErrorObject {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), data: None }
    }

    pub fn with_data(code: i64, message: impl Into<String>, data: Value) -> Self {
        Self { code, message: message.into(), data: Some(data) }
    }

    pub fn parse_error() -> Self {
        Self::new(JSONRPC_PARSE_ERROR, PARSE_ERROR_MESSAGE)
    }

    pub fn invalid_request() -> Self {
        Self::new(JSONRPC_INVALID_REQUEST, INVALID_REQUEST_MESSAGE)
    }

    pub fn method_not_found() -> Self {
        Self::new(JSONRPC_METHOD_NOT_FOUND, METHOD_NOT_FOUND_MESSAGE)
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(JSONRPC_INVALID_PARAMS, message)
    }
}

#[derive(Clone, Debug)]
pub struct RpcError {
    object: RpcErrorObject,
}

impl RpcError {
    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self { object: RpcErrorObject::invalid_params(message) }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self { object: RpcErrorObject::new(JSONRPC_INTERNAL_ERROR, message) }
    }

    pub fn method_not_found() -> Self {
        Self { object: RpcErrorObject::method_not_found() }
    }

    pub fn into_object(self) -> RpcErrorObject {
        self.object
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JSON-RPC error {}: {}", self.object.code, self.object.message)
    }
}

impl std::error::Error for RpcError {}

#[derive(Clone, Debug)]
struct RequestDecodeError {
    id: Value,
    error: RpcErrorObject,
}

impl RequestDecodeError {
    fn new(id: Value, error: RpcErrorObject) -> Self {
        Self { id, error }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockNumberOrTag {
    Number(u64),
    Latest,
    Earliest,
    Pending,
    Safe,
    Finalized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockId {
    Number(BlockNumberOrTag),
    Hash(B256),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address(pub [u8; 20]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct B256(pub [u8; 32]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct U256Hex(pub String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallRequest {
    pub from: Option<Address>,
    pub to: Option<Address>,
    pub gas: Option<u64>,
    pub gas_price: Option<u64>,
    pub value: Option<U256Hex>,
    pub data: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogFilter {
    pub from_block: Option<BlockNumberOrTag>,
    pub to_block: Option<BlockNumberOrTag>,
    pub block_hash: Option<B256>,
    pub address: Option<FilterAddress>,
    pub topics: Vec<Option<Vec<B256>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FilterAddress {
    One(Address),
    Many(Vec<Address>),
}

fn extract_id_for_error(value: &Value) -> Value {
    match value {
        Value::Object(object) => object.get("id").cloned().unwrap_or(Value::Null),
        _ => Value::Null,
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

fn no_params(request: &JsonRpcRequest) -> Result<(), RpcError> {
    match &request.params {
        Value::Null => Ok(()),
        Value::Array(params) if params.is_empty() => Ok(()),
        Value::Object(params) if params.is_empty() => Ok(()),
        _ => Err(RpcError::invalid_params("expected no params")),
    }
}

fn param<'a>(request: &'a JsonRpcRequest, index: usize, name: &'static str) -> Result<&'a Value, RpcError> {
    match &request.params {
        Value::Array(params) => params
            .get(index)
            .ok_or_else(|| RpcError::invalid_params(format!("missing parameter `{name}`"))),
        Value::Object(params) => params
            .get(name)
            .ok_or_else(|| RpcError::invalid_params(format!("missing parameter `{name}`"))),
        Value::Null => Err(RpcError::invalid_params(format!("missing parameter `{name}`"))),
        _ => Err(RpcError::invalid_params("params must be an array or object")),
    }
}

fn param_opt<'a>(request: &'a JsonRpcRequest, index: usize, name: &'static str) -> Result<Option<&'a Value>, RpcError> {
    match &request.params {
        Value::Array(params) => Ok(params.get(index)),
        Value::Object(params) => Ok(params.get(name)),
        Value::Null => Ok(None),
        _ => Err(RpcError::invalid_params("params must be an array or object")),
    }
}

fn parse_block_number_or_tag(value: &Value) -> Result<BlockNumberOrTag, RpcError> {
    let Value::String(s) = value else {
        return Err(type_error("number", "BlockNumberOrTag"));
    };
    match s.as_str() {
        "latest" => Ok(BlockNumberOrTag::Latest),
        "earliest" => Ok(BlockNumberOrTag::Earliest),
        "pending" => Ok(BlockNumberOrTag::Pending),
        "safe" => Ok(BlockNumberOrTag::Safe),
        "finalized" => Ok(BlockNumberOrTag::Finalized),
        _ => parse_hex_u64(s, "number").map(BlockNumberOrTag::Number),
    }
}

fn parse_optional_block(value: Option<&Value>) -> Result<Option<BlockId>, RpcError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => parse_block_id(value).map(Some),
    }
}

fn parse_block_id(value: &Value) -> Result<BlockId, RpcError> {
    match value {
        Value::String(_) => parse_block_number_or_tag(value).map(BlockId::Number),
        Value::Object(object) => {
            if let Some(hash) = object.get("blockHash") {
                return parse_b256(hash).map(BlockId::Hash);
            }
            if let Some(number) = object.get("blockNumber") {
                return parse_block_number_or_tag(number).map(BlockId::Number);
            }
            Err(RpcError::invalid_params("BlockId must contain blockHash or blockNumber"))
        }
        _ => Err(type_error("block", "BlockId")),
    }
}

fn parse_address(value: &Value) -> Result<Address, RpcError> {
    let s = parse_hex_string(value, "address")?;
    let bytes = parse_fixed_hex::<20>(s, "address")?;
    Ok(Address(bytes))
}

fn parse_b256(value: &Value) -> Result<B256, RpcError> {
    let s = parse_hex_string(value, "hash")?;
    let bytes = parse_fixed_hex::<32>(s, "B256")?;
    Ok(B256(bytes))
}

fn parse_index(value: &Value) -> Result<u64, RpcError> {
    match value {
        Value::String(s) => parse_hex_u64(s, "index"),
        Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| RpcError::invalid_params("index must fit in u64")),
        _ => Err(type_error("index", "Index")),
    }
}

fn parse_bool(value: &Value) -> Result<bool, RpcError> {
    match value {
        Value::Bool(value) => Ok(*value),
        _ => Err(type_error("full", "bool")),
    }
}

fn parse_u64(value: &Value) -> Result<u64, RpcError> {
    match value {
        Value::String(s) => parse_hex_u64(s, "u64"),
        Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| RpcError::invalid_params("number must fit in u64")),
        _ => Err(type_error("value", "u64")),
    }
}

fn parse_optional_reward_percentiles(value: Option<&Value>) -> Result<Option<Vec<f64>>, RpcError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(values)) => {
            let mut out = Vec::with_capacity(values.len());
            for value in values {
                let Some(percentile) = value.as_f64() else {
                    return Err(type_error("reward_percentiles", "Option < Vec < f64 > >"));
                };
                out.push(percentile);
            }
            Ok(Some(out))
        }
        Some(_) => Err(type_error("reward_percentiles", "Option < Vec < f64 > >")),
    }
}

fn validate_reward_percentiles(percentiles: &[f64]) -> Result<(), RpcError> {
    let mut previous = None;
    for percentile in percentiles {
        if !(0.0..=100.0).contains(percentile) {
            return Err(RpcError::invalid_params("reward percentiles must be in [0, 100]"));
        }
        if let Some(previous) = previous {
            if *percentile < previous {
                return Err(RpcError::invalid_params("reward percentiles must be sorted"));
            }
        }
        previous = Some(*percentile);
    }
    Ok(())
}

fn parse_call_request(value: &Value) -> Result<CallRequest, RpcError> {
    let Value::Object(object) = value else {
        return Err(RpcError::invalid_params("call request must be an object"));
    };
    Ok(CallRequest {
        from: parse_optional_address(object.get("from"))?,
        to: parse_optional_address(object.get("to"))?,
        gas: parse_optional_quantity(object.get("gas"))?,
        gas_price: parse_optional_quantity(object.get("gasPrice"))?,
        value: parse_optional_u256(object.get("value"))?,
        data: parse_data_field(object)?,
    })
}

fn parse_filter(value: &Value) -> Result<LogFilter, RpcError> {
    let Value::Object(object) = value else {
        return Err(type_error("filter", "filter"));
    };
    Ok(LogFilter {
        from_block: parse_optional_block_number_or_tag(object.get("fromBlock"))?,
        to_block: parse_optional_block_number_or_tag(object.get("toBlock"))?,
        block_hash: parse_optional_b256(object.get("blockHash"))?,
        address: parse_filter_address(object.get("address"))?,
        topics: parse_topics(object.get("topics"))?,
    })
}

fn parse_optional_block_number_or_tag(value: Option<&Value>) -> Result<Option<BlockNumberOrTag>, RpcError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => parse_block_number_or_tag(value).map(Some),
    }
}

fn parse_optional_b256(value: Option<&Value>) -> Result<Option<B256>, RpcError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => parse_b256(value).map(Some),
    }
}

fn parse_optional_address(value: Option<&Value>) -> Result<Option<Address>, RpcError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => parse_address(value).map(Some),
    }
}

fn parse_optional_quantity(value: Option<&Value>) -> Result<Option<u64>, RpcError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => parse_u64(value).map(Some),
    }
}

fn parse_optional_u256(value: Option<&Value>) -> Result<Option<U256Hex>, RpcError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => Ok(Some(U256Hex(parse_hex_string(value, "value")?.to_owned()))),
    }
}

fn parse_data_field(object: &Map<String, Value>) -> Result<Option<String>, RpcError> {
    match (object.get("data"), object.get("input")) {
        (Some(value), _) | (None, Some(value)) => Ok(Some(parse_hex_string(value, "data")?.to_owned())),
        (None, None) => Ok(None),
    }
}

fn parse_filter_address(value: Option<&Value>) -> Result<Option<FilterAddress>, RpcError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(values)) => {
            let mut out = Vec::with_capacity(values.len());
            for value in values {
                out.push(parse_address(value)?);
            }
            Ok(Some(FilterAddress::Many(out)))
        }
        Some(value) => parse_address(value).map(FilterAddress::One).map(Some),
    }
}

fn parse_topics(value: Option<&Value>) -> Result<Vec<Option<Vec<B256>>>, RpcError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Value::Array(topics) = value else {
        return Err(RpcError::invalid_params("topics must be an array"));
    };

    let mut parsed = Vec::with_capacity(topics.len());
    for topic in topics {
        match topic {
            Value::Null => parsed.push(None),
            Value::String(_) => parsed.push(Some(vec![parse_b256(topic)?])),
            Value::Array(alternatives) => {
                let mut parsed_alternatives = Vec::with_capacity(alternatives.len());
                for alternative in alternatives {
                    parsed_alternatives.push(parse_b256(alternative)?);
                }
                parsed.push(Some(parsed_alternatives));
            }
            _ => return Err(RpcError::invalid_params("topic must be null, a hash, or an array of hashes")),
        }
    }
    Ok(parsed)
}

fn parse_hex_string<'a>(value: &'a Value, field: &'static str) -> Result<&'a str, RpcError> {
    let Value::String(s) = value else {
        return Err(type_error(field, "hex string"));
    };
    if !s.starts_with("0x") {
        return Err(RpcError::invalid_params(format!("{field} must start with 0x")));
    }
    Ok(s)
}

fn parse_hex_u64(s: &str, field: &'static str) -> Result<u64, RpcError> {
    let Some(hex) = s.strip_prefix("0x") else {
        return Err(RpcError::invalid_params(format!("{field} must start with 0x")));
    };
    if hex.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(hex, 16).map_err(|_| RpcError::invalid_params(format!("{field} must fit in u64")))
}

fn parse_fixed_hex<const N: usize>(s: &str, field: &'static str) -> Result<[u8; N], RpcError> {
    let Some(hex) = s.strip_prefix("0x") else {
        return Err(RpcError::invalid_params(format!("{field} must start with 0x")));
    };
    if hex.len() != N * 2 {
        return Err(RpcError::invalid_params(format!("{field} must be {N} bytes")));
    }
    let mut out = [0u8; N];
    for index in 0..N {
        let start = index * 2;
        out[index] = u8::from_str_radix(&hex[start..start + 2], 16)
            .map_err(|_| RpcError::invalid_params(format!("{field} contains non-hex characters")))?;
    }
    Ok(out)
}

fn type_error(field: &'static str, expected: &'static str) -> RpcError {
    // Mirrors the recovered parse-error helper shape: field name plus the expected
    // Rust type string, e.g. `number`/`BlockNumberOrTag`, `hash`/`B256`,
    // `index`/`Index`, `full`/`bool`, and `filter`/`filter`.
    RpcError::invalid_params(format!("invalid parameter `{field}`: expected {expected}"))
}

fn hex_quantity(value: u64) -> Value {
    Value::String(format!("0x{value:x}"))
}

fn nullable_hex_quantity(value: Option<u64>) -> Value {
    match value {
        Some(value) => hex_quantity(value),
        None => Value::Null,
    }
}

fn hex_quantity_u256(value: U256Hex) -> Value {
    Value::String(value.0)
}

fn number_to_value(value: u64) -> Value {
    Value::Number(Number::from(value))
}

pub fn fee_history_response(
    oldest_block: u64,
    base_fee_per_gas: Vec<u64>,
    gas_used_ratio: Vec<f64>,
    reward: Option<Vec<Vec<u64>>>,
) -> Value {
    let mut object = Map::new();
    object.insert("oldestBlock".to_owned(), hex_quantity(oldest_block));
    object.insert(
        "baseFeePerGas".to_owned(),
        Value::Array(base_fee_per_gas.into_iter().map(hex_quantity).collect()),
    );
    object.insert(
        "gasUsedRatio".to_owned(),
        Value::Array(gas_used_ratio.into_iter().map(|value| json!(value)).collect()),
    );
    if let Some(reward) = reward {
        object.insert(
            "reward".to_owned(),
            Value::Array(
                reward
                    .into_iter()
                    .map(|row| Value::Array(row.into_iter().map(hex_quantity).collect()))
                    .collect(),
            ),
        );
    }
    Value::Object(object)
}

pub fn block_transaction_count_response(count: Option<u64>) -> Value {
    nullable_hex_quantity(count)
}

pub fn system_txs_response(transactions: Vec<Value>) -> Value {
    Value::Array(transactions)
}
