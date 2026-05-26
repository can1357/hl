use std::fmt;
use std::time::Duration;

use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http::{Method, Request, Uri};
use hyper::{Body, Client, Response};
use hyper_tls::HttpsConnector;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::time;

pub const JSONRPC_VERSION: &str = "2.0";
pub const ETH_SEND_RAW_TRANSACTION: &str = "eth_sendRawTransaction";
pub const APPLICATION_JSON: &str = "application/json";
pub const MAINNET_EVM_RPC_URL: &str = "http://rpc.hyperliquid.xyz/evm";
pub const TESTNET_EVM_RPC_URL: &str = "http://rpc.hyperliquid-testnet.xyz/evm";
pub const DEFAULT_FORWARD_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 128 * 1024;

const UNEXPECTED_FORWARD_ERROR_CODE: i64 = 30_000;
const JSONRPC_PARSE_ERROR: i64 = -32700;
const JSONRPC_INVALID_REQUEST: i64 = -32600;
const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
const JSONRPC_INVALID_PARAMS: i64 = -32602;
const JSONRPC_INTERNAL_ERROR: i64 = -32603;
const JSONRPC_SERVER_ERROR: i64 = -32007;
const JSONRPC_TIMEOUT: i64 = -32009;
const JSONRPC_FORWARD_ERROR: i64 = -32000;
const JSONRPC_RESPONSE_TOO_BIG: i64 = -32008;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvmForwardChain {
    Unsupported(u8),
    Testnet,
    Mainnet,
}

impl EvmForwardChain {
    pub fn from_selector(selector: u8) -> Self {
        match selector {
            2 => Self::Testnet,
            3..=u8::MAX => Self::Mainnet,
            other => Self::Unsupported(other),
        }
    }

    pub fn endpoint(self) -> Result<&'static str, ForwardError> {
        match self {
            Self::Testnet => Ok(TESTNET_EVM_RPC_URL),
            Self::Mainnet => Ok(MAINNET_EVM_RPC_URL),
            Self::Unsupported(selector) => Err(ForwardError::UnsupportedChain(selector)),
        }
    }
}

impl fmt::Display for EvmForwardChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvmForwardChain::Unsupported(selector) => write!(f, "{selector}"),
            EvmForwardChain::Testnet => f.write_str("testnet"),
            EvmForwardChain::Mainnet => f.write_str("mainnet"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct EvmRpcWriteForwarder {
    client: Client<HttpsConnector<hyper::client::HttpConnector>, Body>,
    chain: EvmForwardChain,
    timeout: Duration,
    max_response_bytes: usize,
    retry_policy: RetryPolicy,
    /// [INFERENCE] The write side can mirror accepted raw transactions into the
    /// node fast path when the embedding crate wires this sender.
    node_write_tx: Option<mpsc::UnboundedSender<NodeWriteForward>>,
    /// [INFERENCE] The same accepted transaction is also representable as an L1
    /// `EvmRawTx` handoff; the binary evidence for this file is the raw-tx method
    /// and JSON-RPC forwarding, while the channel name comes from local node/l1
    /// reconstructions.
    l1_write_tx: Option<mpsc::UnboundedSender<L1WriteForward>>,
}

impl EvmRpcWriteForwarder {
    pub fn new(
        client: Client<HttpsConnector<hyper::client::HttpConnector>, Body>,
        chain: EvmForwardChain,
    ) -> Self {
        Self {
            client,
            chain,
            timeout: DEFAULT_FORWARD_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            retry_policy: RetryPolicy::single_attempt(),
            node_write_tx: None,
            l1_write_tx: None,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    pub fn with_node_write_channel(mut self, tx: mpsc::UnboundedSender<NodeWriteForward>) -> Self {
        self.node_write_tx = Some(tx);
        self
    }

    pub fn with_l1_write_channel(mut self, tx: mpsc::UnboundedSender<L1WriteForward>) -> Self {
        self.l1_write_tx = Some(tx);
        self
    }

    pub async fn handle_json_rpc(&self, request: JsonRpcRequest<Value>) -> JsonRpcReply<Value> {
        if request.method != ETH_SEND_RAW_TRANSACTION {
            return JsonRpcReply::error(
                request.id,
                JsonRpcErrorObject::new(JSONRPC_METHOD_NOT_FOUND, "Method not found"),
            );
        }

        let raw_tx = match raw_transaction_param(&request.params) {
            Ok(raw_tx) => raw_tx,
            Err(error) => return JsonRpcReply::error(request.id, error.into_json_rpc_error()),
        };

        match self.forward_raw_transaction(raw_tx).await {
            Ok(forwarded) => JsonRpcReply::success(request.id, Value::String(forwarded.tx_hash)),
            Err(error) => JsonRpcReply::error(request.id, error.into_json_rpc_error()),
        }
    }

    pub async fn forward_raw_transaction(&self, raw_tx: &str) -> Result<ForwardedRawTransaction, ForwardError> {
        let mut attempt = 0usize;

        loop {
            attempt = attempt.saturating_add(1);
            match self.forward_raw_transaction_once(raw_tx).await {
                Ok(forwarded) => return Ok(forwarded),
                Err(error) if self.retry_policy.should_retry(attempt, &error) => continue,
                Err(error) => return Err(error),
            }
        }
    }

    async fn forward_raw_transaction_once(&self, raw_tx: &str) -> Result<ForwardedRawTransaction, ForwardError> {
        let endpoint = self.chain.endpoint().map_err(|error| {
            if let ForwardError::UnsupportedChain(selector) = error {
                log::error!(" @@ unsupported chain for evm rpc tx forwarding chain={selector}\n");
                ForwardError::UnexpectedCode(UNEXPECTED_FORWARD_ERROR_CODE)
            } else {
                error
            }
        })?;

        let request_body = OutboundRawTxRequest {
            jsonrpc: JSONRPC_VERSION,
            method: ETH_SEND_RAW_TRANSACTION,
            params: [raw_tx],
            id: 1,
        };
        let body = serde_json::to_vec(&request_body).map_err(ForwardError::SerializeRequest)?;
        let request = json_post_request(endpoint, Body::from(body))?;

        let response = self.send_request_with_timeout(request).await.map_err(|error| {
            log::error!(" @@ unable to forward raw transaction: {error}\n");
            error
        })?;
        let body = self.read_body_with_timeout(response).await.map_err(|error| {
            log::error!(" @@ unable to forward raw transaction: {error}\n");
            error
        })?;
        let response = parse_upstream_raw_tx_response(&body, self.max_response_bytes).map_err(|error| {
            log::error!(" @@ unable to parse raw transaction response: {error}\n");
            error
        })?;

        match response {
            UpstreamRawTxResponse::Hash(tx_hash) => {
                self.publish_forwarded(raw_tx, &tx_hash)?;
                Ok(ForwardedRawTransaction { raw_tx: raw_tx.to_owned(), tx_hash })
            }
            UpstreamRawTxResponse::Error(error) => Err(ForwardError::UpstreamJsonRpc(error)),
        }
    }

    async fn send_request_with_timeout(&self, request: Request<Body>) -> Result<Response<Body>, ForwardError> {
        match time::timeout(self.timeout, self.client.request(request)).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => Err(ForwardError::Send(error.to_string())),
            Err(_) => Err(ForwardError::Timeout),
        }
    }

    async fn read_body_with_timeout(&self, response: Response<Body>) -> Result<Bytes, ForwardError> {
        match time::timeout(self.timeout, hyper::body::to_bytes(response.into_body())).await {
            Ok(Ok(bytes)) => Ok(bytes),
            Ok(Err(error)) => Err(ForwardError::ReadBody(error.to_string())),
            Err(_) => Err(ForwardError::Timeout),
        }
    }

    fn publish_forwarded(&self, raw_tx: &str, tx_hash: &str) -> Result<(), ForwardError> {
        if let Some(tx) = &self.node_write_tx {
            tx.send(NodeWriteForward::ExternalTx {
                raw_tx: raw_tx.to_owned(),
                tx_hash: tx_hash.to_owned(),
            })
            .map_err(|_| ForwardError::NodeChannelClosed)?;
        }

        if let Some(tx) = &self.l1_write_tx {
            tx.send(L1WriteForward::EvmRawTx {
                raw_tx: raw_tx.to_owned(),
                tx_hash: tx_hash.to_owned(),
            })
            .map_err(|_| ForwardError::L1ChannelClosed)?;
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: usize,
    pub retry_timeouts: bool,
    pub retry_send_errors: bool,
}

impl RetryPolicy {
    pub const fn single_attempt() -> Self {
        Self { max_attempts: 1, retry_timeouts: false, retry_send_errors: false }
    }

    pub const fn retry_network(max_attempts: usize) -> Self {
        Self { max_attempts, retry_timeouts: true, retry_send_errors: true }
    }

    fn should_retry(self, completed_attempts: usize, error: &ForwardError) -> bool {
        if completed_attempts >= self.max_attempts {
            return false;
        }

        match error {
            ForwardError::Timeout => self.retry_timeouts,
            ForwardError::Send(_) | ForwardError::ReadBody(_) => self.retry_send_errors,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeWriteForward {
    ExternalTx { raw_tx: String, tx_hash: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum L1WriteForward {
    EvmRawTx { raw_tx: String, tx_hash: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForwardedRawTransaction {
    pub raw_tx: String,
    pub tx_hash: String,
}

#[derive(Debug)]
pub enum ForwardError {
    UnsupportedChain(u8),
    UnexpectedCode(i64),
    InvalidParams(&'static str),
    InvalidUri(String),
    SerializeRequest(serde_json::Error),
    Send(String),
    ReadBody(String),
    Timeout,
    ResponseTooBig { limit: usize },
    ParseResponse(serde_json::Error),
    InvalidTransactionResponse,
    UpstreamJsonRpc(JsonRpcErrorObject),
    NodeChannelClosed,
    L1ChannelClosed,
}

impl ForwardError {
    fn into_json_rpc_error(self) -> JsonRpcErrorObject {
        match self {
            ForwardError::InvalidParams(message) => JsonRpcErrorObject::new(JSONRPC_INVALID_PARAMS, message),
            ForwardError::UnsupportedChain(selector) => JsonRpcErrorObject::new(
                JSONRPC_FORWARD_ERROR,
                format!("unsupported chain for evm rpc tx forwarding chain={selector}"),
            ),
            ForwardError::UnexpectedCode(code) => {
                JsonRpcErrorObject::new(JSONRPC_FORWARD_ERROR, format!("Unexpected error (code={code})"))
            }
            ForwardError::InvalidUri(message) => JsonRpcErrorObject::new(JSONRPC_INTERNAL_ERROR, message),
            ForwardError::SerializeRequest(error) => {
                JsonRpcErrorObject::new(JSONRPC_INTERNAL_ERROR, format!("unable to forward raw transaction: {error}"))
            }
            ForwardError::Send(_) | ForwardError::ReadBody(_) => {
                JsonRpcErrorObject::new(JSONRPC_FORWARD_ERROR, "Unable to send transaction.")
            }
            ForwardError::Timeout => JsonRpcErrorObject::new(JSONRPC_TIMEOUT, "Unable to send transaction."),
            ForwardError::ResponseTooBig { limit } => {
                JsonRpcErrorObject::new(JSONRPC_RESPONSE_TOO_BIG, format!("Response is too big; max={limit}"))
            }
            ForwardError::ParseResponse(error) => {
                JsonRpcErrorObject::new(JSONRPC_FORWARD_ERROR, format!("Invalid transaction response. {error}"))
            }
            ForwardError::InvalidTransactionResponse => {
                JsonRpcErrorObject::new(JSONRPC_FORWARD_ERROR, "Invalid transaction response.")
            }
            ForwardError::UpstreamJsonRpc(error) => error,
            ForwardError::NodeChannelClosed | ForwardError::L1ChannelClosed => {
                JsonRpcErrorObject::new(JSONRPC_INTERNAL_ERROR, "Unable to send transaction.")
            }
        }
    }
}

impl fmt::Display for ForwardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ForwardError::UnsupportedChain(selector) => {
                write!(f, "unsupported chain for evm rpc tx forwarding chain={selector}")
            }
            ForwardError::UnexpectedCode(code) => write!(f, "Unexpected error (code={code})"),
            ForwardError::InvalidParams(message) => f.write_str(message),
            ForwardError::InvalidUri(message) => f.write_str(message),
            ForwardError::SerializeRequest(error) => write!(f, "unable to forward raw transaction: {error}"),
            ForwardError::Send(error) | ForwardError::ReadBody(error) => f.write_str(error),
            ForwardError::Timeout => f.write_str("timeout"),
            ForwardError::ResponseTooBig { limit } => write!(f, "Response is too big; max={limit}"),
            ForwardError::ParseResponse(error) => write!(f, "Invalid transaction response. {error}"),
            ForwardError::InvalidTransactionResponse => f.write_str("Invalid transaction response."),
            ForwardError::UpstreamJsonRpc(error) => fmt::Display::fmt(error, f),
            ForwardError::NodeChannelClosed => f.write_str("node write channel closed"),
            ForwardError::L1ChannelClosed => f.write_str("l1 write channel closed"),
        }
    }
}

impl std::error::Error for ForwardError {}

#[derive(Clone, Debug, Deserialize)]
pub struct JsonRpcRequest<T = Value> {
    #[serde(default)]
    pub jsonrpc: Option<String>,
    pub method: String,
    #[serde(default)]
    pub params: T,
    #[serde(default)]
    pub id: Value,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct JsonRpcReply<T = Value> {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcErrorObject>,
    pub id: Value,
}

impl<T> JsonRpcReply<T> {
    pub fn success(id: Value, result: T) -> Self {
        Self { jsonrpc: JSONRPC_VERSION, result: Some(result), error: None, id }
    }

    pub fn error(id: Value, error: JsonRpcErrorObject) -> Self {
        Self { jsonrpc: JSONRPC_VERSION, result: None, error: Some(error), id }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct JsonRpcErrorObject {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcErrorObject {
    pub fn new(message_code: i64, message: impl Into<String>) -> Self {
        Self { code: message_code, message: message.into(), data: None }
    }

    pub fn with_data(message_code: i64, message: impl Into<String>, data: Value) -> Self {
        Self { code: message_code, message: message.into(), data: Some(data) }
    }

    pub fn normalized_code(&self) -> i64 {
        match self.code {
            JSONRPC_PARSE_ERROR => JSONRPC_PARSE_ERROR,
            JSONRPC_INVALID_REQUEST => JSONRPC_INVALID_REQUEST,
            JSONRPC_METHOD_NOT_FOUND => JSONRPC_METHOD_NOT_FOUND,
            JSONRPC_INVALID_PARAMS => JSONRPC_INVALID_PARAMS,
            JSONRPC_INTERNAL_ERROR => JSONRPC_INTERNAL_ERROR,
            JSONRPC_SERVER_ERROR => JSONRPC_SERVER_ERROR,
            JSONRPC_TIMEOUT => JSONRPC_TIMEOUT,
            other => other,
        }
    }
}

impl fmt::Display for JsonRpcErrorObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JSON-RPC error {}: {}", self.code, self.message)
    }
}

#[derive(Serialize)]
struct OutboundRawTxRequest<'a> {
    jsonrpc: &'static str,
    method: &'static str,
    params: [&'a str; 1],
    id: u64,
}

#[derive(Deserialize)]
struct UpstreamJsonRpcEnvelope {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    #[allow(dead_code)]
    id: Option<Value>,
    #[serde(flatten)]
    payload: UpstreamJsonRpcPayload,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum UpstreamJsonRpcPayload {
    Result { result: Value },
    Error { error: JsonRpcErrorObject },
}

enum UpstreamRawTxResponse {
    Hash(String),
    Error(JsonRpcErrorObject),
}

fn json_post_request(url: &str, body: Body) -> Result<Request<Body>, ForwardError> {
    let uri = url
        .parse::<Uri>()
        .map_err(|error| ForwardError::InvalidUri(format!("could not parse url={url} err={error}")))?;

    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .body(body)
        .map_err(|error| ForwardError::Send(error.to_string()))
}

fn parse_upstream_raw_tx_response(bytes: &[u8], max_response_bytes: usize) -> Result<UpstreamRawTxResponse, ForwardError> {
    if bytes.len() > max_response_bytes {
        return Err(ForwardError::ResponseTooBig { limit: max_response_bytes });
    }

    let trimmed = trim_ascii_whitespace(bytes);
    let parsed: UpstreamJsonRpcEnvelope = serde_json::from_slice(trimmed).map_err(ForwardError::ParseResponse)?;

    match parsed.payload {
        UpstreamJsonRpcPayload::Result { result } => match result {
            Value::String(tx_hash) => Ok(UpstreamRawTxResponse::Hash(tx_hash)),
            _ => Err(ForwardError::InvalidTransactionResponse),
        },
        UpstreamJsonRpcPayload::Error { error } => Ok(UpstreamRawTxResponse::Error(error)),
    }
}

fn raw_transaction_param(params: &Value) -> Result<&str, ForwardError> {
    match params {
        Value::Array(values) => match values.first() {
            Some(Value::String(raw_tx)) => Ok(raw_tx.as_str()),
            Some(_) => Err(ForwardError::InvalidParams("Invalid transaction response.")),
            None => Err(ForwardError::InvalidParams("No more params")),
        },
        Value::String(raw_tx) => Ok(raw_tx.as_str()),
        Value::Null => Err(ForwardError::InvalidParams("No more params")),
        _ => Err(ForwardError::InvalidParams("Invalid transaction response.")),
    }
}

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|byte| !byte.is_ascii_whitespace()).unwrap_or(bytes.len());
    let end = bytes.iter().rposition(|byte| !byte.is_ascii_whitespace()).map_or(start, |idx| idx + 1);
    &bytes[start..end]
}
