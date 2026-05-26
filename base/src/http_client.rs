//! Reconstruction of `/home/ubuntu/hl/code_Mainnet/base/src/http_client.rs`.
//!
//! Confidence: medium-high for the default client construction, timeout constants,
//! request/response error strings, exchange endpoint construction, and JSON-RPC raw
//! transaction wrapper; medium for source-level names and the exact public type layout.
//!
//! Seed EAs:
//!   - `0x1439010` — constructs the Hyper HTTPS client wrapper. The wrapper stores
//!     `Some(10.0)` at offsets `+0xb8/+0xc0`; the native TLS builder `.build().unwrap()`
//!     panic is sourced to `http_client.rs:24:67`.
//!   - `0x1611910` — async poll state machine for an EVM JSON-RPC
//!     `eth_sendRawTransaction` POST; constructs JSON fields `jsonrpc`, `method`,
//!     `params`, and `id`, posts `application/json`, trims response whitespace, and
//!     maps JSON-RPC error objects.
//!   - `0x2272c80` — async poll state machine for startup/gossip exchange POSTs;
//!     formats `http{ApiUrl::http_suffix_string()}exchange`, logs request and response,
//!     wraps both send and body-read futures in the same f64 seconds timeout.
//!
//! IDA tags applied in this pass: none; the central IDA queue was full. Pending exact
//! tags are listed near the recovered functions below.

use std::fmt;
use std::time::Duration;

use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http::{Method, Request, Uri};
use hyper::body::to_bytes;
use hyper::{Body, Client, Response};
use hyper_tls::HttpsConnector;
use native_tls::TlsConnector;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::time;

use crate::api_url::ApiUrl;

/// Default per-request timeout stored by `base_http_client__build_hyper_client`.
///
/// IDA: `0x143927a..0x143928b` writes IEEE-754 `10.0` to wrapper offset `+0xb8`
/// and sets the option/discriminant byte at `+0xc0` to `1`.
pub const DEFAULT_REQUEST_TIMEOUT_SECS: f64 = 10.0;

const HTTP_SEND_REQUEST_RAW: &str = "http_send_request_raw:";
const HTTP_READ_BODY: &str = "http_read_body:";
const APPLICATION_JSON: &str = "application/json";
const EXCHANGE_ENDPOINT: &str = "exchange";
const MAINNET_EVM_RPC_URL: &str = "http://rpc.hyperliquid.xyz/evm";
const TESTNET_EVM_RPC_URL: &str = "http://rpc.hyperliquid-testnet.xyz/evm";

/// Minimal recovered wrapper around the Hyper client.
///
/// IDA layout evidence: `0x1439010` stores the Hyper client in the first `0xb8`
/// bytes and stores the request-timeout option immediately after it. Seed
/// `0x1611910` also reads a compact chain/API selector from the captured wrapper
/// around offset `+0xc8`; exact padding/field order is compiler-specific and not
/// represented here.
pub struct HttpClient {
    client: Client<HttpsConnector<hyper::client::HttpConnector>, Body>,
    request_timeout_secs: Option<f64>,
    /// [INFERENCE] Source-level name for the compact selector read by `0x1611910`.
    chain: HttpClientChain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpClientChain {
    /// Selectors `0` and `1` are rejected by the EVM forwarding helper.
    Unsupported(u8),
    Testnet,
    Mainnet,
}

impl fmt::Display for HttpClientChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpClientChain::Unsupported(selector) => write!(f, "{selector}"),
            HttpClientChain::Testnet => f.write_str("Testnet"),
            HttpClientChain::Mainnet => f.write_str("Mainnet"),
        }
    }
}

/// Compact startup exchange endpoint selector recovered from the lookup table at
/// `0x2272ce6` (`[6, 4, 3, 2]` as `u16` ApiUrl discriminants).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExchangeApiTarget {
    Localhost,
    WebSandbox,
    Testnet,
    Mainnet,
}

impl ExchangeApiTarget {
    /// Convert the compact startup selector into the `ApiUrl` branch consumed by
    /// `base_api_url__http_suffix_string` at `0x2272d10`.
    pub fn api_url(self) -> ApiUrl {
        match self {
            ExchangeApiTarget::Localhost => ApiUrl::Localhost,
            ExchangeApiTarget::WebSandbox => ApiUrl::WebSandbox,
            ExchangeApiTarget::Testnet => ApiUrl::Testnet,
            ExchangeApiTarget::Mainnet => ApiUrl::Mainnet,
        }
    }
}

#[derive(Debug)]
pub enum HttpClientError {
    UnsupportedChain(String),
    InvalidUri(String),
    Network(String),
    Timeout { label: &'static str, source: time::error::Elapsed },
    Body(String),
    Json(String),
    JsonRpc(JsonRpcError),
}

impl fmt::Display for HttpClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpClientError::UnsupportedChain(message)
            | HttpClientError::InvalidUri(message)
            | HttpClientError::Network(message)
            | HttpClientError::Body(message)
            | HttpClientError::Json(message) => f.write_str(message),
            HttpClientError::Timeout { label, source } => write!(f, "lu::timeout {label}: {source}"),
            HttpClientError::JsonRpc(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for HttpClientError {}

impl HttpClient {
    pub fn new(chain: HttpClientChain) -> Self {
        let mut http = hyper::client::HttpConnector::new();
        // IDA: `0x14390f3` stores `0` at connector offset `+0x80`, matching
        // `HttpConnector::enforce_http(false)` so HTTPS URIs are permitted.
        http.enforce_http(false);

        // IDA: `0x143913a` calls the native-tls/OpenSSL builder and branches at
        // `0x1439152`; the error branch calls the `Result::unwrap` panic path.
        let tls = TlsConnector::builder().build().unwrap();
        let https = HttpsConnector::from((http, tls.into()));

        // IDA: the stack builder image uses defaults plus recovered constants:
        // 20, 90, 1 GiB/ns-style duration sentinels, 1 MiB, 5 MiB, 2 MiB,
        // 16 KiB, and 65_536. Those are Hyper builder internals rather than
        // explicit source fields, so the source reconstruction keeps the boring
        // default builder call.
        let client = Client::builder().build::<_, Body>(https);

        Self { client, request_timeout_secs: Some(DEFAULT_REQUEST_TIMEOUT_SECS), chain }
    }

    pub fn request_timeout(&self) -> Option<Duration> {
        self.request_timeout_secs.map(duration_from_secs_f64_lossy)
    }

    /// Build the startup/gossip exchange URL.
    ///
    /// IDA: `0x2272d10` calls `ApiUrl::http_suffix_string`, then `0x2272d2c`
    /// formats literal `"http"` with that suffix, and `0x2272d77` appends the
    /// endpoint literal `"exchange"`.
    pub fn exchange_url(&self, target: ExchangeApiTarget) -> String {
        format!("http{}{}", target.api_url().http_suffix_string(), EXCHANGE_ENDPOINT)
    }

    /// Startup/gossip JSON exchange POST.
    ///
    pub async fn post_exchange_json<B>(&self, target: ExchangeApiTarget, body: &B) -> Result<String, HttpClientError>
    where
        B: Serialize + ?Sized,
    {
        let url = self.exchange_url(target);
        let body = serde_json::to_vec(body)
            .map_err(|error| HttpClientError::Json(format!("Error serializing response: {error}")))?;

        warn_sending_request(&url, &body);
        let request = json_post_request(&url, Body::from(body))?;
        let response = self.send_with_timeout(HTTP_SEND_REQUEST_RAW, request).await?;
        let bytes = self.read_body_with_timeout(response).await?;
        let response = response_text(bytes)?;
        warn_response(&response);
        Ok(response)
    }

    async fn send_with_timeout(&self, label: &'static str, request: Request<Body>) -> Result<Response<Body>, HttpClientError> {
        match self.request_timeout() {
            Some(timeout) => time::timeout(timeout, self.client.request(request))
                .await
                .map_err(|source| HttpClientError::Timeout { label, source })?
                .map_err(|error| HttpClientError::Network(format!("{label} {error}"))),
            None => self.client.request(request).await.map_err(|error| HttpClientError::Network(format!("{label} {error}"))),
        }
    }

    async fn read_body_with_timeout(&self, response: Response<Body>) -> Result<Bytes, HttpClientError> {
        match self.request_timeout() {
            Some(timeout) => time::timeout(timeout, to_bytes(response.into_body()))
                .await
                .map_err(|source| HttpClientError::Timeout { label: HTTP_READ_BODY, source })?
                .map_err(|error| HttpClientError::Body(format!("{HTTP_READ_BODY} {error}"))),
            None => to_bytes(response.into_body())
                .await
                .map_err(|error| HttpClientError::Body(format!("{HTTP_READ_BODY} {error}"))),
        }
    }

    /// Forward one raw EVM transaction through the chain-specific JSON-RPC endpoint.
    ///
    pub async fn forward_raw_transaction(&self, raw_transaction: &str) -> Result<Value, HttpClientError> {
        let url = match self.chain {
            HttpClientChain::Mainnet => MAINNET_EVM_RPC_URL,
            HttpClientChain::Testnet => TESTNET_EVM_RPC_URL,
            HttpClientChain::Unsupported(selector) => {
                return Err(HttpClientError::UnsupportedChain(format!(
                    "unsupported chain for evm rpc tx forwarding chain={selector}"
                )));
            }
        };

        let request_body = JsonRpcRequest { jsonrpc: "2.0", method: "eth_sendRawTransaction", params: vec![raw_transaction], id: 1 };
        let body = serde_json::to_vec(&request_body)
            .map_err(|error| HttpClientError::Json(format!("unable to forward raw transaction: {error}")))?;
        let request = json_post_request(url, Body::from(body))?;
        let response = self.send_with_timeout(HTTP_SEND_REQUEST_RAW, request).await?;
        let bytes = self.read_body_with_timeout(response).await?;
        parse_json_rpc_response::<Value>(&bytes).map_err(|error| {
            HttpClientError::Json(format!("unable to parse raw transaction response: {error}"))
        })?
    }
}

fn json_post_request(url: &str, body: Body) -> Result<Request<Body>, HttpClientError> {
    let uri = url.parse::<Uri>().map_err(|error| HttpClientError::InvalidUri(format!("could not parse url={url} err={error}")))?;
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .body(body)
        .map_err(|error| HttpClientError::Network(error.to_string()))
}

fn response_text(bytes: Bytes) -> Result<String, HttpClientError> {
    String::from_utf8(bytes.to_vec()).map_err(|error| HttpClientError::Body(format!("Unknown Error: {error}")))
}

/// IDA: `0x15ba010`, called from the `0x1611910` state machine, trims trailing
/// ASCII whitespace before feeding the JSON parser.
fn parse_json_rpc_response<T>(bytes: &[u8]) -> Result<Result<T, HttpClientError>, serde_json::Error>
where
    T: DeserializeOwned,
{
    let trimmed_len = bytes.iter().rposition(|byte| !byte.is_ascii_whitespace()).map_or(0, |idx| idx + 1);
    let response: JsonRpcResponse<T> = serde_json::from_slice(&bytes[..trimmed_len])?;
    Ok(match response.result {
        JsonRpcResult::Success { result } => Ok(result),
        JsonRpcResult::Error { error } => Err(HttpClientError::JsonRpc(error)),
    })
}

/// IDA: `0x15bb930` maps parsed JSON-RPC errors. The exact source enum names are
/// [INFERENCE], but the code classes match the observed branches for `-32700`,
/// `-32603..=-32600`, and `-32007`.
#[derive(Debug, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(default)]
    pub data: Option<Value>,
}

impl JsonRpcError {
    pub fn kind(&self) -> JsonRpcErrorKind {
        match self.code {
            -32700 => JsonRpcErrorKind::ParseError,
            -32600 => JsonRpcErrorKind::InvalidRequest,
            -32601 => JsonRpcErrorKind::MethodNotFound,
            -32602 => JsonRpcErrorKind::InvalidParams,
            -32603 => JsonRpcErrorKind::InternalError,
            -32007 => JsonRpcErrorKind::ServerError32007,
            _ => JsonRpcErrorKind::Other,
        }
    }
}

impl fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JSON-RPC error {}: {}", self.code, self.message)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsonRpcErrorKind {
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    InternalError,
    ServerError32007,
    Other,
}

#[derive(Serialize)]
struct JsonRpcRequest<T> {
    jsonrpc: &'static str,
    method: &'static str,
    params: Vec<T>,
    id: u64,
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    #[serde(flatten)]
    result: JsonRpcResult<T>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum JsonRpcResult<T> {
    Success { result: T },
    Error { error: JsonRpcError },
}

fn duration_from_secs_f64_lossy(secs: f64) -> Duration {
    if !secs.is_finite() || secs <= 0.0 {
        return Duration::ZERO;
    }

    // IDA: `0x2274571..0x2274634` multiplies by 1_000_000.0, clamps, splits
    // whole seconds and remaining microseconds, then converts the remainder to
    // nanoseconds with `* 1000`.
    let micros = (secs * 1_000_000.0).clamp(0.0, u64::MAX as f64) as u64;
    Duration::new(micros / 1_000_000, ((micros % 1_000_000) * 1_000) as u32)
}

fn warn_sending_request(url: &str, body: &[u8]) {
    let body = std::str::from_utf8(body).unwrap_or("<non-utf8>");
    log::warn!(" @@ sending request @@ [url: {url}] @ [body: {body}]\n");
}

fn warn_response(response: &str) {
    log::warn!(" @@ response: {response}\n");
}
