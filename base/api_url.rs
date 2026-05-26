//! Reconstruction of `code_Mainnet/base/src/api_url.rs`.
//!
//! Confidence: Medium-high for the `ApiUrl` variant set and URL suffix construction;
//! medium for source-level item names because the only file-anchored function is stripped.
//!
//! IDA anchors:
//!   - `sub_1450AE0` (seed via `/home/ubuntu/hl/code_Mainnet/base/src/api_url.rs`, line 90:38)
//!     reconstructs an owned `String` suffix for an `ApiUrl` value.
//!   - Panic location `off_566AB28` points at this file and is reached by the
//!     `BTreeMap` index panic string `"no entry found for key"`.
//!   - Call site `0x2272D10` immediately formats `"http{}"` around this suffix;
//!     e.g. the mainnet branch returns `"s://api.hyperliquid.xyz/"`, yielding
//!     `"https://api.hyperliquid.xyz/"` in the caller.
//!   - Custom-address formatting delegates to `std::net::SocketAddr` display
//!     helper `sub_14791A0`; that helper is not owned by this file.
//!
//! IDA tags applied:
//!   - Renamed `sub_1450AE0` -> `base_api_url__http_suffix_string`
//!   - Declared/applied `hl_base_ApiUrl` to the `api_url` parameter.

use std::net::SocketAddr;

/// API endpoint target used to build the Hyperliquid HTTP base URL.
///
/// IDA: layout inferred from `base_api_url__http_suffix_string` (was `sub_1450AE0`).
/// Confidence: Medium-high — discriminants 2..6 are selected directly; discriminants
/// 0 and 1 are formatted by `std::net::SocketAddr` (`sub_14791A0`), indicating a
/// data-bearing custom socket-address variant. Rust's enum layout appears flattened
/// over `SocketAddr::{V4,V6}`.
pub enum ApiUrl {
    /// Custom socket-address target.
    ///
    /// IDA: `sub_1450AE0` default case for discriminants 0/1; formats `"://{}/"`.
    /// Confidence: Medium — exact source variant name is inferred from behavior.
    Custom(SocketAddr),

    /// Mainnet public API.
    ///
    /// IDA: `sub_1450AE0` case 0 after subtracting 2 from discriminant; allocates
    /// and copies `"s://api.hyperliquid.xyz/"`.
    /// Confidence: High.
    Mainnet,

    /// Testnet public API.
    ///
    /// IDA: `sub_1450AE0` case 1; allocates and copies
    /// `"s://api.hyperliquid-testnet.xyz/"`.
    /// Confidence: High.
    Testnet,

    /// Local/private web sandbox API target resolved from a process-global string-keyed map.
    ///
    /// IDA: `sub_1450AE0` case 2 indexes key `"WebSandbox"`, formats `"://{}:3001/"`.
    /// Confidence: High for behavior; source variant name follows the embedded key.
    WebSandbox,

    /// Public web sandbox API target resolved from the same process-global map.
    ///
    /// IDA: `sub_1450AE0` case 3 indexes key `"WebSandboxPublic"`, formats `"://{}/"`.
    /// Confidence: High for behavior; source variant name follows the embedded key.
    WebSandboxPublic,

    /// Local development API target.
    ///
    /// IDA: `sub_1450AE0` case 4; allocates and copies `"://localhost:3001/"`.
    /// Confidence: Medium-high — source variant name inferred from literal.
    Localhost,
}

impl ApiUrl {
    /// Return the URL suffix that the observed caller prefixes with `"http"`.
    ///
    /// IDA: `base_api_url__http_suffix_string` (was `sub_1450AE0`) at `0x1450AE0`.
    /// Confidence: High for branch behavior and literals; Medium for method name.
    ///
    /// Important: this deliberately returns `"s://..."` for TLS endpoints and
    /// `"://..."` for plain HTTP endpoints. Caller `0x2272D10` uses `format!("http{}", suffix)`.
    pub fn http_suffix_string(&self) -> String {
        match self {
            ApiUrl::Custom(addr) => format!("://{addr}/"),
            ApiUrl::Mainnet => "s://api.hyperliquid.xyz/".to_owned(),
            ApiUrl::Testnet => "s://api.hyperliquid-testnet.xyz/".to_owned(),
            ApiUrl::WebSandbox => {
                let ip: String = todo!("global WebSandbox IPv4 map lookup — see sub_1450AE0");
                format!("://{ip}:3001/")
            }
            ApiUrl::WebSandboxPublic => {
                let ip: String =
                    todo!("global WebSandboxPublic IPv4 map lookup — see sub_1450AE0");
                format!("://{ip}/")
            }
            ApiUrl::Localhost => "://localhost:3001/".to_owned(),
        }
    }
}
