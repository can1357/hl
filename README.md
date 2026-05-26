# hl-recon

Rust sources recovered from the stripped `hl-node` binary. Reverse engineered with an agentic coding harness driving IDA, not official.

Layout mirrors what the build metadata implied:

- `base` — utility crate (time, channels, logging, wallet, etc.)
- `bincode_fork` — Hyperliquid's vendored bincode
- `db` — RocksDB wrappers, block reader
- `evm_rpc` — EVM JSON-RPC server
- `global_constants` — static config, AWS names
- `info_server` — public info API handlers
- `l1` — clearinghouse, exchange, ABCI, EVM state, actions
- `net_utils` — TCP, LZ4, rate limiting
- `node` — gossip, consensus, startup glue

No `Cargo.toml`s here. The files won't compile as-is; treat them as readable references for the binary.
