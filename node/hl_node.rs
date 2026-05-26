//! Reconstructed from `/home/ubuntu/hl/code_Mainnet/node/src/hl_node.rs`.
//!
//! Primary area: process entry wiring for node startup, production archiving,
//! CLI/startup action parsing, gossip/ABCI/consensus task launch, and node
//! lifecycle supervision.
//!
//! Seed EAs expanded for this file:
//! - `0x225DD90` — `node_hl_node__expect_parsed_startup_action`: copies a
//!   0xf0-byte parsed action on success and panics with `could not parse action`
//!   when the parser returns its error tag.
//! - `0x2271D00` — `node_hl_node__poll_check_reachability_firewall_ips`: async
//!   reachability/firewall-IP startup check; strings `check_reachability_firewall_ips`,
//!   `failed to load firewall ips`, and `Unreachable peers`.
//! - `0x2272C80` — `node_hl_node__poll_startup_http_request`: reusable startup
//!   HTTP/request future used by public-IP, reachability, and action submission.
//! - `0x2275A10` — production async-touch/archive future reached from hl_node.
//! - `0x22AE8A0` — `node_hl_node__poll_startup_orchestrator`: large startup
//!   state machine; source-path string cluster contains `@@ archiving data to s3`,
//!   `@@ running non-validator to get initial abci state for consensus`, local
//!   ABCI-state stale logging, `@@ serving from @@ [addr: ...] @ [components: ...]`,
//!   and ABCI stream timeout logging.
//! - `0x4546AC0`/`0x4546BA0` — wallet-key parsing/unwrap helpers; strings
//!   `no wallet key provided` and `could not parse wallet key`.
//! - `0x4578BD0`/`0x4579310` — CLI flag parser for chain/key, output writer flags,
//!   service switches, and `replica-cmds-style`.
//! - `0x4583030` — startup/action subcommand parser; strings include `delegate`,
//!   `staking-deposit`, `undelegate`, `staking-withdrawal`, `run-validator`,
//!   `print-address`, `check-reachability`, `abci-state-fln`, `change-validator-profile`,
//!   `approve-non-expiring-agent`, and `serve-eth-rpc`.
//! - `0x4583F60`, `0x4584030`, `0x4584140`, `0x4584180`, `0x4584200` — unwrap
//!   thunks for bool, unsigned integer, u8, address, and commission/limit integer
//!   parsing at hl_node.rs source lines 99/128/136/140.
//!
//! IDA write status for this wave: attempted but blocked by `Server is busy
//! (request queue full)`. The names above are the exact intended tags for the
//! next writable IDA pass.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const DATA_DIR: &str = "/hyperliquid_data";
pub const OVERRIDE_GOSSIP_CONFIG_FLN: &str = "override_gossip_config.json";
pub const NODE_CONFIG_FLN: &str = "node_config.json";
pub const GOSSIP_RPC_PORT: u16 = 4001;
pub const GOSSIP_STREAM_PORT: u16 = 4002;
pub const ABCI_STREAM_PORT: u16 = 4002;
pub const CONSENSUS_RPC_PORT: u16 = 4003;
pub const CONSENSUS_RPC_PORT_END: u16 = 4006;
pub const STARTUP_HTTP_TIMEOUT: Duration = Duration::from_secs(10);
pub const GOSSIP_RPC_TIMEOUT: Duration = Duration::from_secs(40);
pub const CHECK_REACHABILITY_LOG: &str = "check_reachability_firewall_ips";
pub const ARCHIVE_TO_S3_LOG: &str = "@@ archiving data to s3";
pub const NON_VALIDATOR_BOOTSTRAP_LOG: &str = "@@ running non-validator to get initial abci state for consensus";
pub const SERVING_FROM_LOG: &str = "@@ serving from @@";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Chain {
    Mainnet,
    Testnet,
    Dev,
    Local,
}

impl Chain {
    pub fn parse_lossless(value: &str) -> Result<Self, HlNodeError> {
        match value {
            "Mainnet" | "mainnet" => Ok(Self::Mainnet),
            "Testnet" | "testnet" => Ok(Self::Testnet),
            "Dev" | "dev" => Ok(Self::Dev),
            "Local" | "local" => Ok(Self::Local),
            _ => Err(HlNodeError::InvalidArg { key: "chain", value: value.to_owned() }),
        }
    }

    pub fn is_testing(self) -> bool {
        matches!(self, Self::Testnet | Self::Dev | Self::Local)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeRole {
    NonValidator,
    Validator,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildMode {
    NonProduction,
    Development,
    Release,
    Production,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Address(pub [u8; 20]);

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletKey {
    pub secret_hex: String,
    pub address: Address,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OutputWriterFlags {
    pub write_trades: bool,
    pub write_fills: bool,
    pub write_raw_book_diffs: bool,
    pub write_order_statuses: bool,
    pub write_misc_events: bool,
    pub write_hip3_oracle_updates: bool,
    pub write_system_and_core_writer_actions: bool,
    pub disable_output_file_buffering: bool,
    pub batch_by_block: bool,
    pub stream_with_block_info: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicaCmdsStyle {
    Actions,
    RecentActions,
    SignedActions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliOptions {
    pub chain: Chain,
    pub key: Option<WalletKey>,
    pub role: NodeRole,
    pub data_dir: PathBuf,
    pub output_flags: OutputWriterFlags,
    pub serve_evm_rpc: bool,
    pub serve_eth_rpc: bool,
    pub serve_info: bool,
    pub check_reachability: bool,
    pub replica_cmds_style: ReplicaCmdsStyle,
    pub abci_state_fln: Option<PathBuf>,
    pub override_public_ip_address: Option<IpAddr>,
    pub action: Option<StartupAction>,
}

impl Default for CliOptions {
    fn default() -> Self {
        Self {
            chain: Chain::Mainnet,
            key: None,
            role: NodeRole::NonValidator,
            data_dir: PathBuf::from(DATA_DIR),
            output_flags: OutputWriterFlags::default(),
            serve_evm_rpc: false,
            serve_eth_rpc: false,
            serve_info: false,
            check_reachability: true,
            replica_cmds_style: ReplicaCmdsStyle::Actions,
            abci_state_fln: None,
            override_public_ip_address: None,
            action: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StartupAction {
    Delegate { validator: Address, wei: u64 },
    StakingDeposit { wei: u64 },
    Undelegate { validator: Address, wei: u64 },
    StakingWithdrawal { wei: u64 },
    SendSignedAction { action_json: String },
    RawAction { action_json: String },
    ChangeValidatorProfile(ValidatorProfileChange),
    ApproveNonExpiringAgent { signer: Address },
    PrintAddress,
    RunValidator,
    CheckReachability,
    ComputeReferrerStates,
    ComputeL4Snapshots,
    ServeEthRpc,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorProfileChange {
    pub node_ip: Option<IpAddr>,
    pub description: Option<String>,
    pub disable_delegations: Option<bool>,
    pub commission_bps: Option<u16>,
    pub signer: Option<Address>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeIp(pub IpAddr);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GossipConfigInner {
    pub root_node_ips: Vec<NodeIp>,
    pub try_new_peers: bool,
    pub chain: Chain,
    pub reserved_peer_ips: Vec<NodeIp>,
    pub n_gossip_peers: usize,
    pub split_client_blocks: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeConfig {
    pub key: String,
    pub node_ip: Option<NodeIp>,
    pub sentry_ips: Vec<NodeIp>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GossipStatus {
    pub initial_height: u64,
    pub latest_height: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbciStateSnapshot {
    pub initial_height: u64,
    pub height: u64,
    pub round: u64,
    pub node_ips: Vec<IpAddr>,
    pub serialized_state: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupState {
    pub gossip_config: GossipConfigInner,
    pub validator_config: Option<NodeConfig>,
    pub abci_state: AbciStateSnapshot,
    pub bootstrap_peer: Option<IpAddr>,
    pub public_ip: Option<IpAddr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskHandle {
    pub name: &'static str,
    pub component: NodeComponent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeComponent {
    ProductionArchive,
    InfoServer,
    EvmRpc,
    EthRpc,
    GossipRpc,
    GossipStream,
    AbciStream,
    ConsensusRpc,
    ConsensusNetwork,
    AbciEngine,
    NodeServices,
    BootstrapClientBlocks,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeLifecycle {
    pub started_at: Instant,
    pub serving_addr: Option<SocketAddr>,
    pub components: Vec<NodeComponent>,
    pub task_handles: Vec<TaskHandle>,
    pub startup: StartupState,
}

#[derive(Debug)]
pub enum HlNodeError {
    MissingArg(String),
    InvalidArg { key: &'static str, value: String },
    WalletKey(String),
    ParseAction(String),
    Io { path: PathBuf, message: String },
    Json { path: PathBuf, message: String },
    PublicIp(String),
    FirewallIps(String),
    UnreachablePeers(Vec<IpAddr>),
    AbciStreamTimeout { peer: IpAddr, message: String },
    Startup(String),
    Service(String),
}

impl fmt::Display for HlNodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingArg(arg) => write!(f, "missing required argument `{arg}`"),
            Self::InvalidArg { key, value } => write!(f, "invalid value for `{key}`: {value}"),
            Self::WalletKey(message) => f.write_str(message),
            Self::ParseAction(message) => f.write_str(message),
            Self::Io { path, message } => write!(f, "could not load file `{}`: {message}", path.display()),
            Self::Json { path, message } => write!(f, "could not parse json `{}`: {message}", path.display()),
            Self::PublicIp(message) => write!(f, "could not get public ip, not validating against abci state: {message}"),
            Self::FirewallIps(message) => write!(f, "failed to load firewall ips: {message}"),
            Self::UnreachablePeers(peers) => write!(
                f,
                "Unreachable peers were found. Do not run validator with current IP until all peers have added it to their firewalls. unreachable addresses: {peers:?}"
            ),
            Self::AbciStreamTimeout { peer, message } => write!(f, "@@ abci_stream from {peer} timed out: {message}"),
            Self::Startup(message) | Self::Service(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for HlNodeError {}

/// Services called by the process-level hl_node orchestrator.
pub trait HlNodeServices {
    fn now(&mut self) -> Instant;
    fn log_warn(&mut self, message: String);
    fn log_info(&mut self, message: String);
    fn configure_production(&mut self, mode: BuildMode, role: &str) -> Result<(), HlNodeError>;
    fn archive_data_to_s3(&mut self, data_dir: &Path) -> Result<TaskHandle, HlNodeError>;
    fn read_gossip_config(&mut self, path: &Path) -> Result<GossipConfigInner, HlNodeError>;
    fn read_node_config(&mut self, path: &Path) -> Result<NodeConfig, HlNodeError>;
    fn read_firewall_ips(&mut self) -> Result<BTreeSet<IpAddr>, HlNodeError>;
    fn public_ip(&mut self) -> Result<IpAddr, HlNodeError>;
    fn check_reachability(&mut self, peer: IpAddr, port: u16, timeout: Duration) -> Result<bool, HlNodeError>;
    fn query_gossip_status(&mut self, peer: IpAddr, timeout: Duration) -> Result<Option<GossipStatus>, HlNodeError>;
    fn fetch_abci_state(&mut self, peer: IpAddr, timeout: Duration) -> Result<AbciStateSnapshot, HlNodeError>;
    fn linked_local_abci_state(&mut self, path: Option<&Path>) -> Result<Option<AbciStateSnapshot>, HlNodeError>;
    fn save_initial_abci_state(&mut self, state: &AbciStateSnapshot) -> Result<(), HlNodeError>;
    fn submit_startup_action(&mut self, wallet: &WalletKey, action: &StartupAction) -> Result<(), HlNodeError>;
    fn start_info_server(&mut self, addr: SocketAddr, state: &StartupState) -> Result<TaskHandle, HlNodeError>;
    fn start_evm_rpc(&mut self, addr: SocketAddr, state: &StartupState) -> Result<TaskHandle, HlNodeError>;
    fn start_eth_rpc(&mut self, addr: SocketAddr, state: &StartupState) -> Result<TaskHandle, HlNodeError>;
    fn start_gossip_rpc(&mut self, bind: SocketAddr, state: &StartupState) -> Result<TaskHandle, HlNodeError>;
    fn start_gossip_stream_listener(&mut self, bind: SocketAddr, state: &StartupState) -> Result<TaskHandle, HlNodeError>;
    fn start_abci_stream_listener(&mut self, bind: SocketAddr, state: &StartupState) -> Result<TaskHandle, HlNodeError>;
    fn start_consensus_rpc_server(&mut self, bind: SocketAddr, state: &StartupState) -> Result<TaskHandle, HlNodeError>;
    fn start_consensus_network(&mut self, state: &StartupState) -> Result<TaskHandle, HlNodeError>;
    fn start_abci_engine(&mut self, state: &StartupState) -> Result<TaskHandle, HlNodeError>;
    fn start_node_services(&mut self, state: &StartupState) -> Result<Vec<TaskHandle>, HlNodeError>;
    fn start_bootstrap_client_block_forwarder(&mut self, peer: IpAddr, state: &AbciStateSnapshot) -> Result<TaskHandle, HlNodeError>;
}

pub fn parse_bool_unwrap(value: &str) -> bool {
    match value.as_bytes() {
        b"true" => true,
        b"false" => false,
        _ => panic!("called `Result::unwrap()` on an `Err` value"),
    }
}

pub fn parse_u64_unwrap(value: &str) -> u64 {
    parse_unsigned_decimal(value).unwrap_or_else(|_| panic!("called `Result::unwrap()` on an `Err` value"))
}

pub fn parse_u8_unwrap(value: &str) -> u8 {
    let parsed = parse_unsigned_decimal(value).unwrap_or_else(|_| panic!("called `Result::unwrap()` on an `Err` value"));
    u8::try_from(parsed).unwrap_or_else(|_| panic!("called `Result::unwrap()` on an `Err` value"))
}

pub fn parse_address_unwrap(value: &str) -> Address {
    parse_address(value).unwrap_or_else(|_| panic!("called `Result::unwrap()` on an `Err` value"))
}

fn parse_unsigned_decimal(value: &str) -> Result<u64, ()> {
    let raw = value.strip_prefix('+').unwrap_or(value);
    if raw.is_empty() || raw.starts_with('-') {
        return Err(());
    }

    let mut acc = 0u64;
    for byte in raw.bytes() {
        if !byte.is_ascii_digit() {
            return Err(());
        }
        acc = acc.checked_mul(10).ok_or(())?;
        acc = acc.checked_add(u64::from(byte - b'0')).ok_or(())?;
    }
    Ok(acc)
}

fn parse_address(value: &str) -> Result<Address, ()> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    if raw.len() != 40 {
        return Err(());
    }

    let mut out = [0u8; 20];
    for (idx, chunk) in raw.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[idx] = (hi << 4) | lo;
    }
    Ok(Address(out))
}

fn hex_nibble(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(()),
    }
}

/// Recovered `0x4546AC0`/`0x4546BA0` behavior: missing key and parser failure
/// use adjacent messages `no wallet key provided` and `could not parse wallet key`.
pub fn parse_wallet_key_unwrap(raw: Option<&str>) -> Result<WalletKey, HlNodeError> {
    let Some(raw) = raw else {
        return Err(HlNodeError::WalletKey("no wallet key provided".to_owned()));
    };
    let secret_hex = raw.strip_prefix("0x").unwrap_or(raw);
    if secret_hex.len() != 64 || !secret_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(HlNodeError::WalletKey("could not parse wallet key".to_owned()));
    }

    // [INFERENCE] The real parser derives the address from the secret key.  The
    // recovered evidence only exposes the unwrap boundary; keep the key and require the
    // service/wallet layer to derive the address before signing.
    Ok(WalletKey { secret_hex: secret_hex.to_owned(), address: Address([0; 20]) })
}

/// Reconstructed CLI parser from `0x4578BD0`, `0x4579310`, and `0x4583030`.
pub fn parse_cli_options<I, S>(args: I) -> Result<CliOptions, HlNodeError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut kv = BTreeMap::<String, Option<String>>::new();
    let mut positional = Vec::<String>::new();
    let mut iter = args.into_iter().map(Into::into).peekable();

    while let Some(arg) = iter.next() {
        if let Some(stripped) = arg.strip_prefix("--") {
            if let Some((key, value)) = stripped.split_once('=') {
                kv.insert(key.to_owned(), Some(value.to_owned()));
            } else if is_boolean_flag(stripped) {
                kv.insert(stripped.to_owned(), None);
            } else if let Some(value) = iter.next() {
                kv.insert(stripped.to_owned(), Some(value));
            } else {
                return Err(HlNodeError::MissingArg(stripped.to_owned()));
            }
        } else {
            positional.push(arg);
        }
    }

    let mut opts = CliOptions::default();
    if let Some(chain) = take_value(&mut kv, "chain")? {
        opts.chain = Chain::parse_lossless(&chain)?;
    }
    if let Some(key) = take_value(&mut kv, "key")? {
        opts.key = Some(parse_wallet_key_unwrap(Some(&key))?);
    }
    if kv.remove("run-validator").is_some() {
        opts.role = NodeRole::Validator;
    }
    if let Some(path) = take_value(&mut kv, "data-dir")? {
        opts.data_dir = PathBuf::from(path);
    }
    if let Some(path) = take_value(&mut kv, "abci-state-fln")? {
        opts.abci_state_fln = Some(PathBuf::from(path));
    }
    if let Some(ip) = take_value(&mut kv, "override-public-ip-address")? {
        opts.override_public_ip_address = Some(parse_ip_arg("override-public-ip-address", &ip)?);
    }

    opts.output_flags.write_trades = kv.remove("write-trades").is_some();
    opts.output_flags.write_fills = kv.remove("write-fills").is_some();
    opts.output_flags.write_raw_book_diffs = kv.remove("write-raw-book-diffs").is_some();
    opts.output_flags.write_order_statuses = kv.remove("write-order-statuses").is_some();
    opts.output_flags.write_misc_events = kv.remove("write-misc-events").is_some();
    opts.output_flags.write_hip3_oracle_updates = kv.remove("write-hip3-oracle-updates").is_some();
    opts.output_flags.write_system_and_core_writer_actions = kv.remove("write-system-and-core-writer-actions").is_some();
    opts.output_flags.disable_output_file_buffering = kv.remove("disable-output-file-buffering").is_some();
    opts.output_flags.batch_by_block = kv.remove("batch-by-block").is_some();
    opts.output_flags.stream_with_block_info = kv.remove("stream-with-block-info").is_some();
    opts.serve_evm_rpc = kv.remove("serve-evm-rpc").is_some();
    opts.serve_eth_rpc = kv.remove("serve-eth-rpc").is_some();
    opts.serve_info = kv.remove("serve-info").is_some();
    opts.check_reachability = kv.remove("check-reachability").is_some() || opts.check_reachability;

    if let Some(style) = take_value(&mut kv, "replica-cmds-style")? {
        opts.replica_cmds_style = parse_replica_cmds_style(&style)?;
    }

    opts.action = parse_startup_action(&mut kv, &positional)?;
    Ok(opts)
}

fn is_boolean_flag(flag: &str) -> bool {
    matches!(
        flag,
        "write-trades"
            | "write-fills"
            | "write-raw-book-diffs"
            | "write-order-statuses"
            | "write-misc-events"
            | "write-hip3-oracle-updates"
            | "write-system-and-core-writer-actions"
            | "disable-output-file-buffering"
            | "batch-by-block"
            | "stream-with-block-info"
            | "serve-evm-rpc"
            | "serve-eth-rpc"
            | "serve-info"
            | "check-reachability"
            | "run-validator"
            | "print-address"
            | "compute-referrer-states"
            | "compute-l4-snapshots"
    )
}

fn take_value(kv: &mut BTreeMap<String, Option<String>>, key: &'static str) -> Result<Option<String>, HlNodeError> {
    match kv.remove(key) {
        Some(Some(value)) => Ok(Some(value)),
        Some(None) => Err(HlNodeError::MissingArg(key.to_owned())),
        None => Ok(None),
    }
}

fn parse_ip_arg(key: &'static str, value: &str) -> Result<IpAddr, HlNodeError> {
    value.parse().map_err(|_| HlNodeError::InvalidArg { key, value: value.to_owned() })
}

fn parse_replica_cmds_style(value: &str) -> Result<ReplicaCmdsStyle, HlNodeError> {
    match value {
        "actions" => Ok(ReplicaCmdsStyle::Actions),
        "recent-actions" => Ok(ReplicaCmdsStyle::RecentActions),
        "send-signed-action" | "signed-actions" => Ok(ReplicaCmdsStyle::SignedActions),
        _ => Err(HlNodeError::InvalidArg { key: "replica-cmds-style", value: value.to_owned() }),
    }
}

fn parse_startup_action(
    kv: &mut BTreeMap<String, Option<String>>,
    positional: &[String],
) -> Result<Option<StartupAction>, HlNodeError> {
    if kv.remove("print-address").is_some() || positional.iter().any(|s| s == "print-address") {
        return Ok(Some(StartupAction::PrintAddress));
    }
    if kv.remove("run-validator").is_some() || positional.iter().any(|s| s == "run-validator") {
        return Ok(Some(StartupAction::RunValidator));
    }
    if kv.remove("check-reachability").is_some() || positional.iter().any(|s| s == "check-reachability") {
        return Ok(Some(StartupAction::CheckReachability));
    }
    if positional.iter().any(|s| s == "compute-referrer-states") {
        return Ok(Some(StartupAction::ComputeReferrerStates));
    }
    if positional.iter().any(|s| s == "compute-l4-snapshots") {
        return Ok(Some(StartupAction::ComputeL4Snapshots));
    }
    if kv.remove("serve-eth-rpc").is_some() || positional.iter().any(|s| s == "serve-eth-rpc") {
        return Ok(Some(StartupAction::ServeEthRpc));
    }

    if let Some(action_json) = take_value(kv, "send-signed-action")? {
        return Ok(Some(StartupAction::SendSignedAction { action_json }));
    }
    if let Some(action_json) = take_value(kv, "action")? {
        return Ok(Some(StartupAction::RawAction { action_json }));
    }
    if let Some(signer) = take_value(kv, "approve-non-expiring-agent")? {
        return Ok(Some(StartupAction::ApproveNonExpiringAgent { signer: parse_address_unwrap(&signer) }));
    }

    if let Some(wei) = take_value(kv, "staking-deposit")? {
        return Ok(Some(StartupAction::StakingDeposit { wei: parse_u64_unwrap(&wei) }));
    }
    if let Some(wei) = take_value(kv, "staking-withdrawal")? {
        return Ok(Some(StartupAction::StakingWithdrawal { wei: parse_u64_unwrap(&wei) }));
    }
    if let Some(validator) = take_value(kv, "delegate")? {
        let wei = take_value(kv, "wei")?.ok_or_else(|| HlNodeError::MissingArg("wei".to_owned()))?;
        return Ok(Some(StartupAction::Delegate { validator: parse_address_unwrap(&validator), wei: parse_u64_unwrap(&wei) }));
    }
    if let Some(validator) = take_value(kv, "undelegate")? {
        let wei = take_value(kv, "wei")?.ok_or_else(|| HlNodeError::MissingArg("wei".to_owned()))?;
        return Ok(Some(StartupAction::Undelegate { validator: parse_address_unwrap(&validator), wei: parse_u64_unwrap(&wei) }));
    }

    if kv.contains_key("change-validator-profile")
        || kv.contains_key("node-ip")
        || kv.contains_key("description")
        || kv.contains_key("disable-delegations")
        || kv.contains_key("commission-bps")
        || kv.contains_key("signer")
    {
        let node_ip = take_value(kv, "node-ip")?.map(|s| parse_ip_arg("node-ip", &s)).transpose()?;
        let description = take_value(kv, "description")?;
        let disable_delegations = take_value(kv, "disable-delegations")?.map(|s| parse_bool_unwrap(&s));
        let commission_bps = take_value(kv, "commission-bps")?.map(|s| u16::from(parse_u8_unwrap(&s)));
        let signer = take_value(kv, "signer")?.map(|s| parse_address_unwrap(&s));
        return Ok(Some(StartupAction::ChangeValidatorProfile(ValidatorProfileChange {
            node_ip,
            description,
            disable_delegations,
            commission_bps,
            signer,
        })));
    }

    Ok(None)
}

pub fn expect_parsed_startup_action(parsed: Result<StartupAction, String>) -> Result<StartupAction, HlNodeError> {
    parsed.map_err(|error| HlNodeError::ParseAction(format!("could not parse action: {error}")))
}

pub fn gossip_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(OVERRIDE_GOSSIP_CONFIG_FLN)
}

pub fn node_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(NODE_CONFIG_FLN)
}

pub fn bind_addr(port: u16) -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], port))
}

pub fn validate_gossip_config(config: &GossipConfigInner, expected: Chain) -> Result<(), HlNodeError> {
    if config.chain != expected {
        return Err(HlNodeError::InvalidArg { key: "chain", value: format!("{:?}", config.chain) });
    }
    if config.root_node_ips.is_empty() {
        return Err(HlNodeError::Startup("assertion failed: !res.read().root_node_ips.is_empty()".to_owned()));
    }
    Ok(())
}

/// Reconstructed firewall/reachability check from seed `0x2271D00`.
pub fn check_reachability_firewall_ips<S: HlNodeServices>(
    services: &mut S,
    config: &GossipConfigInner,
    validator_config: Option<&NodeConfig>,
) -> Result<(), HlNodeError> {
    services.log_info(CHECK_REACHABILITY_LOG.to_owned());
    let allowed = services.read_firewall_ips().map_err(|error| HlNodeError::FirewallIps(error.to_string()))?;
    let mut unreachable = Vec::new();

    for peer in config.root_node_ips.iter().chain(config.reserved_peer_ips.iter()) {
        if allowed.contains(&peer.0) {
            continue;
        }
        match services.check_reachability(peer.0, GOSSIP_RPC_PORT, STARTUP_HTTP_TIMEOUT) {
            Ok(true) => {}
            Ok(false) | Err(_) => unreachable.push(peer.0),
        }
    }

    if let Some(validator) = validator_config {
        for peer in &validator.sentry_ips {
            match services.check_reachability(peer.0, GOSSIP_RPC_PORT, STARTUP_HTTP_TIMEOUT) {
                Ok(true) => {}
                Ok(false) | Err(_) => unreachable.push(peer.0),
            }
        }
    }

    if unreachable.is_empty() {
        Ok(())
    } else {
        Err(HlNodeError::UnreachablePeers(unreachable))
    }
}

/// Reusable startup HTTP/request wrapper corresponding to seed `0x2272C80`.
pub fn startup_http_request<T, F>(label: &'static str, mut request: F) -> Result<T, HlNodeError>
where
    F: FnMut(Duration) -> Result<T, HlNodeError>,
{
    request(STARTUP_HTTP_TIMEOUT).map_err(|error| HlNodeError::Startup(format!("{label}: {error}")))
}

pub fn load_startup_state<S: HlNodeServices>(services: &mut S, opts: &CliOptions) -> Result<StartupState, HlNodeError> {
    let gossip_path = gossip_config_path(&opts.data_dir);
    let gossip_config = services.read_gossip_config(&gossip_path)?;
    validate_gossip_config(&gossip_config, opts.chain)?;

    let validator_config = if opts.role == NodeRole::Validator {
        Some(services.read_node_config(&node_config_path(&opts.data_dir))?)
    } else {
        None
    };

    let public_ip = match services.public_ip() {
        Ok(ip) => Some(ip),
        Err(error) => {
            services.log_warn(format!("could not get public ip, not validating against abci state: {error}"));
            None
        }
    };

    if opts.check_reachability || matches!(opts.action, Some(StartupAction::CheckReachability)) {
        check_reachability_firewall_ips(services, &gossip_config, validator_config.as_ref())?;
    }

    let linked = services.linked_local_abci_state(opts.abci_state_fln.as_deref())?;
    let (abci_state, bootstrap_peer) = match linked {
        Some(state) if is_local_abci_state_fresh(&state, &gossip_config, public_ip) => (state, None),
        Some(state) => {
            services.log_warn(format!(
                "@@ considering local abci state as stale @@ [stale_reason: node set/public ip mismatch] @ [node_ips: {:?}]",
                state.node_ips
            ));
            bootstrap_abci_state(services, &gossip_config).map(|(state, peer)| (state, Some(peer)))?
        }
        None => {
            services.log_warn(NON_VALIDATOR_BOOTSTRAP_LOG.to_owned());
            bootstrap_abci_state(services, &gossip_config).map(|(state, peer)| (state, Some(peer)))?
        }
    };

    services.save_initial_abci_state(&abci_state)?;
    Ok(StartupState { gossip_config, validator_config, abci_state, bootstrap_peer, public_ip })
}

fn is_local_abci_state_fresh(state: &AbciStateSnapshot, config: &GossipConfigInner, public_ip: Option<IpAddr>) -> bool {
    if state.height == 0 || state.node_ips.is_empty() {
        return false;
    }
    if config.chain.is_testing() {
        return true;
    }
    if let Some(public_ip) = public_ip {
        state.node_ips.contains(&public_ip)
            || config.root_node_ips.iter().any(|ip| ip.0 == public_ip)
            || config.reserved_peer_ips.iter().any(|ip| ip.0 == public_ip)
    } else {
        config.root_node_ips.iter().any(|ip| state.node_ips.contains(&ip.0))
    }
}

fn bootstrap_abci_state<S: HlNodeServices>(
    services: &mut S,
    config: &GossipConfigInner,
) -> Result<(AbciStateSnapshot, IpAddr), HlNodeError> {
    let mut best_peer = None;
    let mut best_status = GossipStatus::default();

    for peer in &config.root_node_ips {
        if let Some(status) = services.query_gossip_status(peer.0, STARTUP_HTTP_TIMEOUT)? {
            if status.latest_height >= best_status.latest_height {
                best_status = status;
                best_peer = Some(peer.0);
            }
        }
    }

    let peer = best_peer
        .or_else(|| config.root_node_ips.first().map(|ip| ip.0))
        .ok_or_else(|| HlNodeError::Startup("unable to find at least 2 valid rpc heights".to_owned()))?;

    match services.fetch_abci_state(peer, GOSSIP_RPC_TIMEOUT) {
        Ok(mut state) => {
            if state.initial_height == 0 {
                state.initial_height = best_status.initial_height;
            }
            Ok((state, peer))
        }
        Err(error) => Err(HlNodeError::AbciStreamTimeout { peer, message: error.to_string() }),
    }
}

pub fn submit_startup_action_if_any<S: HlNodeServices>(
    services: &mut S,
    opts: &CliOptions,
) -> Result<(), HlNodeError> {
    let Some(action) = opts.action.as_ref() else {
        return Ok(());
    };

    match action {
        StartupAction::PrintAddress
        | StartupAction::RunValidator
        | StartupAction::CheckReachability
        | StartupAction::ComputeReferrerStates
        | StartupAction::ComputeL4Snapshots
        | StartupAction::ServeEthRpc => Ok(()),
        action => {
            let wallet = opts.key.as_ref().ok_or_else(|| HlNodeError::WalletKey("no wallet key provided".to_owned()))?;
            services.submit_startup_action(wallet, action)
        }
    }
}

/// Main lifecycle entry corresponding to the `0x22AE8A0` startup orchestrator.
pub fn run_hl_node<S: HlNodeServices>(
    services: &mut S,
    opts: CliOptions,
    build_mode: BuildMode,
) -> Result<NodeLifecycle, HlNodeError> {
    services.configure_production(build_mode, "Node")?;
    let started_at = services.now();
    let mut task_handles = Vec::new();
    let mut components = Vec::new();

    if matches!(build_mode, BuildMode::Production | BuildMode::Release) {
        services.log_warn(ARCHIVE_TO_S3_LOG.to_owned());
        let handle = services.archive_data_to_s3(&opts.data_dir)?;
        components.push(NodeComponent::ProductionArchive);
        task_handles.push(handle);
    }

    let startup = load_startup_state(services, &opts)?;
    submit_startup_action_if_any(services, &opts)?;

    let gossip_bind = bind_addr(GOSSIP_RPC_PORT);
    task_handles.push(services.start_gossip_rpc(gossip_bind, &startup)?);
    components.push(NodeComponent::GossipRpc);

    task_handles.push(services.start_gossip_stream_listener(bind_addr(GOSSIP_STREAM_PORT), &startup)?);
    components.push(NodeComponent::GossipStream);

    task_handles.push(services.start_abci_stream_listener(bind_addr(ABCI_STREAM_PORT), &startup)?);
    components.push(NodeComponent::AbciStream);

    task_handles.push(services.start_abci_engine(&startup)?);
    components.push(NodeComponent::AbciEngine);

    if startup.validator_config.is_some() {
        for port in CONSENSUS_RPC_PORT..=CONSENSUS_RPC_PORT_END {
            task_handles.push(services.start_consensus_rpc_server(bind_addr(port), &startup)?);
        }
        components.push(NodeComponent::ConsensusRpc);
        task_handles.push(services.start_consensus_network(&startup)?);
        components.push(NodeComponent::ConsensusNetwork);
    }

    task_handles.extend(services.start_node_services(&startup)?);
    components.push(NodeComponent::NodeServices);

    if let Some(peer) = startup.bootstrap_peer {
        task_handles.push(services.start_bootstrap_client_block_forwarder(peer, &startup.abci_state)?);
        components.push(NodeComponent::BootstrapClientBlocks);
    }

    let serving_addr = Some(gossip_bind);
    if opts.serve_info {
        task_handles.push(services.start_info_server(gossip_bind, &startup)?);
        components.push(NodeComponent::InfoServer);
    }
    if opts.serve_evm_rpc {
        task_handles.push(services.start_evm_rpc(gossip_bind, &startup)?);
        components.push(NodeComponent::EvmRpc);
    }
    if opts.serve_eth_rpc || matches!(opts.action, Some(StartupAction::ServeEthRpc)) {
        task_handles.push(services.start_eth_rpc(gossip_bind, &startup)?);
        components.push(NodeComponent::EthRpc);
    }

    services.log_warn(format!(
        "{} [addr: {:?}] @ [components: {:?}]",
        SERVING_FROM_LOG, serving_addr, components
    ));

    Ok(NodeLifecycle { started_at, serving_addr, components, task_handles, startup })
}
