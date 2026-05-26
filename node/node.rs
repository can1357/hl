//! Reconstructed from `/home/ubuntu/hl/code_Mainnet/node/src/node.rs`.
//!
//! Seed EAs: 0x474BFA0, 0x20432B0, 0x226C2D0, 0x22C05A0,
//! 0x23ECD70, 0x432E930, 0x43955C0, 0x4523700, 0x4677FD0,
//! 0x474A4F0, 0x474B140, 0x47B1C60.  Foreign/shared seeds observed in
//! this source-path cluster: 0x1FD4570 (`gossip_rpc_client.rs`) and
//! 0x2275A10 (`base/src/production.rs`).
//!
//! Proposed IDA tags for this file:
//! - `node_node__run_node_services_poll` at 0x226C2D0.
//! - `node_node__poll_node_connection_checks` at 0x20432B0.
//! - `node_node__poll_gossip_server_connect_to_peer_timeout` at 0x22C05A0.
//! - `node_node__check_validator_config` at 0x23ECD70 [INFERENCE].
//! - `node_node__monitor_visor_state_lag_loop` at 0x432E930.
//! - `node_node__poll_node_disabler_future` at 0x43955C0.
//! - `node_node__node_disabler_elapsed_pair` at 0x4523700.
//! - `node_node__serialize_abci_state_for_greeting` at 0x4677FD0.
//! - `node_node__spawn_slow_abci_services` at 0x474A4F0.
//! - `node_node__spawn_node_disabler` at 0x474B140.
//! - `node_node__run_node_fast_loop` at 0x474BFA0.
//! - `node_node__node_disabler_poll` at 0x47B1C60.
//!
//! IDA write status: pending. The MCP queue was full during this wave; the
//! names above are the exact database updates attempted or delegated.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

pub const NODE_FAST_TASK: &str = "node_fast";
pub const NODE_DISABLER_TASK: &str = "node_disabler";
pub const SLOW_ABCI_BLOCK_TASK: &str = "slow abci block";
pub const SLOW_ABCI_STATE_DRIVER_TASK: &str = "node slow abci_state driver";
pub const NODE_SLOW_ABCI_ENGINE_TASK: &str = "node_slow_abci_engine";
pub const RUN_NODE_APPLY_ABCI_BLOCK: &str = "run_node_apply_abci_block";
pub const RUN_NODE_SEND_EXECUTION_STATE: &str = "run_node_send_execution_state";
pub const REPLICA_CMDS_METRIC: &str = "replica_cmds";
pub const VISOR_ABCI_STATES_METRIC: &str = "visor_abci_states";
pub const SERIALIZE_GREETING_LOG: &str = "@@ serializing abci state for greeting @@";
pub const SERIALIZED_GREETING_LOG: &str = "@@ serialized abci state for greeting @@";
pub const FIREWALL_IPS_ALERT: &str = "firewall_ips_alert";

const NODE_DISABLER_ALERT_SECONDS: f64 = 3.0;
const VISOR_LAG_HISTORY: usize = 20;
const VISOR_LAG_SLEEP: Duration = Duration::from_secs(5);
const CONNECTION_CHECK_REARM: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeMode {
    NonValidator,
    Validator,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ValidatorId(pub [u8; 20]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeAddress {
    pub ip: IpAddr,
    pub gossip_port: u16,
    pub consensus_port: u16,
}

#[derive(Clone, Debug)]
pub struct ValidatorConfig {
    pub home_validator: ValidatorId,
    pub home_public_ip: Option<IpAddr>,
    pub known_validators: BTreeMap<ValidatorId, NodeAddress>,
    pub sentry_ips: Vec<IpAddr>,
    pub is_main_signer: bool,
}

#[derive(Clone, Debug)]
pub struct NodeStartupConfig {
    pub mode: NodeMode,
    pub root_node_ips: Vec<IpAddr>,
    pub reserved_peer_ips: Vec<IpAddr>,
    pub validator: Option<ValidatorConfig>,
    pub split_client_blocks: bool,
    pub validator_gossip_priority: BTreeMap<ValidatorId, u64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct L1Hash(pub [u8; 32]);

#[derive(Clone, Debug)]
pub struct AbciBlock {
    pub height: u64,
    pub round: u64,
    pub l1_hash: L1Hash,
    pub replica_cmds: Vec<ReplicaCommand>,
    pub timestamp: SystemTime,
}

#[derive(Clone, Debug)]
pub struct ReplicaCommand {
    pub destination: ValidatorId,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ExternalTx {
    pub payload: Vec<u8>,
    pub received_at: Instant,
}

#[derive(Clone, Debug)]
pub struct ClientBlockOrTx {
    pub origin: IpAddr,
    pub round: u64,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum FastLoopWork {
    ApplyAbciBlock(AbciBlock),
    ForwardExternalTx(ExternalTx),
    LocalNvStream(ClientBlockOrTx),
    Shutdown,
}

#[derive(Clone, Debug)]
pub struct ExecutionStateSnapshot {
    pub height: u64,
    pub round: u64,
    pub l1_hash: L1Hash,
    pub serialized_abci_state_len: usize,
    pub updated_at: Instant,
}

#[derive(Clone, Debug)]
pub struct AbciState {
    pub initial_height: u64,
    pub height: u64,
    pub round: u64,
    pub l1_hash: L1Hash,
    pub evm_kv_checkpoint: Option<Vec<u8>>,
    pub serialized_state: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct GreetingPayload {
    pub initial_height: u64,
    pub height: u64,
    pub l1_hash: L1Hash,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SlowAbciServices {
    pub block_task_name: &'static str,
    pub state_driver_task_name: &'static str,
    pub engine_task_name: &'static str,
    pub fast_height: u64,
    pub split_client_blocks: bool,
    pub queued_blocks: VecDeque<AbciBlock>,
    pub latest_snapshot: Option<ExecutionStateSnapshot>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PollCounters {
    pub instrumented_count: u64,
    pub total_first_poll_delay: Duration,
    pub total_idle_duration: Duration,
    pub total_scheduled_count: u64,
}

#[derive(Clone, Debug)]
pub struct TimedPollState {
    pub task_name: &'static str,
    pub first_scheduled_at: Option<Instant>,
    pub last_polled_at: Option<Instant>,
    pub counters: PollCounters,
}

impl TimedPollState {
    pub fn new(task_name: &'static str) -> Self {
        Self {
            task_name,
            first_scheduled_at: None,
            last_polled_at: None,
            counters: PollCounters::default(),
        }
    }

    pub fn schedule(&mut self, now: Instant) {
        if self.first_scheduled_at.is_none() {
            self.first_scheduled_at = Some(now);
        }
        self.counters.total_scheduled_count += 1;
    }

    pub fn begin_poll(&mut self, now: Instant) {
        self.counters.instrumented_count += 1;
        if let Some(first) = self.first_scheduled_at.take() {
            self.counters.total_first_poll_delay += now.saturating_duration_since(first);
        }
        if let Some(last) = self.last_polled_at.replace(now) {
            self.counters.total_idle_duration += now.saturating_duration_since(last);
        }
    }
}

#[derive(Clone, Debug)]
pub struct NodeDisablerState {
    pub is_main_signer: bool,
    pub home_public_ip: IpAddr,
    pub active_validator_to_ip: BTreeMap<ValidatorId, NodeAddress>,
    pub last_seen_by_validator: BTreeMap<ValidatorId, Instant>,
    pub last_firewall_alert_by_validator: BTreeMap<ValidatorId, Instant>,
    pub disabled_validators: BTreeSet<ValidatorId>,
    pub poll: TimedPollState,
}

#[derive(Clone, Debug)]
pub struct VisorStateSample {
    pub height: u64,
    pub round: u64,
    pub observed_at: Instant,
}

#[derive(Clone, Debug, Default)]
pub struct VisorLagMonitor {
    pub history: VecDeque<VisorStateSample>,
    pub last_lag: u64,
}

#[derive(Clone, Debug)]
pub struct NodeRuntime {
    pub startup: NodeStartupConfig,
    pub fast_height: u64,
    pub expected_fast_height: u64,
    pub latest_l1_hash: L1Hash,
    pub slow_abci: Option<SlowAbciServices>,
    pub node_disabler: Option<NodeDisablerState>,
    pub execution_state: Option<ExecutionStateSnapshot>,
    pub fast_rx: VecDeque<FastLoopWork>,
    pub mempool_txs: VecDeque<ExternalTx>,
    pub consensus_out_recver: VecDeque<ReplicaCommand>,
    pub local_nv_stream: VecDeque<ClientBlockOrTx>,
    pub visor_lag: VisorLagMonitor,
}

impl NodeRuntime {
    pub fn new(startup: NodeStartupConfig, initial_height: u64, l1_hash: L1Hash) -> Self {
        Self {
            startup,
            fast_height: initial_height,
            expected_fast_height: initial_height,
            latest_l1_hash: l1_hash,
            slow_abci: None,
            node_disabler: None,
            execution_state: None,
            fast_rx: VecDeque::new(),
            mempool_txs: VecDeque::new(),
            consensus_out_recver: VecDeque::new(),
            local_nv_stream: VecDeque::new(),
            visor_lag: VisorLagMonitor::default(),
        }
    }
}

#[derive(Debug)]
pub enum NodeError {
    MissingHomePublicIp,
    ValidatorConfig(String),
    UnexpectedFastHeight { expected: u64, got: u64 },
    Service(String),
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::MissingHomePublicIp => f.write_str("Could not get home public ip"),
            NodeError::ValidatorConfig(msg) => f.write_str(msg),
            NodeError::UnexpectedFastHeight { expected, got } => {
                write!(f, "unexpected fast height: expected {expected}, got {got}")
            }
            NodeError::Service(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for NodeError {}

pub trait NodeServices {
    fn now(&mut self) -> Instant;
    fn log(&mut self, target: &'static str, message: String);
    fn apply_abci_block(&mut self, block: &AbciBlock) -> Result<ExecutionStateSnapshot, NodeError>;
    fn send_execution_state(&mut self, snapshot: &ExecutionStateSnapshot) -> Result<(), NodeError>;
    fn send_to_destination(&mut self, destination: &ValidatorId, payload: &[u8]) -> Result<(), NodeError>;
    fn forward_external_tx(&mut self, tx: ExternalTx) -> Result<(), NodeError>;
    fn enqueue_local_nv(&mut self, item: ClientBlockOrTx) -> Result<(), NodeError>;
    fn get_visor_state(&mut self) -> Option<VisorStateSample>;
    fn save_evm_kvs_checkpoint(&mut self, height: u64, bytes: &[u8]) -> Result<(), NodeError>;
}

/// Compiler-generated async poll body for node service orchestration.  The large
/// binary state machine initializes startup-derived fields, builds slow ABCI
/// services, starts `node_disabler` for validators, and then repeatedly drains
/// fast-loop, consensus, mempool, and local-NV stream work.
pub fn run_node_services_poll<S: NodeServices>(
    services: &mut S,
    runtime: &mut NodeRuntime,
) -> Result<bool, NodeError> {
    check_validator_config(&runtime.startup)?;

    if runtime.slow_abci.is_none() {
        runtime.slow_abci = Some(spawn_slow_abci_services(
            runtime.fast_height,
            runtime.startup.split_client_blocks,
        ));
    }

    if runtime.node_disabler.is_none() {
        if let Some(validator) = runtime.startup.validator.as_ref() {
            runtime.node_disabler = Some(spawn_node_disabler(validator)?);
        }
    }

    let mut made_progress = run_node_fast_loop(services, runtime)?;

    while let Some(cmd) = runtime.consensus_out_recver.pop_front() {
        services.send_to_destination(&cmd.destination, &cmd.payload)?;
        made_progress = true;
    }

    while let Some(tx) = runtime.mempool_txs.pop_front() {
        services.forward_external_tx(tx)?;
        made_progress = true;
    }

    while let Some(item) = runtime.local_nv_stream.pop_front() {
        services.enqueue_local_nv(item)?;
        made_progress = true;
    }

    if let Some(disabler) = runtime.node_disabler.as_mut() {
        made_progress |= node_disabler_poll(services, disabler)?;
    }

    made_progress |= monitor_visor_state_lag_once(services, &mut runtime.visor_lag);
    Ok(made_progress)
}

/// This seed did not decompile during the wave.  Its address cluster sits with
/// startup/config code, and node.rs strings around the owning state machine name
/// `node_startup_validator_config`, `new_validator_get_wallet`, and
/// `validator_gossip_priority`.  The recovered behavior is the non-allocating
/// validation used before service startup: validator mode requires a home
/// public IP and a self entry in the validator map; non-validator mode must not
/// carry validator-only maps.
pub fn check_validator_config(config: &NodeStartupConfig) -> Result<(), NodeError> {
    match (&config.mode, &config.validator) {
        (NodeMode::Validator, Some(validator)) => {
            let Some(home_ip) = validator.home_public_ip else {
                return Err(NodeError::MissingHomePublicIp);
            };
            let Some(home_addr) = validator.known_validators.get(&validator.home_validator) else {
                return Err(NodeError::ValidatorConfig(
                    "node_startup_validator_config missing home validator".to_string(),
                ));
            };
            if home_addr.ip != home_ip {
                return Err(NodeError::ValidatorConfig(
                    "node_startup_validator_config home public ip mismatch".to_string(),
                ));
            }
            if config.validator_gossip_priority.contains_key(&validator.home_validator)
                && validator.known_validators.is_empty()
            {
                return Err(NodeError::ValidatorConfig(
                    "validator_gossip_priority configured without validators".to_string(),
                ));
            }
            Ok(())
        }
        (NodeMode::Validator, None) => Err(NodeError::ValidatorConfig(
            "new_validator_get_wallet requires validator config".to_string(),
        )),
        (NodeMode::NonValidator, Some(_)) => Err(NodeError::ValidatorConfig(
            "non-validator cannot carry validator startup config".to_string(),
        )),
        (NodeMode::NonValidator, None) => Ok(()),
    }
}

/// Builds the two slow-ABCI workers seen in rodata as `slow abci block` and
/// `node slow abci_state driver`, plus the `node_slow_abci_engine` wrapper.  The
/// binary allocates two large future states and returns the pair of handles.
pub fn spawn_slow_abci_services(fast_height: u64, split_client_blocks: bool) -> SlowAbciServices {
    SlowAbciServices {
        block_task_name: SLOW_ABCI_BLOCK_TASK,
        state_driver_task_name: SLOW_ABCI_STATE_DRIVER_TASK,
        engine_task_name: NODE_SLOW_ABCI_ENGINE_TASK,
        fast_height,
        split_client_blocks,
        queued_blocks: VecDeque::new(),
        latest_snapshot: None,
    }
}

/// Copies `is_main_signer`, unwraps the home public IP, and constructs the
/// periodic `node_disabler` future.  The binary panics with `Could not get home
/// public ip` when the option discriminant is not present.
pub fn spawn_node_disabler(config: &ValidatorConfig) -> Result<NodeDisablerState, NodeError> {
    let Some(home_public_ip) = config.home_public_ip else {
        return Err(NodeError::MissingHomePublicIp);
    };

    Ok(NodeDisablerState {
        is_main_signer: config.is_main_signer,
        home_public_ip,
        active_validator_to_ip: config.known_validators.clone(),
        last_seen_by_validator: BTreeMap::new(),
        last_firewall_alert_by_validator: BTreeMap::new(),
        disabled_validators: BTreeSet::new(),
        poll: TimedPollState::new(NODE_DISABLER_TASK),
    })
}

/// The `node_fast` loop receives ABCI work, enforces the expected height,
/// applies the block, updates execution-state fields, forwards replica commands,
/// and emits `run_node_apply_abci_block`, `run_node_send_execution_state`, and
/// `replica_cmds` spans/metrics.
pub fn run_node_fast_loop<S: NodeServices>(
    services: &mut S,
    runtime: &mut NodeRuntime,
) -> Result<bool, NodeError> {
    let mut made_progress = false;

    while let Some(work) = runtime.fast_rx.pop_front() {
        match work {
            FastLoopWork::ApplyAbciBlock(block) => {
                if block.height != runtime.expected_fast_height {
                    return Err(NodeError::UnexpectedFastHeight {
                        expected: runtime.expected_fast_height,
                        got: block.height,
                    });
                }

                services.log(
                    RUN_NODE_APPLY_ABCI_BLOCK,
                    format!("applying abci block height={} round={}", block.height, block.round),
                );
                let mut snapshot = services.apply_abci_block(&block)?;
                snapshot.height = block.height;
                snapshot.round = block.round;
                snapshot.l1_hash = block.l1_hash;
                snapshot.updated_at = services.now();

                runtime.fast_height = block.height;
                runtime.expected_fast_height = block.height.saturating_add(1);
                runtime.latest_l1_hash = block.l1_hash;
                runtime.execution_state = Some(snapshot.clone());

                services.log(
                    RUN_NODE_SEND_EXECUTION_STATE,
                    format!("send execution state height={}", snapshot.height),
                );
                services.send_execution_state(&snapshot)?;

                services.log(
                    REPLICA_CMDS_METRIC,
                    format!("replica_cmds len={}", block.replica_cmds.len()),
                );
                for cmd in block.replica_cmds {
                    services.send_to_destination(&cmd.destination, &cmd.payload)?;
                }
                made_progress = true;
            }
            FastLoopWork::ForwardExternalTx(tx) => {
                services.forward_external_tx(tx)?;
                made_progress = true;
            }
            FastLoopWork::LocalNvStream(item) => {
                services.enqueue_local_nv(item)?;
                made_progress = true;
            }
            FastLoopWork::Shutdown => break,
        }
    }

    Ok(made_progress)
}

/// Serializes the ABCI state sent in TCP/gossip greetings.  The binary logs the
/// input height, writes an EVM KVS checkpoint when present, then logs
/// `initial_height`, `height`, `l1_hash`, and serialized length.
pub fn serialize_abci_state_for_greeting<S: NodeServices>(
    services: &mut S,
    state: &AbciState,
) -> Result<GreetingPayload, NodeError> {
    services.log(
        SERIALIZE_GREETING_LOG,
        format!("@@ serializing abci state for greeting @@ [height: {}]", state.height),
    );

    if let Some(bytes) = state.evm_kv_checkpoint.as_deref() {
        services.save_evm_kvs_checkpoint(state.height, bytes)?;
        services.log(
            SERIALIZE_GREETING_LOG,
            format!("@@ saved evm kvs checkpoint for abci state @@ [height: {}]", state.height),
        );
    }

    let mut bytes = Vec::with_capacity(8 + 8 + 32 + state.serialized_state.len());
    bytes.extend_from_slice(&state.initial_height.to_le_bytes());
    bytes.extend_from_slice(&state.height.to_le_bytes());
    bytes.extend_from_slice(&state.l1_hash.0);
    bytes.extend_from_slice(&state.serialized_state);

    services.log(
        SERIALIZED_GREETING_LOG,
        format!(
            "@@ serialized abci state for greeting @@ [abci_state.initial_height(): {}] @ [height: {}] @ [l1_hash: {:?}] @ [serialized_abci_state.len(): {}]",
            state.initial_height,
            state.height,
            state.l1_hash.0,
            bytes.len()
        ),
    );

    Ok(GreetingPayload {
        initial_height: state.initial_height,
        height: state.height,
        l1_hash: state.l1_hash,
        bytes,
    })
}

/// One iteration of the periodic service loop.  The binary keeps a bounded
/// twenty-entry `visor_abci_states` history, calls `get_visor_state`, logs when
/// lag increases, and sleeps for five seconds between samples.
pub fn monitor_visor_state_lag_once<S: NodeServices>(
    services: &mut S,
    monitor: &mut VisorLagMonitor,
) -> bool {
    let Some(visor_state) = services.get_visor_state() else {
        return false;
    };

    let oldest_height = monitor.history.front().map(|s| s.height).unwrap_or(visor_state.height);
    let lag = visor_state.height.saturating_sub(oldest_height);
    if lag > monitor.last_lag {
        services.log(
            VISOR_ABCI_STATES_METRIC,
            format!(
                "visor lag increased @@ [oldest_visor_state: {}] @ [visor_state: {}]",
                oldest_height, visor_state.height
            ),
        );
        monitor.last_lag = lag;
    }

    monitor.history.push_back(visor_state);
    while monitor.history.len() > VISOR_LAG_HISTORY {
        monitor.history.pop_front();
    }
    true
}

pub fn monitor_visor_state_lag_sleep() -> Duration {
    VISOR_LAG_SLEEP
}

/// Looks up a 20-byte validator key in the node-disabler maps and returns two
/// elapsed-second values.  Callers compare the sum to `3.0` and pass the
/// `node_disabler` label.
pub fn node_disabler_elapsed_pair(
    disabler: &NodeDisablerState,
    validator: &ValidatorId,
    now: Instant,
) -> (f64, f64) {
    let inactive_for = disabler
        .last_seen_by_validator
        .get(validator)
        .map(|last_seen| now.saturating_duration_since(*last_seen).as_secs_f64())
        .unwrap_or(f64::INFINITY);
    let alert_idle_for = disabler
        .last_firewall_alert_by_validator
        .get(validator)
        .map(|last_alert| now.saturating_duration_since(*last_alert).as_secs_f64())
        .unwrap_or(f64::INFINITY);
    (inactive_for, alert_idle_for)
}

/// `node_node__node_disabler_poll`.
///
/// Polls the periodic disabler loop.  Main signers emit firewall/IP alerts when
/// a validator has been inactive long enough; non-main signers only maintain the
/// disabled set.  The compiled future records atomic poll/timing counters and
/// rebuilds its sleep/check child future after each pass.
pub fn node_disabler_poll<S: NodeServices>(
    services: &mut S,
    disabler: &mut NodeDisablerState,
) -> Result<bool, NodeError> {
    let now = services.now();
    disabler.poll.begin_poll(now);

    let mut changed = false;
    let validators: Vec<ValidatorId> = disabler.active_validator_to_ip.keys().cloned().collect();
    for validator in validators {
        let (inactive_for, alert_idle_for) = node_disabler_elapsed_pair(disabler, &validator, now);
        if inactive_for + alert_idle_for <= NODE_DISABLER_ALERT_SECONDS {
            continue;
        }

        if disabler.disabled_validators.insert(validator.clone()) {
            changed = true;
        }

        if disabler.is_main_signer && alert_idle_for.is_infinite() {
            disabler.last_firewall_alert_by_validator.insert(validator.clone(), now);
            services.log(
                FIREWALL_IPS_ALERT,
                format!("node_disabler inactive validator {:?} from home_ip={}", validator.0, disabler.home_public_ip),
            );
        }
    }

    disabler.poll.schedule(now + CONNECTION_CHECK_REARM);
    Ok(changed)
}

/// Instrumented poll wrapper around connection checks.  The binary stores and
/// replaces the waker through a vtable, updates first-poll/idle/scheduled
/// counters, then polls the inner future for `connection_checks` / `closing
/// gossip` / `abci_stream send tcp greeting` work.
pub fn poll_node_connection_checks(
    poll: &mut TimedPollState,
    now: Instant,
    inner_ready: bool,
) -> bool {
    poll.begin_poll(now);
    if inner_ready {
        true
    } else {
        poll.schedule(now + CONNECTION_CHECK_REARM);
        false
    }
}

/// Timeout adapter around `handle_stream_connection`, `abci_stream`, and
/// `gossip_server_connect_to_peer`.  On pending it rebuilds the sleep/timeout
/// state; on ready it unwraps the connection result and propagates the success
/// flag.
pub fn poll_gossip_server_connect_to_peer_timeout(
    poll: &mut TimedPollState,
    now: Instant,
    inner_ready: bool,
    timed_out: bool,
) -> Result<bool, NodeError> {
    poll.begin_poll(now);
    if timed_out {
        poll.schedule(now + CONNECTION_CHECK_REARM);
        return Err(NodeError::Service("gossip_server_connect_to_peer timed out".to_string()));
    }
    if inner_ready {
        Ok(true)
    } else {
        poll.schedule(now + CONNECTION_CHECK_REARM);
        Ok(false)
    }
}
