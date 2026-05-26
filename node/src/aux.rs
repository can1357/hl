use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NODE_TRADES: &str = "node_trades";
const NODE_FILLS: &str = "node_fills";
const NODE_TWAP_STATUSES: &str = "node_twap_statuses";
const NODE_RAW_BOOK_DIFFS: &str = "node_raw_book_diffs";
const NODE_ORDER_STATUSES: &str = "node_order_statuses";
const MISC_EVENTS: &str = "misc_events";
const HIP3_ORACLE_UPDATES: &str = "hip3_oracle_updates";
const SYSTEM_AND_CORE_WRITER_ACTIONS: &str = "system_and_core_writer_actions";
const EVM_BLOCK_AND_RECEIPTS: &str = "evm_block_and_receipts";

const BATCH_BY_BLOCK_SUFFIX: &str = "_by_block";
const STREAMING_SUFFIX: &str = "_streaming";
const DEFAULT_TIMER_WINDOW: Duration = Duration::from_secs(15);

const EVM_BLOCK_AND_RECEIPTS_KIND_21: u8 = 21;
const EVM_BLOCK_AND_RECEIPTS_KIND_22: u8 = 22;
const EVM_BLOCK_AND_RECEIPTS_KIND_23: u8 = 23;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuxConfig {
    /// [INFERENCE] The first config byte gates the two recovered 15-second
    /// helper timers written at the start of the object.
    pub enable_node_compute_timers: bool,
    pub output_flags: OutputWriterFlags,
    /// [INFERENCE] The last config byte switches `evm_block_and_receipts` from
    /// one combined daily liner to three kind-specific liners plus the combined
    /// liner. The binary always constructs the combined liner.
    pub split_evm_block_and_receipts: bool,
    /// Result of the global deployment lookup performed near the end of the
    /// constructor. The binary clones the key only for network selectors 5 and
    /// 17 when deployment mode is 1.
    pub discovered_liner_key: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutputPartition {
    Plain,
    BatchByBlock,
    StreamWithBlockInfo,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeAux {
    pub node_compute_timer: Option<AuxTimer>,
    pub run_node_compute_timer: Option<AuxTimer>,
    pub evm_block_and_receipts: EvmBlockAndReceiptsWriter,
    pub liners: AuxOutputLiners,
    pub scratch_path: SmallPath,
    pub flush_generation: u32,
    /// Present when the recovered global lookup returned a daily-liner key for
    /// network selector 5 or 17 and deployment mode 1.
    pub discovered_liner_key: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuxOutputLiners {
    pub node_trades: Option<DailyLiner>,
    pub node_fills: Option<DailyLiner>,
    pub node_twap_statuses: Option<DailyLiner>,
    pub node_raw_book_diffs: Option<DailyLiner>,
    pub node_order_statuses: Option<DailyLiner>,
    pub misc_events: Option<DailyLiner>,
    pub hip3_oracle_updates: Option<DailyLiner>,
    pub system_and_core_writer_actions: Option<DailyLiner>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvmBlockAndReceiptsWriter {
    Combined(DailyLiner),
    Split {
        kind_23: EvmKindLiner,
        kind_21: EvmKindLiner,
        kind_22: EvmKindLiner,
        combined: DailyLiner,
        registry: Arc<EvmKindRegistry>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmKindLiner {
    pub kind: u8,
    pub prefix: [u8; 2],
    pub registry_entry: Arc<String>,
    pub liner: Option<DailyLiner>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvmKindRegistry {
    entries: BTreeMap<u8, Arc<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DailyLiner {
    pub key: String,
    pub data_dir: PathBuf,
    pub hourly_dir: PathBuf,
    pub created_day: u32,
    pub created_hour: u8,
    pub buffering_disabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuxTimer {
    pub samples: u64,
    pub total: Duration,
    pub window: Duration,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SmallPath {
    pub bytes: Vec<u8>,
}

pub fn build_output_writers(config: AuxConfig) -> NodeAux {
    if config.output_flags.batch_by_block && config.output_flags.stream_with_block_info {
        panic!("cannot set both batch_by_block and stream_with_block_info");
    }

    let partition = if config.output_flags.batch_by_block {
        OutputPartition::BatchByBlock
    } else if config.output_flags.stream_with_block_info {
        OutputPartition::StreamWithBlockInfo
    } else {
        OutputPartition::Plain
    };

    let liners = AuxOutputLiners {
        node_trades: maybe_liner(
            config.output_flags.write_trades,
            NODE_TRADES,
            &partition,
            config.output_flags.disable_output_file_buffering,
        ),
        node_fills: maybe_liner(
            config.output_flags.write_fills,
            NODE_FILLS,
            &partition,
            config.output_flags.disable_output_file_buffering,
        ),
        // The binary constructs `node_twap_statuses` under the same branch as
        // `node_fills`; there is no independent flag byte for it in the aux
        // constructor.
        node_twap_statuses: maybe_liner(
            config.output_flags.write_fills,
            NODE_TWAP_STATUSES,
            &partition,
            config.output_flags.disable_output_file_buffering,
        ),
        node_raw_book_diffs: maybe_liner(
            config.output_flags.write_raw_book_diffs,
            NODE_RAW_BOOK_DIFFS,
            &partition,
            config.output_flags.disable_output_file_buffering,
        ),
        node_order_statuses: maybe_liner(
            config.output_flags.write_order_statuses,
            NODE_ORDER_STATUSES,
            &partition,
            config.output_flags.disable_output_file_buffering,
        ),
        misc_events: maybe_liner(
            config.output_flags.write_misc_events,
            MISC_EVENTS,
            &partition,
            config.output_flags.disable_output_file_buffering,
        ),
        hip3_oracle_updates: maybe_liner(
            config.output_flags.write_hip3_oracle_updates,
            HIP3_ORACLE_UPDATES,
            &partition,
            config.output_flags.disable_output_file_buffering,
        ),
        system_and_core_writer_actions: maybe_liner(
            config.output_flags.write_system_and_core_writer_actions,
            SYSTEM_AND_CORE_WRITER_ACTIONS,
            &partition,
            config.output_flags.disable_output_file_buffering,
        ),
    };

    let evm_block_and_receipts = if config.split_evm_block_and_receipts {
        build_split_evm_block_and_receipts(config.output_flags.disable_output_file_buffering)
    } else {
        EvmBlockAndReceiptsWriter::Combined(DailyLiner::new(
            EVM_BLOCK_AND_RECEIPTS,
            config.output_flags.disable_output_file_buffering,
        ))
    };

    let timer = config
        .enable_node_compute_timers
        .then(|| AuxTimer::new(DEFAULT_TIMER_WINDOW));

    NodeAux {
        node_compute_timer: timer.clone(),
        run_node_compute_timer: timer,
        evm_block_and_receipts,
        liners,
        scratch_path: SmallPath::default(),
        flush_generation: 0,
        discovered_liner_key: config.discovered_liner_key,
    }
}

fn maybe_liner(
    enabled: bool,
    name: &'static str,
    partition: &OutputPartition,
    buffering_disabled: bool,
) -> Option<DailyLiner> {
    enabled.then(|| DailyLiner::new(&partitioned_liner_key(name, partition), buffering_disabled))
}

fn partitioned_liner_key(name: &str, partition: &OutputPartition) -> String {
    match partition {
        OutputPartition::Plain => name.to_owned(),
        OutputPartition::BatchByBlock => {
            let mut key = String::with_capacity(name.len() + BATCH_BY_BLOCK_SUFFIX.len());
            key.push_str(name);
            key.push_str(BATCH_BY_BLOCK_SUFFIX);
            key
        }
        OutputPartition::StreamWithBlockInfo => {
            let mut key = String::with_capacity(name.len() + STREAMING_SUFFIX.len());
            key.push_str(name);
            key.push_str(STREAMING_SUFFIX);
            key
        }
    }
}

fn build_split_evm_block_and_receipts(buffering_disabled: bool) -> EvmBlockAndReceiptsWriter {
    let registry = Arc::new(EvmKindRegistry::new([
        (EVM_BLOCK_AND_RECEIPTS_KIND_21, "21"),
        (EVM_BLOCK_AND_RECEIPTS_KIND_22, "22"),
        (EVM_BLOCK_AND_RECEIPTS_KIND_23, "23"),
    ]));

    EvmBlockAndReceiptsWriter::Split {
        kind_23: EvmKindLiner::from_registry(EVM_BLOCK_AND_RECEIPTS_KIND_23, &registry),
        kind_21: EvmKindLiner::from_registry(EVM_BLOCK_AND_RECEIPTS_KIND_21, &registry),
        kind_22: EvmKindLiner::from_registry(EVM_BLOCK_AND_RECEIPTS_KIND_22, &registry),
        combined: DailyLiner::new(EVM_BLOCK_AND_RECEIPTS, buffering_disabled),
        registry,
    }
}

impl DailyLiner {
    pub fn new(key: &str, buffering_disabled: bool) -> Self {
        assert_daily_liner_key(key);

        let data_dir = Path::new("data").join(key);
        let hourly_dir = data_dir.join("hourly");
        let (created_day, created_hour) = current_day_and_hour();

        Self {
            key: key.to_owned(),
            data_dir,
            hourly_dir,
            created_day,
            created_hour,
            buffering_disabled,
        }
    }
}

impl AuxTimer {
    pub const fn new(window: Duration) -> Self {
        Self {
            samples: 0,
            total: Duration::ZERO,
            window,
        }
    }
}

impl EvmKindRegistry {
    pub fn new<const N: usize>(entries: [(u8, &'static str); N]) -> Self {
        let mut map = BTreeMap::new();
        for (kind, prefix) in entries {
            map.insert(kind, Arc::new(prefix.to_owned()));
        }
        Self { entries: map }
    }

    pub fn get(&self, kind: u8) -> Option<Arc<String>> {
        self.entries.get(&kind).cloned()
    }
}

impl EvmKindLiner {
    pub fn from_registry(kind: u8, registry: &Arc<EvmKindRegistry>) -> Self {
        let registry_entry = registry
            .get(kind)
            .unwrap_or_else(|| panic!("No entry found for evm_block_and_receipts kind {kind}"));
        let prefix = two_byte_prefix(&registry_entry);
        let liner = evm_kind_daily_liner(kind);

        Self {
            kind,
            prefix,
            registry_entry,
            liner,
        }
    }
}

fn assert_daily_liner_key(key: &str) {
    if key.as_bytes().first() == Some(&b'/') || key.as_bytes().last() == Some(&b'/') {
        panic!("daily liner key must not start or end with '/'");
    }
}

fn two_byte_prefix(value: &str) -> [u8; 2] {
    let bytes = value.as_bytes();
    [bytes.first().copied().unwrap_or(0), bytes.get(1).copied().unwrap_or(0)]
}

fn evm_kind_daily_liner(kind: u8) -> Option<DailyLiner> {
    // Recovered control flow suppresses the kind-specific daily liner for a
    // deployment selector range and for kind indexes outside 21..=23.
    if !(EVM_BLOCK_AND_RECEIPTS_KIND_21..=EVM_BLOCK_AND_RECEIPTS_KIND_23).contains(&kind) {
        return None;
    }

    Some(DailyLiner::new(
        &partitioned_liner_key(EVM_BLOCK_AND_RECEIPTS, &OutputPartition::Plain),
        false,
    ))
}

fn current_day_and_hour() -> (u32, u8) {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let seconds = elapsed.as_secs();
    let day = (seconds / 86_400) as u32;
    let hour = ((seconds / 3_600) % 24) as u8;
    (day, hour)
}

