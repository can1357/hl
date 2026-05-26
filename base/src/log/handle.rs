use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const NO_STRING: u64 = 0x8000_0000_0000_0000;
const DEFAULT_PATTERN: &str = "{d(%Y-%m-%d %H:%M:%S.%f)} {l} {f}:{L} >>> {m}{n}";
const DEFAULT_ROOT: &str = "/data/log/";
const WARN_DIR: &str = "/warn/";
const ERROR_DIR: &str = "/error/";
const MAX_LOG_FILE_BYTES: u64 = 209_715_200;
const DEFAULT_LEVEL: u32 = 10;

const MODULES: [ModuleLogConfig; 13] = [
    ModuleLogConfig { name: "base", default_path_bucket: 0 },
    ModuleLogConfig { name: "peri_base", default_path_bucket: 0 },
    ModuleLogConfig { name: "infra", default_path_bucket: 0 },
    ModuleLogConfig { name: "live", default_path_bucket: 0 },
    ModuleLogConfig { name: "nexus", default_path_bucket: 0 },
    ModuleLogConfig { name: "trade", default_path_bucket: 1 },
    ModuleLogConfig { name: "nn", default_path_bucket: 0 },
    ModuleLogConfig { name: "l1", default_path_bucket: 0 },
    ModuleLogConfig { name: "node", default_path_bucket: 0 },
    ModuleLogConfig { name: "peripheral", default_path_bucket: 0 },
    ModuleLogConfig { name: "net_utils", default_path_bucket: 0 },
    ModuleLogConfig { name: "db", default_path_bucket: 0 },
    ModuleLogConfig { name: "evm_rpc", default_path_bucket: 0 },
];

#[derive(Clone, Debug, Default)]
pub struct LogHandleConfig {
    pub error_path: Option<String>,
    pub warn_path: Option<String>,
    pub log_base_dir: Option<String>,
    pub level: u32,
    pub install_guard: bool,
    pub suppress_live_default_files: bool,
    pub mode_index: u8,
}

#[derive(Debug)]
pub struct LogHandle {
    pub config: LogHandleConfig,
    pub handle: ActiveLogHandle,
    pub guard: Option<LogGuard>,
    pub local_offset_seconds: i32,
}

#[derive(Clone, Debug)]
pub struct ActiveLogHandle {
    config: LogRuntimeConfig,
}

#[derive(Clone, Debug)]
pub struct LogRuntimeConfig {
    pub root_level: u8,
    pub appenders: BTreeMap<String, AppenderConfig>,
    pub loggers: Vec<LoggerConfig>,
}

#[derive(Clone, Debug)]
pub struct AppenderConfig {
    pub name: String,
    pub path: Option<PathBuf>,
    pub pattern: &'static str,
    pub max_file_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct LoggerConfig {
    pub module: &'static str,
    pub level: u32,
    pub appenders: Vec<String>,
    pub additive: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum LogKind {
    Error,
    Warn,
}

#[derive(Clone, Copy, Debug)]
struct ModuleLogConfig {
    name: &'static str,
    default_path_bucket: u8,
}

#[derive(Debug)]
pub struct LogGuard {
    _private: (),
}

impl LogHandle {
    pub fn new(config: LogHandleConfig) -> Self {
        let local_offset_seconds = local_offset_seconds().expect("Local time out of range");
        let runtime_config = build_log4rs_config(&config, local_offset_seconds);
        let guard = config.install_guard.then(LogGuard::install);
        let handle = ActiveLogHandle::init(runtime_config).expect("called `Result::unwrap()` on an `Err` value");

        Self {
            config,
            handle,
            guard,
            local_offset_seconds,
        }
    }

    pub fn runtime_config(&self) -> &LogRuntimeConfig {
        &self.handle.config
    }
}

impl ActiveLogHandle {
    fn init(config: LogRuntimeConfig) -> Result<Self, LogInitError> {
        Ok(Self { config })
    }
}

impl LogGuard {
    fn install() -> Self {
        Self { _private: () }
    }
}

#[derive(Debug)]
pub struct LogInitError;

impl Default for LogRuntimeConfig {
    fn default() -> Self {
        Self {
            root_level: 0,
            appenders: BTreeMap::new(),
            loggers: Vec::new(),
        }
    }
}

fn build_log4rs_config(config: &LogHandleConfig, local_offset_seconds: i32) -> LogRuntimeConfig {
    let mut runtime = LogRuntimeConfig::default();
    runtime.root_level = config.mode_index.saturating_add(1);

    for module in MODULES {
        let error_path = resolve_log_path(
            config,
            LogKind::Error,
            module,
            config.error_path.as_deref(),
            local_offset_seconds,
        );
        let warn_path = resolve_log_path(
            config,
            LogKind::Warn,
            module,
            config.warn_path.as_deref(),
            local_offset_seconds,
        );

        let error_appender = format!("err_appender_{}", module.name);
        let warn_appender = format!("warn_appender_{}", module.name);

        runtime.appenders.insert(
            error_appender.clone(),
            AppenderConfig::rolling_file(error_appender.clone(), error_path),
        );
        runtime.appenders.insert(
            warn_appender.clone(),
            AppenderConfig::rolling_file(warn_appender.clone(), warn_path),
        );

        let level = if config.level == 0 {
            DEFAULT_LEVEL
        } else {
            config.level
        };

        runtime.loggers.push(LoggerConfig {
            module: module.name,
            level,
            appenders: vec![error_appender, warn_appender],
            additive: false,
        });
    }

    runtime
}

fn resolve_log_path(
    config: &LogHandleConfig,
    kind: LogKind,
    module: ModuleLogConfig,
    explicit_path: Option<&str>,
    local_offset_seconds: i32,
) -> Option<PathBuf> {
    if let Some(path) = explicit_path {
        assert!(!is_live_logging_process(), "assertion failed: !is_live");
        return Some(PathBuf::from(path));
    }

    if let Some(base_dir) = config.log_base_dir.as_deref() {
        return Some(custom_base_path(
            base_dir,
            kind,
            local_offset_seconds,
        ));
    }

    if config.suppress_live_default_files || !is_live_logging_process() {
        return None;
    }

    Some(default_live_path(kind, module, local_offset_seconds))
}

fn custom_base_path(
    base_dir: &str,
    kind: LogKind,
    local_offset_seconds: i32,
) -> PathBuf {
    let kind_dir = match kind {
        LogKind::Error => "error",
        LogKind::Warn => "warn",
    };
    Path::new(base_dir)
        .join(kind_dir)
        .join(date_path_component(local_offset_seconds))
}

fn default_live_path(kind: LogKind, module: ModuleLogConfig, local_offset_seconds: i32) -> PathBuf {
    let mut path = String::new();
    path.push_str(live_path_prefix());
    path.push_str(DEFAULT_ROOT);
    path.push_str(default_path_bucket_name(module.default_path_bucket));
    match kind {
        LogKind::Error => path.push_str(ERROR_DIR),
        LogKind::Warn => path.push_str(WARN_DIR),
    }
    path.push_str(&date_path_component(local_offset_seconds));
    PathBuf::from(path)
}

fn date_path_component(local_offset_seconds: i32) -> String {
    format!("{}", local_offset_seconds)
}

fn default_path_bucket_name(bucket: u8) -> &'static str {
    match bucket {
        0 => "0",
        1 => "1",
        _ => "unknown",
    }
}

fn live_path_prefix() -> &'static str {
    ""
}

fn is_live_logging_process() -> bool {
    crate::log::state::is_live_logging_process()
}

fn local_offset_seconds() -> Option<i32> {
    Some(chrono::Local::now().offset().local_minus_utc())
}

impl AppenderConfig {
    fn rolling_file(name: String, path: Option<PathBuf>) -> Self {
        Self {
            name,
            path,
            pattern: DEFAULT_PATTERN,
            max_file_bytes: MAX_LOG_FILE_BYTES,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
struct RawOptionString {
    len_or_sentinel: u64,
    ptr: *const u8,
    len: u64,
}

impl RawOptionString {
    fn is_none(self) -> bool {
        self.len_or_sentinel == NO_STRING
    }
}
