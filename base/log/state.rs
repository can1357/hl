use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};

use super::handle::{LogHandle, LogHandleConfig};

const DEFAULT_N_OVERFLOW_FILES: u32 = 10;
const STARTUP_N_OVERFLOW_FILES: u32 = 100;
const DEFAULT_LEVEL_BYTE: u8 = 1;
const MAX_REASSERTIONS: usize = 100;

static STATE: LazyLock<Mutex<LogState>> = LazyLock::new(|| Mutex::new(LogState::default()));
static LIVE_LOGGING_PROCESS: AtomicBool = AtomicBool::new(false);

/// Process-wide log settings installed before the logging handle is used.
///
/// The optimized binary stores the three `Option<String>` values first, followed by
/// `n_overflow_files` at offset `0x48`, `throttle` at `0x4c`, `log_to_stdout` at `0x4d`,
/// and the one-byte level at `0x4e`. `Debug` prints fields in the declaration order below.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogSettings {
    pub level: LogLevel,
    pub err_fln: Option<String>,
    pub stdout_fln: Option<String>,
    pub throttle: bool,
    pub log_to_stdout: bool,
    pub n_overflow_files: u32,
    pub custom_dir: Option<String>,
}

impl LogSettings {
    pub fn startup(log_to_stdout: bool) -> Self {
        Self {
            n_overflow_files: STARTUP_N_OVERFLOW_FILES,
            log_to_stdout,
            ..Self::default()
        }
    }

    pub fn with_paths(
        mut self,
        err_fln: Option<String>,
        stdout_fln: Option<String>,
        custom_dir: Option<String>,
    ) -> Self {
        self.err_fln = err_fln;
        self.stdout_fln = stdout_fln;
        self.custom_dir = custom_dir;
        self
    }

    fn into_handle_config(self) -> LogHandleConfig {
        LogHandleConfig {
            error_path: self.err_fln,
            warn_path: self.stdout_fln,
            log_base_dir: self.custom_dir,
            level: self.n_overflow_files,
            install_guard: self.throttle,
            suppress_live_default_files: !self.log_to_stdout,
            mode_index: self.level.0,
        }
    }
}

impl Default for LogSettings {
    fn default() -> Self {
        Self {
            level: LogLevel(DEFAULT_LEVEL_BYTE),
            err_fln: None,
            stdout_fln: None,
            throttle: is_live_logging_process(),
            log_to_stdout: false,
            n_overflow_files: DEFAULT_N_OVERFLOW_FILES,
            custom_dir: None,
        }
    }
}

/// One-byte logging level/filter value. The stripped binary preserves the byte but not the
/// source enum name; observed startup/default initialization writes `1`.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct LogLevel(pub u8);

impl std::fmt::Debug for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("LogLevel").field(&self.0).finish()
    }
}

#[derive(Default)]
struct LogState {
    handle: Option<LogHandle>,
    effective_settings: Option<LogSettings>,
    requested_settings: Option<LogSettings>,
    n_sets: usize,
    active: bool,
}

impl LogState {
    fn set(&mut self, settings: LogSettings) {
        if let Some(effective_settings) = &self.effective_settings {
            assert_eq!(effective_settings, &settings);
        } else {
            let effective_settings = settings.clone();
            self.handle = Some(LogHandle::new(effective_settings.clone().into_handle_config()));
            self.effective_settings = Some(effective_settings);
        }

        match &self.requested_settings {
            Some(requested_settings) if requested_settings == &settings => {}
            Some(requested_settings) => {
                assert!(
                    !self.active,
                    "log settings changed after the logging handle became active: old={requested_settings:?}, new={settings:?}",
                );
                assert_eq!(requested_settings, &settings);
            }
            None => {
                self.requested_settings = Some(settings);
            }
        }

        let old_n_sets = self.n_sets;
        self.n_sets = old_n_sets.checked_add(1).unwrap();
        if old_n_sets >= MAX_REASSERTIONS {
            panic!("CGuard was set too many times");
        }
    }

    fn handle(&mut self) -> &LogHandle {
        if self.handle.is_none() {
            self.set(LogSettings::default());
        }
        self.active = true;
        self.handle.as_ref().expect("log handle initialized")
    }
}

/// Install the process-wide log settings. Repeated calls are allowed only when the full
/// settings value is identical to the value already installed.
pub fn set_log_settings(settings: LogSettings) {
    STATE
        .lock()
        .expect("log state mutex poisoned")
        .set(settings);
}

/// Install the default settings. In the binary this corresponds to the special all-sentinel
/// argument path and materializes the defaults before entering the guarded update path.
pub fn set_default_log_settings() {
    set_log_settings(LogSettings::default());
}

pub fn startup_log_settings(log_to_stdout: bool) -> LogSettings {
    LogSettings::startup(log_to_stdout)
}

pub fn with_log_handle<R>(f: impl FnOnce(&LogHandle) -> R) -> R {
    let mut state = STATE.lock().expect("log state mutex poisoned");
    f(state.handle())
}

pub fn configure_live_logging_process(is_live: bool) {
    LIVE_LOGGING_PROCESS.store(is_live, Ordering::Relaxed);
}

pub fn is_live_logging_process() -> bool {
    LIVE_LOGGING_PROCESS.load(Ordering::Relaxed)
}
