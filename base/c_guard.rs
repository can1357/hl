use std::sync::{LazyLock, Mutex};

use crate::build_mode::BuildMode;

const DEFAULT_LOG_LEVEL: u32 = 10;
const MAX_C_GUARD_SETS: usize = 100;

static C_GUARD_STATE: LazyLock<Mutex<CGuardState>> =
    LazyLock::new(|| Mutex::new(CGuardState::default()));

/// Log configuration installed by C-guard call sites before the node hands work to the
/// C-backed execution path.
///
/// The binary stores three nullable owned strings, then a `u32` level and three compact
/// bytes. Repeated calls must pass byte-for-byte equivalent values; a changed guard after
/// the first successful install trips an `assert_eq!`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CGuard {
    pub error_path: Option<String>,
    pub warn_path: Option<String>,
    pub log_base: Option<String>,
    pub level: u32,
    pub install_guard: bool,
    pub disable_default_live_files: bool,
    pub mode_index: u8,
}

impl CGuard {
    pub fn for_build_mode(build_mode: BuildMode) -> Self {
        Self {
            error_path: None,
            warn_path: None,
            log_base: None,
            level: DEFAULT_LOG_LEVEL,
            install_guard: matches!(build_mode, BuildMode::Release { .. }),
            disable_default_live_files: false,
            mode_index: 1,
        }
    }

    pub fn with_level(mut self, level: u32) -> Self {
        self.level = level;
        self
    }

    pub fn with_disable_default_live_files(mut self, disable_default_live_files: bool) -> Self {
        self.disable_default_live_files = disable_default_live_files;
        self
    }
}

impl Default for CGuard {
    fn default() -> Self {
        Self::for_build_mode(BuildMode::Release { flag: 0 })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CGuardLogHandle {
    guard: CGuard,
}

impl CGuardLogHandle {
    fn new(guard: CGuard) -> Self {
        Self { guard }
    }
}

#[derive(Default, Debug)]
struct CGuardState {
    log_handle: Option<CGuardLogHandle>,
    active_guard: Option<CGuard>,
    n_sets: usize,
    inconsistent_state: bool,
}

/// Install or re-assert the process-wide C guard.
///
/// This is not a cancellation guard. It is only a serialized, process-wide consistency guard:
/// callers may invoke it repeatedly during startup/poll setup, but all non-default calls must
/// agree on the same `CGuard` value. A mutex protects the small global state; no critical
/// section is held after this function returns.
pub fn set_c_guard(guard: Option<CGuard>) {
    let guard = guard.unwrap_or_default();
    let mut state = C_GUARD_STATE.lock().expect("CGuard mutex poisoned");

    if let Some(log_handle) = &state.log_handle {
        assert_eq!(&log_handle.guard, &guard);
    } else {
        state.log_handle = Some(CGuardLogHandle::new(guard.clone()));
    }

    assert!(
        !state.inconsistent_state,
        "CGuard state unexpectedly marked inconsistent: count={:?}, guard={:?}",
        state.n_sets,
        state.active_guard
    );

    match &state.active_guard {
        Some(active_guard) => assert_eq!(active_guard, &guard),
        None => state.active_guard = Some(guard),
    }

    state.n_sets = state.n_sets.checked_add(1).unwrap();
    if state.n_sets > MAX_C_GUARD_SETS {
        // The recovered panic literal is contiguous with other rodata strings; this is the
        // human-readable prefix used by the guard-failure path.
        panic!("CGuard was set too many times");
    }
}

pub fn c_guard() {
    set_c_guard(None);
}
