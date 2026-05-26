use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use crate::err_dur_guard::Timespec;

const SKIP_CRIT_MSG_STATS_PATH: &str = "/hyperliquid_data/skip_crit_msg_stats";
const LATEST_STATS_DIR: &str = "/tmp/crit_msg_latest_stats";
const FIRST_REPEAT_WINDOW: Duration = Duration::from_secs(300);
const REPEAT_WINDOW: Duration = Duration::from_secs(1);
const MAX_RENDERED_MESSAGE_LEN: usize = 2_000;
static GLOBAL_CRIT_MSG_STATE: LazyLock<Mutex<CritMsgState>> =
    LazyLock::new(|| Mutex::new(CritMsgState::load_from_default_path()));

/// Call-site identity carried into the critical-message path.
///
/// The recovered code stores this key in two SwissTable maps: one map counts per-hour
/// occurrences, and the second map owns the displayed first/latest message statistics.
/// The string names recovered beside the serde metadata are `flnn` and
/// `code_location_and_stats`.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CritMsgLocation {
    pub flnn: String,
}

impl CritMsgLocation {
    pub fn new(flnn: impl Into<String>) -> Self {
        Self { flnn: flnn.into() }
    }
}

/// Runtime switches compiled into each critical-message call site.
///
/// The five compact fields are read from offsets `0x00`, `0x08`, and `0x11..0x14` by
/// `base_crit_msg__record_critical_message` (`0x143d010`). The first field only gates
/// the per-hour occurrence map; the second is the occurrence threshold that must be met
/// before the call is allowed to alert.
#[derive(Clone, Copy, Debug)]
pub struct CritMsgOptions {
    pub use_occurrence_gate: bool,
    pub n_occurrences_before_alert: u64,
    pub is_bug: bool,
    pub honor_log_filter: bool,
    pub suppress_when_alerts_disabled: bool,
    pub suppress_in_testing: bool,
}

impl Default for CritMsgOptions {
    fn default() -> Self {
        Self {
            use_occurrence_gate: false,
            n_occurrences_before_alert: 0,
            is_bug: false,
            honor_log_filter: true,
            suppress_when_alerts_disabled: true,
            suppress_in_testing: true,
        }
    }
}

/// Production policy supplied by `production.rs` after its process-wide context is installed.
///
/// `production.rs` owns the singleton and the invariant
/// `!(is_production && crash_on_crit)`. This type is deliberately small so the critical-message
/// module can use the policy without duplicating production context construction.
#[derive(Clone, Debug)]
pub struct CritMsgRuntimePolicy {
    pub host_label: String,
    pub is_production: bool,
    pub crash_on_crit: bool,
    pub slack_alerts_enabled: bool,
    pub stats_enabled: bool,
}

impl CritMsgRuntimePolicy {
    pub fn non_production() -> Self {
        Self {
            host_label: "N/A (non-production)".to_owned(),
            is_production: false,
            crash_on_crit: false,
            slack_alerts_enabled: false,
            stats_enabled: true,
        }
    }

    pub fn validate(&self) {
        assert!(!(self.is_production && self.crash_on_crit));
    }
}

/// One operator-configured suppression row from `/hyperliquid_data/skip_crit_msg_stats`.
///
/// Recovered serde field names: `flnn`, `is_ignored`, `first_seen`, `last_seen`,
/// `first_msg`, and `start_time`. Existing notes call the time bound `until`; the binary
/// names the serialized field `start_time`, so the reconstruction keeps that name and treats
/// it as an optional lower bound for when the ignore becomes active.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CritMsgIgnore {
    pub flnn: String,
    pub is_ignored: bool,
    pub first_seen: Option<Timespec>,
    pub last_seen: Option<Timespec>,
    pub first_msg: String,
    pub start_time: Option<Timespec>,
}

impl CritMsgIgnore {
    pub fn matches(&self, location: &CritMsgLocation, now: Timespec) -> bool {
        if !self.is_ignored || self.flnn != location.flnn {
            return false;
        }
        match self.start_time {
            Some(start_time) => now >= start_time,
            None => true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CodeLocationStats {
    pub first_seen: Option<Timespec>,
    pub last_seen: Option<Timespec>,
    pub first_msg: String,
    pub last_msg: String,
    pub is_ignored: bool,
    pub n_bugs: u64,
    pub n_crits: u64,
    suppressed_repeats: u64,
}

impl CodeLocationStats {
    fn new(now: Timespec, msg: &str, is_ignored: bool) -> Self {
        Self {
            first_seen: Some(now),
            last_seen: Some(now),
            first_msg: truncate_msg(msg),
            last_msg: truncate_msg(msg),
            is_ignored,
            n_bugs: 0,
            n_crits: 0,
            suppressed_repeats: 0,
        }
    }

    fn note_seen(&mut self, now: Timespec, msg: &str, is_bug: bool, is_ignored: bool) {
        if self.first_seen.is_none() {
            self.first_seen = Some(now);
            self.first_msg = truncate_msg(msg);
        }
        self.last_seen = Some(now);
        self.last_msg = truncate_msg(msg);
        self.is_ignored = is_ignored;
        if is_bug {
            self.n_bugs = self.n_bugs.saturating_add(1);
        } else {
            self.n_crits = self.n_crits.saturating_add(1);
        }
    }
}

#[derive(Clone, Debug)]
struct RepeatGate {
    first_seen: Option<Timespec>,
    last_alerted: Option<Timespec>,
    suppressed_since_last_alert: u64,
}

impl Default for RepeatGate {
    fn default() -> Self {
        Self {
            first_seen: None,
            last_alerted: None,
            suppressed_since_last_alert: 0,
        }
    }
}

/// Mutable state behind the global `crit_msg_state` mutex.
///
/// The constructor at `0x13cc980` initializes the occurrence map, the latest-stats map, the
/// default `300s` first-repeat window, the default `1s` repeat window, and optionally loads
/// ignores from `/hyperliquid_data/skip_crit_msg_stats`.
#[derive(Clone, Debug)]
pub struct CritMsgState {
    pub ignores: Vec<CritMsgIgnore>,
    pub code_location_and_stats: BTreeMap<CritMsgLocation, CodeLocationStats>,
    pub n_occurrences: HashMap<(CritMsgLocation, i64), u64>,
    repeat_gates: HashMap<CritMsgLocation, RepeatGate>,
    pub first_repeat_window: Duration,
    pub repeat_window: Duration,
    pub stats_enabled: bool,
}

impl Default for CritMsgState {
    fn default() -> Self {
        Self {
            ignores: Vec::new(),
            code_location_and_stats: BTreeMap::new(),
            n_occurrences: HashMap::new(),
            repeat_gates: HashMap::new(),
            first_repeat_window: FIRST_REPEAT_WINDOW,
            repeat_window: REPEAT_WINDOW,
            stats_enabled: true,
        }
    }
}

impl CritMsgState {
    pub fn load_from_default_path() -> Self {
        Self::load_from_path(SKIP_CRIT_MSG_STATS_PATH)
    }

    pub fn load_from_path(path: impl AsRef<Path>) -> Self {
        let mut state = Self::default();
        let path = path.as_ref();
        match fs::read_to_string(path) {
            Ok(contents) => {
                state.stats_enabled = !contents.trim().is_empty();
                state.ignores = parse_ignore_file(&contents);
            }
            Err(_) => {
                state.stats_enabled = false;
            }
        }
        state
    }
    pub fn refresh_ignores_from_default_path(&mut self) {
        if let Ok(contents) = fs::read_to_string(SKIP_CRIT_MSG_STATS_PATH) {
            self.stats_enabled = !contents.trim().is_empty();
            self.ignores = parse_ignore_file(&contents);
        }
    }


    pub fn record(
        &mut self,
        options: CritMsgOptions,
        location: CritMsgLocation,
        msg: &str,
        runtime: &CritMsgRuntimePolicy,
        environment: CritMsgEnvironment,
    ) -> CritMsgDecision {
        runtime.validate();

        if options.honor_log_filter && !environment.log_filter_allows_crit {
            return CritMsgDecision::Suppressed(SuppressReason::LogFilter);
        }
        if options.suppress_when_alerts_disabled && !environment.crit_messages_enabled {
            return CritMsgDecision::Suppressed(SuppressReason::GloballyDisabled);
        }
        if options.suppress_in_testing && environment.testing_mode {
            return CritMsgDecision::Suppressed(SuppressReason::TestingMode);
        }

        let now = environment.now;
        if options.use_occurrence_gate {
            let bucket = now.seconds.div_euclid(3_600);
            let occurrence = self
                .n_occurrences
                .entry((location.clone(), bucket))
                .and_modify(|n| *n = n.saturating_add(1))
                .or_insert(1);
            if *occurrence < options.n_occurrences_before_alert {
                return CritMsgDecision::Suppressed(SuppressReason::OccurrenceGate {
                    count: *occurrence,
                    threshold: options.n_occurrences_before_alert,
                });
            }
        }

        let ignored = self.ignores.iter().any(|ignore| ignore.matches(&location, now));
        let should_alert = self.update_repeat_gate(&location, now, ignored);
        let stats = self
            .code_location_and_stats
            .entry(location.clone())
            .or_insert_with(|| CodeLocationStats::new(now, msg, ignored));
        stats.note_seen(now, msg, options.is_bug, ignored);

        if ignored {
            return CritMsgDecision::Suppressed(SuppressReason::Ignored);
        }
        if !should_alert {
            stats.suppressed_repeats = stats.suppressed_repeats.saturating_add(1);
            return CritMsgDecision::Suppressed(SuppressReason::RepeatWindow);
        }

        let alert = CritMsgAlert {
            host_label: runtime.host_label.clone(),
            location,
            msg: truncate_msg(msg),
            is_bug: options.is_bug,
            should_send_slack: runtime.slack_alerts_enabled,
            should_crash: runtime.crash_on_crit,
        };

        if runtime.crash_on_crit {
            CritMsgDecision::Crash(alert)
        } else {
            CritMsgDecision::Alert(alert)
        }
    }

    fn update_repeat_gate(&mut self, location: &CritMsgLocation, now: Timespec, ignored: bool) -> bool {
        let gate = self.repeat_gates.entry(location.clone()).or_default();
        if gate.first_seen.is_none() {
            gate.first_seen = Some(now);
            gate.last_alerted = Some(now);
            gate.suppressed_since_last_alert = 0;
            return true;
        }

        let Some(last_alerted) = gate.last_alerted else {
            gate.last_alerted = Some(now);
            return true;
        };

        let elapsed = now.saturating_duration_since(last_alerted);
        let window = if gate.suppressed_since_last_alert == 0 {
            self.first_repeat_window
        } else {
            self.repeat_window
        };

        if ignored || elapsed < window {
            gate.suppressed_since_last_alert = gate.suppressed_since_last_alert.saturating_add(1);
            return false;
        }

        gate.last_alerted = Some(now);
        gate.suppressed_since_last_alert = 0;
        true
    }

    pub fn render_latest_stats(&self) -> String {
        let mut out = String::new();
        out.push_str("{\"code_location_and_stats\":[");
        for (idx, (location, stats)) in self.code_location_and_stats.iter().enumerate() {
            if idx != 0 {
                out.push(',');
            }
            out.push_str("{\"flnn\":");
            push_json_string(&mut out, &location.flnn);
            out.push_str(",\"is_ignored\":");
            out.push_str(if stats.is_ignored { "true" } else { "false" });
            out.push_str(",\"first_msg\":");
            push_json_string(&mut out, &stats.first_msg);
            out.push_str(",\"last_msg\":");
            push_json_string(&mut out, &stats.last_msg);
            out.push_str(",\"n_bugs\":");
            out.push_str(&stats.n_bugs.to_string());
            out.push_str(",\"n_crits\":");
            out.push_str(&stats.n_crits.to_string());
            out.push_str(",\"suppressed_repeats\":");
            out.push_str(&stats.suppressed_repeats.to_string());
            out.push('}');
        }
        out.push_str("],\"crit_msg_n_occurrences\":");
        out.push_str(&self.n_occurrences.len().to_string());
        out.push('}');
        out
    }

    pub fn write_latest_stats(&self, runtime: &CritMsgRuntimePolicy) -> std::io::Result<PathBuf> {
        let mut path = PathBuf::from(LATEST_STATS_DIR);
        let mut host = runtime.host_label.replace(' ', "_");
        if host.is_empty() {
            host.push_str("unknown");
        }
        fs::create_dir_all(&path)?;
        path.push(host);
        fs::write(&path, self.render_latest_stats())?;
        Ok(path)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CritMsgEnvironment {
    pub now: Timespec,
    pub log_filter_allows_crit: bool,
    pub crit_messages_enabled: bool,
    pub testing_mode: bool,
}

impl CritMsgEnvironment {
    pub fn current() -> Self {
        Self {
            now: Timespec::now(),
            log_filter_allows_crit: true,
            crit_messages_enabled: true,
            testing_mode: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CritMsgAlert {
    pub host_label: String,
    pub location: CritMsgLocation,
    pub msg: String,
    pub is_bug: bool,
    pub should_send_slack: bool,
    pub should_crash: bool,
}

impl CritMsgAlert {
    pub fn slack_payload(&self) -> String {
        let kind = if self.is_bug { "bug" } else { "crit" };
        let mut out = String::new();
        out.push_str("[");
        out.push_str(kind);
        out.push_str("] ");
        out.push_str(&self.host_label);
        out.push_str(" ");
        out.push_str(&self.location.flnn);
        out.push_str(": ");
        out.push_str(&self.msg);
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CritMsgDecision {
    Alert(CritMsgAlert),
    Crash(CritMsgAlert),
    Suppressed(SuppressReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SuppressReason {
    LogFilter,
    GloballyDisabled,
    TestingMode,
    OccurrenceGate { count: u64, threshold: u64 },
    Ignored,
    RepeatWindow,
}
pub fn crit_msg(flnn: impl Into<String>, msg: impl Into<String>) -> CritMsgDecision {
    let runtime = CritMsgRuntimePolicy::non_production();
    let options = CritMsgOptions::default();
    let location = CritMsgLocation::new(flnn);
    let msg = msg.into();
    let mut state = GLOBAL_CRIT_MSG_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state.record(options, location, &msg, &runtime, CritMsgEnvironment::current())
}

/// Background worker body recovered from `0x13ffc70`.
///
/// The binary sleeps for 300 seconds, reloads the skip/ignore file, sorts entries by their
/// occurrence count, and writes a JSON-ish snapshot under `/tmp/crit_msg_latest_stats/`.
pub fn stats_writer_tick(state: &mut CritMsgState, runtime: &CritMsgRuntimePolicy) -> std::io::Result<PathBuf> {
    state.refresh_ignores_from_default_path();
    if !runtime.stats_enabled || !state.stats_enabled {
        return Ok(PathBuf::from(LATEST_STATS_DIR));
    }
    state.write_latest_stats(runtime)
}

fn truncate_msg(msg: &str) -> String {
    if msg.len() <= MAX_RENDERED_MESSAGE_LEN {
        return msg.to_owned();
    }

    let mut end = MAX_RENDERED_MESSAGE_LEN;
    while !msg.is_char_boundary(end) {
        end -= 1;
    }
    msg[..end].to_owned()
}

fn parse_ignore_file(contents: &str) -> Vec<CritMsgIgnore> {
    let mut ignores = Vec::new();
    for object in contents.split('{').skip(1) {
        let Some(body) = object.split('}').next() else { continue };
        let Some(flnn) = json_string_field(body, "flnn") else { continue };
        let is_ignored = json_bool_field(body, "is_ignored").unwrap_or(true);
        let first_msg = json_string_field(body, "first_msg").unwrap_or_default();
        ignores.push(CritMsgIgnore {
            flnn,
            is_ignored,
            first_seen: None,
            last_seen: None,
            first_msg,
            start_time: None,
        });
    }
    ignores
}

fn json_string_field(body: &str, name: &str) -> Option<String> {
    let needle = format!("\"{name}\"");
    let start = body.find(&needle)? + needle.len();
    let after_colon = body[start..].find(':')? + start + 1;
    let value = body[after_colon..].trim_start();
    let value = value.strip_prefix('"')?;
    let mut out = String::new();
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            out.push(match ch {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '"' => '"',
                '\\' => '\\',
                other => other,
            });
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(out);
        } else {
            out.push(ch);
        }
    }
    None
}

fn json_bool_field(body: &str, name: &str) -> Option<bool> {
    let needle = format!("\"{name}\"");
    let start = body.find(&needle)? + needle.len();
    let after_colon = body[start..].find(':')? + start + 1;
    let value = body[after_colon..].trim_start();
    if value.starts_with("true") {
        Some(true)
    } else if value.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch => out.push(ch),
        }
    }
    out.push('"');
}
