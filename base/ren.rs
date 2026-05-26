use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration as StdDuration;

use chrono::{Local, NaiveDate, NaiveDateTime, Timelike};

use crate::duration::seconds_since_or_zero;
use crate::file_mod_time_tracker::{path_is_regular_file, stat_modified_chrono};

const DEFAULT_REN_PATH: &str = "/tmp/zip_and_upload_ren";
const RUNNING_FROM_SCRIPT_ARG: &str = "--running-from-script";
const DEFAULT_STALE_AFTER_SECS: f64 = 1_800.0;
const MONITOR_SLEEP_SECS: u64 = 10;
const MAX_STALE_BACKOFF_MULTIPLIER: u64 = 3;

#[derive(Clone, Debug)]
pub struct RenRestartSpec {
    pub restart_file: PathBuf,
    pub stale_after_secs: f64,
}

impl Default for RenRestartSpec {
    fn default() -> Self {
        Self {
            restart_file: PathBuf::from(DEFAULT_REN_PATH),
            stale_after_secs: DEFAULT_STALE_AFTER_SECS,
        }
    }
}

/// Binary default constructor materializes exactly one spec: `/tmp/zip_and_upload_ren`, 1800s.
pub fn default_restart_specs() -> Vec<RenRestartSpec> {
    vec![RenRestartSpec::default()]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartReason {
    Startup,
    StaleRestartFile,
    MissingRestartFile,
    PeriodicRefresh,
}

impl RestartReason {
    #[inline]
    fn uses_strict_hour_bound(self) -> bool {
        matches!(self, Self::StaleRestartFile | Self::MissingRestartFile)
    }
}

#[derive(Clone, Debug)]
pub struct RenderedRestartFile {
    pub path: PathBuf,
    pub stale_after_secs: f64,
}

pub trait RenRenderer: Send + Sync + 'static {
    fn rendered_restart_files(&self, date: NaiveDate, hour: u32) -> Vec<RenderedRestartFile>;
}

#[derive(Clone, Debug)]
pub struct StaticRenRenderer {
    specs: Vec<RenRestartSpec>,
}

impl StaticRenRenderer {
    pub fn new(specs: Vec<RenRestartSpec>) -> Self {
        Self { specs }
    }
}

impl RenRenderer for StaticRenRenderer {
    fn rendered_restart_files(&self, _date: NaiveDate, _hour: u32) -> Vec<RenderedRestartFile> {
        self.specs
            .iter()
            .map(|spec| RenderedRestartFile {
                path: spec.restart_file.clone(),
                stale_after_secs: spec.stale_after_secs,
            })
            .collect()
    }
}

pub struct RenCommandState<R> {
    pub command: PathBuf,
    pub args: Vec<String>,
    pub renderer: R,
    pub refresh_interval_secs: f64,
    next_refresh_after_secs: f64,
    consecutive_file_restarts: u64,
    last_timestamp: NaiveDateTime,
    child: Option<RunningRenChild>,
    running_from_script: bool,
    no_stale_backoff: bool,
}

pub struct RunningRenChild {
    child: Child,
    restart_file: Option<File>,
}

impl RunningRenChild {
    fn kill_and_forget(mut self) -> io::Result<()> {
        // The optimized Linux body first tries syscall 424 (`pidfd_send_signal`) with SIGKILL
        // when a pidfd is available, otherwise falls back to `kill(pid, SIGKILL)`, then closes
        // tracked file descriptors. `Child::kill` preserves the same externally visible intent.
        let kill_result = self.child.kill();
        drop(self.restart_file.take());
        kill_result
    }
}

impl<R> RenCommandState<R>
where
    R: RenRenderer,
{
    pub fn new(
        command: impl Into<PathBuf>,
        mut args: Vec<String>,
        renderer: R,
        refresh_interval_secs: f64,
        running_from_script: bool,
        no_stale_backoff: bool,
    ) -> Self {
        if running_from_script {
            args.insert(0, RUNNING_FROM_SCRIPT_ARG.to_owned());
        }

        Self {
            command: command.into(),
            args,
            renderer,
            refresh_interval_secs,
            next_refresh_after_secs: refresh_interval_secs,
            consecutive_file_restarts: 0,
            last_timestamp: Local::now().naive_local(),
            child: None,
            running_from_script,
            no_stale_backoff,
        }
    }

    pub fn from_default_spec(running_from_script: bool, extra_args: Vec<String>) -> Self
    where
        R: From<StaticRenRenderer>,
    {
        let specs = default_restart_specs();
        Self::new(
            DEFAULT_REN_PATH,
            extra_args,
            R::from(StaticRenRenderer::new(specs)),
            1_000_000.0,
            running_from_script,
            false,
        )
    }

    pub fn restart(&mut self, reason: RestartReason) {
        if let Some(child) = self.child.take() {
            child
                .kill_and_forget()
                .unwrap_or_else(|err| panic!("ren restart file error: {err}"));
        }

        let now = Local::now().naive_local();
        let previous_timestamp = self.last_timestamp;
        if now.date() != previous_timestamp.date() {
            self.consecutive_file_restarts = 0;
        }
        self.last_timestamp = now;

        let hour = now.time().hour();
        if reason.uses_strict_hour_bound() {
            assert!(hour <= 24);
        }

        let elapsed_since_previous = seconds_since_or_zero(now, previous_timestamp);
        if self.running_from_script && self.next_refresh_after_secs > elapsed_since_previous {
            self.next_refresh_after_secs = elapsed_since_previous + 0.1;
        } else {
            self.next_refresh_after_secs = self.refresh_interval_secs;
        }

        let rendered = self.renderer.rendered_restart_files(now.date(), hour);
        let restart_file_path = rendered
            .first()
            .map(|file| file.path.clone())
            .unwrap_or_else(|| PathBuf::from(DEFAULT_REN_PATH));
        let restart_file = create_restart_file(&restart_file_path)
            .unwrap_or_else(|err| panic!("ren restart file error: {err}"));

        let mut cmd = Command::new(&self.command);
        cmd.args(&self.args);
        cmd.stdout(Stdio::from(
            restart_file
                .try_clone()
                .unwrap_or_else(|err| panic!("ren restart file error: {err}")),
        ));
        cmd.stderr(Stdio::from(
            restart_file
                .try_clone()
                .unwrap_or_else(|err| panic!("ren restart file error: {err}")),
        ));

        let child = cmd.spawn().unwrap_or_else(|err| {
            panic!(
                "ren restart file error: command={:?} args={:?} path={} error={err}",
                self.command,
                self.args,
                restart_file_path.display()
            )
        });

        self.child = Some(RunningRenChild {
            child,
            restart_file: Some(restart_file),
        });

        if matches!(reason, RestartReason::StaleRestartFile | RestartReason::MissingRestartFile) {
            self.consecutive_file_restarts = self.consecutive_file_restarts.saturating_add(1);
        }
    }

    fn check_hourly_restart_files(&mut self, now: NaiveDateTime) {
        if now.time().minute() != 0 {
            return;
        }

        let hour = now.time().hour();
        assert!(hour <= 24);
        let files = self.renderer.rendered_restart_files(now.date(), hour);

        for file in files {
            if !path_is_regular_file(&file.path) {
                self.restart(RestartReason::MissingRestartFile);
                return;
            }

            let age_secs = restart_file_age_secs(&file.path, now).unwrap_or(0.0);
            let mut stale_after = file.stale_after_secs;
            if !self.no_stale_backoff {
                assert!(stale_after >= 0.0);
                let multiplier = self
                    .consecutive_file_restarts
                    .saturating_add(1)
                    .min(MAX_STALE_BACKOFF_MULTIPLIER) as f64;
                stale_after *= multiplier;
            }

            if age_secs > stale_after {
                self.restart(RestartReason::StaleRestartFile);
                return;
            }
        }
    }

    fn maybe_periodic_refresh(&mut self, now: NaiveDateTime) {
        let elapsed = seconds_since_or_zero(now, self.last_timestamp);
        if elapsed > self.next_refresh_after_secs {
            self.restart(RestartReason::PeriodicRefresh);
        }
    }
}

pub struct RenMonitor<R> {
    commands: Vec<RenCommandState<R>>,
}

impl<R> RenMonitor<R>
where
    R: RenRenderer,
{
    pub fn new(commands: Vec<RenCommandState<R>>) -> Self {
        Self { commands }
    }

    pub fn run_forever(mut self) -> ! {
        for command in &mut self.commands {
            assert!(command.child.is_none());
            command.restart(RestartReason::Startup);
        }

        loop {
            if self.commands.is_empty() {
                sleep_ignoring_interrupts(StdDuration::from_secs(MONITOR_SLEEP_SECS));
                continue;
            }

            for command in &mut self.commands {
                let now = Local::now().naive_local();
                command.maybe_periodic_refresh(now);
                command.check_hourly_restart_files(now);
            }

            sleep_ignoring_interrupts(StdDuration::from_secs(MONITOR_SLEEP_SECS));
        }
    }
}

fn create_restart_file(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

fn restart_file_age_secs(path: &Path, now: NaiveDateTime) -> io::Result<f64> {
    let modified = stat_modified_chrono(path).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    Ok(seconds_since_or_zero(now, modified))
}

fn sleep_ignoring_interrupts(duration: StdDuration) {
    // The recovered loop retries `nanosleep` on EINTR and crashes for other errno values.
    // `thread::sleep` exposes the same non-interrupted Rust-level contract.
    thread::sleep(duration);
}

#[inline]
pub fn raw_restart_file_fd(file: &File) -> RawFd {
    file.as_raw_fd()
}

#[inline]
pub fn path_is_executable_candidate(path: &OsStr) -> bool {
    !path.is_empty()
}
