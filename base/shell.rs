use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static NEXT_OUTPUT_ID: AtomicU64 = AtomicU64::new(0);

pub type Result<T, E = ShellError> = std::result::Result<T, E>;

/// A command to be executed by `/bin/sh -c`.
///
/// The recovered in-memory layout is a `String` followed by a single flag byte. When the
/// flag is clear, failed commands leave stdout/stderr in a `shell_rs_out/` file. When it is
/// set, commands are redirected to `/dev/null`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Shell {
    cmd: String,
    suppress_output: bool,
}

#[derive(Debug)]
pub enum ShellError {
    InvalidCommand { cmd: String },
    Spawn { cmd: String, source: io::Error },
    Wait { cmd: String, source: io::Error },
    ThreadPanicked { cmd: String },
    Failed {
        cmd: String,
        status: ExitStatus,
        output_path: Option<PathBuf>,
        output: Option<String>,
    },
}

impl fmt::Display for ShellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShellError::InvalidCommand { cmd } => write!(f, "invalid cmd: {cmd}"),
            ShellError::Spawn { cmd, source } => {
                write!(f, "failed to spawn shell command {cmd:?}: {source}")
            }
            ShellError::Wait { cmd, source } => {
                write!(f, "Shell::wait_inner failed, cmd: {cmd}: {source}")
            }
            ShellError::ThreadPanicked { cmd } => {
                write!(f, "Shell::wait_inner failed, cmd: {cmd}: worker thread panicked")
            }
            ShellError::Failed {
                cmd,
                status,
                output_path,
                output,
            } => {
                write!(f, "Shell::wait_inner failed, cmd: {cmd}, status: {status}")?;
                if let Some(path) = output_path {
                    write!(f, ", output: {}", path.display())?;
                }
                if let Some(output) = output.as_deref().filter(|s| !s.is_empty()) {
                    write!(f, ": {output}")?;
                }
                Ok(())
            }
        }
    }
}

impl Error for ShellError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ShellError::Spawn { source, .. } | ShellError::Wait { source, .. } => Some(source),
            ShellError::InvalidCommand { .. }
            | ShellError::ThreadPanicked { .. }
            | ShellError::Failed { .. } => None,
        }
    }
}

impl Shell {
    pub fn new(cmd: impl Into<String>) -> Self {
        Self {
            cmd: cmd.into(),
            suppress_output: false,
        }
    }

    pub fn quiet(cmd: impl Into<String>) -> Self {
        Self {
            cmd: cmd.into(),
            suppress_output: true,
        }
    }

    pub fn from_args(args: &[impl AsRef<str>]) -> Result<Self> {
        let cmd = join_shell_args(args)?;
        Ok(Self::new(cmd))
    }

    pub fn from_args_quiet(args: &[impl AsRef<str>]) -> Result<Self> {
        let cmd = join_shell_args(args)?;
        Ok(Self::quiet(cmd))
    }

    pub fn command(&self) -> &str {
        &self.cmd
    }

    pub fn suppress_output(&self) -> bool {
        self.suppress_output
    }

    pub fn wait(&self) -> Result<()> {
        self.wait_inner()
    }

    /// Execute the command through `/bin/sh -c` and require a zero exit status.
    ///
    /// Recovered behavior:
    /// - commands already containing `2>&1` are passed through unchanged;
    /// - otherwise commands starting with `(` or ending with `)` are rejected before spawning;
    /// - quiet commands become `(cmd) > /dev/null 2>&1`;
    /// - non-quiet commands become `(cmd) > shell_rs_out/<name> 2>&1 && rm <name>`, so output
    ///   files survive only on failure.
    pub fn wait_inner(&self) -> Result<()> {
        let (actual_cmd, output_path) = self.execution_command()?;

        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(&actual_cmd)
            .spawn()
            .map_err(|source| ShellError::Spawn {
                cmd: actual_cmd.clone(),
                source,
            })?;

        let status = child.wait().map_err(|source| ShellError::Wait {
            cmd: actual_cmd.clone(),
            source,
        })?;

        if status.success() {
            return Ok(());
        }

        let output = output_path
            .as_ref()
            .and_then(|path| fs::read_to_string(path).ok());

        Err(ShellError::Failed {
            cmd: actual_cmd,
            status,
            output_path,
            output,
        })
    }

    pub fn wait_retry(&self, description: &str) -> Result<()> {
        self.sleep_retry(description, default_retry_sleeps())
    }

    /// Retry a command after the recovered sleep intervals.
    ///
    /// The routine at `0x13c9080` first executes `wait_inner`, sleeps between attempts, and
    /// formats `sleep_retry retried ... for sleep times ... last err ...` before the final
    /// attempt. `nanosleep` interruption by `EINTR` is retried with the remaining duration.
    pub fn sleep_retry(&self, description: &str, sleeps: &[f64]) -> Result<()> {
        let mut last_err = match self.wait_inner() {
            Ok(()) => return Ok(()),
            Err(err) => err,
        };

        for seconds in sleeps {
            sleep_seconds(*seconds);
            match self.wait_inner() {
                Ok(()) => return Ok(()),
                Err(err) => last_err = err,
            }
        }

        eprintln!(
            "sleep_retry retried {description} for sleep times {:?} last err {last_err}",
            sleeps
        );
        self.wait_inner().map_err(|_| last_err)
    }

    /// Async wrapper recovered as a copied shell command plus an `async_wait_inner` task name.
    ///
    /// The binary allocates an owned copy of the command before polling the inner wait task;
    /// this source-level reconstruction keeps the same ownership boundary by moving a clone
    /// into a worker thread.
    pub async fn async_wait_inner(self) -> Result<()> {
        let cmd = self.cmd.clone();
        match thread::spawn(move || self.wait_inner()).join() {
            Ok(result) => result,
            Err(_) => Err(ShellError::ThreadPanicked { cmd }),
        }
    }

    fn execution_command(&self) -> Result<(String, Option<PathBuf>)> {
        if self.cmd.contains("2>&1") {
            return Ok((self.cmd.clone(), None));
        }

        if self.cmd.as_bytes().first() == Some(&b'(') || self.cmd.as_bytes().last() == Some(&b')') {
            return Err(ShellError::InvalidCommand {
                cmd: self.cmd.clone(),
            });
        }

        if self.suppress_output {
            return Ok((format!("({}) > /dev/null 2>&1", self.cmd), None));
        }

        let output_path = next_output_path();
        if let Err(source) = fs::create_dir_all("shell_rs_out") {
            return Err(ShellError::Spawn {
                cmd: self.cmd.clone(),
                source,
            });
        }
        let output = shell_quote_lossless(&output_path.to_string_lossy());
        Ok((
            format!("({}) > {output} 2>&1 && rm {output}", self.cmd),
            Some(output_path),
        ))
    }
}

pub fn run(cmd: impl Into<String>) -> Result<()> {
    Shell::new(cmd).wait()
}

pub fn run_quiet(cmd: impl Into<String>) -> Result<()> {
    Shell::quiet(cmd).wait()
}

pub fn run_args(args: &[impl AsRef<str>]) -> Result<()> {
    Shell::from_args(args)?.wait()
}

pub fn run_args_quiet(args: &[impl AsRef<str>]) -> Result<()> {
    Shell::from_args_quiet(args)?.wait()
}

pub fn wait_retry(cmd: impl Into<String>, description: &str) -> Result<()> {
    Shell::new(cmd).wait_retry(description)
}

pub fn sleep_retry(cmd: impl Into<String>, description: &str, sleeps: &[f64]) -> Result<()> {
    Shell::new(cmd).sleep_retry(description, sleeps)
}

pub fn default_retry_sleeps() -> &'static [f64] {
    &[0.001, 0.05, 0.1]
}

fn join_shell_args(args: &[impl AsRef<str>]) -> Result<String> {
    let mut cmd = String::new();

    for arg in args {
        let arg = arg.as_ref().trim();
        if arg.is_empty() {
            continue;
        }
        let quoted = shell_quote(arg);
        if !cmd.is_empty() {
            cmd.push(' ');
        }
        cmd.push_str(&quoted);
    }

    Ok(cmd)
}

fn shell_quote(arg: &str) -> String {
    if is_safe_shell_word(arg) {
        arg.to_owned()
    } else {
        shell_quote_lossless(arg)
    }
}

fn shell_quote_lossless(arg: &str) -> String {
    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn is_safe_shell_word(arg: &str) -> bool {
    !arg.is_empty()
        && arg.bytes().all(|b| {
            matches!(
                b,
                b'a'..=b'z'
                    | b'A'..=b'Z'
                    | b'0'..=b'9'
                    | b'_' | b'-' | b'.' | b'/' | b':' | b'@' | b'%' | b'+' | b'=' | b','
            )
        })
}

fn next_output_path() -> PathBuf {
    let counter = NEXT_OUTPUT_ID.fetch_add(1, Ordering::Relaxed);
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    PathBuf::from("shell_rs_out").join(format!("{now_nanos}_{counter}"))
}

fn sleep_seconds(seconds: f64) {
    if seconds <= 0.0 || !seconds.is_finite() {
        return;
    }

    thread::sleep(Duration::from_secs_f64(seconds));
}
