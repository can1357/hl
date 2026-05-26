use std::time::Duration;

use chrono::Utc;
use tokio::sync::mpsc;

const CRASH_GRACE_PERIOD: Duration = Duration::from_secs(20);
const CRASH_TIMESTAMP_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.3fZ";

pub type CrashReceiver = mpsc::UnboundedReceiver<String>;

/// Receive the first crash report sent by the task supervisor, print the fatal
/// warning, wait long enough for the log line to flush, then terminate the
/// process.
///
/// The recovered future polls a Tokio unbounded receiver once and keeps the
/// raw `Option<String>` returned by `recv().await`; a closed channel is logged as
/// `None` and still takes the fatal path. The warning includes a UTC timestamp
/// formatted as `%Y-%m-%dT%H:%M:%S%.3fZ`, the caller-supplied label after `@@`,
/// the owned process name, and the received message with `Debug` formatting.
pub async fn recv_and_crash(
    process_name: String,
    label: &'static str,
    mut receiver: CrashReceiver,
) -> ! {
    let message = receiver.recv().await;
    log_crash_report(label, &process_name, &message);
    tokio::time::sleep(CRASH_GRACE_PERIOD).await;
    crash_process();
}

#[inline]
pub async fn recv_crash_message(receiver: &mut CrashReceiver) -> Option<String> {
    receiver.recv().await
}

#[inline]
pub fn log_crash_report(label: &str, process_name: &str, message: &Option<String>) {
    let timestamp = Utc::now().format(CRASH_TIMESTAMP_FORMAT);
    eprintln!(" WARN >>> {timestamp} @@ {label} crashing process name={process_name}:\n{message:?}\n\n");
}

#[cold]
#[inline(never)]
fn crash_process() -> ! {
    std::process::abort();
}
