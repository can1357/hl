use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const LINER_BUFFER_CAPACITY: usize = 0x4000;
const DEFAULT_FLUSH_PERIOD_SECS: f64 = 60.0;
const FLUSH_PERIOD_ENV: &str = "LINER_FLUSH_PERIOD";

/// Timestamp value carried by callers when appending a line.
///
/// IDA: `base_liner__write_bytes` (`0x13D12A0`) stores the caller-supplied
/// timestamp after a flush and compares the next timestamp against it before
/// flushing again. The binary representation is compact, but only elapsed
/// seconds are required by this helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinerTime {
    pub unix_seconds: i64,
    pub nanos: u32,
}

impl LinerTime {
    pub fn now() -> Self {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => Self {
                unix_seconds: duration.as_secs() as i64,
                nanos: duration.subsec_nanos(),
            },
            Err(error) => {
                let duration = error.duration();
                let nanos = duration.subsec_nanos();
                if nanos == 0 {
                    Self {
                        unix_seconds: -(duration.as_secs() as i64),
                        nanos: 0,
                    }
                } else {
                    Self {
                        unix_seconds: -(duration.as_secs() as i64) - 1,
                        nanos: 1_000_000_000 - nanos,
                    }
                }
            }
        }
    }

    pub fn seconds_since(self, earlier: Self) -> f64 {
        let seconds = self.unix_seconds - earlier.unix_seconds;
        let nanos = self.nanos as i64 - earlier.nanos as i64;
        seconds as f64 + (nanos as f64 / 1_000_000_000.0)
    }
}

/// Lazily-opened append-only line writer.
///
/// Recovered behavior:
/// - construction validates/creates parent directories and stores the path;
/// - the file is opened lazily on first write with create+append semantics;
/// - writes use a 16 KiB buffer;
/// - the first write is flushed immediately, then later writes flush only when
///   the caller-provided timestamp is more than `LINER_FLUSH_PERIOD` seconds
///   past the previous flush timestamp;
/// - explicit/periodic flush errors are dropped, while write/open errors panic
///   through `unwrap` paths in the binary.
#[derive(Debug)]
pub struct Liner {
    path: String,
    buffer: Option<LineBuffer>,
    flush_period_secs: f64,
    last_flush_at: Option<LinerTime>,
}

impl Liner {
    /// IDA: `base_liner__new` (`0x13D1720`).
    pub fn new(path: String) -> Self {
        create_parent_dirs(&path).unwrap();

        Self {
            path,
            buffer: None,
            flush_period_secs: liner_flush_period_secs(),
            last_flush_at: None,
        }
    }

    pub fn from_path(path: impl Into<String>) -> Self {
        Self::new(path.into())
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn flush_period_secs(&self) -> f64 {
        self.flush_period_secs
    }

    /// Append raw bytes and run the recovered timestamp-based flush policy.
    ///
    /// IDA: `base_liner__write_bytes` (`0x13D12A0`). The fast path copies into
    /// spare buffer capacity; the slow path uses normal `write_all` behavior.
    pub fn write_bytes(&mut self, now: LinerTime, bytes: &[u8]) {
        self.ensure_buffer().write_all(bytes).unwrap();
        self.flush_if_due(now);
    }

    /// Append an owned byte row after adding a trailing newline.
    ///
    /// IDA: `base_liner__write_owned_line` (`0x13D13B0`) grows the owned vector
    /// by one byte when needed, writes `0x0a`, forwards the whole row, then drops
    /// the vector.
    pub fn write_owned_line(&mut self, now: LinerTime, mut line: Vec<u8>) {
        line.push(b'\n');
        self.write_bytes(now, &line);
    }

    pub fn write_line(&mut self, now: LinerTime, line: impl AsRef<[u8]>) {
        let bytes = line.as_ref();
        let mut owned = Vec::with_capacity(bytes.len() + 1);
        owned.extend_from_slice(bytes);
        self.write_owned_line(now, owned);
    }

    /// Flush buffered data, suppressing I/O errors like the recovered helper.
    ///
    /// IDA: `base_liner__flush_suppressing_errors` (`0x13D1880`) calls
    /// `ensure_buffer` first, so an explicit flush opens the file even if no
    /// line has been written yet.
    pub fn flush_suppressing_errors(&mut self) {
        let _ = self.ensure_buffer().flush();
    }

    pub fn flush(&mut self) -> io::Result<()> {
        match self.buffer.as_mut() {
            Some(buffer) => buffer.flush(),
            None => Ok(()),
        }
    }

    fn flush_existing_suppressing_errors(&mut self) {
        if let Some(buffer) = self.buffer.as_mut() {
            let _ = buffer.flush();
        }
    }

    fn flush_if_due(&mut self, now: LinerTime) {
        let should_flush = match self.last_flush_at {
            Some(last_flush_at) => now.seconds_since(last_flush_at) > self.flush_period_secs,
            None => true,
        };

        if should_flush {
            self.last_flush_at = Some(now);
            self.flush_suppressing_errors();
        }
    }

    /// IDA: `base_liner__ensure_buffer` (`0x13D1460`).
    fn ensure_buffer(&mut self) -> &mut LineBuffer {
        if self.buffer.is_none() {
            self.buffer = Some(LineBuffer::open(&self.path).unwrap());
        }
        self.buffer.as_mut().unwrap()
    }
}

impl Drop for Liner {
    fn drop(&mut self) {
        self.flush_existing_suppressing_errors();
    }
}

#[derive(Debug)]
struct LineBuffer {
    file: File,
    buf: Vec<u8>,
}

impl LineBuffer {
    fn open(path: &str) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file,
            buf: Vec::with_capacity(LINER_BUFFER_CAPACITY),
        })
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        let spare = self.buf.capacity() - self.buf.len();
        if bytes.len() >= spare {
            self.write_all_slow(bytes)
        } else {
            self.buf.extend_from_slice(bytes);
            Ok(())
        }
    }

    fn write_all_slow(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.flush_buf()?;
        if bytes.len() >= self.buf.capacity() {
            self.file.write_all(bytes)
        } else {
            self.buf.extend_from_slice(bytes);
            Ok(())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buf()?;
        self.file.flush()
    }

    fn flush_buf(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            self.file.write_all(&self.buf)?;
            self.buf.clear();
        }
        Ok(())
    }
}

fn create_parent_dirs(path: &str) -> io::Result<()> {
    let path = Path::new(path);
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => fs::create_dir_all(parent),
        _ => Ok(()),
    }
}

/// IDA: `base_liner__flush_period_secs` (`0x13D27D0`).
///
/// Missing/invalid-Unicode environment values fall back to 60 seconds. If the
/// variable exists but does not parse as `f64`, the binary follows a parse
/// `unwrap` panic; this helper intentionally preserves that behavior.
pub fn liner_flush_period_secs() -> f64 {
    match env::var(FLUSH_PERIOD_ENV) {
        Ok(value) => value.parse::<f64>().unwrap(),
        Err(_) => DEFAULT_FLUSH_PERIOD_SECS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn test_path(name: &str) -> PathBuf {
        let mut path = env::temp_dir();
        path.push(format!("hl_liner_test_{}_{}", std::process::id(), name));
        let _ = fs::remove_file(&path);
        path
    }

    #[test]
    fn first_write_flushes_and_appends_newline() {
        let path = test_path("first_write_flushes");
        let mut liner = Liner::from_path(path.to_string_lossy().into_owned());
        liner.write_line(
            LinerTime {
                unix_seconds: 10,
                nanos: 0,
            },
            b"alpha",
        );
        assert_eq!(fs::read(&path).unwrap(), b"alpha\n");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn later_write_buffers_until_period_elapses() {
        let path = test_path("periodic_flush");
        let mut liner = Liner::from_path(path.to_string_lossy().into_owned());
        liner.write_line(
            LinerTime {
                unix_seconds: 10,
                nanos: 0,
            },
            b"alpha",
        );
        liner.write_line(
            LinerTime {
                unix_seconds: 20,
                nanos: 0,
            },
            b"beta",
        );
        assert_eq!(fs::read(&path).unwrap(), b"alpha\n");
        liner.write_line(
            LinerTime {
                unix_seconds: 71,
                nanos: 1,
            },
            b"gamma",
        );
        assert_eq!(fs::read(&path).unwrap(), b"alpha\nbeta\ngamma\n");
        let _ = fs::remove_file(path);
    }
}
