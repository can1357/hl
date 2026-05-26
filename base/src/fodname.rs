use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::time::{SystemTime, SystemTimeError};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum FodName {
    File(PathBuf),
    Directory(PathBuf),
}

impl FodName {
    pub fn parse_existing(path: impl AsRef<OsStr>) -> Result<Self, FodNameError> {
        let path = PathBuf::from(path.as_ref());
        if path_is_regular_file(&path) {
            return Ok(Self::File(path));
        }
        if path_is_directory(&path) {
            return Ok(Self::Directory(path));
        }
        Err(FodNameError::MissingFile { path })
    }

    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self::File(path.into())
    }

    pub fn directory(path: impl Into<PathBuf>) -> Self {
        Self::Directory(path.into())
    }

    pub fn path(&self) -> &Path {
        match self {
            Self::File(path) | Self::Directory(path) => path,
        }
    }

    pub fn is_file(&self) -> bool {
        matches!(self, Self::File(_))
    }

    pub fn is_directory(&self) -> bool {
        matches!(self, Self::Directory(_))
    }

    pub fn age_seconds(&self) -> f64 {
        fod_age(self)
    }
}

impl FromStr for FodName {
    type Err = FodNameError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        Self::parse_existing(path)
    }
}

pub fn fod_age(fod_name: &FodName) -> f64 {
    match fod_name {
        FodName::File(path) => path_age_seconds(path).expect("called `Result::unwrap()` on an `Err` value"),
        FodName::Directory(path) => {
            let Some(paths) = regular_files_under_directory(path) else {
                return path_age_seconds(path).expect("called `Result::unwrap()` on an `Err` value");
            };

            let mut files = paths.into_iter();
            let Some(first) = files.next() else {
                return path_age_seconds(path).expect("called `Result::unwrap()` on an `Err` value");
            };

            let mut youngest_age = path_age_seconds(&first).expect("called `Result::unwrap()` on an `Err` value");
            for file in files {
                let age = path_age_seconds(&file).expect("called `Result::unwrap()` on an `Err` value");
                if age < youngest_age {
                    youngest_age = age;
                }
            }
            youngest_age
        }
    }
}

pub fn regular_files_under_directory(path: &Path) -> Option<BTreeSet<PathBuf>> {
    if !path_is_directory(path) {
        return None;
    }

    let output = Command::new("find").arg(path).output().ok()?;
    if !output.status.success() {
        return None;
    }

    Some(parse_find_stdout_regular_files(&output.stdout))
}

#[cfg(unix)]
pub fn parse_find_stdout_regular_files(stdout: &[u8]) -> BTreeSet<PathBuf> {
    let mut paths = BTreeSet::new();
    for line in stdout.split(|byte| *byte == b'\n') {
        if path_bytes_is_regular_file(line) {
            paths.insert(PathBuf::from(OsString::from_vec(line.to_vec())));
        }
    }
    paths
}

#[cfg(not(unix))]
pub fn parse_find_stdout_regular_files(stdout: &[u8]) -> BTreeSet<PathBuf> {
    let mut paths = BTreeSet::new();
    for line in stdout.split(|byte| *byte == b'\n') {
        let path = PathBuf::from(String::from_utf8_lossy(line).into_owned());
        if path_is_regular_file(&path) {
            paths.insert(path);
        }
    }
    paths
}

pub fn path_age_seconds(path: &Path) -> Result<f64, FodAgeError> {
    let metadata = fs::metadata(path).map_err(|source| FodAgeError::Metadata {
        path: path.to_path_buf(),
        source,
    })?;
    let modified = metadata.modified().map_err(|source| FodAgeError::FileMtime {
        path: path.to_path_buf(),
        source,
    })?;
    system_time_age_seconds(modified).map_err(|source| FodAgeError::SystemDuration {
        path: path.to_path_buf(),
        source,
    })
}

fn system_time_age_seconds(modified: SystemTime) -> Result<f64, SystemTimeError> {
    let elapsed = SystemTime::now().duration_since(modified)?;
    Ok(elapsed.as_secs() as f64 + f64::from(elapsed.subsec_nanos() / 1_000) / 1_000_000.0)
}

pub fn path_is_regular_file(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

pub fn path_is_directory(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.file_type().is_dir())
        .unwrap_or(false)
}

#[cfg(unix)]
pub fn path_bytes_is_regular_file(path: &[u8]) -> bool {
    fs::metadata(OsStr::from_bytes(path))
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

#[cfg(not(unix))]
pub fn path_bytes_is_regular_file(path: &[u8]) -> bool {
    let path = String::from_utf8_lossy(path);
    path_is_regular_file(Path::new(path.as_ref()))
}

#[derive(Debug)]
pub enum FodNameError {
    MissingFile { path: PathBuf },
}

impl fmt::Display for FodNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingFile { path } => write!(f, "missing file: {}", path.display()),
        }
    }
}

impl std::error::Error for FodNameError {}

#[derive(Debug)]
pub enum FodAgeError {
    Metadata { path: PathBuf, source: io::Error },
    FileMtime { path: PathBuf, source: io::Error },
    SystemDuration { path: PathBuf, source: SystemTimeError },
}

impl fmt::Display for FodAgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Metadata { path, source } => write!(f, "fod_age metadata {}: {source}", path.display()),
            Self::FileMtime { path, source } => {
                write!(f, "fod_age could not get file mtime {}: {source}", path.display())
            }
            Self::SystemDuration { path, source } => write!(
                f,
                "fod_age could not convert file mtime to SystemDuration {}: {source}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for FodAgeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Metadata { source, .. } | Self::FileMtime { source, .. } => Some(source),
            Self::SystemDuration { source, .. } => Some(source),
        }
    }
}
