//! Reconstruction of `code_Mainnet/base/src/build_mode.rs`.
//!
//! Confidence: Medium. The two seed functions both anchor to panic locations in this file:
//!   - `sub_13CD410` references line 30, column 199 (`tried to get build_dir of ..., a bug?`).
//!   - `sub_143EF30` references line 17, column 29 (`assertion failed: !arg.ends_with('/')`)
//!     and line 26, column 32 (UTF-8 slicing boundary check).
//!
//! IDA tags intended/applied for this file:
//!   - `sub_13CD410` -> `base_build_mode__build_dir_for_mode`
//!   - `sub_143EF30` -> `base_build_mode__sub_collect_cham_invocation_names`
//!   - `sub_13CD6D0` -> `base_build_mode__sub_prepare_run_client_command` [INFERENCE: file membership]
//!
//! String anchors: `"debug"`, `"release"`, `"run-client"`, `"/code/run-client"`,
//! `"/aws_build/"`, `"/cham/"`, `"assertion failed: !arg.ends_with('/')"`.

use std::env;

/// Build mode discriminant recovered from the two-byte value passed to `sub_13CD410`.
///
/// IDA: `hl_base_BuildModeRepr` / `base_build_mode__build_dir_for_mode` argument bytes.
/// Confidence: Medium — `(0, 0)` takes the direct/local path, byte `1` selects
/// `debug`, byte `2` selects `release`; `(0, nonzero)` follows the panic path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildMode {
    /// Direct/local mode. Only the exact `(0, 0)` representation reaches this branch.
    Local,
    /// Discriminant `1`, formatted as `debug` in the AWS build directory.
    Debug { flag: u8 },
    /// Discriminant `2`, formatted as `release` in the AWS build directory.
    Release { flag: u8 },
    /// Opaque/invalid discriminant; the binary panics when `kind` is not exactly 1 or 2 after the local check.
    Unknown { kind: u8, flag: u8 },
}

impl BuildMode {
    /// Reconstruct the compact two-byte representation used at the ABI boundary.
    ///
    /// IDA: bytes loaded from `cl`/`r8b` in `sub_13CD410`.
    /// Confidence: Medium.
    pub fn from_repr(kind: u8, flag: u8) -> Self {
        match (kind, flag) {
            (0, 0) => Self::Local,
            (1, flag) => Self::Debug { flag },
            (2, flag) => Self::Release { flag },
            _ => Self::Unknown { kind, flag },
        }
    }

    /// Return the build profile directory component used for non-local builds.
    ///
    /// IDA: `sub_13CD410` uses literals `"debug"` and `"release"` before formatting
    /// `"/aws_build/{profile}/{program}"`.
    /// Confidence: High for discriminants 1 and 2.
    pub fn profile_dir(self) -> Option<&'static str> {
        match self {
            Self::Local => None,
            Self::Debug { .. } => Some("debug"),
            Self::Release { .. } => Some("release"),
            Self::Unknown { .. } => None,
        }
    }

    /// Whether callers should add `--running-from-script` after using this build path.
    ///
    /// IDA: `sub_13CD410` writes byte `1` at result offset `+24` only for the
    /// `/aws_build/{debug|release}/...` branch; `sub_13CD6D0` consumes that byte and
    /// prepends `--running-from-script` to the spawned command.
    /// Confidence: Medium.
    pub fn runs_from_script_build(self, program: &str) -> bool {
        self.profile_dir().is_some() && program != "run-client"
    }
}

/// Build path result returned by `base_build_mode__build_dir_for_mode`.
///
/// IDA: `hl_base_BuildPath`, 24-byte Rust string plus a byte at offset `+24`.
/// Confidence: High for the tag behavior; exact Rust type name is not present in the binary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildPath {
    Direct(String),
    ScriptBuild(String),
}

impl BuildPath {
    /// Expose the reconstructed path string.
    ///
    /// IDA: all branches of `sub_13CD410` materialize an owned Rust string.
    /// Confidence: High.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Direct(path) | Self::ScriptBuild(path) => path,
        }
    }

    /// Whether `sub_13CD6D0` treats this build path as coming from a script build.
    ///
    /// IDA: tag byte at result offset `+24`.
    /// Confidence: High.
    pub fn is_script_build(&self) -> bool {
        matches!(self, Self::ScriptBuild(_))
    }
}

/// Compute the build directory/path for an executable name.
///
/// IDA: `base_build_mode__build_dir_for_mode` (was `sub_13CD410`).
/// Confidence: High for string-producing branches; Medium for source-level type names.
///
/// Observed behavior:
/// - exact local/zero mode `(0, 0)` copies `program` directly and sets tag `0`;
/// - any non-local mode with `program == "run-client"` returns `/code/run-client` and tag `0`;
/// - `Debug`/`Release` return `/aws_build/debug/{program}` or `/aws_build/release/{program}`
///   and set tag `1`;
/// - any other representation panics with `tried to get build_dir of ..., a bug?`.
pub fn build_dir_for_mode(program: &str, mode: BuildMode) -> BuildPath {
    match mode {
        BuildMode::Local => BuildPath::Direct(program.to_owned()),
        BuildMode::Debug { .. } | BuildMode::Release { .. } if program == "run-client" => {
            BuildPath::Direct("/code/run-client".to_owned())
        }
        BuildMode::Debug { .. } => BuildPath::ScriptBuild(format!("/aws_build/debug/{program}")),
        BuildMode::Release { .. } => BuildPath::ScriptBuild(format!("/aws_build/release/{program}")),
        BuildMode::Unknown { kind, flag } => {
            let _ = (kind, flag);
            todo!("unexpected BuildMode discriminant panic — see sub_13CD410 / build_mode.rs:30")
        }
    }
}

/// Collect the non-option command names used to infer/display a cham invocation.
///
/// IDA: `base_build_mode__sub_collect_cham_invocation_names` (was `sub_143EF30`).
/// Confidence: Medium — exact source name is unknown, but the algorithm is strongly anchored
/// by `/cham/`, the assertion at line 17, the UTF-8 boundary check at line 26, and the final
/// space-join formatter.
///
/// Recovered behavior:
/// - iterates process arguments;
/// - skips args beginning with `--`;
/// - if an arg contains `/cham/`, asserts it does not end in `/`, takes the final path segment,
///   then truncates that segment at the first `-`;
/// - appends each retained name to an accumulator separated by one space.
pub fn collect_cham_invocation_names() -> String {
    let mut names = String::new();

    for arg in env::args() {
        if arg.starts_with("--") {
            continue;
        }

        let mut name = if arg.contains("/cham/") {
            assert!(!arg.ends_with('/'));
            let after_slash = arg.rsplit('/').next().unwrap_or("");
            match after_slash.find('-') {
                Some(index) => &after_slash[..index],
                None => after_slash,
            }
        } else {
            arg.as_str()
        };

        // [INFERENCE] Empty strings are still passed through the formatter in the binary;
        // keeping that behavior avoids inventing filtering that was not observed.
        if names.is_empty() {
            names.push_str(name);
        } else {
            names.push(' ');
            names.push_str(name);
        }

        // Keep `name` scoped like the original borrowed substring; no semantic effect.
        name = "";
        let _ = name;
    }

    names
}

/// [INFERENCE: file membership] Prepare a command structure for launching `run-client`.
///
/// IDA: `base_build_mode__sub_prepare_run_client_command` (was `sub_13CD6D0`), only direct
/// caller of `sub_13CD410`. Confidence: Low for the source-level signature; Medium for the
/// observed relationship with `BuildPath::ScriptBuild`.
///
/// Known pieces from pseudocode:
/// - calls `build_dir_for_mode(program, mode)`;
/// - formats a command/path using the returned build path;
/// - when the build-path tag is set, prepends `--running-from-script` and then copies the
///   supplied argument vector;
/// - writes a large command/child configuration object at the caller-provided output pointer.
pub fn sub_prepare_run_client_command() {
    todo!("opaque command object layout and caller-owned argv transfer — see sub_13CD6D0")
}
