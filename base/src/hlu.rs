use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use crate::wallet::Wallet;

pub const DATA_DIR: &str = "/hyperliquid_data";
pub const MAIN_VALIDATOR_KEYS_FLN: &str = "main_validator_keys.json";
pub const N_HLP_REQUIRED_VALIDATORS: usize = 2;

pub type ValidatorPrivateKey = [u8; 32];

static HLP_VALIDATOR_WALLETS: LazyLock<Vec<Wallet>> = LazyLock::new(load_hlp_validator_wallets);

/// Process-wide HLP validator wallets loaded from the operator key file.
///
/// Evidence recovered from the binary:
/// - the path literal ends in `/hyperliquid_data/main_validator_keys.json`;
/// - successful decoding yields contiguous 32-byte key records;
/// - each key is converted with the base wallet private-key constructor;
/// - startup panics with `assertion failed: keys.len() >= N_HLP_REQUIRED_VALIDATORS`
///   before constructing wallets when fewer than two keys are present.
pub fn hlp_validator_wallets() -> &'static [Wallet] {
    HLP_VALIDATOR_WALLETS.as_slice()
}

pub fn load_hlp_validator_wallets() -> Vec<Wallet> {
    let path = Path::new(DATA_DIR).join(MAIN_VALIDATOR_KEYS_FLN);
    let keys = read_validator_private_keys(&path)
        .expect("called `Result::unwrap()` on an `Err` value");

    assert!(keys.len() >= N_HLP_REQUIRED_VALIDATORS);

    keys.iter()
        .map(Wallet::from_private_key_bytes)
        .collect()
}

/// Return a randomly ordered quorum-sized subset of the loaded HLP validator wallets.
///
/// The caller observed in the binary allocates `0..wallets.len()`, shuffles the indices
/// with a thread-local RNG, truncates to `min(2, len)`, then maps indices back to wallet
/// references. Because the global loader already asserts at least two keys, the normal
/// returned length is exactly `N_HLP_REQUIRED_VALIDATORS`.
pub fn random_hlp_required_validator_wallets() -> Vec<&'static Wallet> {
    let wallets = hlp_validator_wallets();
    let mut indices: Vec<usize> = (0..wallets.len()).collect();
    shuffle_indices(&mut indices);

    let take = usize::min(N_HLP_REQUIRED_VALIDATORS, indices.len());
    indices.truncate(take);

    indices.into_iter().map(|index| &wallets[index]).collect()
}

pub fn read_validator_private_keys(path: &Path) -> Result<Vec<ValidatorPrivateKey>, HluKeyFileError> {
    let bytes = fs::read(path).map_err(|source| HluKeyFileError::Read {
        path: path.to_path_buf(),
        source,
    })?;

    if path_has_rmp_extension(path) {
        decode_validator_private_keys_from_rmp(&bytes).map_err(|source| HluKeyFileError::Rmp {
            path: path.to_path_buf(),
            source,
        })
    } else {
        serde_json::from_slice(&bytes).map_err(|source| HluKeyFileError::Json {
            path: path.to_path_buf(),
            source,
        })
    }
}

fn decode_validator_private_keys_from_rmp(bytes: &[u8]) -> Result<Vec<ValidatorPrivateKey>, rmp_serde::decode::Error> {
    rmp_serde::from_slice(bytes)
}

fn shuffle_indices(indices: &mut [usize]) {
    let mut remaining = indices.len();
    while remaining > 1 {
        let selected = rand::random_range(0..remaining);
        indices.swap(remaining - 1, selected);
        remaining -= 1;
    }
}

fn path_has_rmp_extension(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if file_name == ".." {
        return false;
    }
    let Some(dot) = file_name.rfind('.') else {
        return false;
    };
    dot != 0 && file_name[dot + 1..].eq_ignore_ascii_case("rmp")
}

#[derive(Debug)]
pub enum HluKeyFileError {
    Read { path: PathBuf, source: io::Error },
    Json { path: PathBuf, source: serde_json::Error },
    Rmp { path: PathBuf, source: rmp_serde::decode::Error },
}

impl fmt::Display for HluKeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => write!(f, "read: {}: {source}", path.display()),
            Self::Json { path, source } => write!(f, "serde_json::from_slice: {}: {source}", path.display()),
            Self::Rmp { path, source } => write!(f, "rmp_serde::from_slice: {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for HluKeyFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::Rmp { source, .. } => Some(source),
        }
    }
}

