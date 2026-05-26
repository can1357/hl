use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const NO_ENTRY_FOUND_FOR_KEY: &str = "no entry found for key";

const STATE_WRAPPER_BYTES: usize = 0x0f8;
const STATE_CACHE_BODY_BYTES: usize = 0x810;
const EVM_STATE_WRAPPER_BYTES: usize = STATE_WRAPPER_BYTES + STATE_CACHE_BODY_BYTES;
const DB_HUB_ARC_ALLOCATION_BYTES: usize = 0x40;

const PRIMARY_HOME_MASK: u32 = 0x081f_feff;
const AUX_HOME_MASK: u32 = 0x00e0_0100;
const TIMED_LINER_MASK: u32 = 0x0020_ff01;

/// Two-byte database code embedded in each wrapped home.
///
/// The binary indexes a static pointer table and heap-copies exactly two bytes
/// before it constructs a wrapper.  Values 21..26 are the EVM/checkpoint writer
/// family observed in the db-hub call sites.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
#[repr(u8)]
pub enum DbCode {
    CA = 0,
    Lu = 1,
    Nf = 2,
    Bi = 3,
    Ps = 4,
    Uf = 5,
    AT = 6,
    Rh = 7,
    EtLower = 8,
    FH = 9,
    AH = 10,
    Oh = 11,
    Ts = 12,
    Th = 13,
    Up = 14,
    Ua = 15,
    Se = 16,
    GP = 17,
    De = 18,
    Dr = 19,
    Vb = 20,
    Et = 21,
    En = 22,
    Eb = 23,
    Ea = 24,
    Ec = 25,
    Es = 26,
}

impl DbCode {
    pub const ALL: [Self; 27] = [
        Self::CA,
        Self::Lu,
        Self::Nf,
        Self::Bi,
        Self::Ps,
        Self::Uf,
        Self::AT,
        Self::Rh,
        Self::EtLower,
        Self::FH,
        Self::AH,
        Self::Oh,
        Self::Ts,
        Self::Th,
        Self::Up,
        Self::Ua,
        Self::Se,
        Self::GP,
        Self::De,
        Self::Dr,
        Self::Vb,
        Self::Et,
        Self::En,
        Self::Eb,
        Self::Ea,
        Self::Ec,
        Self::Es,
    ];

    pub fn id(self) -> u8 {
        self as u8
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::CA => "cA",
            Self::Lu => "lu",
            Self::Nf => "nf",
            Self::Bi => "bi",
            Self::Ps => "Ps",
            Self::Uf => "uf",
            Self::AT => "aT",
            Self::Rh => "rh",
            Self::EtLower => "et",
            Self::FH => "fH",
            Self::AH => "aH",
            Self::Oh => "oh",
            Self::Ts => "ts",
            Self::Th => "th",
            Self::Up => "up",
            Self::Ua => "ua",
            Self::Se => "se",
            Self::GP => "gP",
            Self::De => "de",
            Self::Dr => "dr",
            Self::Vb => "vb",
            Self::Et => "Et",
            Self::En => "En",
            Self::Eb => "Eb",
            Self::Ea => "Ea",
            Self::Ec => "Ec",
            Self::Es => "Es",
        }
    }

    pub fn label_bytes(self) -> Box<[u8; 2]> {
        let bytes = self.label().as_bytes();
        Box::new([bytes[0], bytes[1]])
    }

    /// BTreeMap key used by `DbHub::home_for_code`.
    ///
    /// Evidence: the wrapper helper first tests `0x081f_feff`, then
    /// `0x00e0_0100`; codes not in either mask use bucket `2`.
    pub fn home_bucket(self) -> u8 {
        let bit = 1u32 << self.id();
        if (PRIMARY_HOME_MASK & bit) != 0 {
            0
        } else if (AUX_HOME_MASK & bit) != 0 {
            1
        } else {
            2
        }
    }

    pub fn is_evm_family(self) -> bool {
        matches!(self, Self::Et | Self::En | Self::Eb | Self::Ea | Self::Ec | Self::Es)
    }

    pub fn checkpoint_slot(self) -> Option<usize> {
        match self {
            Self::Et | Self::En | Self::Eb | Self::Ea | Self::Ec | Self::Es => {
                Some((self.id() - DbCode::Et.id()) as usize)
            }
            _ => None,
        }
    }

    pub fn uses_timed_liner_fast_path(self) -> bool {
        (TIMED_LINER_MASK & (1u32 << self.id())) != 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DbHome {
    pub root: PathBuf,
    pub bucket: u8,
}

impl DbHome {
    pub fn new(root: impl Into<PathBuf>, bucket: u8) -> Self {
        Self { root: root.into(), bucket }
    }
}

/// Arc-backed hub recovered from the 64-byte allocation shape:
/// Arc counts at +0/+8 followed by a 48-byte value (`PathBuf` + `BTreeMap`).
#[derive(Clone, Debug)]
pub struct DbHub {
    pub data_path: PathBuf,
    pub homes: BTreeMap<u8, Arc<DbHome>>,
}

impl DbHub {
    pub fn new(data_path: impl Into<PathBuf>, homes: BTreeMap<u8, Arc<DbHome>>) -> Arc<Self> {
        let hub = Arc::new(Self { data_path: data_path.into(), homes });
        debug_assert_eq!(DB_HUB_ARC_ALLOCATION_BYTES, 0x40);
        hub
    }

    pub fn from_homes(data_path: impl Into<PathBuf>, homes: impl IntoIterator<Item = DbHome>) -> Arc<Self> {
        let mut by_bucket = BTreeMap::new();
        for home in homes {
            by_bucket.insert(home.bucket, Arc::new(home));
        }
        Self::new(data_path, by_bucket)
    }

    pub fn home_for_code(&self, code: DbCode) -> Arc<DbHome> {
        self.homes
            .get(&code.home_bucket())
            .cloned()
            .unwrap_or_else(|| panic!("{}", NO_ENTRY_FOUND_FOR_KEY))
    }

    pub fn wrap_home(self: &Arc<Self>, code: DbCode) -> WrappedDbHome {
        let code_label = code.label_bytes();
        let home = self.home_for_code(code);
        let timed_liner = if code.uses_timed_liner_fast_path() {
            None
        } else {
            Some(DailyLinerState::new(code))
        };

        WrappedDbHome {
            hub: Arc::clone(self),
            code,
            code_label,
            home,
            timed_liner,
            raw_wrapper_len: STATE_WRAPPER_BYTES,
        }
    }

    /// Build the three state DB wrappers used by the checkpointed EVM state path.
    ///
    /// Evidence: one call site constructs wrappers for codes `Ea`, `Ec`, and `Es`,
    /// each followed by a 0x810-byte body.  When no checkpoint body is supplied,
    /// three initializer callees fill fresh bodies before the wrappers are flushed.
    pub fn build_evm_state_wrappers(self: &Arc<Self>, checkpoint: Option<EvmStateCheckpointBodies>) -> EvmStateDbHomes {
        let bodies = checkpoint.unwrap_or_else(EvmStateCheckpointBodies::fresh);
        EvmStateDbHomes {
            account: CachedWrappedDbHome::new(self.wrap_home(DbCode::Ea), bodies.account),
            contract: CachedWrappedDbHome::new(self.wrap_home(DbCode::Ec), bodies.contract),
            storage: CachedWrappedDbHome::new(self.wrap_home(DbCode::Es), bodies.storage),
        }
    }

    pub fn build_evm_output_wrappers(self: &Arc<Self>) -> EvmOutputDbHomes {
        EvmOutputDbHomes {
            blocks: self.wrap_home(DbCode::Eb),
            transactions: self.wrap_home(DbCode::Et),
            receipts_or_numbers: self.wrap_home(DbCode::En),
        }
    }

    pub fn checkpoint_record(path: impl Into<PathBuf>, homes: BTreeMap<u8, Arc<DbHome>>) -> Arc<Self> {
        let path = path.into();
        let _date = compact_date_from_path(&path).expect("called `Result::unwrap()` on an `Err` value");
        Self::new(path, homes)
    }

    pub fn save_checkpoint_bundle(&self) -> DbCheckpointBundle {
        DbCheckpointBundle { data_path: self.data_path.clone(), homes: self.homes.clone() }
    }

    pub fn rebuild_from_checkpoint(bundle: DbCheckpointBundle, bodies: Option<EvmStateCheckpointBodies>) -> CheckpointedDbHub {
        let hub = Self::checkpoint_record(bundle.data_path, bundle.homes);
        let state = hub.build_evm_state_wrappers(bodies);
        CheckpointedDbHub { hub, state }
    }
}

#[derive(Clone, Debug)]
pub struct WrappedDbHome {
    pub hub: Arc<DbHub>,
    pub code: DbCode,
    pub code_label: Box<[u8; 2]>,
    pub home: Arc<DbHome>,
    pub timed_liner: Option<DailyLinerState>,
    pub raw_wrapper_len: usize,
}

impl WrappedDbHome {
    pub fn label(&self) -> &str {
        self.code.label()
    }
}

#[derive(Clone, Debug)]
pub struct CachedWrappedDbHome {
    pub wrapper: WrappedDbHome,
    pub body: StateCacheBody,
}

impl CachedWrappedDbHome {
    pub fn new(wrapper: WrappedDbHome, body: StateCacheBody) -> Self {
        Self { wrapper, body }
    }

    pub fn byte_len(&self) -> usize {
        EVM_STATE_WRAPPER_BYTES
    }
}

#[derive(Clone)]
pub struct StateCacheBody {
    bytes: Box<[u8; STATE_CACHE_BODY_BYTES]>,
}

impl StateCacheBody {
    pub fn zeroed() -> Self {
        Self { bytes: Box::new([0; STATE_CACHE_BODY_BYTES]) }
    }

    pub fn as_bytes(&self) -> &[u8; STATE_CACHE_BODY_BYTES] {
        &self.bytes
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8; STATE_CACHE_BODY_BYTES] {
        &mut self.bytes
    }
}

impl fmt::Debug for StateCacheBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateCacheBody")
            .field("len", &STATE_CACHE_BODY_BYTES)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct EvmStateCheckpointBodies {
    pub account: StateCacheBody,
    pub contract: StateCacheBody,
    pub storage: StateCacheBody,
}

impl EvmStateCheckpointBodies {
    pub fn fresh() -> Self {
        Self {
            account: init_account_state_body(),
            contract: init_contract_state_body(),
            storage: init_storage_state_body(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct EvmStateDbHomes {
    pub account: CachedWrappedDbHome,
    pub contract: CachedWrappedDbHome,
    pub storage: CachedWrappedDbHome,
}

impl EvmStateDbHomes {
    pub fn flush(&self, mut sink: impl FnMut(DbCode, &[u8; STATE_CACHE_BODY_BYTES])) {
        sink(self.account.wrapper.code, self.account.body.as_bytes());
        sink(self.contract.wrapper.code, self.contract.body.as_bytes());
        sink(self.storage.wrapper.code, self.storage.body.as_bytes());
    }
}

#[derive(Clone, Debug)]
pub struct EvmOutputDbHomes {
    pub blocks: WrappedDbHome,
    pub transactions: WrappedDbHome,
    pub receipts_or_numbers: WrappedDbHome,
}

#[derive(Clone, Debug)]
pub struct CheckpointedDbHub {
    pub hub: Arc<DbHub>,
    pub state: EvmStateDbHomes,
}

#[derive(Clone, Debug)]
pub struct DbCheckpointBundle {
    pub data_path: PathBuf,
    pub homes: BTreeMap<u8, Arc<DbHome>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DailyLinerState {
    pub code: DbCode,
    pub force_hourly_rotation: bool,
}

impl DailyLinerState {
    pub fn new(code: DbCode) -> Self {
        Self { code, force_hourly_rotation: true }
    }
}

fn init_account_state_body() -> StateCacheBody {
    let mut body = StateCacheBody::zeroed();
    stamp_state_body(body.as_mut_bytes(), DbCode::Ea);
    body
}

fn init_contract_state_body() -> StateCacheBody {
    let mut body = StateCacheBody::zeroed();
    stamp_state_body(body.as_mut_bytes(), DbCode::Ec);
    body
}

fn init_storage_state_body() -> StateCacheBody {
    let mut body = StateCacheBody::zeroed();
    stamp_state_body(body.as_mut_bytes(), DbCode::Es);
    body
}

fn stamp_state_body(bytes: &mut [u8; STATE_CACHE_BODY_BYTES], code: DbCode) {
    let label = code.label().as_bytes();
    bytes[0] = label[0];
    bytes[1] = label[1];
}

fn compact_date_from_path(path: &Path) -> Result<u32, CompactDateError> {
    let text = path.to_string_lossy();
    let bytes = text.as_bytes();
    for window in bytes.windows(8) {
        if window.iter().all(u8::is_ascii_digit) {
            let mut value = 0u32;
            for digit in window {
                value = value * 10 + u32::from(digit - b'0');
            }
            return Ok(value);
        }
    }
    Err(CompactDateError)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactDateError;

impl fmt::Display for CompactDateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("missing compact date in checkpoint path")
    }
}

impl std::error::Error for CompactDateError {}
