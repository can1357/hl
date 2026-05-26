//! Reconstruction of `/home/ubuntu/hl/code_Mainnet/l1/src/abci/state.rs`.
//!
//! Confidence: Medium. The source-path manifest has one panic anchor and twenty
//! rodata-derived seeds. IDA MCP was queue-full during this task, so the tags below
//! are the intended names/comments from local seed analysis and nested-agent output.
//!
//! Seed EAs and recovered roles:
//!   - `0x2208580` -> `l1_abci_state__handle_candidate_peer_abci_state_response`
//!   - `0x2208E60` -> `l1_abci_state__link_and_log_abci_state`
//!   - `0x2209450` -> `l1_abci_state__build_linked_abci_state`
//!   - `0x22AE8A0` -> `l1_abci_state__poll_abci_state_link_future`
//!   - `0x32725D0` -> `l1_abci_state__decode_abci_state_rmp_buffer`
//!   - `0x3273810` -> `l1_abci_state__resolve_and_decode_rmp_state_path`
//!   - `0x444B430` -> `l1_abci_state__compact_order_entries_segment1`
//!   - `0x444C310` -> `l1_abci_state__compact_order_entries_segment2`
//!   - `0x446DA60`/`0x446E050`/`0x446E640` -> state segment serializer monomorphs
//!   - `0x4546BA0` -> exchange/order segment serializer glue
//!   - `0x46CEA60`/`0x46CF030`/`0x46CF490` -> `exchange` field (`state+0xbc0`) dump path serializers
//!   - `0x46CF990`/`0x46CFE90` -> second exchange-like field (`state+0x1640`) dump path serializers
//!
//! Layout anchors verified from current seed analysis and prior struct-name hints:
//!   - `VisorAbciState` fields: `initial_height`, `height`,
//!     `scheduled_freeze_height`, `consensus_time`, `wall_clock_time`, `reference_lag`.
//!   - Scheduled freeze is read as an `Option<u64>`-like pair at offsets `+0x4c8/+0x4d0`.
//!   - Current execution height is read at `+0x2f80` in freeze enforcement paths.
//!   - Linked ABCI state copies three `0x810`-byte chunks from `+0xcb8`, `+0x15c0`, `+0x1ec8`.
//!   - Dump serializers read state height at `+0x28`, serialize field `+0xbc0` or `+0x1640`,
//!     skip mirror writes for `/dev/null`, and choose binary output for `.rmp` paths.

use std::cmp::Ordering;
use std::path::Path;
use std::task::Poll;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const CANDIDATE_PEER_ABCI_STATE_TAG: u16 = 0x0186;
pub const PEER_STATUS_OK_TAG: u8 = 0x0e;
pub const PEER_STATUS_MISSING_LINK_TAG: u16 = 0x0111;
pub const PEER_STATUS_MISMATCH_TAG: u16 = 0x0158;
pub const LINKED_STATE_CHUNK_LEN: usize = 0x810;
pub const DECODED_STATE_COPY_LEN: usize = 0x3ae8;
pub const RESOLVED_RMP_PAYLOAD_LEN: usize = 0x1fb8;
pub const FREEZE_OPTION_DISCRIMINANT_OFFSET: usize = 0x4c8;
pub const FREEZE_OPTION_VALUE_OFFSET: usize = 0x4d0;
pub const CURRENT_HEIGHT_OFFSET: usize = 0x2f80;
pub const EXCHANGE_FIELD_OFFSET: usize = 0x0bc0;
pub const SECOND_EXCHANGE_FIELD_OFFSET: usize = 0x1640;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: u32,
}

impl Timestamp {
    pub const ZERO: Self = Self { seconds: 0, nanos: 0 };

    pub fn now_wall_clock() -> Self {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => Self {
                seconds: duration.as_secs() as i64,
                nanos: duration.subsec_nanos(),
            },
            Err(error) => {
                let duration = error.duration();
                Self {
                    seconds: -(duration.as_secs() as i64),
                    nanos: duration.subsec_nanos(),
                }
            }
        }
    }

    pub fn unix_millis(self) -> i128 {
        i128::from(self.seconds) * 1_000 + i128::from(self.nanos / 1_000_000)
    }

    pub fn saturating_lag_from(self, older: Self) -> Duration {
        if self.unix_millis() <= older.unix_millis() {
            Duration::ZERO
        } else {
            Duration::from_millis((self.unix_millis() - older.unix_millis()) as u64)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hardfork {
    pub version: u8,
    pub round: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VisorAbciState {
    pub initial_height: u64,
    pub height: u64,
    pub scheduled_freeze_height: Option<u64>,
    pub consensus_time: Timestamp,
    pub wall_clock_time: Timestamp,
    pub reference_lag: Duration,
}

impl VisorAbciState {
    pub fn new(initial_height: u64, consensus_time: Timestamp, wall_clock_time: Timestamp) -> Self {
        Self {
            initial_height,
            height: initial_height,
            scheduled_freeze_height: None,
            consensus_time,
            wall_clock_time,
            reference_lag: wall_clock_time.saturating_lag_from(consensus_time),
        }
    }

    /// Update the ABCI context after a block is accepted.
    ///
    /// IDA: seed `0x22AE8A0` snapshots height/time fields into an async future and
    /// asserts that the freeze height is not behind the current context height.
    pub fn advance_to_height(&mut self, height: u64, consensus_time: Timestamp, wall_clock_time: Timestamp) {
        assert!(height >= self.height, "ABCI height cannot go backwards");
        self.height = height;
        self.consensus_time = consensus_time;
        self.wall_clock_time = wall_clock_time;
        self.reference_lag = wall_clock_time.saturating_lag_from(consensus_time);

        if let Some(freeze_height) = self.scheduled_freeze_height {
            assert!(
                freeze_height >= self.height,
                "assertion failed: freeze_height >= self.locus.context.height()"
            );
        }
    }

    /// Apply the `FreezeChain` governance effect.
    ///
    /// Prior RE found the read side at offsets `+0x4c8/+0x4d0`: discriminant `1`
    /// and a `u64` height. The write path must preserve the same invariant: the
    /// chain cannot schedule a freeze in the past and cannot reschedule after it is frozen.
    pub fn schedule_freeze(&mut self, freeze_height: u64) -> Result<(), FreezeScheduleError> {
        if let Some(existing) = self.scheduled_freeze_height {
            if existing <= self.height {
                return Err(FreezeScheduleError::AlreadyFrozen { height: existing });
            }
            return Err(FreezeScheduleError::AlreadyScheduled { height: existing });
        }
        if freeze_height < self.height {
            return Err(FreezeScheduleError::HeightInPast {
                requested: freeze_height,
                current: self.height,
            });
        }
        self.scheduled_freeze_height = Some(freeze_height);
        Ok(())
    }

    pub fn clear_scheduled_freeze(&mut self) {
        self.scheduled_freeze_height = None;
    }

    pub fn freeze_reached(&self) -> bool {
        self.scheduled_freeze_height.is_some_and(|freeze_height| freeze_height <= self.height)
    }

    pub fn assert_block_proposal_allowed(&self) {
        if let Some(freeze_height) = self.scheduled_freeze_height {
            assert!(freeze_height > self.height, "Already frozen at height {freeze_height}");
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreezeScheduleError {
    HeightInPast { requested: u64, current: u64 },
    AlreadyScheduled { height: u64 },
    AlreadyFrozen { height: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpaqueChunk0x810 {
    pub bytes: Box<[u8; LINKED_STATE_CHUNK_LEN]>,
}

impl OpaqueChunk0x810 {
    pub fn copy_from_slice(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), LINKED_STATE_CHUNK_LEN);
        let mut out = Box::new([0u8; LINKED_STATE_CHUNK_LEN]);
        out.copy_from_slice(bytes);
        Self { bytes: out }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkedAbciState {
    pub visor: VisorAbciState,
    pub exchange_snapshot: OpaqueChunk0x810,
    pub evm_snapshot: OpaqueChunk0x810,
    pub auxiliary_snapshot: OpaqueChunk0x810,
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbciStateCore {
    /// Source-level ABCI context. In memory, the state object also has compact
    /// scalar fields near offsets `+0x28` and `+0x60` used by serializers.
    pub visor: VisorAbciState,
    /// `state+0xcb8`, copied as `0x810` bytes by seeds `0x2208E60` and `0x2209450`.
    pub exchange_snapshot: OpaqueChunk0x810,
    /// `state+0x15c0`, copied as `0x810` bytes by the linked-state builders.
    pub evm_snapshot: OpaqueChunk0x810,
    /// `state+0x1ec8`, copied as `0x810` bytes by the linked-state builders.
    pub auxiliary_snapshot: OpaqueChunk0x810,
    /// Candidate peer state cache/root observed around `state+0x740` and `state+0x8b8`.
    pub candidate_peers: CandidatePeerBook,
}

impl AbciStateCore {
    pub fn build_linked_abci_state(&self, hasher: &dyn StateDigest) -> LinkedAbciState {
        let mut digest_input = Vec::with_capacity(LINKED_STATE_CHUNK_LEN * 3 + 48);
        digest_input.extend_from_slice(&self.visor.initial_height.to_le_bytes());
        digest_input.extend_from_slice(&self.visor.height.to_le_bytes());
        digest_input.extend_from_slice(&self.visor.consensus_time.seconds.to_le_bytes());
        digest_input.extend_from_slice(&self.visor.consensus_time.nanos.to_le_bytes());
        digest_input.extend_from_slice(&self.exchange_snapshot.bytes[..]);
        digest_input.extend_from_slice(&self.evm_snapshot.bytes[..]);
        digest_input.extend_from_slice(&self.auxiliary_snapshot.bytes[..]);

        LinkedAbciState {
            visor: self.visor.clone(),
            exchange_snapshot: self.exchange_snapshot.clone(),
            evm_snapshot: self.evm_snapshot.clone(),
            auxiliary_snapshot: self.auxiliary_snapshot.clone(),
            digest: hasher.digest32(&digest_input),
        }
    }

    pub fn link_and_log_abci_state(&self, description: &str, periodic_file: &Path, file: &Path, hasher: &dyn StateDigest) -> LinkedAbciState {
        let linked = self.build_linked_abci_state(hasher);
        log_linked_abci_state(description, periodic_file, file, self.visor.height);
        linked
    }

    pub fn handle_candidate_peer_abci_state_response(
        &mut self,
        response: CandidatePeerResponse<'_>,
        callback: &mut dyn CandidatePeerCallback,
    ) -> CandidatePeerOutcome {
        if response.tag != CANDIDATE_PEER_ABCI_STATE_TAG {
            let outcome = CandidatePeerOutcome::PassthroughError {
                status_tag: PEER_STATUS_OK_TAG,
                original_tag: response.tag,
            };
            callback.on_candidate_peer_result(outcome.success());
            return outcome;
        }

        let local_millis = self.visor.consensus_time.unix_millis();
        let peer_millis = response.peer_consensus_time.unix_millis();
        let reference_lag = match local_millis.cmp(&peer_millis) {
            Ordering::Less => Duration::ZERO,
            Ordering::Equal => Duration::ZERO,
            Ordering::Greater => Duration::from_millis((local_millis - peer_millis) as u64),
        };

        let candidate = CandidatePeerState {
            key: response.key,
            height: response.height,
            linked_digest: response.linked_digest,
            peer_consensus_time: response.peer_consensus_time,
            reference_lag,
        };

        let outcome = match self.candidate_peers.upsert(candidate) {
            CandidatePeerUpdate::Inserted | CandidatePeerUpdate::ReplacedSameKey => CandidatePeerOutcome::Accepted {
                status_tag: PEER_STATUS_OK_TAG,
                reference_lag,
            },
            CandidatePeerUpdate::DigestMismatch { expected, got } => CandidatePeerOutcome::DigestMismatch {
                status_tag: PEER_STATUS_MISMATCH_TAG,
                expected,
                got,
            },
        };
        callback.on_candidate_peer_result(outcome.success());
        outcome
    }
}

pub trait StateDigest {
    fn digest32(&self, bytes: &[u8]) -> [u8; 32];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CandidatePeerKey(pub [u8; 20]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePeerState {
    pub key: CandidatePeerKey,
    pub height: u64,
    pub linked_digest: [u8; 32],
    pub peer_consensus_time: Timestamp,
    pub reference_lag: Duration,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CandidatePeerBook {
    entries: Vec<CandidatePeerState>,
}

impl CandidatePeerBook {
    pub fn upsert(&mut self, candidate: CandidatePeerState) -> CandidatePeerUpdate {
        match self.entries.binary_search_by_key(&candidate.key, |entry| entry.key) {
            Ok(index) => {
                let existing = &mut self.entries[index];
                if existing.height == candidate.height && existing.linked_digest != candidate.linked_digest {
                    CandidatePeerUpdate::DigestMismatch {
                        expected: existing.linked_digest,
                        got: candidate.linked_digest,
                    }
                } else {
                    *existing = candidate;
                    CandidatePeerUpdate::ReplacedSameKey
                }
            }
            Err(index) => {
                self.entries.insert(index, candidate);
                CandidatePeerUpdate::Inserted
            }
        }
    }

    pub fn get(&self, key: CandidatePeerKey) -> Option<&CandidatePeerState> {
        self.entries
            .binary_search_by_key(&key, |entry| entry.key)
            .ok()
            .map(|index| &self.entries[index])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidatePeerUpdate {
    Inserted,
    ReplacedSameKey,
    DigestMismatch { expected: [u8; 32], got: [u8; 32] },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidatePeerResponse<'a> {
    pub tag: u16,
    pub key: CandidatePeerKey,
    pub height: u64,
    pub linked_digest: [u8; 32],
    pub peer_consensus_time: Timestamp,
    pub raw_payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidatePeerOutcome {
    Accepted { status_tag: u8, reference_lag: Duration },
    PassthroughError { status_tag: u8, original_tag: u16 },
    MissingLinkedState { status_tag: u16 },
    DigestMismatch { status_tag: u16, expected: [u8; 32], got: [u8; 32] },
}

impl CandidatePeerOutcome {
    pub fn success(self) -> bool {
        matches!(self, Self::Accepted { status_tag: PEER_STATUS_OK_TAG, .. } | Self::PassthroughError { status_tag: PEER_STATUS_OK_TAG, .. })
    }
}

pub trait CandidatePeerCallback {
    fn on_candidate_peer_result(&mut self, success: bool);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedAbciState {
    pub raw_state: Box<[u8; DECODED_STATE_COPY_LEN]>,
    pub decoded_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeStateError {
    ResolvePathFailed,
    DecodeFailed,
    TrailingBytes { decoded: usize, total: usize },
    WrongSize { actual: usize },
}

pub trait AbciStateDecoder {
    fn decode_rmp_state(&mut self, bytes: &[u8]) -> Result<(Vec<u8>, usize), DecodeStateError>;
}

/// Decode an ABCI state MessagePack buffer and reject trailing bytes.
///
/// IDA: `0x32725D0` copies a `0x3ae8`-byte decoded state to the caller and
/// panics if the decoder cursor does not equal the original input length.
pub fn decode_abci_state_rmp_buffer(decoder: &mut dyn AbciStateDecoder, input: &[u8]) -> Result<DecodedAbciState, DecodeStateError> {
    let (decoded, consumed) = decoder.decode_rmp_state(input)?;
    if consumed != input.len() {
        return Err(DecodeStateError::TrailingBytes { decoded: consumed, total: input.len() });
    }
    if decoded.len() != DECODED_STATE_COPY_LEN {
        return Err(DecodeStateError::WrongSize { actual: decoded.len() });
    }

    let mut raw_state = Box::new([0u8; DECODED_STATE_COPY_LEN]);
    raw_state.copy_from_slice(&decoded);
    Ok(DecodedAbciState { raw_state, decoded_len: consumed })
}

pub trait AbciStatePathResolver {
    fn read_state_file<'a>(&mut self, path: &'a Path) -> Result<&'a [u8], DecodeStateError>;
}

/// Resolve a path and dispatch `.rmp` files into the MessagePack state decoder.
///
/// IDA: `0x3273810` propagates Result discriminant `2` unchanged on path failure,
/// otherwise copies a `0x1fb8` success payload and calls the decode continuation.
pub fn resolve_and_decode_rmp_state_path(
    resolver: &mut dyn AbciStatePathResolver,
    decoder: &mut dyn AbciStateDecoder,
    path: &Path,
) -> Result<DecodedAbciState, DecodeStateError> {
    let bytes = resolver.read_state_file(path)?;
    if path.extension().and_then(|ext| ext.to_str()) != Some("rmp") {
        return Err(DecodeStateError::ResolvePathFailed);
    }
    decode_abci_state_rmp_buffer(decoder, bytes)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateLinkPollState {
    Init,
    BuildScalar,
    ReadPreviousDigest,
    SerializeCurrent,
    CompareRoots,
    Ready,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbciStateLinkFuture {
    pub state: StateLinkPollState,
    pub work_flags: u16,
    pub last_digest: Option<[u8; 32]>,
    pub linked_state: Option<LinkedAbciState>,
}

impl Default for AbciStateLinkFuture {
    fn default() -> Self {
        Self {
            state: StateLinkPollState::Init,
            work_flags: 0,
            last_digest: None,
            linked_state: None,
        }
    }
}

impl AbciStateLinkFuture {
    /// Drive the recovered async state machine one step.
    ///
    /// IDA: `0x22AE8A0` uses a byte discriminant at future `+0x216`, stores
    /// subfutures at `+0x218`, `+0x2b0`, and `+0x21f8`, and returns Pending from
    /// arms that preserve the discriminant.
    pub fn poll_step(&mut self, core: &AbciStateCore, hasher: &dyn StateDigest) -> Poll<Result<&LinkedAbciState, RootMismatch>> {
        loop {
            match self.state {
                StateLinkPollState::Init => {
                    self.work_flags = 0;
                    self.state = StateLinkPollState::BuildScalar;
                }
                StateLinkPollState::BuildScalar => {
                    self.linked_state = Some(core.build_linked_abci_state(hasher));
                    self.state = StateLinkPollState::ReadPreviousDigest;
                    return Poll::Pending;
                }
                StateLinkPollState::ReadPreviousDigest => {
                    self.last_digest = self.linked_state.as_ref().map(|state| state.digest);
                    self.state = StateLinkPollState::SerializeCurrent;
                    return Poll::Pending;
                }
                StateLinkPollState::SerializeCurrent => {
                    self.state = StateLinkPollState::CompareRoots;
                }
                StateLinkPollState::CompareRoots => {
                    if let (Some(previous), Some(current)) = (self.last_digest, self.linked_state.as_ref()) {
                        if previous != current.digest {
                            return Poll::Ready(Err(RootMismatch {
                                block_number: current.visor.height,
                                root: previous,
                                block_hash: current.digest,
                            }));
                        }
                    }
                    self.state = StateLinkPollState::Ready;
                }
                StateLinkPollState::Ready => {
                    return Poll::Ready(Ok(self.linked_state.as_ref().expect("linked state initialized before Ready")));
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootMismatch {
    pub block_number: u64,
    pub root: [u8; 32],
    pub block_hash: [u8; 32],
}

pub trait StateSegmentSerializer {
    fn serialize_rmp_segment(&mut self, field_name: &'static str, height: u64, segment: &[u8]) -> Vec<u8>;
    fn serialize_json_segment(&mut self, field_name: &'static str, height: u64, segment: &[u8]) -> Vec<u8>;
}

pub trait DumpWriter {
    fn write_dump(&mut self, path: &Path, bytes: &[u8]) -> Result<(), DumpWriteError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DumpWriteError {
    Io,
    InvalidPath,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SerializedStateSegment {
    pub field_name: &'static str,
    pub height: u64,
    pub bytes: Vec<u8>,
    pub mirrored_to_dump: bool,
}

/// Core serializer for the `exchange` field at `state+0xbc0`.
///
/// IDA: `0x46CF030`; with dump wrapper `0x46CEA60` and writer `0x46CF490`.
pub fn serialize_exchange_0bc0_with_dump_path(
    serializer: &mut dyn StateSegmentSerializer,
    writer: &mut dyn DumpWriter,
    height: u64,
    exchange_segment: &[u8],
    dump_path: &Path,
) -> Result<SerializedStateSegment, DumpWriteError> {
    serialize_segment_with_optional_dump(serializer, writer, "exchange", height, exchange_segment, dump_path)
}

/// Core serializer for the second exchange-like field at `state+0x1640`.
///
/// IDA: `0x46CF990` and wrapper `0x46CFE90`; same branch shape as the `+0xbc0` serializer.
pub fn serialize_exchange_1640_with_dump_path(
    serializer: &mut dyn StateSegmentSerializer,
    writer: &mut dyn DumpWriter,
    height: u64,
    exchange_segment: &[u8],
    dump_path: &Path,
) -> Result<SerializedStateSegment, DumpWriteError> {
    serialize_segment_with_optional_dump(serializer, writer, "exchange", height, exchange_segment, dump_path)
}

fn serialize_segment_with_optional_dump(
    serializer: &mut dyn StateSegmentSerializer,
    writer: &mut dyn DumpWriter,
    field_name: &'static str,
    height: u64,
    segment: &[u8],
    dump_path: &Path,
) -> Result<SerializedStateSegment, DumpWriteError> {
    let dump_is_rmp = dump_path.extension().and_then(|ext| ext.to_str()) == Some("rmp");
    let bytes = if dump_is_rmp {
        serializer.serialize_rmp_segment(field_name, height, segment)
    } else {
        serializer.serialize_json_segment(field_name, height, segment)
    };

    let mirrored_to_dump = dump_path != Path::new("/dev/null");
    if mirrored_to_dump {
        writer.write_dump(dump_path, &bytes)?;
    }

    Ok(SerializedStateSegment { field_name, height, bytes, mirrored_to_dump })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactOrderEntry0x70 {
    pub timestamp: u64,
    pub oid: u64,
    pub user: [u8; 20],
    pub asset: u32,
    pub side: u8,
    pub price_bits: u64,
    pub size_bits: u64,
    pub flags: u64,
    pub reserved: [u8; 0x30],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactOrderEntry0x48 {
    pub timestamp: u64,
    pub oid: u64,
    pub user: [u8; 20],
    pub asset: u32,
    pub side: u8,
    pub price_bits: u64,
    pub size_bits: u64,
    pub flags: u16,
}

impl From<&CompactOrderEntry0x70> for CompactOrderEntry0x48 {
    fn from(entry: &CompactOrderEntry0x70) -> Self {
        Self {
            timestamp: entry.timestamp,
            oid: entry.oid,
            user: entry.user,
            asset: entry.asset,
            side: entry.side,
            price_bits: entry.price_bits,
            size_bits: entry.size_bits,
            flags: entry.flags as u16,
        }
    }
}

/// In-place compaction used by the state serializers.
///
/// IDA: `0x444B430` maps records of size `0x70` to records of size `0x48` and
/// returns the updated destination end pointer. The caller passes the same source
/// and destination base, so the source stride is intentionally larger than output.
pub fn compact_order_entries_segment1(entries: &[CompactOrderEntry0x70], out: &mut Vec<CompactOrderEntry0x48>) {
    out.reserve(entries.len());
    for entry in entries {
        out.push(CompactOrderEntry0x48::from(entry));
    }
}

/// Second monomorph of the same compaction shape.
///
/// IDA: `0x444C310`; kept separate because the binary has a distinct seed, but
/// the recovered field movement is the same 0x70-to-0x48 transform.
pub fn compact_order_entries_segment2(entries: &[CompactOrderEntry0x70], out: &mut Vec<CompactOrderEntry0x48>) {
    compact_order_entries_segment1(entries, out);
}

fn log_linked_abci_state(description: &str, periodic_file: &Path, file: &Path, height: u64) {
    let _ = ("@@ linked abci state @@", description, periodic_file, file, height);
}
