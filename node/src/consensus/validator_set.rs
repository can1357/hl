//! Reconstruction of `/home/ubuntu/hl/code_Mainnet/node/src/consensus/validator_set.rs`.
//!
//! Seed EAs from `path_to_funcs.json`: `0x44AA5A0`, `0x44ADFA0`, `0x44B3040`,
//! `0x44B3200`, `0x44B4F80`, `0x44B6450`, `0x44B6670`, `0x454AA10`,
//! `0x454B430`, `0x454B700`, `0x454BA50`, `0x454BD70`, `0x4758D70`,
//! `0x47594F0`, `0x4B314F0`, `0x4B31660`, `0x4B31D40`, `0x4B31E70`.
//!
//! Confidence: medium for the exposed data model, field order, and active-stake
//! algorithms; low for exact function-to-seed assignment while the shared IDA
//! worker is queue-full. Grounded local evidence: `protocol/structs.txt` records
//! `ValidatorSetSnapshot` at `0x396B810` and `0x39F39F0` with `stakes` at +0 and
//! `jailed_validators` at +0x20; `recon/node/src/consensus/types.rs` carries the
//! same `BTreeMap<ValidatorIndex, u64>` / `BTreeSet<ValidatorIndex>` shape; the
//! consensus notes require 2/3+ stake quorums and excluding jailed validators.
//!
//! IDA updates pending because every attempted small call returned queue-full or
//! timed out: decompile/callers/callees/xrefs for all seed EAs above; then rename
//! confirmed functions to `node_consensus_validator_set__...`, add source-path
//! header comments, and declare/apply `hl_node_consensus_ValidatorSetSnapshot`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub type Round = u64;
pub type ValidatorIndex = u32;
pub type Stake = u64;
pub type ValidatorSigner = [u8; 20];
pub type SignatureBytes = [u8; 65];
pub type NodeIp = String;

/// Validator profile used by C-chain validator registration and bridge views.
///
/// [INFERENCE] The field names come from `protocol/structs.txt` and
/// `protocol/struct_layouts.md`; exact in-memory offsets other than adjacent
/// serializer/debug field order remain IDA-pending for this source file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CValidatorProfile {
    pub node_ip: NodeIp,
    pub name: String,
    pub description: String,
    pub delegations_disabled: bool,
    pub commission_bps: u16,
    pub signer: ValidatorSigner,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeIpSignature {
    pub node_ip: NodeIp,
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeValidatorInfo {
    pub validator: ValidatorSigner,
    pub stake: Stake,
    pub profile: Option<CValidatorProfile>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeValidatorSet {
    pub validators: Vec<BridgeValidatorInfo>,
    pub epoch: u64,
}

/// Snapshot of the consensus voting set.
///
/// IDA/local layout evidence:
/// - `stakes` at +0x00.
/// - `jailed_validators` at +0x20.
///
/// The ordered containers are important: serializers/debug paths walk validators
/// deterministically, and quorum calculation must not depend on hash-map order.
#[derive(Clone, Eq, PartialEq)]
pub struct ValidatorSetSnapshot {
    pub stakes: BTreeMap<ValidatorIndex, Stake>,
    pub jailed_validators: BTreeSet<ValidatorIndex>,
}

impl fmt::Debug for ValidatorSetSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatorSetSnapshot")
            .field("stakes", &self.stakes)
            .field("jailed_validators", &self.jailed_validators)
            .finish()
    }
}

impl Default for ValidatorSetSnapshot {
    fn default() -> Self { Self::new() }
}

impl ValidatorSetSnapshot {
    pub const fn new() -> Self {
        Self { stakes: BTreeMap::new(), jailed_validators: BTreeSet::new() }
    }

    pub fn from_stakes(stakes: BTreeMap<ValidatorIndex, Stake>) -> Self {
        let mut snapshot = Self { stakes, jailed_validators: BTreeSet::new() };
        snapshot.drop_zero_stake_entries();
        snapshot
    }

    pub fn with_jailed(
        stakes: BTreeMap<ValidatorIndex, Stake>,
        jailed_validators: BTreeSet<ValidatorIndex>,
    ) -> Self {
        let mut snapshot = Self { stakes, jailed_validators };
        snapshot.drop_zero_stake_entries();
        snapshot.drop_unknown_jailed_entries();
        snapshot
    }

    pub fn len(&self) -> usize { self.stakes.len() }

    pub fn is_empty(&self) -> bool { self.stakes.is_empty() }

    pub fn contains_validator(&self, validator: ValidatorIndex) -> bool {
        self.stakes.contains_key(&validator)
    }

    pub fn raw_stake(&self, validator: ValidatorIndex) -> Option<Stake> {
        self.stakes.get(&validator).copied()
    }

    pub fn is_jailed(&self, validator: ValidatorIndex) -> bool {
        self.jailed_validators.contains(&validator)
    }

    /// Returns the voting stake that counts toward consensus quorum.
    /// Missing, zero-stake, and jailed validators count as zero.
    pub fn active_stake(&self, validator: ValidatorIndex) -> Stake {
        if self.is_jailed(validator) {
            0
        } else {
            self.raw_stake(validator).unwrap_or(0)
        }
    }

    pub fn active_validator_count(&self) -> usize {
        self.stakes
            .iter()
            .filter(|(validator, stake)| **stake != 0 && !self.jailed_validators.contains(validator))
            .count()
    }

    pub fn active_validators(&self) -> impl Iterator<Item = (ValidatorIndex, Stake)> + '_ {
        self.stakes.iter().filter_map(|(&validator, &stake)| {
            if stake == 0 || self.jailed_validators.contains(&validator) {
                None
            } else {
                Some((validator, stake))
            }
        })
    }

    /// Sum of all unjailed non-zero stakes. Saturates rather than panicking; the
    /// binary is release-built and consensus callers should convert impossible
    /// supply overflow into a failed quorum, not process abort.
    pub fn total_active_stake(&self) -> Stake {
        self.active_validators()
            .fold(0u64, |acc, (_, stake)| acc.saturating_add(stake))
    }

    /// [INFERENCE] HyperBFT needs strictly more than 2/3 of active stake. The
    /// integer threshold is `floor(2 * total / 3) + 1`, computed without `2*total`
    /// overflow. IDA confirmation is pending for seeds `0x4758D70`/`0x47594F0`.
    pub fn quorum_threshold_for_total(total_active_stake: Stake) -> Option<Stake> {
        if total_active_stake == 0 {
            return None;
        }
        let two_thirds_floor = (total_active_stake / 3)
            .saturating_mul(2)
            .saturating_add(((total_active_stake % 3) * 2) / 3);
        Some(two_thirds_floor.saturating_add(1))
    }

    pub fn quorum_threshold(&self) -> Option<Stake> {
        Self::quorum_threshold_for_total(self.total_active_stake())
    }

    pub fn has_quorum_weight(&self, signed_weight: Stake) -> bool {
        self.quorum_threshold().is_some_and(|threshold| signed_weight >= threshold)
    }

    pub fn insert_or_update_stake(&mut self, validator: ValidatorIndex, stake: Stake) {
        if stake == 0 {
            self.stakes.remove(&validator);
            self.jailed_validators.remove(&validator);
        } else {
            self.stakes.insert(validator, stake);
        }
    }

    pub fn remove_validator(&mut self, validator: ValidatorIndex) -> Option<Stake> {
        self.jailed_validators.remove(&validator);
        self.stakes.remove(&validator)
    }

    pub fn set_jailed(&mut self, validator: ValidatorIndex, jailed: bool) -> bool {
        if !self.contains_validator(validator) {
            return false;
        }
        if jailed {
            self.jailed_validators.insert(validator)
        } else {
            self.jailed_validators.remove(&validator)
        }
    }

    pub fn unjail_all(&mut self) { self.jailed_validators.clear(); }

    pub fn apply_delta(&mut self, delta: ValidatorSetDelta) {
        for (validator, stake) in delta.stake_updates {
            self.insert_or_update_stake(validator, stake);
        }
        for validator in delta.jailed {
            let _ = self.set_jailed(validator, true);
        }
        for validator in delta.unjailed {
            let _ = self.set_jailed(validator, false);
        }
        self.drop_unknown_jailed_entries();
    }

    pub fn tally_votes<I>(&self, voters: I) -> VoteWeightSummary
    where
        I: IntoIterator<Item = ValidatorIndex>,
    {
        let mut seen = BTreeSet::new();
        let mut summary = VoteWeightSummary::new(self.total_active_stake());
        for validator in voters {
            match self.count_vote(validator, &mut seen) {
                CountVoteResult::Counted { stake, reached_quorum } => {
                    summary.counted += 1;
                    summary.signed_weight = summary.signed_weight.saturating_add(stake);
                    if reached_quorum {
                        summary.reached_quorum = true;
                    }
                }
                CountVoteResult::Duplicate => summary.duplicates += 1,
                CountVoteResult::UnknownValidator => summary.unknown += 1,
                CountVoteResult::JailedValidator => summary.jailed += 1,
                CountVoteResult::ZeroStake => summary.zero_stake += 1,
            }
        }
        summary.reached_quorum |= summary
            .threshold
            .is_some_and(|threshold| summary.signed_weight >= threshold);
        summary
    }

    pub fn count_vote(
        &self,
        validator: ValidatorIndex,
        seen: &mut BTreeSet<ValidatorIndex>,
    ) -> CountVoteResult {
        if !seen.insert(validator) {
            return CountVoteResult::Duplicate;
        }
        let Some(&stake) = self.stakes.get(&validator) else {
            return CountVoteResult::UnknownValidator;
        };
        if stake == 0 {
            return CountVoteResult::ZeroStake;
        }
        if self.jailed_validators.contains(&validator) {
            return CountVoteResult::JailedValidator;
        }
        CountVoteResult::Counted { stake, reached_quorum: false }
    }

    /// Verifies that a signature list names a valid, unique, unjailed quorum.
    /// Signature bytes are not checked here; callers do cryptographic verification
    /// before or after this weight pass depending on the message type.
    pub fn check_quorum_indices<I>(&self, voters: I) -> Result<VoteWeightSummary, ValidatorSetError>
    where
        I: IntoIterator<Item = ValidatorIndex>,
    {
        let summary = self.tally_votes(voters);
        if summary.total_active_stake == 0 {
            return Err(ValidatorSetError::EmptyValidators);
        }
        if summary.duplicates != 0 {
            return Err(ValidatorSetError::DuplicateValidatorVote);
        }
        if summary.unknown != 0 {
            return Err(ValidatorSetError::UnknownValidator);
        }
        if summary.jailed != 0 {
            return Err(ValidatorSetError::JailedValidator);
        }
        if summary.zero_stake != 0 {
            return Err(ValidatorSetError::ZeroStakeValidator);
        }
        if !summary.reached_quorum {
            return Err(ValidatorSetError::NoQuorum {
                signed_weight: summary.signed_weight,
                threshold: summary.threshold.unwrap_or(0),
                total_active_stake: summary.total_active_stake,
            });
        }
        Ok(summary)
    }

    pub fn encode_bincode(&self, out: &mut Vec<u8>) {
        encode_varint_u64(out, self.stakes.len() as u64);
        for (&validator, &stake) in &self.stakes {
            encode_varint_u64(out, validator as u64);
            encode_varint_u64(out, stake);
        }
        encode_varint_u64(out, self.jailed_validators.len() as u64);
        for &validator in &self.jailed_validators {
            encode_varint_u64(out, validator as u64);
        }
    }

    pub fn decode_bincode(bytes: &[u8]) -> Result<Self, ValidatorSetDecodeError> {
        let mut cursor = BincodeCursor::new(bytes);
        let stakes_len = cursor.read_len()?;
        let mut stakes = BTreeMap::new();
        for _ in 0..stakes_len {
            let validator = cursor.read_varint_u32()?;
            let stake = cursor.read_varint_u64()?;
            if stake != 0 {
                stakes.insert(validator, stake);
            }
        }
        let jailed_len = cursor.read_len()?;
        let mut jailed_validators = BTreeSet::new();
        for _ in 0..jailed_len {
            jailed_validators.insert(cursor.read_varint_u32()?);
        }
        cursor.finish()?;
        Ok(Self::with_jailed(stakes, jailed_validators))
    }

    fn drop_zero_stake_entries(&mut self) {
        self.stakes.retain(|_, stake| *stake != 0);
    }

    fn drop_unknown_jailed_entries(&mut self) {
        self.jailed_validators.retain(|validator| self.stakes.contains_key(validator));
    }
}

/// Delta applied when a new epoch or heartbeat-derived jail state changes the
/// active validator view.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidatorSetDelta {
    pub stake_updates: BTreeMap<ValidatorIndex, Stake>,
    pub jailed: BTreeSet<ValidatorIndex>,
    pub unjailed: BTreeSet<ValidatorIndex>,
}

impl ValidatorSetDelta {
    pub fn is_empty(&self) -> bool {
        self.stake_updates.is_empty() && self.jailed.is_empty() && self.unjailed.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoundValidatorSetHistory {
    pub current_round: Round,
    pub current: ValidatorSetSnapshot,
    pub round_to_snapshot: BTreeMap<Round, ValidatorSetSnapshot>,
}

impl RoundValidatorSetHistory {
    pub fn new(round: Round, current: ValidatorSetSnapshot) -> Self {
        let mut round_to_snapshot = BTreeMap::new();
        round_to_snapshot.insert(round, current.clone());
        Self { current_round: round, current, round_to_snapshot }
    }

    pub fn snapshot_at_or_before(&self, round: Round) -> Option<&ValidatorSetSnapshot> {
        self.round_to_snapshot.range(..=round).next_back().map(|(_, snapshot)| snapshot)
    }

    pub fn record_round(&mut self, round: Round) {
        self.current_round = round;
        self.round_to_snapshot.insert(round, self.current.clone());
    }

    pub fn apply_delta_at_round(&mut self, round: Round, delta: ValidatorSetDelta) {
        self.current.apply_delta(delta);
        self.record_round(round);
    }

    pub fn prune_before(&mut self, min_round_to_keep: Round) {
        let keep = self.round_to_snapshot.split_off(&min_round_to_keep);
        self.round_to_snapshot = keep;
        if !self.round_to_snapshot.contains_key(&self.current_round) {
            self.round_to_snapshot.insert(self.current_round, self.current.clone());
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CountVoteResult {
    Counted { stake: Stake, reached_quorum: bool },
    Duplicate,
    UnknownValidator,
    JailedValidator,
    ZeroStake,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteWeightSummary {
    pub signed_weight: Stake,
    pub total_active_stake: Stake,
    pub threshold: Option<Stake>,
    pub counted: usize,
    pub duplicates: usize,
    pub unknown: usize,
    pub jailed: usize,
    pub zero_stake: usize,
    pub reached_quorum: bool,
}

impl VoteWeightSummary {
    pub fn new(total_active_stake: Stake) -> Self {
        Self {
            signed_weight: 0,
            total_active_stake,
            threshold: ValidatorSetSnapshot::quorum_threshold_for_total(total_active_stake),
            counted: 0,
            duplicates: 0,
            unknown: 0,
            jailed: 0,
            zero_stake: 0,
            reached_quorum: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidatorSetError {
    EmptyValidators,
    DuplicateValidatorVote,
    UnknownValidator,
    JailedValidator,
    ZeroStakeValidator,
    NoQuorum { signed_weight: Stake, threshold: Stake, total_active_stake: Stake },
}

impl fmt::Display for ValidatorSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyValidators => f.write_str("empty validator set"),
            Self::DuplicateValidatorVote => f.write_str("duplicate validator vote"),
            Self::UnknownValidator => f.write_str("unknown validator"),
            Self::JailedValidator => f.write_str("jailed validator"),
            Self::ZeroStakeValidator => f.write_str("zero-stake validator"),
            Self::NoQuorum { signed_weight, threshold, total_active_stake } => write!(
                f,
                "qc no quorum: signed_weight={signed_weight}, threshold={threshold}, total_active_stake={total_active_stake}",
            ),
        }
    }
}

impl std::error::Error for ValidatorSetError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidatorSetDecodeError {
    Eof { needed: usize, remaining: usize },
    TrailingBytes { remaining: usize },
    VarintReservedByte(u8),
    VarintOverflow { target: &'static str, value: u128 },
    LengthOverflow(u64),
}

impl fmt::Display for ValidatorSetDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eof { needed, remaining } => {
                write!(f, "bincode eof: needed {needed}, remaining {remaining}")
            }
            Self::TrailingBytes { remaining } => write!(f, "bincode left {remaining} trailing bytes"),
            Self::VarintReservedByte(byte) => write!(f, "reserved bincode varint byte 0x{byte:02x}"),
            Self::VarintOverflow { target, value } => {
                write!(f, "bincode varint {value} does not fit in {target}")
            }
            Self::LengthOverflow(value) => write!(f, "bincode length {value} does not fit in usize"),
        }
    }
}

impl std::error::Error for ValidatorSetDecodeError {}

struct BincodeCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BincodeCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }

    fn finish(&self) -> Result<(), ValidatorSetDecodeError> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if remaining == 0 { Ok(()) } else { Err(ValidatorSetDecodeError::TrailingBytes { remaining }) }
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], ValidatorSetDecodeError> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if remaining < len {
            return Err(ValidatorSetDecodeError::Eof { needed: len, remaining });
        }
        let start = self.offset;
        self.offset += len;
        Ok(&self.bytes[start..start + len])
    }

    fn read_u8(&mut self) -> Result<u8, ValidatorSetDecodeError> { Ok(self.read_exact(1)?[0]) }

    fn read_len(&mut self) -> Result<usize, ValidatorSetDecodeError> {
        let value = self.read_varint_u64()?;
        usize::try_from(value).map_err(|_| ValidatorSetDecodeError::LengthOverflow(value))
    }

    fn read_varint_u32(&mut self) -> Result<u32, ValidatorSetDecodeError> {
        let value = self.read_varint_u128()?;
        u32::try_from(value).map_err(|_| ValidatorSetDecodeError::VarintOverflow { target: "u32", value })
    }

    fn read_varint_u64(&mut self) -> Result<u64, ValidatorSetDecodeError> {
        let value = self.read_varint_u128()?;
        u64::try_from(value).map_err(|_| ValidatorSetDecodeError::VarintOverflow { target: "u64", value })
    }

    fn read_varint_u128(&mut self) -> Result<u128, ValidatorSetDecodeError> {
        match self.read_u8()? {
            marker @ 0..=250 => Ok(marker as u128),
            251 => Ok(u16::from_le_bytes(self.read_exact(2)?.try_into().unwrap()) as u128),
            252 => Ok(u32::from_le_bytes(self.read_exact(4)?.try_into().unwrap()) as u128),
            253 => Ok(u64::from_le_bytes(self.read_exact(8)?.try_into().unwrap()) as u128),
            254 => Ok(u128::from_le_bytes(self.read_exact(16)?.try_into().unwrap())),
            reserved => Err(ValidatorSetDecodeError::VarintReservedByte(reserved)),
        }
    }
}

fn encode_varint_u64(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=250 => out.push(value as u8),
        251..=0xffff => {
            out.push(251);
            out.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(252);
            out.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            out.push(253);
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
}
