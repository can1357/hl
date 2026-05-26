#![allow(dead_code)]

use std::cmp::Ordering;
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type Usd = u64;
pub type Nonce = u64;
pub type BlockNumber = u64;
pub type TimestampMillis = u64;

pub const BRIDGE2_FIELD_COUNT: usize = 10;
pub const BRIDGE2_WRAPPER_FIELD: &str = "bridge2";
pub const INSERT_OK_TAG: u16 = 390;
pub const DUPLICATE_WITHDRAWAL_TAG: u16 = 154;
pub const BALANCE_UNDERFLOW_PANIC: &str = "bridge2 withdrawal balance bug";

/// Ethereum event identity used by bridge-v2 deposit and validator-set vote maps.
///
/// The exact member names are inferred from sibling `EthEventId` strings.  The
/// binary treats the serialized type as a named struct and uses it as an ordered
/// map key for deposit/validator-set event votes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EthEventId {
    pub block_number: BlockNumber,
    pub log_index: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct UserAndNonce {
    pub nonce: Nonce,
    pub user: Address,
}

impl UserAndNonce {
    pub const fn new(nonce: Nonce, user: Address) -> Self {
        Self { nonce, user }
    }
}

impl Ord for UserAndNonce {
    fn cmp(&self, other: &Self) -> Ordering {
        self.user.cmp(&other.user).then_with(|| self.nonce.cmp(&other.nonce))
    }
}

impl PartialOrd for UserAndNonce {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Withdrawal {
    pub usd: Usd,
    pub destination: Address,
}

impl Withdrawal {
    pub const fn new(usd: Usd, destination: Address) -> Self {
        Self { usd, destination }
    }
}

/// [INFERENCE] A bridge deposit observed on the EVM side.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DepositData {
    pub user: Address,
    pub usd: Usd,
}

/// [INFERENCE] A completed deposit record retained in `finished_deposits_data`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FinishedDepositData {
    pub user: Address,
    pub usd: Usd,
    pub time: TimestampMillis,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SignatureVotes {
    pub signers: BTreeSet<Address>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FinalizedVotes {
    pub voters: BTreeSet<Address>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidatorSetSignatures {
    pub signers: BTreeSet<Address>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidatorSetFinalizedVotes {
    pub voters: BTreeSet<Address>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Bridge2 {
    pub eth_id_to_deposit_votes: BTreeMap<EthEventId, SignatureVotes>,
    pub finished_deposits_data: BTreeMap<EthEventId, FinishedDepositData>,
    pub withdrawal_signatures: BTreeMap<UserAndNonce, Withdrawal>,
    pub withdrawal_finalized_votes: BTreeMap<UserAndNonce, FinalizedVotes>,
    pub finished_withdrawal_to_time: BTreeMap<UserAndNonce, TimestampMillis>,
    pub validator_set_signatures: BTreeMap<EthEventId, ValidatorSetSignatures>,
    pub validator_set_finalized_votes: BTreeMap<EthEventId, ValidatorSetFinalizedVotes>,
    pub bal: Usd,
    pub last_pruned_deposit_block_number: BlockNumber,
    pub oaw: u32,
}

impl Bridge2 {
    pub const fn field_names() -> [&'static str; BRIDGE2_FIELD_COUNT] {
        [
            "eth_id_to_deposit_votes",
            "finished_deposits_data",
            "withdrawal_signatures",
            "withdrawal_finalized_votes",
            "finished_withdrawal_to_time",
            "validator_set_signatures",
            "validator_set_finalized_votes",
            "bal",
            "last_pruned_deposit_block_number",
            "oaw",
        ]
    }

    /// Records the withdrawal in the signature map and debits the bridge balance.
    ///
    /// Recovered control flow builds `(nonce, user)` and `(usd, destination)` stack
    /// records, inserts them into `withdrawal_signatures`, unwraps the insert
    /// result, then subtracts `usd` from `bal`.  The checked subtraction panic
    /// string is exactly `bridge2 withdrawal balance bug`.
    pub fn record_withdrawal_signature_and_debit(
        &mut self,
        user: Address,
        destination: Address,
        usd: Usd,
        nonce: Nonce,
    ) {
        self.insert_withdrawal_signature(
            UserAndNonce::new(nonce, user),
            Withdrawal::new(usd, destination),
        )
        .unwrap();

        self.bal = self.bal.checked_sub(usd).expect(BALANCE_UNDERFLOW_PANIC);
    }

    /// BTree insert helper recovered as the only direct callee of the debit path.
    ///
    /// Binary comparison order is the 20-byte user address first and nonce second;
    /// this Rust mirror uses the same logical key and rejects duplicates with the
    /// compact error tag `154` before mutating the map.
    pub fn insert_withdrawal_signature(
        &mut self,
        key: UserAndNonce,
        withdrawal: Withdrawal,
    ) -> Result<(), Bridge2InsertError> {
        match self.withdrawal_signatures.entry(key) {
            Entry::Vacant(slot) => {
                slot.insert(withdrawal);
                Ok(())
            }
            Entry::Occupied(_) => Err(Bridge2InsertError::DuplicateWithdrawal(key)),
        }
    }

    pub fn finalize_withdrawal(&mut self, key: UserAndNonce, time: TimestampMillis) {
        self.finished_withdrawal_to_time.insert(key, time);
        self.withdrawal_signatures.remove(&key);
    }

    pub fn prune_finished_deposits_before(&mut self, block_number: BlockNumber) {
        self.finished_deposits_data.retain(|event_id, _| event_id.block_number >= block_number);
        self.eth_id_to_deposit_votes.retain(|event_id, _| event_id.block_number >= block_number);
        self.last_pruned_deposit_block_number = block_number;
    }

    pub const fn serialized_field_count() -> usize {
        BRIDGE2_FIELD_COUNT
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Bridge2Field {
    EthIdToDepositVotes,
    FinishedDepositsData,
    WithdrawalSignatures,
    WithdrawalFinalizedVotes,
    FinishedWithdrawalToTime,
    ValidatorSetSignatures,
    ValidatorSetFinalizedVotes,
    Bal,
    LastPrunedDepositBlockNumber,
    Oaw,
}

impl Bridge2Field {
    pub const fn name(self) -> &'static str {
        match self {
            Self::EthIdToDepositVotes => "eth_id_to_deposit_votes",
            Self::FinishedDepositsData => "finished_deposits_data",
            Self::WithdrawalSignatures => "withdrawal_signatures",
            Self::WithdrawalFinalizedVotes => "withdrawal_finalized_votes",
            Self::FinishedWithdrawalToTime => "finished_withdrawal_to_time",
            Self::ValidatorSetSignatures => "validator_set_signatures",
            Self::ValidatorSetFinalizedVotes => "validator_set_finalized_votes",
            Self::Bal => "bal",
            Self::LastPrunedDepositBlockNumber => "last_pruned_deposit_block_number",
            Self::Oaw => "oaw",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "eth_id_to_deposit_votes" => Some(Self::EthIdToDepositVotes),
            "finished_deposits_data" => Some(Self::FinishedDepositsData),
            "withdrawal_signatures" => Some(Self::WithdrawalSignatures),
            "withdrawal_finalized_votes" => Some(Self::WithdrawalFinalizedVotes),
            "finished_withdrawal_to_time" => Some(Self::FinishedWithdrawalToTime),
            "validator_set_signatures" => Some(Self::ValidatorSetSignatures),
            "validator_set_finalized_votes" => Some(Self::ValidatorSetFinalizedVotes),
            "bal" => Some(Self::Bal),
            "last_pruned_deposit_block_number" => Some(Self::LastPrunedDepositBlockNumber),
            "oaw" => Some(Self::Oaw),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bridge2InsertError {
    DuplicateWithdrawal(UserAndNonce),
}

impl Bridge2InsertError {
    pub const fn compact_tag(self) -> u16 {
        match self {
            Self::DuplicateWithdrawal(_) => DUPLICATE_WITHDRAWAL_TAG,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Bridge2DecodeError {
    WrongFieldCount { expected: usize, actual: usize },
    UnknownField(String),
    DuplicateField(Bridge2Field),
    MissingField(Bridge2Field),
    WrongWrapper(String),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Bridge2SeenFields(u16);

impl Bridge2SeenFields {
    pub const fn new() -> Self {
        Self(0)
    }

    pub fn mark(&mut self, field: Bridge2Field) -> Result<(), Bridge2DecodeError> {
        let bit = 1u16 << field as u8;
        if self.0 & bit != 0 {
            return Err(Bridge2DecodeError::DuplicateField(field));
        }
        self.0 |= bit;
        Ok(())
    }

    pub fn require_all(self) -> Result<(), Bridge2DecodeError> {
        for field in [
            Bridge2Field::EthIdToDepositVotes,
            Bridge2Field::FinishedDepositsData,
            Bridge2Field::WithdrawalSignatures,
            Bridge2Field::WithdrawalFinalizedVotes,
            Bridge2Field::FinishedWithdrawalToTime,
            Bridge2Field::ValidatorSetSignatures,
            Bridge2Field::ValidatorSetFinalizedVotes,
            Bridge2Field::Bal,
            Bridge2Field::LastPrunedDepositBlockNumber,
            Bridge2Field::Oaw,
        ] {
            if self.0 & (1u16 << field as u8) == 0 {
                return Err(Bridge2DecodeError::MissingField(field));
            }
        }
        Ok(())
    }
}
