#![allow(dead_code)]

use std::collections::BTreeSet;

pub type Address = [u8; 20];
pub type Usd = u64;
pub type BlockNumber = u64;
pub type TimestampMillis = u64;

pub const STATUS_OK: u16 = 390;
/// The bridge vote path rejects `usd >= 0xCCCCCCCCCCCCCCCD` before any state
/// lookup and bubbles the raw amount back in the error payload.
pub const STATUS_AMOUNT_OVERFLOW: u16 = 319;
/// [INFERENCE] `sub_374E2E0` returns this when the deposit witness fails the
/// pre-bridge validation performed through `sub_2FDD5D0(...)`.
pub const STATUS_INVALID_DEPOSIT_WITNESS: u16 = 45;
/// [INFERENCE] Returned when the deposit's block number is already at or below
/// `bridge2.last_pruned_deposit_block_number`.
pub const STATUS_DEPOSIT_PRUNED: u16 = 46;
/// [INFERENCE] `l1_qtys_impl_ntl__credit_user_ntl_and_log` exits early with this
/// code when `action.deposit.flags_or_kind != 0`, i.e. the vote targets a closed,
/// already-finished, or otherwise unsupported deposit variant.
pub const STATUS_DEPOSIT_NOT_CREDITABLE: u16 = 55;
/// The credit helper asserts that an expected bridge-deposit bookkeeping row is
/// present before writing the finished-deposit record.
pub const STATUS_EXPECTED_TRACKER_MISSING: u16 = 321;

pub const OUTCOME_TAG_SUCCESS: u8 = 13;
pub const OUTCOME_TAG_ERROR: u8 = 14;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EthEventId {
    pub block_number: BlockNumber,
    pub log_index: u64,
}

/// Action-local deposit witness forwarded into the bridge-v2 vote/finalization
/// helper at `0x3947510`.
///
/// Grounded layout facts from `sub_374E2E0` / `sub_3947510`:
/// - bytes `0x00..0x0F` are read as an ordered key whose first `u64` is compared
///   against `bridge2.last_pruned_deposit_block_number`;
/// - byte `0x38` (`56`) is treated as a compact discriminator/flag byte;
/// - bytes `0x39..0x3F` are additional witness payload consumed by the bridge
///   helper but were not fully named from this handler alone.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DepositWitness {
    pub eth_event_id: EthEventId,
    pub raw_prefix: [u8; 40],
    pub flags_or_kind: u8,
    pub raw_suffix: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VoteEthDepositAction {
    pub usd: Usd,
    pub deposit: DepositWitness,
    pub user: Address,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FinishedDepositData {
    pub user: Address,
    pub usd: Usd,
    /// [INFERENCE] The bridge finalization helper persists a timestamp alongside
    /// the `(user, usd)` pair in `finished_deposits_data`.
    pub time: TimestampMillis,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SignatureVotes {
    pub signers: BTreeSet<Address>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepositVoteProgress {
    VoteRecordedOnly,
    FinalizedNow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoteEthDepositError {
    AmountOverflow { usd: Usd },
    InvalidDepositWitness,
    DepositPruned { block_number: BlockNumber, prune_floor: BlockNumber },
    DepositNotCreditable { flags_or_kind: u8 },
    ExpectedTrackerMissing,
    Raw(u16),
}

impl VoteEthDepositError {
    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::AmountOverflow { .. } => STATUS_AMOUNT_OVERFLOW,
            Self::InvalidDepositWitness => STATUS_INVALID_DEPOSIT_WITNESS,
            Self::DepositPruned { .. } => STATUS_DEPOSIT_PRUNED,
            Self::DepositNotCreditable { .. } => STATUS_DEPOSIT_NOT_CREDITABLE,
            Self::ExpectedTrackerMissing => STATUS_EXPECTED_TRACKER_MISSING,
            Self::Raw(status) => status,
        }
    }

    #[inline]
    pub const fn from_status(status: u16) -> Self {
        match status {
            STATUS_INVALID_DEPOSIT_WITNESS => Self::InvalidDepositWitness,
            STATUS_DEPOSIT_PRUNED => Self::DepositPruned {
                block_number: 0,
                prune_floor: 0,
            },
            STATUS_DEPOSIT_NOT_CREDITABLE => Self::DepositNotCreditable { flags_or_kind: 0 },
            STATUS_EXPECTED_TRACKER_MISSING => Self::ExpectedTrackerMissing,
            other => Self::Raw(other),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BaseActionOutcome {
    Success,
    Error { status: u16, error: VoteEthDepositError },
}

impl BaseActionOutcome {
    #[inline]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Success => OUTCOME_TAG_SUCCESS,
            Self::Error { .. } => OUTCOME_TAG_ERROR,
        }
    }
}

/// State slice touched by `sub_1E5FEB0`, `sub_374E2E0`, and
/// `l1_qtys_impl_ntl__credit_user_ntl_and_log`.
///
/// The concrete binary path:
/// 1. resolves a unique validator/signer record from the outer execution context;
/// 2. validates the deposit witness against bridge-v2 state, updates
///    `bridge2.eth_id_to_deposit_votes`, and reports whether the vote finalized;
/// 3. if finalized, writes the finished-deposit row, activates/restores the user
///    if needed, credits the user's NTL balance, bumps per-user counters, and
///    emits the bridge-deposit credit event.
pub trait VoteEthDepositState {
    /// Mirrors `base_iter__cham_iterator_unique_elem(state+14400, ...)`.
    fn resolve_unique_vote_signer(&self, ctx: &ValidatorVoteContext) -> Result<Address, VoteEthDepositError>;

    /// Mirrors `sub_374E2E0` plus the deeper bridge-v2 vote/finalization helper
    /// `sub_3947510`.
    fn validate_and_record_deposit_vote(
        &mut self,
        signer: Address,
        action: &VoteEthDepositAction,
        ctx: &ValidatorVoteContext,
    ) -> Result<DepositVoteProgress, VoteEthDepositError>;

    /// Mirrors `l1_qtys_impl_ntl__credit_user_ntl_and_log`.
    fn credit_user_ntl_and_log(
        &mut self,
        action: &VoteEthDepositAction,
    ) -> Result<(), VoteEthDepositError>;
}

/// Opaque outer context consumed by the pre-dispatch signer lookup and then
/// threaded into the bridge vote/finalization helper.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ValidatorVoteContext {
    pub raw: [u8; 32],
}

/// Exact handler flow recovered from `sub_1E5FEB0`.
///
/// - Any signer-lookup failure is returned immediately as outer error tag `14`.
/// - A successful bridge vote that does **not** finalize the deposit still returns
///   outer success tag `13`; the user credit path is skipped.
/// - Only the first successful finalization for a deposit reaches the NTL-credit
///   helper.
pub fn apply_vote_eth_deposit<S>(
    state: &mut S,
    vote_ctx: &ValidatorVoteContext,
    action: &VoteEthDepositAction,
) -> BaseActionOutcome
where
    S: VoteEthDepositState,
{
    let signer = match state.resolve_unique_vote_signer(vote_ctx) {
        Ok(signer) => signer,
        Err(error) => {
            return BaseActionOutcome::Error {
                status: error.status(),
                error,
            };
        }
    };

    if action.usd >= 0xCCCC_CCCC_CCCC_CCCD {
        return BaseActionOutcome::Error {
            status: STATUS_AMOUNT_OVERFLOW,
            error: VoteEthDepositError::AmountOverflow { usd: action.usd },
        };
    }

    if action.deposit.flags_or_kind != 0 {
        return BaseActionOutcome::Error {
            status: STATUS_DEPOSIT_NOT_CREDITABLE,
            error: VoteEthDepositError::DepositNotCreditable {
                flags_or_kind: action.deposit.flags_or_kind,
            },
        };
    }


    let progress = match state.validate_and_record_deposit_vote(signer, action, vote_ctx) {
        Ok(progress) => progress,
        Err(error) => {
            return BaseActionOutcome::Error {
                status: error.status(),
                error,
            };
        }
    };

    if progress == DepositVoteProgress::FinalizedNow {
        if let Err(error) = state.credit_user_ntl_and_log(action) {
            return BaseActionOutcome::Error {
                status: error.status(),
                error,
            };
        }
    }

    BaseActionOutcome::Success
}
