#![allow(dead_code)]

use std::collections::BTreeMap;

pub type Address = [u8; 20];
pub type ProposalId = [u8; 32];

pub const WRAPPER_EA: u64 = 0x1F64_980;
pub const APPLY_EA: u64 = 0x398D_1A0;
pub const STAKING_SUMMARY_TOTAL_EA: u64 = 0x3C0F_050;
pub const STAKING_SUMMARY_CHECKPOINT_EA: u64 = 0x3C0F_350;
pub const PROPOSAL_VOTE_UPSERT_EA: u64 = 0x33A5_470;

pub const STATUS_SUCCESS: u16 = 390;
pub const STATUS_RESTRICTED_CALLER_MODE: u16 = 141;
pub const STATUS_GOV_PROPOSAL_DOES_NOT_EXIST: u16 = 261;
pub const STATUS_GOV_ALREADY_VOTED: u16 = 262;
pub const STATUS_GOV_VOTE_INSUFFICIENT_STAKE: u16 = 263;
pub const STATUS_GOV_VOTE_ENDED: u16 = 264;

/// Canonicalized apply-time payload for `govVote`.
///
/// The signed outer action still carries a generic signer nonce, but this handler
/// never reads it directly; the shared nonce gate in `impl_execute_action.rs`
/// runs before the 76-arm action dispatch reaches `sub_1F64980`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GovVoteAction {
    pub proposal_id: ProposalId,
    pub choice: bool,
    pub nonce: u64,
}

/// Proposal expiry cursor copied out of the proposal record and compared against
/// the block / execution cursor passed in `a4 + 96` / `a4 + 104`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct GovernanceCursor {
    pub major: u64,
    pub minor: u32,
    pub patch: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProposalVote {
    pub effective_stake: u64,
    pub choice: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovProposal {
    pub voting_ends_at: GovernanceCursor,
    pub votes_by_user: BTreeMap<Address, ProposalVote>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovVoteError {
    RestrictedCallerMode,
    ProposalDoesNotExist,
    AlreadyVoted,
    InsufficientStake,
    VoteEnded,
}

impl GovVoteError {
    #[inline]
    pub const fn code(self) -> u16 {
        match self {
            Self::RestrictedCallerMode => STATUS_RESTRICTED_CALLER_MODE,
            Self::ProposalDoesNotExist => STATUS_GOV_PROPOSAL_DOES_NOT_EXIST,
            Self::AlreadyVoted => STATUS_GOV_ALREADY_VOTED,
            Self::InsufficientStake => STATUS_GOV_VOTE_INSUFFICIENT_STAKE,
            Self::VoteEnded => STATUS_GOV_VOTE_ENDED,
        }
    }
}

/// Exchange hooks that stay opaque in the binary but are small and well-bounded
/// from the handler's point of view.
///
/// Grounded observations from `0x398D1A0`:
/// - the proposal table is keyed by the 32-byte proposal id;
/// - each proposal carries a 12-byte end cursor checked before any stake lookup;
/// - duplicate votes are rejected before the vote record is inserted;
/// - stake comes from the staking/delegation summary rooted at `gov_state + 45`;
/// - the same staking summary receives a high-water-mark update for the proposal
///   cursor before the vote is stored;
/// - a second per-user table at `gov_state + 63` may rewrite the effective stake
///   that is finally stored alongside the user's boolean choice.
pub trait GovVoteRuntime {
    fn caller_mode(&self) -> u8;
    fn current_cursor(&self) -> GovernanceCursor;
    fn proposal_mut(&mut self, id: &ProposalId) -> Option<&mut GovProposal>;

    /// Recover the effective voting stake exactly as the handler uses it for a
    /// specific proposal deadline. Returning `None` or `Some(0)` rejects the vote
    /// with `GovVoteInsufficientStake`.
    fn effective_vote_stake(
        &mut self,
        voter: &Address,
        proposal_deadline: GovernanceCursor,
    ) -> Option<u64>;
}

/// Reconstructed `govVote` apply path from `sub_1F64980 -> sub_398D1A0`.
///
/// Exact branch order:
/// 1. Reject exchange caller mode `3` with status `141`.
/// 2. Look up the proposal by its 32-byte id; missing proposal => `261`.
/// 3. Compare the current execution cursor against the proposal's stored end
///    cursor; strictly later execution => `264`.
/// 4. Reject repeat votes from the same 20-byte user key with `262`.
/// 5. Ask the staking summary for the user's effective vote stake at that
///    proposal cursor; zero / missing stake => `263`.
/// 6. Insert `user -> { stake, choice }` into the proposal-local vote table.
#[inline]
pub fn apply_gov_vote<R: GovVoteRuntime>(
    runtime: &mut R,
    voter: Address,
    action: &GovVoteAction,
) -> Result<ProposalVote, GovVoteError> {
    if runtime.caller_mode() == 3 {
        return Err(GovVoteError::RestrictedCallerMode);
    }

    let current_cursor = runtime.current_cursor();
    let proposal_deadline = {
        let proposal = runtime
            .proposal_mut(&action.proposal_id)
            .ok_or(GovVoteError::ProposalDoesNotExist)?;

        if current_cursor > proposal.voting_ends_at {
            return Err(GovVoteError::VoteEnded);
        }
        if proposal.votes_by_user.contains_key(&voter) {
            return Err(GovVoteError::AlreadyVoted);
        }

        proposal.voting_ends_at
    };

    let effective_stake = runtime
        .effective_vote_stake(&voter, proposal_deadline)
        .filter(|stake| *stake != 0)
        .ok_or(GovVoteError::InsufficientStake)?;

    let vote = ProposalVote {
        effective_stake,
        choice: action.choice,
    };
    runtime
        .proposal_mut(&action.proposal_id)
        .expect("proposal existence was checked above")
        .votes_by_user
        .insert(voter, vote);
    Ok(vote)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MockRuntime {
        caller_mode: u8,
        current_cursor: GovernanceCursor,
        proposals: BTreeMap<ProposalId, GovProposal>,
        stakes: BTreeMap<Address, u64>,
        checkpoint_calls: Vec<(Address, GovernanceCursor)>,
    }

    impl GovVoteRuntime for MockRuntime {
        fn caller_mode(&self) -> u8 {
            self.caller_mode
        }

        fn current_cursor(&self) -> GovernanceCursor {
            self.current_cursor
        }

        fn proposal_mut(&mut self, id: &ProposalId) -> Option<&mut GovProposal> {
            self.proposals.get_mut(id)
        }

        fn effective_vote_stake(
            &mut self,
            voter: &Address,
            proposal_deadline: GovernanceCursor,
        ) -> Option<u64> {
            self.checkpoint_calls.push((*voter, proposal_deadline));
            self.stakes.get(voter).copied()
        }
    }

    fn addr(last: u8) -> Address {
        let mut out = [0u8; 20];
        out[19] = last;
        out
    }

    fn proposal_id(last: u8) -> ProposalId {
        let mut out = [0u8; 32];
        out[31] = last;
        out
    }

    fn cursor(major: u64, minor: u32, patch: u32) -> GovernanceCursor {
        GovernanceCursor { major, minor, patch }
    }

    fn action(id: ProposalId, choice: bool) -> GovVoteAction {
        GovVoteAction {
            proposal_id: id,
            choice,
            nonce: 123,
        }
    }

    #[test]
    fn mode_three_is_rejected_before_any_lookup() {
        let mut runtime = MockRuntime {
            caller_mode: 3,
            ..Default::default()
        };

        assert_eq!(
            apply_gov_vote(&mut runtime, addr(1), &action(proposal_id(7), true)),
            Err(GovVoteError::RestrictedCallerMode)
        );
        assert!(runtime.checkpoint_calls.is_empty());
    }

    #[test]
    fn missing_proposal_returns_does_not_exist() {
        let mut runtime = MockRuntime::default();

        assert_eq!(
            apply_gov_vote(&mut runtime, addr(1), &action(proposal_id(7), true)),
            Err(GovVoteError::ProposalDoesNotExist)
        );
    }

    #[test]
    fn later_cursor_means_voting_has_ended() {
        let id = proposal_id(7);
        let mut runtime = MockRuntime {
            current_cursor: cursor(10, 0, 1),
            proposals: BTreeMap::from([(
                id,
                GovProposal {
                    voting_ends_at: cursor(10, 0, 0),
                    votes_by_user: BTreeMap::new(),
                },
            )]),
            ..Default::default()
        };

        assert_eq!(
            apply_gov_vote(&mut runtime, addr(1), &action(id, true)),
            Err(GovVoteError::VoteEnded)
        );
        assert!(runtime.checkpoint_calls.is_empty());
    }

    #[test]
    fn duplicate_vote_is_rejected_before_stake_lookup() {
        let id = proposal_id(7);
        let voter = addr(1);
        let mut runtime = MockRuntime {
            proposals: BTreeMap::from([(
                id,
                GovProposal {
                    voting_ends_at: cursor(10, 0, 0),
                    votes_by_user: BTreeMap::from([(
                        voter,
                        ProposalVote {
                            effective_stake: 50,
                            choice: false,
                        },
                    )]),
                },
            )]),
            ..Default::default()
        };

        assert_eq!(
            apply_gov_vote(&mut runtime, voter, &action(id, true)),
            Err(GovVoteError::AlreadyVoted)
        );
        assert!(runtime.checkpoint_calls.is_empty());
    }

    #[test]
    fn zero_or_missing_stake_is_rejected() {
        let id = proposal_id(7);
        let voter = addr(1);
        let mut runtime = MockRuntime {
            proposals: BTreeMap::from([(
                id,
                GovProposal {
                    voting_ends_at: cursor(10, 0, 0),
                    votes_by_user: BTreeMap::new(),
                },
            )]),
            stakes: BTreeMap::from([(voter, 0)]),
            ..Default::default()
        };

        assert_eq!(
            apply_gov_vote(&mut runtime, voter, &action(id, true)),
            Err(GovVoteError::InsufficientStake)
        );
        assert_eq!(runtime.checkpoint_calls, vec![(voter, cursor(10, 0, 0))]);
    }

    #[test]
    fn successful_vote_records_weight_and_choice() {
        let id = proposal_id(7);
        let voter = addr(1);
        let mut runtime = MockRuntime {
            proposals: BTreeMap::from([(
                id,
                GovProposal {
                    voting_ends_at: cursor(10, 0, 0),
                    votes_by_user: BTreeMap::new(),
                },
            )]),
            stakes: BTreeMap::from([(voter, 75)]),
            ..Default::default()
        };

        assert_eq!(
            apply_gov_vote(&mut runtime, voter, &action(id, true)),
            Ok(ProposalVote {
                effective_stake: 75,
                choice: true,
            })
        );
        assert_eq!(runtime.checkpoint_calls, vec![(voter, cursor(10, 0, 0))]);
        assert_eq!(
            runtime
                .proposals
                .get(&id)
                .unwrap()
                .votes_by_user
                .get(&voter),
            Some(&ProposalVote {
                effective_stake: 75,
                choice: true,
            })
        );
    }
}
