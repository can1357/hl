//! VoteGlobal action handler (`0x23E8640`).
//!
//! The user-visible `VoteGlobal` action is a vote-submission wrapper around the
//! much larger `VoteGlobalAction` governance enum.  The outer handler does not
//! always execute the nested action immediately:
//! - it first records / updates vote-tracker state for the submitted wrapper;
//! - only the finalize-now path materializes an inner `VoteGlobalAction` and
//!   forwards it into `l1_action_vote_global__apply_to_exchange_state`;
//! - accepted-but-not-finalized votes return success without mutating exchange
//!   state beyond the vote tracker.
//!
//! Grounding:
//! - wrapper: `sub_23E8640`
//! - outer vote resolution: `sub_2704D90 -> sub_2329990`
//! - inner apply: `l1_action_vote_global__apply_to_exchange_state`

use crate::l1::action::vote_global::{recovered_variant_string, VoteGlobalAction};

pub type Address = [u8; 20];

pub const STATUS_SUCCESS: u16 = 390;
pub const STATUS_MISSING_OR_REJECTED_TRACKER_ENTRY: u16 = 145;

/// Internal sentinel tag used by the outer vote-resolution pipeline to mean
/// "vote recorded / updated, but there is no executable nested action yet".
pub const PENDING_ONLY_SENTINEL_TAG: u64 = 116;

/// The outer `VoteGlobal` payload.
///
/// Protocol notes at `protocol/l1_action_payloads.md` recover six wrapper
/// families.  Only five of them carry a nested `VoteGlobalAction`; `Direct`
/// stores a plain scalar vote value at payload `+0x08`.
#[derive(Clone, Debug, PartialEq)]
pub enum VoteGlobalPayload {
    /// Case 0 (`D`): scalar vote, no nested governance action.
    Direct { value: u32 },
    /// Case 1 (`Q`): bool flag + nested action starting at payload `+0x09`.
    Quorum { flag: bool, action: VoteGlobalAction },
    /// Case 2 (`C`): nested action at payload `+0x18`.
    Consensus { action: VoteGlobalAction },
    /// Case 3 (`P`): nested action + approval bit.
    Proposal { action: VoteGlobalAction, approved: bool },
    /// Case 4 (`A`): nested action + approval bit.
    Approval { action: VoteGlobalAction, approved: bool },
    /// Case 5 (`G`): nested action + approval bit.
    Governance { action: VoteGlobalAction, approved: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoteFinalizeMode {
    /// Handler returned `390` with the result byte clear: vote tracker changed,
    /// but no nested governance action executed.
    RecordedOnly,
    /// Handler returned `390` with the result byte set: the nested
    /// `VoteGlobalAction` was materialized and applied immediately.
    AppliedNow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VoteGlobalError {
    Status(u16),
}

#[derive(Clone, Debug, PartialEq)]
pub struct VoteGlobalOutcome {
    pub finalize_mode: VoteFinalizeMode,
    pub applied_variant: Option<&'static str>,
}

/// Signer / caller facts threaded through the outer vote resolver.
///
/// In the binary these arrive via the `a3` record plus exchange-side mode bytes.
/// The wrapper threads them through the tracker before deciding whether the
/// current submission finalizes a pending vote.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VoteGlobalSignerContext {
    pub signer: Address,
    /// Exchange mode byte read from `exchange + 2290`; mode `3` selects the
    /// alternate tracker tables used by the binary.
    pub caller_mode: u8,
}

/// A small amount of outer-wrapper branching depends on the raw inner
/// `VoteGlobalAction` tag, not just the typed variant, because the binary uses
/// two materializer helpers:
/// - `sub_1EAC160` for the general case
/// - `sub_1EABF10` for a small family of vector-owning / custom-drop layouts
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaterializedVoteGlobalAction<'a> {
    pub raw_tag: u64,
    pub action: &'a VoteGlobalAction,
    /// For raw tag `0x5c` (`SetLiquidQuoteTokens`) the special helper is only
    /// selected when the boolean payload byte at `+8` is set.
    pub payload_byte_8: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoteMaterializerKind {
    General,
    SpecialOwnedLayout,
}

impl<'a> MaterializedVoteGlobalAction<'a> {
    /// Exact helper split recovered from `sub_2704D90`.
    #[inline]
    pub fn materializer_kind(self) -> VoteMaterializerKind {
        match self.raw_tag {
            0x1d | 0x32 | 0x67 => VoteMaterializerKind::SpecialOwnedLayout,
            0x5c if self.payload_byte_8 == 1 => VoteMaterializerKind::SpecialOwnedLayout,
            _ => VoteMaterializerKind::General,
        }
    }
}

/// Outer vote-tracker contract recovered from `sub_2329990`.
///
/// The binary keeps per-mode tracker tables, merges repeat votes into existing
/// buckets when possible, and only hands an executable `VoteGlobalAction` back
/// to the wrapper once the submitted vote crosses that wrapper's threshold.
pub trait VoteGlobalRuntime {
    /// Record or update the outer vote.  Returning `Some(..)` means the vote
    /// finalized and the nested action should execute now.  Returning `None`
    /// means the submission was accepted but only updated tracker state.
    fn resolve_nested_vote(
        &mut self,
        signer: VoteGlobalSignerContext,
        payload: &VoteGlobalPayload,
    ) -> Result<Option<MaterializedVoteGlobalAction<'_>>, VoteGlobalError>;

    /// Execute the inner governance action once the outer vote resolves to a
    /// concrete action.
    fn apply_vote_global_action(
        &mut self,
        signer: VoteGlobalSignerContext,
        action: MaterializedVoteGlobalAction<'_>,
    ) -> Result<(), VoteGlobalError>;
}

/// Reconstructed wrapper flow for `l1_exchange_impl_execute_action__vote_global`.
///
/// Observed control flow:
/// 1. Canonicalize / clone the nested payload into scratch storage.
/// 2. Run the outer vote-tracker resolver (`sub_2704D90 -> sub_2329990`).
/// 3. If the resolver returns the internal `116` sentinel, return `390` with the
///    apply byte clear: the vote was accepted but nothing reached execution.
/// 4. Otherwise rebuild the concrete `VoteGlobalAction` and call the inner
///    governance apply helper.
/// 5. Bubble any non-`390` status as a generic action error envelope.
#[inline]
pub fn apply_vote_global<R: VoteGlobalRuntime>(
    runtime: &mut R,
    signer: VoteGlobalSignerContext,
    payload: &VoteGlobalPayload,
) -> Result<VoteGlobalOutcome, VoteGlobalError> {
    let Some(materialized) = runtime.resolve_nested_vote(signer, payload)? else {
        return Ok(VoteGlobalOutcome {
            finalize_mode: VoteFinalizeMode::RecordedOnly,
            applied_variant: None,
        });
    };

    runtime.apply_vote_global_action(signer, materialized)?;
    Ok(VoteGlobalOutcome {
        finalize_mode: VoteFinalizeMode::AppliedNow,
        applied_variant: Some(recovered_variant_string(materialized.action)),
    })
}

/// Helper for callers that only need the nested action carried by a wrapper,
/// independent of tracker/quorum rules.
#[inline]
pub fn nested_action(payload: &VoteGlobalPayload) -> Option<&VoteGlobalAction> {
    match payload {
        VoteGlobalPayload::Direct { .. } => None,
        VoteGlobalPayload::Quorum { action, .. }
        | VoteGlobalPayload::Consensus { action }
        | VoteGlobalPayload::Proposal { action, .. }
        | VoteGlobalPayload::Approval { action, .. }
        | VoteGlobalPayload::Governance { action, .. } => Some(action),
    }
}
