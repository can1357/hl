#![allow(dead_code)]

use std::collections::BTreeMap;

pub type Address = [u8; 20];
pub type ProposalDigest = [u8; 32];
pub type UnixSeconds = u64;
pub type VotingWeight = u64;

pub const STATUS_OK: u16 = 390;
pub const STATUS_MODE_3_FORBIDDEN: u16 = 141;
pub const STATUS_STAKING_DISABLED: u16 = 251;
pub const STATUS_STRING_TOO_LONG: u16 = 323;
pub const STATUS_ARITHMETIC_OVERFLOW: u16 = 190;
pub const STATUS_GOV_TITLE_LENGTH: u16 = 256;
pub const STATUS_GOV_DESCRIPTION_LENGTH: u16 = 257;
pub const STATUS_GOV_INSUFFICIENT_STAKE: u16 = 258;
pub const STATUS_GOV_PROPOSAL_ALREADY_EXISTS: u16 = 259;
pub const STATUS_GOV_PROPOSAL_USER_LIMIT: u16 = 260;

/// The wrapper rejects title staging lengths above 100 bytes before it enters the
/// shared governance insert helper.
pub const MAX_STAGED_TITLE_BYTES: usize = 100;
/// The shared helper still enforces the stricter governance title limit.
pub const MAX_GOV_TITLE_BYTES: usize = 50;
pub const MAX_DESCRIPTION_BYTES: usize = 1_000;
pub const MIN_PROPOSER_WEIGHT: VotingWeight = 1_000_000_000;
/// The insert helper rejects only once the caller already has more than two live
/// proposals, so the third live proposal is still accepted and the fourth is not.
pub const MAX_EXISTING_PROPOSALS_BEFORE_REJECT: usize = 2;

/// Recovered non-mainnet/test modes (`chain_mode` 1 or 2) use very short voting
/// windows.
pub const TEST_SHORT_PROPOSAL_TTL_SECS: UnixSeconds = 120;
pub const TEST_LONG_PROPOSAL_TTL_SECS: UnixSeconds = 300;
pub const PROD_SHORT_PROPOSAL_TTL_SECS: UnixSeconds = 86_400;
pub const PROD_LONG_PROPOSAL_TTL_SECS: UnixSeconds = 518_400;
pub const SHORT_PROPOSAL_QUORUM_RATE: f64 = 0.05;
pub const LONG_PROPOSAL_QUORUM_RATE: f64 = 0.10;

/// `GovPropose` payload (`sub_1F68BE0`, payload tag `49`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovProposeAction {
    pub title: String,
    pub description: String,
    pub signature_chain_idents: SignatureChainIdents,
    pub hyperliquid_chain: HyperliquidChain,
    /// [INFERENCE] Payload byte `+0x59`; zero selects the short/5% path and any
    /// non-zero value selects the long/10% path.
    pub long_proposal: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SignatureChainIdents {
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HyperliquidChain {
    pub raw: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ProposerIdentity {
    pub address: Address,
    /// [INFERENCE] The handler carries the 20-byte signer plus one trailing `u32`
    /// through the proposal-weight and duplicate-count tables.
    pub profile_hint: u32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProposalStakeComponent {
    /// [INFERENCE] Each prepared component is a 32-byte record assembled by
    /// `sub_375E4C0`: signer-ish key material, one `u32` discriminator, and one
    /// `u64` voting weight.
    pub voter: Address,
    pub profile_hint: u32,
    pub voting_weight: VotingWeight,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PreparedProposalStake {
    pub components: Vec<ProposalStakeComponent>,
    /// Effective proposer weight snapshot forwarded into the insert helper.
    pub effective_weight: VotingWeight,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedGovProposal {
    pub proposal_digest: ProposalDigest,
    pub proposer: ProposerIdentity,
    pub title: String,
    pub description: String,
    pub signature_chain_idents: SignatureChainIdents,
    pub hyperliquid_chain: HyperliquidChain,
    pub long_proposal: bool,
    pub prepared_stake: PreparedProposalStake,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveGovProposal {
    pub proposal_digest: ProposalDigest,
    pub proposer: ProposerIdentity,
    pub title: String,
    pub description: String,
    pub signature_chain_idents: SignatureChainIdents,
    pub hyperliquid_chain: HyperliquidChain,
    pub long_proposal: bool,
    pub created_at: UnixSeconds,
    pub expires_at: UnixSeconds,
    pub required_yes_votes: VotingWeight,
    pub effective_weight: VotingWeight,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExchangeState {
    /// Byte read from `exchange + 2290`; the handler rejects mode `3` up front.
    pub chain_mode: u8,
    /// `a4[8].0 != 0` in the wrapper.
    pub staking_enabled: bool,
    /// [INFERENCE] The live helper at `sub_3C0F050(exchange+2648, proposer)` returns
    /// the proposer weight consulted by the governance insert helper.
    pub proposer_weight_by_user: BTreeMap<ProposerIdentity, VotingWeight>,
    /// Proposal table rooted at `exchange + 2696`.
    pub active_proposals: BTreeMap<ProposalDigest, ActiveGovProposal>,
    pub now_unix_seconds: UnixSeconds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GovProposeContext {
    pub proposer: ProposerIdentity,
    pub proposal_digest: ProposalDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovProposeError {
    Mode3Forbidden,
    StakingDisabled,
    StringTooLong,
    ArithmeticOverflow,
    GovTitleLength,
    GovDescriptionLength,
    GovInsufficientStake,
    GovProposalAlreadyExists,
    GovProposalUserLimit,
}

impl GovProposeError {
    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::Mode3Forbidden => STATUS_MODE_3_FORBIDDEN,
            Self::StakingDisabled => STATUS_STAKING_DISABLED,
            Self::StringTooLong => STATUS_STRING_TOO_LONG,
            Self::ArithmeticOverflow => STATUS_ARITHMETIC_OVERFLOW,
            Self::GovTitleLength => STATUS_GOV_TITLE_LENGTH,
            Self::GovDescriptionLength => STATUS_GOV_DESCRIPTION_LENGTH,
            Self::GovInsufficientStake => STATUS_GOV_INSUFFICIENT_STAKE,
            Self::GovProposalAlreadyExists => STATUS_GOV_PROPOSAL_ALREADY_EXISTS,
            Self::GovProposalUserLimit => STATUS_GOV_PROPOSAL_USER_LIMIT,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GovProposeOutcome {
    pub status: u16,
    pub proposal_digest: ProposalDigest,
}

impl GovProposeOutcome {
    #[inline]
    pub const fn ok(proposal_digest: ProposalDigest) -> Self {
        Self {
            status: STATUS_OK,
            proposal_digest,
        }
    }

    #[inline]
    pub const fn err(error: GovProposeError) -> Self {
        Self {
            status: error.status(),
            proposal_digest: [0; 32],
        }
    }
}

/// Reconstructed `GovPropose` flow from `sub_1F68BE0` + `sub_375E4C0` + `sub_398D540`.
///
/// Exact ordering recovered from the wrapper:
/// 1. Reject chain mode `3` with `141`.
/// 2. Require the staking/governance feature bit, else `251`.
/// 3. Build the canonical proposal digest and precompute proposer stake context via
///    `sub_375E4C0`; overflow in that stage returns `190`.
/// 4. Clone `title` / `description` into owned scratch buffers and reject wrapper
///    sizes `title.len() > 100` or `description.len() > 1000` with `323`.
/// 5. Run the shared governance insert helper:
///    - title length `<= 50` (`256` otherwise),
///    - description length `<= 1000` (`257` otherwise),
///    - proposer effective weight `>= 1e9` (`258` otherwise),
///    - proposal digest uniqueness (`259`),
///    - no more than three simultaneous live proposals for the same proposer (`260`).
/// 6. Compute expiry + quorum requirement from `long_proposal`, insert the live
///    proposal row, and return success together with the 32-byte proposal digest.
#[inline]
pub fn apply_gov_propose(
    exchange: &mut ExchangeState,
    context: GovProposeContext,
    action: &GovProposeAction,
    prepared_stake: PreparedProposalStake,
) -> GovProposeOutcome {
    match prepare_gov_propose(exchange, context, action, prepared_stake)
        .and_then(|prepared| commit_gov_propose(exchange, prepared))
    {
        Ok(proposal_digest) => GovProposeOutcome::ok(proposal_digest),
        Err(error) => GovProposeOutcome::err(error),
    }
}

#[inline]
pub fn prepare_gov_propose(
    exchange: &ExchangeState,
    context: GovProposeContext,
    action: &GovProposeAction,
    prepared_stake: PreparedProposalStake,
) -> Result<PreparedGovProposal, GovProposeError> {
    if exchange.chain_mode == 3 {
        return Err(GovProposeError::Mode3Forbidden);
    }
    if !exchange.staking_enabled {
        return Err(GovProposeError::StakingDisabled);
    }

    let title = clone_bounded(&action.title, MAX_STAGED_TITLE_BYTES)?;
    let description = clone_bounded(&action.description, MAX_DESCRIPTION_BYTES)?;

    Ok(PreparedGovProposal {
        proposal_digest: context.proposal_digest,
        proposer: context.proposer,
        title,
        description,
        signature_chain_idents: action.signature_chain_idents.clone(),
        hyperliquid_chain: action.hyperliquid_chain.clone(),
        long_proposal: action.long_proposal,
        prepared_stake,
    })
}

#[inline]
pub fn commit_gov_propose(
    exchange: &mut ExchangeState,
    prepared: PreparedGovProposal,
) -> Result<ProposalDigest, GovProposeError> {
    if prepared.title.len() > MAX_GOV_TITLE_BYTES {
        return Err(GovProposeError::GovTitleLength);
    }
    if prepared.description.len() > MAX_DESCRIPTION_BYTES {
        return Err(GovProposeError::GovDescriptionLength);
    }

    let proposer_weight = exchange
        .proposer_weight_by_user
        .get(&prepared.proposer)
        .copied()
        .unwrap_or(prepared.prepared_stake.effective_weight);
    if proposer_weight < MIN_PROPOSER_WEIGHT {
        return Err(GovProposeError::GovInsufficientStake);
    }
    if exchange.active_proposals.contains_key(&prepared.proposal_digest) {
        return Err(GovProposeError::GovProposalAlreadyExists);
    }
    if active_proposal_count_for(exchange, prepared.proposer) > MAX_EXISTING_PROPOSALS_BEFORE_REJECT {
        return Err(GovProposeError::GovProposalUserLimit);
    }

    let ttl_secs = proposal_ttl_secs(exchange.chain_mode, prepared.long_proposal);
    let expires_at = exchange
        .now_unix_seconds
        .checked_add(ttl_secs)
        .ok_or(GovProposeError::ArithmeticOverflow)?;
    let required_yes_votes = required_yes_votes(prepared.prepared_stake.effective_weight, prepared.long_proposal);

    exchange.active_proposals.insert(
        prepared.proposal_digest,
        ActiveGovProposal {
            proposal_digest: prepared.proposal_digest,
            proposer: prepared.proposer,
            title: prepared.title,
            description: prepared.description,
            signature_chain_idents: prepared.signature_chain_idents,
            hyperliquid_chain: prepared.hyperliquid_chain,
            long_proposal: prepared.long_proposal,
            created_at: exchange.now_unix_seconds,
            expires_at,
            required_yes_votes,
            effective_weight: prepared.prepared_stake.effective_weight,
        },
    );

    Ok(prepared.proposal_digest)
}

#[inline]
pub fn active_proposal_count_for(exchange: &ExchangeState, proposer: ProposerIdentity) -> usize {
    exchange
        .active_proposals
        .values()
        .filter(|proposal| proposal.proposer == proposer)
        .count()
}

#[inline]
pub fn clone_bounded(value: &str, max_len: usize) -> Result<String, GovProposeError> {
    if value.len() > max_len {
        return Err(GovProposeError::StringTooLong);
    }
    Ok(value.to_owned())
}

#[inline]
pub const fn proposal_ttl_secs(chain_mode: u8, long_proposal: bool) -> UnixSeconds {
    if matches!(chain_mode, 1 | 2) {
        if long_proposal {
            TEST_LONG_PROPOSAL_TTL_SECS
        } else {
            TEST_SHORT_PROPOSAL_TTL_SECS
        }
    } else if long_proposal {
        PROD_LONG_PROPOSAL_TTL_SECS
    } else {
        PROD_SHORT_PROPOSAL_TTL_SECS
    }
}

#[inline]
pub fn required_yes_votes(effective_weight: VotingWeight, long_proposal: bool) -> VotingWeight {
    let rate = if long_proposal {
        LONG_PROPOSAL_QUORUM_RATE
    } else {
        SHORT_PROPOSAL_QUORUM_RATE
    };
    ((effective_weight as f64) * rate).floor() as VotingWeight
}
