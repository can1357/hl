#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type Nonce = u64;

pub const STATUS_OK: u16 = 390;
pub const STATUS_PRECONDITION_FAILED: u16 = 345;
pub const OUTER_OK_TAG: u8 = 13;
pub const OUTER_ERR_TAG: u8 = 14;

pub const ERR_NO_STAKED_HYPE: &str = "Staking user has no staked HYPE";
pub const ERR_SELF_LINK: &str = "Cannot link a staking user to itself";
pub const ERR_ALREADY_LINKED: &str = "Trading user already has a link established";
pub const ERR_STAKING_ALREADY_LINKED: &str = "Staking user already has a link established";
pub const ERR_REQUEST_FIRST: &str = "Trading user must request before staking user";

/// Domain view of the wire payload handled at `0x1E60770`.
///
/// The binary wrapper only reads one explicit address plus `is_finalize`; the
/// other side of the relationship comes from the signed action context:
///
/// - request path (`is_finalize == false`): signer is the trading user and the
///   payload address is the staking user;
/// - finalize path (`is_finalize == true`): signer is the staking user and the
///   payload address is the trading user.
///
/// The generic exchange nonce gate runs before this handler, so `nonce` is part
/// of the semantic action but is not read again here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkStakingUserAction {
    pub staking_user: Address,
    pub trading_user: Address,
    pub nonce: Nonce,
    pub is_finalize: bool,
}

impl LinkStakingUserAction {
    #[inline]
    pub const fn from_wire(signer: Address, payload_user: Address, nonce: Nonce, is_finalize: bool) -> Self {
        if is_finalize {
            Self {
                staking_user: signer,
                trading_user: payload_user,
                nonce,
                is_finalize,
            }
        } else {
            Self {
                staking_user: payload_user,
                trading_user: signer,
                nonce,
                is_finalize,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkRelationship {
    /// Keyed by the trading user before the staking user accepts.
    PendingRequest { staking_user: Address },
    /// Finalized record keyed by the trading user.
    TradingLinked { staking_user: Address },
    /// Finalized mirror record keyed by the staking user.
    StakingLinked { trading_user: Address },
}

impl LinkRelationship {
    #[inline]
    pub const fn is_established(self) -> bool {
        !matches!(self, Self::PendingRequest { .. })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LinkStakingState {
    /// Users that currently satisfy the staking-side prerequisite checked by
    /// `sub_2769FF0`: the staking address must already exist in the staked-HYPE
    /// index before a trading user can request linkage.
    pub staking_users_with_staked_hype: BTreeSet<Address>,
    /// Recovered `BTreeMap<Address, (tag, other_user)>` rooted at exchange
    /// offset `+0x3A18`.
    pub link_by_user: BTreeMap<Address, LinkRelationship>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkStakingUserError {
    pub status: u16,
    pub message: &'static str,
}

impl LinkStakingUserError {
    #[inline]
    pub const fn new(message: &'static str) -> Self {
        Self {
            status: STATUS_PRECONDITION_FAILED,
            message,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkStakingUserResult {
    Applied,
    Rejected(LinkStakingUserError),
}

impl LinkStakingUserResult {
    #[inline]
    pub const fn compact_tag(self) -> u8 {
        match self {
            Self::Applied => OUTER_OK_TAG,
            Self::Rejected(_) => OUTER_ERR_TAG,
        }
    }

    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::Applied => STATUS_OK,
            Self::Rejected(error) => error.status,
        }
    }
}

#[inline]
pub fn apply_link_staking_user(
    state: &mut LinkStakingState,
    action: LinkStakingUserAction,
) -> LinkStakingUserResult {
    if action.is_finalize {
        finalize_link(state, action)
    } else {
        request_link(state, action)
    }
}

fn request_link(
    state: &mut LinkStakingState,
    action: LinkStakingUserAction,
) -> LinkStakingUserResult {
    if !state
        .staking_users_with_staked_hype
        .contains(&action.staking_user)
    {
        return LinkStakingUserResult::Rejected(LinkStakingUserError::new(ERR_NO_STAKED_HYPE));
    }

    if action.staking_user == action.trading_user {
        return LinkStakingUserResult::Rejected(LinkStakingUserError::new(ERR_SELF_LINK));
    }

    if state
        .link_by_user
        .get(&action.trading_user)
        .copied()
        .is_some_and(LinkRelationship::is_established)
    {
        return LinkStakingUserResult::Rejected(LinkStakingUserError::new(ERR_ALREADY_LINKED));
    }

    if state
        .link_by_user
        .get(&action.staking_user)
        .copied()
        .is_some_and(LinkRelationship::is_established)
    {
        return LinkStakingUserResult::Rejected(LinkStakingUserError::new(ERR_STAKING_ALREADY_LINKED));
    }

    state.link_by_user.insert(
        action.trading_user,
        LinkRelationship::PendingRequest {
            staking_user: action.staking_user,
        },
    );

    LinkStakingUserResult::Applied
}

fn finalize_link(
    state: &mut LinkStakingState,
    action: LinkStakingUserAction,
) -> LinkStakingUserResult {
    let Some(LinkRelationship::PendingRequest { staking_user }) = state.link_by_user.get(&action.trading_user).copied() else {
        return LinkStakingUserResult::Rejected(LinkStakingUserError::new(ERR_REQUEST_FIRST));
    };

    if staking_user != action.staking_user {
        return LinkStakingUserResult::Rejected(LinkStakingUserError::new(ERR_REQUEST_FIRST));
    }

    state.link_by_user.insert(
        action.trading_user,
        LinkRelationship::TradingLinked {
            staking_user: action.staking_user,
        },
    );
    state.link_by_user.insert(
        action.staking_user,
        LinkRelationship::StakingLinked {
            trading_user: action.trading_user,
        },
    );

    LinkStakingUserResult::Applied
}
