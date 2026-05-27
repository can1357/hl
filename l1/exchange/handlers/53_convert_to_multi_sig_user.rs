#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type Nonce = u64;

pub const STATUS_OK: u16 = 390;
pub const STATUS_SIGNERS_JSON_PARSE_FAILED: u16 = 189;
pub const STATUS_SIGNERS_JSON_TOO_LONG: u16 = 323;
pub const STATUS_INVALID_THRESHOLD: u16 = 275;
pub const STATUS_TOO_MANY_SIGNERS: u16 = 279;
pub const STATUS_INVALID_USER_TO_CONVERT: u16 = 280;
pub const STATUS_INVALID_AUTHORIZED_USER: u16 = 282;
pub const STATUS_AUTHORIZED_USER_CANNOT_BE_VAULT_OR_SUBACCOUNT: u16 = 283;
pub const STATUS_CANNOT_REGISTER_SELF_AS_AUTHORIZED_USER: u16 = 284;

pub const MAX_SIGNERS_JSON_BYTES: usize = 1_000;
pub const MAX_AUTHORIZED_USERS: usize = 10;

/// Wire action routed to `sub_1E64010`.
///
/// Grounded layout:
/// - `nonce` is carried by the signed outer action and is consumed by the generic
///   exchange nonce gate before this handler runs.
/// - the payload itself is a single string field (`signers`) whose JSON content is
///   parsed by `sub_1B2C1C0` before the core helper executes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConvertToMultiSigUserAction {
    pub user: Address,
    pub nonce: Nonce,
    pub signers_json: String,
}

/// Parsed form of the `signers` JSON string.
///
/// `MultiSigSigners` is grounded by the info-server ABI (`userToMultiSigSigners`)
/// and the field-name strings referenced by the parser (`authorizedUsers`,
/// `threshold`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiSigSigners {
    pub authorized_users: Vec<Address>,
    pub threshold: u32,
}

/// [INFERENCE] The parser distinguishes between a present `authorizedUsers` list
/// and an omitted/null one. The core helper has a dedicated branch for the absent
/// case that removes the caller's existing multisig configuration instead of
/// installing a new one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedSignersPayload {
    Replace(MultiSigSigners),
    ClearExistingConfig,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConvertToMultiSigUserState {
    /// The caller and every authorized user must already resolve as a real user.
    /// The binary checks two internal user indexes before accepting an address.
    pub valid_users: BTreeSet<Address>,
    /// Additional role indexes consulted during authorized-user validation.
    /// Any hit here is rejected with status `283`.
    pub vaults_and_subaccounts: BTreeSet<Address>,
    /// Grounded by the info-server route name `userToMultiSigSigners`.
    pub user_to_multi_sig_signers: BTreeMap<Address, MultiSigSigners>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandlerError {
    pub status: u16,
    /// [INFERENCE] The binary copies structured payload data into the outer error
    /// variant for parse failures and per-signer validation failures. The exact
    /// wire shape is not yet reconstructed, but the offending address is the
    /// semantically important part of those branches.
    pub offender: Option<Address>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConvertToMultiSigUserResult {
    Applied,
    Rejected(HandlerError),
}

#[inline]
pub fn validate_signers_json_len(action: &ConvertToMultiSigUserAction) -> Result<(), HandlerError> {
    if action.signers_json.len() > MAX_SIGNERS_JSON_BYTES {
        return Err(HandlerError {
            status: STATUS_SIGNERS_JSON_TOO_LONG,
            offender: None,
        });
    }
    Ok(())
}

/// Wrapper-level reconstruction of `sub_1E64010`.
///
/// Observed order:
/// 1. Reject `signers.len() > 1000` with status `323` and the original string.
/// 2. Parse the JSON string with `sub_1B2C1C0`; parse/trailing-junk failures map
///    to status `189`.
/// 3. Forward the parsed payload plus outer signer into `sub_27693D0`.
#[inline]
pub fn apply_convert_to_multi_sig_user(
    state: &mut ConvertToMultiSigUserState,
    action: &ConvertToMultiSigUserAction,
    parsed: ParsedSignersPayload,
) -> ConvertToMultiSigUserResult {
    if let Err(error) = validate_signers_json_len(action) {
        return ConvertToMultiSigUserResult::Rejected(error);
    }

    match apply_parsed_convert_to_multi_sig_user(state, action.user, parsed) {
        Ok(()) => ConvertToMultiSigUserResult::Applied,
        Err(error) => ConvertToMultiSigUserResult::Rejected(error),
    }
}

#[inline]
pub fn apply_parsed_convert_to_multi_sig_user(
    state: &mut ConvertToMultiSigUserState,
    user: Address,
    parsed: ParsedSignersPayload,
) -> Result<(), HandlerError> {
    if !state.valid_users.contains(&user) {
        return Err(HandlerError {
            status: STATUS_INVALID_USER_TO_CONVERT,
            offender: Some(user),
        });
    }

    match parsed {
        ParsedSignersPayload::ClearExistingConfig => {
            if state.user_to_multi_sig_signers.remove(&user).is_some() {
                Ok(())
            } else {
                Err(HandlerError {
                    status: STATUS_INVALID_USER_TO_CONVERT,
                    offender: Some(user),
                })
            }
        }
        ParsedSignersPayload::Replace(signers) => install_multi_sig_signers(state, user, signers),
    }
}

fn install_multi_sig_signers(
    state: &mut ConvertToMultiSigUserState,
    user: Address,
    signers: MultiSigSigners,
) -> Result<(), HandlerError> {
    let signer_count = signers.authorized_users.len();
    let threshold = signers.threshold as usize;

    if threshold == 0 || threshold > signer_count {
        return Err(HandlerError {
            status: STATUS_INVALID_THRESHOLD,
            offender: None,
        });
    }

    if signer_count > MAX_AUTHORIZED_USERS {
        return Err(HandlerError {
            status: STATUS_TOO_MANY_SIGNERS,
            offender: None,
        });
    }

    for authorized_user in &signers.authorized_users {
        if !state.valid_users.contains(authorized_user) {
            return Err(HandlerError {
                status: STATUS_INVALID_AUTHORIZED_USER,
                offender: Some(*authorized_user),
            });
        }

        if state.vaults_and_subaccounts.contains(authorized_user) {
            return Err(HandlerError {
                status: STATUS_AUTHORIZED_USER_CANNOT_BE_VAULT_OR_SUBACCOUNT,
                offender: Some(*authorized_user),
            });
        }

        if *authorized_user == user {
            return Err(HandlerError {
                status: STATUS_CANNOT_REGISTER_SELF_AS_AUTHORIZED_USER,
                offender: Some(*authorized_user),
            });
        }
    }

    state.user_to_multi_sig_signers.insert(user, signers);
    Ok(())
}
