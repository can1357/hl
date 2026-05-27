//! RegisterReferrer action handler.
//!
//! Reconstructed from `sub_27E30A0` (EA `0x27E30A0`) and its shared helper
//! `sub_3744EB0`.
//!
//! The action lets an eligible user publish a referral code. The helper maintains
//! two synchronized indexes:
//! - `referrer_by_address`: owner address -> referrer profile
//! - `address_by_code`: referral code -> owner address

use std::collections::{BTreeMap, HashMap};

/// 20-byte user identifier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Address(pub [u8; 20]);

/// Action payload deserialized from `{"registerReferrer": {"code": ... }}`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterReferrerAction {
    pub code: String,
}

/// Per-user state consulted by the registration helper.
///
/// The helper first proves that the submitting address already has an exchange
/// user record, then walks a nested collection inside that record and sums a raw
/// quantity across all buckets/leaves. Registration requires that total to reach
/// at least `1_000_000` raw units.
#[derive(Clone, Debug, Default)]
pub struct UserEligibilityState {
    pub eligibility_total_raw: u64,
}

/// Referrer profile keyed by owner address.
///
/// The binary stores the code plus two zero-initialized 128-bit fields and one
/// trailing `u64` configuration slot. Only the code and trailing slot are used by
/// the `RegisterReferrer` path; the two 128-bit fields appear to be mutable stats
/// maintained elsewhere.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReferrerProfile {
    pub code: String,
    pub stats_0: u128,
    pub stats_1: u128,
    pub n_per_bucket: u64,
}

/// Referrer subsystem slice inside exchange state.
#[derive(Clone, Debug, Default)]
pub struct ReferrerRegistry {
    /// Secondary uniqueness index: code -> owner.
    pub address_by_code: BTreeMap<Vec<u8>, Address>,
    /// Primary profile table: owner -> referrer profile.
    pub referrer_by_address: BTreeMap<Address, ReferrerProfile>,
    /// Exchange users, used for the eligibility gate.
    pub users: HashMap<Address, UserEligibilityState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegisterReferrerError {
    /// Wrapper-level payload validation (`len(code) > 100`).
    CodeTooLong { limit: usize, actual: usize, status: u16 },
    /// Helper-level code-length guard. Unreachable through the user wrapper but
    /// preserved because the shared helper enforces it too.
    CodeTooLongInHelper,
    /// Another referrer already owns this code.
    DuplicateCode,
    /// This address already has a registered referrer profile.
    AlreadyRegistered,
    /// The address is missing user state or its accumulated eligibility metric is
    /// below the raw threshold required to become a referrer.
    NotEligible,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegisterReferrerResult {
    Registered,
    Rejected(RegisterReferrerError),
}

pub const MAX_REFERRER_CODE_LEN: usize = 100;
pub const MIN_REFERRER_ELIGIBILITY_RAW: u64 = 1_000_000;

impl ReferrerRegistry {
    /// Reconstructed `RegisterReferrer` flow.
    ///
    /// Wrapper (`0x27E30A0`):
    /// 1. Reject `code.len() > 100` with status `323`.
    /// 2. Call the shared referrer helper.
    /// 3. Treat helper status `390` as success; otherwise bubble the helper error.
    ///
    /// Shared helper (`0x3744EB0`, user path `a7 = 0`):
    /// 1. Look up the submitting address in exchange user state.
    /// 2. Sum an eligibility metric across nested per-user buckets.
    /// 3. Require `eligibility_total_raw >= 1_000_000`.
    /// 4. Reject duplicate owner addresses in `referrer_by_address`.
    /// 5. Reject duplicate codes in `address_by_code`.
    /// 6. Insert the new address profile with zeroed stats and `n_per_bucket = 0`.
    /// 7. Insert the reverse code -> owner index.
    pub fn register_referrer(
        &mut self,
        user: Address,
        action: &RegisterReferrerAction,
    ) -> RegisterReferrerResult {
        let code = action.code.as_bytes();
        if code.len() > MAX_REFERRER_CODE_LEN {
            return RegisterReferrerResult::Rejected(RegisterReferrerError::CodeTooLong {
                limit: MAX_REFERRER_CODE_LEN,
                actual: code.len(),
                status: 323,
            });
        }

        let Some(user_state) = self.users.get(&user) else {
            return RegisterReferrerResult::Rejected(RegisterReferrerError::NotEligible);
        };

        if user_state.eligibility_total_raw < MIN_REFERRER_ELIGIBILITY_RAW {
            return RegisterReferrerResult::Rejected(RegisterReferrerError::NotEligible);
        }

        if self.referrer_by_address.contains_key(&user) {
            return RegisterReferrerResult::Rejected(RegisterReferrerError::AlreadyRegistered);
        }

        if self.address_by_code.contains_key(code) {
            return RegisterReferrerResult::Rejected(RegisterReferrerError::DuplicateCode);
        }

        self.referrer_by_address.insert(
            user,
            ReferrerProfile {
                code: action.code.clone(),
                stats_0: 0,
                stats_1: 0,
                n_per_bucket: 0,
            },
        );
        self.address_by_code.insert(code.to_vec(), user);

        RegisterReferrerResult::Registered
    }
}

/// Raw status values returned by the helper at `0x3744EB0`.
///
/// These are useful when matching this action against the binary's generic error
/// envelope.
pub mod status {
    pub const APPLIED: u16 = 390;
    pub const CODE_TOO_LONG: u16 = 160;
    pub const DUPLICATE_CODE: u16 = 163;
    pub const ALREADY_REGISTERED: u16 = 164;
    pub const NOT_ELIGIBLE: u16 = 165;
    pub const WRAPPER_CODE_TOO_LONG: u16 = 323;
}
