//! SetReferrer action handler.
//!
//! Reconstructed from `sub_27DE270` (EA `0x27DE270`) and its shared helper
//! `sub_37433C0`, plus the per-referrer side-effect helper `sub_394B7E0`.
//!
//! The handler resolves a referral code to its owning address, rejects
//! self-referrals and duplicate assignments, then tries to consume one slot from
//! the referrer's current referral bucket before marking the user as referred.
//! The binary carries two separate indexes:
//! - `address_by_code`: referral code -> registered referrer owner
//! - `binding_by_user`: user -> chosen referrer binding
//!
//! A third table, `referrer_by_address`, stores the referrer profile used for the
//! bucket/quota side effect. If that profile row is missing, the binary returns
//! success without writing the user binding.

use std::collections::{BTreeMap, HashMap};

/// 20-byte address key used across exchange state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Address(pub [u8; 20]);

/// Action payload deserialized from `{"setReferrer": {"code": ... }}`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetReferrerAction {
    pub code: String,
}

/// Reverse lookup entry stored in the code registry.
///
/// The code tree payload carries the owning referrer address plus one trailing
/// `u32` copied into the per-user binding on success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferrerCodeEntry {
    pub owner: Address,
    pub owner_tag: u32,
}

/// Per-user referrer selection slot stored in the helper's address-keyed hash
/// table. The binary inserts an empty row on first use, then flips `is_set` to 1
/// only after the bucket-side-effect helper succeeds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UserReferrerBinding {
    pub is_set: bool,
    pub referrer: Address,
    pub referrer_tag: u32,
}

/// Attribution recorded against a referrer when a new user claims the code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferredUserLog {
    pub user: Address,
    pub at_ms: u64,
}

/// Referrer profile keyed by owner address.
///
/// `sub_394B7E0` maintains a rolling bucket counter:
/// - `current_bucket = now_ms / referral_bucket_ms`
/// - when the bucket changes, `remaining_new_users` resets to
///   `max(configured_new_users_per_bucket, 1000)`
/// - each successful `SetReferrer` decrements the counter and appends the user to
///   `referred_users`
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReferrerProfile {
    pub current_bucket: u64,
    pub remaining_new_users: u64,
    pub configured_new_users_per_bucket: u64,
    pub referred_users: Vec<ReferredUserLog>,
}

/// Referrer subsystem slice touched by `SetReferrer`.
#[derive(Clone, Debug, Default)]
pub struct ReferrerRegistry {
    /// Secondary lookup tree searched first by raw code bytes.
    pub address_by_code: BTreeMap<Vec<u8>, ReferrerCodeEntry>,
    /// Address-keyed hash table storing each user's chosen referrer.
    pub binding_by_user: HashMap<Address, UserReferrerBinding>,
    /// Referrer profile table used for bucket accounting.
    pub referrer_by_address: BTreeMap<Address, ReferrerProfile>,
    /// Global bucket width in milliseconds (`VoteGlobal::ReferralBucketMillis`).
    pub referral_bucket_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetReferrerError {
    CodeTooLong { limit: usize, actual: usize, status: u16 },
    UnknownCode,
    SelfReferral,
    AlreadySet,
    BucketDisabledOrExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetReferrerResult {
    /// Matches wrapper tag `13` / status `390`.
    Applied { binding_written: bool },
    /// Matches wrapper tag `14`; status depends on the inner rejection.
    Rejected(SetReferrerError),
}

pub const STATUS_OK: u16 = 390;
pub const STATUS_CODE_TOO_LONG: u16 = 323;
pub const STATUS_SELF_REFERRAL: u16 = 158;
pub const STATUS_ALREADY_SET: u16 = 159;
pub const STATUS_BUCKET_DISABLED_OR_EXHAUSTED: u16 = 161;
pub const STATUS_UNKNOWN_CODE: u16 = 162;

pub const OUTER_OK_TAG: u8 = 13;
pub const OUTER_ERR_TAG: u8 = 14;
pub const MAX_REFERRER_CODE_LEN: usize = 100;
pub const MIN_NEW_USERS_PER_BUCKET: u64 = 1_000;

impl SetReferrerResult {
    #[inline]
    pub const fn compact_tag(self) -> u8 {
        match self {
            Self::Applied { .. } => OUTER_OK_TAG,
            Self::Rejected(_) => OUTER_ERR_TAG,
        }
    }

    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::Applied { .. } => STATUS_OK,
            Self::Rejected(SetReferrerError::CodeTooLong { status, .. }) => status,
            Self::Rejected(SetReferrerError::UnknownCode) => STATUS_UNKNOWN_CODE,
            Self::Rejected(SetReferrerError::SelfReferral) => STATUS_SELF_REFERRAL,
            Self::Rejected(SetReferrerError::AlreadySet) => STATUS_ALREADY_SET,
            Self::Rejected(SetReferrerError::BucketDisabledOrExhausted) => {
                STATUS_BUCKET_DISABLED_OR_EXHAUSTED
            }
        }
    }
}

impl ReferrerRegistry {
    /// Reconstructed `SetReferrer` flow.
    ///
    /// Wrapper (`0x27DE270`):
    /// 1. Reject `code.len() > 100` with status `323`.
    /// 2. Forward the exchange referrer slice, signer address, raw code bytes, and
    ///    signed-action time context into `sub_37433C0`.
    /// 3. Return tag `13` on inner status `390`, else tag `14` plus the copied
    ///    inner error payload.
    ///
    /// Helper (`0x37433C0`):
    /// 1. Look up the referral code in `address_by_code`; missing code => `162`.
    /// 2. Reject when the code resolves back to the submitting address => `158`.
    /// 3. Look up or lazily create the user's binding row.
    /// 4. Reject when that row already has `is_set == true` => `159`.
    /// 5. Look up the owning referrer's profile row by address.
    /// 6. If found, call `sub_394B7E0` to consume one slot from the current
    ///    referral bucket and append the user to that profile's attribution log.
    /// 7. Only after step 6 succeeds does the helper write the user binding.
    ///
    /// Observed edge case: if the code lookup succeeds but the matching referrer
    /// profile row is absent, the helper still returns `390` and leaves the user
    /// binding untouched.
    pub fn set_referrer(
        &mut self,
        user: Address,
        action: &SetReferrerAction,
        now_ms: u64,
    ) -> SetReferrerResult {
        let code = action.code.as_bytes();
        if code.len() > MAX_REFERRER_CODE_LEN {
            return SetReferrerResult::Rejected(SetReferrerError::CodeTooLong {
                limit: MAX_REFERRER_CODE_LEN,
                actual: code.len(),
                status: STATUS_CODE_TOO_LONG,
            });
        }

        let Some(code_entry) = self.address_by_code.get(code).copied() else {
            return SetReferrerResult::Rejected(SetReferrerError::UnknownCode);
        };

        if code_entry.owner == user {
            return SetReferrerResult::Rejected(SetReferrerError::SelfReferral);
        }

        if self
            .binding_by_user
            .get(&user)
            .is_some_and(|binding| binding.is_set)
        {
            return SetReferrerResult::Rejected(SetReferrerError::AlreadySet);
        }

        let Some(profile) = self.referrer_by_address.get_mut(&code_entry.owner) else {
            self.binding_by_user.entry(user).or_default();
            return SetReferrerResult::Applied {
                binding_written: false,
            };
        };

        if let Err(error) = apply_referral_bucket_side_effect(
            profile,
            user,
            now_ms,
            self.referral_bucket_ms,
        ) {
            return SetReferrerResult::Rejected(error);
        }

        self.binding_by_user.insert(
            user,
            UserReferrerBinding {
                is_set: true,
                referrer: code_entry.owner,
                referrer_tag: code_entry.owner_tag,
            },
        );

        SetReferrerResult::Applied {
            binding_written: true,
        }
    }
}

#[inline]
fn apply_referral_bucket_side_effect(
    profile: &mut ReferrerProfile,
    user: Address,
    now_ms: u64,
    referral_bucket_ms: u64,
) -> Result<(), SetReferrerError> {
    if referral_bucket_ms == 0 {
        return Err(SetReferrerError::BucketDisabledOrExhausted);
    }

    let bucket = now_ms / referral_bucket_ms;
    if bucket != profile.current_bucket {
        profile.current_bucket = bucket;
        profile.remaining_new_users = profile
            .configured_new_users_per_bucket
            .max(MIN_NEW_USERS_PER_BUCKET);
    }

    if profile.remaining_new_users == 0 {
        return Err(SetReferrerError::BucketDisabledOrExhausted);
    }

    profile.remaining_new_users -= 1;
    profile.referred_users.push(ReferredUserLog { user, at_ms: now_ms });
    Ok(())
}
