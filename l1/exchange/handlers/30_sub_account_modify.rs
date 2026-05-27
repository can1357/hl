#![allow(dead_code)]

use std::collections::HashMap;

pub type Address = [u8; 20];

pub const HANDLER_EA: u64 = 0x22CD_FB0;
pub const HELPER_EA: u64 = 0x36F4_0D0;
pub const VALIDATE_NEW_NAME_EA: u64 = 0x36F4_3C0;

pub const STATUS_SUCCESS: u16 = 390;
pub const STATUS_SUB_ACCOUNT_NAME_NOT_UNIQUE: u16 = 215;
pub const STATUS_SUB_ACCOUNT_INVALID_NAME: u16 = 217;
pub const STATUS_SUB_ACCOUNT_NOT_REGISTERED: u16 = 220;
pub const STATUS_FULL_NAME_TOO_LONG: u16 = 323;

pub const MAX_CANONICAL_NAME_LEN: usize = 16;
pub const MAX_WIRE_NAME_LEN: usize = 100;

/// User action payload passed through `sub_22CDFB0`.
///
/// The wrapper clones `name` as an `Option<String>` and appends the
/// 20-byte `sub_account_user` directly after it before calling the real helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubAccountModifyAction {
    pub name: Option<String>,
    pub sub_account_user: Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubAccountEntry {
    pub name: String,
    pub sub_account_user: Address,
    pub master: Address,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubAccounts {
    pub user_to_sub_accounts: HashMap<Address, Vec<SubAccountEntry>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubAccountModifyError {
    SubAccountNameNotUnique,
    SubAccountInvalidName,
    SubAccountNotRegistered {
        master: Address,
        sub_account_user: Address,
    },
    FullNameTooLong,
}

impl SubAccountModifyError {
    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::SubAccountNameNotUnique => STATUS_SUB_ACCOUNT_NAME_NOT_UNIQUE,
            Self::SubAccountInvalidName => STATUS_SUB_ACCOUNT_INVALID_NAME,
            Self::SubAccountNotRegistered { .. } => STATUS_SUB_ACCOUNT_NOT_REGISTERED,
            Self::FullNameTooLong => STATUS_FULL_NAME_TOO_LONG,
        }
    }
}

/// `l1_sub_account__validate_new_name` canonicalizes names before checking for
/// duplicates.  The exact canonicalization helper is shared with sub-account
/// creation, so this reconstruction leaves it injectable instead of guessing the
/// full text normalization rules.
pub trait SubAccountNameCanonicalizer {
    /// Returns the canonical name on success, or `None` for an invalid wire name.
    fn canonicalize(&mut self, name: &str) -> Option<String>;
}

impl SubAccounts {
    fn validate_wire_name(name: &str) -> Result<(), SubAccountModifyError> {
        if name.as_bytes().len() > MAX_WIRE_NAME_LEN {
            Err(SubAccountModifyError::FullNameTooLong)
        } else {
            Ok(())
        }
    }

    fn validate_new_name<C: SubAccountNameCanonicalizer>(
        &self,
        canonicalizer: &mut C,
        master: &Address,
        name: &str,
    ) -> Result<String, SubAccountModifyError> {
        let canonical = canonicalizer
            .canonicalize(name)
            .ok_or(SubAccountModifyError::SubAccountInvalidName)?;
        if canonical.is_empty() || canonical.len() > MAX_CANONICAL_NAME_LEN {
            return Err(SubAccountModifyError::SubAccountInvalidName);
        }

        if self
            .user_to_sub_accounts
            .get(master)
            .is_some_and(|entries| {
                entries.iter().any(|entry| {
                    canonicalizer
                        .canonicalize(&entry.name)
                        .is_some_and(|existing| existing.as_bytes() == canonical.as_bytes())
                })
            })
        {
            return Err(SubAccountModifyError::SubAccountNameNotUnique);
        }

        Ok(canonical)
    }
}

/// Reconstructs `sub_22CDFB0 -> l1_sub_account__modify_sub_account_name`.
///
/// Observed control flow:
/// 1. If `action.name` is `None`, return success without touching sub-account state.
/// 2. Reject wire names longer than 100 bytes with status `323`.
/// 3. Canonicalize and validate the new name; invalid names return `217`.
/// 4. Scan every sub-account already owned by `master`; if any canonicalized name
///    matches, reject with `215` before checking whether the target sub-account exists.
/// 5. Look up `master` inside `user_to_sub_accounts`; absence returns `220`.
/// 6. Find the row whose `sub_account_user` matches the action; absence also returns `220`.
/// 7. Replace only that row's stored display name. No other exchange state changes.
///
/// A rename to the entry's current canonical name still fails with `215`, because
/// the duplicate scan runs before the target row is located and does not exclude it.
pub fn apply_sub_account_modify<C: SubAccountNameCanonicalizer>(
    sub_accounts: &mut SubAccounts,
    canonicalizer: &mut C,
    master: Address,
    action: &SubAccountModifyAction,
) -> Result<(), SubAccountModifyError> {
    let Some(name) = action.name.as_deref() else {
        return Ok(());
    };

    SubAccounts::validate_wire_name(name)?;
    let _canonical = sub_accounts.validate_new_name(canonicalizer, &master, name)?;

    let entries = sub_accounts.user_to_sub_accounts.get_mut(&master).ok_or(
        SubAccountModifyError::SubAccountNotRegistered {
            master,
            sub_account_user: action.sub_account_user,
        },
    )?;

    let entry = entries.iter_mut().find(|entry| entry.sub_account_user == action.sub_account_user).ok_or(
        SubAccountModifyError::SubAccountNotRegistered {
            master,
            sub_account_user: action.sub_account_user,
        },
    )?;

    entry.name = name.to_owned();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct LowerAsciiCanonicalizer;

    impl SubAccountNameCanonicalizer for LowerAsciiCanonicalizer {
        fn canonicalize(&mut self, name: &str) -> Option<String> {
            if name.is_empty()
                || name.len() > MAX_CANONICAL_NAME_LEN
                || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return None;
            }
            Some(name.to_ascii_lowercase())
        }
    }

    fn addr(last: u8) -> Address {
        let mut out = [0u8; 20];
        out[19] = last;
        out
    }

    #[test]
    fn none_name_is_no_op_success() {
        let master = addr(1);
        let sub = addr(2);
        let mut sub_accounts = SubAccounts {
            user_to_sub_accounts: HashMap::from([(
                master,
                vec![SubAccountEntry {
                    name: "desk".into(),
                    sub_account_user: sub,
                    master,
                }],
            )]),
        };

        let mut canonicalizer = LowerAsciiCanonicalizer;
        let action = SubAccountModifyAction {
            name: None,
            sub_account_user: addr(9),
        };

        assert_eq!(
            apply_sub_account_modify(&mut sub_accounts, &mut canonicalizer, master, &action),
            Ok(())
        );
        assert_eq!(sub_accounts.user_to_sub_accounts[&master][0].name, "desk");
    }

    #[test]
    fn duplicate_name_is_rejected_before_target_lookup() {
        let master = addr(1);
        let sub = addr(2);
        let mut sub_accounts = SubAccounts {
            user_to_sub_accounts: HashMap::from([(
                master,
                vec![SubAccountEntry {
                    name: "Desk".into(),
                    sub_account_user: sub,
                    master,
                }],
            )]),
        };

        let mut canonicalizer = LowerAsciiCanonicalizer;
        let action = SubAccountModifyAction {
            name: Some("desk".into()),
            sub_account_user: addr(3),
        };

        assert_eq!(
            apply_sub_account_modify(&mut sub_accounts, &mut canonicalizer, master, &action),
            Err(SubAccountModifyError::SubAccountNameNotUnique)
        );
    }

    #[test]
    fn successful_rename_updates_only_matching_row() {
        let master = addr(1);
        let sub_a = addr(2);
        let sub_b = addr(3);
        let mut sub_accounts = SubAccounts {
            user_to_sub_accounts: HashMap::from([(
                master,
                vec![
                    SubAccountEntry {
                        name: "Desk".into(),
                        sub_account_user: sub_a,
                        master,
                    },
                    SubAccountEntry {
                        name: "Vault".into(),
                        sub_account_user: sub_b,
                        master,
                    },
                ],
            )]),
        };

        let mut canonicalizer = LowerAsciiCanonicalizer;
        let action = SubAccountModifyAction {
            name: Some("Alpha".into()),
            sub_account_user: sub_b,
        };

        assert_eq!(
            apply_sub_account_modify(&mut sub_accounts, &mut canonicalizer, master, &action),
            Ok(())
        );
        assert_eq!(sub_accounts.user_to_sub_accounts[&master][0].name, "Desk");
        assert_eq!(sub_accounts.user_to_sub_accounts[&master][1].name, "Alpha");
    }
}
