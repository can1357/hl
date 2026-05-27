#![allow(dead_code)]

use std::collections::BTreeMap;

pub type Address = [u8; 20];

pub const WRAPPER_EA: u64 = 0x27E2_170;
pub const HELPER_EA: u64 = 0x2767_D20;
pub const MAP_REMOVE_EA: u64 = 0x2868_B10;
pub const MAP_UPSERT_EA: u64 = 0x285C_0A0;

pub const STATUS_OK: u16 = 390;
pub const STATUS_DISPLAY_NAME_TOO_LONG: u16 = 211;
pub const STATUS_DISPLAY_NAME_TOO_SHORT: u16 = 212;
pub const STATUS_DISPLAY_NAME_NOT_UNIQUE: u16 = 213;
pub const STATUS_WIRE_STRING_TOO_LONG: u16 = 323;

pub const MIN_DISPLAY_NAME_LEN: usize = 3;
pub const MAX_DISPLAY_NAME_LEN: usize = 20;
pub const MAX_WIRE_STRING_LEN_EXCLUSIVE: usize = 101;

/// Deserialized `{"setDisplayName": {"displayName": ... }}` payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetDisplayNameAction {
    pub display_name: String,
}

/// Recovered exchange slice rooted at field offset `+14736` (`a2 + 1842 * 8`).
///
/// The helper stores one owned string per 20-byte user key and enforces global
/// uniqueness over the current values before every non-empty update.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DisplayNameRegistry {
    pub display_name_by_user: BTreeMap<Address, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetDisplayNameError {
    WireStringTooLong,
    DisplayNameTooShort,
    DisplayNameTooLong,
    DisplayNameNotUnique,
}

impl SetDisplayNameError {
    #[inline]
    pub const fn code(&self) -> u16 {
        match self {
            Self::WireStringTooLong => STATUS_WIRE_STRING_TOO_LONG,
            Self::DisplayNameTooShort => STATUS_DISPLAY_NAME_TOO_SHORT,
            Self::DisplayNameTooLong => STATUS_DISPLAY_NAME_TOO_LONG,
            Self::DisplayNameNotUnique => STATUS_DISPLAY_NAME_NOT_UNIQUE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetDisplayNameWrapperTag {
    Ok = 13,
    Err = 14,
}

impl DisplayNameRegistry {
    /// Reconstructed `l1_exchange_impl_execute_action__set_display_name` wrapper
    /// plus `l1_exchange__apply_set_display_name` core helper.
    ///
    /// Observed flow:
    /// 1. Reject `display_name.len() >= 101` with status `323`.
    /// 2. If the submitted string is empty, remove the caller's current entry from
    ///    `display_name_by_user` and return success.
    /// 3. Otherwise require `3 <= len <= 20`; helper statuses are `212` for short
    ///    and `211` for long.
    /// 4. Scan the whole map and reject any exact byte-for-byte duplicate value
    ///    with status `213`.
    /// 5. Upsert `user -> display_name` and return `390`.
    ///
    /// Because the duplicate scan runs before the keyed upsert, resubmitting the
    /// user's current name still fails with `213` instead of behaving as a no-op.
    pub fn apply_set_display_name(
        &mut self,
        user: Address,
        action: &SetDisplayNameAction,
    ) -> Result<(), SetDisplayNameError> {
        let submitted = action.display_name.as_bytes();
        if submitted.len() >= MAX_WIRE_STRING_LEN_EXCLUSIVE {
            return Err(SetDisplayNameError::WireStringTooLong);
        }

        if submitted.is_empty() {
            self.display_name_by_user.remove(&user);
            return Ok(());
        }

        if submitted.len() > MAX_DISPLAY_NAME_LEN {
            return Err(SetDisplayNameError::DisplayNameTooLong);
        }
        if submitted.len() < MIN_DISPLAY_NAME_LEN {
            return Err(SetDisplayNameError::DisplayNameTooShort);
        }
        if self
            .display_name_by_user
            .values()
            .any(|existing| existing.as_bytes() == submitted)
        {
            return Err(SetDisplayNameError::DisplayNameNotUnique);
        }

        self.display_name_by_user
            .insert(user, action.display_name.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(last: u8) -> Address {
        let mut out = [0u8; 20];
        out[19] = last;
        out
    }

    #[test]
    fn empty_string_clears_existing_profile() {
        let user = addr(1);
        let mut registry = DisplayNameRegistry {
            display_name_by_user: BTreeMap::from([(user, "alice".to_owned())]),
        };

        assert_eq!(
            registry.apply_set_display_name(
                user,
                &SetDisplayNameAction {
                    display_name: String::new(),
                },
            ),
            Ok(())
        );
        assert!(!registry.display_name_by_user.contains_key(&user));
    }

    #[test]
    fn wrapper_guard_rejects_wire_string_over_100_bytes() {
        let user = addr(1);
        let mut registry = DisplayNameRegistry::default();

        assert_eq!(
            registry.apply_set_display_name(
                user,
                &SetDisplayNameAction {
                    display_name: "x".repeat(100),
                },
            ),
            Err(SetDisplayNameError::DisplayNameTooLong)
        );

        assert_eq!(
            registry.apply_set_display_name(
                user,
                &SetDisplayNameAction {
                    display_name: "x".repeat(101),
                },
            ),
            Err(SetDisplayNameError::WireStringTooLong)
        );
    }

    #[test]
    fn duplicate_name_is_global_across_users() {
        let mut registry = DisplayNameRegistry {
            display_name_by_user: BTreeMap::from([(addr(1), "alice".to_owned())]),
        };

        assert_eq!(
            registry.apply_set_display_name(
                addr(2),
                &SetDisplayNameAction {
                    display_name: "alice".to_owned(),
                },
            ),
            Err(SetDisplayNameError::DisplayNameNotUnique)
        );
    }

    #[test]
    fn resubmitting_same_name_is_not_a_no_op() {
        let user = addr(1);
        let mut registry = DisplayNameRegistry {
            display_name_by_user: BTreeMap::from([(user, "alice".to_owned())]),
        };

        assert_eq!(
            registry.apply_set_display_name(
                user,
                &SetDisplayNameAction {
                    display_name: "alice".to_owned(),
                },
            ),
            Err(SetDisplayNameError::DisplayNameNotUnique)
        );
    }

    #[test]
    fn unique_rename_replaces_existing_value_for_same_user() {
        let user = addr(1);
        let mut registry = DisplayNameRegistry {
            display_name_by_user: BTreeMap::from([(user, "alice".to_owned())]),
        };

        assert_eq!(
            registry.apply_set_display_name(
                user,
                &SetDisplayNameAction {
                    display_name: "bob".to_owned(),
                },
            ),
            Ok(())
        );
        assert_eq!(registry.display_name_by_user.get(&user), Some(&"bob".to_owned()));
    }
}
