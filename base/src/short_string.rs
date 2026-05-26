use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::convert::Infallible;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str;
use std::str::FromStr;
use std::sync::{LazyLock, RwLock};

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const MAX_INLINE_LEN: usize = 16;
pub const LONG_ALIAS_LEN: usize = 10;
pub const LONG_ALIAS_CACHE_INSERT_LIMIT: usize = 99_999;

static LONG_STRING_ALIASES: LazyLock<RwLock<HashMap<String, ShortString>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Inline string key stored as the little-endian bytes of the string in a `u128`.
///
/// The constructors pack byte zero into the low byte, byte one into bits 8..15,
/// and so on.  There is no explicit length field; formatting trims zero bytes
/// from the high end of the 16-byte word.
#[repr(transparent)]
#[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ShortString(u128);

impl ShortString {
    pub const EMPTY: Self = Self(0);

    #[inline]
    pub const fn from_raw(raw: u128) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn into_raw(self) -> u128 {
        self.0
    }

    #[inline]
    pub fn new(value: &str) -> Self {
        short_string(value)
    }

    #[inline]
    pub fn len(self) -> usize {
        short_string_len(self.0)
    }

    #[inline]
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn bytes(self) -> ([u8; MAX_INLINE_LEN], usize) {
        let bytes = self.0.to_le_bytes();
        let len = short_string_len_from_bytes(&bytes);
        (bytes, len)
    }

    #[inline]
    pub fn fmt_str(self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (bytes, len) = self.bytes();
        let value = str::from_utf8(&bytes[..len]).map_err(|_| fmt::Error)?;
        formatter.write_str(value)
    }
}

impl fmt::Display for ShortString {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_str(formatter)
    }
}

impl fmt::Debug for ShortString {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (bytes, len) = self.bytes();
        let value = str::from_utf8(&bytes[..len]).map_err(|_| fmt::Error)?;
        fmt::Debug::fmt(value, formatter)
    }
}

impl FromStr for ShortString {
    type Err = Infallible;

    #[inline]
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(short_string(value))
    }
}

impl From<&str> for ShortString {
    #[inline]
    fn from(value: &str) -> Self {
        short_string(value)
    }
}

impl Serialize for ShortString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let (bytes, len) = self.bytes();
        let value = str::from_utf8(&bytes[..len]).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(value)
    }
}

impl<'de> Deserialize<'de> for ShortString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ShortStringVisitor;

        impl<'de> Visitor<'de> for ShortStringVisitor {
            type Value = ShortString;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a short inline string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(short_string(value))
            }
        }

        deserializer.deserialize_str(ShortStringVisitor)
    }
}

/// Construct a `ShortString` from UTF-8 text.
///
/// Inputs up to sixteen bytes are packed directly.  Longer inputs are reduced to
/// a deterministic ten-character uppercase alias and cached by the original
/// string while the cache has at most 99,999 entries.  The recovered binary uses
/// a read lock for the fast path, releases it while computing the alias, then
/// takes the write lock only for the optional insertion.
pub fn short_string(value: &str) -> ShortString {
    let bytes = value.as_bytes();
    if bytes.len() <= MAX_INLINE_LEN {
        return ShortString(pack_inline_recursive(bytes, 0));
    }

    if let Some(cached) = LONG_STRING_ALIASES
        .read()
        .expect("short string alias cache poisoned")
        .get(value)
        .copied()
    {
        return cached;
    }

    let alias = generated_long_alias(value);

    assert!(alias.len() <= MAX_INLINE_LEN);
    let packed = ShortString(pack_inline_recursive(&alias, 0));

    if LONG_STRING_ALIASES
        .read()
        .expect("short string alias cache poisoned")
        .len()
        <= LONG_ALIAS_CACHE_INSERT_LIMIT
    {
        LONG_STRING_ALIASES
            .write()
            .expect("short string alias cache poisoned")
            .insert(value.to_owned(), packed);
    }

    packed
}

/// Recursive byte packer recovered from the small helper monomorph.
///
/// This intentionally mirrors the binary's recursive shape: recurse to the end,
/// multiply the tail by 256 with overflow checking, then OR in the current byte.
fn pack_inline_recursive(bytes: &[u8], index: usize) -> u128 {
    if index == bytes.len() {
        return 0;
    }

    let byte = u128::from(bytes[index]);
    let tail = pack_inline_recursive(bytes, index + 1);
    tail.checked_mul(256)
        .expect("short string byte packing overflow")
        | byte
}

fn generated_long_alias(value: &str) -> [u8; LONG_ALIAS_LEN] {
    let mut alias = [0u8; LONG_ALIAS_LEN];
    for (counter, slot) in alias.iter_mut().enumerate() {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        (counter as u32).hash(&mut hasher);
        *slot = b'A' + (hasher.finish() % 26) as u8;
    }
    alias
}

#[inline]
fn short_string_len(raw: u128) -> usize {
    short_string_len_from_bytes(&raw.to_le_bytes())
}

#[inline]
fn short_string_len_from_bytes(bytes: &[u8; MAX_INLINE_LEN]) -> usize {
    bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map(|index| index + 1)
        .unwrap_or(0)
}
