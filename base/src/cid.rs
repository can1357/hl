use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::de::{self, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const MAINNET_NAMESPACE: u8 = 2;
pub const TESTNET_NAMESPACE: u8 = 3;
pub const KNOWN_NAMESPACE_COUNT: u8 = 12;

pub const USDC_2_MAINNET_ALIAS: &str = "Usdc2Mainnet";
pub const USDC_2_MAINNET_ADDRESS: &str = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831";
pub const BRIDGE_2_MAINNET_ALIAS: &str = "Bridge2Mainnet";
pub const BRIDGE_2_MAINNET_ADDRESS: &str = "0x2Df1c51E09aECF9cacB7bc98cB1742757f163dF7";
pub const BRIDGE_2_TESTNET_ALIAS: &str = "Bridge2Testnet";
pub const BRIDGE_2_TESTNET_ADDRESS: &str = "0x08cfc1B6b2dCF36A1480b99353A354AA8AC56f89";
pub const USDC_2_TESTNET_ALIAS: &str = "Usdc2Testnet";
pub const USDC_2_TESTNET_ADDRESS: &str = "0x1baAbB04529D43a73232B713C0FE471f7c7334d5";

pub type CidAliasTables = BTreeMap<u8, CidAliasTable>;
pub type NamedAliasSet = &'static [(&'static str, &'static str)];

const MAINNET_NAMED_ALIASES: NamedAliasSet = &[
    (USDC_2_MAINNET_ALIAS, USDC_2_MAINNET_ADDRESS),
    (BRIDGE_2_MAINNET_ALIAS, BRIDGE_2_MAINNET_ADDRESS),
];

const TESTNET_NAMED_ALIASES: NamedAliasSet = &[
    (BRIDGE_2_TESTNET_ALIAS, BRIDGE_2_TESTNET_ADDRESS),
    (USDC_2_TESTNET_ALIAS, USDC_2_TESTNET_ADDRESS),
];

const DEFAULT_NAMED_ALIAS_SETS: &[(u8, NamedAliasSet)] = &[
    (MAINNET_NAMESPACE, MAINNET_NAMED_ALIASES),
    (TESTNET_NAMESPACE, TESTNET_NAMED_ALIASES),
];

/// 128-bit chain/client identifier key.
///
/// IDA: keys move through the serializer as a single 16-byte scalar and are converted
/// to hex strings by `sub_1449A80` before the outer sequence writer stores them.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Cid(pub u128);

impl Cid {
    pub const ZERO: Self = Self(0);

    pub const fn new(raw: u128) -> Self {
        Self(raw)
    }

    pub const fn into_raw(self) -> u128 {
        self.0
    }

    pub fn parse_hex(input: &str) -> Result<Self, CidParseError> {
        let bytes = input.as_bytes();
        let digits = if bytes.starts_with(b"0x") || bytes.starts_with(b"0X") {
            &bytes[2..]
        } else {
            bytes
        };

        if digits.is_empty() || digits.len() > 32 {
            return Err(CidParseError::InvalidLength(digits.len()));
        }

        let mut value = 0u128;
        for (index, byte) in digits.iter().copied().enumerate() {
            let nibble = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err(CidParseError::InvalidHex { index, byte }),
            };
            value = (value << 4) | u128::from(nibble);
        }

        Ok(Self(value))
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

impl FromStr for Cid {
    type Err = CidParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_hex(s)
    }
}

impl Serialize for Cid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Cid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CidVisitor;

        impl<'de> Visitor<'de> for CidVisitor {
            type Value = Cid;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a 128-bit identifier encoded as hex")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Cid::parse_hex(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(CidVisitor)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CidParseError {
    InvalidLength(usize),
    InvalidHex { index: usize, byte: u8 },
}

impl fmt::Display for CidParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(len) => write!(f, "expected 1..=32 hex digits, got {len}"),
            Self::InvalidHex { index, byte } => {
                write!(f, "invalid hex byte 0x{byte:02x} at offset {index}")
            }
        }
    }
}

/// 20-byte value copied out of the loaded CID tables.
///
/// IDA: `sub_1405240` and `sub_13C6430` both move `16 + 4` bytes per resolved entry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResolvedCid {
    pub canonical: Cid,
    pub tag: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CidAliasSerdeEntry {
    pub alias: Cid,
    pub resolved: ResolvedCid,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CidAliasTable {
    entries: BTreeMap<Cid, ResolvedCid>,
}

impl CidAliasTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, alias: Cid, resolved: ResolvedCid) -> Option<ResolvedCid> {
        self.entries.insert(alias, resolved)
    }

    pub fn get(&self, alias: Cid) -> Option<ResolvedCid> {
        self.entries.get(&alias).copied()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (Cid, ResolvedCid)> + '_ {
        self.entries.iter().map(|(alias, resolved)| (*alias, *resolved))
    }

    /// IDA: `sub_13C6430`, called by `sub_13F1A30`.
    ///
    /// The binary allocates `48 * len` bytes and emits one serde element per map entry:
    /// `(lower_hex_alias, ResolvedCid)`.
    pub fn to_serde_entries(&self) -> Vec<CidAliasSerdeEntry> {
        self.iter()
            .map(|(alias, resolved)| CidAliasSerdeEntry { alias, resolved })
            .collect()
    }
}

impl Serialize for CidAliasTable {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.entries.len()))?;
        for entry in self.to_serde_entries() {
            seq.serialize_element(&entry)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for CidAliasTable {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TableVisitor;

        impl<'de> Visitor<'de> for TableVisitor {
            type Value = CidAliasTable;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a sequence of CID alias entries")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut table = CidAliasTable::new();
                while let Some(entry) = seq.next_element::<CidAliasSerdeEntry>()? {
                    table.insert(entry.alias, entry.resolved);
                }
                Ok(table)
            }
        }

        deserializer.deserialize_seq(TableVisitor)
    }
}

pub fn default_named_alias_sets() -> &'static [(u8, NamedAliasSet)] {
    DEFAULT_NAMED_ALIAS_SETS
}

pub fn is_rmp_source_path(source: &str) -> bool {
    Path::new(source)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("rmp"))
        .unwrap_or(false)
}

/// File/path validation gate recovered from `sub_144A710`.
///
/// The binary rejects unsupported sources before attempting to parse them. Exact OS
/// metadata handling lives in foreign helpers, so this trait keeps that validation as an
/// explicit dependency.
pub trait CidAliasParser {
    fn parse_named_aliases(
        &mut self,
        named: NamedAliasSet,
    ) -> Result<CidAliasTable, CidLoadError>;

    fn resolve_namespace_source(&mut self, namespace: u8) -> Option<String>;

    fn validate_source_spec(&mut self, source: &str) -> bool;

    fn parse_rmp_alias_source(&mut self, source: &str) -> Result<CidAliasTable, CidLoadError>;

    fn parse_text_alias_source(&mut self, source: &str) -> Result<CidAliasTable, CidLoadError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CidLoadError {
    ParserFailed(Box<str>),
}

impl CidLoadError {
    pub fn parser_failed(message: impl Into<Box<str>>) -> Self {
        Self::ParserFailed(message.into())
    }
}

impl fmt::Display for CidLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParserFailed(message) => f.write_str(message),
        }
    }
}

/// IDA: `sub_144E940`.
///
/// `.rmp` sources take a dedicated decode path; everything else falls through the text
/// parser path.
pub fn parse_source_spec<P: CidAliasParser>(
    parser: &mut P,
    source: &str,
) -> Result<CidAliasTable, CidLoadError> {
    if is_rmp_source_path(source) {
        parser.parse_rmp_alias_source(source)
    } else {
        parser.parse_text_alias_source(source)
    }
}

/// IDA: `sub_1405720`.
///
/// Seeds namespace `2`/`3` with the four hard-coded aliases above, then walks namespace
/// ids `0..12`, resolves an optional source spec for each id, validates it, parses it,
/// and inserts/replaces that namespace table in the final nested map.
pub fn load_chain_id_alias_map<P: CidAliasParser>(
    parser: &mut P,
) -> Result<CidAliasTables, CidLoadError> {
    let mut tables = CidAliasTables::new();

    for &(namespace, named_aliases) in default_named_alias_sets() {
        let parsed = parser.parse_named_aliases(named_aliases)?;
        tables.insert(namespace, parsed);
    }

    for namespace in 0..KNOWN_NAMESPACE_COUNT {
        let Some(source) = parser.resolve_namespace_source(namespace) else {
            continue;
        };
        if !parser.validate_source_spec(&source) {
            continue;
        }
        let parsed = parse_source_spec(parser, &source)?;
        tables.insert(namespace, parsed);
    }

    Ok(tables)
}

/// Safe lookup wrapper for the loaded nested tables.
///
/// IDA: `sub_1405240` performs the same two-stage search (`namespace` then `Cid`) under
/// a global lock; once a namespace table exists, the stripped caller unwraps the inner
/// lookup on miss.
pub fn lookup_loaded_chain_id_alias(
    tables: &CidAliasTables,
    namespace: u8,
    alias: Cid,
) -> Option<ResolvedCid> {
    tables.get(&namespace).and_then(|table| table.get(alias))
}

/// Closer source-level analogue for the stripped global lookup path.
///
/// Returns `None` when the namespace table is absent. Once the namespace exists, a
/// missing alias is treated as a logic error and panics, matching the unwrap path
/// recovered at `0x1405240`.
pub fn lookup_loaded_chain_id_alias_strict(
    tables: &CidAliasTables,
    namespace: u8,
    alias: Cid,
) -> Option<ResolvedCid> {
    let table = tables.get(&namespace)?;
    Some(
        table
            .get(alias)
            .unwrap_or_else(|| panic!("missing chain-id alias {alias} in namespace {namespace}")),
    )
}
