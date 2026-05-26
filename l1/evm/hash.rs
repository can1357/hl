use serde::de::{Error as DeError, Expected, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

pub const RAW_HASH_BYTES: usize = 2048;
pub const DIGEST_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest32(pub [u8; DIGEST_BYTES]);

impl Digest32 {
    pub const ZERO: Self = Self([0; DIGEST_BYTES]);

    pub const fn new(bytes: [u8; DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; DIGEST_BYTES] {
        self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != DIGEST_BYTES {
            return None;
        }
        let mut out = [0u8; DIGEST_BYTES];
        out.copy_from_slice(bytes);
        Some(Self(out))
    }

    pub fn from_sha256(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut out = [0u8; DIGEST_BYTES];
        out.copy_from_slice(&digest);
        Self(out)
    }

    pub fn write_lower_hex(&self, out: &mut String) {
        push_lower_hex(out, &self.0);
    }
}

impl AsRef<[u8]> for Digest32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; DIGEST_BYTES]> for Digest32 {
    fn from(bytes: [u8; DIGEST_BYTES]) -> Self {
        Self(bytes)
    }
}

impl From<Digest32> for [u8; DIGEST_BYTES] {
    fn from(hash: Digest32) -> Self {
        hash.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawHash {
    pub hash: [u8; RAW_HASH_BYTES],
    pub n_elements: u64,
    pub n_bytes: u64,
}

impl Default for RawHash {
    fn default() -> Self {
        Self { hash: [0; RAW_HASH_BYTES], n_elements: 0, n_bytes: 0 }
    }
}

impl RawHash {
    pub const fn new(hash: [u8; RAW_HASH_BYTES], n_elements: u64, n_bytes: u64) -> Self {
        Self { hash, n_elements, n_bytes }
    }

    pub fn digest(&self) -> Digest32 {
        // The recovered helper hashes exactly the 0x800-byte payload.  The two
        // counters are serialized beside the payload but are not included in
        // this per-bucket digest.
        Digest32::from_sha256(&self.hash)
    }

    pub fn as_payload(&self) -> &[u8; RAW_HASH_BYTES] {
        &self.hash
    }

    pub fn from_payload_slice(hash: &[u8], n_elements: u64, n_bytes: u64) -> Option<Self> {
        if hash.len() != RAW_HASH_BYTES {
            return None;
        }
        let mut out = [0u8; RAW_HASH_BYTES];
        out.copy_from_slice(hash);
        Some(Self::new(out, n_elements, n_bytes))
    }
}

impl Serialize for RawHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let mut state = serializer.serialize_struct("RawHash", 3)?;
            state.serialize_field("n_elements", &self.n_elements)?;
            state.serialize_field("n_bytes", &self.n_bytes)?;
            state.serialize_field("hash", &HexBytes::<RAW_HASH_BYTES>(&self.hash))?;
            state.end()
        } else {
            (&self.n_elements, &self.n_bytes, serde_bytes::Bytes::new(&self.hash)).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for RawHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_any(RawHashVisitor)
        } else {
            let (n_elements, n_bytes, hash): (u64, u64, serde_bytes::ByteBuf) = Deserialize::deserialize(deserializer)?;
            let hash = byte_buf_to_array::<RAW_HASH_BYTES, D::Error>(hash)?;
            Ok(Self { hash, n_elements, n_bytes })
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LtHash {
    pub accounts_hash: RawHash,
    pub contracts_hash: RawHash,
    pub storage_hash: RawHash,
}

impl LtHash {
    pub const fn new(accounts_hash: RawHash, contracts_hash: RawHash, storage_hash: RawHash) -> Self {
        Self { accounts_hash, contracts_hash, storage_hash }
    }

    pub fn bucket_digests(&self) -> LtHashDigests {
        LtHashDigests {
            accounts_hash: self.accounts_hash.digest(),
            contracts_hash: self.contracts_hash.digest(),
            storage_hash: self.storage_hash.digest(),
        }
    }

    pub fn write_compact_msgpack(&self, out: &mut Vec<u8>) -> Result<(), rmp_serde::encode::Error> {
        self.serialize(&mut rmp_serde::Serializer::new(out).with_struct_map())
    }

    pub fn compact_msgpack(&self) -> Result<Vec<u8>, rmp_serde::encode::Error> {
        let mut out = Vec::new();
        self.write_compact_msgpack(&mut out)?;
        Ok(out)
    }

    pub fn compact_msgpack_sha256(&self) -> Result<Digest32, rmp_serde::encode::Error> {
        let msgpack = self.compact_msgpack()?;
        Ok(Digest32::from_sha256(&msgpack))
    }
}

impl Serialize for LtHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let mut state = serializer.serialize_struct("LtHash", 3)?;
            state.serialize_field("accounts_hash", &self.accounts_hash)?;
            state.serialize_field("contracts_hash", &self.contracts_hash)?;
            state.serialize_field("storage_hash", &self.storage_hash)?;
            state.end()
        } else {
            (&self.accounts_hash, &self.contracts_hash, &self.storage_hash).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for LtHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_any(LtHashVisitor)
        } else {
            let (accounts_hash, contracts_hash, storage_hash) = Deserialize::deserialize(deserializer)?;
            Ok(Self { accounts_hash, contracts_hash, storage_hash })
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LtHashDigests {
    pub accounts_hash: Digest32,
    pub contracts_hash: Digest32,
    pub storage_hash: Digest32,
}

impl LtHashDigests {
    pub const ZERO: Self = Self {
        accounts_hash: Digest32::ZERO,
        contracts_hash: Digest32::ZERO,
        storage_hash: Digest32::ZERO,
    };

    pub fn as_flat_bytes(&self) -> [u8; DIGEST_BYTES * 3] {
        let mut out = [0u8; DIGEST_BYTES * 3];
        out[..DIGEST_BYTES].copy_from_slice(self.accounts_hash.as_bytes());
        out[DIGEST_BYTES..DIGEST_BYTES * 2].copy_from_slice(self.contracts_hash.as_bytes());
        out[DIGEST_BYTES * 2..].copy_from_slice(self.storage_hash.as_bytes());
        out
    }
}

impl From<&LtHash> for LtHashDigests {
    fn from(value: &LtHash) -> Self {
        value.bucket_digests()
    }
}

impl From<LtHashDigests> for [Digest32; 3] {
    fn from(value: LtHashDigests) -> Self {
        [value.accounts_hash, value.contracts_hash, value.storage_hash]
    }
}

pub fn sha256_payload_and_lt_hash(payload: &[u8], state_hashes: &LtHash) -> Result<(Digest32, Digest32), rmp_serde::encode::Error> {
    let payload_digest = Digest32::from_sha256(payload);
    let state_digest = state_hashes.compact_msgpack_sha256()?;
    Ok((payload_digest, state_digest))
}

pub fn digest_raw_state_hashes(state_hashes: &LtHash) -> LtHashDigests {
    state_hashes.bucket_digests()
}

pub fn write_lt_hash_parts_to_path(path: impl AsRef<Path>, state_hashes: &LtHash) -> io::Result<()> {
    let path = path.as_ref();
    if path == Path::new("/dev/null") {
        return Ok(());
    }

    let mut bytes = Vec::new();
    state_hashes
        .write_compact_msgpack(&mut bytes)
        .map_err(|source| io::Error::new(io::ErrorKind::InvalidData, source))?;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, bytes)
}

pub fn lower_hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    push_lower_hex(&mut out, bytes);
    out
}

pub fn parse_lower_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != N * 2 {
        return None;
    }

    let mut out = [0u8; N];
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < N {
        let hi = decode_hex_digit(bytes[i * 2])?;
        let lo = decode_hex_digit(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Some(out)
}

fn push_lower_hex(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.reserve(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
}

fn decode_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn byte_buf_to_array<const N: usize, E>(buf: serde_bytes::ByteBuf) -> Result<[u8; N], E>
where
    E: DeError,
{
    if buf.len() != N {
        return Err(E::invalid_length(buf.len(), &FixedBytesExpected::<N>));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(buf.as_ref());
    Ok(out)
}

struct HexBytes<'a, const N: usize>(&'a [u8; N]);

impl<const N: usize> Serialize for HexBytes<'_, N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&lower_hex_bytes(self.0))
    }
}

struct RawHashVisitor;

impl<'de> Visitor<'de> for RawHashVisitor {
    type Value = RawHash;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RawHash as [n_elements, n_bytes, hash] or a map with n_elements, n_bytes, hash")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let n_elements = seq.next_element()?.ok_or_else(|| A::Error::invalid_length(0, &self))?;
        let n_bytes = seq.next_element()?.ok_or_else(|| A::Error::invalid_length(1, &self))?;
        let hex: String = seq.next_element()?.ok_or_else(|| A::Error::invalid_length(2, &self))?;
        let hash = parse_lower_hex::<RAW_HASH_BYTES>(&hex).ok_or_else(|| A::Error::custom("invalid RawHash.hash hex"))?;
        Ok(RawHash { hash, n_elements, n_bytes })
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut n_elements = None;
        let mut n_bytes = None;
        let mut hash = None;

        while let Some(key) = map.next_key::<&str>()? {
            match key {
                "n_elements" => set_once(&mut n_elements, map.next_value()?, key)?,
                "n_bytes" => set_once(&mut n_bytes, map.next_value()?, key)?,
                "hash" => {
                    let hex: String = map.next_value()?;
                    let parsed = parse_lower_hex::<RAW_HASH_BYTES>(&hex).ok_or_else(|| A::Error::custom("invalid RawHash.hash hex"))?;
                    set_once(&mut hash, parsed, key)?;
                }
                _ => {
                    let _ = map.next_value::<IgnoredAny>()?;
                }
            }
        }

        Ok(RawHash {
            hash: hash.ok_or_else(|| A::Error::missing_field("hash"))?,
            n_elements: n_elements.ok_or_else(|| A::Error::missing_field("n_elements"))?,
            n_bytes: n_bytes.ok_or_else(|| A::Error::missing_field("n_bytes"))?,
        })
    }
}

struct LtHashVisitor;

impl<'de> Visitor<'de> for LtHashVisitor {
    type Value = LtHash;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LtHash as [accounts_hash, contracts_hash, storage_hash] or matching map")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let accounts_hash = seq.next_element()?.ok_or_else(|| A::Error::invalid_length(0, &self))?;
        let contracts_hash = seq.next_element()?.ok_or_else(|| A::Error::invalid_length(1, &self))?;
        let storage_hash = seq.next_element()?.ok_or_else(|| A::Error::invalid_length(2, &self))?;
        Ok(LtHash { accounts_hash, contracts_hash, storage_hash })
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut accounts_hash = None;
        let mut contracts_hash = None;
        let mut storage_hash = None;

        while let Some(key) = map.next_key::<&str>()? {
            match key {
                "accounts_hash" => set_once(&mut accounts_hash, map.next_value()?, key)?,
                "contracts_hash" => set_once(&mut contracts_hash, map.next_value()?, key)?,
                "storage_hash" => set_once(&mut storage_hash, map.next_value()?, key)?,
                _ => {
                    let _ = map.next_value::<IgnoredAny>()?;
                }
            }
        }

        Ok(LtHash {
            accounts_hash: accounts_hash.ok_or_else(|| A::Error::missing_field("accounts_hash"))?,
            contracts_hash: contracts_hash.ok_or_else(|| A::Error::missing_field("contracts_hash"))?,
            storage_hash: storage_hash.ok_or_else(|| A::Error::missing_field("storage_hash"))?,
        })
    }
}

struct FixedBytesExpected<const N: usize>;

impl<const N: usize> fmt::Display for FixedBytesExpected<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "exactly {N} bytes")
    }
}

impl<const N: usize> Expected for FixedBytesExpected<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "exactly {N} bytes")
    }
}

fn set_once<T, E>(slot: &mut Option<T>, value: T, field: &'static str) -> Result<(), E>
where
    E: DeError,
{
    if slot.is_some() {
        return Err(E::duplicate_field(field));
    }
    *slot = Some(value);
    Ok(())
}
