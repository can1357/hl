#![allow(dead_code)]

use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use tiny_keccak::{Hasher, Keccak};

pub type Digest32 = [u8; 32];
pub type AddressBytes = [u8; 20];

const KECCAK256_LEN: usize = 32;
const HARD_LINK_TMP_DIR: &str = "utils_hard_link_and_replace";

static NEXT_HARD_LINK_TMP: AtomicU64 = AtomicU64::new(0);

pub fn encode_rmp_named<T>(value: &T) -> Result<Vec<u8>, rmp_serde::encode::Error>
where
    T: Serialize + ?Sized,
{
    let mut out = Vec::new();
    {
        let mut serializer = rmp_serde::Serializer::new(&mut out).with_struct_map();
        value.serialize(&mut serializer)?;
    }
    Ok(out)
}

pub fn hash<T>(value: &T) -> Digest32
where
    T: Serialize + ?Sized,
{
    let encoded = encode_rmp_named(value).unwrap();
    keccak256(&encoded)
}

pub fn try_hash<T>(value: &T) -> Result<Digest32, rmp_serde::encode::Error>
where
    T: Serialize + ?Sized,
{
    let encoded = encode_rmp_named(value)?;
    Ok(keccak256(&encoded))
}

pub fn blake3_hash<T>(value: &T) -> Digest32
where
    T: Serialize + ?Sized,
{
    let encoded = encode_rmp_named(value).unwrap();
    blake3_256(&encoded)
}

pub fn keccak256(bytes: &[u8]) -> Digest32 {
    let mut out = [0u8; KECCAK256_LEN];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut out);
    out
}

pub fn blake3_256(bytes: &[u8]) -> Digest32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

// Recovered as a special monomorph before the common hash body: collect string
// slices from an unordered table, sort them, then hash the ordered MessagePack.
pub fn hash_sorted_str_set(values: &HashSet<String>) -> Digest32 {
    let mut sorted: Vec<&str> = values.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    hash(&sorted)
}

pub fn keccak_rmp_u64_triplet(a: u64, b: u64, c: u64) -> Digest32 {
    hash(&(a, b, c))
}

pub fn keccak_rmp_u64_h256_hex(n: u64, h256: &Digest32) -> Digest32 {
    hash(&(n, HexH256(h256)))
}

pub fn blake3_rmp_u64_h256_hex(n: u64, h256: &Digest32) -> Digest32 {
    blake3_hash(&(n, HexH256(h256)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenDetails<'a> {
    pub name: &'a str,
    pub sz_decimals: u8,
    pub wei_decimals: u8,
}

impl Serialize for TokenDetails<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut st = serializer.serialize_struct("TokenDetails", 3)?;
        st.serialize_field("name", self.name)?;
        st.serialize_field("szDecimals", &self.sz_decimals)?;
        st.serialize_field("weiDecimals", &self.wei_decimals)?;
        st.end()
    }
}

pub fn keccak_rmp_token_details_with_nonce(details: TokenDetails<'_>, nonce: u64) -> Digest32 {
    hash(&(details, nonce))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateVaultPayload<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub initial_usd: u64,
    pub nonce: u64,
    pub frozen_user: Option<AddressBytes>,
}

impl Serialize for CreateVaultPayload<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let field_count = 4 + usize::from(self.frozen_user.is_some());
        let mut st = serializer.serialize_struct("CreateVault", field_count)?;
        st.serialize_field("name", self.name)?;
        st.serialize_field("description", self.description)?;
        st.serialize_field("initialUsd", &self.initial_usd)?;
        st.serialize_field("nonce", &self.nonce)?;
        if let Some(address) = &self.frozen_user {
            st.serialize_field("frozenUser", &HexAddress(address))?;
        }
        st.end()
    }
}

pub fn keccak_rmp_address_create_vault(
    depositor: &AddressBytes,
    payload: &CreateVaultPayload<'_>,
) -> Digest32 {
    hash(&(HexAddress(depositor), payload))
}

pub struct HexH256<'a>(pub &'a Digest32);
pub struct HexAddress<'a>(pub &'a AddressBytes);

impl Serialize for HexH256<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut out = [0u8; 66];
        write_prefixed_lower_hex(self.0, &mut out);
        // SAFETY: `write_prefixed_lower_hex` writes only ASCII `0x` and hex digits.
        let s = unsafe { std::str::from_utf8_unchecked(&out) };
        serializer.serialize_str(s)
    }
}

impl Serialize for HexAddress<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut out = [0u8; 42];
        write_prefixed_lower_hex(self.0, &mut out);
        // SAFETY: `write_prefixed_lower_hex` writes only ASCII `0x` and hex digits.
        let s = unsafe { std::str::from_utf8_unchecked(&out) };
        serializer.serialize_str(s)
    }
}

fn write_prefixed_lower_hex(bytes: &[u8], out: &mut [u8]) {
    debug_assert_eq!(out.len(), bytes.len() * 2 + 2);
    out[0] = b'0';
    out[1] = b'x';

    for (idx, byte) in bytes.iter().copied().enumerate() {
        out[2 + idx * 2] = nybble_to_hex(byte >> 4);
        out[3 + idx * 2] = nybble_to_hex(byte & 0x0f);
    }
}

#[inline]
const fn nybble_to_hex(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

pub type HardLinkReplaceResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

// The recovered routine compares `(st_dev, st_ino)` first. If the paths already
// name the same inode it returns success without touching the filesystem;
// otherwise it hard-links through a unique path under `utils_hard_link_and_replace/`
// and then moves that link into place.
pub fn hard_link_and_replace(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> HardLinkReplaceResult<()> {
    let src = src.as_ref();
    let dst = dst.as_ref();

    if same_file(src, dst) {
        return Ok(());
    }

    let tmp = next_hard_link_tmp_path();
    ensure_parent_dir(&tmp)?;
    fs::hard_link(src, &tmp)?;

    let move_result = (|| {
        ensure_parent_dir(dst)?;
        move_path(&tmp, dst)
    })();

    if move_result.is_err() {
        let _ = fs::remove_file(&tmp);
    }

    move_result
}

#[cfg(unix)]
fn same_file(a: &Path, b: &Path) -> bool {
    let (Ok(a), Ok(b)) = (fs::metadata(a), fs::metadata(b)) else {
        return false;
    };
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn next_hard_link_tmp_path() -> PathBuf {
    let seq = NEXT_HARD_LINK_TMP.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    Path::new(HARD_LINK_TMP_DIR).join(format!("{now}_{}_{seq}", std::process::id()))
}

fn ensure_parent_dir(path: &Path) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    fs::create_dir_all(parent)
}

fn move_path(src: &Path, dst: &Path) -> HardLinkReplaceResult<()> {
    let status = Command::new("mv").arg(src).arg(dst).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "mv {} {} failed with {status}",
            src.display(),
            dst.display()
        )
        .into())
    }
}
