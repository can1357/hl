//! Recovered C-chain staking deposit action payload, wire shape, and apply-path gates.
//!
//! Evidence anchors in the current binary:
//! - the action enum serializer arm for case `0x3c` writes `"type": "cDeposit"`;
//! - the action payload serializer writes four payload fields in this order:
//!   `signatureChainId`, `hyperliquidChain`, `wei`, `nonce`;
//! - the binary/RMP serializer emits the same logical data as a five-element
//!   array: `["cDeposit", signatureChainId, hyperliquidChain, wei, nonce]`;
//! - the payload visitor has the diagnostic string `struct CDepositAction with 4 elements`;
//! - the apply path rejects a missing deposit amount before entering state logic,
//!   then runs one of three C-staking validation phases described below.

#![allow(dead_code)]

use core::fmt;

pub type Address = [u8; 20];
pub type Wei = u64;
pub type Nonce = u64;

pub const ACTION_TYPE: &str = "cDeposit";
pub const ACTION_ENUM_NAME: &str = "CDeposit";
pub const PAYLOAD_FIELD_COUNT: usize = 4;
pub const HUMAN_READABLE_FIELD_COUNT_WITH_TYPE: usize = 5;
pub const BINARY_SIGNABLE_ARRAY_LEN: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureChainId(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HyperliquidChain {
    Local = 0,
    Sandbox = 1,
    Testnet = 2,
    Mainnet = 3,
}

impl HyperliquidChain {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Sandbox => "sandbox",
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }

    pub const fn from_wire_discriminant(discriminant: u8) -> Option<Self> {
        match discriminant {
            0 => Some(Self::Local),
            1 => Some(Self::Sandbox),
            2 => Some(Self::Testnet),
            3 => Some(Self::Mainnet),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct CDepositAction {
    /// Serialized as `signatureChainId`.  The serializer treats this as a 32-byte
    /// integer-like value and writes a `0x` hex quantity with leading zero bytes
    /// removed; an all-zero value is written as `0x0`.
    pub signature_chain_id: SignatureChainId,
    /// Serialized as `wei`.
    pub wei: Wei,
    /// Serialized as `nonce`.
    pub nonce: Nonce,
    /// Serialized as `hyperliquidChain` with string values `local`, `sandbox`,
    /// `testnet`, or `mainnet`.  The optimized `Result` layout uses the invalid
    /// discriminant `4` as the decode-error niche, so valid payloads are only 0..=3.
    pub hyperliquid_chain: HyperliquidChain,
}

impl CDepositAction {
    pub const fn new(
        signature_chain_id: SignatureChainId,
        hyperliquid_chain: HyperliquidChain,
        wei: Wei,
        nonce: Nonce,
    ) -> Self {
        Self { signature_chain_id, wei, nonce, hyperliquid_chain }
    }

    pub const fn action_type(&self) -> &'static str {
        ACTION_TYPE
    }

    pub const fn serde_fields() -> [CDepositField; PAYLOAD_FIELD_COUNT] {
        [
            CDepositField::SignatureChainId,
            CDepositField::HyperliquidChain,
            CDepositField::Wei,
            CDepositField::Nonce,
        ]
    }

    /// Binary signable layout recovered from the non-human-readable serializer.
    /// The first byte is the MessagePack fixed-array marker `0x95`, followed by
    /// `"cDeposit"` and the four payload values in derive order.
    pub fn encode_signable_msgpack<W: ByteWriter>(&self, out: &mut W) -> Result<(), W::Error> {
        out.write_byte(0x90 | BINARY_SIGNABLE_ARRAY_LEN)?;
        write_msgpack_str(out, ACTION_TYPE)?;
        write_msgpack_signature_chain_id(out, self.signature_chain_id)?;
        write_msgpack_str(out, self.hyperliquid_chain.as_str())?;
        write_msgpack_u64(out, self.wei)?;
        write_msgpack_u64(out, self.nonce)
    }

    /// Human-readable serializer shape: a five-field map containing `type` plus
    /// the four payload fields.  This mirrors the branch that calls the string
    /// serializer for `type`, `signatureChainId`, `hyperliquidChain`, `wei`, and
    /// `nonce` before writing each value.
    pub fn write_human_readable_json_object<W: fmt::Write>(&self, out: &mut W) -> fmt::Result {
        out.write_str("{\"type\":\"")?;
        out.write_str(ACTION_TYPE)?;
        out.write_str("\",\"signatureChainId\":\"")?;
        write_signature_chain_id_hex(out, self.signature_chain_id)?;
        out.write_str("\",\"hyperliquidChain\":\"")?;
        out.write_str(self.hyperliquid_chain.as_str())?;
        out.write_str("\",\"wei\":")?;
        write_u64_decimal(out, self.wei)?;
        out.write_str(",\"nonce\":")?;
        write_u64_decimal(out, self.nonce)?;
        out.write_char('}')
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CDepositField {
    SignatureChainId,
    HyperliquidChain,
    Wei,
    Nonce,
}

impl CDepositField {
    pub const fn name(self) -> &'static str {
        match self {
            Self::SignatureChainId => "signatureChainId",
            Self::HyperliquidChain => "hyperliquidChain",
            Self::Wei => "wei",
            Self::Nonce => "nonce",
        }
    }

    pub const fn bit(self) -> u8 {
        match self {
            Self::SignatureChainId => 1 << 0,
            Self::HyperliquidChain => 1 << 1,
            Self::Wei => 1 << 2,
            Self::Nonce => 1 << 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CDepositDecodeError {
    DuplicateField(CDepositField),
    MissingField(CDepositField),
    UnknownHyperliquidChain,
    TooManySequenceElements,
    SignatureChainIdTooLong { len: usize },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CDepositSeenFields(u8);

impl CDepositSeenFields {
    pub const fn new() -> Self {
        Self(0)
    }

    pub fn mark(&mut self, field: CDepositField) -> Result<(), CDepositDecodeError> {
        let bit = field.bit();
        if self.0 & bit != 0 {
            return Err(CDepositDecodeError::DuplicateField(field));
        }
        self.0 |= bit;
        Ok(())
    }

    pub fn require_all(self) -> Result<(), CDepositDecodeError> {
        for field in CDepositAction::serde_fields() {
            if self.0 & field.bit() == 0 {
                return Err(CDepositDecodeError::MissingField(field));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CDepositApplyError {
    /// The outer apply wrapper checks an option/tag byte before touching state.
    /// The recovered error code is `251` in the compact result enum.
    MissingDepositAmount,
    /// The state helper returns compact result code `368` when neither recovered
    /// participation set contains the current epoch/key tuple for the user.
    UserNotInRequiredCStakingSet,
    RecheckFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CDepositValidationPhase {
    /// Short path: refresh/recompute the output ledger from existing state only.
    LedgerRefreshOnly,
    /// Status `2` plus the recovered feature/count gates: run the historical
    /// amount precheck, refresh the ledger, and optionally mirror into the second
    /// C-staking table when the feature byte is enabled.
    LegacyStatusTwoPrecheck,
    /// Main deposit path: prove the user is in either recovered C-staking set,
    /// increment per-user/global counters with saturating-at-`u64::MAX` semantics,
    /// apply the deposit amount, refresh the ledger, then run status-specific
    /// rechecks.
    ApplyAndRecheck { finalize_immediately: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CDepositStateFlags {
    /// State byte at the first recovered C-staking gate.  When set for statuses
    /// `>= 4`, the apply path bypasses the main deposit mutation and only refreshes
    /// the ledger output.
    pub gate_high_status_refresh_only: bool,
    /// State byte at the low-status gate.  When set for statuses `< 4`, or when
    /// status is `< 2`, the apply path uses the ledger-refresh-only path.
    pub gate_low_status_refresh_only: bool,
    /// Feature byte used by the status-2 compatibility branch.
    pub enable_status_two_precheck: bool,
}

pub const fn recovered_validation_phase(
    user_status: u8,
    flags: CDepositStateFlags,
    prior_deposit_count: u64,
    direct_amount_supplied: bool,
) -> CDepositValidationPhase {
    if user_status >= 4 {
        if flags.gate_high_status_refresh_only {
            return CDepositValidationPhase::LedgerRefreshOnly;
        }
    } else {
        if flags.gate_low_status_refresh_only || user_status < 2 {
            return CDepositValidationPhase::LedgerRefreshOnly;
        }
        if user_status == 2 {
            if prior_deposit_count >= 2 && !direct_amount_supplied && flags.enable_status_two_precheck {
                return CDepositValidationPhase::LegacyStatusTwoPrecheck;
            }
            return CDepositValidationPhase::LedgerRefreshOnly;
        }
    }

    CDepositValidationPhase::ApplyAndRecheck { finalize_immediately: user_status == 4 }
}

pub fn validate_outer_deposit_amount(amount: Option<Wei>) -> Result<Wei, CDepositApplyError> {
    amount.ok_or(CDepositApplyError::MissingDepositAmount)
}

pub fn validate_c_staking_membership(
    in_primary_set: bool,
    in_secondary_set: bool,
) -> Result<(), CDepositApplyError> {
    if in_primary_set || in_secondary_set {
        Ok(())
    } else {
        Err(CDepositApplyError::UserNotInRequiredCStakingSet)
    }
}

pub const fn increment_deposit_counter(counter: u64) -> u64 {
    if counter == u64::MAX { u64::MAX } else { counter + 1 }
}

pub trait ByteWriter {
    type Error;

    fn write_byte(&mut self, byte: u8) -> Result<(), Self::Error>;
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
}

impl ByteWriter for Vec<u8> {
    type Error = core::convert::Infallible;

    fn write_byte(&mut self, byte: u8) -> Result<(), Self::Error> {
        self.push(byte);
        Ok(())
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

pub fn write_msgpack_str<W: ByteWriter>(out: &mut W, s: &str) -> Result<(), W::Error> {
    let len = s.len();
    if len <= 31 {
        out.write_byte(0xa0 | len as u8)?;
    } else if len <= u8::MAX as usize {
        out.write_byte(0xd9)?;
        out.write_byte(len as u8)?;
    } else if len <= u16::MAX as usize {
        out.write_byte(0xda)?;
        out.write_all(&(len as u16).to_be_bytes())?;
    } else {
        out.write_byte(0xdb)?;
        out.write_all(&(len as u32).to_be_bytes())?;
    }
    out.write_all(s.as_bytes())
}

pub fn write_msgpack_u64<W: ByteWriter>(out: &mut W, value: u64) -> Result<(), W::Error> {
    if value <= 0x7f {
        out.write_byte(value as u8)
    } else if value <= u8::MAX as u64 {
        out.write_byte(0xcc)?;
        out.write_byte(value as u8)
    } else if value <= u16::MAX as u64 {
        out.write_byte(0xcd)?;
        out.write_all(&(value as u16).to_be_bytes())
    } else if value <= u32::MAX as u64 {
        out.write_byte(0xce)?;
        out.write_all(&(value as u32).to_be_bytes())
    } else {
        out.write_byte(0xcf)?;
        out.write_all(&value.to_be_bytes())
    }
}

pub fn write_msgpack_signature_chain_id<W: ByteWriter>(
    out: &mut W,
    chain_id: SignatureChainId,
) -> Result<(), W::Error> {
    let mut first = 0usize;
    while first < 32 && chain_id.0[first] == 0 {
        first += 1;
    }
    let len = if first == 32 {
        3usize
    } else {
        let first_hex_digits = if chain_id.0[first] < 16 { 1 } else { 2 };
        2 + first_hex_digits + (31 - first) * 2
    };

    if len <= 31 {
        out.write_byte(0xa0 | len as u8)?;
    } else {
        out.write_byte(0xd9)?;
        out.write_byte(len as u8)?;
    }

    write_signature_chain_id_hex_bytes(out, chain_id)
}

pub fn write_signature_chain_id_hex<W: fmt::Write>(
    out: &mut W,
    chain_id: SignatureChainId,
) -> fmt::Result {
    out.write_str("0x")?;
    let mut first = 0usize;
    while first < 32 && chain_id.0[first] == 0 {
        first += 1;
    }
    if first == 32 {
        return out.write_char('0');
    }
    let first_byte = chain_id.0[first];
    if first_byte < 16 {
        out.write_char(hex_digit(first_byte))?;
    } else {
        out.write_char(hex_digit(first_byte >> 4))?;
        out.write_char(hex_digit(first_byte & 0x0f))?;
    }
    first += 1;
    while first < 32 {
        let byte = chain_id.0[first];
        out.write_char(hex_digit(byte >> 4))?;
        out.write_char(hex_digit(byte & 0x0f))?;
        first += 1;
    }
    Ok(())
}

fn write_signature_chain_id_hex_bytes<W: ByteWriter>(
    out: &mut W,
    chain_id: SignatureChainId,
) -> Result<(), W::Error> {
    out.write_all(b"0x")?;
    let mut first = 0usize;
    while first < 32 && chain_id.0[first] == 0 {
        first += 1;
    }
    if first == 32 {
        return out.write_byte(b'0');
    }
    let first_byte = chain_id.0[first];
    if first_byte < 16 {
        out.write_byte(hex_digit(first_byte) as u8)?;
    } else {
        out.write_byte(hex_digit(first_byte >> 4) as u8)?;
        out.write_byte(hex_digit(first_byte & 0x0f) as u8)?;
    }
    first += 1;
    while first < 32 {
        let byte = chain_id.0[first];
        out.write_byte(hex_digit(byte >> 4) as u8)?;
        out.write_byte(hex_digit(byte & 0x0f) as u8)?;
        first += 1;
    }
    Ok(())
}

pub const fn hex_digit(nibble: u8) -> char {
    match nibble & 0x0f {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'a',
        11 => 'b',
        12 => 'c',
        13 => 'd',
        14 => 'e',
        _ => 'f',
    }
}

pub fn write_u64_decimal<W: fmt::Write>(out: &mut W, mut value: u64) -> fmt::Result {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    if value == 0 {
        return out.write_char('0');
    }
    while value != 0 {
        i -= 1;
        buf[i] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    // Decimal digits are written by construction.
    out.write_str(core::str::from_utf8(&buf[i..]).unwrap_or(""))
}
