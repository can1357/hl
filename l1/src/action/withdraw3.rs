//! Recovered bridge withdrawal action payload, validation gates, and signable bytes.
//!
//! Current binary evidence ties the recovered apply wrappers to compact result tags
//! `13`/`14`, a success sentinel `390`, and the bridge-withdrawal state helper
//! returning compact error `368` when the current user is not accepted by either
//! recovered participation set.  Local action tables identify variant `0x2e` as
//! `Withdraw3` with fields `destination`, `usd`, `nonce`, and `signatureChainId`.

#![allow(dead_code)]

use core::fmt;

pub type Address = [u8; 20];
pub type Usd = u64;
pub type Nonce = u64;

pub const ACTION_TYPE: &str = "withdraw3";
pub const ACTION_ENUM_NAME: &str = "Withdraw3";
pub const PAYLOAD_FIELD_COUNT: usize = 4;
pub const HUMAN_READABLE_FIELD_COUNT_WITH_TYPE: usize = 5;
pub const BINARY_SIGNABLE_ARRAY_LEN: u8 = 5;
pub const COMPACT_SUCCESS_SENTINEL: u16 = 390;
pub const COMPACT_NOT_IN_WITHDRAW_SET: u16 = 368;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SignatureChainId(pub [u8; 32]);

impl SignatureChainId {
    pub const ZERO: Self = Self([0; 32]);

    pub const fn from_u64(value: u64) -> Self {
        let bytes = value.to_be_bytes();
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 8 {
            out[24 + i] = bytes[i];
            i += 1;
        }
        Self(out)
    }

    pub const fn low_u64(self) -> u64 {
        let b = self.0;
        u64::from_be_bytes([b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]])
    }

    pub const fn fits_u64(self) -> bool {
        let mut i = 0;
        while i < 24 {
            if self.0[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Withdraw3Action {
    /// Ethereum/L1 recipient.  The JSON and MessagePack serializers render this
    /// as a prefixed lower-hex address under field `destination`.
    pub destination: Address,
    /// Withdrawal notional under field `usd`.  The apply path rejects zero-value
    /// withdrawals before bridge balance mutation.
    pub usd: Usd,
    /// Action nonce.  Unlike older withdraw-like typed data using `time`,
    /// Withdraw3 carries the nonce in the action payload and the signing suffix;
    /// the two values must match before constructing the signable payload.
    pub nonce: Nonce,
    /// EIP-712 signature chain id.  Recovered sibling serializers emit the same
    /// 32-byte value as a minimal `0x` hex quantity under `signatureChainId`.
    pub signature_chain_id: SignatureChainId,
}

impl Withdraw3Action {
    pub const fn new(
        destination: Address,
        usd: Usd,
        nonce: Nonce,
        signature_chain_id: SignatureChainId,
    ) -> Self {
        Self { destination, usd, nonce, signature_chain_id }
    }

    pub const fn action_type(&self) -> &'static str {
        ACTION_TYPE
    }

    pub const fn serde_fields() -> [Withdraw3Field; PAYLOAD_FIELD_COUNT] {
        [
            Withdraw3Field::Destination,
            Withdraw3Field::Usd,
            Withdraw3Field::Nonce,
            Withdraw3Field::SignatureChainId,
        ]
    }

    pub fn validate(&self) -> Result<(), Withdraw3ValidationError> {
        if self.usd == 0 {
            return Err(Withdraw3ValidationError::ZeroUsd);
        }
        Ok(())
    }

    pub fn validate_signing_context(
        &self,
        context: &Withdraw3SigningContext,
    ) -> Result<(), Withdraw3ValidationError> {
        self.validate()?;
        if self.nonce != context.nonce {
            return Err(Withdraw3ValidationError::NonceMismatch {
                action: self.nonce,
                context: context.nonce,
            });
        }
        Ok(())
    }

    /// Binary signable layout recovered for action payload serializers: a fixed
    /// array containing the action type string and the four payload values in
    /// field order.  The L1 signing suffix is appended by `write_signing_preimage`.
    pub fn encode_signable_msgpack<W: ByteWriter>(&self, out: &mut W) -> Result<(), W::Error> {
        out.write_byte(0x90 | BINARY_SIGNABLE_ARRAY_LEN)?;
        write_msgpack_str(out, ACTION_TYPE)?;
        write_msgpack_address(out, self.destination)?;
        write_msgpack_u64(out, self.usd)?;
        write_msgpack_u64(out, self.nonce)?;
        write_msgpack_signature_chain_id(out, self.signature_chain_id)
    }

    pub fn write_human_readable_json_object<W: fmt::Write>(&self, out: &mut W) -> fmt::Result {
        out.write_str("{\"type\":\"")?;
        out.write_str(ACTION_TYPE)?;
        out.write_str("\",\"destination\":\"")?;
        write_address_hex(out, self.destination)?;
        out.write_str("\",\"usd\":")?;
        write_u64_decimal(out, self.usd)?;
        out.write_str(",\"nonce\":")?;
        write_u64_decimal(out, self.nonce)?;
        out.write_str(",\"signatureChainId\":\"")?;
        write_signature_chain_id_hex(out, self.signature_chain_id)?;
        out.write_str("\"}")
    }

    pub fn write_signing_preimage<W: ByteWriter>(
        &self,
        context: &Withdraw3SigningContext,
        out: &mut W,
    ) -> Result<(), Withdraw3EncodeError<W::Error>> {
        self.validate_signing_context(context).map_err(Withdraw3EncodeError::Validation)?;
        self.encode_signable_msgpack(out).map_err(Withdraw3EncodeError::Write)?;
        write_signing_suffix(out, context).map_err(Withdraw3EncodeError::Write)
    }

    pub fn signing_preimage(
        &self,
        context: &Withdraw3SigningContext,
    ) -> Result<Vec<u8>, Withdraw3EncodeError<core::convert::Infallible>> {
        let mut out = Vec::new();
        self.write_signing_preimage(context, &mut out)?;
        Ok(out)
    }

    pub fn agent_source_byte(chain: HyperliquidChain) -> u8 {
        match chain {
            HyperliquidChain::Mainnet => b'a',
            _ => b'b',
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Withdraw3Field {
    Destination,
    Usd,
    Nonce,
    SignatureChainId,
}

impl Withdraw3Field {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Destination => "destination",
            Self::Usd => "usd",
            Self::Nonce => "nonce",
            Self::SignatureChainId => "signatureChainId",
        }
    }

    pub const fn bit(self) -> u8 {
        match self {
            Self::Destination => 1 << 0,
            Self::Usd => 1 << 1,
            Self::Nonce => 1 << 2,
            Self::SignatureChainId => 1 << 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Withdraw3DecodeError {
    DuplicateField(Withdraw3Field),
    MissingField(Withdraw3Field),
    TooManySequenceElements,
    InvalidAddressLength { len: usize },
    SignatureChainIdTooLong { len: usize },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Withdraw3SeenFields(u8);

impl Withdraw3SeenFields {
    pub const fn new() -> Self {
        Self(0)
    }

    pub fn mark(&mut self, field: Withdraw3Field) -> Result<(), Withdraw3DecodeError> {
        let bit = field.bit();
        if self.0 & bit != 0 {
            return Err(Withdraw3DecodeError::DuplicateField(field));
        }
        self.0 |= bit;
        Ok(())
    }

    pub fn require_all(self) -> Result<(), Withdraw3DecodeError> {
        for field in Withdraw3Action::serde_fields() {
            if self.0 & field.bit() == 0 {
                return Err(Withdraw3DecodeError::MissingField(field));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HyperliquidChain {
    Local = 0,
    Sandbox = 1,
    Testnet = 2,
    Mainnet = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Withdraw3SigningContext {
    pub nonce: Nonce,
    pub vault_address: Option<Address>,
    pub expires_after: Option<u64>,
}

impl Withdraw3SigningContext {
    pub const fn new(nonce: Nonce) -> Self {
        Self { nonce, vault_address: None, expires_after: None }
    }

    pub const fn with_vault(mut self, vault_address: Address) -> Self {
        self.vault_address = Some(vault_address);
        self
    }

    pub const fn with_expires_after(mut self, expires_after: u64) -> Self {
        self.expires_after = Some(expires_after);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Withdraw3ValidationError {
    ZeroUsd,
    NonceMismatch { action: Nonce, context: Nonce },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Withdraw3EncodeError<E> {
    Validation(Withdraw3ValidationError),
    Write(E),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Withdraw3ApplyError {
    UserNotInRequiredWithdrawalSet,
    RecheckFailed,
    ZeroUsd,
    InsufficientBalance,
    BridgeBalanceExceeded,
    WithdrawalTooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Withdraw3ValidationPhase {
    LedgerRefreshOnly,
    LegacyStatusTwoPrecheck,
    ApplyAndRecheck { finalize_immediately: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Withdraw3StateFlags {
    pub gate_high_status_refresh_only: bool,
    pub gate_low_status_refresh_only: bool,
    pub enable_status_two_precheck: bool,
}

pub const fn recovered_validation_phase(
    user_status: u8,
    flags: Withdraw3StateFlags,
    prior_withdraw_count: u64,
    direct_amount_supplied: bool,
) -> Withdraw3ValidationPhase {
    if user_status >= 4 {
        if flags.gate_high_status_refresh_only {
            return Withdraw3ValidationPhase::LedgerRefreshOnly;
        }
    } else {
        if flags.gate_low_status_refresh_only || user_status < 2 {
            return Withdraw3ValidationPhase::LedgerRefreshOnly;
        }
        if user_status == 2 {
            if prior_withdraw_count >= 2 && !direct_amount_supplied && flags.enable_status_two_precheck {
                return Withdraw3ValidationPhase::LegacyStatusTwoPrecheck;
            }
            return Withdraw3ValidationPhase::LedgerRefreshOnly;
        }
    }

    Withdraw3ValidationPhase::ApplyAndRecheck { finalize_immediately: user_status == 4 }
}

pub fn validate_withdrawal_membership(
    in_primary_set: bool,
    in_secondary_set: bool,
) -> Result<(), Withdraw3ApplyError> {
    if in_primary_set || in_secondary_set {
        Ok(())
    } else {
        Err(Withdraw3ApplyError::UserNotInRequiredWithdrawalSet)
    }
}

pub const fn increment_withdrawal_counter(counter: u64) -> u64 {
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

pub fn write_msgpack_address<W: ByteWriter>(out: &mut W, address: Address) -> Result<(), W::Error> {
    out.write_byte(0xd9)?;
    out.write_byte(42)?;
    write_address_hex_bytes(out, address)
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

pub fn write_signing_suffix<W: ByteWriter>(
    out: &mut W,
    context: &Withdraw3SigningContext,
) -> Result<(), W::Error> {
    out.write_all(&context.nonce.to_be_bytes())?;
    match context.vault_address {
        Some(vault_address) => {
            out.write_byte(1)?;
            out.write_all(&vault_address)?;
        }
        None => out.write_byte(0)?,
    }
    if let Some(expires_after) = context.expires_after {
        out.write_byte(0)?;
        out.write_all(&expires_after.to_be_bytes())?;
    }
    Ok(())
}

pub fn write_address_hex<W: fmt::Write>(out: &mut W, address: Address) -> fmt::Result {
    out.write_str("0x")?;
    for byte in address {
        out.write_char(hex_digit(byte >> 4))?;
        out.write_char(hex_digit(byte & 0x0f))?;
    }
    Ok(())
}

fn write_address_hex_bytes<W: ByteWriter>(out: &mut W, address: Address) -> Result<(), W::Error> {
    out.write_all(b"0x")?;
    for byte in address {
        out.write_byte(hex_digit(byte >> 4) as u8)?;
        out.write_byte(hex_digit(byte & 0x0f) as u8)?;
    }
    Ok(())
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
    out.write_str(core::str::from_utf8(&buf[i..]).unwrap_or(""))
}
