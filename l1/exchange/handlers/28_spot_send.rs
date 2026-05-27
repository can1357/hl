#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type TokenIndex = u64;
pub type Wei = u64;
pub type TimestampMillis = u64;
pub type SignatureChainIdent = u64;

pub const HANDLER_EA: u64 = 0x1F66_070;
pub const CORE_HELPER_EA: u64 = 0x2714_570;
pub const APPLY_HELPER_EA: u64 = 0x2712_CE0;
pub const PROFILE_LOOKUP_EA: u64 = 0x2755_400;
pub const STATUS_OK: u16 = 390;
pub const ERR_INVALID_DESTINATION: u16 = 182;
pub const ERR_SELF_TRANSFER: u16 = 222;
pub const ERR_INVALID_TOKEN: u16 = 248;
/// Sender-profile gate checked before any string parsing or balance work.
pub const ERR_SPOT_SEND_PROFILE_BLOCKED: u16 = 367;
pub const ERR_TRANSFER_RESTRICTED: u16 = 344;
pub const ERR_SPOT_DISABLED: u16 = 249;
pub const ERR_STRING_TOO_LONG: u16 = 323;
pub const ERR_AMOUNT_INVALID: u16 = 356;
pub const ERR_INSUFFICIENT_BALANCE: u16 = 247;
pub const MAX_WIRE_STRING_LEN: usize = 100;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpotSendAction {
    pub destination: String,
    pub token: String,
    pub amount: String,
    /// Shared signature verification consumes this before the handler body runs.
    pub signature_chain_idents: Vec<SignatureChainIdent>,
    /// The binary forwards this through the shared signed-action path as the action nonce.
    pub time: TimestampMillis,
    /// Shared signer-domain validation consumes this before the handler body runs.
    pub hyperliquid_chain: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenInfo {
    pub index: TokenIndex,
    pub wei_decimals: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerReason {
    SpotSend,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerEvent {
    pub from: Address,
    pub to: Address,
    pub token: TokenIndex,
    pub wei: Wei,
    pub reason: LedgerReason,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExchangeLedgerState {
    pub spot_disabled: bool,
    pub token_by_name: BTreeMap<String, TokenInfo>,
    pub balances: BTreeMap<(Address, TokenIndex), Wei>,
    pub ledger_events: Vec<LedgerEvent>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExchangeSpotSendCtx {
    pub ledger: ExchangeLedgerState,
    /// `sub_2755400(...)+60` drives the leading feature gate.
    pub sender_profile_class: BTreeMap<Address, u8>,
    /// Matches the `profile_class == 3` branch guarded by `exchange[91][1]`.
    pub profile_class_3_enabled: bool,
    /// Matches the `profile_class > 3` branch guarded by `exchange[91][0]`.
    pub profile_class_4_plus_enabled: bool,
    /// [INFERENCE] The shared transfer core rejects these sender/token pairs with `344`.
    pub blocked_sender_tokens: BTreeSet<(Address, TokenIndex)>,
    /// [INFERENCE] The shared transfer core rejects these destination/token pairs with `344`.
    pub blocked_destination_tokens: BTreeSet<(Address, TokenIndex)>,
    /// [INFERENCE] `sub_2712CE0` records transfer-side volume/wei deltas after the balance move.
    pub sent_volume_by_user_token: BTreeMap<(Address, TokenIndex), Wei>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpotSendApplied {
    pub from: Address,
    pub to: Address,
    pub token: TokenIndex,
    pub wei: Wei,
    pub nonce_ms: TimestampMillis,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SpotSendError {
    ProfileBlocked,
    InvalidDestination,
    StringTooLong,
    InvalidToken,
    SpotDisabled,
    AmountInvalid,
    TransferRestricted,
    SelfTransfer,
    InsufficientBalance,
    Arithmetic,
}

impl SpotSendError {
    #[inline]
    pub const fn code(&self) -> u16 {
        match self {
            Self::ProfileBlocked => ERR_SPOT_SEND_PROFILE_BLOCKED,
            Self::InvalidDestination => ERR_INVALID_DESTINATION,
            Self::StringTooLong => ERR_STRING_TOO_LONG,
            Self::InvalidToken => ERR_INVALID_TOKEN,
            Self::SpotDisabled => ERR_SPOT_DISABLED,
            Self::AmountInvalid => ERR_AMOUNT_INVALID,
            Self::TransferRestricted => ERR_TRANSFER_RESTRICTED,
            Self::SelfTransfer => ERR_SELF_TRANSFER,
            Self::InsufficientBalance => ERR_INSUFFICIENT_BALANCE,
            Self::Arithmetic => ERR_AMOUNT_INVALID,
        }
    }
}

/// Reconstructs `sub_1F66070`.
///
/// Observed handler flow:
/// 1. Lookup the sender profile with `sub_2755400` and reject with `367` when the
///    matching exchange feature bit is off.
/// 2. Bound `destination`, `token`, and `amount` to `< 101` bytes; each failure returns `323`.
/// 3. Parse `destination` with `base_address__from_str`; parse failure returns `182`.
/// 4. Forward `(sender, destination, token string, amount string, time)` into the shared
///    spot-transfer core at `0x2714570`.
/// 5. On success the wrapper returns the outer variant tag `13`; otherwise it returns tag `14`
///    with the compact error payload copied from the shared core.
///
/// The generic signed-action path reserves `action.time` as the signer nonce before this handler
/// runs, so `signature_chain_idents` and `hyperliquid_chain` are not consumed directly here.
pub fn apply_spot_send(
    ctx: &mut ExchangeSpotSendCtx,
    sender: Address,
    action: &SpotSendAction,
) -> Result<SpotSendApplied, SpotSendError> {
    validate_sender_profile_gate(ctx, &sender)?;

    if action.destination.len() > MAX_WIRE_STRING_LEN
        || action.token.len() > MAX_WIRE_STRING_LEN
        || action.amount.len() > MAX_WIRE_STRING_LEN
    {
        return Err(SpotSendError::StringTooLong);
    }

    let destination = parse_address(&action.destination).map_err(|_| SpotSendError::InvalidDestination)?;
    let (token, wei) = ctx.ledger.resolve_transfer(&action.token, &action.amount)?;

    if ctx.blocked_sender_tokens.contains(&(sender, token))
        || ctx.blocked_destination_tokens.contains(&(destination, token))
    {
        return Err(SpotSendError::TransferRestricted);
    }

    ctx.ledger.transfer_spot_wei(sender, destination, token, wei)?;
    ctx.sent_volume_by_user_token
        .entry((sender, token))
        .and_modify(|total| *total = total.saturating_add(wei))
        .or_insert(wei);

    Ok(SpotSendApplied {
        from: sender,
        to: destination,
        token,
        wei,
        nonce_ms: action.time,
    })
}

fn validate_sender_profile_gate(
    ctx: &ExchangeSpotSendCtx,
    sender: &Address,
) -> Result<(), SpotSendError> {
    match ctx.sender_profile_class.get(sender).copied().unwrap_or(0) {
        0..=2 => Ok(()),
        3 if ctx.profile_class_3_enabled => Ok(()),
        4..=u8::MAX if ctx.profile_class_4_plus_enabled => Ok(()),
        _ => Err(SpotSendError::ProfileBlocked),
    }
}

impl ExchangeLedgerState {
    pub fn resolve_transfer(&self, token_name: &str, amount: &str) -> Result<(TokenIndex, Wei), SpotSendError> {
        if self.spot_disabled {
            return Err(SpotSendError::SpotDisabled);
        }
        let Some(token) = self.token_by_name.get(token_name).copied() else {
            return Err(SpotSendError::InvalidToken);
        };
        let wei = parse_amount_to_wei(amount, token.wei_decimals)?;
        Ok((token.index, wei))
    }

    pub fn transfer_spot_wei(
        &mut self,
        from: Address,
        to: Address,
        token: TokenIndex,
        wei: Wei,
    ) -> Result<(), SpotSendError> {
        if from == to {
            return Err(SpotSendError::SelfTransfer);
        }

        let from_entry = self.balances.entry((from, token)).or_insert(0);
        *from_entry = from_entry.checked_sub(wei).ok_or(SpotSendError::InsufficientBalance)?;

        let to_entry = self.balances.entry((to, token)).or_insert(0);
        if let Some(next) = to_entry.checked_add(wei) {
            *to_entry = next;
        } else {
            let refund = self.balances.entry((from, token)).or_insert(0);
            *refund = refund.checked_add(wei).ok_or(SpotSendError::Arithmetic)?;
            return Err(SpotSendError::Arithmetic);
        }

        self.ledger_events.push(LedgerEvent {
            from,
            to,
            token,
            wei,
            reason: LedgerReason::SpotSend,
        });
        Ok(())
    }
}

pub fn parse_amount_to_wei(text: &str, decimals: u8) -> Result<Wei, SpotSendError> {
    if text.is_empty() || matches!(text.as_bytes()[0], b'+' | b'-') {
        return Err(SpotSendError::AmountInvalid);
    }

    let scale = pow10(decimals)?;
    let mut whole = 0u64;
    let mut frac = 0u64;
    let mut frac_digits = 0u8;
    let mut seen_dot = false;
    let mut seen_digit = false;

    for &byte in text.as_bytes() {
        if byte == b'.' {
            if seen_dot {
                return Err(SpotSendError::AmountInvalid);
            }
            seen_dot = true;
            continue;
        }

        let digit = byte.checked_sub(b'0').ok_or(SpotSendError::AmountInvalid)?;
        if digit > 9 {
            return Err(SpotSendError::AmountInvalid);
        }

        seen_digit = true;
        if seen_dot {
            if frac_digits == decimals {
                return Err(SpotSendError::AmountInvalid);
            }
            frac = frac
                .checked_mul(10)
                .and_then(|value| value.checked_add(digit as u64))
                .ok_or(SpotSendError::Arithmetic)?;
            frac_digits += 1;
        } else {
            whole = whole
                .checked_mul(10)
                .and_then(|value| value.checked_add(digit as u64))
                .ok_or(SpotSendError::Arithmetic)?;
        }
    }

    if !seen_digit {
        return Err(SpotSendError::AmountInvalid);
    }

    while frac_digits < decimals {
        frac = frac.checked_mul(10).ok_or(SpotSendError::Arithmetic)?;
        frac_digits += 1;
    }

    whole
        .checked_mul(scale)
        .and_then(|value| value.checked_add(frac))
        .ok_or(SpotSendError::Arithmetic)
}

fn pow10(decimals: u8) -> Result<u64, SpotSendError> {
    let mut out = 1u64;
    let mut remaining = decimals;
    while remaining != 0 {
        out = out.checked_mul(10).ok_or(SpotSendError::Arithmetic)?;
        remaining -= 1;
    }
    Ok(out)
}

fn parse_address(value: &str) -> Result<Address, ()> {
    let bytes = value.as_bytes();
    if bytes.len() < 2 {
        return Err(());
    }

    let body = if bytes.starts_with(b"0x") { &value[2..] } else { value };
    if body.len() < 40 {
        return Err(());
    }

    let padding_len = body.len() - 40;
    if !body[..padding_len].chars().all(|ch| ch == '0') {
        return Err(());
    }

    let mut hex = &body[padding_len..];
    if hex.as_bytes().starts_with(b"0x") {
        hex = &hex[2..];
    }

    let mut decoder = HexByteDecoder { input: hex, pos: 0 };
    let mut out = [0u8; 20];
    for slot in &mut out {
        *slot = match decoder.next_byte()? {
            Some(byte) => byte,
            None => return Err(()),
        };
    }
    if decoder.next_byte()?.is_some() {
        return Err(());
    }
    Ok(out)
}

struct HexByteDecoder<'a> {
    input: &'a str,
    pos: usize,
}

impl HexByteDecoder<'_> {
    fn next_byte(&mut self) -> Result<Option<u8>, ()> {
        let Some((hi, _)) = self.next_nibble()? else {
            return Ok(None);
        };
        let Some((lo, _)) = self.next_nibble()? else {
            return Err(());
        };
        Ok(Some((hi << 4) | lo))
    }

    fn next_nibble(&mut self) -> Result<Option<(u8, usize)>, ()> {
        while self.pos < self.input.len() {
            let byte = self.input.as_bytes()[self.pos];
            let index = self.pos;
            self.pos += 1;

            let nibble = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                b'\t' | b'\n' | b'\r' | b' ' => continue,
                _ => return Err(()),
            };
            return Ok(Some((nibble, index)));
        }
        Ok(None)
    }
}
