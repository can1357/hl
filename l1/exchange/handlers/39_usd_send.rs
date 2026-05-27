#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type Nonce = u64;
pub type TimestampMillis = u64;
pub type Usd6 = i64;

pub const HANDLER_EA: u64 = 0x1F64_A40;
pub const CORE_HELPER_EA: u64 = 0x2710_530;
pub const FEE_HELPER_EA: u64 = 0x2710_1A0;
pub const PROFILE_LOOKUP_EA: u64 = 0x2755_400;

pub const STATUS_OK: u16 = 390;
pub const ERR_INSUFFICIENT_WITHDRAWABLE_BALANCE: u16 = 51;
pub const ERR_NONCE_ALREADY_USED: u16 = 90;
pub const ERR_FIRST_DEX_SPLIT_NOT_PROFITABLE: u16 = 91;
pub const ERR_NONCE_OVERFLOW: u16 = 198;
pub const ERR_INVALID_DESTINATION: u16 = 182;
pub const ERR_SELF_TRANSFER: u16 = 222;
pub const ERR_ZERO_AMOUNT: u16 = 49;
pub const ERR_STRING_TOO_LONG: u16 = 323;
pub const ERR_RESERVED_DESTINATION: u16 = 330;
pub const MAX_WIRE_STRING_LEN: usize = 100;
pub const FIRST_DEX_FEE_USD6: Usd6 = 1_000_000;
pub const USDC_DECIMALS: u8 = 6;

const RESERVED_DESTINATION_ALL_22: Address = [0x22; 20];
const RESERVED_DESTINATION_20_PREFIX: Address = {
    let mut out = [0u8; 20];
    out[0] = 0x20;
    out
};

/// Recovered from the string-based serializer and the handler field accesses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsdSendAction {
    pub destination: String,
    pub amount: String,
    /// Consumed by the shared signed-action verifier before `sub_1F64A40` runs.
    pub signature_chain_idents: Vec<u64>,
    /// The generic user-action path reserves this as the signer nonce before the
    /// handler body executes.
    pub time: TimestampMillis,
    /// Shared signer-domain validation consumes this before the handler body runs.
    pub hyperliquid_chain: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerReason {
    UsdSendDirect,
    UsdSendFirstDexFee,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerEvent {
    pub from: Address,
    pub to: Address,
    pub usd6: Usd6,
    pub reason: LedgerReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeeRecipient {
    pub user: Address,
    /// Weight used by the first-dex fee distributor.
    pub weight: f64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct UsdSendFeePolicy {
    /// `sub_27101A0` returns zero for destinations in these synthetic-address ranges.
    pub fee_exempt_synthetic_destinations: BTreeSet<Address>,
    /// [INFERENCE] Matches the table at `exchange+1472` walked before the fee is charged.
    pub fee_exempt_destinations_primary: BTreeSet<Address>,
    /// [INFERENCE] Matches the secondary exemption table at `exchange+792`.
    pub fee_exempt_destinations_secondary: BTreeSet<Address>,
    /// [INFERENCE] `sub_2755400(sender)+61` jumps directly to the fee-charging path.
    pub force_fee_sender_profiles: BTreeSet<Address>,
    /// [INFERENCE] Singleton sender exemption read from `exchange+528`.
    pub fee_exempt_sender: Option<Address>,
    /// When true, `0x20 00..00` is also rejected with compact code `330`.
    pub reject_20_prefix_destination: bool,
    pub first_dex_recipients: Vec<FeeRecipient>,
    pub residual_fee_recipient: Address,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExchangeUsdSendState {
    /// Recovered from the hash table at `exchange+1856`; success writes `time * 1000`
    /// back into the sender account record.
    pub last_nonce_ms_by_user: BTreeMap<Address, Nonce>,
    /// The transfer helper debits sender withdrawable balance by the full amount.
    pub withdrawable_usdc_by_user: BTreeMap<Address, Usd6>,
    /// [INFERENCE] Mirrors the sender/destination notional volume updates emitted at
    /// the tail of `sub_2710530`.
    pub ntl_volume_by_user: BTreeMap<Address, Usd6>,
    pub ledger_events: Vec<LedgerEvent>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ExchangeUsdSendCtx {
    pub state: ExchangeUsdSendState,
    pub fee_policy: UsdSendFeePolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsdSendApplied {
    pub sender: Address,
    pub destination: Address,
    pub nonce_ms: Nonce,
    pub gross_usd6: Usd6,
    pub first_dex_fee_usd6: Usd6,
    pub net_destination_usd6: Usd6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsdSendError {
    NonceAlreadyUsed,
    NonceOverflow,
    StringTooLong,
    InvalidDestination,
    ZeroAmount,
    SelfTransfer,
    ReservedDestination,
    FirstDexSplitNotProfitable,
    InsufficientWithdrawableBalance,
    Arithmetic,
}

impl UsdSendError {
    #[inline]
    pub const fn code(self) -> u16 {
        match self {
            Self::NonceAlreadyUsed => ERR_NONCE_ALREADY_USED,
            Self::NonceOverflow => ERR_NONCE_OVERFLOW,
            Self::StringTooLong => ERR_STRING_TOO_LONG,
            Self::InvalidDestination => ERR_INVALID_DESTINATION,
            Self::ZeroAmount => ERR_ZERO_AMOUNT,
            Self::SelfTransfer => ERR_SELF_TRANSFER,
            Self::ReservedDestination => ERR_RESERVED_DESTINATION,
            Self::FirstDexSplitNotProfitable => ERR_FIRST_DEX_SPLIT_NOT_PROFITABLE,
            Self::InsufficientWithdrawableBalance => ERR_INSUFFICIENT_WITHDRAWABLE_BALANCE,
            Self::Arithmetic => ERR_NONCE_OVERFLOW,
        }
    }
}

/// Reconstructs `sub_1F64A40` plus the transfer core at `sub_2710530`.
///
/// Grounded flow:
/// 1. Reject `destination` or `amount` strings at 101+ bytes with `323`.
/// 2. Normalize the action nonce as `time * 1000`; overflow returns `198`, and the
///    sender-local monotonic replay guard rejects `nonce_ms <= last_nonce_ms` with `90`.
/// 3. Parse `amount` as a six-decimal USDC quantity; scaled zero returns `49`.
/// 4. Parse `destination` with `base_address__from_str`; parse failure returns `182`.
/// 5. Reject self-send with `222` and reserved destinations with `330`.
/// 6. Compute a first-dex fee of either `0` or `1_000_000` scaled USDC via
///    `sub_27101A0`; the downstream clearinghouse transfer rejects `amount <= fee`
///    with `91` and insufficient sender balance with `51`.
/// 7. Debit the sender by the gross amount, credit the destination by `amount - fee`,
///    distribute the fee, then persist `last_nonce_ms = time * 1000`.
///
/// The generic signed-action path already consumed `signature_chain_idents`,
/// `hyperliquid_chain`, and the signer-scoped nonce reservation before this handler runs.
pub fn apply_usd_send(
    ctx: &mut ExchangeUsdSendCtx,
    sender: Address,
    action: &UsdSendAction,
) -> Result<UsdSendApplied, UsdSendError> {
    if action.destination.len() > MAX_WIRE_STRING_LEN || action.amount.len() > MAX_WIRE_STRING_LEN {
        return Err(UsdSendError::StringTooLong);
    }

    let nonce_ms = action.time.checked_mul(1_000).ok_or(UsdSendError::NonceOverflow)?;
    let last_nonce_ms = ctx.state.last_nonce_ms_by_user.get(&sender).copied().unwrap_or(0);
    if nonce_ms <= last_nonce_ms {
        return Err(UsdSendError::NonceAlreadyUsed);
    }

    let gross_usd6 = parse_usd6(&action.amount)?;
    if gross_usd6 == 0 {
        return Err(UsdSendError::ZeroAmount);
    }

    let destination = parse_address(&action.destination).map_err(|_| UsdSendError::InvalidDestination)?;
    if destination == sender {
        return Err(UsdSendError::SelfTransfer);
    }
    if is_reserved_destination(destination, ctx.fee_policy.reject_20_prefix_destination) {
        return Err(UsdSendError::ReservedDestination);
    }

    let first_dex_fee_usd6 = ctx.fee_policy.compute_first_dex_fee(&sender, &destination);
    if gross_usd6 <= first_dex_fee_usd6 {
        return Err(UsdSendError::FirstDexSplitNotProfitable);
    }
    let net_destination_usd6 = gross_usd6
        .checked_sub(first_dex_fee_usd6)
        .ok_or(UsdSendError::Arithmetic)?;

    transfer_withdrawable_usdc(&mut ctx.state, sender, destination, gross_usd6, net_destination_usd6)?;
    distribute_first_dex_fee(&mut ctx.state, sender, first_dex_fee_usd6, &ctx.fee_policy)?;

    ctx.state.last_nonce_ms_by_user.insert(sender, nonce_ms);
    add_ntl_volume(&mut ctx.state.ntl_volume_by_user, sender, -gross_usd6)?;
    add_ntl_volume(&mut ctx.state.ntl_volume_by_user, destination, net_destination_usd6)?;

    Ok(UsdSendApplied {
        sender,
        destination,
        nonce_ms,
        gross_usd6,
        first_dex_fee_usd6,
        net_destination_usd6,
    })
}

impl UsdSendFeePolicy {
    pub fn compute_first_dex_fee(&self, sender: &Address, destination: &Address) -> Usd6 {
        if self.fee_exempt_synthetic_destinations.contains(destination) {
            return 0;
        }
        if self.force_fee_sender_profiles.contains(sender) {
            return if is_synthetic_user_address(sender) { 0 } else { FIRST_DEX_FEE_USD6 };
        }
        if self.fee_exempt_destinations_primary.contains(destination)
            || self.fee_exempt_destinations_secondary.contains(destination)
            || *destination == RESERVED_DESTINATION_ALL_22
            || self.fee_exempt_sender.as_ref().is_some_and(|allowed| allowed == sender)
        {
            return 0;
        }
        if is_synthetic_user_address(sender) {
            0
        } else {
            FIRST_DEX_FEE_USD6
        }
    }
}

fn transfer_withdrawable_usdc(
    state: &mut ExchangeUsdSendState,
    sender: Address,
    destination: Address,
    gross_usd6: Usd6,
    net_destination_usd6: Usd6,
) -> Result<(), UsdSendError> {
    let sender_balance = state.withdrawable_usdc_by_user.entry(sender).or_insert(0);
    *sender_balance = sender_balance
        .checked_sub(gross_usd6)
        .ok_or(UsdSendError::InsufficientWithdrawableBalance)?;

    let destination_balance = state.withdrawable_usdc_by_user.entry(destination).or_insert(0);
    *destination_balance = destination_balance
        .checked_add(net_destination_usd6)
        .ok_or(UsdSendError::Arithmetic)?;

    state.ledger_events.push(LedgerEvent {
        from: sender,
        to: destination,
        usd6: net_destination_usd6,
        reason: LedgerReason::UsdSendDirect,
    });
    Ok(())
}

fn distribute_first_dex_fee(
    state: &mut ExchangeUsdSendState,
    sender: Address,
    fee_usd6: Usd6,
    policy: &UsdSendFeePolicy,
) -> Result<(), UsdSendError> {
    if fee_usd6 == 0 {
        return Ok(());
    }

    let mut residue = fee_usd6;
    let total_weight: f64 = policy.first_dex_recipients.iter().map(|entry| entry.weight).sum();
    if total_weight > 0.0 {
        for entry in &policy.first_dex_recipients {
            if entry.weight <= 0.0 {
                continue;
            }
            let share = ((fee_usd6 as f64) * (entry.weight / total_weight)).trunc() as Usd6;
            residue = residue.checked_sub(share).ok_or(UsdSendError::Arithmetic)?;
            credit_fee_recipient(state, sender, entry.user, share)?;
        }
    }

    credit_fee_recipient(state, sender, policy.residual_fee_recipient, residue)
}

fn credit_fee_recipient(
    state: &mut ExchangeUsdSendState,
    sender: Address,
    recipient: Address,
    usd6: Usd6,
) -> Result<(), UsdSendError> {
    if usd6 == 0 {
        return Ok(());
    }
    let recipient_balance = state.withdrawable_usdc_by_user.entry(recipient).or_insert(0);
    *recipient_balance = recipient_balance.checked_add(usd6).ok_or(UsdSendError::Arithmetic)?;
    state.ledger_events.push(LedgerEvent {
        from: sender,
        to: recipient,
        usd6,
        reason: LedgerReason::UsdSendFirstDexFee,
    });
    Ok(())
}

fn add_ntl_volume(map: &mut BTreeMap<Address, Usd6>, user: Address, delta: Usd6) -> Result<(), UsdSendError> {
    let entry = map.entry(user).or_insert(0);
    *entry = entry.checked_add(delta).ok_or(UsdSendError::Arithmetic)?;
    Ok(())
}

fn is_reserved_destination(destination: Address, reject_20_prefix_destination: bool) -> bool {
    destination == RESERVED_DESTINATION_ALL_22
        || (reject_20_prefix_destination && destination == RESERVED_DESTINATION_20_PREFIX)
}

/// `sub_37E51D0` recognizes a few compact synthetic-address ranges and the fee helper
/// waives the first-dex fee when the destination lands inside them.
fn is_synthetic_user_address(address: &Address) -> bool {
    address_in_half_open_range(*address, synthetic_floor(0x30, 0), synthetic_ceiling(0x30, 20_000))
        || address_in_half_open_range(*address, synthetic_floor(0x31, 0), synthetic_ceiling(0x31, 10_000))
        || address_in_half_open_range(*address, synthetic_floor(0x32, 0), synthetic_ceiling(0x32, 999_999))
}

fn address_in_half_open_range(address: Address, floor: Address, ceiling: Address) -> bool {
    address >= floor && address <= ceiling
}

fn synthetic_floor(prefix: u8, tail: u64) -> Address {
    synthetic_addr(prefix, tail)
}

fn synthetic_ceiling(prefix: u8, tail: u64) -> Address {
    synthetic_addr(prefix, tail)
}

fn synthetic_addr(prefix: u8, tail: u64) -> Address {
    let mut out = [0u8; 20];
    out[0] = prefix;
    out[8..16].copy_from_slice(&tail.to_be_bytes());
    out
}

fn parse_usd6(text: &str) -> Result<Usd6, UsdSendError> {
    if text.is_empty() || matches!(text.as_bytes()[0], b'+' | b'-') {
        return Err(UsdSendError::ZeroAmount);
    }

    let mut whole = 0i64;
    let mut frac = 0i64;
    let mut frac_digits = 0u8;
    let mut seen_dot = false;
    let mut seen_digit = false;

    for &byte in text.as_bytes() {
        if byte == b'.' {
            if seen_dot {
                return Err(UsdSendError::ZeroAmount);
            }
            seen_dot = true;
            continue;
        }

        let digit = byte.checked_sub(b'0').ok_or(UsdSendError::ZeroAmount)?;
        if digit > 9 {
            return Err(UsdSendError::ZeroAmount);
        }
        seen_digit = true;
        if seen_dot {
            if frac_digits == USDC_DECIMALS {
                return Err(UsdSendError::ZeroAmount);
            }
            frac = frac
                .checked_mul(10)
                .and_then(|value| value.checked_add(digit as i64))
                .ok_or(UsdSendError::Arithmetic)?;
            frac_digits += 1;
        } else {
            whole = whole
                .checked_mul(10)
                .and_then(|value| value.checked_add(digit as i64))
                .ok_or(UsdSendError::Arithmetic)?;
        }
    }

    if !seen_digit {
        return Err(UsdSendError::ZeroAmount);
    }

    while frac_digits < USDC_DECIMALS {
        frac = frac.checked_mul(10).ok_or(UsdSendError::Arithmetic)?;
        frac_digits += 1;
    }

    whole
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_add(frac))
        .ok_or(UsdSendError::Arithmetic)
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
