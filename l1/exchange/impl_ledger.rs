use std::collections::BTreeMap;

pub type Address = [u8; 20];
pub type TokenId = [u8; 16];
pub type TokenIndex = u64;
pub type Wei = u64;

pub const USDC_TOKEN: TokenIndex = 0;
pub const PURR_TOKEN: TokenIndex = 1;
pub const SPOT_SUCCESS: u16 = 390;
pub const LEDGER_SELF_TRANSFER: u16 = 222;
pub const LEDGER_INSUFFICIENT_BALANCE: u16 = 247;
pub const LEDGER_INVALID_TOKEN: u16 = 248;
pub const LEDGER_SPOT_DISABLED: u16 = 249;
pub const LEDGER_NAME_TOO_LONG: u16 = 323;
pub const LEDGER_ARITHMETIC: u16 = 356;

const OUTCOME_TOKEN_PREFIX: &str = "outcomeToken";
const MAX_LEDGER_STRING_LEN: usize = 100;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenInfo {
    pub token_id: TokenId,
    pub name: String,
    pub wei_decimals: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutcomeTokenRecord {
    /// Recovered from the outcome-token record field read at `+0x20`.
    pub leg0_token: TokenIndex,
    /// Recovered from the outcome-token record field read at `+0x48`.
    pub leg1_token: TokenIndex,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpecialTokenClass {
    SpotOrQuote,
    OutcomeLinked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerError {
    InvalidToken { token: String },
    SpotDisabled { token: String },
    NameTooLong,
    AmountInvalid,
    Arithmetic,
    SelfTransfer,
    InsufficientBalance,
}

impl LedgerError {
    pub const fn code(&self) -> u16 {
        match self {
            Self::InvalidToken { .. } => LEDGER_INVALID_TOKEN,
            Self::SpotDisabled { .. } => LEDGER_SPOT_DISABLED,
            Self::NameTooLong => LEDGER_NAME_TOO_LONG,
            Self::AmountInvalid => LEDGER_ARITHMETIC,
            Self::Arithmetic => LEDGER_ARITHMETIC,
            Self::SelfTransfer => LEDGER_SELF_TRANSFER,
            Self::InsufficientBalance => LEDGER_INSUFFICIENT_BALANCE,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerEvent {
    pub from: Address,
    pub to: Address,
    pub token: TokenIndex,
    pub wei: Wei,
    pub reason: LedgerReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerReason {
    SpotSend,
    SubAccountSpotTransfer,
    SystemSpotSend,
}

#[derive(Clone, Debug, Default)]
pub struct ExchangeLedgerState {
    pub spot_disabled: bool,
    pub tokens: Vec<TokenInfo>,
    pub token_id_to_token: BTreeMap<TokenId, TokenIndex>,
    pub spot_or_quote_tokens: BTreeMap<TokenIndex, ()>,
    pub token_to_outcome_market: BTreeMap<TokenIndex, u64>,
    pub outcome_token_records: BTreeMap<u64, OutcomeTokenRecord>,
    pub balances: BTreeMap<(Address, TokenIndex), Wei>,
    pub ledger_events: Vec<LedgerEvent>,
}

impl ExchangeLedgerState {
    /// Ledger token resolver recovered at `0x3c0de00`.
    ///
    /// The call returns `(ok, token)` in registers.  It accepts the two built-ins
    /// `USDC` and `PURR`, canonical `outcomeToken<N>` aliases, and duplicate-safe
    /// `NAME:0x<16-byte-token-id>` aliases whose left side must match the token's
    /// stored name byte-for-byte.
    pub fn resolve_ledger_token_name(&self, token_name: &str) -> Option<TokenIndex> {
        if let Some((display_name, token_id_text)) = token_name.split_once(':') {
            let token_id = parse_token_id_hex16(token_id_text)?;
            let token = *self.token_id_to_token.get(&token_id)?;
            if self.special_token_class(token).is_some() {
                return None;
            }
            let info = self.tokens.get(token as usize)?;
            return (info.name.as_bytes() == display_name.as_bytes()).then_some(token);
        }

        match token_name.as_bytes() {
            b"USDC" => return Some(USDC_TOKEN),
            b"PURR" => return Some(PURR_TOKEN),
            _ => {}
        }

        let suffix = token_name.strip_prefix(OUTCOME_TOKEN_PREFIX)?;
        if suffix.is_empty() {
            return None;
        }
        let outcome_number = parse_canonical_unsigned_decimal(suffix)?;
        let leg = outcome_number % 10;
        if leg > 1 {
            return None;
        }
        let record = self.outcome_token_records.get(&(outcome_number / 10))?;
        Some(if leg == 0 { record.leg0_token } else { record.leg1_token })
    }

    pub fn apply_spot_send(
        &mut self,
        from: Address,
        to: Address,
        token_name: &str,
        amount: &str,
    ) -> Result<(), LedgerError> {
        self.apply_token_transfer(from, to, token_name, amount, LedgerReason::SpotSend)
    }

    pub fn apply_sub_account_spot_transfer(
        &mut self,
        parent_or_subaccount: Address,
        counterparty: Address,
        is_deposit: bool,
        token_name: &str,
        amount: &str,
    ) -> Result<(), LedgerError> {
        let (from, to) = if is_deposit {
            (parent_or_subaccount, counterparty)
        } else {
            (counterparty, parent_or_subaccount)
        };
        self.apply_token_transfer(from, to, token_name, amount, LedgerReason::SubAccountSpotTransfer)
    }

    pub fn apply_system_spot_send(
        &mut self,
        from: Address,
        to: Address,
        token: TokenIndex,
        wei: Wei,
    ) -> Result<(), LedgerError> {
        self.transfer_spot_wei(from, to, token, wei, LedgerReason::SystemSpotSend)
    }

    pub fn apply_token_transfer(
        &mut self,
        from: Address,
        to: Address,
        token_name: &str,
        amount: &str,
        reason: LedgerReason,
    ) -> Result<(), LedgerError> {
        if token_name.len() > MAX_LEDGER_STRING_LEN || amount.len() > MAX_LEDGER_STRING_LEN {
            return Err(LedgerError::NameTooLong);
        }
        if self.spot_disabled {
            return Err(LedgerError::SpotDisabled { token: token_name.to_owned() });
        }
        let token = self
            .resolve_ledger_token_name(token_name)
            .ok_or_else(|| LedgerError::InvalidToken { token: token_name.to_owned() })?;
        let decimals = self.tokens.get(token as usize).map_or(8, |info| info.wei_decimals);
        let wei = parse_amount_to_wei(amount, decimals)?;
        self.transfer_spot_wei(from, to, token, wei, reason)
    }

    pub fn transfer_spot_wei(
        &mut self,
        from: Address,
        to: Address,
        token: TokenIndex,
        wei: Wei,
        reason: LedgerReason,
    ) -> Result<(), LedgerError> {
        if from == to {
            return Err(LedgerError::SelfTransfer);
        }
        self.debit_balance(from, token, wei)?;
        if let Err(err) = self.credit_balance(to, token, wei) {
            let _ = self.credit_balance(from, token, wei);
            return Err(err);
        }
        self.ledger_events.push(LedgerEvent { from, to, token, wei, reason });
        Ok(())
    }

    pub fn credit_balance(&mut self, user: Address, token: TokenIndex, wei: Wei) -> Result<Wei, LedgerError> {
        let entry = self.balances.entry((user, token)).or_insert(0);
        *entry = entry.checked_add(wei).ok_or(LedgerError::Arithmetic)?;
        Ok(*entry)
    }

    pub fn debit_balance(&mut self, user: Address, token: TokenIndex, wei: Wei) -> Result<Wei, LedgerError> {
        let entry = self.balances.entry((user, token)).or_insert(0);
        *entry = entry.checked_sub(wei).ok_or(LedgerError::InsufficientBalance)?;
        Ok(*entry)
    }

    pub fn special_token_class(&self, token: TokenIndex) -> Option<SpecialTokenClass> {
        if self.spot_or_quote_tokens.contains_key(&token) {
            return Some(SpecialTokenClass::SpotOrQuote);
        }
        if let Some(outcome_id) = self.token_to_outcome_market.get(&token) {
            return if self.outcome_token_records.contains_key(outcome_id) {
                Some(SpecialTokenClass::OutcomeLinked)
            } else {
                Some(SpecialTokenClass::SpotOrQuote)
            };
        }
        None
    }
}

pub fn parse_token_id_hex16(mut text: &str) -> Option<TokenId> {
    if let Some(rest) = text.strip_prefix("0x") {
        text = rest;
    }
    if text.len() != 32 {
        return None;
    }

    let mut out = [0u8; 16];
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < 16 {
        let hi = hex_nibble(bytes[2 * i])?;
        let lo = hex_nibble(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_canonical_unsigned_decimal(text: &str) -> Option<u64> {
    if text.is_empty() || text.as_bytes()[0] == b'+' || text.as_bytes()[0] == b'-' {
        return None;
    }
    if text.len() > 1 && text.as_bytes()[0] == b'0' {
        return None;
    }
    let mut value = 0u64;
    for &byte in text.as_bytes() {
        let digit = byte.checked_sub(b'0')?;
        if digit > 9 {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(digit as u64)?;
    }
    (value.to_string().as_bytes() == text.as_bytes()).then_some(value)
}

pub fn parse_amount_to_wei(text: &str, decimals: u8) -> Result<Wei, LedgerError> {
    if text.is_empty() || text.as_bytes()[0] == b'+' || text.as_bytes()[0] == b'-' {
        return Err(LedgerError::AmountInvalid);
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
                return Err(LedgerError::AmountInvalid);
            }
            seen_dot = true;
            continue;
        }
        let digit = byte.checked_sub(b'0').ok_or(LedgerError::AmountInvalid)?;
        if digit > 9 {
            return Err(LedgerError::AmountInvalid);
        }
        seen_digit = true;
        if seen_dot {
            if frac_digits == decimals {
                return Err(LedgerError::AmountInvalid);
            }
            frac = frac.checked_mul(10).and_then(|v| v.checked_add(digit as u64)).ok_or(LedgerError::Arithmetic)?;
            frac_digits += 1;
        } else {
            whole = whole.checked_mul(10).and_then(|v| v.checked_add(digit as u64)).ok_or(LedgerError::Arithmetic)?;
        }
    }

    if !seen_digit {
        return Err(LedgerError::AmountInvalid);
    }
    while frac_digits < decimals {
        frac = frac.checked_mul(10).ok_or(LedgerError::Arithmetic)?;
        frac_digits += 1;
    }
    whole
        .checked_mul(scale)
        .and_then(|v| v.checked_add(frac))
        .ok_or(LedgerError::Arithmetic)
}

fn pow10(decimals: u8) -> Result<u64, LedgerError> {
    let mut value = 1u64;
    let mut remaining = decimals;
    while remaining != 0 {
        value = value.checked_mul(10).ok_or(LedgerError::Arithmetic)?;
        remaining -= 1;
    }
    Ok(value)
}
