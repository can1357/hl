#![allow(dead_code)]

pub type Address = [u8; 20];

pub const OUTCOME_TAG_SUCCESS: u8 = 13;
pub const OUTCOME_TAG_ERROR: u8 = 14;

pub const STATUS_SUCCESS: u16 = 390;
pub const STATUS_MISSING_VALIDATOR: u16 = 145;
pub const STATUS_INPUT_TOO_LONG: u16 = 323;
pub const STATUS_RISK_FREE_RATE_OUT_OF_RANGE: u16 = 320;
pub const MAX_RISK_FREE_RATE_TEXT_LEN: usize = 100;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PackedDateTime {
    pub days_from_ce: i32,
    pub seconds_from_midnight: u32,
    pub micros: u32,
}

/// Single-field action recovered from the `riskFreeRate` serializer string.
///
/// The wrapper clones the field into owned staging memory before validation and
/// passes the staged bytes to a decimal parser helper. The helper name shows that
/// the upstream JSON accepted either a decimal string or a float; by the time the
/// apply path runs, the handler only cares about the staged textual form.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidatorL1StreamAction {
    pub risk_free_rate_text: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct RiskFreeRateSnapshot {
    pub risk_free_rate: f64,
    pub updated_at: PackedDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecimalParseFailure {
    /// Raw helper status bubbled out unchanged by the action handler.
    pub status: u16,
}

/// Recovered state touched by `sub_2706E40`.
///
/// The handler performs two map operations:
/// - a membership probe in a 20-byte-key tree rooted at recovered exchange offset
///   `+0x908`; failure returns `145` before any parsing or mutation;
/// - an insert-or-replace into a second 20-byte-key tree at recovered offset
///   `+0x3268`, storing the new rate together with the exchange's current packed
///   wall-clock timestamp.
pub trait ValidatorL1StreamState {
    fn has_registered_validator(&self, validator: &Address) -> bool;
    fn current_time(&self) -> PackedDateTime;
    fn replace_risk_free_rate(
        &mut self,
        validator: Address,
        next: RiskFreeRateSnapshot,
    ) -> Option<RiskFreeRateSnapshot>;
}

/// Narrow trait for the decimal helper the binary calls through
/// `l1_qtys_mod__parse_decimal_from_str_or_float` plus the follow-on conversion
/// helper at `0x4EAD680`.
///
/// Any helper-side parse/conversion failure is returned to the caller unchanged;
/// the action-specific logic only adds the length cap, validator-membership check,
/// and the final inclusive `[0.0, 1.0]` range gate.
pub trait RiskFreeRateParser {
    fn parse_risk_free_rate(&self, text: &[u8]) -> Result<f64, DecimalParseFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidatorL1StreamError {
    MissingValidator,
    InputTooLong,
    DecimalParse(DecimalParseFailure),
    RiskFreeRateOutOfRange,
}

impl ValidatorL1StreamError {
    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::MissingValidator => STATUS_MISSING_VALIDATOR,
            Self::InputTooLong => STATUS_INPUT_TOO_LONG,
            Self::DecimalParse(failure) => failure.status,
            Self::RiskFreeRateOutOfRange => STATUS_RISK_FREE_RATE_OUT_OF_RANGE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidatorL1StreamOutcome {
    Success,
    Error { status: u16, error: ValidatorL1StreamError },
}

impl ValidatorL1StreamOutcome {
    #[inline]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Success => OUTCOME_TAG_SUCCESS,
            Self::Error { .. } => OUTCOME_TAG_ERROR,
        }
    }
}

/// Recovered handler body for `ValidatorL1Stream` (`0x21E0370`) plus its only
/// action-specific helper (`0x2706E40`).
///
/// High-confidence behavior:
/// 1. Clone the incoming `riskFreeRate` field into owned memory even when the
///    action later fails.
/// 2. Require the caller address to already exist in the exchange-side validator
///    membership tree; otherwise return `145`.
/// 3. Reject staged input longer than 100 bytes with `323`.
/// 4. Parse the staged bytes through the decimal/string-or-float helper and bubble
///    any helper-side failure status unchanged.
/// 5. Convert the parsed decimal to `f64`, then require a finite inclusive range
///    of `0.0 <= risk_free_rate <= 1.0`; otherwise return `320`.
/// 6. Insert or replace the caller's risk-free-rate snapshot with the new rate and
///    the exchange's current packed timestamp.
/// 7. Return outer tag `13` on success, `14` plus the helper/error status on any
///    failure.
pub fn apply_validator_l1_stream<S, P>(
    state: &mut S,
    parser: &P,
    validator: Address,
    action: &ValidatorL1StreamAction,
) -> ValidatorL1StreamOutcome
where
    S: ValidatorL1StreamState,
    P: RiskFreeRateParser,
{
    let staged = action.risk_free_rate_text.as_bytes().to_vec();

    match validate_and_apply_validator_l1_stream(state, parser, validator, &staged) {
        Ok(()) => ValidatorL1StreamOutcome::Success,
        Err(error) => ValidatorL1StreamOutcome::Error {
            status: error.status(),
            error,
        },
    }
}

#[inline]
pub fn validate_and_apply_validator_l1_stream<S, P>(
    state: &mut S,
    parser: &P,
    validator: Address,
    staged_risk_free_rate: &[u8],
) -> Result<(), ValidatorL1StreamError>
where
    S: ValidatorL1StreamState,
    P: RiskFreeRateParser,
{
    if !state.has_registered_validator(&validator) {
        return Err(ValidatorL1StreamError::MissingValidator);
    }

    if staged_risk_free_rate.len() > MAX_RISK_FREE_RATE_TEXT_LEN {
        return Err(ValidatorL1StreamError::InputTooLong);
    }

    let risk_free_rate = parser
        .parse_risk_free_rate(staged_risk_free_rate)
        .map_err(ValidatorL1StreamError::DecimalParse)?;

    if !risk_free_rate.is_finite() || !(0.0..=1.0).contains(&risk_free_rate) {
        return Err(ValidatorL1StreamError::RiskFreeRateOutOfRange);
    }

    state.replace_risk_free_rate(
        validator,
        RiskFreeRateSnapshot {
            risk_free_rate,
            updated_at: state.current_time(),
        },
    );
    Ok(())
}
