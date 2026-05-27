//! ValidatorL1UpdateReferenceOracle handler.
//!
//! Reconstructed from wrapper `sub_27FA570` (EA `0x27FA570`), core helper
//! `sub_2707190`, cooldown gate `sub_325ED00`, external-perp validator
//! `l1_perp_dex__build_external_perp_pxs` (`0x27448F0`), and the clearinghouse
//! oracle mutator `sub_3709040`.
//!
//! The wrapper is thin: it forwards `(out, action, validator, exchange_state)` to
//! the core helper and repacks the generic result envelope. The core path does the
//! real work:
//! 1. prove the caller address belongs to the validator set used for this flow;
//! 2. enforce a per-validator `DexFlowClock` throttle unless that validator is in
//!    `ForceRefresh` mode;
//! 3. reject overly large `oraclePxs` / `externalPerpPxs` vectors before any
//!    heavier work;
//! 4. validate and normalize `externalPerpPxs` against the main perp metadata;
//! 5. mutate clearinghouse `0` oracle state in place.
//!
//! The source below keeps the handler path load-bearing and leaves the larger
//! transitive helpers summarized instead of re-implementing the whole oracle
//! subsystem.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{Duration as ChronoDuration, NaiveDateTime};

pub type Address = [u8; 20];
pub type AssetId = u64;
pub type RawPx = u64;
pub type TimeMillis = u64;

pub const STATUS_SUCCESS: u16 = 390;
pub const STATUS_PERP_DEX_FLOW_THROTTLED: u16 = 120;
pub const STATUS_MISSING_VALIDATOR: u16 = 145;
pub const STATUS_EXPLICIT_MESSAGE: u16 = 224;
pub const STATUS_UNKNOWN_DEX: u16 = 321;
pub const STATUS_BOUNDS: u16 = 323;
pub const MAINNET_DEX_ID: usize = 0;
pub const MAX_ACTION_VEC_LEN: usize = 10_000;
pub const VALIDATOR_UPDATE_MIN_REFRESH_MILLIS: i64 = 2_500;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidatorL1UpdateReferenceOracleAction {
    pub oracle_pxs: Vec<RawPx>,
    pub mark_pxs: Vec<Option<RawPx>>,
    pub external_perp_pxs: Vec<ExternalPerpPx>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExternalPerpPx {
    pub asset: AssetId,
    pub px: RawPx,
    pub flags: u16,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DexFlowStatus {
    #[default]
    Active,
    Paused,
    Deleted,
    ForceRefresh,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DexFlowClock {
    pub status: DexFlowStatus,
    pub last_flow_time: NaiveDateTime,
}

impl DexFlowClock {
    fn record_flow(&mut self, now: NaiveDateTime) -> Result<(), HandlerError> {
        if self.status != DexFlowStatus::ForceRefresh {
            let next_allowed = self.last_flow_time + ChronoDuration::milliseconds(VALIDATOR_UPDATE_MIN_REFRESH_MILLIS);
            if next_allowed > now {
                return Err(HandlerError::Throttled);
            }
        }
        self.last_flow_time = now;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OracleUpdateConfig {
    pub min_update_interval_millis: TimeMillis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleError {
    OraclePriceMustBePositive,
    OraclePriceUpdateTooOften,
    UnexpectedOraclePriceLength { got: usize, expected: usize },
}

#[derive(Clone, Debug, Default)]
pub struct PerpAssetRow {
    pub oracle_px: RawPx,
    pub mark_px: RawPx,
}

#[derive(Clone, Debug, Default)]
pub struct ClearinghouseOracleDomain {
    pub rows: Vec<PerpAssetRow>,
    pub external_perp_pxs: BTreeMap<AssetId, ExternalPerpPx>,
    pub last_update_millis: Option<TimeMillis>,
}

impl ClearinghouseOracleDomain {
    fn apply_validator_reference_oracle_update(
        &mut self,
        now_ms: TimeMillis,
        action: &ValidatorL1UpdateReferenceOracleAction,
        config: OracleUpdateConfig,
    ) -> Result<(), HandlerError> {
        self.set_oracle_prices(now_ms, &action.oracle_pxs, config)?;

        if action.mark_pxs.len() != self.rows.len() {
            return Err(HandlerError::Oracle(OracleError::UnexpectedOraclePriceLength {
                got: action.mark_pxs.len(),
                expected: self.rows.len(),
            }));
        }

        for (local, maybe_px) in action.mark_pxs.iter().copied().enumerate() {
            if let Some(px) = maybe_px {
                validate_positive_price(px)?;
                self.rows[local].mark_px = px;
            }
        }

        for external in action.external_perp_pxs.iter().copied() {
            validate_positive_price(external.px)?;
            self.external_perp_pxs.insert(external.asset, external);
        }

        Ok(())
    }

    fn set_oracle_prices(
        &mut self,
        now_ms: TimeMillis,
        prices: &[RawPx],
        config: OracleUpdateConfig,
    ) -> Result<(), HandlerError> {
        if prices.len() != self.rows.len() {
            return Err(HandlerError::Oracle(OracleError::UnexpectedOraclePriceLength {
                got: prices.len(),
                expected: self.rows.len(),
            }));
        }
        if let Some(last) = self.last_update_millis {
            if now_ms.saturating_sub(last) < config.min_update_interval_millis {
                return Err(HandlerError::Oracle(OracleError::OraclePriceUpdateTooOften));
            }
        }

        for (row, px) in self.rows.iter_mut().zip(prices.iter().copied()) {
            validate_positive_price(px)?;
            row.oracle_px = px;
        }
        self.last_update_millis = Some(now_ms);
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct ValidatorReferenceOracleRuntime {
    /// Membership gate reconstructed from the tree walked at `exchange_state + 2312`.
    pub authorized_validators: BTreeSet<Address>,
    /// Optional per-validator throttle entries reconstructed from `sub_325ED00`.
    pub clocks: BTreeMap<Address, DexFlowClock>,
}

#[derive(Clone, Debug, Default)]
pub struct ExchangeState {
    pub now_ms: TimeMillis,
    pub now_dt: NaiveDateTime,
    pub validator_reference_oracle: ValidatorReferenceOracleRuntime,
    pub clearinghouses: Vec<ClearinghouseOracleDomain>,
    /// Known external perp assets for the main clearinghouse.
    pub external_perp_universe: BTreeSet<AssetId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandlerError {
    MissingValidator,
    Throttled,
    Bounds,
    UnknownDex,
    ExplicitMessage(&'static str),
    Oracle(OracleError),
}

impl HandlerError {
    pub const fn status(&self) -> u16 {
        match self {
            Self::MissingValidator => STATUS_MISSING_VALIDATOR,
            Self::Throttled => STATUS_PERP_DEX_FLOW_THROTTLED,
            Self::Bounds => STATUS_BOUNDS,
            Self::UnknownDex => STATUS_UNKNOWN_DEX,
            Self::ExplicitMessage(_) => STATUS_EXPLICIT_MESSAGE,
            Self::Oracle(OracleError::OraclePriceMustBePositive) => STATUS_EXPLICIT_MESSAGE,
            Self::Oracle(OracleError::OraclePriceUpdateTooOften) => STATUS_PERP_DEX_FLOW_THROTTLED,
            Self::Oracle(OracleError::UnexpectedOraclePriceLength { .. }) => STATUS_EXPLICIT_MESSAGE,
        }
    }
}

pub fn apply_validator_l1_update_reference_oracle(
    state: &mut ExchangeState,
    validator: Address,
    action: &ValidatorL1UpdateReferenceOracleAction,
    config: OracleUpdateConfig,
) -> Result<(), HandlerError> {
    if !state
        .validator_reference_oracle
        .authorized_validators
        .contains(&validator)
    {
        return Err(HandlerError::MissingValidator);
    }

    if let Some(clock) = state.validator_reference_oracle.clocks.get_mut(&validator) {
        clock.record_flow(state.now_dt)?;
    }

    if action.oracle_pxs.len() > MAX_ACTION_VEC_LEN || action.external_perp_pxs.len() > MAX_ACTION_VEC_LEN {
        return Err(HandlerError::Bounds);
    }

    validate_external_perp_pxs(action.external_perp_pxs.as_slice(), &state.external_perp_universe)?;

    let clearinghouse = state
        .clearinghouses
        .get_mut(MAINNET_DEX_ID)
        .ok_or(HandlerError::UnknownDex)?;

    clearinghouse.apply_validator_reference_oracle_update(state.now_ms, action, config)
}

fn validate_external_perp_pxs(
    external_perp_pxs: &[ExternalPerpPx],
    known_assets: &BTreeSet<AssetId>,
) -> Result<(), HandlerError> {
    for external in external_perp_pxs.iter().copied() {
        validate_positive_price(external.px)?;
        if !known_assets.contains(&external.asset) {
            return Err(HandlerError::ExplicitMessage("externalPerpPxs missing perp"));
        }
    }
    Ok(())
}

fn validate_positive_price(px: RawPx) -> Result<(), HandlerError> {
    if px == 0 {
        Err(HandlerError::Oracle(OracleError::OraclePriceMustBePositive))
    } else {
        Ok(())
    }
}

pub mod status {
    pub const APPLIED: u16 = super::STATUS_SUCCESS;
    pub const THROTTLED: u16 = super::STATUS_PERP_DEX_FLOW_THROTTLED;
    pub const MISSING_VALIDATOR: u16 = super::STATUS_MISSING_VALIDATOR;
    pub const EXPLICIT_MESSAGE: u16 = super::STATUS_EXPLICIT_MESSAGE;
    pub const UNKNOWN_DEX: u16 = super::STATUS_UNKNOWN_DEX;
    pub const BOUNDS: u16 = super::STATUS_BOUNDS;
}
