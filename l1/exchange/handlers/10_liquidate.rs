//! Liquidate action handler reconstructed from `0x23E66F0`.
//!
//! The generic signer nonce gate runs before this handler via
//! `impl_execute_action`; this path only performs liquidator authorization,
//! request-shape validation, request normalization, and then forwards the
//! resulting liquidation route into the perp-dex liquidation executor at
//! `0x2725150`.

use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type AssetId = u32;
pub type DexId = u64;
pub type InternalAsset = u64;

pub const STATUS_SUCCESS: u16 = 390;
pub const STATUS_INVALID_LIQUIDATOR: u16 = 35;
pub const STATUS_LIQUIDATE_DUPLICATE_ASSET: u16 = 36;
pub const STATUS_DEFAULT_LIQUIDATOR_IN_ADDITIONAL: u16 = 37;
pub const STATUS_INVALID_INPUT_SPAN: u16 = 323;
pub const STATUS_INVALID_ROUTE_ASSET: u16 = 350;
pub const STATUS_MARKET_NOT_LIQUIDATION_READY: u16 = 97;
pub const STATUS_UNAUTHORIZED_DELEGATE: u16 = 124;

pub const MAX_TOP_LEVEL_REQUESTS: usize = 10_000;
pub const MAX_ASSETS_PER_LIQUIDATOR: usize = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiquidateRequestMode {
    /// `(*payload & 1) == 0` and `*payload != 2`.
    ///
    /// No per-liquidator asset overrides are supplied; the default liquidator is
    /// used for the downstream liquidation plan.
    AllMarkets,
    /// `*payload == 2`.
    ///
    /// The handler classifies one wire asset, verifies that the resolved perp/dex
    /// market is in trading status `3`, and then routes liquidation through the
    /// direct single-market branch inside `process_perp_dex_order`.
    SingleAsset { asset: AssetId },
    /// `(*payload & 1) != 0`.
    ///
    /// Each entry contributes one additional liquidator plus the set of markets it
    /// is allowed to liquidate in this action.
    AdditionalLiquidators(Vec<LiquidatorAssetsRequest>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiquidatorAssetsRequest {
    pub liquidator: Address,
    pub assets: Vec<AssetId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiquidateAction {
    pub mode: LiquidateRequestMode,
    pub liquidated_user: Address,
    pub default_liquidator: Address,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LiquidationRegistry {
    /// Membership gate backed by the tree rooted at `exchange+0x3948`.
    pub active_liquidators: BTreeSet<Address>,
    /// Delegate map backed by the tree rooted at `exchange+0x8d0`.
    ///
    /// When the signer is not the default liquidator, the signer must appear in
    /// this set for the selected default liquidator.
    pub delegate_liquidators: BTreeMap<Address, BTreeSet<Address>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MarketKind {
    Spot,
    Perp,
    Other(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassifiedAsset {
    pub kind: MarketKind,
    pub internal_asset: InternalAsset,
    pub dex: DexId,
    pub market_is_liquidation_ready: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiquidationPlan {
    pub liquidated_user: Address,
    pub default_liquidator: Address,
    pub single_asset: Option<ClassifiedAsset>,
    /// Additional liquidator routing after wire assets are normalized into the
    /// internal market ids consumed by the downstream executor.
    pub additional_liquidator_assets: BTreeMap<Address, Vec<InternalAsset>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiquidateError {
    InvalidLiquidator,
    UnauthorizedDelegate {
        signer: Address,
        default_liquidator: Address,
    },
    DefaultLiquidatorInAdditionalLiquidators,
    DuplicateAssetInAdditionalLiquidators {
        internal_asset: InternalAsset,
    },
    TooManyRequests,
    TooManyAssetsForLiquidator {
        liquidator: Address,
        asset_count: usize,
    },
    InvalidRouteAsset {
        asset: AssetId,
    },
    MarketNotLiquidationReady {
        asset: AssetId,
        internal_asset: InternalAsset,
    },
}

impl LiquidateError {
    #[inline]
    pub const fn status(&self) -> u16 {
        match self {
            Self::InvalidLiquidator => STATUS_INVALID_LIQUIDATOR,
            Self::UnauthorizedDelegate { .. } => STATUS_UNAUTHORIZED_DELEGATE,
            Self::DefaultLiquidatorInAdditionalLiquidators => STATUS_DEFAULT_LIQUIDATOR_IN_ADDITIONAL,
            Self::DuplicateAssetInAdditionalLiquidators { .. } => STATUS_LIQUIDATE_DUPLICATE_ASSET,
            Self::TooManyRequests | Self::TooManyAssetsForLiquidator { .. } => STATUS_INVALID_INPUT_SPAN,
            Self::InvalidRouteAsset { .. } => STATUS_INVALID_ROUTE_ASSET,
            Self::MarketNotLiquidationReady { .. } => STATUS_MARKET_NOT_LIQUIDATION_READY,
        }
    }
}

pub trait LiquidateExchangeCtx {
    fn liquidation_registry(&self) -> &LiquidationRegistry;
    fn classify_wire_asset_id(&self, asset: AssetId) -> Result<ClassifiedAsset, LiquidateError>;
    fn execute_liquidation_plan(&mut self, plan: LiquidationPlan) -> Result<(), LiquidateError>;
}

#[inline]
fn authorize_liquidator(
    registry: &LiquidationRegistry,
    signer: Address,
    default_liquidator: Address,
) -> Result<(), LiquidateError> {
    if !registry.active_liquidators.contains(&default_liquidator) {
        return Err(LiquidateError::InvalidLiquidator);
    }
    if signer == default_liquidator {
        return Ok(());
    }
    let Some(delegates) = registry.delegate_liquidators.get(&default_liquidator) else {
        return Err(LiquidateError::UnauthorizedDelegate {
            signer,
            default_liquidator,
        });
    };
    if delegates.contains(&signer) {
        Ok(())
    } else {
        Err(LiquidateError::UnauthorizedDelegate {
            signer,
            default_liquidator,
        })
    }
}

fn normalize_request_mode<E: LiquidateExchangeCtx>(
    exchange: &E,
    action: &LiquidateAction,
) -> Result<LiquidationPlan, LiquidateError> {
    let mut plan = LiquidationPlan {
        liquidated_user: action.liquidated_user,
        default_liquidator: action.default_liquidator,
        single_asset: None,
        additional_liquidator_assets: BTreeMap::new(),
    };

    match &action.mode {
        LiquidateRequestMode::AllMarkets => {}
        LiquidateRequestMode::SingleAsset { asset } => {
            let classified = exchange.classify_wire_asset_id(*asset)?;
            if classified.kind != MarketKind::Perp {
                return Err(LiquidateError::InvalidRouteAsset { asset: *asset });
            }
            if !classified.market_is_liquidation_ready {
                return Err(LiquidateError::MarketNotLiquidationReady {
                    asset: *asset,
                    internal_asset: classified.internal_asset,
                });
            }
            plan.single_asset = Some(classified);
        }
        LiquidateRequestMode::AdditionalLiquidators(entries) => {
            if entries.len() > MAX_TOP_LEVEL_REQUESTS {
                return Err(LiquidateError::TooManyRequests);
            }

            let mut seen_assets = BTreeSet::<InternalAsset>::new();
            for entry in entries {
                if entry.liquidator == action.default_liquidator {
                    return Err(LiquidateError::DefaultLiquidatorInAdditionalLiquidators);
                }
                if entry.assets.len() > MAX_ASSETS_PER_LIQUIDATOR {
                    return Err(LiquidateError::TooManyAssetsForLiquidator {
                        liquidator: entry.liquidator,
                        asset_count: entry.assets.len(),
                    });
                }

                let mut normalized = Vec::with_capacity(entry.assets.len());
                for &asset in &entry.assets {
                    let classified = exchange.classify_wire_asset_id(asset)?;
                    if classified.kind != MarketKind::Perp {
                        return Err(LiquidateError::InvalidRouteAsset { asset });
                    }
                    if !classified.market_is_liquidation_ready {
                        return Err(LiquidateError::MarketNotLiquidationReady {
                            asset,
                            internal_asset: classified.internal_asset,
                        });
                    }
                    if !seen_assets.insert(classified.internal_asset) {
                        return Err(LiquidateError::DuplicateAssetInAdditionalLiquidators {
                            internal_asset: classified.internal_asset,
                        });
                    }
                    normalized.push(classified.internal_asset);
                }
                plan.additional_liquidator_assets
                    .insert(entry.liquidator, normalized);
            }
        }
    }

    Ok(plan)
}

/// Source-level reconstruction of `l1_exchange_impl_execute_action__liquidate`.
///
/// Observed control flow:
/// 1. Read `liquidated_user` from `action+0x20` and `default_liquidator` from `action+0x34`.
/// 2. Require `default_liquidator` membership in the exchange liquidator registry.
/// 3. If the signer is not `default_liquidator`, require it in the default liquidator's
///    delegate set.
/// 4. Normalize the request mode:
///    - no overrides,
///    - one explicit perp asset,
///    - or a per-liquidator asset-routing table.
/// 5. Reject duplicate assets across the additional-liquidator table and reject any table
///    that includes the default liquidator itself.
/// 6. Forward the resulting plan into the perp-dex liquidation executor at `0x2725150`.
///
/// The downstream executor is responsible for the actual liquidation math, open-order
/// cancellation, book interaction, and position-size deltas.
pub fn liquidate<E: LiquidateExchangeCtx>(
    exchange: &mut E,
    signer: Address,
    action: &LiquidateAction,
) -> Result<(), LiquidateError> {
    authorize_liquidator(exchange.liquidation_registry(), signer, action.default_liquidator)?;
    let plan = normalize_request_mode(exchange, action)?;
    exchange.execute_liquidation_plan(plan)
}
