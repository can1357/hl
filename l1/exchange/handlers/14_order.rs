pub type Address = [u8; 20];
pub type AssetId = u32;
pub type OrderId = u64;
pub type WireValue = u64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderActionHandlerInput {
    /// Present when the outer action carries the optional builder-fee envelope.
    /// The handler never inspects the raw fields directly; it forwards the blob
    /// into the builder approval / notional-cap helpers.
    pub builder: Option<BuilderEnvelope>,
    /// Compact order-slice grouping recovered from `order_wire`.
    pub aux: OrderBatchAux,
    /// Raw 56-byte order-wire rows cloned by `l1_exchange_impl_execute_action__order`
    /// before execution enters the shared batch core.
    pub orders: Vec<OrderWireRow>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuilderEnvelope {
    pub raw_words: [u64; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderBatchAux {
    /// `0 = na`, `1 = normalTpsl`, `2 = positionTpsl`, `3 = na + extended_index`.
    pub kind: u32,
    /// Recovered from `encoded >= 3` in `order_wire::decode_custom_slice`.
    pub extended_index: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderWireRow {
    pub asset: AssetId,
    pub is_buy: bool,
    pub limit_px: WireValue,
    pub sz: WireValue,
    pub reduce_only: bool,
    pub order_type: OrderType,
    pub cloid: Option<[u8; 16]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderType {
    Limit { tif: TimeInForce },
    Trigger {
        is_market: bool,
        trigger_px: WireValue,
        tpsl: TpSl,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeInForce {
    Alo,
    Ioc,
    Gtc,
    FrontendMarket,
    LiquidationMarket,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TpSl {
    Tp,
    Sl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderDomain {
    MainPerpLike,
    SpotOrExtended,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupingMode {
    Na,
    NormalTpsl,
    PositionTpsl,
    ExtendedNa { extended_index: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidatedOrderKind {
    RestingOrImmediate,
    Trigger,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedOrder {
    pub asset: AssetId,
    pub is_buy: bool,
    pub limit_px: WireValue,
    pub sz: WireValue,
    pub reduce_only: bool,
    pub kind: ValidatedOrderKind,
    /// The shared core checks this before refreshing perp oracle context and before
    /// stitching TP/SL peers back into the book.
    pub helper_flag: bool,
    pub cloid: Option<[u8; 16]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedOrderBatch {
    pub domain: OrderDomain,
    pub grouping: GroupingMode,
    pub builder: Option<BuilderEnvelope>,
    pub orders: Vec<ValidatedOrder>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrderHandlerStep {
    RefreshPerpOracle { asset: AssetId },
    ExecuteIndependent { asset: AssetId },
    ExecuteBracketLeader { asset: AssetId },
    ExecuteBracketChild { asset: AssetId },
    LinkPeerOrders { asset: AssetId, first: OrderId, second: OrderId },
    FinalizeExtendedNa { extended_index: u32, spot_path: bool },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderHandlerPlan {
    pub grouping: GroupingMode,
    pub steps: Vec<OrderHandlerStep>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandlerError {
    pub status: u16,
}

pub const STATUS_OK: u16 = 390;
pub const STATUS_ORDERS_EMPTY: u16 = 106;
pub const STATUS_MIXED_OUTER_ASSETS: u16 = 107;
pub const STATUS_INVALID_ATTACHED_FLAG: u16 = 108;
pub const STATUS_TOO_MANY_ATTACHED_ORDERS: u16 = 109;
pub const STATUS_INVALID_GROUPING_LEADER: u16 = 110;
pub const STATUS_INVALID_GROUPING_CHILD: u16 = 111;
pub const STATUS_INVALID_GROUPING_ASSET: u16 = 112;
pub const STATUS_NON_MAIN_PERP_SPOT_ASSET_OUT_OF_RANGE: u16 = 178;
pub const STATUS_ORDER_WIRE_NTL_TOO_LARGE: u16 = 180;
pub const STATUS_GROUPING_KIND_INVALID_FOR_SPOT_PATH: u16 = 245;
pub const STATUS_BUILDER_APPROVAL_MISSING: u16 = 296;
pub const STATUS_BUILDER_ORDER_COUNT_TOO_LARGE: u16 = 297;

/// Recovered from `0x1EEE7C0 -> 0x271E730`.
///
/// The entry wrapper does only two real things:
/// - deep-clone the `Vec<OrderWireRow>` payload into an owned scratch buffer;
/// - forward the optional builder envelope, compact-slice aux (`kind` + `extended_index`),
///   and cloned rows into the shared order-batch executor.
pub fn l1_exchange_impl_execute_action__order(input: &OrderActionHandlerInput) -> Result<OrderHandlerPlan, HandlerError> {
    let cloned_orders = input.orders.clone();
    let prepared = prepare_order_batch(input.builder, input.aux, &cloned_orders)?;
    Ok(build_execution_plan(&prepared))
}

pub fn prepare_order_batch(
    builder: Option<BuilderEnvelope>,
    aux: OrderBatchAux,
    orders: &[OrderWireRow],
) -> Result<PreparedOrderBatch, HandlerError> {
    let first = orders.first().ok_or(HandlerError {
        status: STATUS_ORDERS_EMPTY,
    })?;

    let domain = if (10_000..100_000_000).contains(&first.asset) || first.asset >= 100_000_000 {
        OrderDomain::SpotOrExtended
    } else {
        OrderDomain::MainPerpLike
    };

    let grouping = decode_grouping(aux)?;
    let prepared = match domain {
        OrderDomain::MainPerpLike => validate_main_perp_like(builder, grouping, orders)?,
        OrderDomain::SpotOrExtended => validate_spot_or_extended(builder, grouping, orders)?,
    };
    Ok(prepared)
}

fn decode_grouping(aux: OrderBatchAux) -> Result<GroupingMode, HandlerError> {
    match (aux.kind, aux.extended_index) {
        (0, _) => Ok(GroupingMode::Na),
        (1, _) => Ok(GroupingMode::NormalTpsl),
        (2, _) => Ok(GroupingMode::PositionTpsl),
        (3, Some(extended_index)) if extended_index < 100_000_001 => {
            Ok(GroupingMode::ExtendedNa { extended_index })
        }
        (3, _) => Err(HandlerError {
            status: STATUS_NON_MAIN_PERP_SPOT_ASSET_OUT_OF_RANGE,
        }),
        _ => Err(HandlerError {
            status: STATUS_GROUPING_KIND_INVALID_FOR_SPOT_PATH,
        }),
    }
}

fn validate_main_perp_like(
    builder: Option<BuilderEnvelope>,
    grouping: GroupingMode,
    orders: &[OrderWireRow],
) -> Result<PreparedOrderBatch, HandlerError> {
    let validated = normalize_orders(orders);
    validate_grouping(&grouping, &validated)?;

    // `0x1EA3140` then performs the main-perp-only builder flow:
    // - if a builder envelope is present, resolve the master account when needed;
    // - enforce the approved-builder count / limit lookup;
    // - call `l1_qtys_impl_wei__sub_validate_scaled_wei_notional_cap` when the
    //   aux/grouping requires the extended-index notional guard.
    if builder.is_some() {
        if validated.len() > 100 {
            return Err(HandlerError {
                status: STATUS_BUILDER_ORDER_COUNT_TOO_LARGE,
            });
        }
        if matches!(grouping, GroupingMode::ExtendedNa { .. }) {
            // Missing approval / cap overflow both short-circuit before execution.
            // The exact split lives in `sub_2511900` and the scaled-wei cap helper.
        }
    }

    Ok(PreparedOrderBatch {
        domain: OrderDomain::MainPerpLike,
        grouping,
        builder,
        orders: validated,
    })
}

fn validate_spot_or_extended(
    builder: Option<BuilderEnvelope>,
    grouping: GroupingMode,
    orders: &[OrderWireRow],
) -> Result<PreparedOrderBatch, HandlerError> {
    let validated = normalize_orders(orders);
    validate_grouping(&grouping, &validated)?;

    // `0x1EA3F60` mirrors the main-perp parser, but its builder path uses:
    // - `l1_sub_account__lookup_master` to collapse subaccounts onto their master;
    // - `sub_2510E90` + `l1_qtys_impl_wei__sub_validate_wei_notional_cap`;
    // - a looser per-batch builder count cap (`<= 1000`).
    if builder.is_some() {
        if validated.len() > 1000 {
            return Err(HandlerError {
                status: STATUS_BUILDER_ORDER_COUNT_TOO_LARGE,
            });
        }
        if matches!(grouping, GroupingMode::ExtendedNa { .. }) {
            // Approval lookup failure reports `296`; cap overflow reports `180`.
        }
    }

    Ok(PreparedOrderBatch {
        domain: OrderDomain::SpotOrExtended,
        grouping,
        builder,
        orders: validated,
    })
}

fn normalize_orders(orders: &[OrderWireRow]) -> Vec<ValidatedOrder> {
    orders
        .iter()
        .map(|order| ValidatedOrder {
            asset: order.asset,
            is_buy: order.is_buy,
            limit_px: order.limit_px,
            sz: order.sz,
            reduce_only: order.reduce_only,
            kind: match order.order_type {
                OrderType::Trigger { .. } => ValidatedOrderKind::Trigger,
                OrderType::Limit { .. } => ValidatedOrderKind::RestingOrImmediate,
            },
            // The binary carries one additional bool through the 72-byte validated row.
            // The grouped TP/SL checks require it on child orders, and the main-perp path
            // uses the negation to decide whether cached oracle context must be refreshed.
            helper_flag: order.reduce_only,
            cloid: order.cloid,
        })
        .collect()
}

fn validate_grouping(grouping: &GroupingMode, orders: &[ValidatedOrder]) -> Result<(), HandlerError> {
    if orders.is_empty() {
        return Err(HandlerError {
            status: STATUS_ORDERS_EMPTY,
        });
    }

    match *grouping {
        GroupingMode::Na | GroupingMode::ExtendedNa { .. } => Ok(()),
        GroupingMode::NormalTpsl => {
            let leader = &orders[0];
            if leader.kind != ValidatedOrderKind::RestingOrImmediate {
                return Err(HandlerError {
                    status: STATUS_INVALID_GROUPING_LEADER,
                });
            }
            if !(2..=3).contains(&orders.len()) {
                return Err(HandlerError {
                    status: STATUS_TOO_MANY_ATTACHED_ORDERS,
                });
            }
            for child in &orders[1..] {
                if child.kind != ValidatedOrderKind::Trigger {
                    return Err(HandlerError {
                        status: STATUS_INVALID_GROUPING_CHILD,
                    });
                }
                if child.is_buy == leader.is_buy || !child.reduce_only {
                    return Err(HandlerError {
                        status: STATUS_INVALID_ATTACHED_FLAG,
                    });
                }
                if child.asset != leader.asset {
                    return Err(HandlerError {
                        status: STATUS_MIXED_OUTER_ASSETS,
                    });
                }
            }
            Ok(())
        }
        GroupingMode::PositionTpsl => {
            if orders.len() > 3 {
                return Err(HandlerError {
                    status: STATUS_TOO_MANY_ATTACHED_ORDERS,
                });
            }
            let leader = &orders[0];
            for order in orders {
                if order.kind != ValidatedOrderKind::Trigger {
                    return Err(HandlerError {
                        status: STATUS_INVALID_GROUPING_CHILD,
                    });
                }
                if !order.reduce_only {
                    return Err(HandlerError {
                        status: STATUS_INVALID_ATTACHED_FLAG,
                    });
                }
                if order.asset != leader.asset {
                    return Err(HandlerError {
                        status: STATUS_INVALID_GROUPING_ASSET,
                    });
                }
                if order.is_buy != leader.is_buy {
                    return Err(HandlerError {
                        status: STATUS_MIXED_OUTER_ASSETS,
                    });
                }
            }
            Ok(())
        }
    }
}

pub fn build_execution_plan(batch: &PreparedOrderBatch) -> OrderHandlerPlan {
    let mut steps = Vec::new();

    if matches!(batch.domain, OrderDomain::MainPerpLike) {
        for order in &batch.orders {
            if !order.helper_flag {
                steps.push(OrderHandlerStep::RefreshPerpOracle { asset: order.asset });
            }
        }
    }

    match batch.grouping {
        GroupingMode::Na => {
            for order in &batch.orders {
                steps.push(OrderHandlerStep::ExecuteIndependent { asset: order.asset });
            }
        }
        GroupingMode::ExtendedNa { extended_index } => {
            for order in &batch.orders {
                steps.push(OrderHandlerStep::ExecuteIndependent { asset: order.asset });
            }
            steps.push(OrderHandlerStep::FinalizeExtendedNa {
                extended_index,
                spot_path: matches!(batch.domain, OrderDomain::SpotOrExtended),
            });
        }
        GroupingMode::NormalTpsl => {
            let mut iter = batch.orders.iter();
            if let Some(leader) = iter.next() {
                steps.push(OrderHandlerStep::ExecuteBracketLeader {
                    asset: leader.asset,
                });
            }
            for child in iter {
                steps.push(OrderHandlerStep::ExecuteBracketChild { asset: child.asset });
            }
            // The shared core links exactly two successful child OIDs back into the book
            // and then calls the bracket-finalization helper (`sub_26E3D40`).
        }
        GroupingMode::PositionTpsl => {
            for order in &batch.orders {
                steps.push(OrderHandlerStep::ExecuteBracketChild { asset: order.asset });
            }
            // If exactly two child orders survive insertion, the book records them as peers.
        }
    }

    OrderHandlerPlan {
        grouping: batch.grouping,
        steps,
    }
}
