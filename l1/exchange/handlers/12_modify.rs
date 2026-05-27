#![allow(dead_code)]

use std::vec::Vec;

pub type Address = [u8; 20];
pub type OrderId = u64;
pub type AssetId = u32;

pub const STATUS_SUCCESS: u16 = 390;
pub const STATUS_SPOT_DISABLED: u16 = 249;
pub const STATUS_UNKNOWN_DEX: u16 = 321;
pub const STATUS_OLD_ORDER_NOT_FOUND: u16 = 56;
pub const STATUS_REPLACE_INCOMPATIBLE: u16 = 57;
pub const STATUS_DIRECT_REPLACE_FAILED: u16 = 58;

/// User-visible `modify` action.
///
/// The binary wrapper at `0x22BE760` forwards two pieces of state into the
/// real helper:
/// - the order id to replace (`oid`), used for the old-slot lookup;
/// - a fully decoded replacement order (`order`), which carries the new limit,
///   size, tif, reduce-only bit, and optional `cloid` exactly like a fresh
///   `order` action.
///
/// The old order is never resolved by cloid. Lookup is always `(user, oid)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModifyAction {
    pub oid: OrderId,
    pub order: OrderRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderRequest {
    pub oid: OrderId,
    pub asset: AssetId,
    pub side: Side,
    pub limit_px: u64,
    pub sz: u64,
    pub reduce_only: bool,
    pub tif_code: u8,
    pub cloid: Option<u128>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Buy,
    Sell,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModifyRoute {
    Unknown,
    PerpMain,
    PerpPerDex { dex: u64, local_asset: u64 },
    Spot { spot_index: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExistingOrder {
    pub oid: OrderId,
    pub side: Side,
    pub reduce_only: bool,
    pub parent_oid: Option<OrderId>,
    pub peer_oid: Option<OrderId>,
    pub child_oids: Vec<OrderId>,
    pub cloid: Option<u128>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedReplacement {
    pub route: ModifyRoute,
    pub request: OrderRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InsertResult {
    pub status: u16,
    pub new_oid: Option<OrderId>,
    pub new_peer_oid: Option<OrderId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModifyOutcome {
    pub status: u16,
    pub route: ModifyRoute,
    pub old_oid: OrderId,
    pub new_oid: Option<OrderId>,
    pub replacement_cloid: Option<u128>,
    pub child_oids_rebound: bool,
    pub child_oids_pruned: bool,
}

pub trait ModifyBookRuntime {
    fn classify_asset(&self, asset: AssetId) -> Result<ModifyRoute, u16>;
    fn spot_modify_enabled(&self) -> bool;
    fn validate_perp_replacement(
        &self,
        user: Address,
        request: &OrderRequest,
        route: ModifyRoute,
    ) -> Result<ValidatedReplacement, u16>;
    fn validate_spot_replacement(
        &self,
        user: Address,
        request: &OrderRequest,
        route: ModifyRoute,
    ) -> Result<ValidatedReplacement, u16>;
    fn find_existing_by_user_oid(
        &self,
        route: ModifyRoute,
        user: Address,
        oid: OrderId,
    ) -> Option<ExistingOrder>;
    fn remove_existing_for_replace(
        &mut self,
        route: ModifyRoute,
        user: Address,
        oid: OrderId,
    );
    fn insert_replacement(
        &mut self,
        route: ModifyRoute,
        user: Address,
        replacement: &ValidatedReplacement,
    ) -> InsertResult;
    fn rebind_child_oids(
        &mut self,
        route: ModifyRoute,
        user: Address,
        old_child_oids: &[OrderId],
        new_parent_oid: OrderId,
    );
    fn wire_peer_link(
        &mut self,
        route: ModifyRoute,
        user: Address,
        new_oid: OrderId,
        peer_oid: OrderId,
    );
    fn prune_child_tree(&mut self, route: ModifyRoute, user: Address, old_child_oids: &[OrderId]);
}

/// Recovered from `sub_22BE760 -> l1_perp_dex__sub_modify_order_across_dex`.
///
/// The ordering of operations matters:
/// 1. route and validate the replacement order;
/// 2. find the existing resting order by `(user, action.oid)`;
/// 3. reject side/reduce-only/raw-kind-2 parent mismatches before mutating the book;
/// 4. remove the old order from the selected book;
/// 5. insert the replacement through the normal order-insert path;
/// 6. on success, rebind copied child/peer order ids onto the replacement;
/// 7. on failure after removal, prune the copied child tree instead of restoring
///    the original order.
///
/// `order.cloid` is treated as part of the new order only. The replaced order's
/// cloid does not participate in the lookup.
pub fn apply_modify<R: ModifyBookRuntime>(
    runtime: &mut R,
    user: Address,
    action: &ModifyAction,
) -> ModifyOutcome {
    let route = match runtime.classify_asset(action.order.asset) {
        Ok(route) => route,
        Err(status) => {
            return ModifyOutcome {
                status,
                route: ModifyRoute::Unknown,
                old_oid: action.oid,
                new_oid: None,
                replacement_cloid: action.order.cloid,
                child_oids_rebound: false,
                child_oids_pruned: false,
            };
        }
    };

    if matches!(route, ModifyRoute::Spot { .. }) && !runtime.spot_modify_enabled() {
        return ModifyOutcome {
            status: STATUS_SPOT_DISABLED,
            route,
            old_oid: action.oid,
            new_oid: None,
            replacement_cloid: action.order.cloid,
            child_oids_rebound: false,
            child_oids_pruned: false,
        };
    }

    let replacement = match route {
        ModifyRoute::Spot { .. } => runtime.validate_spot_replacement(user, &action.order, route),
        ModifyRoute::PerpMain | ModifyRoute::PerpPerDex { .. } => {
            runtime.validate_perp_replacement(user, &action.order, route)
        }
    };
    let replacement = match replacement {
        Ok(replacement) => replacement,
        Err(status) => {
            return ModifyOutcome {
                status,
                route,
                old_oid: action.oid,
                new_oid: None,
                replacement_cloid: action.order.cloid,
                child_oids_rebound: false,
                child_oids_pruned: false,
            };
        }
    };

    let existing = match runtime.find_existing_by_user_oid(route, user, action.oid) {
        Some(existing) => existing,
        None => {
            return ModifyOutcome {
                status: STATUS_OLD_ORDER_NOT_FOUND,
                route,
                old_oid: action.oid,
                new_oid: None,
                replacement_cloid: action.order.cloid,
                child_oids_rebound: false,
                child_oids_pruned: false,
            };
        }
    };

    if replacement_breaks_existing_shape(&existing, &replacement) {
        return ModifyOutcome {
            status: STATUS_REPLACE_INCOMPATIBLE,
            route,
            old_oid: action.oid,
            new_oid: None,
            replacement_cloid: action.order.cloid,
            child_oids_rebound: false,
            child_oids_pruned: false,
        };
    }

    let carried_children = existing.child_oids.clone();
    runtime.remove_existing_for_replace(route, user, action.oid);

    let inserted = runtime.insert_replacement(route, user, &replacement);
    if inserted.status != STATUS_SUCCESS {
        let mut status = inserted.status;
        if status == 196 {
            status = STATUS_DIRECT_REPLACE_FAILED;
        }
        runtime.prune_child_tree(route, user, &carried_children);
        return ModifyOutcome {
            status,
            route,
            old_oid: action.oid,
            new_oid: inserted.new_oid,
            replacement_cloid: replacement.request.cloid,
            child_oids_rebound: false,
            child_oids_pruned: !carried_children.is_empty(),
        };
    }

    let new_oid = inserted.new_oid;
    if let Some(new_oid) = new_oid {
        runtime.rebind_child_oids(route, user, &carried_children, new_oid);
        if let Some(peer_oid) = inserted.new_peer_oid {
            runtime.wire_peer_link(route, user, new_oid, peer_oid);
        }
    }

    ModifyOutcome {
        status: STATUS_SUCCESS,
        route,
        old_oid: action.oid,
        new_oid,
        replacement_cloid: replacement.request.cloid,
        child_oids_rebound: new_oid.is_some() && !carried_children.is_empty(),
        child_oids_pruned: false,
    }
}

fn replacement_breaks_existing_shape(
    existing: &ExistingOrder,
    replacement: &ValidatedReplacement,
) -> bool {
    existing.side != replacement.request.side
        || existing.reduce_only != replacement.request.reduce_only
        || existing.parent_oid.is_some() && replacement.request.tif_code == 2
}

#[cfg(test)]
mod tests {
    use super::{replacement_breaks_existing_shape, ExistingOrder, ModifyRoute, OrderRequest, Side, ValidatedReplacement};

    #[test]
    fn replace_keeps_oid_lookup_and_new_cloid() {
        let existing = ExistingOrder {
            oid: 7,
            side: Side::Buy,
            reduce_only: false,
            parent_oid: None,
            peer_oid: None,
            child_oids: vec![],
            cloid: Some(1),
        };
        let replacement = ValidatedReplacement {
            route: ModifyRoute::PerpMain,
            request: OrderRequest {
                oid: 99,
                asset: 0,
                side: Side::Buy,
                limit_px: 10,
                sz: 1,
                reduce_only: false,
                tif_code: 0,
                cloid: Some(2),
            },
        };

        assert!(!replacement_breaks_existing_shape(&existing, &replacement));
        assert_eq!(existing.oid, 7);
        assert_eq!(replacement.request.cloid, Some(2));
    }

    #[test]
    fn replace_rejects_parented_kind_two_swap() {
        let existing = ExistingOrder {
            oid: 7,
            side: Side::Sell,
            reduce_only: true,
            parent_oid: Some(5),
            peer_oid: None,
            child_oids: vec![11, 12],
            cloid: None,
        };
        let replacement = ValidatedReplacement {
            route: ModifyRoute::Spot { spot_index: 3 },
            request: OrderRequest {
                oid: 77,
                asset: 3,
                side: Side::Sell,
                limit_px: 10,
                sz: 1,
                reduce_only: true,
                tif_code: 2,
                cloid: None,
            },
        };

        assert!(replacement_breaks_existing_shape(&existing, &replacement));
    }
}
