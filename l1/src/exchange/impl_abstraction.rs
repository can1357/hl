#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type DexIndex = u64;
pub type AssetId = u64;
pub type SettlementAsset = u64;

pub const PERP_ASSET_STRIDE: u64 = 10_000;
pub const MAX_API_ASSET_BEFORE_OFFSET: u64 = 0x05f4_5a5f;
pub const API_PERP_OFFSET: u64 = 100_000;

pub const OK: u16 = 390;
pub const ERR_ABSTRACTION_ADDRESS_MISSING: u16 = 124;
pub const ERR_ABSTRACTION_OWNER_MISMATCH: u16 = 21;
pub const ERR_DIRECT_IMPL_REJECTED: u16 = 196;
pub const ERR_ABSTRACTION_ADDRESS_NOT_MAPPED: u16 = 220;
pub const ERR_COLLATERAL_MISMATCH: u16 = 234;
pub const ERR_AMOUNT_OVERFLOW: u16 = 319;
pub const ERR_UNKNOWN_DEX: u16 = 321;
pub const ERR_STRING_TOO_LONG: u16 = 323;
pub const ERR_NOT_ALLOWED: u16 = 347;
pub const ERR_DEX_NOTIONAL_CAP: u16 = 351;
pub const ERR_CLASS2_DESTINATION_DEX: u16 = 361;
pub const ERR_DEX_SOURCE_FOR_CLASS: u16 = 366;
pub const ERR_REQUIRED_SET_MISS: u16 = 368;
pub const ERR_SIDE_EFFECT_CHANGED_MAPPING: u16 = 382;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExchangeLayout {
    /// One of the two mirrored exchange layouts.  The binary keeps separate
    /// helper families and state offsets for the two layouts; branch behavior is
    /// the same except for which tables/helpers are touched.
    FirstClass,
    /// The alternate mirrored layout.
    SecondClass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserClass {
    SpotOnly,
    Legacy,
    AbstractionOptIn,
    DexUser,
    PrivilegedDexUser,
    Other(u8),
}

impl UserClass {
    pub const fn from_status_byte(byte: u8) -> Self {
        match byte {
            0 => Self::SpotOnly,
            1 => Self::Legacy,
            2 => Self::AbstractionOptIn,
            3 => Self::DexUser,
            4 => Self::PrivilegedDexUser,
            other => Self::Other(other),
        }
    }

    #[inline]
    pub const fn status_byte(self) -> u8 {
        match self {
            Self::SpotOnly => 0,
            Self::Legacy => 1,
            Self::AbstractionOptIn => 2,
            Self::DexUser => 3,
            Self::PrivilegedDexUser => 4,
            Self::Other(byte) => byte,
        }
    }

    #[inline]
    pub const fn is_privileged(self) -> bool {
        self.status_byte() >= 4
    }

    #[inline]
    pub const fn requires_dex_gate(self) -> bool {
        self.status_byte() >= 2
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionResult {
    pub code: u16,
    pub api_asset: Option<i64>,
    pub amount_or_nonce: u64,
    pub address: Option<Address>,
    pub aux_address: Option<Address>,
    pub message: Option<String>,
    pub generated_orders: Vec<GeneratedOrder>,
}

impl ActionResult {
    pub fn ok() -> Self {
        Self {
            code: OK,
            api_asset: None,
            amount_or_nonce: 0,
            address: None,
            aux_address: None,
            message: None,
            generated_orders: Vec::new(),
        }
    }

    pub fn code(code: u16) -> Self {
        Self { code, ..Self::ok() }
    }

    pub fn direct_impl_rejected(asset: AssetId, reason: u64, payload: Address) -> Self {
        Self {
            code: ERR_DIRECT_IMPL_REJECTED,
            api_asset: asset_to_api_id(asset),
            amount_or_nonce: reason,
            address: Some(payload),
            aux_address: None,
            message: None,
            generated_orders: Vec::new(),
        }
    }

    #[inline]
    pub const fn is_ok(&self) -> bool {
        self.code == OK
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedOrder {
    pub asset: AssetId,
    pub oid: u64,
    pub user: Address,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Clearinghouse {
    pub settlement_asset: SettlementAsset,
    pub name: String,
    /// Status byte `3` is treated as removed; removed dexes use an empty name.
    pub status: u8,
    pub open_interest_cap_e6: Option<u64>,
    pub user_notional_cap_e6: Option<u64>,
    pub current_open_interest_e6: u64,
    pub abstraction_collateral: BTreeMap<Address, SettlementAsset>,
}

impl Clearinghouse {
    #[inline]
    pub fn is_removed(&self) -> bool {
        self.status == 3
    }

    #[inline]
    pub fn display_name_for_event(&self) -> &str {
        if self.is_removed() { "" } else { &self.name }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UserRoutingBucket {
    pub primary_required_keys: BTreeSet<u64>,
    pub secondary_required_keys: BTreeSet<u64>,
    pub accepted_count: u64,
}

impl UserRoutingBucket {
    pub fn accepts(&self, key: u64) -> bool {
        self.primary_required_keys.contains(&key) || self.secondary_required_keys.contains(&key)
    }

    pub fn bump(&mut self) {
        self.accepted_count = self.accepted_count.saturating_add(1);
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AbstractionAddressBook {
    /// Tree lookup used first in the binary.  The key is the abstraction address;
    /// the value is the owner that address is currently allowed to act for.
    pub tree_owner_by_abstraction: BTreeMap<Address, Address>,
    /// Hash lookup used after the tree miss path.  It must also map back to the
    /// current actor or the action returns `ERR_ABSTRACTION_ADDRESS_NOT_MAPPED`.
    pub hash_owner_by_abstraction: BTreeMap<Address, Address>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbstractionSideState {
    pub layout: ExchangeLayout,
    pub disable_privileged_direct_path: bool,
    pub disable_low_class_direct_path: bool,
    pub dex_abstraction_enabled: bool,
    pub enforce_active_dex_for_abstraction: bool,
    pub clearinghouses: Vec<Clearinghouse>,
    pub routing_buckets: BTreeMap<Address, UserRoutingBucket>,
    pub global_routed_count: u64,
    pub abstraction_addresses: AbstractionAddressBook,
}

impl AbstractionSideState {
    pub fn clearinghouse(&self, dex: DexIndex) -> Result<&Clearinghouse, ActionResult> {
        self.clearinghouses
            .get(dex as usize)
            .ok_or_else(|| ActionResult::code(ERR_UNKNOWN_DEX))
    }

    pub fn settlement_asset(&self, dex: DexIndex) -> Result<SettlementAsset, ActionResult> {
        Ok(self.clearinghouse(dex)?.settlement_asset)
    }

    pub fn bucket_mut(&mut self, user: Address) -> &mut UserRoutingBucket {
        self.routing_buckets.entry(user).or_default()
    }

    pub fn bump_global(&mut self) {
        self.global_routed_count = self.global_routed_count.saturating_add(1);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExchangeAbstraction {
    pub first_class: AbstractionSideState,
    pub second_class: AbstractionSideState,
}

impl ExchangeAbstraction {
    pub fn side(&self, layout: ExchangeLayout) -> &AbstractionSideState {
        match layout {
            ExchangeLayout::FirstClass => &self.first_class,
            ExchangeLayout::SecondClass => &self.second_class,
        }
    }

    pub fn side_mut(&mut self, layout: ExchangeLayout) -> &mut AbstractionSideState {
        match layout {
            ExchangeLayout::FirstClass => &mut self.first_class,
            ExchangeLayout::SecondClass => &mut self.second_class,
        }
    }

    pub fn route_order_action<B: AbstractionBackend>(
        &mut self,
        backend: &mut B,
        layout: ExchangeLayout,
        order: &OrderAction,
        user: Address,
        context: &OrderContext,
    ) -> ActionResult {
        self.route_dex_action(layout, user, order.global_asset, context.required_key, backend, |backend, this| {
            backend.apply_order_action(this, layout, order, user, context)
        })
    }

    pub fn route_outer_order_action<B: AbstractionBackend>(
        &mut self,
        backend: &mut B,
        layout: ExchangeLayout,
        order: &OrderAction,
        user: Address,
        context: &OrderContext,
    ) -> OuterActionResult {
        let result = self.route_order_action(backend, layout, order, user, context);
        OuterActionResult { slot: 0, result }
    }

    pub fn route_collateral_action<B: AbstractionBackend>(
        &mut self,
        backend: &mut B,
        layout: ExchangeLayout,
        asset: AssetId,
        user: Address,
        context: &OrderContext,
    ) -> ActionResult {
        self.route_dex_action(layout, user, asset, context.required_key, backend, |backend, this| {
            backend.apply_collateral_action(this, layout, asset, user, context)
        })
    }

    pub fn route_set_user_asset_leverage<B: AbstractionBackend>(
        &mut self,
        backend: &mut B,
        layout: ExchangeLayout,
        req: &AssetLeverageUpdate,
    ) -> ActionResult {
        self.route_dex_action(layout, req.user, req.asset, req.required_key, backend, |backend, this| {
            backend.apply_asset_leverage(this, layout, req)
        })
    }

    pub fn route_user_asset_position_delta<B: AbstractionBackend>(
        &mut self,
        backend: &mut B,
        layout: ExchangeLayout,
        req: &AssetPositionDelta,
    ) -> ActionResult {
        self.route_dex_action(layout, req.user, req.asset, req.required_key, backend, |backend, this| {
            backend.apply_asset_position_delta(this, layout, req)
        })
    }

    fn route_dex_action<B: AbstractionBackend, F>(
        &mut self,
        layout: ExchangeLayout,
        user: Address,
        asset: AssetId,
        required_key: u64,
        backend: &mut B,
        apply_direct: F,
    ) -> ActionResult
    where
        F: FnOnce(&mut B, &mut Self) -> ActionResult,
    {
        let class = backend.user_class(layout, user);
        let status = class.status_byte();
        let dex = asset / PERP_ASSET_STRIDE;
        let direct = {
            let side = self.side(layout);
            status < 2
                || (status < 4 && side.disable_low_class_direct_path)
                || (status >= 4 && side.disable_privileged_direct_path)
                || (status == 2 && (!side.dex_abstraction_enabled || asset < PERP_ASSET_STRIDE))
        };

        if direct {
            return apply_direct(backend, self);
        }

        if status == 2 {
            let settlement_asset = match self.side(layout).settlement_asset(dex) {
                Ok(asset) => asset,
                Err(err) => return err,
            };
            let enter_as_spot = settlement_asset == 0;
            let pre = backend.recheck_user_settlement(self, layout, user, settlement_asset, enter_as_spot, 0, true);
            if !pre.is_ok() {
                backend.propagate_soft_failure(&pre);
                return pre;
            }
            let result = apply_direct(backend, self);
            if self.side(layout).dex_abstraction_enabled {
                let post = backend.recheck_user_settlement(
                    self,
                    layout,
                    user,
                    settlement_asset,
                    true,
                    dex,
                    enter_as_spot,
                );
                if !post.is_ok() {
                    backend.propagate_soft_failure(&post);
                    return post;
                }
            }
            return result;
        }

        let allowed = {
            let side = self.side_mut(layout);
            let bucket = side.bucket_mut(user);
            if bucket.accepts(required_key) {
                bucket.bump();
                side.bump_global();
                true
            } else {
                false
            }
        };
        if !allowed {
            return ActionResult::code(ERR_REQUIRED_SET_MISS);
        }

        let settlement_asset = match self.side(layout).settlement_asset(dex) {
            Ok(asset) => asset,
            Err(err) => return err,
        };
        backend.pre_mutation(self, layout, user, settlement_asset, true, dex, class.is_privileged());
        let result = apply_direct(backend, self);
        if class.is_privileged() {
            backend.finalize_privileged(self, layout, user, settlement_asset, true, dex);
        } else {
            let post = backend.recheck_user_settlement(self, layout, user, settlement_asset, true, dex, false);
            if !post.is_ok() {
                backend.propagate_hard_failure(&post);
                return post;
            }
        }
        result
    }

    pub fn gate_apply_state<B: AbstractionBackend>(
        &mut self,
        backend: &mut B,
        layout: ExchangeLayout,
        user: Address,
        target: GateTarget,
        inner: &InnerApply,
    ) -> ActionResult {
        let class = backend.user_class(layout, user);
        let status = class.status_byte();
        let direct = {
            let side = self.side(layout);
            status < 2
                || (status < 4 && side.disable_low_class_direct_path)
                || (status >= 4 && side.disable_privileged_direct_path)
                || (status == 2
                    && (inner.count < 2
                        || target.dex_arg_is_resolved
                        || !side.dex_abstraction_enabled
                        || target.dex_or_settlement == 0))
        };
        if direct {
            return backend.apply_inner(self, layout, inner);
        }

        if status == 2 {
            let settlement_asset = if target.dex_arg_is_resolved {
                target.dex_or_settlement
            } else {
                match self.side(layout).settlement_asset(target.dex_or_settlement) {
                    Ok(asset) => asset,
                    Err(err) => return err,
                }
            };
            let enter = !target.dex_arg_is_resolved;
            let pre = backend.recheck_user_settlement(self, layout, user, settlement_asset, enter, 0, true);
            if !pre.is_ok() {
                backend.propagate_soft_failure(&pre);
                return pre;
            }
            let result = backend.apply_inner(self, layout, inner);
            if self.side(layout).dex_abstraction_enabled {
                let post = backend.recheck_user_settlement(
                    self,
                    layout,
                    user,
                    settlement_asset,
                    true,
                    target.dex_or_settlement,
                    settlement_asset == 0,
                );
                if !post.is_ok() {
                    backend.propagate_soft_failure(&post);
                    return post;
                }
            }
            return result;
        }

        let allowed = {
            let side = self.side_mut(layout);
            let bucket = side.bucket_mut(user);
            if bucket.accepts(inner.required_key) {
                bucket.bump();
                side.bump_global();
                true
            } else {
                false
            }
        };
        if !allowed {
            return ActionResult::code(ERR_REQUIRED_SET_MISS);
        }

        let settlement_asset = if target.dex_arg_is_resolved {
            target.dex_or_settlement
        } else {
            match self.side(layout).settlement_asset(target.dex_or_settlement) {
                Ok(asset) => asset,
                Err(err) => return err,
            }
        };
        let enter = !target.dex_arg_is_resolved;
        backend.pre_mutation(
            self,
            layout,
            user,
            settlement_asset,
            enter,
            target.dex_or_settlement,
            class.is_privileged(),
        );
        let result = backend.apply_inner(self, layout, inner);
        if class.is_privileged() {
            backend.finalize_privileged(self, layout, user, settlement_asset, enter, target.dex_or_settlement);
        } else {
            let post = backend.recheck_user_settlement(
                self,
                layout,
                user,
                settlement_asset,
                enter,
                target.dex_or_settlement,
                false,
            );
            if !post.is_ok() {
                backend.propagate_hard_failure(&post);
                return post;
            }
        }
        result
    }

    pub fn apply_account_abstraction<B: AbstractionBackend>(
        &mut self,
        backend: &mut B,
        layout: ExchangeLayout,
        actor: Address,
        req: &AccountAbstractionRequest,
        ctx: ApplyContext,
    ) -> ActionResult {
        if let Some(abstraction) = req.abstraction_address {
            if let Some(owner) = self.side(layout).abstraction_addresses.tree_owner_by_abstraction.get(&abstraction) {
                if *owner != actor {
                    if req.source_address == abstraction && req.collateral == 0 && req.allow_self_tree_alias {
                        // Observed fast path: an already-active tree entry may act for itself
                        // without falling through to the mismatch error.
                    } else {
                        return ActionResult {
                            code: ERR_ABSTRACTION_OWNER_MISMATCH,
                            address: Some(actor),
                            aux_address: Some(abstraction),
                            ..ActionResult::ok()
                        };
                    }
                }
            } else if self
                .side(layout)
                .abstraction_addresses
                .hash_owner_by_abstraction
                .get(&abstraction)
                .copied()
                != Some(actor)
            {
                return ActionResult {
                    code: ERR_ABSTRACTION_ADDRESS_NOT_MAPPED,
                    address: Some(actor),
                    aux_address: Some(abstraction),
                    ..ActionResult::ok()
                };
            }
        } else if req.requires_abstraction_address {
            return ActionResult {
                code: ERR_ABSTRACTION_ADDRESS_MISSING,
                address: Some(actor),
                aux_address: Some(req.source_address),
                ..ActionResult::ok()
            };
        }

        let source_class = backend.user_class(layout, req.source_address);
        if source_class.status_byte() <= 3
            && req.destination.is_dex()
            && !backend.class2_dex_destination_enabled(layout)
            && source_class == UserClass::AbstractionOptIn
            && req.destination.dex_index().unwrap_or(0) != 0
        {
            return ActionResult::code(ERR_CLASS2_DESTINATION_DEX);
        }

        let actor_class = backend.user_class(layout, actor);
        if !backend.user_class_enabled(layout, actor_class) && req.source.is_dex() {
            if actor_class.status_byte() >= 3 {
                return ActionResult::code(ERR_DEX_SOURCE_FOR_CLASS);
            }
            if actor_class == UserClass::AbstractionOptIn && req.source.dex_index().unwrap_or(0) != 0 {
                return ActionResult::code(ERR_CLASS2_DESTINATION_DEX);
            }
        }

        if req.source.same_presence_and_address(&req.destination, actor)
            && (!req.source.is_dex() || req.source.dex_index() == req.destination.dex_index())
        {
            return ActionResult::code(ERR_NOT_ALLOWED);
        }

        let source_name = match self.resolve_location_name(layout, req.source) {
            Ok(name) => name,
            Err(err) => return err,
        };
        let destination_name = match self.resolve_location_name(layout, req.destination) {
            Ok(name) => name,
            Err(err) => return err,
        };

        if let Some(dex) = req.source.dex_index().or_else(|| req.destination.dex_index()) {
            let ch = match self.side(layout).clearinghouse(dex) {
                Ok(ch) => ch,
                Err(err) => return err,
            };
            if self.side(layout).enforce_active_dex_for_abstraction && !ch.is_removed() {
                if req.collateral != ch.settlement_asset {
                    return ActionResult::code(ERR_COLLATERAL_MISMATCH);
                }
            }
        }

        if req.notional_e6 % 100 == 0 {
            if let Some(err) = self.check_destination_caps(layout, req) {
                return err;
            }
        } else if req.source.is_dex() || req.destination.is_dex() {
            if let Some(dex) = req.source.dex_index().or_else(|| req.destination.dex_index()) {
                let ch = match self.side(layout).clearinghouse(dex) {
                    Ok(ch) => ch,
                    Err(err) => return err,
                };
                if self.side(layout).enforce_active_dex_for_abstraction && !ch.is_removed() {
                    if req.collateral != ch.settlement_asset {
                        return ActionResult::code(ERR_COLLATERAL_MISMATCH);
                    }
                }
            }
        }

        let envelope = AbstractionEnvelope {
            source: req.source,
            destination: req.destination,
            source_name,
            destination_name,
            actor,
            source_address: req.source_address,
            collateral: req.collateral,
            notional_e6: req.notional_e6,
            effective_class: actor_class,
        };

        match actor_class {
            UserClass::SpotOnly | UserClass::Legacy => backend.apply_abstraction_inner(self, layout, &envelope, ctx),
            UserClass::DexUser => self.apply_dex_user_abstraction(backend, layout, actor, &envelope, ctx),
            _ => self.apply_generated_abstraction(backend, layout, actor, &envelope, ctx),
        }
    }

    fn apply_dex_user_abstraction<B: AbstractionBackend>(
        &mut self,
        backend: &mut B,
        layout: ExchangeLayout,
        actor: Address,
        envelope: &AbstractionEnvelope,
        ctx: ApplyContext,
    ) -> ActionResult {
        if backend.should_preflight_actor(layout, actor) {
            let pre = backend.preflight_abstraction_actor(self, layout, actor, envelope.collateral);
            if !pre.is_ok() {
                return pre;
            }
            backend.pre_mutation(self, layout, actor, envelope.collateral, false, envelope.destination.dex_index().unwrap_or(0), false);
            let result = backend.apply_abstraction_inner(self, layout, envelope, ctx);
            backend.finalize_privileged(self, layout, actor, envelope.collateral, false, envelope.destination.dex_index().unwrap_or(0));
            result
        } else {
            backend.apply_abstraction_inner(self, layout, envelope, ctx)
        }
    }

    fn apply_generated_abstraction<B: AbstractionBackend>(
        &mut self,
        backend: &mut B,
        layout: ExchangeLayout,
        actor: Address,
        envelope: &AbstractionEnvelope,
        ctx: ApplyContext,
    ) -> ActionResult {
        let mut result = backend.apply_abstraction_inner(self, layout, envelope, ctx);
        if result.code != 246 || result.generated_orders.is_empty() {
            return result;
        }

        for generated in result.generated_orders.clone() {
            let pre_class = backend.user_class(layout, actor);
            if backend.user_class_enabled(layout, pre_class) {
                backend.pre_mutation(self, layout, actor, envelope.collateral, false, envelope.destination.dex_index().unwrap_or(0), pre_class.is_privileged());
                let generated_result = backend.apply_generated_order(self, layout, &generated, ctx);
                if pre_class.is_privileged() {
                    backend.finalize_privileged(self, layout, actor, envelope.collateral, false, envelope.destination.dex_index().unwrap_or(0));
                } else {
                    backend.post_generated_order(self, layout, actor, envelope.collateral);
                }
                if generated_result.code == ERR_SIDE_EFFECT_CHANGED_MAPPING {
                    backend.propagate_soft_failure(&generated_result);
                    return result;
                }
                if !generated_result.is_ok() {
                    backend.propagate_soft_failure(&generated_result);
                }
            } else {
                let generated_result = backend.apply_generated_order(self, layout, &generated, ctx);
                if generated_result.code == ERR_SIDE_EFFECT_CHANGED_MAPPING {
                    backend.propagate_soft_failure(&generated_result);
                    return result;
                }
                if !generated_result.is_ok() {
                    backend.propagate_soft_failure(&generated_result);
                }
            }
        }

        if result.code != OK {
            backend.propagate_soft_failure(&result);
            result = ActionResult::code(OK);
        }
        result
    }

    pub fn apply_user_abstraction_side_effects<B: AbstractionBackend>(
        &mut self,
        backend: &mut B,
        layout: ExchangeLayout,
        actor_class: UserClass,
        mode: SideEffectMode,
        seed: u64,
        user: Address,
    ) {
        let targets = self.side_effect_targets(layout, actor_class, mode, seed);
        if actor_class.status_byte() < 2 {
            return;
        }

        for target in targets {
            let settlement = match target {
                SideEffectTarget::Spot(value) => value,
                SideEffectTarget::Dex(dex) => match self.side(layout).settlement_asset(dex) {
                    Ok(asset) => asset,
                    Err(err) => {
                        backend.propagate_soft_failure(&err);
                        continue;
                    }
                },
            };

            if actor_class.is_privileged() {
                backend.finalize_privileged(
                    self,
                    layout,
                    user,
                    settlement,
                    matches!(target, SideEffectTarget::Spot(_)),
                    target.dex_index().unwrap_or(0),
                );
            } else {
                let result = backend.recheck_user_settlement(
                    self,
                    layout,
                    user,
                    settlement,
                    matches!(target, SideEffectTarget::Spot(_)),
                    target.dex_index().unwrap_or(0),
                    false,
                );
                if !result.is_ok() {
                    backend.propagate_hard_failure(&result);
                }
            }

            if mode == SideEffectMode::EmitNotionalCapEvent && !matches!(target, SideEffectTarget::Spot(_)) {
                let dex = target.dex_index().unwrap_or(0);
                if let Ok(ch) = self.side(layout).clearinghouse(dex) {
                    backend.emit_dex_notional_cap_event(user, dex, ch.display_name_for_event(), ch.settlement_asset);
                }
            }
        }
    }

    fn resolve_location_name(&self, layout: ExchangeLayout, location: PortfolioLocation) -> Result<String, ActionResult> {
        match location {
            PortfolioLocation::Spot => Ok("spot".to_owned()),
            PortfolioLocation::Dex(dex) => {
                let clearinghouse = self.side(layout).clearinghouse(dex)?;
                Ok(clearinghouse.display_name_for_event().to_owned())
            }
        }
    }

    fn check_destination_caps(&self, layout: ExchangeLayout, req: &AccountAbstractionRequest) -> Option<ActionResult> {
        let dex = req.destination.dex_index()?;
        let clearinghouse = self.side(layout).clearinghouse(dex).ok()?;
        let existing = clearinghouse.current_open_interest_e6;
        let requested = req.notional_e6 / 100;
        if let Some(cap) = clearinghouse.open_interest_cap_e6 {
            if existing.saturating_add(requested) > cap {
                let excess = cap.saturating_sub(existing) as f64 / 1_000_000.0;
                return Some(ActionResult {
                    code: ERR_DEX_NOTIONAL_CAP,
                    message: Some(format!("available_notional={excess}")),
                    ..ActionResult::ok()
                });
            }
        }
        if let Some(cap) = clearinghouse.user_notional_cap_e6 {
            if requested > cap {
                let capped = cap as f64 / 1_000_000.0;
                return Some(ActionResult {
                    code: ERR_DEX_NOTIONAL_CAP,
                    message: Some(format!("user_notional_cap={capped}")),
                    ..ActionResult::ok()
                });
            }
        }
        None
    }

    fn side_effect_targets(
        &self,
        layout: ExchangeLayout,
        class: UserClass,
        mode: SideEffectMode,
        seed: u64,
    ) -> Vec<SideEffectTarget> {
        match mode {
            SideEffectMode::SingleGlobalAsset => {
                let dex = seed / PERP_ASSET_STRIDE;
                if class.status_byte() < 2 || (class.status_byte() < 3 && seed < PERP_ASSET_STRIDE) {
                    Vec::new()
                } else {
                    vec![SideEffectTarget::Dex(dex)]
                }
            }
            SideEffectMode::SingleDex => {
                if class.status_byte() < 2 || (class.status_byte() < 3 && seed == 0) {
                    Vec::new()
                } else {
                    vec![SideEffectTarget::Dex(seed)]
                }
            }
            SideEffectMode::OpenDexOnly => vec![SideEffectTarget::Dex(seed)],
            SideEffectMode::AllDexes => (0..self.side(layout).clearinghouses.len() as u64)
                .map(SideEffectTarget::Dex)
                .collect(),
            SideEffectMode::AllNonRemovedDexes => self
                .side(layout)
                .clearinghouses
                .iter()
                .enumerate()
                .filter_map(|(idx, ch)| (!ch.is_removed()).then_some(SideEffectTarget::Dex(idx as u64)))
                .collect(),
            SideEffectMode::SpotAndDexFromBook => vec![SideEffectTarget::Spot(seed)],
            SideEffectMode::EmitNotionalCapEvent => vec![SideEffectTarget::Dex(seed)],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderAction {
    pub global_asset: AssetId,
    pub user: Address,
    pub nonce: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderContext {
    pub required_key: u64,
    pub builder_code: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OuterActionResult {
    pub slot: u64,
    pub result: ActionResult,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssetLeverageUpdate {
    pub user: Address,
    pub asset: AssetId,
    pub required_key: u64,
    pub cross: bool,
    pub leverage: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssetPositionDelta {
    pub user: Address,
    pub asset: AssetId,
    pub required_key: u64,
    pub delta: i128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GateTarget {
    pub dex_arg_is_resolved: bool,
    pub dex_or_settlement: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InnerApply {
    pub required_key: u64,
    pub count: u64,
    pub kind: InnerApplyKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InnerApplyKind {
    CDeposit,
    Withdraw3,
    WithdrawLikeA,
    WithdrawLikeB,
    VaultTransfer,
    SpotDeploy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortfolioLocation {
    Spot,
    Dex(DexIndex),
}

impl PortfolioLocation {
    #[inline]
    pub const fn is_dex(self) -> bool {
        matches!(self, Self::Dex(_))
    }

    #[inline]
    pub const fn dex_index(self) -> Option<DexIndex> {
        match self {
            Self::Spot => None,
            Self::Dex(dex) => Some(dex),
        }
    }

    #[inline]
    pub const fn same_presence_and_address(self, other: &Self, _actor: Address) -> bool {
        matches!((self, *other), (Self::Spot, Self::Spot) | (Self::Dex(_), Self::Dex(_)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountAbstractionRequest {
    pub source: PortfolioLocation,
    pub destination: PortfolioLocation,
    pub source_address: Address,
    pub abstraction_address: Option<Address>,
    pub requires_abstraction_address: bool,
    pub allow_self_tree_alias: bool,
    pub collateral: SettlementAsset,
    pub notional_e6: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbstractionEnvelope {
    pub source: PortfolioLocation,
    pub destination: PortfolioLocation,
    pub source_name: String,
    pub destination_name: String,
    pub actor: Address,
    pub source_address: Address,
    pub collateral: SettlementAsset,
    pub notional_e6: u64,
    pub effective_class: UserClass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplyContext {
    pub block_time: u64,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SideEffectMode {
    /// Uses `seed / 10_000`; only allocates a dex target for classes that can
    /// cross the abstraction gate.
    SingleGlobalAsset = 0,
    /// Uses `seed` directly as the dex index.
    SingleDex = 1,
    OpenDexOnly = 2,
    SpotAndDexFromBook = 3,
    AllDexes = 4,
    AllNonRemovedDexes = 5,
    EmitNotionalCapEvent = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SideEffectTarget {
    Spot(u64),
    Dex(DexIndex),
}

impl SideEffectTarget {
    #[inline]
    pub const fn dex_index(self) -> Option<DexIndex> {
        match self {
            Self::Spot(_) => None,
            Self::Dex(dex) => Some(dex),
        }
    }
}

pub trait AbstractionBackend {
    fn user_class(&self, layout: ExchangeLayout, user: Address) -> UserClass;
    fn user_class_enabled(&self, layout: ExchangeLayout, class: UserClass) -> bool;
    fn class2_dex_destination_enabled(&self, layout: ExchangeLayout) -> bool;

    fn apply_order_action(
        &mut self,
        state: &mut ExchangeAbstraction,
        layout: ExchangeLayout,
        order: &OrderAction,
        user: Address,
        context: &OrderContext,
    ) -> ActionResult;

    fn apply_collateral_action(
        &mut self,
        state: &mut ExchangeAbstraction,
        layout: ExchangeLayout,
        asset: AssetId,
        user: Address,
        context: &OrderContext,
    ) -> ActionResult;

    fn apply_asset_leverage(
        &mut self,
        state: &mut ExchangeAbstraction,
        layout: ExchangeLayout,
        req: &AssetLeverageUpdate,
    ) -> ActionResult;

    fn apply_asset_position_delta(
        &mut self,
        state: &mut ExchangeAbstraction,
        layout: ExchangeLayout,
        req: &AssetPositionDelta,
    ) -> ActionResult;

    fn apply_inner(&mut self, state: &mut ExchangeAbstraction, layout: ExchangeLayout, inner: &InnerApply) -> ActionResult;

    fn apply_abstraction_inner(
        &mut self,
        state: &mut ExchangeAbstraction,
        layout: ExchangeLayout,
        envelope: &AbstractionEnvelope,
        ctx: ApplyContext,
    ) -> ActionResult;

    fn apply_generated_order(
        &mut self,
        state: &mut ExchangeAbstraction,
        layout: ExchangeLayout,
        order: &GeneratedOrder,
        ctx: ApplyContext,
    ) -> ActionResult;

    fn should_preflight_actor(&self, layout: ExchangeLayout, actor: Address) -> bool;
    fn preflight_abstraction_actor(
        &mut self,
        state: &mut ExchangeAbstraction,
        layout: ExchangeLayout,
        actor: Address,
        collateral: SettlementAsset,
    ) -> ActionResult;

    fn pre_mutation(
        &mut self,
        state: &mut ExchangeAbstraction,
        layout: ExchangeLayout,
        user: Address,
        settlement_asset: SettlementAsset,
        enter: bool,
        dex: DexIndex,
        privileged: bool,
    );

    fn recheck_user_settlement(
        &mut self,
        state: &mut ExchangeAbstraction,
        layout: ExchangeLayout,
        user: Address,
        settlement_asset: SettlementAsset,
        enter: bool,
        dex: DexIndex,
        hard: bool,
    ) -> ActionResult;

    fn finalize_privileged(
        &mut self,
        state: &mut ExchangeAbstraction,
        layout: ExchangeLayout,
        user: Address,
        settlement_asset: SettlementAsset,
        enter: bool,
        dex: DexIndex,
    );

    fn post_generated_order(
        &mut self,
        state: &mut ExchangeAbstraction,
        layout: ExchangeLayout,
        user: Address,
        settlement_asset: SettlementAsset,
    );

    fn emit_dex_notional_cap_event(&mut self, user: Address, dex: DexIndex, dex_name: &str, settlement_asset: SettlementAsset);
    fn propagate_soft_failure(&mut self, result: &ActionResult);
    fn propagate_hard_failure(&mut self, result: &ActionResult);
}

pub const fn asset_to_api_id(asset: AssetId) -> Option<i64> {
    if asset < PERP_ASSET_STRIDE {
        Some(asset as i64)
    } else if asset <= MAX_API_ASSET_BEFORE_OFFSET {
        Some((asset + API_PERP_OFFSET) as i64)
    } else {
        None
    }
}
