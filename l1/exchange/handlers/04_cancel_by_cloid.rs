//! Cancel-by-cloid action handler.
//!
//! Handler EA: `0x21DFF60` (`sub_21DFF60`)
//! Shared cancel helper: `0x2725010`
//! Common cancel executor: `0x24BBCF0`
//! Downstream order path: `l1_perp_dex__submit_or_simulate_order` (`0x275A380`)
//!
//! The generic signed-action nonce gate runs before this handler reaches the
//! 76-way execute-action switch, so there is no handler-local nonce logic here.

#![allow(dead_code)]

pub const STATUS_OK: u16 = 390;
pub const STATUS_TOO_MANY_CANCELS: u16 = 323;
pub const MAX_CANCELS_PER_ACTION: usize = 10_000;

pub type WireAssetId = u32;
pub type OrderId = u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Address(pub [u8; 20]);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Cloid(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancelByCloidEntry {
    /// Wire asset id passed into `classify_wire_asset_id(...)`.
    pub asset: WireAssetId,
    /// Raw 128-bit client order id.
    pub cloid: Cloid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelByCloidAction {
    pub cancels: Vec<CancelByCloidEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelSelector {
    OrderId(OrderId),
    Cloid(Cloid),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InternalCancelRequest {
    pub asset: WireAssetId,
    pub selector: CancelSelector,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelKind {
    ByOrderId = 2,
    ByCloid = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivilegedSnapshot {
    /// Exchange slot `+15000`.
    pub signer: Address,
    /// Exchange slot `+15008`.
    pub lane_or_user_slot: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelEngineReport {
    pub status: u16,
    pub per_cancel: Vec<PerCancelReport>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerCancelReport {
    pub status: u16,
    pub asset: WireAssetId,
    pub selector: CancelSelector,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CancelByCloidResult {
    Applied(CancelEngineReport),
    TooManyCancels { submitted: usize },
}

/// Minimal handler-facing exchange state recovered from `0x2725010`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExchangeCancelState {
    /// Monotonic action-local accounting slot at exchange offset `+2168`.
    pub cancel_request_counter: u64,
    /// Updated only for vault-privileged callers.
    pub privileged_snapshot: Option<PrivilegedSnapshot>,
}

/// [INFERENCE] Per-user/per-asset cloid lookup index consumed by the downstream
/// cancel engine.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UserAssetCloidIndex {
    pub entries: std::collections::BTreeMap<(Address, WireAssetId), std::collections::BTreeMap<Cloid, OrderId>>,
}

impl UserAssetCloidIndex {
    #[inline]
    pub fn lookup(&self, user: &Address, asset: WireAssetId, cloid: Cloid) -> Option<OrderId> {
        self.entries.get(&(*user, asset)).and_then(|orders| orders.get(&cloid)).copied()
    }
}

pub trait CancelByCloidHooks {
    /// Mirrors the pair of privilege checks in `0x2725010`.
    fn is_vault_privileged_group_a_0(&self, signer: &Address) -> bool;
    fn is_vault_privileged_group_a(&self, signer: &Address) -> bool;

    /// Captures the current signer/lane into exchange offsets `+15000/+15008`
    /// when the action is sent from a vault-privileged lane.
    fn current_lane_or_user_slot(&self) -> u32;

    /// Shared cancel engine. The live binary forwards `CancelKind::ByCloid`
    /// into `l1_perp_dex__submit_or_simulate_order`, which classifies the wire
    /// asset, resolves the cloid inside the book-specific user/asset index, and
    /// then runs the common remove-order path.
    fn cancel_requests(
        &mut self,
        signer: &Address,
        kind: CancelKind,
        requests: &[InternalCancelRequest],
    ) -> CancelEngineReport;
}

#[inline]
fn lift_cancel_requests(action: &CancelByCloidAction) -> Vec<InternalCancelRequest> {
    action
        .cancels
        .iter()
        .copied()
        .map(|cancel| InternalCancelRequest {
            asset: cancel.asset,
            selector: CancelSelector::Cloid(cancel.cloid),
        })
        .collect()
}

/// Reconstructed `CancelByCloid` handler.
///
/// Exact flow grounded in `0x21DFF60 -> 0x2725010 -> 0x24BBCF0`:
///
/// 1. Clone the wire `cancels` vector into owned handler memory.
/// 2. Reject `len > 10_000` with status `323`; the failure payload carries the
///    submitted length.
/// 3. Rewrite each 20-byte wire entry into a 32-byte internal cancel request
///    tagged as `CancelKind::ByCloid`.
/// 4. Add the request count to exchange offset `+2168`, saturating to `u64::MAX`
///    on overflow.
/// 5. If the signer is in either vault-privileged group, snapshot the current
///    signer/lane into exchange offsets `+15000/+15008`.
/// 6. Forward the internal requests into the shared cancel engine.
///
/// The actual cloid-to-order lookup is not performed in this thin wrapper.
/// Downstream, `l1_perp_dex__submit_or_simulate_order` checks the request tag,
/// hashes `(user, asset)` into a per-book lookup structure, resolves the 16-byte
/// cloid to an order id, and then reuses the normal cancel/remove path.
pub fn apply_cancel_by_cloid<H: CancelByCloidHooks>(
    exchange: &mut ExchangeCancelState,
    hooks: &mut H,
    signer: &Address,
    action: &CancelByCloidAction,
) -> CancelByCloidResult {
    let owned_cancels = action.cancels.clone();
    let cancel_count = owned_cancels.len();
    if cancel_count > MAX_CANCELS_PER_ACTION {
        return CancelByCloidResult::TooManyCancels {
            submitted: cancel_count,
        };
    }

    let internal_requests = lift_cancel_requests(&CancelByCloidAction {
        cancels: owned_cancels,
    });

    exchange.cancel_request_counter = exchange
        .cancel_request_counter
        .saturating_add(cancel_count as u64);

    if hooks.is_vault_privileged_group_a_0(signer) || hooks.is_vault_privileged_group_a(signer) {
        exchange.privileged_snapshot = Some(PrivilegedSnapshot {
            signer: *signer,
            lane_or_user_slot: hooks.current_lane_or_user_slot(),
        });
    }

    CancelByCloidResult::Applied(hooks.cancel_requests(
        signer,
        CancelKind::ByCloid,
        &internal_requests,
    ))
}
