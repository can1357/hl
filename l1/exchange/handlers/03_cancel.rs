#![allow(dead_code)]

pub type Address = [u8; 20];
pub type AssetId = u64;
pub type DexId = u64;
pub type OrderId = u64;

pub const CANCEL_HANDLER_EA: u64 = 0x22BE610;
pub const CANCEL_CORE_EA: u64 = 0x2721120;
pub const STATUS_SUCCESS: u16 = 390;
pub const STATUS_CANCEL_BATCH_TOO_LARGE: u16 = 323;
pub const CANCEL_MAX_BATCH_EXCLUSIVE: usize = 0x2711;

/// Wire entry lowered by `sub_2518AD0` before the per-item cancel loop runs.
///
/// Current IDA evidence:
/// - each source entry occupies 16 bytes;
/// - `+0x00..0x07` is copied into the internal order-id slot;
/// - `+0x08..0x0b` is copied into the internal asset slot;
/// - the single control byte at internal offset `+0x08` is forced to zero for this
///   handler, so the normal `Cancel` path always resolves by explicit `oid` rather than
///   the alternate lookup branch used elsewhere.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct CancelTarget {
    pub oid: OrderId,
    pub asset: u32,
    pub _pad: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct CancelAction {
    pub cancels: Vec<CancelTarget>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireAssetRoute {
    Perp { dex_id: DexId, local_asset: AssetId },
    Spot { asset: AssetId },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionResult {
    pub code: u16,
    pub user: Address,
    pub asset: AssetId,
    pub generated_effects: Vec<GeneratedEffect>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GeneratedEffect {
    Cancelled { asset: AssetId, oid: OrderId },
    BookSideEffect,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelItemResult {
    pub target: CancelTarget,
    pub route: Result<WireAssetRoute, u16>,
    pub result: ActionResult,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CancelApplyResult {
    Applied { item_results: Vec<CancelItemResult> },
    RejectedBatch { status: u16, count: usize },
}

/// Minimal interface the recovered handler needs from exchange state.
///
/// This matches the observed control flow without inventing unrelated policy:
/// - count the batch toward the exchange-side action meter (`state + 2168` in IDA);
/// - optionally mirror the current user/epoch into the privileged-vault audit slots
///   (`state + 15000/+15008`);
/// - classify the wire asset exactly once per cancel;
/// - dispatch into either the perp-book or the spot-book removal path.
pub trait CancelEngine {
    fn add_to_user_action_meter(&mut self, delta: u64);
    fn signer_is_vault_privileged_group_a(&self, signer: &Address) -> bool;
    fn signer_is_vault_privileged_group_a_0(&self, signer: &Address) -> bool;
    fn record_privileged_vault_actor(&mut self);

    fn classify_wire_asset(&self, wire_asset: u32) -> Result<WireAssetRoute, u16>;
    fn cancel_perp(&mut self, signer: Address, dex_id: DexId, local_asset: AssetId, oid: OrderId) -> ActionResult;
    fn cancel_spot(&mut self, signer: Address, asset: AssetId, oid: OrderId) -> ActionResult;
}

/// Recovered `Cancel` handler.
///
/// Grounded by `sub_22BE610`, `sub_2721120`, `sub_2518AD0`, `sub_251A180`,
/// `sub_24BBCF0`, and the spot-only branch `sub_2726AF0`.
///
/// Observed flow:
/// 1. Clone the incoming cancel vector into owned storage.
/// 2. Reject immediately when `len >= 0x2711` with status `323`.
/// 3. Add the batch length to the exchange-side action counter.
/// 4. If the signer belongs to either privileged vault group-A predicate, refresh the
///    dedicated attribution slots before applying the cancels.
/// 5. For each target, classify the wire asset, then remove the order from either the
///    routed perp book or the routed spot book.
/// 6. Return a top-level success code (`390`) with one nested `ActionResult` per entry.
///
/// The generic user-action nonce gate runs before dispatch enters this handler, so there
/// is no handler-local nonce check here.
pub fn apply_cancel_action<E: CancelEngine>(engine: &mut E, signer: Address, action: &CancelAction) -> CancelApplyResult {
    let owned = action.cancels.clone();
    if owned.len() >= CANCEL_MAX_BATCH_EXCLUSIVE {
        return CancelApplyResult::RejectedBatch {
            status: STATUS_CANCEL_BATCH_TOO_LARGE,
            count: owned.len(),
        };
    }

    engine.add_to_user_action_meter(owned.len() as u64);

    if engine.signer_is_vault_privileged_group_a_0(&signer)
        || engine.signer_is_vault_privileged_group_a(&signer)
    {
        engine.record_privileged_vault_actor();
    }

    let mut item_results = Vec::with_capacity(owned.len());
    for target in owned {
        let route = engine.classify_wire_asset(target.asset);
        let result = match route {
            Ok(WireAssetRoute::Perp { dex_id, local_asset }) => {
                engine.cancel_perp(signer, dex_id, local_asset, target.oid)
            }
            Ok(WireAssetRoute::Spot { asset }) => engine.cancel_spot(signer, asset, target.oid),
            Err(code) => ActionResult {
                code,
                user: signer,
                asset: target.asset as AssetId,
                generated_effects: Vec::new(),
            },
        };
        item_results.push(CancelItemResult { target, route, result });
    }

    CancelApplyResult::Applied { item_results }
}
