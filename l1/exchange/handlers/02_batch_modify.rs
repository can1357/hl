#![allow(dead_code)]

pub type Address = [u8; 20];
pub type AssetId = u32;
pub type OrderId = u64;

pub const OK: u16 = 390;
pub const ERR_BATCH_TOO_LARGE: u16 = 323;
pub const ERR_MODIFY_MISSING_ORDER: u16 = 56;
pub const ERR_MODIFY_INVALID_NEW_ORDER: u16 = 57;
pub const ERR_MODIFY_RESUBMIT: u16 = 58;
pub const ERR_ALT_BOOK_BRANCH_DISABLED: u16 = 249;
pub const MAX_BATCH_MODIFIES: usize = 10_000;

/// `batchModify` action payload used by `0x21DFD90`.
///
/// The binary stores the vector at payload `+0x08`; each entry is 80 bytes and is
/// passed through the same single-modify helper used by `Modify` (`0x22BE760`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchModifyAction {
    pub modifies: Vec<ModifyEntry>,
}

/// Observed 80-byte entry layout.
///
/// The wrapper splits each entry into a 24-byte selector block and a 56-byte
/// order block before calling `l1_perp_dex__sub_modify_order_across_dex`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModifyEntry {
    pub selector: ModifySelector,
    pub order: ModifyOrderWire,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModifySelector {
    raw: [u8; 24],
}

impl ModifySelector {
    /// Existing order id used for the `find_order_by_user_oid` lookup.
    #[inline]
    pub fn old_oid(&self) -> OrderId {
        u64::from_le_bytes(self.raw[8..16].try_into().unwrap())
    }

    /// Bit 0 gates an extra pre-lookup filter checked before the main order
    /// lookup. The remaining selector bytes are forwarded opaquely.
    #[inline]
    pub fn has_extra_filter(&self) -> bool {
        self.raw[0] & 1 == 1
    }

    #[inline]
    pub fn raw(&self) -> &[u8; 24] {
        &self.raw
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModifyOrderWire {
    raw: [u8; 56],
}

impl ModifyOrderWire {
    /// Wire asset id read by the shared modify helper before book selection.
    #[inline]
    pub fn asset(&self) -> AssetId {
        u32::from_le_bytes(self.raw[32..36].try_into().unwrap())
    }

    /// Optional 16-byte auxiliary id copied when byte `+0x3c` is set.
    #[inline]
    pub fn aux_id(&self) -> Option<[u8; 16]> {
        (self.raw[0x3c] == 1).then(|| self.raw[0x3d..0x4d].try_into().unwrap())
    }

    /// Final byte pair copied verbatim into the single-modify helper's compact
    /// order representation. They participate in compatibility checks against the
    /// existing resting order.
    #[inline]
    pub fn terminal_flags(&self) -> (u8, u8) {
        (self.raw[0x4d], self.raw[0x4e])
    }

    #[inline]
    pub fn raw(&self) -> &[u8; 56] {
        &self.raw
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionResult {
    pub code: u16,
}

impl ActionResult {
    #[inline]
    pub const fn ok() -> Self {
        Self { code: OK }
    }

    #[inline]
    pub const fn err(code: u16) -> Self {
        Self { code }
    }
}

/// Shape returned by the `BatchModify` dispatch arm.
///
/// Success returns a staged copy of the modify list plus one per-entry result.
/// Overflow rejects the whole action before any per-entry apply calls run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchModifyDispatch {
    Applied {
        staged_modifies: Vec<ModifyEntry>,
        results: Vec<ActionResult>,
    },
    RejectedTooLarge {
        code: u16,
        staged_modifies: Vec<ModifyEntry>,
    },
}

/// Hook surface for the shared single-modify helper at `0x271C490`.
///
/// The binary batch wrapper does not implement modify logic itself. It clones the
/// entry vector and then invokes the same helper as the standalone `Modify`
/// action once per staged entry.
///
/// The shared helper performs, in order:
/// 1. classify the wire asset and choose the direct-price or indexed-price book path;
/// 2. validate the replacement order's admission/risk checks for that market;
/// 3. optionally enforce the selector-side prefilter before the main lookup;
/// 4. locate the current resting order by `(user, old_oid)`;
/// 5. reject mismatched side/type families with `ERR_MODIFY_INVALID_NEW_ORDER`;
/// 6. remove the old order, insert the replacement, and repair child/trigger links;
/// 7. process generated fills/events on success;
/// 8. map missing order to `ERR_MODIFY_MISSING_ORDER`, invalid replacement to
///    `ERR_MODIFY_INVALID_NEW_ORDER`, and resubmit/no-fill after removal to
///    `ERR_MODIFY_RESUBMIT`.
///
/// The alternate indexed-book branch is short-circuited with `249` when the
/// corresponding exchange-state gate is disabled.
pub trait ModifyApplyHooks {
    fn apply_single_modify_across_dex(&mut self, user: Address, modify: &ModifyEntry) -> ActionResult;
}

/// Reconstruction of `0x21DFD90` (`l1_exchange_impl_execute_action__batch_modify`).
///
/// Notable wrapper behavior grounded in the binary:
/// - clones the incoming modify list into owned staging memory even on success;
/// - rejects `len > 10_000` with code `323` before any state mutation;
/// - otherwise applies every staged modify sequentially against the same exchange
///   state and collects each helper result into a 96-byte per-entry result row;
/// - does not stop at the first failure and does not roll back earlier mutations.
pub fn batch_modify_handler<H: ModifyApplyHooks>(
    hooks: &mut H,
    user: Address,
    action: &BatchModifyAction,
) -> BatchModifyDispatch {
    let staged_modifies = action.modifies.clone();
    if staged_modifies.len() > MAX_BATCH_MODIFIES {
        return BatchModifyDispatch::RejectedTooLarge {
            code: ERR_BATCH_TOO_LARGE,
            staged_modifies,
        };
    }

    let mut results = Vec::with_capacity(staged_modifies.len());
    for modify in &staged_modifies {
        results.push(hooks.apply_single_modify_across_dex(user, modify));
    }

    BatchModifyDispatch::Applied {
        staged_modifies,
        results,
    }
}
