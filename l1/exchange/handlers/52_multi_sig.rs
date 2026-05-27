pub type Address = [u8; 20];

pub const STATUS_SUCCESS: u16 = 390;

/// Lowered action record shape recovered from the shared dispatcher at `0x2759240`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionRecord {
    pub discriminant: u64,
    pub payload: [u8; 232],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BaseActionOutcome {
    Success { status: u16 },
    Error { status: u16, raw: [u8; 96] },
}

/// User-visible `MultiSigAction` envelope.
///
/// Grounded by the dedicated payload parser at `0x20A7800` plus its nested field
/// decoder at `0x20E3F70`:
/// - required fields: `multiSigUser`, `outerSigner`, `action`
/// - map/object form and 3-element tuple/sequence form are both accepted
/// - the `action` field is decoded with the same generic nested-action parser used
///   for ordinary top-level actions
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiSigAction {
    pub multi_sig_user: Address,
    pub outer_signer: Address,
    pub action: Box<ActionRecord>,
}

/// Lowered payload actually consumed by the concrete apply wrapper.
///
/// In the `UserActionTag::MultiSig` arm of `dispatch_base_action_outcome`
/// (`0x2759240`), the dispatcher does **not** pass the whole outer payload into
/// `sub_282EE50`. Instead it extracts the nested action pointer stored inside the
/// lowered payload and calls:
///
/// `sub_282EE50(out, inner_action, user_key20, exchange_state)`
///
/// So by the time the handler runs, all multisig-specific authorization work has
/// already happened upstream; the handler only re-enters the generic action
/// dispatcher on the prepared inner action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedMultiSigAction {
    pub inner_action: Box<ActionRecord>,
}

pub trait MultiSigDispatcher {
    fn evm_chain_byte(&self) -> u8;

    fn dispatch_base_action_outcome(
        &mut self,
        action: &ActionRecord,
        force_timing: u8,
        action_tag_for_sampling: u8,
        user_key20: &Address,
    ) -> BaseActionOutcome;
}

/// Concrete handler body recovered from `sub_282EE50` (`0x282EE50`).
///
/// Exact control flow:
/// 1. Read `chain_byte = exchange_state.evm_chain_byte()`.
/// 2. Tail back into the shared `dispatch_base_action_outcome` routine.
/// 3. Dispatch the already-materialized nested action with `force_timing = 0` and
///    `action_tag_for_sampling = chain_byte`.
///
/// There are no multisig-specific state mutations here. Any threshold checks,
/// signer matching, unsupported-inner-action rejection, or remapping from the
/// outer signer to the multisig user happens before this wrapper is reached.
#[inline]
pub fn apply_multi_sig<D: MultiSigDispatcher>(
    dispatcher: &mut D,
    action: &PreparedMultiSigAction,
    user_key20: &Address,
) -> BaseActionOutcome {
    let chain_byte = dispatcher.evm_chain_byte();
    dispatcher.dispatch_base_action_outcome(action.inner_action.as_ref(), 0, chain_byte, user_key20)
}

/// Source-level equivalent of the outer `UserActionTag::MultiSig` dispatcher arm.
#[inline]
pub fn dispatch_multi_sig<D: MultiSigDispatcher>(
    dispatcher: &mut D,
    action: &PreparedMultiSigAction,
    user_key20: &Address,
) -> BaseActionOutcome {
    apply_multi_sig(dispatcher, action, user_key20)
}
