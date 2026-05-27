pub const STATUS_SUCCESS: u16 = 390;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NoopAction;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BaseActionOutcome {
    Success { status: u16 },
    Error { status: u16, raw: [u8; 96] },
}

/// Recovered from `l1_exchange_end_block__dispatch_base_action_outcome`
/// (`0x2759240`): case `UserActionTag::Noop == 0` does not call a handler.
/// The switch jumps straight to the shared success arm, which encodes variant
/// tag `13` / status `390` and returns with no payload-derived mutations.
///
/// The real effect of a signed `noop` happens before this point:
/// - generic exchange nonce validation/reservation succeeds upstream;
/// - the retained nonce set is updated there;
/// - this apply step then accepts the action without touching balances,
///   positions, registry state, or emitting deferred effects.
#[inline]
pub fn apply_noop(_action: &NoopAction) -> BaseActionOutcome {
    BaseActionOutcome::Success {
        status: STATUS_SUCCESS,
    }
}

/// Lowered form of the concrete case-0 dispatch in the `0x2759240` jump table.
/// The surrounding dispatcher may collect timing samples before/after the match,
/// but the Noop arm itself is just the shared success return.
#[inline]
pub fn dispatch_noop(action: &NoopAction) -> BaseActionOutcome {
    apply_noop(action)
}
