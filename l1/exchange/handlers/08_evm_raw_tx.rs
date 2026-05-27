//! EvmRawTx action handler.
//!
//! Reconstructed from `l1_action_evm_raw_tx__validate_and_apply_raw_tx`
//! (`0x1F661C0`) with supporting context from:
//! - `recon/l1/src/action/evm_raw_tx.rs`
//! - `recon/l1/src/evm/transactor.rs`
//! - `recon/l1/src/exchange/impl_execute_action.rs`
//!
//! This file focuses on the handler path: admission gates, transaction validation,
//! pending-pool insertion, and the state touched on success.

pub const HANDLER_STATUS_SUCCESS: u16 = 390;
pub const HANDLER_STATUS_USER_MISSING: u16 = 327;
pub const HANDLER_STATUS_INVALID: u16 = 331;
pub const HANDLER_STATUS_EVM_DISABLED: u16 = 142;
pub const HANDLER_STATUS_POOL_EVICTED: u16 = 335;

pub const MAX_RAW_TX_BYTES: usize = 0x3e800;
pub const MAX_CALLDATA_BYTES: usize = 0x20000;
pub const LARGE_CALLDATA_EMPTY_PREFIX_THRESHOLD: usize = 0xc001;
pub const MIN_FEE_CAP_WEI: u64 = 100_000_000;
pub const NORMAL_ACCOUNT_GAS_LIMIT: u64 = 3_000_000;
pub const BIG_BLOCK_ACCOUNT_GAS_LIMIT: u64 = 30_000_000;
pub const NONCE_LOOKAHEAD: u64 = 8;

pub type Address = [u8; 20];
pub type B256 = [u8; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmRawTxAction {
    /// Raw signed Ethereum transaction bytes.
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct U256(pub [u64; 4]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature {
    pub odd_y_parity: bool,
    pub r: B256,
    pub s: B256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignedEthTxKind {
    Legacy,
    Eip2930,
    Eip1559,
    Eip4844,
    Eip7702,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedEthTxSummary {
    pub kind: SignedEthTxKind,
    pub chain_id: Option<u64>,
    pub nonce: u64,
    pub gas_limit: u64,
    pub fee_cap: U256,
    pub priority_fee: Option<U256>,
    pub value: U256,
    pub input_len: usize,
    pub input_starts_with_zero: bool,
    pub signature: Signature,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvmAccountView {
    pub nonce: u64,
    pub balance: U256,
    pub big_block_gas_limit: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedEvmRawTx {
    pub sender: Address,
    pub tx_hash: B256,
    pub signable_hash: B256,
    pub intrinsic_gas: u64,
    pub upfront_cost: U256,
    pub tx: SignedEthTxSummary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxSnapshot {
    pub sender: Address,
    pub tx_key: B256,
    pub nonce: u64,
    pub gas_limit: u64,
    pub fee_cap: U256,
    pub priority_fee: U256,
    pub value: U256,
    pub upfront_cost: U256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawTxPoolAccountCtx {
    pub address: Address,
    pub account_key: u64,
    pub account_subkey: u32,
    pub nonce: u64,
    pub balance: U256,
    pub big_block_gas_limit: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawTxPoolInsertResult {
    Evicted = HANDLER_STATUS_POOL_EVICTED as isize,
    Retained = HANDLER_STATUS_SUCCESS as isize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RawTxDecodeError {
    Empty,
    UnsupportedTypedTransaction(u8),
    RlpExpectedList,
    RlpExpectedBytes,
    RlpTrailingBytes,
    RlpInputTooShort,
    RlpNonCanonical,
    RlpWrongFieldCount { expected: usize, actual: usize },
    InvalidAddressLength(usize),
    InvalidHashLength(usize),
    InvalidLegacyV(U256),
    InvalidYParity(U256),
    IntegerTooLarge,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RawTxApplyError {
    EvmDisabled,
    SignerNotRegistered,
    RawTransactionTooLarge { len: usize, max: usize },
    Decode(RawTxDecodeError),
    UnsupportedForBlockExecution,
    InvalidSignature,
    WrongChainId { expected: u64, actual: u64 },
    CallDataTooLarge { len: usize, max: usize },
    LargeCallDataStartsWithZero { len: usize },
    GasLimitTooHigh { gas_limit: u64, max: u64 },
    FeeCapTooLow { fee_cap: U256, min: U256 },
    PriorityFeeAboveFeeCap { priority_fee: U256, fee_cap: U256 },
    IntrinsicGasTooHigh { intrinsic: u64, gas_limit: u64 },
    NonceTooLow { account_nonce: u64, tx_nonce: u64 },
    NonceTooHigh { account_nonce: u64, tx_nonce: u64, lookahead: u64 },
    BalanceTooLow { balance: U256, required: U256 },
    /// The binary performs additional pool-conflict / replacement checks before the
    /// final insert. The exact helper names are still unresolved, but rejection here
    /// is surfaced through the generic invalid-action wrapper.
    PendingPoolConflict,
    PoolEvicted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandlerStepKind {
    PreDispatch,
    AdmissionGate,
    Decode,
    SignatureRecovery,
    EnvelopeValidation,
    AccountValidation,
    PendingPoolValidation,
    StateMutation,
    Return,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandlerStep {
    pub kind: HandlerStepKind,
    pub detail: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmRawTxHandlerFlow {
    pub handler_ea: u64,
    pub action_tag: &'static str,
    pub generic_nonce_gate_before_dispatch: bool,
    pub success_status: u16,
    pub error_statuses: &'static [u16],
    pub touched_state: &'static [&'static str],
    pub steps: &'static [HandlerStep],
}

pub const EVM_RAW_TX_HANDLER_FLOW: EvmRawTxHandlerFlow = EvmRawTxHandlerFlow {
    handler_ea: 0x1F66_1C0,
    action_tag: "EvmRawTx",
    generic_nonce_gate_before_dispatch: true,
    success_status: HANDLER_STATUS_SUCCESS,
    error_statuses: &[
        HANDLER_STATUS_EVM_DISABLED,
        HANDLER_STATUS_USER_MISSING,
        HANDLER_STATUS_INVALID,
        HANDLER_STATUS_POOL_EVICTED,
    ],
    touched_state: &[
        "l1_state.foundation_self_signer_addresses",
        "exchange user registry / signer lookup tree",
        "evm account view for recovered sender",
        "pending raw-tx index keyed by sender",
        "small_raw_tx_pool or big_raw_tx_pool",
        "pool prune reference derived from account nonce/balance/gas tier",
    ],
    steps: &[
        HandlerStep {
            kind: HandlerStepKind::PreDispatch,
            detail: "The shared exchange nonce validator runs before the action-switch dispatch. EvmRawTx does not add a second handler-local replay domain.",
        },
        HandlerStep {
            kind: HandlerStepKind::AdmissionGate,
            detail: "Reject with status 142 when `l1_state.evm_enabled` is false.",
        },
        HandlerStep {
            kind: HandlerStepKind::AdmissionGate,
            detail: "If the signed-action `signer_or_sender20` is not present in `foundation_self_signer_addresses`, require it to exist in the exchange user registry; otherwise return status 327 before decoding the raw transaction.",
        },
        HandlerStep {
            kind: HandlerStepKind::Decode,
            detail: "Reject raw byte blobs longer than 0x3e800 bytes, then decode the Ethereum envelope. The decoder understands Legacy, EIP-2930, EIP-1559, EIP-4844, and EIP-7702 framing.",
        },
        HandlerStep {
            kind: HandlerStepKind::EnvelopeValidation,
            detail: "Only Legacy, EIP-2930, and EIP-1559 continue through the block-execution path. EIP-4844 and EIP-7702 decode successfully but are rejected as unsupported for this handler.",
        },
        HandlerStep {
            kind: HandlerStepKind::SignatureRecovery,
            detail: "Build the signable encoding, keccak it, require a low-`s` signature, and recover the EVM sender address from `(signable_hash, signature)`.",
        },
        HandlerStep {
            kind: HandlerStepKind::EnvelopeValidation,
            detail: "If the transaction carries a chain id, it must equal the chain id from L1 state. Calldata must be at most 0x20000 bytes, and calldata of length >= 0xc001 must not start with `0x00`.",
        },
        HandlerStep {
            kind: HandlerStepKind::AccountValidation,
            detail: "Load the recovered sender account view. Gas limit is capped at 3,000,000 for normal accounts or 30,000,000 for big-block accounts.",
        },
        HandlerStep {
            kind: HandlerStepKind::AccountValidation,
            detail: "Require `fee_cap >= 100_000_000 wei`, and when a priority fee is present, require `priority_fee <= fee_cap`.",
        },
        HandlerStep {
            kind: HandlerStepKind::AccountValidation,
            detail: "Compute intrinsic gas from the envelope and reject when `gas_limit < intrinsic_gas`.",
        },
        HandlerStep {
            kind: HandlerStepKind::AccountValidation,
            detail: "Enforce sender nonce window: `tx_nonce` must be `>= account.nonce` and `< account.nonce + 8`.",
        },
        HandlerStep {
            kind: HandlerStepKind::AccountValidation,
            detail: "Compute upfront cost as `fee_cap * gas_limit + value` and reject when sender balance is insufficient.",
        },
        HandlerStep {
            kind: HandlerStepKind::PendingPoolValidation,
            detail: "[INFERENCE] The handler materializes a tx snapshot, looks up existing pending state for the recovered sender, and runs additional replacement / ordering checks before final pool insertion. Those checks sit between validation and the transactor insert helper in the binary.",
        },
        HandlerStep {
            kind: HandlerStepKind::StateMutation,
            detail: "Insert the tx snapshot into `small_raw_tx_pool` or `big_raw_tx_pool` via `l1_evm_transactor__insert_raw_tx_and_prune_pool` (`0x3272280`). The chosen pool matches the sender's big-block account flag.",
        },
        HandlerStep {
            kind: HandlerStepKind::StateMutation,
            detail: "When the selected pool crosses its prune threshold, derive a prune-reference transaction from `(account nonce, balance-derived fee floor, gas tier, account key)` and trim the pool to the priority window. Per-sender retention is capped at eight entries.",
        },
        HandlerStep {
            kind: HandlerStepKind::Return,
            detail: "Return status 390 only if the inserted tx key is still present after pruning. If the fresh tx is immediately pruned out, the helper returns status 335 and the action fails.",
        },
    ],
};

pub fn describe_validate_and_apply_raw_tx() -> &'static EvmRawTxHandlerFlow {
    &EVM_RAW_TX_HANDLER_FLOW
}
