#![allow(dead_code)]

use std::collections::BTreeSet;

pub const USER_ACTION_TAG_BASE: u64 = 0x74;
pub const USER_ACTION_VARIANT_COUNT: u8 = 76;
pub const NONCE_WINDOW_MS: u64 = 86_400_000;
pub const NONCE_SET_CAP_PRIMARY: usize = 100;
pub const NONCE_SET_CAP_NON_PRIMARY: usize = 400;
pub const STATUS_SUCCESS: u16 = 390;
pub const STATUS_WITHDRAW3_NONCE_ALREADY_USED: u16 = 0x5a;

/// Lowered form used by the concrete execution dispatcher at `0x2759240`.
///
/// The first 76 user-visible action variants are stored as
/// `discriminant = 0x74 + variant_index`. The same switch continues with 12
/// non-`Action` extensions after that range (`sendToEvmWithDestination`,
/// `userPortfolioMargin`, `userSetAbstraction`, `agentSetAbstraction`,
/// `userOutcome`, `gossipPriority`, `agentSendAsset`, `hip3Liquidator`,
/// `l1ValidatorVote`, `authorizeAqaV2`, `stakingLinkDisable`, `voteL1Hash`);
/// those are intentionally omitted here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionRecord {
    pub discriminant: u64,
    pub payload: [u8; 232],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum UserActionTag {
    Noop = 0,
    ApproveAgent3 = 1,
    BatchModify = 2,
    Cancel = 3,
    CancelByCloid = 4,
    ClaimRewards = 5,
    CreateSubAccount = 6,
    CreateVault = 7,
    EvmRawTx = 8,
    ForceIncreaseEpoch = 9,
    Liquidate = 10,
    LinkStakingUser = 11,
    Modify = 12,
    NetChildVaultPositions = 13,
    Order = 14,
    RegisterReferrer = 15,
    RegisterValidator = 16,
    CValidator = 17,
    ScheduleCancel = 18,
    SetDisplayName = 19,
    VoteGlobal = 20,
    ValidatorL1Vote = 21,
    ValidatorL1Stream = 22,
    ValidatorL1UpdateReferenceOracle = 23,
    SetGlobal = 24,
    SetReferrer = 25,
    SpotDeploy = 26,
    SpotUser = 27,
    SpotSend = 28,
    SignValidatorSetUpdate = 29,
    SubAccountModify = 30,
    SubAccountTransfer = 31,
    SubAccountSpotTransfer = 32,
    TokenDelegate = 33,
    TwapCancel = 34,
    TwapOrder = 35,
    UpdateIsolatedMargin = 36,
    TopUpIsolatedOnlyMargin = 37,
    UpdateLeverage = 38,
    UsdSend = 39,
    ValidatorSignWithdrawal = 40,
    VaultDistribute = 41,
    VaultModify = 42,
    VaultTransfer = 43,
    VoteEthDeposit = 44,
    VoteEthFinalizedValidatorSetUpdate = 45,
    VoteEthFinalizedWithdrawal = 46,
    Withdraw3 = 47,
    VoteAppHash = 48,
    GovPropose = 49,
    GovVote = 50,
    UsdClassTransfer = 51,
    MultiSig = 52,
    ConvertToMultiSigUser = 53,
    ApproveBuilderFee = 54,
    StartFeeTrial = 55,
    SystemBole = 56,
    SystemSpotSend = 57,
    DeployerSendToEvmForFrozenUser = 58,
    SystemUsdClassTransfer = 59,
    CSigner = 60,
    CWithdraw = 61,
    CDeposit = 62,
    CUserModify = 63,
    ReassessFees = 64,
    EvmUserModify = 65,
    ReserveRequestWeight = 66,
    FinalizeEvmContract = 67,
    Hip3Deploy = 68,
    SendAsset = 69,
    SystemApproveBuilderFee = 70,
    SystemSendAsset = 71,
    SystemAlignedQuoteSupplyDelta = 72,
    AgentEnableDexAbstraction = 73,
    UserDexAbstraction = 74,
    BorrowLend = 75,
}

impl UserActionTag {
    #[inline]
    pub fn from_action_record(record: &ActionRecord) -> Option<Self> {
        let index = record.discriminant.checked_sub(USER_ACTION_TAG_BASE)?;
        if index >= USER_ACTION_VARIANT_COUNT as u64 {
            return None;
        }
        // SAFETY: `index` is range-checked above and this enum is `#[repr(u8)]`.
        Some(unsafe { core::mem::transmute(index as u8) })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandlerRef {
    pub case_index: u8,
    pub wire_type: &'static str,
    pub rust_variant: &'static str,
    pub handler_ea: u64,
    pub handler_symbol: &'static str,
    pub notes: &'static str,
}

impl HandlerRef {
    pub const fn new(
        case_index: u8,
        wire_type: &'static str,
        rust_variant: &'static str,
        handler_ea: u64,
        handler_symbol: &'static str,
        notes: &'static str,
    ) -> Self {
        Self { case_index, wire_type, rust_variant, handler_ea, handler_symbol, notes }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonceError {
    BelowRetainedFloor { nonce_ms: u64, smallest_retained_ms: u64 },
    TooFarFuture { nonce_ms: u64, max_allowed_ms: u64 },
    TooOld { nonce_ms: u64, min_allowed_ms: u64 },
    Duplicate { nonce_ms: u64 },
    Withdraw3AlreadyUsed { nonce_ms: u64, stored_ms: u64, status: u16 },
}

/// Binary chain:
/// - `0x4D9B6B0` `l1_nonce__check_and_remember_exchange_nonce`
/// - `0x379AE30` `l1_exchange_impl_execute_action__lookup_user_nonce_bucket`
/// - `0x3577AE0` `l1_exchange_impl_execute_action__insert_user_nonce_bucket`
/// - `0x3986CC0` `l1_nonce__validate_candidate`
///
/// This generic nonce gate runs *before* the action reaches the 76-arm execution
/// switch. On success the nonce is inserted into the per-user retained set and
/// the smallest values are pruned until the bucket is back under the size cap.
#[inline]
pub fn validate_and_reserve_generic_nonce(
    retained_nonces_ms: &mut BTreeSet<u64>,
    now_ms: u64,
    non_primary_lane: bool,
    nonce_ms: u64,
) -> Result<(), NonceError> {
    let cap = if non_primary_lane {
        NONCE_SET_CAP_NON_PRIMARY
    } else {
        NONCE_SET_CAP_PRIMARY
    };

    if retained_nonces_ms.len() >= cap {
        if let Some(&smallest_retained_ms) = retained_nonces_ms.iter().next() {
            if nonce_ms < smallest_retained_ms {
                return Err(NonceError::BelowRetainedFloor {
                    nonce_ms,
                    smallest_retained_ms,
                });
            }
        }
    }

    let max_allowed_ms = now_ms.saturating_add(NONCE_WINDOW_MS);
    if nonce_ms > max_allowed_ms {
        return Err(NonceError::TooFarFuture {
            nonce_ms,
            max_allowed_ms,
        });
    }

    let min_allowed_ms = now_ms.saturating_sub(NONCE_WINDOW_MS);
    if nonce_ms < min_allowed_ms {
        return Err(NonceError::TooOld {
            nonce_ms,
            min_allowed_ms,
        });
    }

    if !retained_nonces_ms.insert(nonce_ms) {
        return Err(NonceError::Duplicate { nonce_ms });
    }

    while retained_nonces_ms.len() > cap {
        let smallest = *retained_nonces_ms.iter().next().expect("bucket is non-empty after insert");
        retained_nonces_ms.remove(&smallest);
    }

    Ok(())
}

/// `Withdraw3` adds a second replay gate inside its own handler path.
///
/// Grounded by `0x2734200` (`l1_action_withdraw3__apply_withdrawal_core`):
/// it derives `nonce_ms = time * 1000`, then rejects `nonce_ms <= stored_ms`
/// with status `0x5A` before storing the new value back into the per-user slot.
#[inline]
pub fn validate_withdraw3_local_nonce(
    stored_ms: Option<u64>,
    nonce_ms: u64,
) -> Result<u64, NonceError> {
    if let Some(stored_ms) = stored_ms {
        if nonce_ms <= stored_ms {
            return Err(NonceError::Withdraw3AlreadyUsed {
                nonce_ms,
                stored_ms,
                status: STATUS_WITHDRAW3_NONCE_ALREADY_USED,
            });
        }
    }
    Ok(nonce_ms)
}

/// Source-level reconstruction of the concrete 76-arm action switch.
///
/// The observed binary switch is `0x2759240`, which operates on the lowered
/// `ActionRecord` form. The match below is the equivalent source-level routing
/// for the externally deserialized `Action` enum variants recovered from the
/// current binary. Internal-only tags `76..87` are intentionally excluded.
#[inline]
pub fn impl_execute_action(action: UserActionTag) -> HandlerRef {
    match action {
        UserActionTag::Noop => HandlerRef::new(
            0,
            "noop",
            "NoopAction",
            0x2759_240,
            "inline_success",
            "case 0 does not call a separate handler; it falls through to the inlined success path",
        ),
        UserActionTag::ApproveAgent3 => HandlerRef::new(1, "approveAgent", "ApproveAgent3Action", 0x1E5F_770, "l1_exchange_impl_execute_action__approve_agent3", ""),
        UserActionTag::BatchModify => HandlerRef::new(2, "batchModify", "BatchModifyAction", 0x21DF_D90, "l1_exchange_impl_execute_action__batch_modify", ""),
        UserActionTag::Cancel => HandlerRef::new(3, "cancel", "CancelAction", 0x22BE_610, "sub_22BE610", ""),
        UserActionTag::CancelByCloid => HandlerRef::new(4, "cancelByCloid", "CancelByCloidAction", 0x21DF_F60, "sub_21DFF60", ""),
        UserActionTag::ClaimRewards => HandlerRef::new(5, "claimRewards", "ClaimRewardsAction", 0x2710_E30, "l1_qtys_impl_ntl__apply_fill_ntl_volume_updates", "direct inlined success/error wrapper around the staking reward balance update helper"),
        UserActionTag::CreateSubAccount => HandlerRef::new(6, "createSubAccount", "CreateSubAccountAction", 0x27E3_140, "sub_27E3140", ""),
        UserActionTag::CreateVault => HandlerRef::new(7, "createVault", "CreateVaultAction", 0x1E5F_3C0, "sub_1E5F3C0", ""),
        UserActionTag::EvmRawTx => HandlerRef::new(8, "evmRawTx", "EvmRawTxAction", 0x1F66_1C0, "l1_action_evm_raw_tx__validate_and_apply_raw_tx", ""),
        UserActionTag::ForceIncreaseEpoch => HandlerRef::new(9, "ForceIncreaseEpoch", "ForceIncreaseEpochAction", 0x21E0_A00, "sub_21E0A00", ""),
        UserActionTag::Liquidate => HandlerRef::new(10, "liquidate", "LiquidateAction", 0x23E6_6F0, "l1_exchange_impl_execute_action__liquidate", ""),
        UserActionTag::LinkStakingUser => HandlerRef::new(11, "linkStakingUser", "LinkStakingUserAction", 0x1E60_770, "sub_1E60770", ""),
        UserActionTag::Modify => HandlerRef::new(12, "modify", "ModifyAction", 0x22BE_760, "sub_22BE760", ""),
        UserActionTag::NetChildVaultPositions => HandlerRef::new(13, "NetChildVaultPositions", "NetChildVaultPositionsAction", 0x27E8_CB0, "sub_27E8CB0", ""),
        UserActionTag::Order => HandlerRef::new(14, "order", "OrderAction", 0x1EEE_7C0, "l1_exchange_impl_execute_action__order", ""),
        UserActionTag::RegisterReferrer => HandlerRef::new(15, "registerReferrer", "RegisterReferrerAction", 0x27E3_0A0, "sub_27E30A0", ""),
        UserActionTag::RegisterValidator => HandlerRef::new(16, "registerValidator", "RegisterValidatorAction", 0x3367_800, "sub_3367800", ""),
        UserActionTag::CValidator => HandlerRef::new(17, "CValidator", "CValidatorAction", 0x2768_FF0, "sub_2768FF0", "nested Register/ChangeProfile/Unregister switch"),
        UserActionTag::ScheduleCancel => HandlerRef::new(18, "scheduleCancel", "ScheduleCancelAction", 0x1E5F_C40, "sub_1E5FC40", ""),
        UserActionTag::SetDisplayName => HandlerRef::new(19, "setDisplayName", "SetDisplayNameAction", 0x27E2_170, "sub_27E2170", ""),
        UserActionTag::VoteGlobal => HandlerRef::new(20, "VoteGlobal", "VoteGlobalAction", 0x23E8_640, "l1_exchange_impl_execute_action__vote_global", "applies the nested VoteGlobal action payload"),
        UserActionTag::ValidatorL1Vote => HandlerRef::new(21, "ValidatorL1Vote", "ValidatorL1VoteAction", 0x22CD_B40, "sub_22CDB40", ""),
        UserActionTag::ValidatorL1Stream => HandlerRef::new(22, "ValidatorL1Stream", "ValidatorL1StreamAction", 0x21E0_370, "sub_21E0370", ""),
        UserActionTag::ValidatorL1UpdateReferenceOracle => HandlerRef::new(23, "validatorL1UpdateReferenceOracle", "ValidatorL1UpdateReferenceOracleAction", 0x27FA_570, "l1_exchange_impl_execute_action__validator_l1_update_reference_oracle", ""),
        UserActionTag::SetGlobal => HandlerRef::new(24, "setGlobal", "SetGlobalAction", 0x1F67_B30, "l1_oracle_oracle__validate_validator_l1_reference_oracle_update", "deserializer string order shows case 24 is SetGlobal; the execution callee is the global/oracle update entry point"),
        UserActionTag::SetReferrer => HandlerRef::new(25, "setReferrer", "SetReferrerAction", 0x27DE_270, "sub_27DE270", ""),
        UserActionTag::SpotDeploy => HandlerRef::new(26, "spotDeploy", "SpotDeployAction", 0x23E7_D10, "l1_exchange_impl_execute_action__spot_deploy", "nested spot deploy variant switch"),
        UserActionTag::SpotUser => HandlerRef::new(27, "spotUser", "SpotUserAction", 0x21CF_EC0, "sub_21CFEC0", ""),
        UserActionTag::SpotSend => HandlerRef::new(28, "spotSend", "SpotSendAction", 0x1F66_070, "sub_1F66070", ""),
        UserActionTag::SignValidatorSetUpdate => HandlerRef::new(29, "SignValidatorSetUpdate", "SignValidatorSetUpdateAction", 0x1E64_2E0, "sub_1E642E0", ""),
        UserActionTag::SubAccountModify => HandlerRef::new(30, "subAccountModify", "SubAccountModifyAction", 0x22CD_FB0, "sub_22CDFB0", ""),
        UserActionTag::SubAccountTransfer => HandlerRef::new(31, "subAccountTransfer", "SubAccountTransferAction", 0x1E60_D00, "sub_1E60D00", ""),
        UserActionTag::SubAccountSpotTransfer => HandlerRef::new(32, "subAccountSpotTransfer", "SubAccountSpotTransferAction", 0x1E64_420, "sub_1E64420", ""),
        UserActionTag::TokenDelegate => HandlerRef::new(33, "tokenDelegate", "TokenDelegateAction", 0x1E5F_A70, "sub_1E5FA70", ""),
        UserActionTag::TwapCancel => HandlerRef::new(34, "twapCancel", "TwapCancelAction", 0x22C4_630, "sub_22C4630", ""),
        UserActionTag::TwapOrder => HandlerRef::new(35, "twapOrder", "TwapOrderAction", 0x2722_790, "l1_perp_dex__sub_place_trigger_order_across_dex", ""),
        UserActionTag::UpdateIsolatedMargin => HandlerRef::new(36, "updateIsolatedMargin", "UpdateIsolatedMarginAction", 0x21E2_B60, "sub_21E2B60", ""),
        UserActionTag::TopUpIsolatedOnlyMargin => HandlerRef::new(37, "topUpIsolatedOnlyMargin", "TopUpIsolatedOnlyMarginAction", 0x21E2_EE0, "sub_21E2EE0", ""),
        UserActionTag::UpdateLeverage => HandlerRef::new(38, "updateLeverage", "UpdateLeverageAction", 0x21E0_B70, "sub_21E0B70", ""),
        UserActionTag::UsdSend => HandlerRef::new(39, "usdSend", "UsdSendAction", 0x1F64_A40, "sub_1F64A40", ""),
        UserActionTag::ValidatorSignWithdrawal => HandlerRef::new(40, "ValidatorSignWithdrawal", "ValidatorSignWithdrawalAction", 0x374E_C60, "l1_exchange_impl_execute_action__validator_sign_withdrawal", ""),
        UserActionTag::VaultDistribute => HandlerRef::new(41, "vaultDistribute", "VaultDistributeAction", 0x1E60_020, "l1_exchange_impl_vault__wrap_vault_distribute_action", ""),
        UserActionTag::VaultModify => HandlerRef::new(42, "vaultModify", "VaultModifyAction", 0x22C5_FD0, "sub_22C5FD0", ""),
        UserActionTag::VaultTransfer => HandlerRef::new(43, "vaultTransfer", "VaultTransferAction", 0x1E5F_B20, "l1_action_vault_transfer__validate_vault_transfer_main", ""),
        UserActionTag::VoteEthDeposit => HandlerRef::new(44, "VoteEthDeposit", "VoteEthDepositAction", 0x1E5F_EB0, "sub_1E5FEB0", ""),
        UserActionTag::VoteEthFinalizedValidatorSetUpdate => HandlerRef::new(45, "VoteEthFinalizedValidatorSetUpdate", "VoteEthFinalizedValidatorSetUpdateAction", 0x1E64_CB0, "l1_exchange_impl_execute_action__vote_eth_finalized_validator_set_update", ""),
        UserActionTag::VoteEthFinalizedWithdrawal => HandlerRef::new(46, "VoteEthFinalizedWithdrawal", "VoteEthFinalizedWithdrawalAction", 0x2717_7C0, "l1_exchange_impl_execute_action__vote_eth_finalized_withdrawal", ""),
        UserActionTag::Withdraw3 => HandlerRef::new(47, "withdraw3", "Withdraw3Action", 0x1F67_810, "l1_action_withdraw3__apply_wrapper_main", "handler-local monotonic replay check lives downstream at 0x2734200"),
        UserActionTag::VoteAppHash => HandlerRef::new(48, "VoteAppHash", "VoteAppHashAction", 0x1E5F_5D0, "sub_1E5F5D0", ""),
        UserActionTag::GovPropose => HandlerRef::new(49, "govPropose", "GovProposeAction", 0x1F68_BE0, "sub_1F68BE0", ""),
        UserActionTag::GovVote => HandlerRef::new(50, "govVote", "GovVoteAction", 0x1F64_980, "sub_1F64980", ""),
        UserActionTag::UsdClassTransfer => HandlerRef::new(51, "usdClassTransfer", "UsdClassTransferAction", 0x1E60_850, "l1_exchange_impl_execute_action__usd_class_transfer", ""),
        UserActionTag::MultiSig => HandlerRef::new(52, "multiSig", "MultiSigAction", 0x282E_E50, "sub_282EE50", "nested inner-action dispatch"),
        UserActionTag::ConvertToMultiSigUser => HandlerRef::new(53, "convertToMultiSigUser", "ConvertToMultiSigUserAction", 0x1E64_010, "sub_1E64010", ""),
        UserActionTag::ApproveBuilderFee => HandlerRef::new(54, "approveBuilderFee", "ApproveBuilderFeeAction", 0x1E60_A90, "sub_1E60A90", ""),
        UserActionTag::StartFeeTrial => HandlerRef::new(55, "startFeeTrial", "StartFeeTrialAction", 0x21E0_0B0, "sub_21E00B0", ""),
        UserActionTag::SystemBole => HandlerRef::new(56, "systemBole", "SystemBoleAction", 0x1F69_020, "l1_exchange_impl_execute_action__system_bole", ""),
        UserActionTag::SystemSpotSend => HandlerRef::new(57, "systemSpotSend", "SystemSpotSendAction", 0x1E5F_CF0, "sub_1E5FCF0", ""),
        UserActionTag::DeployerSendToEvmForFrozenUser => HandlerRef::new(58, "DeployerSendToEvmForFrozenUser", "DeployerSendToEvmForFrozenUserAction", 0x1E64_C20, "l1_exchange_impl_execute_action__deployer_send_to_evm_for_frozen_user", ""),
        UserActionTag::SystemUsdClassTransfer => HandlerRef::new(59, "SystemUsdClassTransfer", "SystemUsdClassTransferAction", 0x1E64_530, "sub_1E64530", ""),
        UserActionTag::CSigner => HandlerRef::new(60, "cSigner", "CSignerAction", 0x21CF_DD0, "l1_exchange_impl_execute_action__c_signer", "nested signer-operation switch"),
        UserActionTag::CWithdraw => HandlerRef::new(61, "cWithdraw", "CWithdrawAction", 0x2758_800, "l1_exchange_impl_execute_action__c_withdraw", ""),
        UserActionTag::CDeposit => HandlerRef::new(62, "cDeposit", "CDepositAction", 0x1F65_F80, "l1_action_c_deposit__apply_bridge_deposit_base", ""),
        UserActionTag::CUserModify => HandlerRef::new(63, "cUserModify", "CUserModifyAction", 0x3996_230, "l1_exchange_impl_execute_action__c_user_modify", ""),
        UserActionTag::ReassessFees => HandlerRef::new(64, "reassessFees", "ReassessFeesAction", 0x22CE_180, "l1_exchange_impl_execute_action__reassess_fees", "zero-payload maintenance action"),
        UserActionTag::EvmUserModify => HandlerRef::new(65, "evmUserModify", "EvmUserModifyAction", 0x22CD_990, "l1_exchange_impl_execute_action__evm_user_modify", ""),
        UserActionTag::ReserveRequestWeight => HandlerRef::new(66, "ReserveRequestWeight", "ReserveRequestWeightAction", 0x2758_AE0, "l1_exchange_impl_execute_action__reserve_request_weight", ""),
        UserActionTag::FinalizeEvmContract => HandlerRef::new(67, "FinalizeEvmContract", "FinalizeEvmContractAction", 0x22CE_0D0, "l1_exchange_impl_execute_action__finalize_evm_contract", ""),
        UserActionTag::Hip3Deploy => HandlerRef::new(68, "Hip3Deploy", "Hip3DeployAction", 0x21DD_7E0, "l1_exchange_impl_execute_action__hip3_deploy", "nested deployment variant switch forwarded into the perp/asset deployment adapter"),
        UserActionTag::SendAsset => HandlerRef::new(69, "sendAsset", "SendAssetAction", 0x1F67_8C0, "l1_exchange_impl_execute_action__send_asset", ""),
        UserActionTag::SystemApproveBuilderFee => HandlerRef::new(70, "SystemApproveBuilderFee", "SystemApproveBuilderFeeAction", 0x1E64_620, "l1_exchange_impl_execute_action__system_approve_builder_fee", ""),
        UserActionTag::SystemSendAsset => HandlerRef::new(71, "SystemSendAsset", "SystemSendAssetAction", 0x2728_E10, "l1_exchange_impl_execute_action__system_send_asset", ""),
        UserActionTag::SystemAlignedQuoteSupplyDelta => HandlerRef::new(72, "SystemAlignedQuoteSupplyDelta", "SystemAlignedQuoteSupplyDeltaAction", 0x1E64_AC0, "l1_exchange_impl_execute_action__system_aligned_quote_supply_delta", ""),
        UserActionTag::AgentEnableDexAbstraction => HandlerRef::new(73, "agentEnableDexAbstraction", "AgentEnableDexAbstractionAction", 0x219A_7A0, "l1_exchange_impl_execute_action__agent_enable_dex_abstraction", "unit action; no payload beyond the type tag"),
        UserActionTag::UserDexAbstraction => HandlerRef::new(74, "userDexAbstraction", "UserDexAbstractionAction", 0x1E60_E00, "l1_exchange_impl_execute_action__user_dex_abstraction", ""),
        UserActionTag::BorrowLend => HandlerRef::new(75, "borrowLend", "BoleAction", 0x2764_B90, "l1_exchange_impl_execute_action__borrow_lend", ""),
    }
}

#[inline]
pub fn dispatch_action_record(record: &ActionRecord) -> Option<HandlerRef> {
    Some(impl_execute_action(UserActionTag::from_action_record(record)?))
}
