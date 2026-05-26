//! Recovered governance action payloads and dispatch notes for `VoteGlobalAction`.
//!
//! The current binary has three large monomorphs for applying this action family
//! (`0x2355f40`, `0x4caa870`, `0x4cb3200`).  All three use the same dispatch shape:
//! load a `u64` tag from action offset `+0x00`; if the tag is at least `0x12`,
//! dispatch on `tag - 0x12`; otherwise route through the same outer dispatch arm
//! as normalized case `0x4e`.  The normalized switch has 98 arms (`0..=97`).
//!
//! Variant and field names below are recovered from local binary type strings such
//! as `struct variant VoteGlobalAction::SetEvmPrecompileEnabled with 2 elements`
//! and from the current dispatch side effects.  Numeric limits and state-control
//! behavior are from the current decompilation, not from stale local notes.

#![allow(dead_code)]

pub type Address = [u8; 20];
pub type Asset = u32;
pub type ValidatorIndex = u64;
pub type TimestampMillis = u64;
pub type DurationSeconds = u64;
pub type DurationMillis = u64;
pub type Wei = u64;
pub type Ntl = u64;
pub type RawPx = u64;
pub type UserTokenKey = [u8; 20];

pub const NORMALIZED_TAG_OFFSET: u64 = 0x12;
pub const MAX_ASSET_INDEX_EXCLUSIVE: u64 = 0x65;
pub const MAX_VEC_LEN_10K: u64 = 0x2710;
pub const MAX_SAFE_DECIMAL_U64: u64 = 0x0ccccccccccccccc;
pub const MAINNET_MAX_FUNDING_IMPACT_USD: u64 = 5_000_000_000_000;
pub const TESTNET_MAX_FUNDING_IMPACT_USD: u64 = 1_000_000_000_000;
pub const MIN_NATIVE_TOKEN_MARKET_CAP_NTL: u64 = 100_000_000_000;
pub const MIN_TESTNET_SPOT_SEND_WEI: u64 = 1_000_000;
pub const MAX_REFERENCE_ORACLE_BOUND: f64 = 2.0;
pub const MAX_DAILY_PX_RANGE: f64 = 0.01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteGlobalDispatchSlot {
    /// Raw tags `< 0x12` are routed here by the optimized dispatch prelude.
    /// Raw tag `0x60` (`0x4e + 0x12`) also lands in the same normalized arm.
    LowTagOrNormalized78,
    /// Raw tags `>= 0x12` use this normalized case.
    Normalized(u64),
}

pub fn dispatch_slot(raw_tag: u64) -> VoteGlobalDispatchSlot {
    if raw_tag < NORMALIZED_TAG_OFFSET {
        VoteGlobalDispatchSlot::LowTagOrNormalized78
    } else {
        let normalized = raw_tag - NORMALIZED_TAG_OFFSET;
        if normalized == 0x4e {
            VoteGlobalDispatchSlot::LowTagOrNormalized78
        } else {
            VoteGlobalDispatchSlot::Normalized(normalized)
        }
    }
}

#[derive(Debug, Clone)]
pub enum VoteGlobalAction {
    // Raw low-tag family.  The optimized branch uses an inner selector
    // `selector = raw_tag >= 2 ? raw_tag - 2 : 1`; selectors 0..15 are visible.
    LowTag(LowTagVoteGlobalAction),

    // Normalized cases 0x00..0x58 match the long-standing governance family, but
    // the current raw tag is shifted by +0x12 in the apply path.
    FeeSchedule(FeeSchedule),                         // raw 0x12, case 0x00
    ReferralBucketMillis(DurationMillis),             // raw 0x13, case 0x01
    OverrideFundingImpactUsd(Vec<FundingImpactOverride>), // raw 0x14, case 0x02
    FundingClamp(AssetValue<f64>),                    // raw 0x15, case 0x03
    DefaultImpactUsd(u64),                            // raw 0x16, case 0x04
    MaxOrderDistanceFromAnchor(AssetValue<f64>),      // raw 0x17, case 0x05
    InsertMarginTable(MarginTable),                   // raw 0x18, case 0x06
    SetMarginTableIds(Vec<MarginTableIdChange>),      // raw 0x19, case 0x07
    SimulateCrashHeight(u64),                         // raw 0x1a, case 0x08
    NewSzDecimals(Vec<AssetBoolOrByte>),              // raw 0x1b, case 0x09
    PerformAutoDeleveraging(bool),                    // raw 0x1c, case 0x0a
    AssetsAtOpenInterestCap(Vec<u64>),                // raw 0x1d, case 0x0b
    AdlShortfallRemaining(u64),                       // raw 0x1e, case 0x0c
    HlOnlyCoins(Vec<AssetToggle>),                    // raw 0x1f, case 0x0d
    StakingEpochDurationSeconds(DurationSeconds),     // raw 0x20, case 0x0e
    StrictIsolatedCoins(Vec<AssetToggle>),            // raw 0x21, case 0x0f
    Bridge2WithdrawFee(u64),                          // raw 0x22, case 0x10
    AllowedBridgeValidators(Vec<AddressToggle>),      // raw 0x23, case 0x11
    AllowedCValidator(Vec<CValidatorPermission>),     // raw 0x24, case 0x12
    ForceRecomputeValidatorState,                     // raw 0x25, case 0x13
    OverrideMaxSignatureValiditySeconds(Option<Address>), // raw 0x26, case 0x14
    OverrideIsolatedMaxLeverage(Option<Address>),     // raw 0x27, case 0x15
    OverrideIsolatedMarginRequirement(Option<Address>), // raw 0x28, case 0x16
    CanonicalTokens(Vec<TokenEntry>),                 // raw 0x29, case 0x17
    DisableSpot(bool),                                // raw 0x2a, case 0x18
    MaxHlpWithdrawPerSecond(AssetValue<f64>),         // raw 0x2b, case 0x19
    QuarantineUser(Address, UserControlValue),        // raw 0x2c, case 0x1a
    CancelUserOrders(Address, UserControlValue),      // raw 0x2d, case 0x1b
    UserCanLiquidate(Address),                        // raw 0x2e, case 0x1c
    UserIsUnrewarded(Address),                        // raw 0x2f, case 0x1d
    AllowDuplicateTokenNames(bool),                   // raw 0x30, case 0x1e
    DeployGasAuctionChange(DeployGasAuctionChange),   // raw 0x31, case 0x1f
    FreezeChain(u64),                                 // raw 0x32, case 0x20
    ModifyVault(VoteGlobalVaultModification),         // raw 0x33, case 0x21
    HaltPerpTrading { asset: Asset, is_halted: bool }, // raw 0x34, case 0x22
    RegisterAsset2(RegisterAssetRequest2),            // raw 0x35, case 0x23
    ModifyReferrer(ModifyReferrer),                   // raw 0x36, case 0x24
    ModifyNonCirculatingSupply(ModifyNonCirculatingSupply), // raw 0x37
    ModifyBroadcaster(Address, bool),                 // raw 0x38, case 0x26
    ModifyCStakingPeriods(ModifyCStakingPeriods),     // raw 0x39, case 0x27
    CValidator(CValidatorAction),                     // raw 0x3a, case 0x28
    UnjailAll,                                        // raw 0x3b, case 0x29
    MaxNValidators(u64),                              // raw 0x3c, case 0x2a
    SetReserveAccumulator(SetReserveAccumulator),     // raw 0x3d, case 0x2b
    UnjailSigner(Address),                            // raw 0x3e, case 0x2c
    RefundCSignerRequestWeights(u64),                 // raw 0x3f, case 0x2d
    TestnetSpotDeploy(TestnetDeployPayload),          // raw 0x40, case 0x2e
    TestnetHip3Deploy(TestnetDeployPayload),          // raw 0x41, case 0x2f
    SetNativeToken(NativeTokenConfig),                // raw 0x42, case 0x30
    SetSelfDelegationRequirement(u64),                // raw 0x43, case 0x31
    SetAllowAllValidators(bool),                      // raw 0x44, case 0x32
    DisableCValidator { validator: Address, disable: bool }, // raw 0x45
    DisableNodeIp { ip: [u8; 5], disable: bool },     // raw 0x46
    SetStakesDecaySeconds(DurationSeconds),           // raw 0x47, case 0x35
    SetDistributeRewardBucketSeconds(DurationSeconds), // raw 0x48
    SetMaxOiPerSecond { name: Vec<u8>, max_oi_per_second: RawPx }, // raw 0x49
    SetEvmEnabled(bool),                              // raw 0x4a, case 0x38
    SetPartialLiquidationCooldown(DurationMillis),    // raw 0x4b, case 0x39
    SetEvmBlockDuration { is_big: bool, seconds: u64 }, // raw 0x4c
    SetEvmPrecompileEnabled { address: Address, enabled: bool }, // raw 0x4d
    SetEvmL1TransfersEnabled(bool),                   // raw 0x4e, case 0x3c
    SetMaxWithdrawLeverage(LeverageFraction),         // raw 0x4f, case 0x3d
    SetActionDelayerEnabled(bool),                    // raw 0x50, case 0x3e
    SetActionDelayedActionsRefund(u64),               // raw 0x51, case 0x3f
    EnableQuoteToken { token: Asset, allowed: bool }, // raw 0x52, case 0x40
    ValidatorL1VoteEnabled(bool),                     // raw 0x53, case 0x41
    SetCheckAllUsersCollateralizedCross(bool),        // raw 0x54, case 0x42
    SetPerpDexTransferBounds(SetPerpDexTransferBounds), // raw 0x55
    SetPerpDexOpenInterestFundingCap(SetPerpDexSourceLimit), // raw 0x56
    SetPerpDexOpenInterestLimit(SetPerpDexSourceLimit), // raw 0x57
    SetPerpDexDailyInterestLimit(SetPerpDexDailyInterestLimit), // raw 0x58
    SetPerpDexMaxNotionalTransferredTotal(SetPerpDexSourceLimit), // raw 0x59
    SetPageStatus(bool),                              // raw 0x5a, case 0x48
    SetLiquidBaseTokens(Vec<Address>),                // raw 0x5b, case 0x49
    SetLiquidQuoteTokens(Vec<Address>),               // raw 0x5c, case 0x4a
    SetCoreWriterActionEnabled(SetCoreWriterActionEnabled), // raw 0x5d
    SetPerpDexsLocked(bool),                          // raw 0x5e, case 0x4c
    SetHip3NoCross(bool),                             // raw 0x5f, case 0x4d
    SetUsdcEvmContract(UsdcEvmContractConfig),        // raw 0x60, normalized case 0x4e
    SetDexAbstractionEnabled(bool),                   // raw 0x61, case 0x4f
    SetBole(SetBoleAction),                           // raw 0x62, case 0x50
    TestnetFixUsdc(u64),                              // raw 0x63, case 0x51
    TestnetDepositFor { user: Address, wei: Wei },    // raw 0x64, case 0x52
    TestnetSpotSendFor(TestnetSpotSendFor),           // raw 0x65, case 0x53
    TestnetDisableFeeTrial(bool),                     // raw 0x66, case 0x54
    TestnetChangeTokenDeployer { deployer: Address, token: Asset }, // raw 0x67
    TestnetChangePerpDexDeployer { hip3_deployer: Address, name: Vec<u8> }, // raw 0x68
    TestnetSetYesterdayUserVlm(TestnetSetYesterdayUserVlm), // raw 0x69
    TestnetAddMainnetUsers(Vec<Address>),             // raw 0x6a, case 0x58

    // Current binary normalized cases 0x59..0x61 are visible in the apply path;
    // only payload layout and state effects are recovered with high confidence.
    SetPerpDexOpenInterestCap2(SetPerpDexOpenInterestCap2), // raw 0x6b
    SetPerpDexDailyPxRange(SetPerpDexDailyPxRange),   // raw 0x6c
    SetOutcomeFeeScale(u64),                          // raw 0x6d
    SetPerpDexMaxNUsersWithPositions(u64),            // raw 0x6e
    SetPerpDexRegistrationBatch(SetPerpDexRegistrationBatch), // raw 0x6f
    SetHardPolicy(SetHardPolicy),                     // raw 0x70
    SetReferenceOracleConfig(ReferenceOracleConfig),  // raw 0x71
    SetPerpDexPriceBand(SetPerpDexPriceBand),         // raw 0x72
    SetPerpDexTrackedUsers(TrackedUsersConfig),        // raw 0x73
}

#[derive(Debug, Clone)]
pub enum LowTagVoteGlobalAction {
    /// selector 0: writes a bool to the state byte at the low perps-dex flag slot.
    SetPerpDexFlag0(bool),
    /// selector 1: large HIP-3/perp-dex configuration path; validates asset index,
    /// optional scalar fields, quote/user token maps, and invokes the perp-dex update
    /// helper. Raw tags 0, 1, and 3 all reach this selector in optimized code.
    SetPerpDexConfig(PerpDexConfigUpdate),
    /// selector 2: parses optional address/value via `sub_24cdf/4592ef0` and stores
    /// into state offsets `+1176/+1184`.
    SetPerpDexOptionalAddress(Option<Address>),
    /// selector 3: validates two price-like objects for a dex asset and updates a
    /// clearinghouse map via `sub_37350c0`.
    SetPerpDexMarketPair(SetPerpDexMarketPair),
    SetPerpDexFlag4(bool),
    SetPerpDexAssetList(Vec<Asset>),
    SetPerpDexDelayedAction(SetPerpDexDelayedAction),
    SetPerpDexFlag7(bool),
    SetPerpDexFlag8(bool),
    SetPerpDexU64Slot9(u64),
    SetPerpDexU64Slot10(u64),
    SetPerpDexU64Slot11(u64),
    SetPerpDexLimits(LowTagPerpDexLimits),
    SetPerpDexU64Slot13(u64),
    EnablePerpDexAsset { asset: u64, value: u64 },
    TogglePerpDexAsset { asset: u64, is_cross_allowed: bool },
}

#[derive(Debug, Clone, Default)]
pub struct FeeSchedule {
    pub base_fee_bps: u64,
    pub max_maker_rebate_bps: u64,
    pub max_referrer_rebate_bps: u64,
    pub max_staking_rebate_bps: u64,
    pub cross_margin_fee_bps: u64,
    pub isolated_margin_fee_bps: u64,
    pub builder_fee_bps: u64,
    pub spot_fee_bps: u64,
    pub _unknown_field_8: u64,
}

#[derive(Debug, Clone, Default)]
pub struct FundingImpactOverride {
    pub asset: Asset,
    pub impact_usd: u64,
}

#[derive(Debug, Clone, Default)]
pub struct AssetValue<T> {
    pub asset: Asset,
    pub value: T,
}

#[derive(Debug, Clone, Default)]
pub struct MarginTable {
    pub id: u32,
    pub entries: Vec<MarginTableEntry>,
}

#[derive(Debug, Clone, Default)]
pub struct MarginTableEntry {
    pub lower_bound: u64,
    pub initial_margin_fraction: f64,
    pub maintenance_margin_fraction: f64,
}

#[derive(Debug, Clone, Default)]
pub struct MarginTableIdChange {
    pub asset: Asset,
    pub margin_table_id: u32,
}

#[derive(Debug, Clone, Default)]
pub struct AssetBoolOrByte {
    pub asset: Asset,
    pub value: u8,
}

#[derive(Debug, Clone, Default)]
pub struct AssetToggle {
    pub asset: Asset,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AddressToggle {
    pub address: Address,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CValidatorPermission {
    pub validator: Address,
    pub allowed: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TokenEntry {
    pub token: Asset,
    pub address: Address,
}

#[derive(Debug, Clone, Default)]
pub struct UserControlValue {
    pub raw: u64,
}

#[derive(Debug, Clone, Default)]
pub struct DeployGasAuctionChange {
    pub disable: bool,
    pub gas_auction_change: GasAuctionChange,
}

#[derive(Debug, Clone, Default)]
pub struct GasAuctionChange {
    pub start_premium: u64,
    pub end_premium: u64,
    pub duration_millis: DurationMillis,
    pub bucket_millis: DurationMillis,
}

#[derive(Debug, Clone, Default)]
pub struct VoteGlobalVaultModification {
    pub vault_address: Address,
    pub allow_deposits: bool,
    pub always_close_on_withdraw: bool,
    pub max_distributable: u64,
    pub is_cross_margin: bool,
    pub manager: Address,
    pub name: Vec<u8>,
    pub description: Vec<u8>,
    pub _unknown_field_8: u64,
}

#[derive(Debug, Clone, Default)]
pub struct RegisterAssetRequest2 {
    pub asset: Asset,
    pub asset_name: Vec<u8>,
    pub sz_decimals: u8,
    pub oracle_px: RawPx,
    pub max_leverage: u64,
    pub only_isolated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ModifyReferrer {
    pub code: [u8; 24],
    pub n_per_bucket: u128,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ModifyNonCirculatingSupply {
    pub token: Asset,
    pub add: u64,
    pub remove: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ModifyCStakingPeriods {
    pub stakes: u64,
    pub jailed_signers: u128,
}

#[derive(Debug, Clone, Default)]
pub struct CValidatorAction {
    pub c_validator: Address,
    pub action: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SetReserveAccumulator {
    pub order_ntl: i128,
    pub decay_duration: u128,
    pub max_px: u64,
}

#[derive(Debug, Clone, Default)]
pub struct TestnetDeployPayload {
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct NativeTokenConfig {
    pub token_index: u64,
    pub min_market_cap_ntl: u64,
}

#[derive(Debug, Clone, Default)]
pub struct LeverageFraction {
    pub numerator: u64,
    pub denominator: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SetPerpDexTransferBounds {
    pub src: u8,
    pub transfer_out_usd: u128,
    pub max_under_initial_margin: u128,
}

#[derive(Debug, Clone, Default)]
pub struct SetPerpDexSourceLimit {
    pub src: u8,
    pub value: u128,
}

#[derive(Debug, Clone, Default)]
pub struct SetPerpDexDailyInterestLimit {
    pub src: u8,
    pub limit: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SetCoreWriterActionEnabled {
    pub encoding_version: u8,
    pub enabled: bool,
    pub action_id: u64,
}

#[derive(Debug, Clone, Default)]
pub struct UsdcEvmContractConfig {
    pub address: Address,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub enum SetBoleAction {
    Reserve,
    TestnetAction(Vec<u8>),
    Raw(Vec<u8>),
}

impl Default for SetBoleAction {
    fn default() -> Self {
        Self::Raw(Vec::new())
    }
}

#[derive(Debug, Clone, Default)]
pub struct TestnetSpotSendFor {
    pub user: Address,
    pub destination: Address,
    pub coin: Asset,
    pub wei: Wei,
}

#[derive(Debug, Clone, Default)]
pub struct TestnetSetYesterdayUserVlm {
    pub user: Address,
    pub wei: Wei,
    pub cross: u64,
    pub spot_add: u64,
    pub spot_cross: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SetPerpDexOpenInterestCap2 {
    /// Current case 0x59: subtag 2 clears a vector; subtag 3 sets a count bounded
    /// by `<= 100`; other subtags validate native-token context and replace an
    /// 80-byte-record vector at the recovered state slot.
    pub subtag: u64,
    pub optional_limit: u64,
    pub records: Vec<[u8; 80]>,
}

#[derive(Debug, Clone, Default)]
pub struct SetPerpDexDailyPxRange {
    /// Current case 0x5a accepts three parsed f64s and requires
    /// `min <= max <= 1`, `0 < px_range <= 0.01`, and `min >= 0.01`.
    pub min_px_ratio: f64,
    pub max_px_ratio: f64,
    pub daily_px_range: f64,
}

#[derive(Debug, Clone, Default)]
pub struct SetPerpDexRegistrationBatch {
    pub dex: Vec<u8>,
    pub users: Vec<Address>,
}

#[derive(Debug, Clone, Default)]
pub struct SetHardPolicy {
    pub flags: u64,
    pub primary_limit: u64,
    pub secondary_limit: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ReferenceOracleConfig {
    pub enabled: bool,
    pub price: f64,
    pub confidence: f64,
    pub mode: u8,
}

#[derive(Debug, Clone, Default)]
pub struct SetPerpDexPriceBand {
    pub lower: f64,
    pub upper: f64,
    pub index: u8,
}

#[derive(Debug, Clone, Default)]
pub struct TrackedUsersConfig {
    pub sentinel: u64,
    pub users: Vec<Address>,
}

#[derive(Debug, Clone, Default)]
pub struct PerpDexConfigUpdate {
    pub dex: u64,
    pub native_asset: u64,
    pub optional_max_notional: Option<u64>,
    pub optional_market_cap: Option<u64>,
    pub users: Vec<Address>,
}

#[derive(Debug, Clone, Default)]
pub struct SetPerpDexMarketPair {
    pub dex: u64,
    pub base: Asset,
    pub quote: Asset,
    pub optional_size: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct SetPerpDexDelayedAction {
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct LowTagPerpDexLimits {
    pub maybe_min_ntl: Option<u64>,
    pub maybe_max_ntl: Option<u64>,
    pub maybe_decay_seconds: Option<u64>,
    pub maybe_perp_dex_limit: Option<u64>,
    pub maybe_open_interest_limit: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteGlobalValidationError {
    InvalidAssetIndex { asset: u64 },
    DecimalTooLarge { value: u64 },
    ValueOutOfRange,
    TestnetOnlyOrDisabled,
}

pub fn validate_visible_bounds(action: &VoteGlobalAction, is_testnet: bool) -> Result<(), VoteGlobalValidationError> {
    match action {
        VoteGlobalAction::FundingClamp(asset_value) if asset_value.asset as u64 >= MAX_ASSET_INDEX_EXCLUSIVE => {
            Err(VoteGlobalValidationError::InvalidAssetIndex { asset: asset_value.asset as u64 })
        }
        VoteGlobalAction::MaxOrderDistanceFromAnchor(asset_value) if asset_value.asset as u64 >= MAX_ASSET_INDEX_EXCLUSIVE => {
            Err(VoteGlobalValidationError::InvalidAssetIndex { asset: asset_value.asset as u64 })
        }
        VoteGlobalAction::MaxHlpWithdrawPerSecond(asset_value) if asset_value.asset as u64 >= MAX_ASSET_INDEX_EXCLUSIVE => {
            Err(VoteGlobalValidationError::InvalidAssetIndex { asset: asset_value.asset as u64 })
        }
        VoteGlobalAction::OverrideFundingImpactUsd(overrides) => {
            let max = if is_testnet { TESTNET_MAX_FUNDING_IMPACT_USD } else { MAINNET_MAX_FUNDING_IMPACT_USD };
            if overrides.iter().any(|entry| entry.impact_usd > max) {
                Err(VoteGlobalValidationError::ValueOutOfRange)
            } else {
                Ok(())
            }
        }
        VoteGlobalAction::SetPerpDexDailyPxRange(bounds) => {
            if bounds.min_px_ratio >= 0.01
                && bounds.min_px_ratio <= bounds.max_px_ratio
                && bounds.max_px_ratio <= 1.0
                && bounds.daily_px_range > 0.0
                && bounds.daily_px_range <= MAX_DAILY_PX_RANGE
            {
                Ok(())
            } else {
                Err(VoteGlobalValidationError::ValueOutOfRange)
            }
        }
        VoteGlobalAction::SetPerpDexPriceBand(band) => {
            if band.lower.is_finite() && band.upper.is_finite() && band.index < 4 {
                Ok(())
            } else {
                Err(VoteGlobalValidationError::ValueOutOfRange)
            }
        }
        VoteGlobalAction::SetReferenceOracleConfig(config) => {
            if (0.0..MAX_REFERENCE_ORACLE_BOUND).contains(&config.confidence) {
                Ok(())
            } else {
                Err(VoteGlobalValidationError::ValueOutOfRange)
            }
        }
        _ => Ok(()),
    }
}

pub fn recovered_variant_string(action: &VoteGlobalAction) -> &'static str {
    match action {
        VoteGlobalAction::LowTag(_) => "VoteGlobalAction::<low-tag-family>",
        VoteGlobalAction::FeeSchedule(_) => "VoteGlobalAction::FeeSchedule",
        VoteGlobalAction::ReferralBucketMillis(_) => "VoteGlobalAction::ReferralBucketMillis",
        VoteGlobalAction::OverrideFundingImpactUsd(_) => "VoteGlobalAction::OverrideFundingImpactUsd",
        VoteGlobalAction::FundingClamp(_) => "VoteGlobalAction::FundingClamp",
        VoteGlobalAction::DefaultImpactUsd(_) => "VoteGlobalAction::DefaultImpactUsd",
        VoteGlobalAction::MaxOrderDistanceFromAnchor(_) => "VoteGlobalAction::MaxOrderDistanceFromAnchor",
        VoteGlobalAction::InsertMarginTable(_) => "VoteGlobalAction::InsertMarginTable",
        VoteGlobalAction::SetMarginTableIds(_) => "VoteGlobalAction::SetMarginTableIds",
        VoteGlobalAction::SimulateCrashHeight(_) => "VoteGlobalAction::SimulateCrashHeight",
        VoteGlobalAction::NewSzDecimals(_) => "VoteGlobalAction::NewSzDecimals",
        VoteGlobalAction::PerformAutoDeleveraging(_) => "VoteGlobalAction::PerformAutoDeleveraging",
        VoteGlobalAction::AssetsAtOpenInterestCap(_) => "VoteGlobalAction::AssetsAtOpenInterestCap",
        VoteGlobalAction::AdlShortfallRemaining(_) => "VoteGlobalAction::AdlShortfallRemaining",
        VoteGlobalAction::HlOnlyCoins(_) => "VoteGlobalAction::HlOnlyCoins",
        VoteGlobalAction::StakingEpochDurationSeconds(_) => "VoteGlobalAction::StakingEpochDurationSeconds",
        VoteGlobalAction::StrictIsolatedCoins(_) => "VoteGlobalAction::StrictIsolatedCoins",
        VoteGlobalAction::Bridge2WithdrawFee(_) => "VoteGlobalAction::Bridge2WithdrawFee",
        VoteGlobalAction::AllowedBridgeValidators(_) => "VoteGlobalAction::AllowedBridgeValidators",
        VoteGlobalAction::AllowedCValidator(_) => "VoteGlobalAction::AllowedCValidator",
        VoteGlobalAction::ForceRecomputeValidatorState => "VoteGlobalAction::ForceRecomputeValidatorState",
        VoteGlobalAction::OverrideMaxSignatureValiditySeconds(_) => "VoteGlobalAction::OverrideMaxSignatureValiditySeconds",
        VoteGlobalAction::OverrideIsolatedMaxLeverage(_) => "VoteGlobalAction::OverrideIsolatedMaxLeverage",
        VoteGlobalAction::OverrideIsolatedMarginRequirement(_) => "VoteGlobalAction::OverrideIsolatedMarginRequirement",
        VoteGlobalAction::CanonicalTokens(_) => "VoteGlobalAction::CanonicalTokens",
        VoteGlobalAction::DisableSpot(_) => "VoteGlobalAction::DisableSpot",
        VoteGlobalAction::MaxHlpWithdrawPerSecond(_) => "VoteGlobalAction::MaxHlpWithdrawPerSecond",
        VoteGlobalAction::QuarantineUser(_, _) => "VoteGlobalAction::QuarantineUser",
        VoteGlobalAction::CancelUserOrders(_, _) => "VoteGlobalAction::CancelUserOrders",
        VoteGlobalAction::UserCanLiquidate(_) => "VoteGlobalAction::UserCanLiquidate",
        VoteGlobalAction::UserIsUnrewarded(_) => "VoteGlobalAction::UserIsUnrewarded",
        VoteGlobalAction::AllowDuplicateTokenNames(_) => "VoteGlobalAction::AllowDuplicateTokenNames",
        VoteGlobalAction::DeployGasAuctionChange(_) => "VoteGlobalAction::DeployGasAuctionChange",
        VoteGlobalAction::FreezeChain(_) => "VoteGlobalAction::FreezeChain",
        VoteGlobalAction::ModifyVault(_) => "VoteGlobalAction::ModifyVault",
        VoteGlobalAction::HaltPerpTrading { .. } => "VoteGlobalAction::HaltPerpTrading",
        VoteGlobalAction::RegisterAsset2(_) => "VoteGlobalAction::RegisterAsset2",
        VoteGlobalAction::ModifyReferrer(_) => "VoteGlobalAction::ModifyReferrer",
        VoteGlobalAction::ModifyNonCirculatingSupply(_) => "VoteGlobalAction::ModifyNonCirculatingSupply",
        VoteGlobalAction::ModifyBroadcaster(_, _) => "VoteGlobalAction::ModifyBroadcaster",
        VoteGlobalAction::ModifyCStakingPeriods(_) => "VoteGlobalAction::ModifyCStakingPeriods",
        VoteGlobalAction::CValidator(_) => "VoteGlobalAction::CValidator",
        VoteGlobalAction::UnjailAll => "VoteGlobalAction::UnjailAll",
        VoteGlobalAction::MaxNValidators(_) => "VoteGlobalAction::MaxNValidators",
        VoteGlobalAction::SetReserveAccumulator(_) => "VoteGlobalAction::SetReserveAccumulator",
        VoteGlobalAction::UnjailSigner(_) => "VoteGlobalAction::UnjailSigner",
        VoteGlobalAction::RefundCSignerRequestWeights(_) => "VoteGlobalAction::RefundCSignerRequestWeights",
        VoteGlobalAction::TestnetSpotDeploy(_) => "VoteGlobalAction::TestnetSpotDeploy",
        VoteGlobalAction::TestnetHip3Deploy(_) => "VoteGlobalAction::TestnetHip3Deploy",
        VoteGlobalAction::SetNativeToken(_) => "VoteGlobalAction::SetNativeToken",
        VoteGlobalAction::SetSelfDelegationRequirement(_) => "VoteGlobalAction::SetSelfDelegationRequirement",
        VoteGlobalAction::SetAllowAllValidators(_) => "VoteGlobalAction::SetAllowAllValidators",
        VoteGlobalAction::DisableCValidator { .. } => "VoteGlobalAction::DisableCValidator",
        VoteGlobalAction::DisableNodeIp { .. } => "VoteGlobalAction::DisableNodeIp",
        VoteGlobalAction::SetStakesDecaySeconds(_) => "VoteGlobalAction::SetStakesDecaySeconds",
        VoteGlobalAction::SetDistributeRewardBucketSeconds(_) => "VoteGlobalAction::SetDistributeRewardBucketSeconds",
        VoteGlobalAction::SetMaxOiPerSecond { .. } => "VoteGlobalAction::SetMaxOiPerSecond",
        VoteGlobalAction::SetEvmEnabled(_) => "VoteGlobalAction::SetEvmEnabled",
        VoteGlobalAction::SetPartialLiquidationCooldown(_) => "VoteGlobalAction::SetPartialLiquidationCooldown",
        VoteGlobalAction::SetEvmBlockDuration { .. } => "VoteGlobalAction::SetEvmBlockDuration",
        VoteGlobalAction::SetEvmPrecompileEnabled { .. } => "VoteGlobalAction::SetEvmPrecompileEnabled",
        VoteGlobalAction::SetEvmL1TransfersEnabled(_) => "VoteGlobalAction::SetEvmL1TransfersEnabled",
        VoteGlobalAction::SetMaxWithdrawLeverage(_) => "VoteGlobalAction::SetMaxWithdrawLeverage",
        VoteGlobalAction::SetActionDelayerEnabled(_) => "VoteGlobalAction::SetActionDelayerEnabled",
        VoteGlobalAction::SetActionDelayedActionsRefund(_) => "VoteGlobalAction::SetActionDelayedActionsRefund",
        VoteGlobalAction::EnableQuoteToken { .. } => "VoteGlobalAction::EnableQuoteToken",
        VoteGlobalAction::ValidatorL1VoteEnabled(_) => "VoteGlobalAction::ValidatorL1VoteEnabled",
        VoteGlobalAction::SetCheckAllUsersCollateralizedCross(_) => "VoteGlobalAction::SetCheckAllUsersCollateralizedCross",
        VoteGlobalAction::SetPerpDexTransferBounds(_) => "VoteGlobalAction::SetPerpDexTransferBounds",
        VoteGlobalAction::SetPerpDexOpenInterestFundingCap(_) => "VoteGlobalAction::SetPerpDexOpenInterestFundingCap",
        VoteGlobalAction::SetPerpDexOpenInterestLimit(_) => "VoteGlobalAction::SetPerpDexOpenInterestLimit",
        VoteGlobalAction::SetPerpDexDailyInterestLimit(_) => "VoteGlobalAction::SetPerpDexDailyInterestLimit",
        VoteGlobalAction::SetPerpDexMaxNotionalTransferredTotal(_) => "VoteGlobalAction::SetPerpDexMaxNotionalTransferredTotal",
        VoteGlobalAction::SetPageStatus(_) => "VoteGlobalAction::SetPageStatus",
        VoteGlobalAction::SetLiquidBaseTokens(_) => "VoteGlobalAction::SetLiquidBaseTokens",
        VoteGlobalAction::SetLiquidQuoteTokens(_) => "VoteGlobalAction::SetLiquidQuoteTokens",
        VoteGlobalAction::SetCoreWriterActionEnabled(_) => "VoteGlobalAction::SetCoreWriterActionEnabled",
        VoteGlobalAction::SetPerpDexsLocked(_) => "VoteGlobalAction::SetPerpDexsLocked",
        VoteGlobalAction::SetHip3NoCross(_) => "VoteGlobalAction::SetHip3NoCross",
        VoteGlobalAction::SetUsdcEvmContract(_) => "VoteGlobalAction::SetUsdcEvmContract",
        VoteGlobalAction::SetDexAbstractionEnabled(_) => "VoteGlobalAction::SetDexAbstractionEnabled",
        VoteGlobalAction::SetBole(_) => "VoteGlobalAction::SetBole",
        VoteGlobalAction::TestnetFixUsdc(_) => "VoteGlobalAction::TestnetFixUsdc",
        VoteGlobalAction::TestnetDepositFor { .. } => "VoteGlobalAction::TestnetDepositFor",
        VoteGlobalAction::TestnetSpotSendFor(_) => "VoteGlobalAction::TestnetSpotSendFor",
        VoteGlobalAction::TestnetDisableFeeTrial(_) => "VoteGlobalAction::TestnetDisableFeeTrial",
        VoteGlobalAction::TestnetChangeTokenDeployer { .. } => "VoteGlobalAction::TestnetChangeTokenDeployer",
        VoteGlobalAction::TestnetChangePerpDexDeployer { .. } => "VoteGlobalAction::TestnetChangePerpDexDeployer",
        VoteGlobalAction::TestnetSetYesterdayUserVlm(_) => "VoteGlobalAction::TestnetSetYesterdayUserVlm",
        VoteGlobalAction::TestnetAddMainnetUsers(_) => "VoteGlobalAction::TestnetAddMainnetUsers",
        VoteGlobalAction::SetPerpDexOpenInterestCap2(_) => "VoteGlobalAction::SetPerpDexOpenInterestCap2",
        VoteGlobalAction::SetPerpDexDailyPxRange(_) => "VoteGlobalAction::SetPerpDexDailyPxRange",
        VoteGlobalAction::SetOutcomeFeeScale(_) => "VoteGlobalAction::SetOutcomeFeeScale",
        VoteGlobalAction::SetPerpDexMaxNUsersWithPositions(_) => "VoteGlobalAction::SetPerpDexMaxNUsersWithPositions",
        VoteGlobalAction::SetPerpDexRegistrationBatch(_) => "VoteGlobalAction::SetPerpDexRegistrationBatch",
        VoteGlobalAction::SetHardPolicy(_) => "VoteGlobalAction::SetHardPolicy",
        VoteGlobalAction::SetReferenceOracleConfig(_) => "VoteGlobalAction::SetReferenceOracleConfig",
        VoteGlobalAction::SetPerpDexPriceBand(_) => "VoteGlobalAction::SetPerpDexPriceBand",
        VoteGlobalAction::SetPerpDexTrackedUsers(_) => "VoteGlobalAction::SetPerpDexTrackedUsers",
    }
}