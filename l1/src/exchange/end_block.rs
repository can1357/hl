use std::cmp::Ordering;
use std::collections::BTreeMap;

const SYNTHETIC_SETTLEMENT_ACTION: u64 = 173;
const GENERATED_ACTION_SENTINEL: u64 = 204;
const SUCCESS_OUTCOME_TAG: u8 = 13;
const ERROR_OUTCOME_TAG: u8 = 14;
const PRIMARY_ADDRESS_TRAILER_TAG: u8 = 0x20;
const SPECIAL_ADDRESS_TRAILER_TAG: u8 = 0x22;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndBlockLane {
    Base,
    Dex0,
    Dex1,
}

impl EndBlockLane {
    #[inline]
    fn funding_lane(self) -> FundingLane {
        match self {
            Self::Base | Self::Dex0 => FundingLane::Primary,
            Self::Dex1 => FundingLane::Secondary,
        }
    }

    #[inline]
    fn uses_evm_hook(self) -> bool {
        matches!(self, Self::Dex1)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FundingLane {
    Primary,
    Secondary,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FundingKey {
    pub limbs: [u64; 4],
}

impl FundingKey {
    #[inline]
    pub fn is_newer_than(self, old: Self) -> bool {
        // The recovered compare checks the high limb first (+0x20), then walks
        // backward through +0x18, +0x10, +0x08 before accepting a new key.
        for idx in (0..4).rev() {
            match self.limbs[idx].cmp(&old.limbs[idx]) {
                Ordering::Greater => return true,
                Ordering::Less => return false,
                Ordering::Equal => {}
            }
        }
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FundingUpdate {
    NoOracle,
    MissingDerivedData,
    Invalid,
    Success(FundingKey),
}

impl FundingUpdate {
    #[inline]
    fn should_warn(&self) -> bool {
        !matches!(self, Self::NoOracle | Self::Success(_))
    }
}

#[derive(Clone, Debug, Default)]
pub struct FundingLaneState {
    pub last_key: Option<FundingKey>,
    pub warning_emitted: bool,
    pub pending_by_key: BTreeMap<AddressKey, u64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct AddressKey(pub [u8; 20]);

impl AddressKey {
    #[inline]
    pub fn from_u64_word(word: u64) -> Self {
        let mut out = [0u8; 20];
        out[12..20].copy_from_slice(&word.to_be_bytes());
        Self(out)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressTrailer {
    pub bytes: [u8; 20],
}

impl AddressTrailer {
    pub fn from_asset_key(asset_key: u64, special_asset_key: Option<u64>) -> Self {
        let mut bytes = [0u8; 20];
        if special_asset_key == Some(asset_key) {
            // Special local account: tag byte 0x22, eleven more 0x22 bytes,
            // and a final 0x2222222222222222 word.
            bytes[..12].fill(SPECIAL_ADDRESS_TRAILER_TAG);
            bytes[12..20].copy_from_slice(&0x2222_2222_2222_2222u64.to_le_bytes());
        } else {
            bytes[0] = PRIMARY_ADDRESS_TRAILER_TAG;
            bytes[12..20].copy_from_slice(&asset_key.swap_bytes().to_le_bytes());
        }
        Self { bytes }
    }
}

#[derive(Clone, Debug)]
pub struct SettlementEntry72 {
    pub action_fields: [u8; 32],
    pub asset_key: u64,
    pub amount: u64,
    pub aux: u32,
}

impl SettlementEntry72 {
    #[inline]
    pub fn contributes_to_funding_sum(&self) -> bool {
        self.asset_key == 0
    }
}

#[derive(Clone, Debug)]
pub struct FundingMapDelta {
    pub key: AddressKey,
    pub amount: u64,
}

#[derive(Clone, Debug)]
pub struct GeneratedAction296 {
    pub action: ActionRecord,
    pub user_key: AddressKey,
    pub settlement_meta: [u8; 33],
    pub trailer_asset_key: u64,
    pub aux: u32,
}

impl GeneratedAction296 {
    #[inline]
    pub fn is_sentinel(&self) -> bool {
        self.action.discriminant == GENERATED_ACTION_SENTINEL
    }
}

#[derive(Clone, Debug, Default)]
pub struct EvmEndBlockOutputs {
    pub settlement_entries: Vec<SettlementEntry72>,
    pub generated_actions: Vec<GeneratedAction296>,
    pub funding_map_deltas: Vec<FundingMapDelta>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionRecord {
    pub discriminant: u64,
    pub payload: [u8; 232],
}

impl ActionRecord {
    #[inline]
    pub fn synthetic_settlement(entry: &SettlementEntry72) -> Self {
        let mut payload = [0u8; 232];
        payload[..32].copy_from_slice(&entry.action_fields);
        payload[32..40].copy_from_slice(&entry.asset_key.to_le_bytes());
        payload[40..48].copy_from_slice(&entry.amount.to_le_bytes());
        payload[48..52].copy_from_slice(&entry.aux.to_le_bytes());
        Self { discriminant: SYNTHETIC_SETTLEMENT_ACTION, payload }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyOutcome104 {
    pub tag: u8,
    pub payload: [u8; 103],
}

impl ApplyOutcome104 {
    #[inline]
    pub fn success() -> Self {
        Self { tag: SUCCESS_OUTCOME_TAG, payload: [0u8; 103] }
    }

    #[inline]
    pub fn receipt_word(&self) -> u64 {
        let mut word = [0u8; 8];
        word.copy_from_slice(&self.payload[0..8]);
        u64::from_le_bytes(word)
    }

    #[inline]
    pub fn is_error_payload(&self) -> bool {
        self.tag == ERROR_OUTCOME_TAG
    }
}

#[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndBlockRecord {
    pub action: ActionRecord,
    pub compact_outcome: [u8; 32],
    pub receipt_word: u64,
    pub address_trailer: AddressTrailer,
    pub aux: u32,
}

pub trait EndBlockHooks {
    fn apply_end_block_evm_outputs(&mut self, lane: EndBlockLane, elapsed_or_block_time_delta: u64) -> EvmEndBlockOutputs;
    fn compute_funding_update(&mut self, lane: FundingLane, funding_notional_sum: u64) -> FundingUpdate;
    fn compact_funding_deltas(&mut self, lane: FundingLane);
    fn note_funding_warning(&mut self, lane: FundingLane, update: &FundingUpdate);
    fn evm_chain_byte(&self) -> u8;
    fn dispatch_action_outcome(
        &mut self,
        lane: EndBlockLane,
        chain_byte: u8,
        action_sequence: u64,
        action: &ActionRecord,
        address_trailer: &AddressTrailer,
    ) -> ApplyOutcome104;
    fn settle_generated_action(
        &mut self,
        lane: EndBlockLane,
        user_key: &AddressKey,
        action: &ActionRecord,
        settlement_meta: &[u8; 33],
    ) -> ApplyOutcome104;
    fn dispatch_evm_hook_action(
        &mut self,
        user_key: &AddressKey,
        action_sequence: u64,
        settlement_meta_payload: &[u8; 32],
        action: &ActionRecord,
    );
    fn compact_action_outcome(&mut self, outcome: &ApplyOutcome104) -> [u8; 32];
    fn finish_generated_action_scan(&mut self, lane: EndBlockLane);
}

#[derive(Clone, Debug)]
pub struct ExchangeEndBlockState<H> {
    pub initialized: bool,
    pub global_action_sequence: u64,
    pub dispatch_action_sequence: u64,
    pub in_end_block_dispatch: bool,
    pub special_asset_key: Option<u64>,
    pub primary_funding: FundingLaneState,
    pub secondary_funding: FundingLaneState,
    pub hooks: H,
}

impl<H: EndBlockHooks> ExchangeEndBlockState<H> {
    pub fn collect_base_end_block_actions(&mut self, elapsed_or_block_time_delta: u64) -> Vec<EndBlockRecord> {
        self.collect_lane(EndBlockLane::Base, elapsed_or_block_time_delta)
    }

    pub fn collect_dex0_end_block_actions(&mut self, elapsed_or_block_time_delta: u64) -> Vec<EndBlockRecord> {
        self.collect_lane(EndBlockLane::Dex0, elapsed_or_block_time_delta)
    }

    pub fn collect_dex1_end_block_actions(&mut self, elapsed_or_block_time_delta: u64) -> Vec<EndBlockRecord> {
        self.collect_lane(EndBlockLane::Dex1, elapsed_or_block_time_delta)
    }

    pub fn collect_lane(&mut self, lane: EndBlockLane, elapsed_or_block_time_delta: u64) -> Vec<EndBlockRecord> {
        let outputs = self.hooks.apply_end_block_evm_outputs(lane, elapsed_or_block_time_delta);
        let funding_notional_sum = sum_zero_tagged_settlements(&outputs.settlement_entries);

        self.apply_funding_update(lane.funding_lane(), funding_notional_sum);
        self.merge_funding_map_deltas(lane.funding_lane(), &outputs.funding_map_deltas);

        let mut records = Vec::with_capacity(outputs.settlement_entries.len().saturating_add(outputs.generated_actions.len()));
        for entry in &outputs.settlement_entries {
            records.push(self.dispatch_synthetic_settlement(lane, entry));
        }

        for generated in &outputs.generated_actions {
            if generated.is_sentinel() {
                break;
            }
            records.push(self.dispatch_generated_action(lane, generated));
        }
        self.hooks.finish_generated_action_scan(lane);

        records
    }

    fn apply_funding_update(&mut self, lane: FundingLane, funding_notional_sum: u64) {
        let update = self.hooks.compute_funding_update(lane, funding_notional_sum);
        let mut should_compact = false;
        let mut should_warn = false;

        {
            let lane_state = self.funding_lane_mut(lane);
            match update {
                FundingUpdate::NoOracle => {
                    should_compact = lane_state.warning_emitted;
                }
                FundingUpdate::Success(key) => {
                    if lane_state.last_key.map_or(true, |old| key.is_newer_than(old)) {
                        lane_state.last_key = Some(key);
                    }
                    should_compact = lane_state.warning_emitted;
                }
                FundingUpdate::MissingDerivedData | FundingUpdate::Invalid => {
                    should_warn = !lane_state.warning_emitted;
                    lane_state.warning_emitted = true;
                    should_compact = true;
                }
            }
        }

        if should_warn {
            self.hooks.note_funding_warning(lane, &update);
        }
        if should_compact {
            self.hooks.compact_funding_deltas(lane);
        }
    }

    fn merge_funding_map_deltas(&mut self, lane: FundingLane, deltas: &[FundingMapDelta]) {
        let pending = &mut self.funding_lane_mut(lane).pending_by_key;
        for delta in deltas {
            let entry = pending.entry(delta.key).or_insert(0);
            *entry = entry.saturating_add(delta.amount);
        }
    }

    fn dispatch_synthetic_settlement(&mut self, lane: EndBlockLane, entry: &SettlementEntry72) -> EndBlockRecord {
        let action = ActionRecord::synthetic_settlement(entry);
        let address_trailer = AddressTrailer::from_asset_key(entry.asset_key, self.special_asset_key);
        let chain_byte = self.hooks.evm_chain_byte();
        let action_sequence = self.next_dispatch_sequence();

        self.in_end_block_dispatch = true;
        let outcome = self.hooks.dispatch_action_outcome(lane, chain_byte, action_sequence, &action, &address_trailer);
        self.in_end_block_dispatch = false;

        self.bump_global_action_sequence();
        self.record_from_parts(action, outcome, address_trailer, entry.aux)
    }

    fn dispatch_generated_action(&mut self, lane: EndBlockLane, generated: &GeneratedAction296) -> EndBlockRecord {
        let address_trailer = AddressTrailer::from_asset_key(generated.trailer_asset_key, self.special_asset_key);
        let action_sequence = self.current_global_sequence_for_generated_action();

        if lane.uses_evm_hook() {
            let mut hook_payload = [0u8; 32];
            hook_payload.copy_from_slice(&generated.settlement_meta[1..33]);
            self.hooks.dispatch_evm_hook_action(&generated.user_key, action_sequence, &hook_payload, &generated.action);
        }

        let outcome = self.hooks.settle_generated_action(
            lane,
            &generated.user_key,
            &generated.action,
            &generated.settlement_meta,
        );
        self.bump_global_action_sequence();

        self.record_from_parts(generated.action.clone(), outcome, address_trailer, generated.aux)
    }

    fn record_from_parts(
        &mut self,
        action: ActionRecord,
        outcome: ApplyOutcome104,
        address_trailer: AddressTrailer,
        aux: u32,
    ) -> EndBlockRecord {
        let compact_outcome = if outcome.is_error_payload() {
            self.hooks.compact_action_outcome(&outcome)
        } else {
            let mut success = outcome.clone();
            success.tag = SUCCESS_OUTCOME_TAG;
            self.hooks.compact_action_outcome(&success)
        };
        EndBlockRecord { action, compact_outcome, receipt_word: outcome.receipt_word(), address_trailer, aux }
    }

    #[inline]
    fn next_dispatch_sequence(&mut self) -> u64 {
        let current = self.dispatch_action_sequence;
        self.dispatch_action_sequence = self.dispatch_action_sequence.saturating_add(1);
        current
    }

    #[inline]
    fn current_global_sequence_for_generated_action(&mut self) -> u64 {
        if !self.initialized {
            self.initialized = true;
            self.global_action_sequence = 0;
        }
        self.global_action_sequence
    }

    #[inline]
    fn bump_global_action_sequence(&mut self) {
        if !self.initialized {
            self.initialized = true;
            self.global_action_sequence = 0;
        }
        self.global_action_sequence = self.global_action_sequence.saturating_add(1);
    }

    #[inline]
    fn funding_lane_mut(&mut self, lane: FundingLane) -> &mut FundingLaneState {
        match lane {
            FundingLane::Primary => &mut self.primary_funding,
            FundingLane::Secondary => &mut self.secondary_funding,
        }
    }
}

pub fn sum_zero_tagged_settlements(entries: &[SettlementEntry72]) -> u64 {
    let mut total = 0u64;
    for entry in entries {
        if entry.contributes_to_funding_sum() {
            total = total.saturating_add(entry.amount);
        }
    }
    total
}
