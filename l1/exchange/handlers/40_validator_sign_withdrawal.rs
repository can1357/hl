#![allow(dead_code)]

use std::collections::BTreeMap;

pub type Address = [u8; 20];
pub type Nonce = u64;
pub type Usd = u64;
pub type SignatureBytes = Vec<u8>;

pub const STATUS_OK: u16 = 390;
pub const STATUS_AMOUNT_OVERFLOW: u16 = 319;
pub const STATUS_BAD_SIGNATURE: u16 = 122;
pub const STATUS_SIGNER_MISMATCH: u16 = 287;
pub const STATUS_DUPLICATE_VALIDATOR_SIGNATURE: u16 = 144;

/// `sub_374EC60` rejects `usd >= 0xCCCCCCCCCCCCCCCD` before any bridge-request
/// construction or signer/state lookup.
pub const BRIDGE_WITHDRAWAL_USD_LIMIT_EXCLUSIVE: u64 = 0xCCCC_CCCC_CCCC_CCCD;
/// `sub_3942D90` trims the pending-signature tree once it grows past `100` keys.
pub const MAX_TRACKED_PENDING_WITHDRAWALS: usize = 100;
pub const MAINNET_BRIDGE_CHAIN_ID: u64 = 42_161;
pub const TESTNET_BRIDGE_CHAIN_ID: u64 = 421_614;

/// The payload documentation originally labeled the first field as `tx`, but the
/// handler feeds it into the bridge-request `amount` slot, applies the same large
/// amount guard used by other withdrawal/signing paths, and forwards the second
/// field as the bridge nonce.
#[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorSignWithdrawalAction {
    pub usd: Usd,
    pub nonce: Nonce,
    /// Opaque witness/signature bundle at payload `+0x10..+0x57`.
    ///
    /// The wrapper passes these 72 bytes both into the bridge-signature recovery
    /// helper (`sub_14C6F50`) and into the pending-signature tracker mutation
    /// helper (`sub_3942D90`).
    pub withdrawal_data: WithdrawalData,
    pub user: Address,
    pub destination: Address,
}

#[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawalData {
    pub raw: [u8; 72],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UserAndNonce {
    pub nonce: Nonce,
    pub user: Address,
}

impl UserAndNonce {
    #[inline]
    pub const fn new(nonce: Nonce, user: Address) -> Self {
        Self { nonce, user }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Withdrawal {
    pub usd: Usd,
    pub destination: Address,
}

impl Withdrawal {
    #[inline]
    pub const fn new(usd: Usd, destination: Address) -> Self {
        Self { usd, destination }
    }
}

/// `base_iter__cham_iterator_unique_elem(...)` does not just return the signer
/// address; it resolves an opaque per-validator slot that the pending-signature
/// tree uses for duplicate detection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct BridgeValidatorSlot(pub [u8; 32]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedValidatorSignature {
    pub signer: Address,
    /// [INFERENCE] The mutation helper persists enough of the witness blob to keep
    /// per-validator bridge-signature material alongside the slot key.
    pub witness: WithdrawalData,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingSignedWithdrawal {
    pub withdrawal: Withdrawal,
    pub validator_slot_to_signature: BTreeMap<BridgeValidatorSlot, RecordedValidatorSignature>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PendingWithdrawalSignatures {
    pub by_user_and_nonce: BTreeMap<UserAndNonce, PendingSignedWithdrawal>,
}

impl PendingWithdrawalSignatures {
    /// Recovered state mutation from `sub_3942D90`:
    ///
    /// - bucket by `(user, nonce)`;
    /// - reject the same validator slot signing that bucket twice (`144`);
    /// - retain the canonical `(usd, destination)` withdrawal tuple for the bucket;
    /// - store the validator's witness bytes; and
    /// - [INFERENCE] trim the tree back to at most `100` keys.
    pub fn record_signature(
        &mut self,
        key: UserAndNonce,
        withdrawal: Withdrawal,
        slot: BridgeValidatorSlot,
        signer: Address,
        witness: WithdrawalData,
    ) -> Result<(), ValidatorSignWithdrawalError> {
        let entry = self
            .by_user_and_nonce
            .entry(key)
            .or_insert_with(|| PendingSignedWithdrawal {
                withdrawal,
                validator_slot_to_signature: BTreeMap::new(),
            });

        if entry.validator_slot_to_signature.contains_key(&slot) {
            return Err(ValidatorSignWithdrawalError::DuplicateValidatorSignature {
                key,
                slot,
            });
        }

        entry.withdrawal = withdrawal;
        entry.validator_slot_to_signature.insert(
            slot,
            RecordedValidatorSignature {
                signer,
                witness,
            },
        );

        while self.by_user_and_nonce.len() > MAX_TRACKED_PENDING_WITHDRAWALS {
            let Some(first_key) = self.by_user_and_nonce.keys().next().copied() else {
                break;
            };
            self.by_user_and_nonce.remove(&first_key);
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeRequest {
    pub tag: u8,
    pub payload_hash: [u8; 32],
    pub chain_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeRequestPayloadType {
    RequestWithdrawal = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidatorSignWithdrawalError {
    AmountOverflow { usd: Usd },
    BadSignature,
    SignerMismatch {
        recovered: Address,
        expected: Address,
    },
    DuplicateValidatorSignature {
        key: UserAndNonce,
        slot: BridgeValidatorSlot,
    },
    /// `base_iter__cham_iterator_unique_elem(...)` can fail before signature
    /// recovery or state mutation. The concrete status depends on the live bridge
    /// validator context and is forwarded unchanged by the wrapper.
    Raw(u16),
}

impl ValidatorSignWithdrawalError {
    #[inline]
    pub const fn status(self) -> u16 {
        match self {
            Self::AmountOverflow { .. } => STATUS_AMOUNT_OVERFLOW,
            Self::BadSignature => STATUS_BAD_SIGNATURE,
            Self::SignerMismatch { .. } => STATUS_SIGNER_MISMATCH,
            Self::DuplicateValidatorSignature { .. } => STATUS_DUPLICATE_VALIDATOR_SIGNATURE,
            Self::Raw(status) => status,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ValidatorVoteContext {
    pub raw: [u8; 32],
}

pub trait ValidatorSignWithdrawalCrypto {
    fn build_request_withdrawal_hash(&self, action: &ValidatorSignWithdrawalAction) -> [u8; 32];
    fn recover_request_withdrawal_signer(
        &self,
        request: &BridgeRequest,
        witness: &WithdrawalData,
    ) -> Option<Address>;
}

pub trait ValidatorSignWithdrawalState {
    /// Mirrors the leading `base_iter__cham_iterator_unique_elem(...)` lookup.
    fn resolve_unique_bridge_validator_slot(
        &self,
        ctx: &ValidatorVoteContext,
    ) -> Result<BridgeValidatorSlot, ValidatorSignWithdrawalError>;

    fn pending_withdrawal_signatures(&mut self) -> &mut PendingWithdrawalSignatures;
}

#[inline]
pub const fn bridge_chain_id(chain_discriminant: u8) -> u64 {
    if chain_discriminant == 3 {
        MAINNET_BRIDGE_CHAIN_ID
    } else {
        TESTNET_BRIDGE_CHAIN_ID
    }
}

#[inline]
pub fn build_bridge_request<C: ValidatorSignWithdrawalCrypto>(
    crypto: &C,
    chain_discriminant: u8,
    action: &ValidatorSignWithdrawalAction,
) -> BridgeRequest {
    BridgeRequest {
        tag: b'a',
        payload_hash: crypto.build_request_withdrawal_hash(action),
        chain_id: bridge_chain_id(chain_discriminant),
    }
}

/// Recovered wrapper flow for `sub_374EC60`
/// / `l1_exchange_impl_execute_action__validator_sign_withdrawal`:
///
/// 1. Reject absurdly large `usd` values with `319`.
/// 2. Resolve the caller's current bridge-validator slot from the outer context;
///    any failure status from that lookup is returned unchanged.
/// 3. Build the canonical bridge request for payload type `5` (`requestWithdrawal`)
///    over `(user, destination, usd, nonce)` and the chain id chosen from the
///    chain discriminant (`42161` on mainnet, `421614` otherwise).
/// 4. Recover the signer from `action.withdrawal_data`; recovery failure returns
///    `122` and a recovered-address mismatch returns `287`.
/// 5. Upsert the pending `(user, nonce)` withdrawal bucket, reject a duplicate
///    signature from the same validator slot with `144`, and prune the tracker
///    back to at most `100` keys.
pub fn apply_validator_sign_withdrawal<S, C>(
    state: &mut S,
    signer: Address,
    chain_discriminant: u8,
    ctx: &ValidatorVoteContext,
    action: &ValidatorSignWithdrawalAction,
    crypto: &C,
) -> Result<(), ValidatorSignWithdrawalError>
where
    S: ValidatorSignWithdrawalState,
    C: ValidatorSignWithdrawalCrypto,
{
    if action.usd >= BRIDGE_WITHDRAWAL_USD_LIMIT_EXCLUSIVE {
        return Err(ValidatorSignWithdrawalError::AmountOverflow { usd: action.usd });
    }

    let slot = state.resolve_unique_bridge_validator_slot(ctx)?;
    let request = build_bridge_request(crypto, chain_discriminant, action);
    let recovered = crypto
        .recover_request_withdrawal_signer(&request, &action.withdrawal_data)
        .ok_or(ValidatorSignWithdrawalError::BadSignature)?;
    if recovered != signer {
        return Err(ValidatorSignWithdrawalError::SignerMismatch {
            recovered,
            expected: signer,
        });
    }

    state.pending_withdrawal_signatures().record_signature(
        UserAndNonce::new(action.nonce, action.user),
        Withdrawal::new(action.usd, action.destination),
        slot,
        signer,
        action.withdrawal_data.clone(),
    )
}
