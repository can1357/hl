use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type ValidatorKey = [u8; 32];
pub type Nonce = u64;

pub const STATUS_OK: u16 = 390;
pub const STATUS_ALREADY_REGISTERED: u16 = 147;
pub const STATUS_VALIDATOR_UNAVAILABLE: u16 = 148;
pub const STATUS_VALIDATOR_JOIN_PROOF_REJECTED: u16 = 150;
pub const STATUS_SIGNATURE_RECOVERY_ERROR: u16 = 122;
pub const STATUS_COLD_USER_SIGNATURE_MISMATCH: u16 = 287;

pub const VALIDATOR_JOIN_TOPIC: &str = "VALIDATOR_JOIN";
pub const ACTION_DOMAIN_CHAIN_ID: u64 = 1337;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterValidatorAction {
    /// First 64 bytes of the payload.
    pub signature: [u8; 64],
    /// The 32-byte validator identity looked up in the pre-approved key set.
    pub validator: ValidatorKey,
    /// Serialized compact/EIP-712 signature recovered through the generic action
    /// signer path.
    pub cold_user_signature: Vec<u8>,
    pub nonce: Nonce,
    pub cold_user: Address,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredValidatorAuth {
    /// `sub_33A6920(..., signer, 1)` seeds a fresh 20-byte-keyed map before the
    /// validator record is inserted.
    ///
    /// [INFERENCE] In this handler the map acts as a one-entry bootstrap stake or
    /// weight table keyed by the hot/action signer.
    pub initial_signer_weight_by_address: BTreeMap<Address, u64>,
    /// The action signer carried in the outer execution context (`a3`).
    pub signer: Address,
    /// Cold user recovered from the secondary signature and stored alongside the
    /// validator signer relationship.
    pub cold_user: Address,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RegisterValidatorState {
    /// `a2[11]`/`a2[12]`: 32-byte-key tree consulted before any signature work.
    ///
    /// [INFERENCE] The exact source tree name is unknown; the handler treats it as
    /// the set of validator identities eligible to complete registration.
    pub known_validator_keys: BTreeSet<ValidatorKey>,
    /// `a2[1]`/`a2[2]`: final registry keyed by the same 32-byte validator key.
    pub validator_key_to_auth: BTreeMap<ValidatorKey, RegisteredValidatorAuth>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegisterValidatorError<R> {
    /// Compact status 148.
    ///
    /// This covers both early failure modes in the handler: the validator key is
    /// absent from the eligibility tree, or the key cannot be normalized for the
    /// join-proof checks.
    ValidatorUnavailable,
    /// Compact status 150.
    ValidatorJoinProofRejected,
    /// Compact status 122 with a recovery/detail payload.
    ColdUserSignatureRecovery(R),
    /// Compact status 287.
    ColdUserSignatureMismatch,
    /// Compact status 147.
    AlreadyRegistered,
}

pub trait RegisterValidatorCrypto {
    type RecoverError;

    /// Mirrors `sub_1583680` and the follow-on normalization done before both
    /// signature checks.
    fn validator_key_is_well_formed(&self, validator: &ValidatorKey) -> bool;

    /// Verifies the validator-owned join proof built from:
    /// - the validator identity,
    /// - the literal topic `VALIDATOR_JOIN`, and
    /// - the action nonce.
    fn verify_validator_join_proof(
        &self,
        validator: &ValidatorKey,
        signature: &[u8; 64],
        nonce: Nonce,
    ) -> bool;

    /// Recovers the address from the secondary signature over the same join payload
    /// hashed through the generic L1 action domain.
    fn recover_cold_user(
        &self,
        validator: &ValidatorKey,
        cold_user_signature: &[u8],
        nonce: Nonce,
        action_domain_tag: u8,
        chain_id: u64,
    ) -> Result<Address, Self::RecoverError>;
}

#[inline]
pub const fn action_domain_tag(feature_state: u8) -> u8 {
    98 - u8::from(feature_state == 3)
}

pub fn apply_register_validator<C: RegisterValidatorCrypto>(
    state: &mut RegisterValidatorState,
    signer: Address,
    action: &RegisterValidatorAction,
    feature_state: u8,
    crypto: &C,
) -> Result<(), RegisterValidatorError<C::RecoverError>> {
    if !state.known_validator_keys.contains(&action.validator) {
        return Err(RegisterValidatorError::ValidatorUnavailable);
    }
    if !crypto.validator_key_is_well_formed(&action.validator) {
        return Err(RegisterValidatorError::ValidatorUnavailable);
    }
    if !crypto.verify_validator_join_proof(&action.validator, &action.signature, action.nonce) {
        return Err(RegisterValidatorError::ValidatorJoinProofRejected);
    }

    let recovered_cold_user = crypto
        .recover_cold_user(
            &action.validator,
            &action.cold_user_signature,
            action.nonce,
            action_domain_tag(feature_state),
            ACTION_DOMAIN_CHAIN_ID,
        )
        .map_err(RegisterValidatorError::ColdUserSignatureRecovery)?;
    if recovered_cold_user != action.cold_user {
        return Err(RegisterValidatorError::ColdUserSignatureMismatch);
    }
    if state.validator_key_to_auth.contains_key(&action.validator) {
        return Err(RegisterValidatorError::AlreadyRegistered);
    }

    let mut initial_signer_weight_by_address = BTreeMap::new();
    initial_signer_weight_by_address.insert(signer, 1);

    state.validator_key_to_auth.insert(
        action.validator,
        RegisteredValidatorAuth {
            initial_signer_weight_by_address,
            signer,
            cold_user: action.cold_user,
        },
    );
    Ok(())
}
