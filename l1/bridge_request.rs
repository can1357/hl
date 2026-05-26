use core::fmt;

use serde::{Deserialize, Serialize};

use crate::utils::keccak256;

pub type Address = [u8; 20];
pub type B256 = [u8; 32];

const BRIDGE_ACTION_TAG: u8 = b'a';
const MAINNET_ARBITRUM_CHAIN_ID: u64 = 42_161;
const TESTNET_ARBITRUM_CHAIN_ID: u64 = 421_614;
const MAX_VEC_ITEMS_20_BYTE: usize = 0x333333333333333;
const MAX_VEC_ITEMS_32_BYTE: usize = 1usize << 59;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Chain {
    Local,
    Sandbox,
    Testnet,
    Mainnet,
}

impl Chain {
    #[inline]
    pub const fn signature_chain_id(self) -> u64 {
        match self {
            Chain::Mainnet => MAINNET_ARBITRUM_CHAIN_ID,
            Chain::Local | Chain::Sandbox | Chain::Testnet => TESTNET_ARBITRUM_CHAIN_ID,
        }
    }

    #[inline]
    pub const fn signing_name(self) -> &'static str {
        match self {
            Chain::Local => "Local",
            Chain::Sandbox => "Sandbox",
            Chain::Testnet => "Testnet",
            Chain::Mainnet => "Mainnet",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BridgeRole {
    Locker,
    Finalizer,
}

impl BridgeRole {
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            BridgeRole::Locker => "Locker",
            BridgeRole::Finalizer => "Finalizer",
        }
    }
}
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgePayloadType {
    ModifyValidator = 0,
    ChangeDisputePeriodSeconds = 1,
    ChangeBlockDurationMillis = 2,
    ChangeLockerThreshold = 3,
    UpdateValidatorSet = 4,
    RequestWithdrawal = 5,
    Reserved = 6,
    InvalidateWithdrawals = 7,
}

impl BridgePayloadType {
    pub fn from_discriminant(discriminant: u8) -> Result<Self, BridgeRequestError> {
        match discriminant {
            0 => Ok(Self::ModifyValidator),
            1 => Ok(Self::ChangeDisputePeriodSeconds),
            2 => Ok(Self::ChangeBlockDurationMillis),
            3 => Ok(Self::ChangeLockerThreshold),
            4 => Ok(Self::UpdateValidatorSet),
            5 => Ok(Self::RequestWithdrawal),
            6 => Ok(Self::Reserved),
            7 => Ok(Self::InvalidateWithdrawals),
            _ => Err(BridgeRequestError::UnknownAction),
        }
    }

    pub fn from_action_name(action: &str) -> Result<Self, BridgeRequestError> {
        match action {
            "modifyLocker" | "modifyFinalizer" => Ok(Self::ModifyValidator),
            "changeDisputePeriodSeconds" => Ok(Self::ChangeDisputePeriodSeconds),
            "changeBlockDurationMillis" => Ok(Self::ChangeBlockDurationMillis),
            "changeLockerThreshold" => Ok(Self::ChangeLockerThreshold),
            "updateValidatorSet" => Ok(Self::UpdateValidatorSet),
            "requestWithdrawal" => Ok(Self::RequestWithdrawal),
            "invalidateWithdrawals" => Ok(Self::InvalidateWithdrawals),
            _ => Err(BridgeRequestError::UnknownAction),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeValidator {
    pub locker: Address,
    pub finalizer: Address,
    pub withdrawal_root: B256,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BridgeRequestPayload {
    ModifyValidator {
        role: BridgeRole,
        active: bool,
        validator: Address,
        nonce: u64,
    },
    ChangeDisputePeriodSeconds {
        seconds: u64,
        nonce: u64,
    },
    ChangeBlockDurationMillis {
        millis: u64,
        nonce: u64,
    },
    ChangeLockerThreshold {
        threshold: u64,
        nonce: u64,
    },
    UpdateValidatorSet {
        validators: Vec<BridgeValidator>,
        nonce: u64,
    },
    RequestWithdrawal {
        account: Address,
        destination: Address,
        amount: u64,
        nonce: u64,
    },
    InvalidateWithdrawals {
        account: Address,
        withdrawal_ids: Vec<B256>,
        nonce: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeRequest {
    /// The recovered constructor allocates one byte and writes ASCII `a` before
    /// attaching the payload hash and chain id.
    pub tag: u8,
    pub payload_hash: B256,
    pub chain_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BridgeRequestError {
    UnknownAction,
    MissingField(&'static str),
    DuplicateField(&'static str),
    WrongFieldCount,
    InvalidRole,
    InvalidAddressLength,
    InvalidHashLength,
    TooManyItems,
}

impl fmt::Display for BridgeRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BridgeRequestError::UnknownAction => f.write_str("unknown bridge request action"),
            BridgeRequestError::MissingField(field) => write!(f, "missing bridge request field `{field}`"),
            BridgeRequestError::DuplicateField(field) => write!(f, "duplicate bridge request field `{field}`"),
            BridgeRequestError::WrongFieldCount => f.write_str("wrong number of bridge request fields"),
            BridgeRequestError::InvalidRole => f.write_str("invalid bridge validator role"),
            BridgeRequestError::InvalidAddressLength => f.write_str("bridge address must be 20 bytes"),
            BridgeRequestError::InvalidHashLength => f.write_str("bridge hash must be 32 bytes"),
            BridgeRequestError::TooManyItems => f.write_str("bridge request vector length overflow"),
        }
    }
}

impl BridgeRequestPayload {
    pub fn action_name(&self) -> &'static str {
        match self {
            BridgeRequestPayload::ModifyValidator { role: BridgeRole::Locker, .. } => "modifyLocker",
            BridgeRequestPayload::ModifyValidator { role: BridgeRole::Finalizer, .. } => "modifyFinalizer",
            BridgeRequestPayload::ChangeDisputePeriodSeconds { .. } => "changeDisputePeriodSeconds",
            BridgeRequestPayload::ChangeBlockDurationMillis { .. } => "changeBlockDurationMillis",
            BridgeRequestPayload::ChangeLockerThreshold { .. } => "changeLockerThreshold",
            BridgeRequestPayload::UpdateValidatorSet { .. } => "updateValidatorSet",
            BridgeRequestPayload::RequestWithdrawal { .. } => "requestWithdrawal",
            BridgeRequestPayload::InvalidateWithdrawals { .. } => "invalidateWithdrawals",
        }
    }
    pub fn payload_type(&self) -> BridgePayloadType {
        match self {
            BridgeRequestPayload::ModifyValidator { .. } => BridgePayloadType::ModifyValidator,
            BridgeRequestPayload::ChangeDisputePeriodSeconds { .. } => BridgePayloadType::ChangeDisputePeriodSeconds,
            BridgeRequestPayload::ChangeBlockDurationMillis { .. } => BridgePayloadType::ChangeBlockDurationMillis,
            BridgeRequestPayload::ChangeLockerThreshold { .. } => BridgePayloadType::ChangeLockerThreshold,
            BridgeRequestPayload::UpdateValidatorSet { .. } => BridgePayloadType::UpdateValidatorSet,
            BridgeRequestPayload::RequestWithdrawal { .. } => BridgePayloadType::RequestWithdrawal,
            BridgeRequestPayload::InvalidateWithdrawals { .. } => BridgePayloadType::InvalidateWithdrawals,
        }
    }

    pub fn nonce(&self) -> u64 {
        match self {
            BridgeRequestPayload::ModifyValidator { nonce, .. }
            | BridgeRequestPayload::ChangeDisputePeriodSeconds { nonce, .. }
            | BridgeRequestPayload::ChangeBlockDurationMillis { nonce, .. }
            | BridgeRequestPayload::ChangeLockerThreshold { nonce, .. }
            | BridgeRequestPayload::UpdateValidatorSet { nonce, .. }
            | BridgeRequestPayload::RequestWithdrawal { nonce, .. }
            | BridgeRequestPayload::InvalidateWithdrawals { nonce, .. } => *nonce,
        }
    }

    pub fn validate(&self) -> Result<(), BridgeRequestError> {
        match self {
            BridgeRequestPayload::UpdateValidatorSet { validators, .. } => {
                checked_20_byte_vec_len(validators.len())?;
                Ok(())
            }
            BridgeRequestPayload::InvalidateWithdrawals { withdrawal_ids, .. } => {
                checked_32_byte_vec_len(withdrawal_ids.len())?;
                Ok(())
            }
            BridgeRequestPayload::ModifyValidator { .. }
            | BridgeRequestPayload::ChangeDisputePeriodSeconds { .. }
            | BridgeRequestPayload::ChangeBlockDurationMillis { .. }
            | BridgeRequestPayload::ChangeLockerThreshold { .. }
            | BridgeRequestPayload::RequestWithdrawal { .. } => Ok(()),
        }
    }

    pub fn bridge_request(&self, chain: Chain) -> Result<BridgeRequest, BridgeRequestError> {
        self.validate()?;
        Ok(BridgeRequest {
            tag: BRIDGE_ACTION_TAG,
            payload_hash: self.struct_hash(),
            chain_id: chain.signature_chain_id(),
        })
    }

    pub fn struct_hash(&self) -> B256 {
        let mut enc = Eip712StructEncoder::new();
        enc.push_string(self.action_name());

        match self {
            BridgeRequestPayload::ModifyValidator { active, validator, nonce, .. } => {
                enc.push_address(validator);
                enc.push_bool(*active);
                enc.push_u64(*nonce);
            }
            BridgeRequestPayload::ChangeDisputePeriodSeconds { seconds, nonce }
            | BridgeRequestPayload::ChangeBlockDurationMillis { millis: seconds, nonce }
            | BridgeRequestPayload::ChangeLockerThreshold { threshold: seconds, nonce } => {
                enc.push_u64(*seconds);
                enc.push_u64(*nonce);
            }
            BridgeRequestPayload::UpdateValidatorSet { validators, nonce } => {
                enc.push_address_array(validators.iter().map(|validator| &validator.locker));
                enc.push_address_array(validators.iter().map(|validator| &validator.finalizer));
                enc.push_hash_array(validators.iter().map(|validator| &validator.withdrawal_root));
                enc.push_u64(*nonce);
            }
            BridgeRequestPayload::RequestWithdrawal { account, destination, amount, nonce } => {
                enc.push_address(account);
                enc.push_address(destination);
                enc.push_u64(*amount);
                enc.push_u64(*nonce);
            }
            BridgeRequestPayload::InvalidateWithdrawals { account, withdrawal_ids, nonce } => {
                enc.push_address(account);
                enc.push_hash_array(withdrawal_ids.iter());
                enc.push_u64(*nonce);
            }
        }

        enc.finish()
    }

    pub fn from_action_fields(action: &str, fields: BridgeFields) -> Result<Self, BridgeRequestError> {
        match action {
            "modifyLocker" => fields.into_modify_validator(BridgeRole::Locker),
            "modifyFinalizer" => fields.into_modify_validator(BridgeRole::Finalizer),
            "changeDisputePeriodSeconds" => fields.into_change_dispute_period_seconds(),
            "changeBlockDurationMillis" => fields.into_change_block_duration_millis(),
            "changeLockerThreshold" => fields.into_change_locker_threshold(),
            "updateValidatorSet" => fields.into_update_validator_set(),
            "requestWithdrawal" => fields.into_request_withdrawal(),
            "invalidateWithdrawals" => fields.into_invalidate_withdrawals(),
            _ => Err(BridgeRequestError::UnknownAction),
        }
    }
}

impl BridgeRequest {
    #[inline]
    pub const fn new(payload_hash: B256, chain_id: u64) -> Self {
        Self { tag: BRIDGE_ACTION_TAG, payload_hash, chain_id }
    }

    #[inline]
    pub fn data(&self) -> [u8; 1] {
        [self.tag]
    }

    #[inline]
    pub fn validate(&self) -> bool {
        self.tag == BRIDGE_ACTION_TAG
            && (self.chain_id == MAINNET_ARBITRUM_CHAIN_ID || self.chain_id == TESTNET_ARBITRUM_CHAIN_ID)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BridgeFields {
    pub role: Option<BridgeRole>,
    pub active: Option<bool>,
    pub validator: Option<Address>,
    pub account: Option<Address>,
    pub destination: Option<Address>,
    pub amount: Option<u64>,
    pub value: Option<u64>,
    pub nonce: Option<u64>,
    pub validators: Option<Vec<BridgeValidator>>,
    pub withdrawal_ids: Option<Vec<B256>>,
}

impl BridgeFields {
    fn into_modify_validator(self, role: BridgeRole) -> Result<BridgeRequestPayload, BridgeRequestError> {
        let active = require(self.active, "active")?;
        let validator = require(self.validator, "validator")?;
        let nonce = require(self.nonce, "nonce")?;
        if let Some(parsed_role) = self.role {
            if parsed_role != role {
                return Err(BridgeRequestError::InvalidRole);
            }
        }
        Ok(BridgeRequestPayload::ModifyValidator { role, active, validator, nonce })
    }

    fn into_change_dispute_period_seconds(self) -> Result<BridgeRequestPayload, BridgeRequestError> {
        Ok(BridgeRequestPayload::ChangeDisputePeriodSeconds {
            seconds: require(self.value, "seconds")?,
            nonce: require(self.nonce, "nonce")?,
        })
    }

    fn into_change_block_duration_millis(self) -> Result<BridgeRequestPayload, BridgeRequestError> {
        Ok(BridgeRequestPayload::ChangeBlockDurationMillis {
            millis: require(self.value, "millis")?,
            nonce: require(self.nonce, "nonce")?,
        })
    }

    fn into_change_locker_threshold(self) -> Result<BridgeRequestPayload, BridgeRequestError> {
        Ok(BridgeRequestPayload::ChangeLockerThreshold {
            threshold: require(self.value, "threshold")?,
            nonce: require(self.nonce, "nonce")?,
        })
    }

    fn into_update_validator_set(self) -> Result<BridgeRequestPayload, BridgeRequestError> {
        let validators = require(self.validators, "validators")?;
        checked_20_byte_vec_len(validators.len())?;
        Ok(BridgeRequestPayload::UpdateValidatorSet {
            validators,
            nonce: require(self.nonce, "nonce")?,
        })
    }

    fn into_request_withdrawal(self) -> Result<BridgeRequestPayload, BridgeRequestError> {
        Ok(BridgeRequestPayload::RequestWithdrawal {
            account: require(self.account, "account")?,
            destination: require(self.destination, "destination")?,
            amount: require(self.amount, "amount")?,
            nonce: require(self.nonce, "nonce")?,
        })
    }

    fn into_invalidate_withdrawals(self) -> Result<BridgeRequestPayload, BridgeRequestError> {
        let withdrawal_ids = require(self.withdrawal_ids, "withdrawalIds")?;
        checked_32_byte_vec_len(withdrawal_ids.len())?;
        Ok(BridgeRequestPayload::InvalidateWithdrawals {
            account: require(self.account, "account")?,
            withdrawal_ids,
            nonce: require(self.nonce, "nonce")?,
        })
    }
}

fn require<T>(value: Option<T>, field: &'static str) -> Result<T, BridgeRequestError> {
    value.ok_or(BridgeRequestError::MissingField(field))
}

fn checked_20_byte_vec_len(len: usize) -> Result<(), BridgeRequestError> {
    if len > MAX_VEC_ITEMS_20_BYTE {
        Err(BridgeRequestError::TooManyItems)
    } else {
        Ok(())
    }
}

fn checked_32_byte_vec_len(len: usize) -> Result<(), BridgeRequestError> {
    if len >= MAX_VEC_ITEMS_32_BYTE {
        Err(BridgeRequestError::TooManyItems)
    } else {
        Ok(())
    }
}

#[derive(Default)]
struct Eip712StructEncoder {
    bytes: Vec<u8>,
}

impl Eip712StructEncoder {
    fn new() -> Self {
        Self { bytes: Vec::with_capacity(256) }
    }

    fn push_string(&mut self, value: &str) {
        self.bytes.push(6);
        self.bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        self.bytes.extend_from_slice(value.as_bytes());
    }

    fn push_address(&mut self, address: &Address) {
        self.bytes.push(0);
        self.bytes.extend_from_slice(address);
    }

    fn push_bool(&mut self, value: bool) {
        self.bytes.push(5);
        self.bytes.push(u8::from(value));
    }

    fn push_u64(&mut self, value: u64) {
        self.bytes.push(4);
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn push_hash(&mut self, hash: &B256) {
        self.bytes.push(4);
        self.bytes.extend_from_slice(hash);
    }

    fn push_address_array<'a, I>(&mut self, values: I)
    where
        I: IntoIterator<Item = &'a Address>,
    {
        let offset = self.start_array();
        let mut count = 0usize;
        for value in values {
            self.push_address(value);
            count += 1;
        }
        self.finish_array(offset, count);
    }

    fn push_hash_array<'a, I>(&mut self, values: I)
    where
        I: IntoIterator<Item = &'a B256>,
    {
        let offset = self.start_array();
        let mut count = 0usize;
        for value in values {
            self.push_hash(value);
            count += 1;
        }
        self.finish_array(offset, count);
    }

    fn start_array(&mut self) -> usize {
        self.bytes.push(8);
        let offset = self.bytes.len();
        self.bytes.extend_from_slice(&0u64.to_be_bytes());
        offset
    }

    fn finish_array(&mut self, offset: usize, count: usize) {
        self.bytes[offset..offset + 8].copy_from_slice(&(count as u64).to_be_bytes());
    }

    fn finish(self) -> B256 {
        // The binary converts the field vector into nested EIP-712 data and then
        // absorbs the serialized bytes through the Keccak sponge.  The tags here
        // mirror the recovered value tags: 0=address, 4=uint/hash, 5=bool,
        // 6=string, 8=array.
        keccak256(&self.bytes)
    }
}

pub fn parse_role(value: &str) -> Result<BridgeRole, BridgeRequestError> {
    match value {
        "Locker" | "locker" => Ok(BridgeRole::Locker),
        "Finalizer" | "finalizer" => Ok(BridgeRole::Finalizer),
        _ => Err(BridgeRequestError::InvalidRole),
    }
}

pub fn copy_address(bytes: &[u8]) -> Result<Address, BridgeRequestError> {
    if bytes.len() != 20 {
        return Err(BridgeRequestError::InvalidAddressLength);
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(bytes);
    Ok(out)
}

pub fn copy_hash(bytes: &[u8]) -> Result<B256, BridgeRequestError> {
    if bytes.len() != 32 {
        return Err(BridgeRequestError::InvalidHashLength);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}
