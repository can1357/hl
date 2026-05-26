use core::cmp::Ordering;
use core::fmt;

use serde::de::{Error as DeError, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const ACTION_TYPE: &str = "EvmRawTx";
pub const ACTION_STRUCT_NAME: &str = "EvmRawTxAction";
pub const ACTION_FIELD_DATA: &str = "data";
pub const MAX_RAW_TX_BYTES: usize = 0x3e800;
pub const MAX_CALLDATA_BYTES: usize = 0x20000;
pub const LARGE_CALLDATA_EMPTY_PREFIX_THRESHOLD: usize = 0xc001;
pub const MIN_FEE_CAP_WEI: U256 = U256::from_u64(100_000_000);
pub const NORMAL_ACCOUNT_GAS_LIMIT: u64 = 3_000_000;
pub const BIG_BLOCK_ACCOUNT_GAS_LIMIT: u64 = 30_000_000;
pub const NONCE_LOOKAHEAD: u64 = 8;

const TX_TYPE_EIP2930: u8 = 1;
const TX_TYPE_EIP1559: u8 = 2;
const TX_TYPE_EIP4844: u8 = 3;
const TX_TYPE_EIP7702: u8 = 4;
const RLP_LIST_PREFIX: u8 = 0xc0;
const RLP_LONG_LIST_PREFIX: u8 = 0xf7;
const RLP_STRING_PREFIX: u8 = 0x80;
const RLP_LONG_STRING_PREFIX: u8 = 0xb7;
const LEGACY_PROTECTED_V_BASE: u64 = 35;
const LEGACY_UNPROTECTED_V_BASE: u64 = 27;

const SECP256K1_HALF_ORDER: U256 = U256([
    0x7fffffffffffffff,
    0xffffffffffffffff,
    0x5d576e7357a4501d,
    0xdfe92f46681b20a0,
]);

pub type Address = [u8; 20];
pub type B256 = [u8; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmRawTxAction {
    pub data: Vec<u8>,
}

pub type EvmRawTxPayload = EvmRawTxAction;

impl EvmRawTxAction {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn encoded_len(&self) -> usize {
        self.data.len()
    }

    pub fn decode_transaction(&self) -> Result<SignedEthTx, RawTxDecodeError> {
        decode_raw_transaction(&self.data)
    }

    pub fn validate<C, S>(&self, crypto: &C, state: &mut S) -> Result<ValidatedEvmRawTx, EvmRawTxValidationError>
    where
        C: EvmRawTxCrypto,
        S: EvmRawTxState,
    {
        validate_evm_raw_tx(self, crypto, state)
    }
}

impl Serialize for EvmRawTxAction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // The recovered serializer opens a one-field struct named
        // `EvmRawTxAction`, writes field `data`, emits bytes `0x` first, and then
        // streams the transaction bytes as hex.
        let mut out = String::with_capacity(2 + self.data.len() * 2);
        append_hex_prefixed(&mut out, &self.data);

        let mut state = serializer.serialize_struct(ACTION_STRUCT_NAME, 1)?;
        state.serialize_field(ACTION_FIELD_DATA, &out)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for EvmRawTxAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Data,
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str("`data`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: DeError,
                    {
                        match value {
                            ACTION_FIELD_DATA => Ok(Field::Data),
                            _ => Err(E::unknown_field(value, &[ACTION_FIELD_DATA])),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ActionVisitor;

        impl<'de> Visitor<'de> for ActionVisitor {
            type Value = EvmRawTxAction;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("EvmRawTxAction with field `data`")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut data = None;
                while let Some(field) = map.next_key()? {
                    match field {
                        Field::Data => {
                            if data.is_some() {
                                return Err(A::Error::duplicate_field(ACTION_FIELD_DATA));
                            }
                            let encoded: &str = map.next_value()?;
                            data = Some(decode_hex_prefixed(encoded).map_err(A::Error::custom)?);
                        }
                    }
                }

                Ok(EvmRawTxAction {
                    data: data.ok_or_else(|| A::Error::missing_field(ACTION_FIELD_DATA))?,
                })
            }
        }

        deserializer.deserialize_struct(ACTION_STRUCT_NAME, &[ACTION_FIELD_DATA], ActionVisitor)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignedEthTx {
    Legacy(LegacyTx, Signature),
    Eip2930(Eip2930Tx, Signature),
    Eip1559(Eip1559Tx, Signature),
    Eip4844(Eip4844Tx, Signature),
    Eip7702(Eip7702Tx, Signature),
}

impl SignedEthTx {
    pub fn chain_id(&self) -> Option<u64> {
        match self {
            SignedEthTx::Legacy(tx, _) => tx.chain_id,
            SignedEthTx::Eip2930(tx, _) => Some(tx.chain_id),
            SignedEthTx::Eip1559(tx, _) => Some(tx.chain_id),
            SignedEthTx::Eip4844(tx, _) => Some(tx.chain_id),
            SignedEthTx::Eip7702(tx, _) => Some(tx.chain_id),
        }
    }

    pub fn nonce(&self) -> u64 {
        match self {
            SignedEthTx::Legacy(tx, _) => tx.nonce,
            SignedEthTx::Eip2930(tx, _) => tx.nonce,
            SignedEthTx::Eip1559(tx, _) => tx.nonce,
            SignedEthTx::Eip4844(tx, _) => tx.nonce,
            SignedEthTx::Eip7702(tx, _) => tx.nonce,
        }
    }

    pub fn gas_limit(&self) -> u64 {
        match self {
            SignedEthTx::Legacy(tx, _) => tx.gas_limit,
            SignedEthTx::Eip2930(tx, _) => tx.gas_limit,
            SignedEthTx::Eip1559(tx, _) => tx.gas_limit,
            SignedEthTx::Eip4844(tx, _) => tx.gas_limit,
            SignedEthTx::Eip7702(tx, _) => tx.gas_limit,
        }
    }

    pub fn value(&self) -> U256 {
        match self {
            SignedEthTx::Legacy(tx, _) => tx.value,
            SignedEthTx::Eip2930(tx, _) => tx.value,
            SignedEthTx::Eip1559(tx, _) => tx.value,
            SignedEthTx::Eip4844(tx, _) => tx.value,
            SignedEthTx::Eip7702(tx, _) => tx.value,
        }
    }

    pub fn fee_cap(&self) -> U256 {
        match self {
            SignedEthTx::Legacy(tx, _) => tx.gas_price,
            SignedEthTx::Eip2930(tx, _) => tx.gas_price,
            SignedEthTx::Eip1559(tx, _) => tx.max_fee_per_gas,
            SignedEthTx::Eip4844(tx, _) => tx.max_fee_per_gas,
            SignedEthTx::Eip7702(tx, _) => tx.max_fee_per_gas,
        }
    }

    pub fn priority_fee(&self) -> Option<U256> {
        match self {
            SignedEthTx::Eip1559(tx, _) => Some(tx.max_priority_fee_per_gas),
            SignedEthTx::Eip4844(tx, _) => Some(tx.max_priority_fee_per_gas),
            SignedEthTx::Eip7702(tx, _) => Some(tx.max_priority_fee_per_gas),
            _ => None,
        }
    }

    pub fn input(&self) -> &[u8] {
        match self {
            SignedEthTx::Legacy(tx, _) => &tx.input,
            SignedEthTx::Eip2930(tx, _) => &tx.input,
            SignedEthTx::Eip1559(tx, _) => &tx.input,
            SignedEthTx::Eip4844(tx, _) => &tx.input,
            SignedEthTx::Eip7702(tx, _) => &tx.input,
        }
    }

    pub fn to(&self) -> &TxKind {
        match self {
            SignedEthTx::Legacy(tx, _) => &tx.to,
            SignedEthTx::Eip2930(tx, _) => &tx.to,
            SignedEthTx::Eip1559(tx, _) => &tx.to,
            SignedEthTx::Eip4844(tx, _) => &tx.to,
            SignedEthTx::Eip7702(tx, _) => &tx.to,
        }
    }

    pub fn access_list(&self) -> &[AccessListItem] {
        match self {
            SignedEthTx::Legacy(_, _) => &[],
            SignedEthTx::Eip2930(tx, _) => &tx.access_list,
            SignedEthTx::Eip1559(tx, _) => &tx.access_list,
            SignedEthTx::Eip4844(tx, _) => &tx.access_list,
            SignedEthTx::Eip7702(tx, _) => &tx.access_list,
        }
    }

    pub fn signature(&self) -> &Signature {
        match self {
            SignedEthTx::Legacy(_, sig) => sig,
            SignedEthTx::Eip2930(_, sig) => sig,
            SignedEthTx::Eip1559(_, sig) => sig,
            SignedEthTx::Eip4844(_, sig) => sig,
            SignedEthTx::Eip7702(_, sig) => sig,
        }
    }

    pub fn is_validation_supported(&self) -> bool {
        matches!(self, SignedEthTx::Legacy(..) | SignedEthTx::Eip2930(..) | SignedEthTx::Eip1559(..))
    }

    pub fn raw_signed_encoding(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.append_raw_signed_encoding(&mut out);
        out
    }

    pub fn append_raw_signed_encoding(&self, out: &mut Vec<u8>) {
        match self {
            SignedEthTx::Legacy(tx, sig) => append_legacy_signed(tx, sig, out),
            SignedEthTx::Eip2930(tx, sig) => {
                out.push(TX_TYPE_EIP2930);
                append_eip2930_signed(tx, sig, out);
            }
            SignedEthTx::Eip1559(tx, sig) => {
                out.push(TX_TYPE_EIP1559);
                append_eip1559_signed(tx, sig, out);
            }
            SignedEthTx::Eip4844(tx, sig) => {
                out.push(TX_TYPE_EIP4844);
                append_eip4844_signed(tx, sig, out);
            }
            SignedEthTx::Eip7702(tx, sig) => {
                out.push(TX_TYPE_EIP7702);
                append_eip7702_signed(tx, sig, out);
            }
        }
    }

    pub fn signable_encoding(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.append_signable_encoding(&mut out);
        out
    }

    pub fn append_signable_encoding(&self, out: &mut Vec<u8>) {
        match self {
            SignedEthTx::Legacy(tx, _) => append_legacy_signable(tx, out),
            SignedEthTx::Eip2930(tx, _) => {
                out.push(TX_TYPE_EIP2930);
                append_eip2930_signable(tx, out);
            }
            SignedEthTx::Eip1559(tx, _) => {
                out.push(TX_TYPE_EIP1559);
                append_eip1559_signable(tx, out);
            }
            SignedEthTx::Eip4844(tx, _) => {
                out.push(TX_TYPE_EIP4844);
                append_eip4844_signable(tx, out);
            }
            SignedEthTx::Eip7702(tx, _) => {
                out.push(TX_TYPE_EIP7702);
                append_eip7702_signable(tx, out);
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyTx {
    pub chain_id: Option<u64>,
    pub nonce: u64,
    pub gas_price: U256,
    pub gas_limit: u64,
    pub to: TxKind,
    pub value: U256,
    pub input: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Eip2930Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price: U256,
    pub gas_limit: u64,
    pub to: TxKind,
    pub value: U256,
    pub input: Vec<u8>,
    pub access_list: Vec<AccessListItem>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Eip1559Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: u64,
    pub to: TxKind,
    pub value: U256,
    pub input: Vec<u8>,
    pub access_list: Vec<AccessListItem>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Eip4844Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: u64,
    pub to: TxKind,
    pub value: U256,
    pub input: Vec<u8>,
    pub access_list: Vec<AccessListItem>,
    pub max_fee_per_blob_gas: U256,
    pub blob_versioned_hashes: Vec<B256>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Eip7702Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: u64,
    pub to: TxKind,
    pub value: U256,
    pub input: Vec<u8>,
    pub access_list: Vec<AccessListItem>,
    pub authorization_list: Vec<Authorization>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxKind {
    Create,
    Call(Address),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<B256>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authorization {
    pub chain_id: u64,
    pub address: Address,
    pub nonce: u64,
    pub y_parity: bool,
    pub r: B256,
    pub s: B256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature {
    pub y_parity: bool,
    pub r: B256,
    pub s: B256,
}

impl Signature {
    pub fn is_low_s(self) -> bool {
        let s = U256::from_be_bytes(self.s);
        !s.is_zero() && s <= SECP256K1_HALF_ORDER
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Default)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    pub const ONE: Self = Self([0, 0, 0, 1]);

    pub const fn from_u64(value: u64) -> Self {
        Self([0, 0, 0, value])
    }

    pub fn from_be_slice(bytes: &[u8]) -> Result<Self, RawTxDecodeError> {
        if bytes.len() > 32 {
            return Err(RawTxDecodeError::IntegerTooLarge);
        }

        let mut full = [0u8; 32];
        full[32 - bytes.len()..].copy_from_slice(bytes);
        Ok(Self::from_be_bytes(full))
    }

    pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self([
            u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            u64::from_be_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
            ]),
            u64::from_be_bytes([
                bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
            ]),
            u64::from_be_bytes([
                bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
            ]),
        ])
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    pub fn as_u64(self) -> Result<u64, RawTxDecodeError> {
        if self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 {
            Ok(self.0[3])
        } else {
            Err(RawTxDecodeError::IntegerTooLarge)
        }
    }

    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        let (d, carry0) = self.0[3].overflowing_add(rhs.0[3]);
        let (c0, carry1a) = self.0[2].overflowing_add(rhs.0[2]);
        let (c, carry1b) = c0.overflowing_add(carry0 as u64);
        let (b0, carry2a) = self.0[1].overflowing_add(rhs.0[1]);
        let (b, carry2b) = b0.overflowing_add((carry1a | carry1b) as u64);
        let (a0, carry3a) = self.0[0].overflowing_add(rhs.0[0]);
        let (a, carry3b) = a0.overflowing_add((carry2a | carry2b) as u64);
        if carry3a | carry3b {
            None
        } else {
            Some(Self([a, b, c, d]))
        }
    }

    pub fn checked_mul_u64(self, rhs: u64) -> Option<Self> {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        let rhs = u128::from(rhs);
        for idx in (0..4).rev() {
            let wide = u128::from(self.0[idx]) * rhs + carry;
            out[idx] = wide as u64;
            carry = wide >> 64;
        }
        if carry == 0 {
            Some(Self(out))
        } else {
            None
        }
    }

    pub fn to_minimal_be_vec(self) -> Vec<u8> {
        if self.is_zero() {
            return Vec::new();
        }

        let mut full = [0u8; 32];
        for (idx, limb) in self.0.iter().enumerate() {
            full[idx * 8..idx * 8 + 8].copy_from_slice(&limb.to_be_bytes());
        }
        let first = full.iter().position(|byte| *byte != 0).unwrap_or(32);
        full[first..].to_vec()
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for limb in self.0 {
            write!(f, "{limb:016x}")?;
        }
        Ok(())
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
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
pub enum EvmRawTxValidationError {
    EvmDisabled,
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
    Execution(EvmExecutionError),
}

impl From<RawTxDecodeError> for EvmRawTxValidationError {
    fn from(error: RawTxDecodeError) -> Self {
        Self::Decode(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvmExecutionError {
    Rejected { code: u8 },
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedEvmRawTx {
    pub tx: SignedEthTx,
    pub sender: Address,
    pub tx_hash: B256,
    pub signable_hash: B256,
    pub intrinsic_gas: u64,
    pub upfront_cost: U256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvmAccountView {
    pub nonce: u64,
    pub balance: U256,
    pub big_block_gas_limit: bool,
}

pub trait EvmRawTxCrypto {
    fn keccak256(&self, bytes: &[u8]) -> B256;
    fn recover_address(&self, signable_hash: B256, signature: &Signature) -> Option<Address>;
}

pub trait EvmRawTxState {
    fn evm_enabled(&self) -> bool;
    fn chain_id(&self) -> u64;
    fn account(&self, address: &Address) -> EvmAccountView;
    fn execute_evm_raw_tx(&mut self, validated: &ValidatedEvmRawTx) -> Result<(), EvmExecutionError>;
}

pub fn validate_evm_raw_tx<C, S>(
    action: &EvmRawTxAction,
    crypto: &C,
    state: &mut S,
) -> Result<ValidatedEvmRawTx, EvmRawTxValidationError>
where
    C: EvmRawTxCrypto,
    S: EvmRawTxState,
{
    if !state.evm_enabled() {
        return Err(EvmRawTxValidationError::EvmDisabled);
    }

    if action.data.len() > MAX_RAW_TX_BYTES {
        return Err(EvmRawTxValidationError::RawTransactionTooLarge {
            len: action.data.len(),
            max: MAX_RAW_TX_BYTES,
        });
    }

    let tx = decode_raw_transaction(&action.data)?;
    if !tx.is_validation_supported() {
        return Err(EvmRawTxValidationError::UnsupportedForBlockExecution);
    }

    let signable = tx.signable_encoding();
    let signable_hash = crypto.keccak256(&signable);
    let signature = *tx.signature();
    if !signature.is_low_s() {
        return Err(EvmRawTxValidationError::InvalidSignature);
    }

    let sender = crypto
        .recover_address(signable_hash, &signature)
        .ok_or(EvmRawTxValidationError::InvalidSignature)?;

    if let Some(actual) = tx.chain_id() {
        let expected = state.chain_id();
        if actual != expected {
            return Err(EvmRawTxValidationError::WrongChainId { expected, actual });
        }
    }

    let input = tx.input();
    if input.len() > MAX_CALLDATA_BYTES {
        return Err(EvmRawTxValidationError::CallDataTooLarge {
            len: input.len(),
            max: MAX_CALLDATA_BYTES,
        });
    }
    if input.len() >= LARGE_CALLDATA_EMPTY_PREFIX_THRESHOLD && input.first() == Some(&0) {
        return Err(EvmRawTxValidationError::LargeCallDataStartsWithZero { len: input.len() });
    }

    let account = state.account(&sender);
    let max_gas = if account.big_block_gas_limit {
        BIG_BLOCK_ACCOUNT_GAS_LIMIT
    } else {
        NORMAL_ACCOUNT_GAS_LIMIT
    };
    let gas_limit = tx.gas_limit();
    if gas_limit > max_gas {
        return Err(EvmRawTxValidationError::GasLimitTooHigh { gas_limit, max: max_gas });
    }

    let fee_cap = tx.fee_cap();
    if fee_cap < MIN_FEE_CAP_WEI {
        return Err(EvmRawTxValidationError::FeeCapTooLow {
            fee_cap,
            min: MIN_FEE_CAP_WEI,
        });
    }
    if let Some(priority_fee) = tx.priority_fee() {
        if priority_fee > fee_cap {
            return Err(EvmRawTxValidationError::PriorityFeeAboveFeeCap { priority_fee, fee_cap });
        }
    }

    let intrinsic_gas = intrinsic_gas(&tx).ok_or(EvmRawTxValidationError::IntrinsicGasTooHigh {
        intrinsic: u64::MAX,
        gas_limit,
    })?;
    if gas_limit < intrinsic_gas {
        return Err(EvmRawTxValidationError::IntrinsicGasTooHigh { intrinsic: intrinsic_gas, gas_limit });
    }

    let tx_nonce = tx.nonce();
    if tx_nonce < account.nonce {
        return Err(EvmRawTxValidationError::NonceTooLow {
            account_nonce: account.nonce,
            tx_nonce,
        });
    }
    let max_nonce = account.nonce.saturating_add(NONCE_LOOKAHEAD);
    if tx_nonce >= max_nonce {
        return Err(EvmRawTxValidationError::NonceTooHigh {
            account_nonce: account.nonce,
            tx_nonce,
            lookahead: NONCE_LOOKAHEAD,
        });
    }

    let gas_cost = fee_cap
        .checked_mul_u64(gas_limit)
        .ok_or(EvmRawTxValidationError::BalanceTooLow {
            balance: account.balance,
            required: U256([u64::MAX; 4]),
        })?;
    let upfront_cost = gas_cost
        .checked_add(tx.value())
        .ok_or(EvmRawTxValidationError::BalanceTooLow {
            balance: account.balance,
            required: U256([u64::MAX; 4]),
        })?;
    if account.balance < upfront_cost {
        return Err(EvmRawTxValidationError::BalanceTooLow {
            balance: account.balance,
            required: upfront_cost,
        });
    }

    let validated = ValidatedEvmRawTx {
        tx,
        sender,
        tx_hash: crypto.keccak256(&action.data),
        signable_hash,
        intrinsic_gas,
        upfront_cost,
    };
    state.execute_evm_raw_tx(&validated)?;
    Ok(validated)
}

pub fn decode_raw_transaction(raw: &[u8]) -> Result<SignedEthTx, RawTxDecodeError> {
    let (&first, rest) = raw.split_first().ok_or(RawTxDecodeError::Empty)?;
    if first >= 0x80 {
        decode_legacy(raw)
    } else {
        match first {
            TX_TYPE_EIP2930 => decode_eip2930(rest),
            TX_TYPE_EIP1559 => decode_eip1559(rest),
            TX_TYPE_EIP4844 => decode_eip4844(rest),
            TX_TYPE_EIP7702 => decode_eip7702(rest),
            other => Err(RawTxDecodeError::UnsupportedTypedTransaction(other)),
        }
    }
}

fn decode_legacy(raw: &[u8]) -> Result<SignedEthTx, RawTxDecodeError> {
    let items = read_exact_list(raw)?;
    require_field_count(&items, 9)?;

    let nonce = rlp_u64(items[0])?;
    let gas_price = rlp_u256(items[1])?;
    let gas_limit = rlp_u64(items[2])?;
    let to = rlp_tx_kind(items[3])?;
    let value = rlp_u256(items[4])?;
    let input = items[5].to_vec();
    let v = rlp_u256(items[6])?;
    let (chain_id, y_parity) = legacy_v(v)?;
    let signature = Signature {
        y_parity,
        r: rlp_b256(items[7])?,
        s: rlp_b256(items[8])?,
    };

    Ok(SignedEthTx::Legacy(
        LegacyTx {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            input,
        },
        signature,
    ))
}

fn decode_eip2930(raw: &[u8]) -> Result<SignedEthTx, RawTxDecodeError> {
    let items = read_exact_list(raw)?;
    require_field_count(&items, 11)?;
    Ok(SignedEthTx::Eip2930(
        Eip2930Tx {
            chain_id: rlp_u64(items[0])?,
            nonce: rlp_u64(items[1])?,
            gas_price: rlp_u256(items[2])?,
            gas_limit: rlp_u64(items[3])?,
            to: rlp_tx_kind(items[4])?,
            value: rlp_u256(items[5])?,
            input: items[6].to_vec(),
            access_list: decode_access_list(items[7])?,
        },
        Signature {
            y_parity: rlp_y_parity(items[8])?,
            r: rlp_b256(items[9])?,
            s: rlp_b256(items[10])?,
        },
    ))
}

fn decode_eip1559(raw: &[u8]) -> Result<SignedEthTx, RawTxDecodeError> {
    let items = read_exact_list(raw)?;
    require_field_count(&items, 12)?;
    Ok(SignedEthTx::Eip1559(
        Eip1559Tx {
            chain_id: rlp_u64(items[0])?,
            nonce: rlp_u64(items[1])?,
            max_priority_fee_per_gas: rlp_u256(items[2])?,
            max_fee_per_gas: rlp_u256(items[3])?,
            gas_limit: rlp_u64(items[4])?,
            to: rlp_tx_kind(items[5])?,
            value: rlp_u256(items[6])?,
            input: items[7].to_vec(),
            access_list: decode_access_list(items[8])?,
        },
        Signature {
            y_parity: rlp_y_parity(items[9])?,
            r: rlp_b256(items[10])?,
            s: rlp_b256(items[11])?,
        },
    ))
}

fn decode_eip4844(raw: &[u8]) -> Result<SignedEthTx, RawTxDecodeError> {
    let items = read_exact_list(raw)?;
    require_field_count(&items, 14)?;
    Ok(SignedEthTx::Eip4844(
        Eip4844Tx {
            chain_id: rlp_u64(items[0])?,
            nonce: rlp_u64(items[1])?,
            max_priority_fee_per_gas: rlp_u256(items[2])?,
            max_fee_per_gas: rlp_u256(items[3])?,
            gas_limit: rlp_u64(items[4])?,
            to: rlp_tx_kind(items[5])?,
            value: rlp_u256(items[6])?,
            input: items[7].to_vec(),
            access_list: decode_access_list(items[8])?,
            max_fee_per_blob_gas: rlp_u256(items[9])?,
            blob_versioned_hashes: decode_b256_list(items[10])?,
        },
        Signature {
            y_parity: rlp_y_parity(items[11])?,
            r: rlp_b256(items[12])?,
            s: rlp_b256(items[13])?,
        },
    ))
}

fn decode_eip7702(raw: &[u8]) -> Result<SignedEthTx, RawTxDecodeError> {
    let items = read_exact_list(raw)?;
    require_field_count(&items, 13)?;
    Ok(SignedEthTx::Eip7702(
        Eip7702Tx {
            chain_id: rlp_u64(items[0])?,
            nonce: rlp_u64(items[1])?,
            max_priority_fee_per_gas: rlp_u256(items[2])?,
            max_fee_per_gas: rlp_u256(items[3])?,
            gas_limit: rlp_u64(items[4])?,
            to: rlp_tx_kind(items[5])?,
            value: rlp_u256(items[6])?,
            input: items[7].to_vec(),
            access_list: decode_access_list(items[8])?,
            authorization_list: decode_authorization_list(items[9])?,
        },
        Signature {
            y_parity: rlp_y_parity(items[10])?,
            r: rlp_b256(items[11])?,
            s: rlp_b256(items[12])?,
        },
    ))
}

fn legacy_v(v: U256) -> Result<(Option<u64>, bool), RawTxDecodeError> {
    let v64 = v.as_u64().map_err(|_| RawTxDecodeError::InvalidLegacyV(v))?;
    match v64 {
        27 => Ok((None, false)),
        28 => Ok((None, true)),
        v if v >= LEGACY_PROTECTED_V_BASE => {
            let adjusted = v - LEGACY_PROTECTED_V_BASE;
            Ok((Some(adjusted / 2), adjusted & 1 == 1))
        }
        _ => Err(RawTxDecodeError::InvalidLegacyV(v)),
    }
}

fn rlp_y_parity(bytes: &[u8]) -> Result<bool, RawTxDecodeError> {
    match rlp_u256(bytes)? {
        U256::ZERO => Ok(false),
        U256::ONE => Ok(true),
        value => Err(RawTxDecodeError::InvalidYParity(value)),
    }
}

fn rlp_u64(bytes: &[u8]) -> Result<u64, RawTxDecodeError> {
    rlp_u256(bytes)?.as_u64()
}

fn rlp_u256(bytes: &[u8]) -> Result<U256, RawTxDecodeError> {
    if bytes.len() > 1 && bytes[0] == 0 {
        return Err(RawTxDecodeError::RlpNonCanonical);
    }
    U256::from_be_slice(bytes)
}

fn rlp_tx_kind(bytes: &[u8]) -> Result<TxKind, RawTxDecodeError> {
    match bytes.len() {
        0 => Ok(TxKind::Create),
        20 => {
            let mut address = [0u8; 20];
            address.copy_from_slice(bytes);
            Ok(TxKind::Call(address))
        }
        len => Err(RawTxDecodeError::InvalidAddressLength(len)),
    }
}

fn rlp_b256(bytes: &[u8]) -> Result<B256, RawTxDecodeError> {
    if bytes.len() > 32 {
        return Err(RawTxDecodeError::InvalidHashLength(bytes.len()));
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

fn decode_b256_list(bytes: &[u8]) -> Result<Vec<B256>, RawTxDecodeError> {
    read_exact_list(bytes)?
        .into_iter()
        .map(|item| {
            if item.len() != 32 {
                Err(RawTxDecodeError::InvalidHashLength(item.len()))
            } else {
                let mut out = [0u8; 32];
                out.copy_from_slice(item);
                Ok(out)
            }
        })
        .collect()
}

fn decode_access_list(bytes: &[u8]) -> Result<Vec<AccessListItem>, RawTxDecodeError> {
    let entries = read_exact_list(bytes)?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let fields = read_exact_list(entry)?;
        require_field_count(&fields, 2)?;
        let address = match fields[0].len() {
            20 => {
                let mut address = [0u8; 20];
                address.copy_from_slice(fields[0]);
                address
            }
            len => return Err(RawTxDecodeError::InvalidAddressLength(len)),
        };
        out.push(AccessListItem {
            address,
            storage_keys: decode_b256_list(fields[1])?,
        });
    }
    Ok(out)
}

fn decode_authorization_list(bytes: &[u8]) -> Result<Vec<Authorization>, RawTxDecodeError> {
    let entries = read_exact_list(bytes)?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let fields = read_exact_list(entry)?;
        require_field_count(&fields, 6)?;
        let address = match fields[1].len() {
            20 => {
                let mut address = [0u8; 20];
                address.copy_from_slice(fields[1]);
                address
            }
            len => return Err(RawTxDecodeError::InvalidAddressLength(len)),
        };
        out.push(Authorization {
            chain_id: rlp_u64(fields[0])?,
            address,
            nonce: rlp_u64(fields[2])?,
            y_parity: rlp_y_parity(fields[3])?,
            r: rlp_b256(fields[4])?,
            s: rlp_b256(fields[5])?,
        });
    }
    Ok(out)
}

fn require_field_count(fields: &[&[u8]], expected: usize) -> Result<(), RawTxDecodeError> {
    if fields.len() == expected {
        Ok(())
    } else {
        Err(RawTxDecodeError::RlpWrongFieldCount {
            expected,
            actual: fields.len(),
        })
    }
}

fn read_exact_list(bytes: &[u8]) -> Result<Vec<&[u8]>, RawTxDecodeError> {
    let (payload, rest) = rlp_read_list(bytes)?;
    if !rest.is_empty() {
        return Err(RawTxDecodeError::RlpTrailingBytes);
    }

    let mut cursor = payload;
    let mut out = Vec::new();
    while !cursor.is_empty() {
        let (item, rest) = rlp_read_item(cursor)?;
        out.push(item);
        cursor = rest;
    }
    Ok(out)
}

fn rlp_read_list(bytes: &[u8]) -> Result<(&[u8], &[u8]), RawTxDecodeError> {
    let (&tag, rest) = bytes.split_first().ok_or(RawTxDecodeError::RlpInputTooShort)?;
    if tag < RLP_LIST_PREFIX {
        return Err(RawTxDecodeError::RlpExpectedList);
    }
    if tag <= RLP_LONG_LIST_PREFIX {
        let len = usize::from(tag - RLP_LIST_PREFIX);
        split_payload(rest, len)
    } else {
        let len_of_len = usize::from(tag - RLP_LONG_LIST_PREFIX);
        let (len_bytes, rest) = split_payload(rest, len_of_len)?;
        let len = decode_rlp_len(len_bytes)?;
        split_payload(rest, len)
    }
}

fn rlp_read_item(bytes: &[u8]) -> Result<(&[u8], &[u8]), RawTxDecodeError> {
    let (&tag, rest) = bytes.split_first().ok_or(RawTxDecodeError::RlpInputTooShort)?;
    if tag < RLP_STRING_PREFIX {
        return Ok((&bytes[..1], rest));
    }
    if tag < RLP_LIST_PREFIX {
        if tag <= RLP_LONG_STRING_PREFIX {
            let len = usize::from(tag - RLP_STRING_PREFIX);
            split_payload(rest, len)
        } else {
            let len_of_len = usize::from(tag - RLP_LONG_STRING_PREFIX);
            let (len_bytes, rest) = split_payload(rest, len_of_len)?;
            let len = decode_rlp_len(len_bytes)?;
            split_payload(rest, len)
        }
    } else {
        let (_, rest) = rlp_read_list(bytes)?;
        let consumed = bytes.len() - rest.len();
        Ok((&bytes[..consumed], rest))
    }
}

fn split_payload(bytes: &[u8], len: usize) -> Result<(&[u8], &[u8]), RawTxDecodeError> {
    if bytes.len() < len {
        return Err(RawTxDecodeError::RlpInputTooShort);
    }
    Ok(bytes.split_at(len))
}

fn decode_rlp_len(bytes: &[u8]) -> Result<usize, RawTxDecodeError> {
    if bytes.is_empty() || bytes[0] == 0 || bytes.len() > core::mem::size_of::<usize>() {
        return Err(RawTxDecodeError::RlpNonCanonical);
    }
    let mut len = 0usize;
    for byte in bytes {
        len = (len << 8) | usize::from(*byte);
    }
    Ok(len)
}

fn intrinsic_gas(tx: &SignedEthTx) -> Option<u64> {
    let mut gas = match tx.to() {
        TxKind::Create => 53_000u64,
        TxKind::Call(_) => 21_000u64,
    };
    for byte in tx.input() {
        gas = gas.checked_add(if *byte == 0 { 4 } else { 16 })?;
    }
    for item in tx.access_list() {
        gas = gas.checked_add(2_400)?;
        gas = gas.checked_add(1_900u64.checked_mul(item.storage_keys.len() as u64)?)?;
    }
    Some(gas)
}

fn append_legacy_signable(tx: &LegacyTx, out: &mut Vec<u8>) {
    let mut fields = Vec::with_capacity(if tx.chain_id.is_some() { 9 } else { 6 });
    fields.push(rlp_integer_bytes(U256::from_u64(tx.nonce)));
    fields.push(rlp_integer_bytes(tx.gas_price));
    fields.push(rlp_integer_bytes(U256::from_u64(tx.gas_limit)));
    fields.push(tx_kind_bytes(&tx.to));
    fields.push(rlp_integer_bytes(tx.value));
    fields.push(tx.input.clone());
    if let Some(chain_id) = tx.chain_id {
        fields.push(rlp_integer_bytes(U256::from_u64(chain_id)));
        fields.push(Vec::new());
        fields.push(Vec::new());
    }
    append_rlp_list_from_bytes(&fields, out);
}

fn append_legacy_signed(tx: &LegacyTx, sig: &Signature, out: &mut Vec<u8>) {
    let v = match tx.chain_id {
        Some(chain_id) => LEGACY_PROTECTED_V_BASE + chain_id.saturating_mul(2) + u64::from(sig.y_parity),
        None => LEGACY_UNPROTECTED_V_BASE + u64::from(sig.y_parity),
    };
    let fields = vec![
        rlp_integer_bytes(U256::from_u64(tx.nonce)),
        rlp_integer_bytes(tx.gas_price),
        rlp_integer_bytes(U256::from_u64(tx.gas_limit)),
        tx_kind_bytes(&tx.to),
        rlp_integer_bytes(tx.value),
        tx.input.clone(),
        rlp_integer_bytes(U256::from_u64(v)),
        b256_integer_bytes(sig.r),
        b256_integer_bytes(sig.s),
    ];
    append_rlp_list_from_bytes(&fields, out);
}

fn append_eip2930_signable(tx: &Eip2930Tx, out: &mut Vec<u8>) {
    append_eip2930_fields(tx, None, out);
}

fn append_eip2930_signed(tx: &Eip2930Tx, sig: &Signature, out: &mut Vec<u8>) {
    append_eip2930_fields(tx, Some(sig), out);
}

fn append_eip2930_fields(tx: &Eip2930Tx, sig: Option<&Signature>, out: &mut Vec<u8>) {
    let mut fields = vec![
        rlp_integer_bytes(U256::from_u64(tx.chain_id)),
        rlp_integer_bytes(U256::from_u64(tx.nonce)),
        rlp_integer_bytes(tx.gas_price),
        rlp_integer_bytes(U256::from_u64(tx.gas_limit)),
        tx_kind_bytes(&tx.to),
        rlp_integer_bytes(tx.value),
        tx.input.clone(),
        access_list_bytes(&tx.access_list),
    ];
    if let Some(sig) = sig {
        push_signature_fields(&mut fields, sig);
    }
    append_rlp_list_from_bytes(&fields, out);
}

fn append_eip1559_signable(tx: &Eip1559Tx, out: &mut Vec<u8>) {
    append_eip1559_fields(tx, None, out);
}

fn append_eip1559_signed(tx: &Eip1559Tx, sig: &Signature, out: &mut Vec<u8>) {
    append_eip1559_fields(tx, Some(sig), out);
}

fn append_eip1559_fields(tx: &Eip1559Tx, sig: Option<&Signature>, out: &mut Vec<u8>) {
    let mut fields = vec![
        rlp_integer_bytes(U256::from_u64(tx.chain_id)),
        rlp_integer_bytes(U256::from_u64(tx.nonce)),
        rlp_integer_bytes(tx.max_priority_fee_per_gas),
        rlp_integer_bytes(tx.max_fee_per_gas),
        rlp_integer_bytes(U256::from_u64(tx.gas_limit)),
        tx_kind_bytes(&tx.to),
        rlp_integer_bytes(tx.value),
        tx.input.clone(),
        access_list_bytes(&tx.access_list),
    ];
    if let Some(sig) = sig {
        push_signature_fields(&mut fields, sig);
    }
    append_rlp_list_from_bytes(&fields, out);
}

fn append_eip4844_signable(tx: &Eip4844Tx, out: &mut Vec<u8>) {
    append_eip4844_fields(tx, None, out);
}

fn append_eip4844_signed(tx: &Eip4844Tx, sig: &Signature, out: &mut Vec<u8>) {
    append_eip4844_fields(tx, Some(sig), out);
}

fn append_eip4844_fields(tx: &Eip4844Tx, sig: Option<&Signature>, out: &mut Vec<u8>) {
    let mut fields = vec![
        rlp_integer_bytes(U256::from_u64(tx.chain_id)),
        rlp_integer_bytes(U256::from_u64(tx.nonce)),
        rlp_integer_bytes(tx.max_priority_fee_per_gas),
        rlp_integer_bytes(tx.max_fee_per_gas),
        rlp_integer_bytes(U256::from_u64(tx.gas_limit)),
        tx_kind_bytes(&tx.to),
        rlp_integer_bytes(tx.value),
        tx.input.clone(),
        access_list_bytes(&tx.access_list),
        rlp_integer_bytes(tx.max_fee_per_blob_gas),
        b256_list_bytes(&tx.blob_versioned_hashes),
    ];
    if let Some(sig) = sig {
        push_signature_fields(&mut fields, sig);
    }
    append_rlp_list_from_bytes(&fields, out);
}

fn append_eip7702_signable(tx: &Eip7702Tx, out: &mut Vec<u8>) {
    append_eip7702_fields(tx, None, out);
}

fn append_eip7702_signed(tx: &Eip7702Tx, sig: &Signature, out: &mut Vec<u8>) {
    append_eip7702_fields(tx, Some(sig), out);
}

fn append_eip7702_fields(tx: &Eip7702Tx, sig: Option<&Signature>, out: &mut Vec<u8>) {
    let mut fields = vec![
        rlp_integer_bytes(U256::from_u64(tx.chain_id)),
        rlp_integer_bytes(U256::from_u64(tx.nonce)),
        rlp_integer_bytes(tx.max_priority_fee_per_gas),
        rlp_integer_bytes(tx.max_fee_per_gas),
        rlp_integer_bytes(U256::from_u64(tx.gas_limit)),
        tx_kind_bytes(&tx.to),
        rlp_integer_bytes(tx.value),
        tx.input.clone(),
        access_list_bytes(&tx.access_list),
        authorization_list_bytes(&tx.authorization_list),
    ];
    if let Some(sig) = sig {
        push_signature_fields(&mut fields, sig);
    }
    append_rlp_list_from_bytes(&fields, out);
}

fn push_signature_fields(fields: &mut Vec<Vec<u8>>, sig: &Signature) {
    fields.push(rlp_integer_bytes(U256::from_u64(u64::from(sig.y_parity))));
    fields.push(b256_integer_bytes(sig.r));
    fields.push(b256_integer_bytes(sig.s));
}

fn tx_kind_bytes(kind: &TxKind) -> Vec<u8> {
    match kind {
        TxKind::Create => Vec::new(),
        TxKind::Call(address) => address.to_vec(),
    }
}

fn b256_integer_bytes(value: B256) -> Vec<u8> {
    let first = value.iter().position(|byte| *byte != 0).unwrap_or(32);
    value[first..].to_vec()
}

fn rlp_integer_bytes(value: U256) -> Vec<u8> {
    value.to_minimal_be_vec()
}

fn access_list_bytes(list: &[AccessListItem]) -> Vec<u8> {
    let mut entries = Vec::with_capacity(list.len());
    for item in list {
        entries.push(vec![item.address.to_vec(), b256_list_bytes(&item.storage_keys)]);
    }
    nested_rlp_list(entries)
}

fn authorization_list_bytes(list: &[Authorization]) -> Vec<u8> {
    let mut entries = Vec::with_capacity(list.len());
    for item in list {
        entries.push(vec![
            rlp_integer_bytes(U256::from_u64(item.chain_id)),
            item.address.to_vec(),
            rlp_integer_bytes(U256::from_u64(item.nonce)),
            rlp_integer_bytes(U256::from_u64(u64::from(item.y_parity))),
            b256_integer_bytes(item.r),
            b256_integer_bytes(item.s),
        ]);
    }
    nested_rlp_list(entries)
}

fn b256_list_bytes(list: &[B256]) -> Vec<u8> {
    let fields: Vec<Vec<u8>> = list.iter().map(|item| item.to_vec()).collect();
    let mut out = Vec::new();
    append_rlp_list_from_bytes(&fields, &mut out);
    out
}

fn nested_rlp_list(entries: Vec<Vec<Vec<u8>>>) -> Vec<u8> {
    let mut encoded_entries = Vec::with_capacity(entries.len());
    for fields in entries {
        let mut entry = Vec::new();
        append_rlp_list_from_bytes(&fields, &mut entry);
        encoded_entries.push(entry);
    }
    let mut out = Vec::new();
    append_rlp_list_from_encoded_items(&encoded_entries, &mut out);
    out
}

fn append_rlp_list_from_bytes(fields: &[Vec<u8>], out: &mut Vec<u8>) {
    let mut payload = Vec::new();
    for field in fields {
        append_rlp_bytes(field, &mut payload);
    }
    append_rlp_list_payload(&payload, out);
}

fn append_rlp_list_from_encoded_items(items: &[Vec<u8>], out: &mut Vec<u8>) {
    let payload_len = items.iter().map(Vec::len).sum();
    append_rlp_header(RLP_LIST_PREFIX, payload_len, out);
    for item in items {
        out.extend_from_slice(item);
    }
}

fn append_rlp_list_payload(payload: &[u8], out: &mut Vec<u8>) {
    append_rlp_header(RLP_LIST_PREFIX, payload.len(), out);
    out.extend_from_slice(payload);
}

fn append_rlp_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    if bytes.len() == 1 && bytes[0] < RLP_STRING_PREFIX {
        out.push(bytes[0]);
    } else {
        append_rlp_header(RLP_STRING_PREFIX, bytes.len(), out);
        out.extend_from_slice(bytes);
    }
}

fn append_rlp_header(base: u8, len: usize, out: &mut Vec<u8>) {
    if len < 56 {
        out.push(base + len as u8);
    } else {
        let be = len.to_be_bytes();
        let first = be.iter().position(|byte| *byte != 0).unwrap_or(be.len() - 1);
        let len_bytes = &be[first..];
        out.push(base + 55 + len_bytes.len() as u8);
        out.extend_from_slice(len_bytes);
    }
}

fn append_hex_prefixed(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("0x");
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
}

fn decode_hex_prefixed(value: &str) -> Result<Vec<u8>, HexDecodeError> {
    let hex = value.strip_prefix("0x").ok_or(HexDecodeError::MissingPrefix)?;
    if hex.len() % 2 != 0 {
        return Err(HexDecodeError::OddLength);
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        out.push((hex_nibble(bytes[idx])? << 4) | hex_nibble(bytes[idx + 1])?);
        idx += 2;
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HexDecodeError {
    MissingPrefix,
    OddLength,
    InvalidHex,
}

impl fmt::Display for HexDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HexDecodeError::MissingPrefix => f.write_str("raw EVM transaction data must start with 0x"),
            HexDecodeError::OddLength => f.write_str("raw EVM transaction hex has odd length"),
            HexDecodeError::InvalidHex => f.write_str("raw EVM transaction data contains non-hex characters"),
        }
    }
}

impl std::error::Error for HexDecodeError {}

fn hex_nibble(byte: u8) -> Result<u8, HexDecodeError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(HexDecodeError::InvalidHex),
    }
}
