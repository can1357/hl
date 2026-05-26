use core::cmp;

/// 256-bit hash-like values copied as four little-endian machine words in the
/// optimized binary.
pub type B256 = [u8; 32];

/// Recovered Ethereum address. The builder copies this as 16 bytes plus the
/// remaining 4 bytes after it has built the transaction envelope.
pub type Address = [u8; 20];

/// Gas-price values used by the reconstructed builder. The binary performs the
/// arithmetic as a two-limb integer and only the low 128 bits are live at the
/// observed call sites.
pub type GasPrice = u128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature {
    pub r: B256,
    pub s: B256,
    pub y_parity: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyTx {
    pub nonce: u64,
    pub gas_price: GasPrice,
    pub gas_limit: u64,
    pub to: TxKind,
    pub value: GasPrice,
    pub input: Vec<u8>,
    pub chain_id: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Eip2930Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price: GasPrice,
    pub gas_limit: u64,
    pub to: TxKind,
    pub value: GasPrice,
    pub input: Vec<u8>,
    pub access_list: Vec<AccessListItem>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Eip1559Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_fee_per_gas: GasPrice,
    pub max_priority_fee_per_gas: GasPrice,
    pub gas_limit: u64,
    pub to: TxKind,
    pub value: GasPrice,
    pub input: Vec<u8>,
    pub access_list: Vec<AccessListItem>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Eip4844Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_fee_per_gas: GasPrice,
    pub max_priority_fee_per_gas: GasPrice,
    pub gas_limit: u64,
    pub to: TxKind,
    pub value: GasPrice,
    pub input: Vec<u8>,
    pub access_list: Vec<AccessListItem>,
    pub blob_versioned_hashes: Vec<B256>,
    pub max_fee_per_blob_gas: GasPrice,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Eip7702Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_fee_per_gas: GasPrice,
    pub max_priority_fee_per_gas: GasPrice,
    pub gas_limit: u64,
    pub to: TxKind,
    pub value: GasPrice,
    pub input: Vec<u8>,
    pub access_list: Vec<AccessListItem>,
    pub authorization_list: Vec<Authorization>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignedTransaction {
    Legacy(LegacyTx, Signature),
    Eip2930(Eip2930Tx, Signature),
    Eip1559(Eip1559Tx, Signature),
    Eip4844(Eip4844Tx, Signature),
    Eip7702(Eip7702Tx, Signature),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcTransactionEnvelope {
    Legacy(RpcTx<LegacyTx>),
    Eip2930(RpcTx<Eip2930Tx>),
    Eip1559(RpcTx<Eip1559Tx>),
    Eip4844(RpcTx<Eip4844Tx>),
    Eip7702(RpcTx<Eip7702Tx>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcTx<T> {
    pub hash: B256,
    pub transaction: T,
    pub signature: Signature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredTransaction {
    pub transaction: SignedTransaction,
    pub hash: B256,
    pub signer: Address,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionResponseContext {
    pub base_fee_per_gas: Option<GasPrice>,
    pub block_hash: Option<B256>,
    pub block_number: Option<u64>,
    pub transaction_index: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionResponse {
    pub effective_gas_price: Option<GasPrice>,
    pub transaction: RpcTransactionEnvelope,
    pub block_hash: Option<B256>,
    pub block_number: Option<u64>,
    pub transaction_index: Option<u64>,
    pub from: Address,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

/// Build the transaction object returned by Ethereum RPC methods.
///
/// The recovered monomorph at `0x1606580` first forces the transaction hash lazy
/// cell, copies one of five transaction variants, inserts the common hash and
/// signature into the variant-specific payload, then writes the recovered signer
/// and block-position fields into the response. The variant discriminants in
/// the binary are `0..=4` in the order used by `SignedTransaction` above.
pub fn build_transaction_response(
    recovered: &RecoveredTransaction,
    context: TransactionResponseContext,
) -> TransactionResponse {
    let transaction = rpc_transaction_envelope(recovered);
    let effective_gas_price = effective_gas_price_for_response(&transaction, context.base_fee_per_gas);

    TransactionResponse {
        effective_gas_price: Some(effective_gas_price),
        transaction,
        block_hash: context.block_hash,
        block_number: context.block_number,
        transaction_index: context.transaction_index,
        from: recovered.signer,
    }
}

#[inline]
pub fn rpc_transaction_envelope(recovered: &RecoveredTransaction) -> RpcTransactionEnvelope {
    match &recovered.transaction {
        SignedTransaction::Legacy(tx, signature) => RpcTransactionEnvelope::Legacy(RpcTx {
            hash: recovered.hash,
            transaction: tx.clone(),
            signature: *signature,
        }),
        SignedTransaction::Eip2930(tx, signature) => RpcTransactionEnvelope::Eip2930(RpcTx {
            hash: recovered.hash,
            transaction: tx.clone(),
            signature: *signature,
        }),
        SignedTransaction::Eip1559(tx, signature) => RpcTransactionEnvelope::Eip1559(RpcTx {
            hash: recovered.hash,
            transaction: tx.clone(),
            signature: *signature,
        }),
        SignedTransaction::Eip4844(tx, signature) => RpcTransactionEnvelope::Eip4844(RpcTx {
            hash: recovered.hash,
            transaction: tx.clone(),
            signature: *signature,
        }),
        SignedTransaction::Eip7702(tx, signature) => RpcTransactionEnvelope::Eip7702(RpcTx {
            hash: recovered.hash,
            transaction: tx.clone(),
            signature: *signature,
        }),
    }
}

/// Compute the `effective_gas_price` field exactly as recovered from the RPC
/// response builder.
///
/// With no block base fee, the function returns the transaction gas price or
/// max-fee field directly. With a base fee, it starts at the base fee and only
/// adds a positive delta when `max_fee_per_gas >= base_fee_per_gas`. Dynamic-fee
/// transactions cap that delta by `max_priority_fee_per_gas`; legacy and
/// EIP-2930 transactions use the full `gas_price - base_fee_per_gas` delta. The
/// final addition is checked; the recovered binary branches to the Rust overflow
/// panic for this file when the two-limb add carries.
#[inline]
pub fn effective_gas_price_for_response(
    transaction: &RpcTransactionEnvelope,
    base_fee_per_gas: Option<GasPrice>,
) -> GasPrice {
    let max_fee_per_gas = transaction.max_fee_or_gas_price();

    match base_fee_per_gas {
        None => max_fee_per_gas,
        Some(base_fee_per_gas) => {
            if max_fee_per_gas < base_fee_per_gas {
                return base_fee_per_gas;
            }

            let delta = max_fee_per_gas - base_fee_per_gas;
            let delta = match transaction.max_priority_fee_per_gas() {
                Some(max_priority_fee_per_gas) => cmp::min(delta, max_priority_fee_per_gas),
                None => delta,
            };

            base_fee_per_gas
                .checked_add(delta)
                .expect("effective gas price overflow")
        }
    }
}

impl RpcTransactionEnvelope {
    #[inline]
    pub fn max_fee_or_gas_price(&self) -> GasPrice {
        match self {
            Self::Legacy(tx) => tx.transaction.gas_price,
            Self::Eip2930(tx) => tx.transaction.gas_price,
            Self::Eip1559(tx) => tx.transaction.max_fee_per_gas,
            Self::Eip4844(tx) => tx.transaction.max_fee_per_gas,
            Self::Eip7702(tx) => tx.transaction.max_fee_per_gas,
        }
    }

    #[inline]
    pub fn max_priority_fee_per_gas(&self) -> Option<GasPrice> {
        match self {
            Self::Legacy(_) | Self::Eip2930(_) => None,
            Self::Eip1559(tx) => Some(tx.transaction.max_priority_fee_per_gas),
            Self::Eip4844(tx) => Some(tx.transaction.max_priority_fee_per_gas),
            Self::Eip7702(tx) => Some(tx.transaction.max_priority_fee_per_gas),
        }
    }

    #[inline]
    pub fn hash(&self) -> B256 {
        match self {
            Self::Legacy(tx) => tx.hash,
            Self::Eip2930(tx) => tx.hash,
            Self::Eip1559(tx) => tx.hash,
            Self::Eip4844(tx) => tx.hash,
            Self::Eip7702(tx) => tx.hash,
        }
    }

    #[inline]
    pub fn signature(&self) -> Signature {
        match self {
            Self::Legacy(tx) => tx.signature,
            Self::Eip2930(tx) => tx.signature,
            Self::Eip1559(tx) => tx.signature,
            Self::Eip4844(tx) => tx.signature,
            Self::Eip7702(tx) => tx.signature,
        }
    }
}
