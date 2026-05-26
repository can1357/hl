use serde::Serialize;
use tiny_keccak::{Hasher, Keccak};

pub const L1_ACTION_CHAIN_ID: u64 = 1337;
pub const MAINNET_CHAIN_DISCRIMINANT: u8 = 3;
pub const MAINNET_SOURCE: u8 = b'a';
pub const TESTNET_SOURCE: u8 = b'b';

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct Address(pub [u8; Address::LEN]);

impl Address {
    pub const LEN: usize = 20;

    #[inline]
    pub const fn zero() -> Self {
        Self([0; Self::LEN])
    }

    #[inline]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

// The context layout recovered from the three monomorphs is:
// optional expires-after tag/value, nonce, then optional vault address.  The
// hash suffix is always big-endian nonce, a vault tag byte, optional vault
// bytes, then optional expires-after marker byte `0` plus a big-endian value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RmpSignableContext {
    pub expires_after: Option<u64>,
    pub nonce: u64,
    pub vault_address: Option<Address>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AgentSignablePayload {
    pub source: String,
    #[serde(rename = "connectionId")]
    pub connection_id: [u8; 32],
    #[serde(skip_serializing)]
    pub chain_id: u64,
    #[serde(skip_serializing)]
    pub verifying_contract: Address,
}

// The embedded/multisig path keeps the raw chain discriminant alongside the
// hash; its callers compare this byte and the nonce before accepting the
// payload for signature serialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmbeddedSignablePayload {
    pub signature_chain_id: [u8; 32],
    pub connection_id: [u8; 32],
    pub nonce: u64,
    pub chain: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmbeddedSignableMismatch {
    Chain { expected: u8, actual: u8 },
    Nonce { expected: u64, actual: u64 },
}

// Recovered source canonicalization: chain discriminant `3` serializes as the
// one-byte string `"a"`; every other observed path serializes as `"b"`.
#[inline]
pub const fn source_byte_for_chain(chain: u8) -> u8 {
    if chain == MAINNET_CHAIN_DISCRIMINANT {
        MAINNET_SOURCE
    } else {
        TESTNET_SOURCE
    }
}

pub fn source_string_for_chain(chain: u8) -> String {
    let mut source = String::with_capacity(1);
    source.push(source_byte_for_chain(chain) as char);
    source
}

// The binary constructs an rmp-serde serializer over a Vec and unwraps the
// result.  The serializer is configured for named struct maps, which is the
// canonical byte representation used before the signing suffix is appended.
pub fn encode_rmp_named<T>(value: &T) -> Result<Vec<u8>, rmp_serde::encode::Error>
where
    T: Serialize + ?Sized,
{
    let mut out = Vec::new();
    {
        let mut serializer = rmp_serde::Serializer::new(&mut out).with_struct_map();
        value.serialize(&mut serializer)?;
    }
    Ok(out)
}

pub fn build_default_action_signable<T>(
    action: &T,
    chain: u8,
    context: &RmpSignableContext,
) -> AgentSignablePayload
where
    T: Serialize + ?Sized,
{
    let encoded = encode_rmp_named(action).unwrap();
    build_agent_signable_from_encoded(encoded, chain, context)
}

pub fn build_canonical_action_signable<T, C>(
    action: &T,
    canonicalize: impl FnOnce(&T) -> C,
    chain: u8,
    context: &RmpSignableContext,
) -> AgentSignablePayload
where
    C: Serialize,
{
    let canonical = canonicalize(action);
    let encoded = encode_rmp_named(&canonical).unwrap();
    build_agent_signable_from_encoded(encoded, chain, context)
}

pub fn try_build_default_action_signable<T>(
    action: &T,
    chain: u8,
    context: &RmpSignableContext,
) -> Result<AgentSignablePayload, rmp_serde::encode::Error>
where
    T: Serialize + ?Sized,
{
    let encoded = encode_rmp_named(action)?;
    Ok(build_agent_signable_from_encoded(encoded, chain, context))
}

pub fn build_agent_signable_from_encoded(
    encoded_action: Vec<u8>,
    chain: u8,
    context: &RmpSignableContext,
) -> AgentSignablePayload {
    AgentSignablePayload {
        source: source_string_for_chain(chain),
        connection_id: action_connection_id(encoded_action, context),
        chain_id: L1_ACTION_CHAIN_ID,
        verifying_contract: Address::zero(),
    }
}

pub fn build_embedded_action_signable<T>(
    action: &T,
    signature_chain_id: [u8; 32],
    chain: u8,
    context: &RmpSignableContext,
) -> EmbeddedSignablePayload
where
    T: Serialize + ?Sized,
{
    let encoded = encode_rmp_named(action).unwrap();
    EmbeddedSignablePayload {
        signature_chain_id,
        connection_id: action_connection_id(encoded, context),
        nonce: context.nonce,
        chain,
    }
}

pub fn try_build_embedded_action_signable<T>(
    action: &T,
    signature_chain_id: [u8; 32],
    chain: u8,
    context: &RmpSignableContext,
) -> Result<EmbeddedSignablePayload, rmp_serde::encode::Error>
where
    T: Serialize + ?Sized,
{
    let encoded = encode_rmp_named(action)?;
    Ok(EmbeddedSignablePayload {
        signature_chain_id,
        connection_id: action_connection_id(encoded, context),
        nonce: context.nonce,
        chain,
    })
}

pub fn check_embedded_action_signable(
    signable: &EmbeddedSignablePayload,
    chain: u8,
    context: &RmpSignableContext,
) -> Result<(), EmbeddedSignableMismatch> {
    if signable.chain != chain {
        return Err(EmbeddedSignableMismatch::Chain {
            expected: chain,
            actual: signable.chain,
        });
    }

    if signable.nonce != context.nonce {
        return Err(EmbeddedSignableMismatch::Nonce {
            expected: context.nonce,
            actual: signable.nonce,
        });
    }

    Ok(())
}

pub fn action_connection_id(mut encoded_action: Vec<u8>, context: &RmpSignableContext) -> [u8; 32] {
    append_signing_suffix(&mut encoded_action, context);
    keccak256(&encoded_action)
}

pub fn append_signing_suffix(out: &mut Vec<u8>, context: &RmpSignableContext) {
    let extra_len = 8
        + 1
        + context.vault_address.map_or(0, |_| Address::LEN)
        + context.expires_after.map_or(0, |_| 1 + 8);
    out.reserve(extra_len);

    out.extend_from_slice(&context.nonce.to_be_bytes());

    match context.vault_address {
        Some(vault_address) => {
            out.push(1);
            out.extend_from_slice(vault_address.as_bytes());
        }
        None => out.push(0),
    }

    if let Some(expires_after) = context.expires_after {
        out.push(0);
        out.extend_from_slice(&expires_after.to_be_bytes());
    }
}

#[inline]
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut out);
    out
}
