//! DEFICIENT PILOT OUTPUT: this file is retained for provenance but is not an acceptable final reconstruction.
//! Rebuild required: split the wallet/signing/serializer work across nested agents and replace TODO-heavy bodies with recovered Rust logic.
//! Reconstruction of `code_Mainnet/base/src/wallet.rs`.
//!
//! Confidence: Medium. The file is dominated by crypto/signing helpers and many
//! monomorphized multisig-signature serializers. Function membership is anchored
//! by panic locations for `/home/ubuntu/hl/code_Mainnet/base/src/wallet.rs` at:
//!   - `0x5666e50`: line 15, col 73 (`base_wallet__from_private_key_bytes` unwrap)
//!   - `0x5666e68`: line 27, col 66 (signing unwraps, consensus signing helpers)
//!   - `0x56ee7e0`: line 34, col 55 (multisig signature digest builder unwrap)
//!
//! IDA tags applied in this pass:
//!   - Declared: `hl_base_Wallet`, `hl_base_Signature`, `hl_base_MultisigConsensusPayload`, `hl_base_BytesVec`
//!   - Renamed/commented core functions: `0x13d1960`, `0x3340100`, `0x14a2710`,
//!     `0x1592610`, `0x37f0e40`, `0x3340a40`, `0x3341af0`, `0x454c050`,
//!     `0x454ad50`, `0x454aec0`, `0x454b020`, `0x454b170`, `0x454b300`,
//!     `0x454b430`, `0x454b700`, `0x454ba50`, `0x454bd70`.
//!   - Renamed/commented/typed multisig serializer monomorphs at
//!     `0x359d5f0..0x35a10e0`; one representative body is reconstructed below.

/// 20-byte account address recovered from secp256k1 public-key material.
///
/// IDA: stored inline in `hl_base_Wallet` at offsets `0x80..0x94`.
/// Confidence: Medium — `base_wallet__address_from_public_key` writes 20 bytes plus
/// a 4-byte tail after hashing a 64-byte raw public key.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct Address(pub [u8; 20]);

/// secp256k1/Ethereum style recoverable signature.
///
/// IDA: `hl_base_Signature`; prior struct evidence also showed `r` at `0x00`,
/// `s` at `0x20`, `v` at `0x40`.
/// Confidence: High — all signers write 64 big-endian bytes plus one recovery byte.
#[derive(Clone, Copy)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

/// Wallet/key wrapper containing secret scalar, derived public-key material, and address.
///
/// IDA: `hl_base_Wallet`, constructor `base_wallet__from_private_key_bytes`
/// (was `sub_13D1960`).
/// Confidence: Medium — exact upstream k256/alloy field names are not present in
/// the stripped binary, but offsets/size are observed: 152 bytes total, address-like
/// material starts at `0x80`, and a presence flag is stored at `0x78`.
pub struct Wallet {
    /// [INFERENCE] k256 secret scalar plus precomputed public-key/projective data.
    pub _unknown_secret_and_public_material_at_0: [u8; 120],
    pub _unknown_has_address_at_120: u64,
    pub address: Address,
    pub _unknown_address_tail_at_148: u32,
}

/// Error/result carrier used by the reconstructed signing paths.
///
/// IDA: several callees return Rust `Result` layouts; precise error enum is not
/// reconstructed here.
/// Confidence: Low.
pub enum WalletError {
    Opaque,
}

impl Wallet {
    /// Constructs a wallet from a 32-byte big-endian secp256k1 private scalar.
    ///
    /// IDA: `base_wallet__from_private_key_bytes` (was `sub_13D1960`).
    /// Confidence: Medium.
    ///
    /// Evidence:
    /// - Calls `sub_1454D80` with the caller-provided scalar pointer; that helper
    ///   byte-swaps four u64 limbs and rejects zero/out-of-range scalars.
    /// - On `Err`, panics at wallet.rs line 15/col 73 with `Result::unwrap()`.
    /// - Calls `base_wallet__address_from_public_key` (`0x1592610`) on derived
    ///   public-key material and stores a 20-byte address-like value at offset `0x80`.
    pub fn from_private_key_bytes(private_key_be: &[u8; 32]) -> Self {
        let _ = private_key_be;
        todo!("k256 scalar construction and public-key derivation — see sub_13D1960 and sub_1454D80")
    }

    /// Signs a precomputed 32-byte digest and returns a recoverable signature.
    ///
    /// IDA: `base_wallet__sign_hash` (was `sub_14A2710`).
    /// Confidence: Medium.
    ///
    /// The normal path writes eight big-endian u64 limbs followed by a recovery id;
    /// the recovery byte is normalized with `+ 27`. The error path stores a small
    /// `Result` discriminant and is unwrapped by callers at wallet.rs line 27/col 66.
    pub fn sign_hash(&self, digest: &[u8; 32]) -> Result<Signature, WalletError> {
        let _ = (self, digest);
        todo!("ECDSA signing call target and exact error enum are opaque — see sub_14A2710")
    }

    /// Derives an account address from public-key material.
    ///
    /// IDA: `base_wallet__address_from_public_key` (was `sub_1592610`).
    /// Confidence: Medium.
    ///
    /// The helper rejects malformed key encodings with the string
    /// `raw public key must be 64 bytes`, hashes the 64-byte key, and returns the
    /// final 20-byte address-sized value.
    pub fn address_from_public_key(public_key_material: &[u8]) -> Address {
        let _ = public_key_material;
        todo!("public-key encoding and hash extraction — see sub_1592610")
    }
}

/// Discriminated consensus payload passed into the consensus EIP-712 hash helper.
///
/// IDA: `hl_base_MultisigConsensusPayload`, consumed by
/// `base_wallet__hash_consensus_payload` (`0x454c050`).
/// Confidence: Medium.
pub struct ConsensusPayloadRef<'a> {
    /// Observed variants used by signing helpers: 0, 1, 2, 3, 4.
    pub variant: u64,
    pub payload: &'a [u8],
}

/// Computes the hash signed for Hyperliquid consensus messages.
///
/// IDA: `base_wallet__hash_consensus_payload` (was `sub_454C050`).
/// Confidence: Medium.
///
/// Evidence:
/// - Allocates/copies the literal `Hyperliquid Consensus Payload` (29 bytes).
/// - Uses the type/domain string `ConsensusMsg` (13 bytes).
/// - Finalizes a 32-byte digest through the same hashing/finalization helpers used
///   by other EIP-712 paths.
pub fn hash_consensus_payload(payload: ConsensusPayloadRef<'_>) -> [u8; 32] {
    let _ = payload;
    todo!("typed-data/domain encoding for ConsensusMsg — see sub_454C050")
}

/// Signs a consensus payload variant and appends the signature to the copied payload.
///
/// IDA: variants below are separate monomorphized/copy-size helpers.
/// Confidence: Medium.
pub fn sign_consensus_payload_variant(wallet: &Wallet, payload: ConsensusPayloadRef<'_>) -> Vec<u8> {
    let digest = hash_consensus_payload(payload);
    let _signature = wallet
        .sign_hash(&digest)
        .expect("called `Result::unwrap()` on an `Err` value — wallet.rs:27:66");
    todo!("copy exact variant-specific payload layout and append signature — see 0x454ad50/0x454aec0/0x454b020/0x454b170/0x454b300")
}

/// Variant-0 consensus signer.
///
/// IDA: `base_wallet__sign_consensus_variant_0` (was `sub_454AD50`).
/// Confidence: Medium — copies `0xb0` bytes, appends 65-byte signature at `0xb0`.
pub fn sign_consensus_variant_0(wallet: &Wallet, payload_bytes: &[u8]) -> Vec<u8> {
    let _ = (wallet, payload_bytes);
    todo!("variant 0 payload fields are opaque — see sub_454AD50")
}

/// Variant-1 consensus signer.
///
/// IDA: `base_wallet__sign_consensus_variant_1` (was `sub_454B020`).
/// Confidence: Medium — copies `0x50` bytes, appends 65-byte signature at `0x50`.
pub fn sign_consensus_variant_1(wallet: &Wallet, payload_bytes: &[u8]) -> Vec<u8> {
    let _ = (wallet, payload_bytes);
    todo!("variant 1 payload fields are opaque — see sub_454B020")
}

/// Variant-2 consensus signer.
///
/// IDA: `base_wallet__sign_consensus_variant_2` (was `sub_454B170`).
/// Confidence: Medium — copies `0x70` bytes, appends 65-byte signature at `0x70`.
pub fn sign_consensus_variant_2(wallet: &Wallet, payload_bytes: &[u8]) -> Vec<u8> {
    let _ = (wallet, payload_bytes);
    todo!("variant 2 payload fields are opaque — see sub_454B170")
}

/// Variant-3 consensus signer.
///
/// IDA: `base_wallet__sign_consensus_variant_3` (was `sub_454AEC0`).
/// Confidence: Medium — copies `0x120` bytes, appends 65-byte signature at `0x120`.
pub fn sign_consensus_variant_3(wallet: &Wallet, payload_bytes: &[u8]) -> Vec<u8> {
    let _ = (wallet, payload_bytes);
    todo!("variant 3 payload fields are opaque — see sub_454AEC0")
}

/// Variant-4 consensus signer.
///
/// IDA: `base_wallet__sign_consensus_variant_4` (was `sub_454B300`).
/// Confidence: Medium — copies `0x20` bytes, appends 65-byte signature at `0x20`.
pub fn sign_consensus_variant_4(wallet: &Wallet, payload_bytes: &[u8]) -> Vec<u8> {
    let _ = (wallet, payload_bytes);
    todo!("variant 4 payload fields are opaque — see sub_454B300")
}

/// Reconstructs the byte frame used for signed action enqueueing.
///
/// IDA: `base_wallet__serialize_signed_action_frame` (was `sub_3340A40`).
/// Confidence: Medium.
///
/// Layout observed in the success path:
/// 1. 65-byte signature (`r`, `s`, `v`) assembled from big-endian limbs.
/// 2. 8-byte big-endian nonce/timestamp-like value from payload offset `0x148`.
/// 3. one byte indicating optional 20-byte address at payload offsets `0x151..0x165`.
/// 4. one byte flag from payload offset `0x165`.
/// 5. optional 8-byte field from the frame header.
/// 6. serialized action body appended from another serializer.
pub fn serialize_signed_action_frame(frame_360: &[u8]) -> Result<Vec<u8>, WalletError> {
    let _ = frame_360;
    todo!("action body serializer and result enum mapping — see sub_3340A40")
}

/// Signs and enqueues one or more action frames.
///
/// IDA: `base_wallet__sign_and_enqueue_multi_action_frame` (was `sub_3340100`).
/// Confidence: Medium.
///
/// For each 360-byte input frame the function calls `serialize_signed_action_frame`.
/// It concatenates serialized frames, prefixes a 32-bit big-endian length for an
/// intermediate payload, appends the concatenated frames and an 8-byte big-endian
/// timestamp, signs the resulting digest, and appends the 65-byte signature.
pub fn sign_and_enqueue_multi_action_frame(
    wallet: &Wallet,
    frames_360: &[[u8; 360]],
    timestamp_ms: u64,
) -> Result<Vec<u8>, WalletError> {
    let _ = (wallet, frames_360, timestamp_ms);
    todo!("exact result variants 188/320/390 and intermediate action serializer — see sub_3340100")
}

/// Builds the 360-byte signed action payload used before frame serialization.
///
/// IDA: `base_wallet__build_signed_action_payload` (was `sub_3341AF0`).
/// Confidence: Low/Medium.
///
/// The helper copies a 240-byte action body, computes or forwards a nonce, writes
/// optional expiry/address fields, and conditionally uses a default `+30000 ms`
/// expiration for many action variants.
pub fn build_signed_action_payload(action_and_context: &[u8]) -> [u8; 360] {
    let _ = action_and_context;
    todo!("action enum layout and expiration matrix are opaque — see sub_3341AF0")
}

/// Builds the digest that multisig inner signatures sign.
///
/// IDA: `base_wallet__build_multisig_signature_digest` (was `sub_37F0E40`).
/// Confidence: Medium.
///
/// Error-string mapping observed in this helper:
/// - `Failed to serialize ...`
/// - `Failed to decode ...`
/// - `Failed to make ...`
/// - `Failed to convert ...`
/// - `Nested EIP712 ...`
pub fn build_multisig_signature_digest() -> Result<[u8; 32], WalletError> {
    todo!("nested EIP-712 data source is implicit in monomorphized caller — see sub_37F0E40")
}

/// Representative body for the repeated multisig signature serializer monomorphs.
///
/// IDA: `base_wallet__serialize_multisig_signature__mono_unknown_00`
/// (was `serialize_multisig_signature` at `0x359D5F0`).
/// Confidence: Medium.
///
/// Caller evidence: `0x38eea70` validates outer conditions, then calls this function
/// to write a 65-byte signature into an option/result-like return.
pub fn serialize_multisig_signature__mono_unknown_00(
    wallet: &Wallet,
    _typed_multisig_payload: &[u8],
) -> Result<Signature, WalletError> {
    let digest = build_multisig_signature_digest()?;
    wallet.sign_hash(&digest)
}

// Remaining multisig signature serializer monomorphizations.
//
// All observed functions have the same 309-byte shape:
// - call `base_wallet__build_multisig_signature_digest` (`0x37f0e40`), unwrap at
//   wallet.rs:34:55 on error;
// - call `base_wallet__sign_hash` (`0x14a2710`), unwrap at wallet.rs:27:66 on error;
// - copy the resulting 65-byte signature to the caller-provided output.
//
// Type arguments were not recoverable from the stripped binary in this pass, so the
// suffixes are intentionally `unknown_NN` rather than fabricated action names.
//
// IDA monomorph list:
// - `base_wallet__serialize_multisig_signature__mono_unknown_00`: `0x359d5f0`, caller `0x38eea70`
// - `base_wallet__serialize_multisig_signature__mono_unknown_01`: `0x359d760`, caller `0x3a11660`
// - `base_wallet__serialize_multisig_signature__mono_unknown_02`: `0x359d8d0`, caller `0x3a1ccc0`
// - `base_wallet__serialize_multisig_signature__mono_unknown_03`: `0x359da40`, caller `0x3a1e670`
// - `base_wallet__serialize_multisig_signature__mono_unknown_04`: `0x359dbb0`, caller `0x3311d50`
// - `base_wallet__serialize_multisig_signature__mono_unknown_05`: `0x359dd20`, caller `0x38eb760`
// - `base_wallet__serialize_multisig_signature__mono_unknown_06`: `0x359de90`, caller `0x3a1b8a0`
// - `base_wallet__serialize_multisig_signature__mono_unknown_07`: `0x359e000`, caller `0x3a114b0`
// - `base_wallet__serialize_multisig_signature__mono_unknown_08`: `0x359e170`, caller `0x3a1e4c0`
// - `base_wallet__serialize_multisig_signature__mono_unknown_09`: `0x359e2e0`, caller `0x38e2a20`
// - `base_wallet__serialize_multisig_signature__mono_unknown_10`: `0x359e450`, caller `0x38e8480`
// - `base_wallet__serialize_multisig_signature__mono_unknown_11`: `0x359e5c0`, caller `0x38eb910`
// - `base_wallet__serialize_multisig_signature__mono_unknown_12`: `0x359e730`, caller `0x33e0290`
// - `base_wallet__serialize_multisig_signature__mono_unknown_13`: `0x359e8a0`, caller `0x38ec4f0`
// - `base_wallet__serialize_multisig_signature__mono_unknown_14`: `0x359ea10`, caller `0x38e2bd0`
// - `base_wallet__serialize_multisig_signature__mono_unknown_15`: `0x359eb80`, caller `0x3a1cb00`
// - `base_wallet__serialize_multisig_signature__mono_unknown_16`: `0x359ecf0`, caller `0x38dff60`
// - `base_wallet__serialize_multisig_signature__mono_unknown_17`: `0x359ee60`, callers `0x333f7b0`, `0x33609f0`
// - `base_wallet__serialize_multisig_signature__mono_unknown_18`: `0x359efd0`, caller `0x38ede00`
// - `base_wallet__serialize_multisig_signature__mono_unknown_19`: `0x359f140`, caller `0x38e8630`
// - `base_wallet__serialize_multisig_signature__mono_unknown_20`: `0x359f2b0`, caller `0x33e08b0`
// - `base_wallet__serialize_multisig_signature__mono_unknown_21`: `0x359f420`, caller `0x3317160`
// - `base_wallet__serialize_multisig_signature__mono_unknown_22`: `0x359f590`, caller `0x3a1c6d0`
// - `base_wallet__serialize_multisig_signature__mono_unknown_23`: `0x359f700`, caller `0x38ec6a0`
// - `base_wallet__serialize_multisig_signature__mono_unknown_24`: `0x359f870`, caller `0x33e0440`
// - `base_wallet__serialize_multisig_signature__mono_unknown_25`: `0x359f9e0`, caller `0x3311ba0`
// - `base_wallet__serialize_multisig_signature__mono_unknown_26`: `0x359fb50`, caller `0x3a1bf80`
// - `base_wallet__serialize_multisig_signature__mono_unknown_27`: `0x359fcc0`, caller `0x38eed20`
// - `base_wallet__serialize_multisig_signature__mono_unknown_28`: `0x359fe30`, caller `0x38f7870`
// - `base_wallet__serialize_multisig_signature__mono_unknown_29`: `0x359ffa0`, caller `0x330d940`
// - `base_wallet__serialize_multisig_signature__mono_unknown_30`: `0x35a0110`, caller `0x3a1c130`
// - `base_wallet__serialize_multisig_signature__mono_unknown_31`: `0x35a0280`, caller `0x38edfc0`
// - `base_wallet__serialize_multisig_signature__mono_unknown_32`: `0x35a03f0`, caller `0x330daf0`
// - `base_wallet__serialize_multisig_signature__mono_unknown_33`: `0x35a0560`, caller `0x3a1c880`
// - `base_wallet__serialize_multisig_signature__mono_unknown_34`: `0x35a06d0`, caller `0x3a1aec0`
// - `base_wallet__serialize_multisig_signature__mono_unknown_35`: `0x35a0840`, caller `0x38dfdb0`
// - `base_wallet__serialize_multisig_signature__mono_unknown_36`: `0x35a09b0`, caller `0x38f7a20`
// - `base_wallet__serialize_multisig_signature__mono_unknown_37`: `0x35a0b20`, caller `0x3316fb0`
// - `base_wallet__serialize_multisig_signature__mono_unknown_38`: `0x35a0c90`, caller `0x33e0700`
// - `base_wallet__serialize_multisig_signature__mono_unknown_39`: `0x35a0e00`, caller `0x3a1b6f0`
// - `base_wallet__serialize_multisig_signature__mono_unknown_40`: `0x35a0f70`, caller `0x38eeed0`
// - `base_wallet__serialize_multisig_signature__mono_unknown_41`: `0x35a10e0`, caller `0x38ee8c0`

/// [INFERENCE: file membership] Validates a consensus payload signer against a
/// historical block/user-state table before accepting variant 0.
///
/// IDA: `base_wallet__validate_consensus_variant_0_signer` (was `sub_454B700`).
/// Confidence: Low/Medium — same address-lookup pattern as adjacent variant checks.
pub fn validate_consensus_variant_0_signer(payload: &[u8], history: &[u8]) -> Result<(), WalletError> {
    let _ = (payload, history);
    todo!("historical signer table layout is opaque — see sub_454B700")
}

/// [INFERENCE: file membership] Validates a consensus payload signer for variant 1.
///
/// IDA: `base_wallet__validate_consensus_variant_1_signer` (was `sub_454BA50`).
/// Confidence: Low/Medium.
pub fn validate_consensus_variant_1_signer(payload: &[u8], history: &[u8]) -> Result<(), WalletError> {
    let _ = (payload, history);
    todo!("historical signer table layout is opaque — see sub_454BA50")
}

/// [INFERENCE: file membership] Validates a consensus payload signer for variant 3.
///
/// IDA: `base_wallet__validate_consensus_variant_3_signer` (was `sub_454BD70`).
/// Confidence: Low/Medium.
pub fn validate_consensus_variant_3_signer(payload: &[u8], history: &[u8]) -> Result<(), WalletError> {
    let _ = (payload, history);
    todo!("historical signer table layout is opaque — see sub_454BD70")
}

/// [INFERENCE: file membership] Validates a consensus payload signer for variant 4.
///
/// IDA: `base_wallet__validate_consensus_variant_4_signer` (was `sub_454B430`).
/// Confidence: Low/Medium.
pub fn validate_consensus_variant_4_signer(payload: &[u8], history: &[u8]) -> Result<(), WalletError> {
    let _ = (payload, history);
    todo!("historical signer table layout is opaque — see sub_454B430")
}
