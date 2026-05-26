//! Reconstruction of `/home/ubuntu/hl/code_Mainnet/node/src/consensus/signed.rs`.
//!
//! Confidence: medium for the verification control flow around the assigned seed;
//! low-to-medium for Rust field names because the source uses optimized generic
//! `Signed<T>` monomorphs and helper calls in `base/src/wallet.rs`, which is still
//! marked deficient in `recon/base/src/wallet.rs`.
//!
//! Seed EA: `0x47B01B0`.
//! IDA updates applied:
//! - `0x47B01B0` -> `node_consensus_signed__verify_signed_block`.
//! - `0x454AA10` -> `node_consensus_signed__verify_signed_timeout`.
//! - `0x4758D70` -> `node_consensus_signed__verify_quorum_certificate`.
//! - `0x47594F0` -> `node_consensus_signed__verify_timeout_certificate`.
//! - Function comments added with the signed.rs source path and the string anchor
//!   `Unexpected proposer for block. Is execution behind?` at `0x1e2d6a`.
//! - Declared `hl_node_consensus_Address20`, `hl_node_consensus_Signature65`,
//!   `hl_node_consensus_Hash32`, and `hl_node_consensus_SignedBlockPrefix`.
//! - Applied provisional `__usercall` types to `0x47B01B0`, `0x454AA10`, `0x4758D70`, and `0x47594F0`.
//!
//! Local disassembly anchors:
//! - `0x47B01D3..0x47B0208`: load block round/proposer context, call the signer
//!   lookup/recovery hook, and branch on the recovered `Result` discriminant.
//! - `0x47B023E..0x47B026A`: compare the recovered/expected 20-byte proposer with
//!   the proposer stored in the signed block.
//! - `0x47B0270..0x47B036F`: build the `SignableContentVerifySignature` diagnostic;
//!   the format string is `Unexpected proposer for block. Is execution behind? @@
//!   [block_hash: ...] @ [round: ...] @ [proposer: ...] @ [expected_proposer: ...]`.
//! - `0x47B03FB..0x47B0442`: verify the block QC, enforce `qc.round < block.round`,
//!   then verify an optional TC only when `tc.round == block.round - 1`.
//! - `0x454AA10`: signed-timeout verifier; hashes consensus payload variant `2`,
//!   optionally verifies the embedded QC first, and compares recovered signer bytes.
//! - `0x4758D70`: quorum-certificate verifier; hashes consensus payload variant `1`,
//!   verifies each signature against the validator set, then checks quorum weight.
//! - `0x47594F0`: timeout-certificate verifier; rejects an empty certificate,
//!   enforces timeout-round consistency, verifies signed timeouts, then checks quorum.

use std::fmt;

pub type Round = u64;
pub type Stake = u64;
pub type BlockHash = [u8; 32];
pub type ValidatorSigner = [u8; 20];
pub type SignatureBytes = [u8; 65];

/// Generic consensus signature wrapper.
///
/// Layout evidence:
/// - `protocol/structs.txt` records one `Signed<T>` monomorph with `content` at
///   `+0x00` and signature at `+0x70` (`0x396BC00`).
/// - Another block-sized monomorph has signature at `+0xb0` (`0x3833F50`).
/// The wrapper itself is therefore the normal Rust field order: content, signature.
#[derive(Clone, Eq, PartialEq)]
pub struct Signed<T> {
    pub content: T,
    pub signature: SignatureBytes,
}

impl<T: fmt::Debug> fmt::Debug for Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signed")
            .field("content", &self.content)
            .field("signature", &SignatureDebug(&self.signature))
            .finish()
    }
}

/// Block payload covered by consensus signature payload variant `0`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsensusBlock {
    pub block_hash: BlockHash,
    pub round: Round,
    pub proposer: ValidatorSigner,
    pub qc: Option<QuorumCertificate>,
    pub tc: Option<TimeoutCertificate>,
    /// [INFERENCE] The block body is serialized by adjacent consensus type code;
    /// signed.rs only needs to preserve it as bytes when hashing/dispatching.
    pub body: Vec<u8>,
}

pub type SignedBlock = Signed<ConsensusBlock>;

/// Payload covered by consensus signature payload variant `1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuorumCertificate {
    pub block_hash: BlockHash,
    pub round: Round,
    pub signatures: Vec<QcSignature>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QcSignature {
    pub signer: ValidatorSigner,
    pub signature: SignatureBytes,
}

/// Payload covered by consensus signature payload variant `2`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Timeout {
    pub qc: Option<QuorumCertificate>,
    pub validator: ValidatorSigner,
    pub round: Round,
}

pub type SignedTimeout = Signed<Timeout>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeoutCertificate {
    pub signed_timeouts: Vec<SignedTimeout>,
    pub round: Round,
}

/// Narrow replacement for calls into the deficient `base/src/wallet.rs` recovery
/// helpers. The binary computes a consensus payload hash (`0x454C050`) and recovers
/// a 20-byte signer address from the 65-byte secp256k1 signature; signed.rs only
/// depends on that recovered address, not on the concrete crypto implementation.
pub trait ConsensusSignatureBackend {
    fn recover_signer(
        &self,
        payload: ConsensusPayload<'_>,
        signature: &SignatureBytes,
    ) -> Result<ValidatorSigner, SignatureHookError>;
}

/// Narrow validator-set view required by signed.rs.
///
/// The optimized binary keeps the stake/proposer lookup in foreign consensus-state
/// helpers. This trait captures only the calls observed from signed.rs: expected
/// proposer by round, signer stake at a round, and the highest round covered by the
/// current stake snapshot.
pub trait ConsensusValidatorSet {
    fn valid_until_round(&self) -> Round;

    fn expected_proposer(&self, round: Round) -> Result<ValidatorSigner, SignedConsensusError>;

    fn stake_for_signer(
        &self,
        round: Round,
        signer: &ValidatorSigner,
    ) -> Result<Option<Stake>, SignedConsensusError>;

    fn total_active_stake(&self, round: Round) -> Result<Stake, SignedConsensusError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsensusPayload<'a> {
    Block(&'a ConsensusBlock),
    QuorumVote { block_hash: &'a BlockHash, round: Round },
    Timeout(&'a Timeout),
    /// [INFERENCE] Remaining wallet variants are present in `base/src/wallet.rs`
    /// (`0x454AEC0`, `0x454B300`) but are not reached by the signed.rs seed.
    Other { tag: u64, bytes: &'a [u8] },
}

impl ConsensusPayload<'_> {
    pub const fn tag(self) -> u64 {
        match self {
            Self::Block(_) => 0,
            Self::QuorumVote { .. } => 1,
            Self::Timeout(_) => 2,
            Self::Other { tag, .. } => tag,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignedConsensusMessage {
    Block(SignedBlock),
    Timeout(SignedTimeout),
    TimeoutCertificate(TimeoutCertificate),
    QuorumCertificate(QuorumCertificate),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignedConsensusError {
    SignableContentVerifySignature {
        signable_content: SignableContentKind,
        signer: ValidatorSigner,
        recovered: ValidatorSigner,
    },
    UnexpectedProposer {
        block_hash: BlockHash,
        round: Round,
        proposer: ValidatorSigner,
        expected_proposer: ValidatorSigner,
    },
    VerifySignature(SignatureHookError),
    VerifyQcSignature,
    BadBlockQcRound { block_round: Round, qc_round: Round },
    BadBlockTcRound { block_round: Round, tc_round: Round },
    TcNoTimeout,
    TimeoutRoundMismatch { expected: Round, got: Round },
    EmptyValidators,
    QcNoQuorum { signed_weight: Stake, threshold: Stake },
    TcNoQuorum { signed_weight: Stake, threshold: Stake },
    UnknownValidator { round: Round, signer: ValidatorSigner },
    QueryingStakesForHighRound { round: Round, valid_until: Round },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignableContentKind {
    Block,
    QuorumVote,
    Timeout,
    Other(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureHookError {
    MalformedSignature,
    RecoveryFailed,
    HashingFailed,
}

pub fn verify_signed_message<B, V>(
    backend: &B,
    validators: &V,
    message: &SignedConsensusMessage,
) -> Result<(), SignedConsensusError>
where
    B: ConsensusSignatureBackend,
    V: ConsensusValidatorSet,
{
    match message {
        SignedConsensusMessage::Block(block) => verify_signed_block(backend, validators, block),
        SignedConsensusMessage::Timeout(timeout) => verify_signed_timeout(backend, validators, timeout, true),
        SignedConsensusMessage::TimeoutCertificate(tc) => verify_timeout_certificate(backend, validators, tc),
        SignedConsensusMessage::QuorumCertificate(qc) => verify_quorum_certificate(backend, validators, qc),
    }
}

/// Recovered seed `0x47B01B0`.
pub fn verify_signed_block<B, V>(
    backend: &B,
    validators: &V,
    signed_block: &SignedBlock,
) -> Result<(), SignedConsensusError>
where
    B: ConsensusSignatureBackend,
    V: ConsensusValidatorSet,
{
    let block = &signed_block.content;
    reject_high_round(validators, block.round)?;

    let expected_proposer = validators.expected_proposer(block.round)?;
    if block.proposer != expected_proposer {
        return Err(SignedConsensusError::UnexpectedProposer {
            block_hash: block.block_hash,
            round: block.round,
            proposer: block.proposer,
            expected_proposer,
        });
    }

    verify_signature_matches(
        backend,
        ConsensusPayload::Block(block),
        &signed_block.signature,
        expected_proposer,
        SignableContentKind::Block,
    )?;

    match block.qc.as_ref() {
        Some(qc) => {
            verify_quorum_certificate(backend, validators, qc)?;
            if qc.round >= block.round {
                return Err(SignedConsensusError::BadBlockQcRound {
                    block_round: block.round,
                    qc_round: qc.round,
                });
            }
        }
        None if block.round != 0 => {
            return Err(SignedConsensusError::BadBlockQcRound {
                block_round: block.round,
                qc_round: block.round,
            });
        }
        None => {}
    }

    if let Some(tc) = block.tc.as_ref() {
        let Some(expected_tc_round) = block.round.checked_sub(1) else {
            return Err(SignedConsensusError::BadBlockTcRound { block_round: block.round, tc_round: tc.round });
        };
        if tc.round != expected_tc_round {
            return Err(SignedConsensusError::BadBlockTcRound { block_round: block.round, tc_round: tc.round });
        }
        verify_timeout_certificate(backend, validators, tc)?;
    }

    Ok(())
}

/// Recovered from `0x454AA10`; `verify_embedded_qc` is set when the caller wants
/// timeout verification to recurse into the timeout's QC before checking the
/// timeout signature.
pub fn verify_signed_timeout<B, V>(
    backend: &B,
    validators: &V,
    signed_timeout: &SignedTimeout,
    verify_embedded_qc: bool,
) -> Result<(), SignedConsensusError>
where
    B: ConsensusSignatureBackend,
    V: ConsensusValidatorSet,
{
    let timeout = &signed_timeout.content;
    reject_high_round(validators, timeout.round)?;

    if verify_embedded_qc {
        if let Some(qc) = timeout.qc.as_ref() {
            verify_quorum_certificate(backend, validators, qc)?;
        }
    }

    verify_signature_matches(
        backend,
        ConsensusPayload::Timeout(timeout),
        &signed_timeout.signature,
        timeout.validator,
        SignableContentKind::Timeout,
    )
}

/// Recovered from `0x4758D70`.
pub fn verify_quorum_certificate<B, V>(
    backend: &B,
    validators: &V,
    qc: &QuorumCertificate,
) -> Result<(), SignedConsensusError>
where
    B: ConsensusSignatureBackend,
    V: ConsensusValidatorSet,
{
    reject_high_round(validators, qc.round)?;

    let total_active = validators.total_active_stake(qc.round)?;
    let Some(threshold) = quorum_threshold(total_active) else {
        return Err(SignedConsensusError::EmptyValidators);
    };

    let mut signed_weight = 0u64;
    for (idx, signed) in qc.signatures.iter().enumerate() {
        if qc.signatures[..idx].iter().any(|prev| prev.signer == signed.signer) {
            continue;
        }

        verify_signature_matches(
            backend,
            ConsensusPayload::QuorumVote { block_hash: &qc.block_hash, round: qc.round },
            &signed.signature,
            signed.signer,
            SignableContentKind::QuorumVote,
        )
        .map_err(|_| SignedConsensusError::VerifyQcSignature)?;

        let Some(stake) = validators.stake_for_signer(qc.round, &signed.signer)? else {
            return Err(SignedConsensusError::UnknownValidator { round: qc.round, signer: signed.signer });
        };
        signed_weight = signed_weight.saturating_add(stake);
        if signed_weight >= threshold {
            return Ok(());
        }
    }

    Err(SignedConsensusError::QcNoQuorum { signed_weight, threshold })
}

/// Recovered from `0x47594F0`.
pub fn verify_timeout_certificate<B, V>(
    backend: &B,
    validators: &V,
    tc: &TimeoutCertificate,
) -> Result<(), SignedConsensusError>
where
    B: ConsensusSignatureBackend,
    V: ConsensusValidatorSet,
{
    reject_high_round(validators, tc.round)?;

    if tc.signed_timeouts.is_empty() {
        return Err(SignedConsensusError::TcNoTimeout);
    }

    let total_active = validators.total_active_stake(tc.round)?;
    let Some(threshold) = quorum_threshold(total_active) else {
        return Err(SignedConsensusError::EmptyValidators);
    };

    let mut signed_weight = 0u64;
    for (idx, signed_timeout) in tc.signed_timeouts.iter().enumerate() {
        let timeout = &signed_timeout.content;
        if timeout.round != tc.round {
            return Err(SignedConsensusError::TimeoutRoundMismatch { expected: tc.round, got: timeout.round });
        }
        if tc.signed_timeouts[..idx]
            .iter()
            .any(|prev| prev.content.validator == timeout.validator)
        {
            continue;
        }

        verify_signed_timeout(backend, validators, signed_timeout, true)?;

        let Some(stake) = validators.stake_for_signer(tc.round, &timeout.validator)? else {
            return Err(SignedConsensusError::UnknownValidator { round: tc.round, signer: timeout.validator });
        };
        signed_weight = signed_weight.saturating_add(stake);
        if signed_weight >= threshold {
            return Ok(());
        }
    }

    Err(SignedConsensusError::TcNoQuorum { signed_weight, threshold })
}

pub fn verify_signature_matches<B>(
    backend: &B,
    payload: ConsensusPayload<'_>,
    signature: &SignatureBytes,
    signer: ValidatorSigner,
    kind: SignableContentKind,
) -> Result<(), SignedConsensusError>
where
    B: ConsensusSignatureBackend,
{
    let recovered = backend
        .recover_signer(payload, signature)
        .map_err(SignedConsensusError::VerifySignature)?;
    if recovered == signer {
        Ok(())
    } else {
        Err(SignedConsensusError::SignableContentVerifySignature {
            signable_content: kind,
            signer,
            recovered,
        })
    }
}

pub fn reject_high_round<V>(validators: &V, round: Round) -> Result<(), SignedConsensusError>
where
    V: ConsensusValidatorSet,
{
    let valid_until = validators.valid_until_round();
    if round > valid_until {
        Err(SignedConsensusError::QueryingStakesForHighRound { round, valid_until })
    } else {
        Ok(())
    }
}

pub fn quorum_threshold(total_active_stake: Stake) -> Option<Stake> {
    if total_active_stake == 0 {
        return None;
    }
    let two_thirds_floor = (total_active_stake / 3)
        .saturating_mul(2)
        .saturating_add(((total_active_stake % 3) * 2) / 3);
    Some(two_thirds_floor.saturating_add(1))
}

/// Thin bincode-fork boundary: signed.rs dispatches the consensus payload variant;
/// the actual byte writer remains in the packet/serializer layer.
pub trait ConsensusPayloadEncoder {
    type Error;

    fn encode_block(&mut self, block: &ConsensusBlock) -> Result<(), Self::Error>;
    fn encode_quorum_vote(&mut self, block_hash: &BlockHash, round: Round) -> Result<(), Self::Error>;
    fn encode_timeout(&mut self, timeout: &Timeout) -> Result<(), Self::Error>;
    fn encode_other(&mut self, tag: u64, bytes: &[u8]) -> Result<(), Self::Error>;
}

pub fn encode_signable_payload<E>(
    encoder: &mut E,
    payload: ConsensusPayload<'_>,
) -> Result<(), E::Error>
where
    E: ConsensusPayloadEncoder,
{
    match payload {
        ConsensusPayload::Block(block) => encoder.encode_block(block),
        ConsensusPayload::QuorumVote { block_hash, round } => encoder.encode_quorum_vote(block_hash, round),
        ConsensusPayload::Timeout(timeout) => encoder.encode_timeout(timeout),
        ConsensusPayload::Other { tag, bytes } => encoder.encode_other(tag, bytes),
    }
}

struct SignatureDebug<'a>(&'a SignatureBytes);

impl fmt::Debug for SignatureDebug<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        for byte in self.0 {
            write!(f, "{:02x}", *byte)?;
        }
        Ok(())
    }
}
