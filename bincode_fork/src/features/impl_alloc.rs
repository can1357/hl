//! Alloc-backed writer helpers recovered for bincode-fork packet serialization.
//!
//! Source placement: `/home/ubuntu/hl/bincode-fork/src/features/impl_alloc.rs`.
//! This is a required foreign callee cluster for `enc/write.rs`: protocol packet
//! serializers first run with `SizeWriter`, then with this `VecWriter` so the
//! final `Vec<u8>` is allocated once at the counted size.
//!
//! Seeds/callees: `0x4AA9AE0`, `0x4AA9D70`, `0x4AA9E50`, `0x4AA9ED0`,
//! `0x4AA9F80`, and reserve/grow helper `0x454F5D0`. Confidence is high for the
//! public behavior (`Vec::with_capacity`, `extend_from_slice`, `collect`); field
//! order in machine code is allocator-specific and not modeled in Rust source.

extern crate alloc;

use alloc::vec::Vec;

use crate::{
    config::Config,
    enc::{self, write::SizeWriter, EncoderImpl},
    error::EncodeError,
};

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct VecWriter {
    inner: Vec<u8>,
}

impl VecWriter {
    #[inline]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inner: Vec::with_capacity(cap),
        }
    }

    #[inline]
    pub(crate) fn collect(self) -> Vec<u8> {
        self.inner
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.inner.len()
    }
}

impl enc::write::Writer for VecWriter {
    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        self.inner.extend_from_slice(bytes);
        Ok(())
    }
}

/// Encode into a freshly allocated byte vector.
///
/// The recovered binary performs the same two-pass strategy visible in bincode
/// 2.x: first count bytes with `SizeWriter`, then allocate a `VecWriter` exactly
/// large enough and encode again. Any error from either pass is propagated.
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn encode_to_vec<E: enc::Encode, C: Config>(val: E, config: C) -> Result<Vec<u8>, EncodeError> {
    let size = {
        let mut size_encoder = EncoderImpl::<_, C>::new(SizeWriter::default(), config);
        val.encode(&mut size_encoder)?;
        size_encoder.into_writer().bytes_written
    };

    let writer = VecWriter::with_capacity(size);
    let mut encoder = EncoderImpl::<_, C>::new(writer, config);
    val.encode(&mut encoder)?;
    Ok(encoder.into_writer().collect())
}
