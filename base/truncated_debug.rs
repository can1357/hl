use std::fmt;

/// Maximum number of bytes kept from a formatted debug string before the
/// truncation marker is appended.
///
/// The recovered code compares the allocated `String` length with `0x2710` and
/// slices at that byte offset. It intentionally relies on Rust's `str` slicing
/// check: if byte 10_000 is in the middle of a UTF-8 code point, the formatter
/// panics instead of rounding to a character boundary.
pub const TRUNCATED_DEBUG_BYTES: usize = 10_000;

/// Marker appended after the preserved prefix when debug output is too long.
pub const TRUNCATED_DEBUG_SUFFIX: &str = "[...]";

/// Wrap a value so formatter output contains at most the first 10,000 bytes of
/// that value's `Debug` representation followed by `[...]`.
///
/// The wrapper stores the caller's value directly. Most call sites pass a
/// reference, which is why the recovered monomorphs load a pointer-sized field
/// and then call the wrapped type's `Debug` adapter.
#[derive(Clone, Copy)]
pub struct TruncatedDebug<T>(pub T);

impl<T> TruncatedDebug<T> {
    #[inline]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.0
    }

    #[inline]
    pub const fn get(&self) -> &T {
        &self.0
    }
}

#[inline]
pub const fn truncated_debug<T>(value: T) -> TruncatedDebug<T> {
    TruncatedDebug::new(value)
}

#[inline]
pub const fn truncated_debug_ref<T: ?Sized>(value: &T) -> TruncatedDebug<&T> {
    TruncatedDebug::new(value)
}

impl<T: fmt::Debug> fmt::Debug for TruncatedDebug<T> {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_truncated_debug(&self.0, formatter)
    }
}

impl<T: fmt::Debug> fmt::Display for TruncatedDebug<T> {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_truncated_debug(&self.0, formatter)
    }
}

/// Format `value` with `Debug`, then forward either the whole temporary string
/// or a byte prefix plus the recovered suffix.
///
/// This mirrors the monomorphs in the binary: first `alloc::fmt::format` builds
/// a `String` from a single `{:?}` argument, then `Formatter::write_str` emits
/// the complete string or `&formatted[..10000]` followed by `"[...]"`.
#[inline]
pub fn fmt_truncated_debug<T: fmt::Debug + ?Sized>(
    value: &T,
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    let formatted = format!("{value:?}");

    if formatted.len() <= TRUNCATED_DEBUG_BYTES {
        return formatter.write_str(&formatted);
    }

    formatter.write_str(&formatted[..TRUNCATED_DEBUG_BYTES])?;
    formatter.write_str(TRUNCATED_DEBUG_SUFFIX)
}
