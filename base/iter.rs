use std::fmt;

/// Extension methods recovered from the monomorphized iterator helper at `0x33690c0`.
///
/// The observed specialization walks every item, stores the first yielded value,
/// accepts later equal values, and panics only when a later value is distinct.  An
/// empty iterator returns `None`; callers decide how to map that absence into their
/// domain error.
pub trait ChamIterator: Iterator + Sized {
    /// Return the only distinct element yielded by this iterator.
    ///
    /// Duplicate equal elements are allowed.  The binary keeps scanning after the
    /// first element instead of stopping early, because disagreement between two
    /// elements is a hard invariant violation.  The panic format string recovered
    /// from the helper is:
    ///
    /// `".ChamIterator::unique_elem: not unique elems: [{:?}, {:?}, ...]"`
    #[inline]
    fn unique_elem(self) -> Option<Self::Item>
    where
        Self::Item: PartialEq + fmt::Debug,
    {
        let mut unique = None;

        for elem in self {
            if let Some(prev) = unique.as_ref() {
                if prev != &elem {
                    panic!(
                        ".ChamIterator::unique_elem: not unique elems: [{prev:?}, {elem:?}, ...]"
                    );
                }
            }

            // The recovered code overwrites the saved slot with the latest equal
            // value before continuing.  For `Copy` monomorphs this compiles to a
            // fixed-width copy; for owned values it drops the previous equal item.
            unique = Some(elem);
        }

        unique
    }
}

impl<I> ChamIterator for I where I: Iterator + Sized {}

