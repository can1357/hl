//! Line-oriented consensus output helpers recovered from the consensus logging path.

/// Minimum byte length before a hex-looking value is shortened.
///
/// The recovered helper only abbreviates strings at least `0x15` bytes long and
/// beginning with `"0x"`. Shorter strings and non-hex-looking strings are moved
/// through without allocation.
pub const HEX_LINE_MIN_LEN: usize = 0x15;

const HEX_LINE_HEAD_BYTES: usize = 6;
const HEX_LINE_TAIL_BYTES: usize = 4;
const HEX_LINE_SEPARATOR: &str = "..";

/// Return a log-line-safe form of an owned hex string.
///
/// Recovered behavior at `0x4756930`:
/// - input is an owned `String` laid out as Rust's `String`/`Vec<u8>`;
/// - if `len < 21` or the bytes do not start with `b"0x"`, the original
///   allocation is returned unchanged;
/// - otherwise the result is `s[..6] + ".." + s[len - 4..]`.
///
/// The slice operations intentionally preserve Rust's UTF-8 boundary checks.
/// The binary checks byte offsets 6 and `len - 4` before constructing the two
/// `&str` display arguments, so non-boundary inputs panic instead of silently
/// producing invalid UTF-8.
pub fn abbreviate_hex_line(s: String) -> String {
    let len = s.len();
    if len < HEX_LINE_MIN_LEN || !s.as_bytes().starts_with(b"0x") {
        return s;
    }

    let head = &s[..HEX_LINE_HEAD_BYTES];
    let tail = &s[len - HEX_LINE_TAIL_BYTES..];

    let mut out = String::with_capacity(HEX_LINE_HEAD_BYTES + HEX_LINE_SEPARATOR.len() + HEX_LINE_TAIL_BYTES);
    out.push_str(head);
    out.push_str(HEX_LINE_SEPARATOR);
    out.push_str(tail);
    out
}

/// Trait form used by the consensus logging helpers: consume a value and return
/// the equivalent value with large line fields shortened.
pub trait Line {
    fn line(self) -> Self;
}

impl Line for String {
    fn line(self) -> Self {
        abbreviate_hex_line(self)
    }
}

impl<T: Line> Line for Vec<T> {
    fn line(self) -> Self {
        self.into_iter().map(Line::line).collect()
    }
}

/// Reconstructed shape of the 104-byte records handled by
/// `node_consensus_liner__line_nested_outputs` (`0x47bb890`).
///
/// The first 24 bytes are an owned `String`, the next 72 bytes are another
/// consensus output value, and the final eight bytes are carried through without
/// interpretation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NestedLineOutput {
    pub label: String,
    pub output: ConsensusLineOutput,
    pub _unknown_field_at_0x60: u64,
}

impl Line for NestedLineOutput {
    fn line(self) -> Self {
        Self {
            label: abbreviate_hex_line(self.label),
            output: line_consensus_output(self.output),
            _unknown_field_at_0x60: self._unknown_field_at_0x60,
        }
    }
}

/// Consensus output value forms observed in the line helper callers.
///
/// Variant names are source-level reconstructions. The recovered discriminants
/// are: string field variant `3`, vector-of-output variant `4`, and nested
/// 104-byte record vector variant `5`. Other 72-byte variants are passed through
/// unchanged by `0x4756600`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsensusLineOutput {
    /// Variant 3: owns a string that may be abbreviated when it looks like a
    /// long hex value.
    HexString(String),
    /// Variant 4: vector/range of 72-byte output values, each recursively lined.
    Outputs(Vec<ConsensusLineOutput>),
    /// Variant 5: vector/range of 104-byte records; both the record label and
    /// nested output are recursively lined.
    Nested(Vec<NestedLineOutput>),
    /// Any other consensus output variant. The binary copies these 72-byte
    /// values through without inspecting their fields.
    Other {
        discriminant: u64,
        _unknown_field_at_0x08: Vec<u8>,
    },
}

impl Line for ConsensusLineOutput {
    fn line(self) -> Self {
        line_consensus_output(self)
    }
}

/// Recursive consensus-output line conversion recovered from `0x4756600`.
pub fn line_consensus_output(output: ConsensusLineOutput) -> ConsensusLineOutput {
    match output {
        ConsensusLineOutput::HexString(s) => ConsensusLineOutput::HexString(abbreviate_hex_line(s)),
        ConsensusLineOutput::Outputs(outputs) => ConsensusLineOutput::Outputs(line_output_vec(outputs)),
        ConsensusLineOutput::Nested(records) => ConsensusLineOutput::Nested(line_nested_outputs(records)),
        other => other,
    }
}

/// Consume a vector of consensus output values and line each element.
///
/// This corresponds to `0x454d410`, which walks 72-byte elements, calls the
/// recursive output liner for every element, and returns the rebuilt vector.
pub fn line_output_vec(outputs: Vec<ConsensusLineOutput>) -> Vec<ConsensusLineOutput> {
    outputs.into_iter().map(line_consensus_output).collect()
}

/// Consume nested consensus-output records and line each record.
///
/// This corresponds to `0x47bb890`, which shortens the leading string field and
/// recursively lines the embedded 72-byte output field for every 104-byte record.
pub fn line_nested_outputs(records: Vec<NestedLineOutput>) -> Vec<NestedLineOutput> {
    records.into_iter().map(Line::line).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abbreviates_long_hex_strings() {
        assert_eq!(
            abbreviate_hex_line("0x1234567890abcdef1234".to_owned()),
            "0x1234..1234",
        );
    }

    #[test]
    fn preserves_short_or_non_hex_strings_without_reformatting() {
        assert_eq!(abbreviate_hex_line("0x1234567890".to_owned()), "0x1234567890");
        assert_eq!(abbreviate_hex_line("validator-0x1234567890abcdef".to_owned()), "validator-0x1234567890abcdef");
    }

    #[test]
    fn recursively_lines_nested_outputs() {
        let output = ConsensusLineOutput::Nested(vec![NestedLineOutput {
            label: "0xaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            output: ConsensusLineOutput::HexString("0xbbbbbbbbbbbbbbbbbbbbbbbb".to_owned()),
            _unknown_field_at_0x60: 7,
        }]);

        assert_eq!(
            line_consensus_output(output),
            ConsensusLineOutput::Nested(vec![NestedLineOutput {
                label: "0xaaaa..aaaa".to_owned(),
                output: ConsensusLineOutput::HexString("0xbbbb..bbbb".to_owned()),
                _unknown_field_at_0x60: 7,
            }]),
        );
    }
}
