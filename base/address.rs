use std::fmt;
use std::convert::TryFrom;
use std::str::FromStr;

/// Fixed-width EVM-style account address.
///
/// Evidence: `base_address__from_str` at `0x1444A00` writes exactly twenty decoded
/// bytes into the success arm and rejects decoded input that is shorter or longer.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Address(pub [u8; Address::LEN]);

impl Address {
    pub const LEN: usize = 20;
    pub const HEX_LEN: usize = Self::LEN * 2;

    #[inline]
    pub const fn new(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    #[inline]
    pub const fn zero() -> Self {
        Self([0; Self::LEN])
    }

    #[inline]
    pub const fn as_array(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    #[inline]
    pub const fn into_array(self) -> [u8; Self::LEN] {
        self.0
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Decode an address string using the recovered parser rules.
    ///
    /// The binary accepts an optional leading `0x`. After that prefix, at least forty
    /// bytes must remain. If more than forty bytes remain, every character before the
    /// final forty-byte window must be the character `'0'`; otherwise the parser emits
    /// `"trailing characters of Address string must be '0'"`.
    pub fn parse(value: &str) -> Result<Self, AddressParseError> {
        value.parse()
    }
}

impl From<[u8; Address::LEN]> for Address {
    #[inline]
    fn from(bytes: [u8; Address::LEN]) -> Self {
        Self(bytes)
    }
}

impl From<Address> for [u8; Address::LEN] {
    #[inline]
    fn from(address: Address) -> Self {
        address.0
    }
}

impl AsRef<[u8; Address::LEN]> for Address {
    #[inline]
    fn as_ref(&self) -> &[u8; Address::LEN] {
        &self.0
    }
}

impl AsRef<[u8]> for Address {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Address {
    type Error = AddressParseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != Self::LEN {
            return Err(AddressParseError::InvalidStringLength);
        }

        let mut out = [0u8; Self::LEN];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }
}

impl FromStr for Address {
    type Err = AddressParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let bytes = value.as_bytes();
        if bytes.len() < 2 {
            return Err(AddressParseError::StringTooShort);
        }

        let body = if bytes.starts_with(b"0x") {
            &value[2..]
        } else {
            value
        };

        if body.len() < Self::HEX_LEN {
            return Err(AddressParseError::StringTooShort);
        }

        let padding_len = body.len() - Self::HEX_LEN;

        // The recovered code slices by this byte index and lets Rust's str boundary
        // check panic if the index falls inside a multi-byte scalar.
        let padding = &body[..padding_len];
        for ch in padding.chars() {
            if ch != '0' {
                return Err(AddressParseError::NonZeroPadding);
            }
        }

        let mut hex = &body[padding_len..];
        if hex.as_bytes().starts_with(b"0x") {
            hex = &hex[2..];
        }

        decode_exact_20(hex)
    }
}

impl fmt::LowerHex for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `0x4E11B20` writes this prefix only for alternate lower-hex formatting.
        if f.alternate() {
            f.write_str("0x")?;
        }

        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }

        Ok(())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Callers format addresses with the conventional `0x` prefix.
        write!(f, "{self:#x}")
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({self})")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AddressParseError {
    StringTooShort,
    NonZeroPadding,
    InvalidStringLength,
    InvalidHexCharacter { c: char, index: usize },
}

impl fmt::Display for AddressParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StringTooShort => f.write_str("string too short to be Address"),
            Self::NonZeroPadding => {
                f.write_str("trailing characters of Address string must be '0'")
            }
            Self::InvalidStringLength => f.write_str("Invalid string length"),
            Self::InvalidHexCharacter { c, index } => {
                write!(f, "Invalid character '{c}' at position {index}")
            }
        }
    }
}

impl std::error::Error for AddressParseError {}

fn decode_exact_20(input: &str) -> Result<Address, AddressParseError> {
    let mut decoder = HexByteDecoder::new(input);
    let mut out = [0u8; Address::LEN];

    for slot in &mut out {
        *slot = match decoder.next_byte()? {
            Some(byte) => byte,
            None => return Err(AddressParseError::InvalidStringLength),
        };
    }

    if decoder.next_byte()?.is_some() {
        return Err(AddressParseError::InvalidStringLength);
    }

    Ok(Address(out))
}

struct HexByteDecoder<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> HexByteDecoder<'a> {
    #[inline]
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn next_byte(&mut self) -> Result<Option<u8>, AddressParseError> {
        let Some((hi, _hi_pos)) = self.next_nibble()? else {
            return Ok(None);
        };
        let Some((lo, _lo_pos)) = self.next_nibble()? else {
            return Err(AddressParseError::InvalidStringLength);
        };
        Ok(Some((hi << 4) | lo))
    }

    fn next_nibble(&mut self) -> Result<Option<(u8, usize)>, AddressParseError> {
        while self.pos < self.input.len() {
            let byte = self.input.as_bytes()[self.pos];
            let index = self.pos;
            self.pos += 1;

            match byte {
                b'0'..=b'9' => return Ok(Some((byte - b'0', index))),
                b'a'..=b'f' => return Ok(Some((byte - b'a' + 10, index))),
                b'A'..=b'F' => return Ok(Some((byte - b'A' + 10, index))),
                b'\t' | b'\n' | b'\r' | b' ' => continue,
                0x00..=0x7f => {
                    return Err(AddressParseError::InvalidHexCharacter {
                        c: byte as char,
                        index,
                    });
                }
                _ => {
                    let ch = self.input[index..].chars().next().expect("valid UTF-8");
                    self.pos = index + ch.len_utf8();
                    return Err(AddressParseError::InvalidHexCharacter { c: ch, index });
                }
            }
        }

        Ok(None)
    }
}
