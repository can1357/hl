use std::collections::BTreeSet;
use std::sync::LazyLock;

pub type Address = [u8; 20];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum HlChain {
    Local = 0,
    Sandbox = 1,
    Testnet = 2,
    Mainnet = 3,
}

impl HlChain {
    #[inline]
    pub const fn from_discriminant(discriminant: u8) -> Option<Self> {
        match discriminant {
            0 => Some(Self::Local),
            1 => Some(Self::Sandbox),
            2 => Some(Self::Testnet),
            3 => Some(Self::Mainnet),
            _ => None,
        }
    }

    #[inline]
    pub const fn discriminant(self) -> u8 {
        self as u8
    }

    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Sandbox => "sandbox",
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }
}

pub trait ChainExt: Copy {
    fn chain_discriminant(self) -> u8;

    #[inline]
    fn chain(self) -> Option<HlChain> {
        HlChain::from_discriminant(self.chain_discriminant())
    }

    #[inline]
    fn is_mainnet(self) -> bool {
        self.chain_discriminant() == HlChain::Mainnet as u8
    }

    #[inline]
    fn is_testing(self) -> bool {
        matches!(self.chain_discriminant(), 0 | 1 | 2)
    }

    #[inline]
    fn has_foundation_extension_set(self) -> bool {
        matches!(self.chain_discriminant(), 1 | 2 | 3)
    }

    /// Canonical EIP-712 source byte: mainnet signs with `a`, every other observed chain with `b`.
    #[inline]
    fn agent_source_byte(self) -> u8 {
        if self.is_mainnet() { b'a' } else { b'b' }
    }

    /// Foundation signer addresses whose validator address is also the signing address.
    ///
    /// Local chain deliberately has no recovered set and panics with `invalid chain` in the binary.
    fn foundation_self_signer_addresses(self) -> &'static BTreeSet<Address> {
        match self.chain_discriminant() {
            1 => sandbox_self_signers(),
            2 => testnet_self_signers(),
            3 => mainnet_self_signers(),
            _ => panic!("invalid chain"),
        }
    }

    /// Foundation validator addresses.
    ///
    /// On mainnet this differs from `foundation_self_signer_addresses`: Foundation 5 validates as
    /// `0x66be52ec79f829cc88e5778a255e2cb9492798fd` but signs with
    /// `0x5795ab6e71ecbefa255fc4728cc34893ba992d44`.
    fn foundation_validator_addresses(self) -> &'static BTreeSet<Address> {
        match self.chain_discriminant() {
            3 => mainnet_foundation_validators(),
            _ => self.foundation_self_signer_addresses(),
        }
    }

    /// Foundation signer addresses, including the mainnet Foundation 5 signer override.
    fn foundation_signer_addresses(self) -> &'static BTreeSet<Address> {
        match self.chain_discriminant() {
            3 => mainnet_foundation_signers(),
            _ => self.foundation_self_signer_addresses(),
        }
    }

    #[inline]
    fn is_foundation_self_signer(self, address: &Address) -> bool {
        self.foundation_self_signer_addresses().contains(address)
    }

    #[inline]
    fn is_foundation_validator(self, address: &Address) -> bool {
        self.foundation_validator_addresses().contains(address)
    }

    #[inline]
    fn is_foundation_signer(self, address: &Address) -> bool {
        self.foundation_signer_addresses().contains(address)
    }
}

impl ChainExt for HlChain {
    #[inline]
    fn chain_discriminant(self) -> u8 {
        self.discriminant()
    }
}

impl ChainExt for u8 {
    #[inline]
    fn chain_discriminant(self) -> u8 {
        self
    }
}

static SANDBOX_SELF_SIGNERS: LazyLock<BTreeSet<Address>> = LazyLock::new(|| {
    set_from_array([
        addr(0x7db9972a235370a3, 0x11d0ae3dfc545a95, 0x4c786599),
        addr(0xa40cf273de4f7727, 0x8b911dd4c6a023d6, 0x0647d979),
        addr(0xa89a7f8ab7bcf9c5, 0x7542e22dc0e4b768, 0xb0101762),
        addr(0xf027b2abfa8de836, 0xd8cdcce22af88bb8, 0xaacef849),
    ])
});

static TESTNET_SELF_SIGNERS: LazyLock<BTreeSet<Address>> = LazyLock::new(|| {
    set_from_array([
        addr(0x172054cfc01b32ef, 0xfe0bf6af7a15b36e, 0x1ad730b3),
        addr(0x3c83a5cae32a05e8, 0x8ca6a0350edb5401, 0x94851a76),
        addr(0x4dbf394da4b348b8, 0x8e8090d22051af83, 0xe4cbaef4),
        addr(0x946bf3135c7d15e4, 0x462b510f74b6e304, 0xaabb5b21),
    ])
});

static MAINNET_SELF_SIGNERS: LazyLock<BTreeSet<Address>> = LazyLock::new(|| {
    set_from_array(MAINNET_SELF_SIGNER_ADDRESSES)
});

static MAINNET_FOUNDATION_VALIDATORS: LazyLock<BTreeSet<Address>> = LazyLock::new(|| {
    let mut addresses = set_from_array(MAINNET_SELF_SIGNER_ADDRESSES);
    addresses.insert(FOUNDATION_5_VALIDATOR_ADDRESS);
    addresses
});

static MAINNET_FOUNDATION_SIGNERS: LazyLock<BTreeSet<Address>> = LazyLock::new(|| {
    let mut addresses = set_from_array(MAINNET_SELF_SIGNER_ADDRESSES);
    addresses.insert(FOUNDATION_5_SIGNER_ADDRESS);
    addresses
});

pub fn sandbox_self_signers() -> &'static BTreeSet<Address> {
    &*SANDBOX_SELF_SIGNERS
}

pub fn testnet_self_signers() -> &'static BTreeSet<Address> {
    &*TESTNET_SELF_SIGNERS
}

pub fn mainnet_self_signers() -> &'static BTreeSet<Address> {
    &*MAINNET_SELF_SIGNERS
}

pub fn mainnet_foundation_validators() -> &'static BTreeSet<Address> {
    &*MAINNET_FOUNDATION_VALIDATORS
}

pub fn mainnet_foundation_signers() -> &'static BTreeSet<Address> {
    &*MAINNET_FOUNDATION_SIGNERS
}

const MAINNET_SELF_SIGNER_ADDRESSES: [Address; 4] = [
    addr(0x5ac99df645f34148, 0x76c816caa18b2d23, 0x4024b487),
    addr(0x80f0cd23da5bf3a0, 0x101110cfd0f89c8a, 0x69a1384d),
    addr(0xa82fe73bbd768bc1, 0x5d1ef2f6142a21ff, 0x8bd762ad),
    addr(0xdf35aee8ef565868, 0x6142acd1e5ab5dbc, 0xdf8c51e8),
];

pub const FOUNDATION_5_VALIDATOR_ADDRESS: Address =
    addr(0x66be52ec79f829cc, 0x88e5778a255e2cb9, 0x492798fd);
pub const FOUNDATION_5_SIGNER_ADDRESS: Address =
    addr(0x5795ab6e71ecbefa, 0x255fc4728cc34893, 0xba992d44);

#[inline]
fn set_from_array<const N: usize>(addresses: [Address; N]) -> BTreeSet<Address> {
    addresses.into_iter().collect()
}

#[inline]
pub const fn addr(high: u64, mid: u64, low: u32) -> Address {
    let high = high.to_be_bytes();
    let mid = mid.to_be_bytes();
    let low = low.to_be_bytes();
    [
        high[0], high[1], high[2], high[3], high[4], high[5], high[6], high[7], mid[0], mid[1],
        mid[2], mid[3], mid[4], mid[5], mid[6], mid[7], low[0], low[1], low[2], low[3],
    ]
}
