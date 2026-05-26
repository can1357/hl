use std::env;
use std::ffi::CStr;
use std::fmt;
use std::fs;
use std::io;
use std::os::raw::{c_char, c_int, c_long};
use std::path::{Path, PathBuf};
use std::ptr;
use std::str::FromStr;

use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

pub const CHAM_DIR_NAME: &str = "cham";
pub const HL_DIR_NAME: &str = "hl";
pub const AWS_NAME_FILE_NAME: &str = "aws_name";
pub const AWS_NAME_FIELD: &str = "aws_name";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[repr(u8)]
pub enum HlChain {
    Local,
    Sandbox,
    Testnet,
    Mainnet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
pub enum AwsNameBucket {
    Dummy,
    Scratch,
    Onchain,
    TestnetNode,
    Environment,
    Heavy,
    Solo,
    Locker,
    Rpc,
    Short,
    Web,
    Nv,
    Join,
    Feed,
    HyperliquidityPerp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[repr(u8)]
pub enum AwsName {
    Ec = 0,
    DummyTokyo = 1,
    DummyTokyo2 = 2,
    GaOnchain = 3,
    GbOnchain = 4,
    NodeTestnet = 5,
    NodeTestnet2 = 6,
    NodeTestnet3 = 7,
    NodeTestnet4 = 8,
    Ea = 9,
    Ea2 = 10,
    Ea3 = 11,
    EaMm = 12,
    HeavyTestnet = 13,
    HeavyMainnet = 14,
    Eb = 15,
    Ed = 16,
    Ee = 17,
    SoloTestnet = 18,
    SoloMainnet = 19,
    LockerTestnet = 20,
    LockerMainnet = 21,
    RpcTestnet = 22,
    RpcSandbox = 23,
    RpcMainnet = 24,
    RpcMainnet2 = 25,
    Sa = 26,
    Sb = 27,
    Sc = 28,
    Sd = 29,
    WebSandbox = 30,
    SoloSandbox = 31,
    NvTestnet = 32,
    NvTestnet2 = 33,
    NvMainnet = 34,
    NvMainnet2 = 35,
    JoinMainnet = 36,
    FBinSpot = 37,
    FBinSpot2 = 38,
    FBinSpot3 = 39,
    FBinSpot4 = 40,
    FBinSpot5 = 41,
    FBinSpot6 = 42,
    FBinSpot7 = 43,
    FBinSpot8 = 44,
    FBinPerp = 45,
    FBinPerp2 = 46,
    FOkexSpot = 47,
    FOkexSpot2 = 48,
    FOkexPerp = 49,
    FHuobiSpot = 50,
    FHuobiSpot2 = 51,
    FHuobiSpot3 = 52,
    FHuobiSpot4 = 53,
    FHuobiPi = 54,
    FHuobiPerp = 55,
    FCobSpot = 56,
    FKraSpot = 57,
    FBybitSpot = 58,
    ScratchDummy = 59,
    ScratchCron = 60,
    OBinSpot = 61,
    FHlPerp = 62,
    GaHlPerp = 63,
    GaHlPerp2 = 64,
    GaHlPerp3 = 65,
    GbHlPerp = 66,
    GbHlPerp2 = 67,
    GbHlPerp3 = 68,
    GcHlPerp = 69,
    GcHlPerp2 = 70,
    GdHlPerp = 71,
    GdHlPerp2 = 72,
    GsHlPerp = 73,
    EaHlPerp = 74,
    EbHlPerp = 75,
}

pub const AWS_NAME_VARIANTS: [AwsName; 76] = [
    AwsName::Ec,
    AwsName::DummyTokyo,
    AwsName::DummyTokyo2,
    AwsName::GaOnchain,
    AwsName::GbOnchain,
    AwsName::NodeTestnet,
    AwsName::NodeTestnet2,
    AwsName::NodeTestnet3,
    AwsName::NodeTestnet4,
    AwsName::Ea,
    AwsName::Ea2,
    AwsName::Ea3,
    AwsName::EaMm,
    AwsName::HeavyTestnet,
    AwsName::HeavyMainnet,
    AwsName::Eb,
    AwsName::Ed,
    AwsName::Ee,
    AwsName::SoloTestnet,
    AwsName::SoloMainnet,
    AwsName::LockerTestnet,
    AwsName::LockerMainnet,
    AwsName::RpcTestnet,
    AwsName::RpcSandbox,
    AwsName::RpcMainnet,
    AwsName::RpcMainnet2,
    AwsName::Sa,
    AwsName::Sb,
    AwsName::Sc,
    AwsName::Sd,
    AwsName::WebSandbox,
    AwsName::SoloSandbox,
    AwsName::NvTestnet,
    AwsName::NvTestnet2,
    AwsName::NvMainnet,
    AwsName::NvMainnet2,
    AwsName::JoinMainnet,
    AwsName::FBinSpot,
    AwsName::FBinSpot2,
    AwsName::FBinSpot3,
    AwsName::FBinSpot4,
    AwsName::FBinSpot5,
    AwsName::FBinSpot6,
    AwsName::FBinSpot7,
    AwsName::FBinSpot8,
    AwsName::FBinPerp,
    AwsName::FBinPerp2,
    AwsName::FOkexSpot,
    AwsName::FOkexSpot2,
    AwsName::FOkexPerp,
    AwsName::FHuobiSpot,
    AwsName::FHuobiSpot2,
    AwsName::FHuobiSpot3,
    AwsName::FHuobiSpot4,
    AwsName::FHuobiPi,
    AwsName::FHuobiPerp,
    AwsName::FCobSpot,
    AwsName::FKraSpot,
    AwsName::FBybitSpot,
    AwsName::ScratchDummy,
    AwsName::ScratchCron,
    AwsName::OBinSpot,
    AwsName::FHlPerp,
    AwsName::GaHlPerp,
    AwsName::GaHlPerp2,
    AwsName::GaHlPerp3,
    AwsName::GbHlPerp,
    AwsName::GbHlPerp2,
    AwsName::GbHlPerp3,
    AwsName::GcHlPerp,
    AwsName::GcHlPerp2,
    AwsName::GdHlPerp,
    AwsName::GdHlPerp2,
    AwsName::GsHlPerp,
    AwsName::EaHlPerp,
    AwsName::EbHlPerp,
];

pub const AWS_NAME_STRINGS: [&str; 76] = [
    "Ec",
    "DummyTokyo",
    "DummyTokyo2",
    "GaOnchain",
    "GbOnchain",
    "NodeTestnet",
    "NodeTestnet2",
    "NodeTestnet3",
    "NodeTestnet4",
    "Ea",
    "Ea2",
    "Ea3",
    "EaMm",
    "HeavyTestnet",
    "HeavyMainnet",
    "Eb",
    "Ed",
    "Ee",
    "SoloTestnet",
    "SoloMainnet",
    "LockerTestnet",
    "LockerMainnet",
    "RpcTestnet",
    "RpcSandbox",
    "RpcMainnet",
    "RpcMainnet2",
    "Sa",
    "Sb",
    "Sc",
    "Sd",
    "WebSandbox",
    "SoloSandbox",
    "NvTestnet",
    "NvTestnet2",
    "NvMainnet",
    "NvMainnet2",
    "JoinMainnet",
    "FBinSpot",
    "FBinSpot2",
    "FBinSpot3",
    "FBinSpot4",
    "FBinSpot5",
    "FBinSpot6",
    "FBinSpot7",
    "FBinSpot8",
    "FBinPerp",
    "FBinPerp2",
    "FOkexSpot",
    "FOkexSpot2",
    "FOkexPerp",
    "FHuobiSpot",
    "FHuobiSpot2",
    "FHuobiSpot3",
    "FHuobiSpot4",
    "FHuobiPi",
    "FHuobiPerp",
    "FCobSpot",
    "FKraSpot",
    "FBybitSpot",
    "ScratchDummy",
    "ScratchCron",
    "OBinSpot",
    "FHlPerp",
    "GaHlPerp",
    "GaHlPerp2",
    "GaHlPerp3",
    "GbHlPerp",
    "GbHlPerp2",
    "GbHlPerp3",
    "GcHlPerp",
    "GcHlPerp2",
    "GdHlPerp",
    "GdHlPerp2",
    "GsHlPerp",
    "EaHlPerp",
    "EbHlPerp",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VariantNotFound;

impl AwsName {
    pub const fn as_str(self) -> &'static str {
        match self {
            AwsName::Ec => "Ec",
            AwsName::DummyTokyo => "DummyTokyo",
            AwsName::DummyTokyo2 => "DummyTokyo2",
            AwsName::GaOnchain => "GaOnchain",
            AwsName::GbOnchain => "GbOnchain",
            AwsName::NodeTestnet => "NodeTestnet",
            AwsName::NodeTestnet2 => "NodeTestnet2",
            AwsName::NodeTestnet3 => "NodeTestnet3",
            AwsName::NodeTestnet4 => "NodeTestnet4",
            AwsName::Ea => "Ea",
            AwsName::Ea2 => "Ea2",
            AwsName::Ea3 => "Ea3",
            AwsName::EaMm => "EaMm",
            AwsName::HeavyTestnet => "HeavyTestnet",
            AwsName::HeavyMainnet => "HeavyMainnet",
            AwsName::Eb => "Eb",
            AwsName::Ed => "Ed",
            AwsName::Ee => "Ee",
            AwsName::SoloTestnet => "SoloTestnet",
            AwsName::SoloMainnet => "SoloMainnet",
            AwsName::LockerTestnet => "LockerTestnet",
            AwsName::LockerMainnet => "LockerMainnet",
            AwsName::RpcTestnet => "RpcTestnet",
            AwsName::RpcSandbox => "RpcSandbox",
            AwsName::RpcMainnet => "RpcMainnet",
            AwsName::RpcMainnet2 => "RpcMainnet2",
            AwsName::Sa => "Sa",
            AwsName::Sb => "Sb",
            AwsName::Sc => "Sc",
            AwsName::Sd => "Sd",
            AwsName::WebSandbox => "WebSandbox",
            AwsName::SoloSandbox => "SoloSandbox",
            AwsName::NvTestnet => "NvTestnet",
            AwsName::NvTestnet2 => "NvTestnet2",
            AwsName::NvMainnet => "NvMainnet",
            AwsName::NvMainnet2 => "NvMainnet2",
            AwsName::JoinMainnet => "JoinMainnet",
            AwsName::FBinSpot => "FBinSpot",
            AwsName::FBinSpot2 => "FBinSpot2",
            AwsName::FBinSpot3 => "FBinSpot3",
            AwsName::FBinSpot4 => "FBinSpot4",
            AwsName::FBinSpot5 => "FBinSpot5",
            AwsName::FBinSpot6 => "FBinSpot6",
            AwsName::FBinSpot7 => "FBinSpot7",
            AwsName::FBinSpot8 => "FBinSpot8",
            AwsName::FBinPerp => "FBinPerp",
            AwsName::FBinPerp2 => "FBinPerp2",
            AwsName::FOkexSpot => "FOkexSpot",
            AwsName::FOkexSpot2 => "FOkexSpot2",
            AwsName::FOkexPerp => "FOkexPerp",
            AwsName::FHuobiSpot => "FHuobiSpot",
            AwsName::FHuobiSpot2 => "FHuobiSpot2",
            AwsName::FHuobiSpot3 => "FHuobiSpot3",
            AwsName::FHuobiSpot4 => "FHuobiSpot4",
            AwsName::FHuobiPi => "FHuobiPi",
            AwsName::FHuobiPerp => "FHuobiPerp",
            AwsName::FCobSpot => "FCobSpot",
            AwsName::FKraSpot => "FKraSpot",
            AwsName::FBybitSpot => "FBybitSpot",
            AwsName::ScratchDummy => "ScratchDummy",
            AwsName::ScratchCron => "ScratchCron",
            AwsName::OBinSpot => "OBinSpot",
            AwsName::FHlPerp => "FHlPerp",
            AwsName::GaHlPerp => "GaHlPerp",
            AwsName::GaHlPerp2 => "GaHlPerp2",
            AwsName::GaHlPerp3 => "GaHlPerp3",
            AwsName::GbHlPerp => "GbHlPerp",
            AwsName::GbHlPerp2 => "GbHlPerp2",
            AwsName::GbHlPerp3 => "GbHlPerp3",
            AwsName::GcHlPerp => "GcHlPerp",
            AwsName::GcHlPerp2 => "GcHlPerp2",
            AwsName::GdHlPerp => "GdHlPerp",
            AwsName::GdHlPerp2 => "GdHlPerp2",
            AwsName::GsHlPerp => "GsHlPerp",
            AwsName::EaHlPerp => "EaHlPerp",
            AwsName::EbHlPerp => "EbHlPerp",
        }
    }

    pub const fn bucket(self) -> AwsNameBucket {
        match self {
            AwsName::Ec | AwsName::DummyTokyo | AwsName::DummyTokyo2 => AwsNameBucket::Dummy,
            AwsName::ScratchDummy | AwsName::ScratchCron => AwsNameBucket::Scratch,
            AwsName::GaOnchain | AwsName::GbOnchain => AwsNameBucket::Onchain,
            AwsName::NodeTestnet
            | AwsName::NodeTestnet2
            | AwsName::NodeTestnet3
            | AwsName::NodeTestnet4 => AwsNameBucket::TestnetNode,
            AwsName::Ea
            | AwsName::Ea2
            | AwsName::Ea3
            | AwsName::EaMm
            | AwsName::Eb
            | AwsName::Ed
            | AwsName::Ee => AwsNameBucket::Environment,
            AwsName::HeavyTestnet | AwsName::HeavyMainnet => AwsNameBucket::Heavy,
            AwsName::SoloTestnet | AwsName::SoloMainnet | AwsName::SoloSandbox => AwsNameBucket::Solo,
            AwsName::LockerTestnet | AwsName::LockerMainnet => AwsNameBucket::Locker,
            AwsName::RpcTestnet | AwsName::RpcSandbox | AwsName::RpcMainnet | AwsName::RpcMainnet2 => AwsNameBucket::Rpc,
            AwsName::Sa | AwsName::Sb | AwsName::Sc | AwsName::Sd => AwsNameBucket::Short,
            AwsName::WebSandbox => AwsNameBucket::Web,
            AwsName::NvTestnet | AwsName::NvTestnet2 | AwsName::NvMainnet | AwsName::NvMainnet2 => AwsNameBucket::Nv,
            AwsName::JoinMainnet => AwsNameBucket::Join,
            AwsName::FBinSpot
            | AwsName::FBinSpot2
            | AwsName::FBinSpot3
            | AwsName::FBinSpot4
            | AwsName::FBinSpot5
            | AwsName::FBinSpot6
            | AwsName::FBinSpot7
            | AwsName::FBinSpot8
            | AwsName::FBinPerp
            | AwsName::FBinPerp2
            | AwsName::FOkexSpot
            | AwsName::FOkexSpot2
            | AwsName::FOkexPerp
            | AwsName::FHuobiSpot
            | AwsName::FHuobiSpot2
            | AwsName::FHuobiSpot3
            | AwsName::FHuobiSpot4
            | AwsName::FHuobiPi
            | AwsName::FHuobiPerp
            | AwsName::FCobSpot
            | AwsName::FKraSpot
            | AwsName::FBybitSpot
            | AwsName::OBinSpot => AwsNameBucket::Feed,
            AwsName::FHlPerp
            | AwsName::GaHlPerp
            | AwsName::GaHlPerp2
            | AwsName::GaHlPerp3
            | AwsName::GbHlPerp
            | AwsName::GbHlPerp2
            | AwsName::GbHlPerp3
            | AwsName::GcHlPerp
            | AwsName::GcHlPerp2
            | AwsName::GdHlPerp
            | AwsName::GdHlPerp2
            | AwsName::GsHlPerp
            | AwsName::EaHlPerp
            | AwsName::EbHlPerp => AwsNameBucket::HyperliquidityPerp,
        }
    }

    // Chain suffixes are explicit in the recovered variant spellings. Chain-neutral
    // infra/feed/perp names deliberately return None instead of inventing a chain.
    pub const fn chain_hint(self) -> Option<HlChain> {
        match self {
            AwsName::RpcSandbox | AwsName::WebSandbox | AwsName::SoloSandbox => Some(HlChain::Sandbox),
            AwsName::NodeTestnet
            | AwsName::NodeTestnet2
            | AwsName::NodeTestnet3
            | AwsName::NodeTestnet4
            | AwsName::HeavyTestnet
            | AwsName::SoloTestnet
            | AwsName::LockerTestnet
            | AwsName::RpcTestnet
            | AwsName::NvTestnet
            | AwsName::NvTestnet2 => Some(HlChain::Testnet),
            AwsName::GaOnchain
            | AwsName::GbOnchain
            | AwsName::HeavyMainnet
            | AwsName::SoloMainnet
            | AwsName::LockerMainnet
            | AwsName::RpcMainnet
            | AwsName::RpcMainnet2
            | AwsName::NvMainnet
            | AwsName::NvMainnet2
            | AwsName::JoinMainnet => Some(HlChain::Mainnet),
            AwsName::Ec
            | AwsName::DummyTokyo
            | AwsName::DummyTokyo2
            | AwsName::Ea
            | AwsName::Ea2
            | AwsName::Ea3
            | AwsName::EaMm
            | AwsName::Eb
            | AwsName::Ed
            | AwsName::Ee
            | AwsName::Sa
            | AwsName::Sb
            | AwsName::Sc
            | AwsName::Sd
            | AwsName::ScratchDummy
            | AwsName::ScratchCron
            | AwsName::FBinSpot
            | AwsName::FBinSpot2
            | AwsName::FBinSpot3
            | AwsName::FBinSpot4
            | AwsName::FBinSpot5
            | AwsName::FBinSpot6
            | AwsName::FBinSpot7
            | AwsName::FBinSpot8
            | AwsName::FBinPerp
            | AwsName::FBinPerp2
            | AwsName::FOkexSpot
            | AwsName::FOkexSpot2
            | AwsName::FOkexPerp
            | AwsName::FHuobiSpot
            | AwsName::FHuobiSpot2
            | AwsName::FHuobiSpot3
            | AwsName::FHuobiSpot4
            | AwsName::FHuobiPi
            | AwsName::FHuobiPerp
            | AwsName::FCobSpot
            | AwsName::FKraSpot
            | AwsName::FBybitSpot
            | AwsName::OBinSpot
            | AwsName::FHlPerp
            | AwsName::GaHlPerp
            | AwsName::GaHlPerp2
            | AwsName::GaHlPerp3
            | AwsName::GbHlPerp
            | AwsName::GbHlPerp2
            | AwsName::GbHlPerp3
            | AwsName::GcHlPerp
            | AwsName::GcHlPerp2
            | AwsName::GdHlPerp
            | AwsName::GdHlPerp2
            | AwsName::GsHlPerp
            | AwsName::EaHlPerp
            | AwsName::EbHlPerp => None,
        }
    }

    pub fn parse_trimmed(input: &str) -> Result<Self, VariantNotFound> {
        input.trim().parse()
    }
}

impl fmt::Display for AwsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AwsName {
    type Err = VariantNotFound;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Ec" => Ok(AwsName::Ec),
            "DummyTokyo" => Ok(AwsName::DummyTokyo),
            "DummyTokyo2" => Ok(AwsName::DummyTokyo2),
            "GaOnchain" => Ok(AwsName::GaOnchain),
            "GbOnchain" => Ok(AwsName::GbOnchain),
            "NodeTestnet" => Ok(AwsName::NodeTestnet),
            "NodeTestnet2" => Ok(AwsName::NodeTestnet2),
            "NodeTestnet3" => Ok(AwsName::NodeTestnet3),
            "NodeTestnet4" => Ok(AwsName::NodeTestnet4),
            "Ea" => Ok(AwsName::Ea),
            "Ea2" => Ok(AwsName::Ea2),
            "Ea3" => Ok(AwsName::Ea3),
            "EaMm" => Ok(AwsName::EaMm),
            "HeavyTestnet" => Ok(AwsName::HeavyTestnet),
            "HeavyMainnet" => Ok(AwsName::HeavyMainnet),
            "Eb" => Ok(AwsName::Eb),
            "Ed" => Ok(AwsName::Ed),
            "Ee" => Ok(AwsName::Ee),
            "SoloTestnet" => Ok(AwsName::SoloTestnet),
            "SoloMainnet" => Ok(AwsName::SoloMainnet),
            "LockerTestnet" => Ok(AwsName::LockerTestnet),
            "LockerMainnet" => Ok(AwsName::LockerMainnet),
            "RpcTestnet" => Ok(AwsName::RpcTestnet),
            "RpcSandbox" => Ok(AwsName::RpcSandbox),
            "RpcMainnet" => Ok(AwsName::RpcMainnet),
            "RpcMainnet2" => Ok(AwsName::RpcMainnet2),
            "Sa" => Ok(AwsName::Sa),
            "Sb" => Ok(AwsName::Sb),
            "Sc" => Ok(AwsName::Sc),
            "Sd" => Ok(AwsName::Sd),
            "WebSandbox" => Ok(AwsName::WebSandbox),
            "SoloSandbox" => Ok(AwsName::SoloSandbox),
            "NvTestnet" => Ok(AwsName::NvTestnet),
            "NvTestnet2" => Ok(AwsName::NvTestnet2),
            "NvMainnet" => Ok(AwsName::NvMainnet),
            "NvMainnet2" => Ok(AwsName::NvMainnet2),
            "JoinMainnet" => Ok(AwsName::JoinMainnet),
            "FBinSpot" => Ok(AwsName::FBinSpot),
            "FBinSpot2" => Ok(AwsName::FBinSpot2),
            "FBinSpot3" => Ok(AwsName::FBinSpot3),
            "FBinSpot4" => Ok(AwsName::FBinSpot4),
            "FBinSpot5" => Ok(AwsName::FBinSpot5),
            "FBinSpot6" => Ok(AwsName::FBinSpot6),
            "FBinSpot7" => Ok(AwsName::FBinSpot7),
            "FBinSpot8" => Ok(AwsName::FBinSpot8),
            "FBinPerp" => Ok(AwsName::FBinPerp),
            "FBinPerp2" => Ok(AwsName::FBinPerp2),
            "FOkexSpot" => Ok(AwsName::FOkexSpot),
            "FOkexSpot2" => Ok(AwsName::FOkexSpot2),
            "FOkexPerp" => Ok(AwsName::FOkexPerp),
            "FHuobiSpot" => Ok(AwsName::FHuobiSpot),
            "FHuobiSpot2" => Ok(AwsName::FHuobiSpot2),
            "FHuobiSpot3" => Ok(AwsName::FHuobiSpot3),
            "FHuobiSpot4" => Ok(AwsName::FHuobiSpot4),
            "FHuobiPi" => Ok(AwsName::FHuobiPi),
            "FHuobiPerp" => Ok(AwsName::FHuobiPerp),
            "FCobSpot" => Ok(AwsName::FCobSpot),
            "FKraSpot" => Ok(AwsName::FKraSpot),
            "FBybitSpot" => Ok(AwsName::FBybitSpot),
            "ScratchDummy" => Ok(AwsName::ScratchDummy),
            "ScratchCron" => Ok(AwsName::ScratchCron),
            "OBinSpot" => Ok(AwsName::OBinSpot),
            "FHlPerp" => Ok(AwsName::FHlPerp),
            "GaHlPerp" => Ok(AwsName::GaHlPerp),
            "GaHlPerp2" => Ok(AwsName::GaHlPerp2),
            "GaHlPerp3" => Ok(AwsName::GaHlPerp3),
            "GbHlPerp" => Ok(AwsName::GbHlPerp),
            "GbHlPerp2" => Ok(AwsName::GbHlPerp2),
            "GbHlPerp3" => Ok(AwsName::GbHlPerp3),
            "GcHlPerp" => Ok(AwsName::GcHlPerp),
            "GcHlPerp2" => Ok(AwsName::GcHlPerp2),
            "GdHlPerp" => Ok(AwsName::GdHlPerp),
            "GdHlPerp2" => Ok(AwsName::GdHlPerp2),
            "GsHlPerp" => Ok(AwsName::GsHlPerp),
            "EaHlPerp" => Ok(AwsName::EaHlPerp),
            "EbHlPerp" => Ok(AwsName::EbHlPerp),
            _ => Err(VariantNotFound),
        }
    }
}

impl<'de> Deserialize<'de> for AwsName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(AwsNameVisitor)
    }
}

struct AwsNameVisitor;

impl<'de> Visitor<'de> for AwsNameVisitor {
    type Value = AwsName;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an AWS name variant or an object with an aws_name field")
    }

    fn visit_str<E>(self, value: &str) -> Result<AwsName, E>
    where
        E: de::Error,
    {
        value.parse().map_err(|_| E::unknown_variant(value, &AWS_NAME_STRINGS))
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<AwsName, E>
    where
        E: de::Error,
    {
        self.visit_str(value)
    }

    fn visit_string<E>(self, value: String) -> Result<AwsName, E>
    where
        E: de::Error,
    {
        self.visit_str(&value)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<AwsName, A::Error>
    where
        A: SeqAccess<'de>,
    {
        match seq.next_element::<AwsName>()? {
            Some(value) => Ok(value),
            None => Ok(current()),
        }
    }

    fn visit_map<A>(self, mut map: A) -> Result<AwsName, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut aws_name = None;
        while let Some(key) = map.next_key::<String>()? {
            if key == AWS_NAME_FIELD {
                if aws_name.is_some() {
                    return Err(de::Error::duplicate_field(AWS_NAME_FIELD));
                }
                aws_name = Some(map.next_value::<AwsName>()?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(aws_name.unwrap_or_else(current))
    }
}

pub fn home_dir_string() -> io::Result<String> {
    if let Some(home) = env::var("HOME").ok().filter(|home| !home.is_empty()) {
        return Ok(home);
    }

    passwd_home_dir().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "home directory not found"))
}

#[cfg(unix)]
fn passwd_home_dir() -> Option<String> {
    #[repr(C)]
    struct Passwd {
        pw_name: *mut c_char,
        pw_passwd: *mut c_char,
        pw_uid: u32,
        pw_gid: u32,
        pw_gecos: *mut c_char,
        pw_dir: *mut c_char,
        pw_shell: *mut c_char,
    }

    unsafe extern "C" {
        fn getuid() -> u32;
        fn getpwuid_r(
            uid: u32,
            pwd: *mut Passwd,
            buf: *mut c_char,
            buflen: usize,
            result: *mut *mut Passwd,
        ) -> c_int;
        fn sysconf(name: c_int) -> c_long;
    }

    const _SC_GETPW_R_SIZE_MAX: c_int = 70;

    unsafe {
        let size = match sysconf(_SC_GETPW_R_SIZE_MAX) {
            n if n > 0 => n as usize,
            _ => 512,
        };
        let mut buf = vec![0u8; size];
        let mut pwd = Passwd {
            pw_name: ptr::null_mut(),
            pw_passwd: ptr::null_mut(),
            pw_uid: 0,
            pw_gid: 0,
            pw_gecos: ptr::null_mut(),
            pw_dir: ptr::null_mut(),
            pw_shell: ptr::null_mut(),
        };
        let mut result = ptr::null_mut();
        if getpwuid_r(getuid(), &mut pwd, buf.as_mut_ptr().cast(), buf.len(), &mut result) != 0
            || result.is_null()
            || pwd.pw_dir.is_null()
        {
            return None;
        }

        let home = CStr::from_ptr(pwd.pw_dir).to_str().ok()?;
        if home.is_empty() {
            None
        } else {
            Some(home.to_owned())
        }
    }
}

#[cfg(not(unix))]
fn passwd_home_dir() -> Option<String> {
    None
}

pub fn select_code_dir_from_home(home: impl AsRef<Path>) -> PathBuf {
    let home = home.as_ref();
    let cham = home.join(CHAM_DIR_NAME);
    if cham.is_dir() {
        return cham;
    }

    let hl = home.join(HL_DIR_NAME);
    if !hl.is_dir() {
        fs::create_dir_all(&hl).unwrap_or_else(|err| panic!("could not create {}: {}", hl.display(), err));
    }
    hl
}

pub fn selected_code_dir() -> PathBuf {
    select_code_dir_from_home(home_dir_string().unwrap())
}

pub fn aws_name_path_in(code_dir: impl AsRef<Path>) -> PathBuf {
    code_dir.as_ref().join(AWS_NAME_FILE_NAME)
}

pub fn aws_name_path() -> PathBuf {
    aws_name_path_in(selected_code_dir())
}

pub fn read_aws_name_file() -> io::Result<String> {
    fs::read_to_string(aws_name_path())
}

pub fn current() -> AwsName {
    AwsName::parse_trimmed(&read_aws_name_file().unwrap()).unwrap()
}
