use std::env;
use std::fs;
use std::io;
use std::path::Path;

pub const CHAM_DIR_SUFFIX: &str = "/cham";
pub const HL_DIR_SUFFIX: &str = "/hl";
pub const CODE_DIR_SUFFIX: &str = "/code";
pub const STATIC_CONFIG_SUFFIX: &str = "/static_config";

pub const DEFAULT_AWS_NAME: AwsName = AwsName::NvTestnet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticConfig {
    pub home_dir: String,
    pub cham_dir: String,
    pub code_dir: String,
    pub aws_name: AwsName,
}

impl StaticConfig {
    pub fn load() -> Self {
        let home_dir = home_dir_string();
        let cham_dir = select_cham_dir(&home_dir)
            .unwrap_or_else(|err| panic!("could not create {}: {}", err.path, err.source));

        if !is_existing_dir(&cham_dir) {
            panic!("cham_dir does not exist: {}", cham_dir);
        }

        let code_dir = append_suffix(&cham_dir, CODE_DIR_SUFFIX);
        let aws_name = read_static_config_aws_name(&code_dir).unwrap_or(DEFAULT_AWS_NAME);

        Self {
            home_dir,
            cham_dir,
            code_dir,
            aws_name,
        }
    }

    pub fn static_config_path(&self) -> String {
        append_suffix(&self.code_dir, STATIC_CONFIG_SUFFIX)
    }
}

pub fn static_config() -> StaticConfig {
    StaticConfig::load()
}

fn home_dir_string() -> String {
    #[allow(deprecated)]
    env::home_dir()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn select_cham_dir(home_dir: &str) -> Result<String, CreateDirError> {
    let cham_dir = append_suffix(home_dir, CHAM_DIR_SUFFIX);
    if is_existing_dir(&cham_dir) {
        return Ok(cham_dir);
    }

    let hl_dir = append_suffix(home_dir, HL_DIR_SUFFIX);
    if !is_existing_dir(&hl_dir) {
        fs::create_dir(&hl_dir).map_err(|source| CreateDirError {
            path: hl_dir.clone(),
            source,
        })?;
    }
    Ok(hl_dir)
}

fn read_static_config_aws_name(code_dir: &str) -> Option<AwsName> {
    let path = append_suffix(code_dir, STATIC_CONFIG_SUFFIX);
    let contents = fs::read_to_string(path).ok()?;
    parse_static_config_aws_name(&contents)
}

fn parse_static_config_aws_name(contents: &str) -> Option<AwsName> {
    let mut cursor = JsonCursor::new(contents);
    cursor.skip_ws();
    if cursor.peek()? != b'{' {
        return AwsName::from_static_config_str(cursor.parse_string()?);
    }

    cursor.bump();
    loop {
        cursor.skip_ws();
        match cursor.peek()? {
            b'}' => return None,
            b'"' => {}
            _ => return None,
        }

        let key = cursor.parse_string()?;
        cursor.skip_ws();
        cursor.expect(b':')?;
        cursor.skip_ws();

        if key == "aws_name" {
            return match cursor.peek()? {
                b'"' => AwsName::from_static_config_str(cursor.parse_string()?),
                b'{' => cursor.parse_externally_tagged_aws_name(),
                _ => None,
            };
        }

        cursor.skip_json_value()?;
        cursor.skip_ws();
        match cursor.peek()? {
            b',' => {
                cursor.bump();
            }
            b'}' => return None,
            _ => return None,
        }
    }
}

fn append_suffix(prefix: &str, suffix: &str) -> String {
    let mut out = String::with_capacity(prefix.len() + suffix.len());
    out.push_str(prefix);
    out.push_str(suffix);
    out
}

fn is_existing_dir(path: &str) -> bool {
    Path::new(path).is_dir()
}

#[derive(Debug)]
struct CreateDirError {
    path: String,
    source: io::Error,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

impl AwsName {
    pub fn from_static_config_str(value: &str) -> Option<Self> {
        Some(match value {
            "Ec" => Self::Ec,
            "DummyTokyo" => Self::DummyTokyo,
            "DummyTokyo2" => Self::DummyTokyo2,
            "GaOnchain" => Self::GaOnchain,
            "GbOnchain" => Self::GbOnchain,
            "NodeTestnet" => Self::NodeTestnet,
            "NodeTestnet2" => Self::NodeTestnet2,
            "NodeTestnet3" => Self::NodeTestnet3,
            "NodeTestnet4" => Self::NodeTestnet4,
            "Ea" => Self::Ea,
            "Ea2" => Self::Ea2,
            "Ea3" => Self::Ea3,
            "EaMm" => Self::EaMm,
            "HeavyTestnet" => Self::HeavyTestnet,
            "HeavyMainnet" => Self::HeavyMainnet,
            "Eb" => Self::Eb,
            "Ed" => Self::Ed,
            "Ee" => Self::Ee,
            "SoloTestnet" => Self::SoloTestnet,
            "SoloMainnet" => Self::SoloMainnet,
            "LockerTestnet" => Self::LockerTestnet,
            "LockerMainnet" => Self::LockerMainnet,
            "RpcTestnet" => Self::RpcTestnet,
            "RpcSandbox" => Self::RpcSandbox,
            "RpcMainnet" => Self::RpcMainnet,
            "RpcMainnet2" => Self::RpcMainnet2,
            "Sa" => Self::Sa,
            "Sb" => Self::Sb,
            "Sc" => Self::Sc,
            "Sd" => Self::Sd,
            "WebSandbox" => Self::WebSandbox,
            "SoloSandbox" => Self::SoloSandbox,
            "NvTestnet" => Self::NvTestnet,
            "NvTestnet2" => Self::NvTestnet2,
            "NvMainnet" => Self::NvMainnet,
            "NvMainnet2" => Self::NvMainnet2,
            "JoinMainnet" => Self::JoinMainnet,
            "FBinSpot" => Self::FBinSpot,
            "FBinSpot2" => Self::FBinSpot2,
            "FBinSpot3" => Self::FBinSpot3,
            "FBinSpot4" => Self::FBinSpot4,
            "FBinSpot5" => Self::FBinSpot5,
            "FBinSpot6" => Self::FBinSpot6,
            "FBinSpot7" => Self::FBinSpot7,
            "FBinSpot8" => Self::FBinSpot8,
            "FBinPerp" => Self::FBinPerp,
            "FBinPerp2" => Self::FBinPerp2,
            "FOkexSpot" => Self::FOkexSpot,
            "FOkexSpot2" => Self::FOkexSpot2,
            "FOkexPerp" => Self::FOkexPerp,
            "FHuobiSpot" => Self::FHuobiSpot,
            "FHuobiSpot2" => Self::FHuobiSpot2,
            "FHuobiSpot3" => Self::FHuobiSpot3,
            "FHuobiSpot4" => Self::FHuobiSpot4,
            "FHuobiPi" => Self::FHuobiPi,
            "FHuobiPerp" => Self::FHuobiPerp,
            "FCobSpot" => Self::FCobSpot,
            "FKraSpot" => Self::FKraSpot,
            "FBybitSpot" => Self::FBybitSpot,
            "ScratchDummy" => Self::ScratchDummy,
            "ScratchCron" => Self::ScratchCron,
            "OBinSpot" => Self::OBinSpot,
            "FHlPerp" => Self::FHlPerp,
            "GaHlPerp" => Self::GaHlPerp,
            "GaHlPerp2" => Self::GaHlPerp2,
            "GaHlPerp3" => Self::GaHlPerp3,
            "GbHlPerp" => Self::GbHlPerp,
            "GbHlPerp2" => Self::GbHlPerp2,
            "GbHlPerp3" => Self::GbHlPerp3,
            "GcHlPerp" => Self::GcHlPerp,
            "GcHlPerp2" => Self::GcHlPerp2,
            "GdHlPerp" => Self::GdHlPerp,
            "GdHlPerp2" => Self::GdHlPerp2,
            "GsHlPerp" => Self::GsHlPerp,
            "EaHlPerp" => Self::EaHlPerp,
            "EbHlPerp" => Self::EbHlPerp,
            _ => return None,
        })
    }
}

struct JsonCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonCursor<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            bytes: input.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }

    fn expect(&mut self, expected: u8) -> Option<()> {
        (self.bump()? == expected).then_some(())
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.pos += 1;
        }
    }

    fn parse_string(&mut self) -> Option<&'a str> {
        self.expect(b'"')?;
        let start = self.pos;
        while let Some(byte) = self.bump() {
            match byte {
                b'"' => return std::str::from_utf8(&self.bytes[start..self.pos - 1]).ok(),
                b'\\' => return None,
                0..=0x1f => return None,
                _ => {}
            }
        }
        None
    }

    fn parse_externally_tagged_aws_name(&mut self) -> Option<AwsName> {
        self.expect(b'{')?;
        self.skip_ws();
        let variant = self.parse_string()?;
        self.skip_ws();
        self.expect(b':')?;
        self.skip_ws();
        self.expect_null()?;
        self.skip_ws();
        self.expect(b'}')?;
        AwsName::from_static_config_str(variant)
    }

    fn expect_null(&mut self) -> Option<()> {
        self.bytes.get(self.pos..self.pos + 4).filter(|value| *value == b"null")?;
        self.pos += 4;
        Some(())
    }

    fn skip_json_value(&mut self) -> Option<()> {
        match self.peek()? {
            b'"' => self.parse_string().map(drop),
            b'{' => self.skip_compound(b'{', b'}'),
            b'[' => self.skip_compound(b'[', b']'),
            b't' => self.skip_literal(b"true"),
            b'f' => self.skip_literal(b"false"),
            b'n' => self.skip_literal(b"null"),
            b'-' | b'0'..=b'9' => self.skip_number(),
            _ => None,
        }
    }

    fn skip_compound(&mut self, open: u8, close: u8) -> Option<()> {
        self.expect(open)?;
        let mut depth = 1usize;
        while let Some(byte) = self.bump() {
            match byte {
                b'"' => {
                    self.pos -= 1;
                    self.parse_string()?;
                }
                value if value == open => depth += 1,
                value if value == close => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(());
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn skip_literal(&mut self, literal: &[u8]) -> Option<()> {
        self.bytes.get(self.pos..self.pos + literal.len()).filter(|value| *value == literal)?;
        self.pos += literal.len();
        Some(())
    }

    fn skip_number(&mut self) -> Option<()> {
        let start = self.pos;
        while matches!(self.peek(), Some(b'-' | b'+' | b'.' | b'0'..=b'9' | b'e' | b'E')) {
            self.pos += 1;
        }
        (self.pos > start).then_some(())
    }
}
