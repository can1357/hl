use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub type Dex = String;
pub type Coin = String;
pub type Token = String;
pub type Outcome = String;
pub type Question = String;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Address(pub String);

impl Address {
    pub fn validate_str(value: &str) -> Result<(), &'static str> {
        let raw = value.strip_prefix("0x").unwrap_or(value);
        if raw.len() != 40 || !raw.as_bytes().iter().all(u8::is_ascii_hexdigit) {
            return Err("address must be 20 bytes encoded as 40 hex characters, with optional 0x prefix");
        }
        Ok(())
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Address::validate_str(&value).map_err(serde::de::Error::custom)?;
        Ok(Self(value))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FileSnapshotRequest {
    #[serde(rename = "l4Snapshots")]
    L4Snapshots {
        #[serde(rename = "includeUsers")]
        include_users: bool,
        #[serde(rename = "includeTriggerOrders")]
        include_trigger_orders: bool,
    },

    #[serde(rename = "referrerStates")]
    ReferrerStates,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum InfoRequest {
    #[serde(rename = "fileSnapshot")]
    FileSnapshot {
        request: FileSnapshotRequest,
        #[serde(rename = "outPath")]
        out_path: String,
        #[serde(rename = "includeHeightInOutput", default)]
        include_height_in_output: bool,
    },

    #[serde(rename = "webData2")]
    WebData2 { user: Address },

    #[serde(rename = "webData3")]
    WebData3 { user: Address },

    #[serde(rename = "meta")]
    Meta {
        #[serde(default)]
        dex: Option<Dex>,
    },

    #[serde(rename = "spotMeta")]
    SpotMeta {
        #[serde(rename = "includeDebugDetails", default, skip_serializing_if = "is_false")]
        include_debug_details: bool,
    },

    #[serde(rename = "outcomeMeta")]
    OutcomeMeta,

    #[serde(rename = "clearinghouseState")]
    ClearinghouseState {
        user: Address,
        #[serde(default)]
        dex: Option<Dex>,
    },

    #[serde(rename = "spotClearinghouseState")]
    SpotClearinghouseState {
        user: Address,
        #[serde(rename = "ignorePortfolioMargin", default)]
        ignore_portfolio_margin: bool,
    },

    #[serde(rename = "openOrders")]
    OpenOrders {
        user: Address,
        #[serde(default)]
        dex: Option<Dex>,
    },

    #[serde(rename = "exchangeStatus")]
    ExchangeStatus,

    #[serde(rename = "frontendOpenOrders")]
    FrontendOpenOrders {
        user: Address,
        #[serde(default)]
        dex: Option<Dex>,
    },

    #[serde(rename = "liquidatable")]
    Liquidatable,

    #[serde(rename = "activeAssetData")]
    ActiveAssetData { user: Address, coin: Coin },

    #[serde(rename = "maxMarketOrderNtls")]
    MaxMarketOrderNtls,

    #[serde(rename = "vaultSummaries")]
    VaultSummaries { leader: Address },

    #[serde(rename = "userVaultEquities")]
    UserVaultEquities { user: Address },

    #[serde(rename = "leadingVaults")]
    LeadingVaults { user: Address },

    #[serde(rename = "extraAgents")]
    ExtraAgents { user: Address },

    #[serde(rename = "subAccounts")]
    SubAccounts {
        user: Address,
        #[serde(default)]
        dex: Option<Dex>,
    },

    #[serde(rename = "subAccounts2")]
    SubAccounts2 { user: Address },

    #[serde(rename = "userFees")]
    UserFees { user: Address },

    #[serde(rename = "userRateLimit")]
    UserRateLimit { user: Address },

    #[serde(rename = "spotDeployState")]
    SpotDeployState { user: Address },

    #[serde(rename = "spotPairDeployAuctionStatus")]
    SpotPairDeployAuctionStatus,

    #[serde(rename = "perpDeployAuctionStatus")]
    PerpDeployAuctionStatus,

    #[serde(rename = "votes")]
    Votes { user: Address },

    #[serde(rename = "delegations")]
    Delegations { user: Address },

    #[serde(rename = "delegatorSummary")]
    DelegatorSummary { user: Address },

    #[serde(rename = "maxBuilderFee")]
    MaxBuilderFee { user: Address, builder: Address },

    #[serde(rename = "userToMultiSigSigners")]
    UserToMultiSigSigners { user: Address },

    #[serde(rename = "userRole")]
    UserRole { user: Address },

    #[serde(rename = "perpsAtOpenInterestCap")]
    PerpsAtOpenInterestCap {
        #[serde(default)]
        dex: Option<Dex>,
    },

    #[serde(rename = "perpDexLimits")]
    PerpDexLimits {
        #[serde(default)]
        dex: Option<Dex>,
    },

    #[serde(rename = "validatorL1Votes")]
    ValidatorL1Votes,

    #[serde(rename = "marginTable")]
    MarginTable {
        #[serde(default)]
        dex: Option<Dex>,
        id: u32,
    },

    #[serde(rename = "perpDexs")]
    PerpDexs,

    #[serde(rename = "allPerpMetas")]
    AllPerpMetas,

    #[serde(rename = "alignedQuoteTokenInfo")]
    AlignedQuoteTokenInfo { token: Token },

    #[serde(rename = "userDexAbstraction")]
    UserDexAbstraction { user: Address },

    #[serde(rename = "perpDexStatus")]
    PerpDexStatus {
        #[serde(default)]
        dex: Option<Dex>,
    },

    #[serde(rename = "borrowLendUserState")]
    BorrowLendUserState { user: Address },

    #[serde(rename = "borrowLendReserveState")]
    BorrowLendReserveState { token: Token },

    #[serde(rename = "allBorrowLendReserveStates")]
    AllBoleReserveStates,

    #[serde(rename = "userAbstraction")]
    UserAbstraction { user: Address },

    #[serde(rename = "perpAnnotation")]
    PerpAnnotation { coin: Coin },

    #[serde(rename = "perpCategories")]
    PerpCategories,

    #[serde(rename = "perpConciseAnnotations")]
    PerpConciseAnnotations,

    #[serde(rename = "settledOutcome")]
    SettledOutcome { outcome: Outcome },

    #[serde(rename = "settledQuestion")]
    SettledQuestion { question: Question },

    #[serde(rename = "approvedBuilders")]
    ApprovedBuilders { user: Address },

    #[serde(rename = "gossipPriorityAuctionStatus")]
    GossipPriorityAuctionStatus,
}

pub type NodeInfoRequest = InfoRequest;

impl InfoRequest {
    pub fn validate(&self) -> Result<(), RequestValidationError> {
        match self {
            Self::FileSnapshot { out_path, .. } => {
                validate_non_empty("outPath", out_path)?;
            }
            Self::ActiveAssetData { coin, .. } | Self::PerpAnnotation { coin } => {
                validate_non_empty("coin", coin)?;
            }
            Self::MarginTable { id, .. } => {
                if *id == 0 {
                    return Err(RequestValidationError::ZeroId);
                }
            }
            Self::AlignedQuoteTokenInfo { token } | Self::BorrowLendReserveState { token } => {
                validate_non_empty("token", token)?;
            }
            Self::SettledOutcome { outcome } => validate_non_empty("outcome", outcome)?,
            Self::SettledQuestion { question } => validate_non_empty("question", question)?,
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestValidationError {
    EmptyField(&'static str),
    ZeroId,
}

fn validate_non_empty(field: &'static str, value: &str) -> Result<(), RequestValidationError> {
    if value.is_empty() {
        Err(RequestValidationError::EmptyField(field))
    } else {
        Ok(())
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}
