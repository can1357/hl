use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use serde::Deserialize;

pub type ChainName = String;
pub type RpcProviderName = String;
pub type ApiKey = String;
pub type Url = String;
pub type BucketName = String;
pub type IpAddress = String;

pub type EthChainToRpcProviderToKeys = BTreeMap<ChainName, BTreeMap<RpcProviderName, Vec<ApiKey>>>;
pub type ChainToEtherscanWsUrls = BTreeMap<ChainName, Vec<Url>>;
pub type ChainToReplicaS3Bucket = BTreeMap<ChainName, BucketName>;
pub type NamedKeys = BTreeMap<String, ApiKey>;

static EMPTY_STRINGS: &[String] = &[];

/// Lazily loaded API-secret configuration.
///
/// Recovered evidence:
/// - `0x13d28e0` appends `"/api_secrets.json"` to the process base-code path,
///   calls the shared file loader, maps the loader's missing-file arm to `Default`,
///   and unwrap-panics on other load errors.
/// - `0x13abf40` is the Serde visitor. It accepts exactly the field names modeled
///   below, including the later `risk_url`, `risk_key`, `ip_info_main_key`, and `cg_key`
///   fields that were not present in older local notes.
/// - Missing fields are not reported as errors; the generated visitor substitutes
///   `None` for optional strings and empty containers for collections.
#[derive(Clone, Default, Deserialize)]
pub struct ApiSecrets {
    #[serde(default)]
    pub slack_key: Option<String>,
    #[serde(default)]
    pub mainnet_slack_channel: Option<String>,
    #[serde(default)]
    pub testnet_slack_channel: Option<String>,
    #[serde(default)]
    pub sandbox_slack_channel: Option<String>,
    #[serde(default)]
    pub pager_duty_key: Option<String>,
    #[serde(default)]
    pub risk_url: Option<String>,
    #[serde(default)]
    pub risk_key: Option<String>,
    #[serde(default)]
    pub eth_chain_to_rpc_provider_to_keys: EthChainToRpcProviderToKeys,
    #[serde(default)]
    pub chain_to_etherscan_ws_urls: ChainToEtherscanWsUrls,
    #[serde(default)]
    pub etherscan_keys: Option<Vec<String>>,
    #[serde(default)]
    pub etherscan_v2_keys: Option<Vec<String>>,
    #[serde(default)]
    pub ip_endpoint: Option<String>,
    #[serde(default)]
    pub ip_main_key: Option<String>,
    #[serde(default)]
    pub ip_backup_keys: Option<Vec<String>>,
    #[serde(default)]
    pub ip_info_main_key: Option<String>,
    #[serde(default)]
    pub ip_info_backup_keys: Option<Vec<String>>,
    #[serde(default)]
    pub zip_and_upload_skip_cp: Option<Vec<String>>,
    #[serde(default)]
    pub internal_ips: BTreeSet<IpAddress>,
    #[serde(default)]
    pub s3_bucket: Option<String>,
    #[serde(default)]
    pub chain_to_replica_s3_bucket: ChainToReplicaS3Bucket,
    #[serde(default)]
    pub s3_daily_prefix: Option<String>,
    #[serde(default)]
    pub visor_remote: Option<String>,
    #[serde(default)]
    pub b_keys: NamedKeys,
    #[serde(default)]
    pub cg_key: Option<String>,
}

impl fmt::Debug for ApiSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiSecrets")
            .field("slack_key", &SecretOption(self.slack_key.as_deref()))
            .field("mainnet_slack_channel", &self.mainnet_slack_channel)
            .field("testnet_slack_channel", &self.testnet_slack_channel)
            .field("sandbox_slack_channel", &self.sandbox_slack_channel)
            .field("pager_duty_key", &SecretOption(self.pager_duty_key.as_deref()))
            .field("risk_url", &self.risk_url)
            .field("risk_key", &SecretOption(self.risk_key.as_deref()))
            .field("eth_chain_to_rpc_provider_to_keys", &NestedSecretMapShape(&self.eth_chain_to_rpc_provider_to_keys))
            .field("chain_to_etherscan_ws_urls", &self.chain_to_etherscan_ws_urls)
            .field("etherscan_keys", &SecretSlice(self.etherscan_keys()))
            .field("etherscan_v2_keys", &SecretSlice(self.etherscan_v2_keys()))
            .field("ip_endpoint", &self.ip_endpoint)
            .field("ip_main_key", &SecretOption(self.ip_main_key.as_deref()))
            .field("ip_backup_keys", &SecretSlice(self.ip_backup_keys()))
            .field("ip_info_main_key", &SecretOption(self.ip_info_main_key.as_deref()))
            .field("ip_info_backup_keys", &SecretSlice(self.ip_info_backup_keys()))
            .field("zip_and_upload_skip_cp", &self.zip_and_upload_skip_cp)
            .field("internal_ips", &self.internal_ips)
            .field("s3_bucket", &self.s3_bucket)
            .field("chain_to_replica_s3_bucket", &self.chain_to_replica_s3_bucket)
            .field("s3_daily_prefix", &self.s3_daily_prefix)
            .field("visor_remote", &self.visor_remote)
            .field("b_keys", &SecretMapShape(&self.b_keys))
            .field("cg_key", &SecretOption(self.cg_key.as_deref()))
            .finish()
    }
}

pub static API_SECRETS: LazyLock<ApiSecrets> = LazyLock::new(load_api_secrets);

pub fn api_secrets() -> &'static ApiSecrets {
    &API_SECRETS
}

pub fn load_api_secrets() -> ApiSecrets {
    load_api_secrets_result().unwrap()
}

pub fn load_api_secrets_result() -> Result<ApiSecrets, ApiSecretsLoadError> {
    match load_api_secrets_from_path(&api_secrets_path())? {
        Some(secrets) => Ok(secrets),
        None => Ok(ApiSecrets::default()),
    }
}

pub fn load_api_secrets_from_path(path: &Path) -> Result<Option<ApiSecrets>, ApiSecretsLoadError> {
    let path = expand_tilde(path);
    if !is_regular_file(&path) {
        return Ok(None);
    }

    let bytes = fs::read(&path).map_err(|source| ApiSecretsLoadError::Read { path: path.clone(), source })?;
    let secrets = if path_has_rmp_extension(&path) {
        rmp_serde::from_slice(&bytes).map_err(|source| ApiSecretsLoadError::Rmp { path, source })?
    } else {
        serde_json::from_slice(&bytes).map_err(|source| ApiSecretsLoadError::Json { path, source })?
    };
    Ok(Some(secrets))
}

/// Runtime path used by the recovered initializer.
///
/// The base-code directory itself is owned by the neighboring path/bootstrap module:
/// that code derives a home directory, prefers a `cham` directory when it exists,
/// falls back to `hl`, appends `code`, and creates/verifies the directory. The
/// initializer in this file only appends the fixed API-secret filename.
pub fn api_secrets_path() -> PathBuf {
    base_code_dir().join("api_secrets.json")
}

pub fn base_code_dir() -> PathBuf {
    let home = env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    let cham = home.join("cham");
    let base = if cham.is_dir() { cham } else { home.join("hl") };
    base.join("code")
}

pub fn expand_tilde(path: &Path) -> PathBuf {
    let Some(path_str) = path.to_str() else {
        return path.to_path_buf();
    };
    if path_str == "~" {
        return env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| path.to_path_buf());
    }
    if let Some(rest) = path_str.strip_prefix("~/") {
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}

pub fn is_regular_file(path: &Path) -> bool {
    path.metadata().map(|metadata| metadata.is_file()).unwrap_or(false)
}

fn path_has_rmp_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.eq_ignore_ascii_case("rmp"))
        .unwrap_or(false)
}

impl ApiSecrets {
    pub fn slack_key(&self) -> Option<&str> {
        non_empty(self.slack_key.as_deref())
    }

    pub fn slack_channel(&self, chain: SlackChain) -> Option<&str> {
        match chain {
            SlackChain::Mainnet => non_empty(self.mainnet_slack_channel.as_deref()),
            SlackChain::Testnet => non_empty(self.testnet_slack_channel.as_deref()),
            SlackChain::Sandbox => non_empty(self.sandbox_slack_channel.as_deref()),
        }
    }

    pub fn slack_alert(&self, chain: SlackChain) -> Option<SlackAlertConfigRef<'_>> {
        Some(SlackAlertConfigRef {
            authorization: self.slack_key()?,
            channel: self.slack_channel(chain)?,
        })
    }

    pub fn pager_duty_key(&self) -> Option<&str> {
        non_empty(self.pager_duty_key.as_deref())
    }

    pub fn risk_api(&self) -> Option<RiskApiRef<'_>> {
        Some(RiskApiRef {
            url: non_empty(self.risk_url.as_deref())?,
            key: non_empty(self.risk_key.as_deref())?,
        })
    }

    pub fn rpc_provider_keys(&self, chain: &str, provider: &str) -> Option<&[String]> {
        self.eth_chain_to_rpc_provider_to_keys
            .get(chain)
            .and_then(|providers| providers.get(provider))
            .map(Vec::as_slice)
            .filter(|keys| !keys.is_empty())
    }

    pub fn first_rpc_provider_key(&self, chain: &str, provider: &str) -> Option<&str> {
        self.rpc_provider_keys(chain, provider)?.iter().find_map(|key| non_empty(Some(key.as_str())))
    }

    pub fn etherscan_ws_urls(&self, chain: &str) -> Option<&[String]> {
        self.chain_to_etherscan_ws_urls.get(chain).map(Vec::as_slice).filter(|urls| !urls.is_empty())
    }

    pub fn etherscan_keys(&self) -> &[String] {
        self.etherscan_keys.as_deref().unwrap_or(EMPTY_STRINGS)
    }

    pub fn etherscan_v2_keys(&self) -> &[String] {
        self.etherscan_v2_keys.as_deref().unwrap_or(EMPTY_STRINGS)
    }

    pub fn ip_lookup(&self) -> Option<IpLookupSecretsRef<'_>> {
        Some(IpLookupSecretsRef {
            endpoint: non_empty(self.ip_endpoint.as_deref())?,
            main_key: non_empty(self.ip_main_key.as_deref())?,
            backup_keys: self.ip_backup_keys(),
        })
    }

    pub fn ip_backup_keys(&self) -> &[String] {
        self.ip_backup_keys.as_deref().unwrap_or(EMPTY_STRINGS)
    }

    pub fn ip_info_lookup(&self) -> Option<IpInfoSecretsRef<'_>> {
        Some(IpInfoSecretsRef {
            main_key: non_empty(self.ip_info_main_key.as_deref())?,
            backup_keys: self.ip_info_backup_keys(),
        })
    }

    pub fn ip_info_backup_keys(&self) -> &[String] {
        self.ip_info_backup_keys.as_deref().unwrap_or(EMPTY_STRINGS)
    }

    pub fn should_skip_zip_and_upload_copy(&self, item: &str) -> bool {
        self.zip_and_upload_skip_cp
            .as_ref()
            .map(|items| items.iter().any(|candidate| candidate == item))
            .unwrap_or(false)
    }

    pub fn is_internal_ip(&self, ip: &str) -> bool {
        self.internal_ips.contains(ip)
    }

    pub fn s3_bucket(&self) -> Option<&str> {
        non_empty(self.s3_bucket.as_deref())
    }

    pub fn replica_s3_bucket(&self, chain: &str) -> Option<&str> {
        self.chain_to_replica_s3_bucket.get(chain).and_then(|bucket| non_empty(Some(bucket.as_str())))
    }

    pub fn s3_daily_prefix(&self) -> Option<&str> {
        non_empty(self.s3_daily_prefix.as_deref())
    }

    pub fn visor_remote(&self) -> Option<&str> {
        non_empty(self.visor_remote.as_deref())
    }

    pub fn b_key(&self, name: &str) -> Option<&str> {
        self.b_keys.get(name).and_then(|key| non_empty(Some(key.as_str())))
    }

    pub fn cg_key(&self) -> Option<&str> {
        non_empty(self.cg_key.as_deref())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackChain {
    Mainnet,
    Testnet,
    Sandbox,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlackAlertConfigRef<'a> {
    pub authorization: &'a str,
    pub channel: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RiskApiRef<'a> {
    pub url: &'a str,
    pub key: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpLookupSecretsRef<'a> {
    pub endpoint: &'a str,
    pub main_key: &'a str,
    pub backup_keys: &'a [String],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpInfoSecretsRef<'a> {
    pub main_key: &'a str,
    pub backup_keys: &'a [String],
}

#[derive(Debug)]
pub enum ApiSecretsLoadError {
    Read { path: PathBuf, source: io::Error },
    Json { path: PathBuf, source: serde_json::Error },
    Rmp { path: PathBuf, source: rmp_serde::decode::Error },
}

impl fmt::Display for ApiSecretsLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiSecretsLoadError::Read { path, source } => write!(f, "{}: {source}", path.display()),
            ApiSecretsLoadError::Json { path, source } => write!(f, "{}: {source}", path.display()),
            ApiSecretsLoadError::Rmp { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl std::error::Error for ApiSecretsLoadError {}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

struct SecretOption<'a>(Option<&'a str>);

impl fmt::Debug for SecretOption<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.map(|value| !value.is_empty()).unwrap_or(false) {
            f.write_str("Some(<redacted>)")
        } else {
            f.write_str("None")
        }
    }
}

struct SecretSlice<'a>(&'a [String]);

impl fmt::Debug for SecretSlice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("redacted_keys").field("len", &self.0.len()).finish()
    }
}

struct SecretMapShape<'a>(&'a NamedKeys);

impl fmt::Debug for SecretMapShape<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("redacted_map").field("len", &self.0.len()).finish()
    }
}

struct NestedSecretMapShape<'a>(&'a EthChainToRpcProviderToKeys);

impl fmt::Debug for NestedSecretMapShape<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n_providers = self.0.values().map(BTreeMap::len).sum::<usize>();
        let n_keys = self.0.values().flat_map(BTreeMap::values).map(Vec::len).sum::<usize>();
        f.debug_struct("redacted_nested_map")
            .field("chains", &self.0.len())
            .field("providers", &n_providers)
            .field("keys", &n_keys)
            .finish()
    }
}
