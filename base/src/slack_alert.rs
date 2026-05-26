use std::fmt;
use std::time::{Duration, Instant};

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::Serialize;

const SLACK_POST_MESSAGE_URL: &str = "https://slack.com/api/chat.postMessage";
const APPLICATION_JSON: &str = "application/json";
const SLACK_ALERT_SPAN: &str = "slack alert";

/// Slack destinations recovered from the API-secrets key cluster.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackAlertSecrets {
    /// Value passed directly as the `Authorization` header.
    pub slack_key: String,
    pub mainnet_slack_channel: String,
    pub testnet_slack_channel: String,
    pub sandbox_slack_channel: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackAlertChain {
    Mainnet,
    Testnet,
    Sandbox,
}

/// Runtime configuration used by the alert future.
///
/// IDA evidence: the generated future checks the configured-token singleton before
/// constructing a `reqwest::Client`; if the singleton is unset, the future returns
/// without attempting HTTP. The post body contains `channel` and one mrkdwn section
/// block, and retry handling iterates over a captured slice of `f64` seconds.
#[derive(Clone, Debug)]
pub struct SlackAlertConfig {
    pub authorization: String,
    pub channel: String,
    pub retry_delays_secs: Vec<f64>,
}

impl SlackAlertConfig {
    pub fn from_secrets(secrets: &SlackAlertSecrets, chain: SlackAlertChain, retry_delays_secs: Vec<f64>) -> Option<Self> {
        let channel = match chain {
            SlackAlertChain::Mainnet => &secrets.mainnet_slack_channel,
            SlackAlertChain::Testnet => &secrets.testnet_slack_channel,
            SlackAlertChain::Sandbox => &secrets.sandbox_slack_channel,
        };

        if secrets.slack_key.is_empty() || channel.is_empty() {
            return None;
        }

        Some(Self {
            authorization: secrets.slack_key.clone(),
            channel: channel.clone(),
            retry_delays_secs,
        })
    }
}

#[derive(Debug)]
pub enum SlackAlertError {
    Serialize(serde_json::Error),
    Http(reqwest::Error),
    InvalidRetryDelay(f64),
}

impl fmt::Display for SlackAlertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SlackAlertError::Serialize(error) => write!(f, "serialize slack alert body: {error}"),
            SlackAlertError::Http(error) => write!(f, "send slack alert: {error}"),
            SlackAlertError::InvalidRetryDelay(delay) => write!(f, "invalid slack alert retry delay: {delay}"),
        }
    }
}

impl std::error::Error for SlackAlertError {}

impl From<serde_json::Error> for SlackAlertError {
    fn from(error: serde_json::Error) -> Self {
        SlackAlertError::Serialize(error)
    }
}

impl From<reqwest::Error> for SlackAlertError {
    fn from(error: reqwest::Error) -> Self {
        SlackAlertError::Http(error)
    }
}

#[derive(Clone, Debug)]
pub struct SlackAlertThrottle {
    pub min_interval: Duration,
    pub last_alert_at: Option<Instant>,
    pub n_logs_swallowed: u64,
}

impl SlackAlertThrottle {
    pub fn new(min_interval: Duration) -> Self {
        Self { min_interval, last_alert_at: None, n_logs_swallowed: 0 }
    }

    pub fn should_alert(&mut self, now: Instant) -> SlackThrottleDecision {
        if let Some(last_alert_at) = self.last_alert_at {
            if now.duration_since(last_alert_at) < self.min_interval {
                self.n_logs_swallowed = self.n_logs_swallowed.saturating_add(1);
                return SlackThrottleDecision::RecentlyAlerted { n_logs_swallowed: self.n_logs_swallowed };
            }
        }

        let swallowed = self.n_logs_swallowed;
        self.n_logs_swallowed = 0;
        self.last_alert_at = Some(now);
        SlackThrottleDecision::Alert { n_logs_swallowed: swallowed }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackThrottleDecision {
    Alert { n_logs_swallowed: u64 },
    RecentlyAlerted { n_logs_swallowed: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SlackAlertOutcome {
    NotConfigured,
    Throttled { n_logs_swallowed: u64 },
    Sent,
}

#[derive(Serialize)]
struct SlackPostBody<'a> {
    channel: &'a str,
    blocks: [SlackBlock<'a>; 1],
}

#[derive(Serialize)]
struct SlackBlock<'a> {
    #[serde(rename = "type")]
    block_type: &'static str,
    text: SlackText<'a>,
}

#[derive(Serialize)]
struct SlackText<'a> {
    #[serde(rename = "type")]
    text_type: &'static str,
    text: &'a str,
}

fn slack_post_body<'a>(channel: &'a str, text: &'a str) -> SlackPostBody<'a> {
    SlackPostBody {
        channel,
        blocks: [SlackBlock {
            block_type: "section",
            text: SlackText { text_type: "mrkdwn", text },
        }],
    }
}

/// Serialize and send one Slack `chat.postMessage` request.
///
/// IDA evidence: the request builder calls `.post("https://slack.com/api/chat.postMessage")`,
/// then `.header("Authorization", key)`, `.header("Content-Type", "application/json")`,
/// then `.body(serialized_json).send().await`. The response body/status is not consumed by
/// the recovered future; transport errors are retained for retry/error reporting.
pub async fn post_slack_message(client: &reqwest::Client, config: &SlackAlertConfig, text: &str) -> Result<(), SlackAlertError> {
    let body = serde_json::to_vec(&slack_post_body(&config.channel, text))?;

    client
        .post(SLACK_POST_MESSAGE_URL)
        .header(AUTHORIZATION, config.authorization.as_str())
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .body(body)
        .send()
        .await?;

    Ok(())
}

/// Send a Slack alert, retrying after the recovered retry-delay schedule.
///
/// The optimized future always performs the initial post first. On error, it iterates over
/// a captured `f64` slice; non-zero values are converted with `Duration::try_from_secs_f64`
/// and awaited before posting again.
pub async fn send_slack_alert(config: &SlackAlertConfig, text: &str) -> Result<(), SlackAlertError> {
    let client = reqwest::Client::new();
    let mut last_error = match post_slack_message(&client, config, text).await {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };

    for &delay_secs in &config.retry_delays_secs {
        if delay_secs != 0.0 {
            let delay = Duration::try_from_secs_f64(delay_secs).map_err(|_| SlackAlertError::InvalidRetryDelay(delay_secs))?;
            tokio::time::sleep(delay).await;
        }

        match post_slack_message(&client, config, text).await {
            Ok(()) => return Ok(()),
            Err(error) => last_error = error,
        }
    }

    Err(last_error)
}

/// Alert only when Slack is configured and the caller's throttle permits it.
///
/// Recovered log text around the critical-message path includes
/// `@@ Alerting if slack configured:` and `(not alerting because alerted recently)` with
/// `n_logs_swallowed`; this helper preserves that decision boundary and emits the
/// observed Slack-alert span/log before posting.
pub async fn alert_if_slack_configured(
    config: Option<&SlackAlertConfig>,
    throttle: Option<&mut SlackAlertThrottle>,
    now: Instant,
    text: &str,
) -> Result<SlackAlertOutcome, SlackAlertError> {
    let Some(config) = config else {
        return Ok(SlackAlertOutcome::NotConfigured);
    };

    if let Some(throttle) = throttle {
        match throttle.should_alert(now) {
            SlackThrottleDecision::Alert { .. } => {}
            SlackThrottleDecision::RecentlyAlerted { n_logs_swallowed } => {
                return Ok(SlackAlertOutcome::Throttled { n_logs_swallowed });
            }
        }
    }

    tracing::info!(target: SLACK_ALERT_SPAN, "@@ Alerting if slack configured: {text}");
    send_slack_alert(config, text).await?;
    Ok(SlackAlertOutcome::Sent)
}
