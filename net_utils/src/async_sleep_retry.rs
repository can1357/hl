//! Reconstructed from `/home/ubuntu/hl/code_Mainnet/net_utils/src/async_sleep_retry.rs`.
//!
//! Seed EAs: `0x2039060`, `0x22689F0`, `0x22C54A0`.
//!
//! Recovered facts used by `node/src/gossip_rpc_client.rs`:
//! - retry wrappers carry a static `desc` string such as `gossip_rpc_request`,
//!   `send gossip rpc request`, `rpc connect`, or `gossip response`.
//! - failures are formatted as
//!   `AsyncSleepRetry::retry desc=[...] n_tries=... failed: ...`.
//! - after the final attempt, the error is formatted with
//!   `async_sleep_retry retries exhausted` before being returned to the caller.
//! - some monomorphs compute their delay from request kind / height delta; the
//!   generic helper below keeps that decision in the caller-provided closure.
//!
//! IDA tag plan, not applied because the shared queue was full:
//! `0x22689F0` -> `net_utils_async_sleep_retry__poll_retry_future`.

#![allow(dead_code)]

use std::fmt;
use std::future::Future;
use std::time::Duration;

use tokio::time::sleep;

#[derive(Clone, Copy, Debug)]
pub struct AsyncSleepRetryPolicy {
    pub desc: &'static str,
    pub max_tries: usize,
    pub first_delay: Duration,
}

impl AsyncSleepRetryPolicy {
    pub const fn new(desc: &'static str, max_tries: usize, first_delay: Duration) -> Self {
        Self { desc, max_tries, first_delay }
    }

    pub const fn gossip_rpc_request() -> Self {
        Self::new("gossip_rpc_request", 10, Duration::from_secs(2))
    }

    pub const fn rpc_connect() -> Self {
        Self::new("rpc connect", 10, Duration::from_secs(2))
    }
}

#[derive(Debug)]
pub struct AsyncSleepRetryError<E> {
    pub desc: &'static str,
    pub n_tries: usize,
    pub source: E,
}

impl<E: fmt::Display> fmt::Display for AsyncSleepRetryError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "async_sleep_retry retries exhausted: {} [n_retries: {}]",
            self.source, self.n_tries,
        )
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for AsyncSleepRetryError<E> {}

pub async fn async_sleep_retry<T, E, F, Fut, D>(
    policy: AsyncSleepRetryPolicy,
    mut f: F,
    mut delay_after_error: D,
) -> Result<T, AsyncSleepRetryError<E>>
where
    E: fmt::Display,
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Result<T, E>>,
    D: FnMut(usize, &E) -> Duration,
{
    let max_tries = policy.max_tries.max(1);
    let mut last_error = None;

    for attempt in 0..max_tries {
        match f(attempt).await {
            Ok(value) => return Ok(value),
            Err(error) => {
                log_retry_failure(policy.desc, attempt + 1, &error);
                let delay = delay_after_error(attempt + 1, &error);
                last_error = Some(error);
                if attempt + 1 != max_tries && !delay.is_zero() {
                    sleep(delay).await;
                }
            }
        }
    }

    Err(AsyncSleepRetryError {
        desc: policy.desc,
        n_tries: max_tries,
        source: last_error.expect("retry loop always attempts at least once"),
    })
}

pub fn log_retry_failure(desc: &str, n_tries: usize, error: &dyn fmt::Display) {
    let _ = (desc, n_tries, error);
}

pub fn fixed_delay(_: usize, _: &dyn fmt::Display, delay: Duration) -> Duration {
    delay
}
