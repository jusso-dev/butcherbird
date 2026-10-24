//! Shared HTTP client, rate gate and retry policy.

use std::future::Future;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::secret::{redact_truncate, Secret};
use crate::Error;

use super::ProviderError;

pub(crate) struct IntervalGate {
    interval: Duration,
    next: Mutex<Instant>,
}

impl IntervalGate {
    pub(crate) fn per_minute(requests: u32) -> Self {
        let requests = requests.max(1);
        let interval = Duration::from_secs_f64(60.0 / f64::from(requests));
        Self {
            interval,
            next: Mutex::new(Instant::now()),
        }
    }

    pub(crate) async fn wait(&self) {
        if self.interval.is_zero() {
            return;
        }
        let mut next = self.next.lock().await;
        let now = Instant::now();
        let scheduled = (*next).max(now);
        *next = scheduled + self.interval;
        drop(next);
        let delay = scheduled.saturating_duration_since(now);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
}

pub(crate) fn client(timeout: Duration) -> Result<reqwest::Client, Error> {
    reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("butcherbird/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|err| Error::Client(err.to_string()))
}

/// Percent-encode a single URL path segment.
pub(crate) fn encode_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Send a request, spacing calls through `gate` and backing off on 429 and 5xx.
pub(crate) async fn send<F, Fut>(
    gate: &IntervalGate,
    secret: &Secret,
    mut build: F,
) -> Result<reqwest::Response, ProviderError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<reqwest::Response, reqwest::Error>>,
{
    let mut backoff = Duration::from_secs(1);
    for attempt in 0..4 {
        gate.wait().await;
        let response = match build().await {
            Ok(response) => response,
            Err(_) if attempt < 3 => {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(8));
                continue;
            }
            Err(_) => return Err(ProviderError::Transport),
        };
        let status = response.status();
        if status.as_u16() == 401 || status.as_u16() == 403 {
            return Err(ProviderError::Auth);
        }
        if status.as_u16() == 429 || status.is_server_error() {
            if attempt < 3 {
                let wait = retry_after(&response).unwrap_or(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(8));
                tokio::time::sleep(wait.min(Duration::from_secs(30))).await;
                continue;
            }
            if status.as_u16() == 429 {
                return Err(ProviderError::RateLimited);
            }
            let code = status.as_u16();
            let body = read_body(response, secret).await;
            return Err(ProviderError::Http { status: code, body });
        }
        if !status.is_success() {
            let code = status.as_u16();
            let body = read_body(response, secret).await;
            return Err(ProviderError::Http { status: code, body });
        }
        return Ok(response);
    }
    Err(ProviderError::RateLimited)
}

fn retry_after(response: &reqwest::Response) -> Option<Duration> {
    let value = response.headers().get(reqwest::header::RETRY_AFTER)?;
    let text = value.to_str().ok()?;
    let seconds: u64 = text.parse().ok()?;
    Some(Duration::from_secs(seconds))
}

async fn read_body(response: reqwest::Response, secret: &Secret) -> String {
    let text = response.text().await.unwrap_or_default();
    redact_truncate(&text, secret, 180)
}
