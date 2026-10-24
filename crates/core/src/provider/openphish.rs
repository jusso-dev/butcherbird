//! OpenPhish public feed. No API key.
//!
//! The feed is downloaded and matched locally. A URL that is absent is
//! unknown: the feed is a list of phishing URLs, not a clean list.
//! The feed is kept in memory for one hour so a bulk check does not
//! download it once per indicator.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::config::Config;
use crate::ioc::{parse_ioc, Ioc, IocType};
use crate::score::{Finding, Verdict};
use crate::secret::Secret;

use super::http::{self, IntervalGate};
use super::{
    enabled_or_skip, origin, rate_of, ready, AuthKind, Provider, ProviderError, ProviderMeta, Slot,
    Tier,
};

const DEFAULT_URL: &str = "https://openphish.com";
const FEED_TTL: Duration = Duration::from_secs(3600);

/// OpenPhish provider identity.
pub const OPENPHISH_META: ProviderMeta = ProviderMeta {
    id: "openphish",
    types: &[IocType::Url],
    tier: Tier::Free,
    auth: AuthKind::None,
    default_rate_per_minute: 2,
};

struct Feed {
    fetched: Instant,
    urls: Arc<HashSet<String>>,
}

/// OpenPhish feed client.
pub struct OpenPhish {
    client: reqwest::Client,
    base_url: String,
    gate: IntervalGate,
    feed: Mutex<Option<Feed>>,
}

impl OpenPhish {
    /// `base_url` is the origin, for example `https://openphish.com`.
    pub fn new(client: reqwest::Client, base_url: impl Into<String>, rate_per_minute: u32) -> Self {
        Self {
            client,
            base_url: base_url.into(),
            gate: IntervalGate::per_minute(rate_per_minute),
            feed: Mutex::new(None),
        }
    }
}

pub(crate) fn slot(cfg: &Config, client: reqwest::Client) -> Slot {
    if let Err(skipped) = enabled_or_skip(cfg, OPENPHISH_META) {
        return skipped;
    }
    ready(OpenPhish::new(
        client,
        origin(cfg, OPENPHISH_META.id, DEFAULT_URL),
        rate_of(cfg, OPENPHISH_META),
    ))
}

#[async_trait]
impl Provider for OpenPhish {
    fn meta(&self) -> ProviderMeta {
        OPENPHISH_META
    }

    async fn lookup(&self, ioc: &Ioc) -> Result<Finding, ProviderError> {
        let urls = self.feed().await?;
        if urls.contains(&ioc.value) {
            return Ok(Finding {
                verdict: Verdict::Malicious,
                confidence: 90,
                detail: "listed".to_string(),
            });
        }
        Ok(Finding {
            verdict: Verdict::Unknown,
            confidence: 0,
            detail: "not in OpenPhish feed".to_string(),
        })
    }
}

impl OpenPhish {
    async fn feed(&self) -> Result<Arc<HashSet<String>>, ProviderError> {
        {
            let guard = self.feed.lock().unwrap_or_else(|err| err.into_inner());
            if let Some(feed) = guard.as_ref() {
                if feed.fetched.elapsed() < FEED_TTL {
                    return Ok(feed.urls.clone());
                }
            }
        }
        let urls = Arc::new(self.download().await?);
        let mut guard = self.feed.lock().unwrap_or_else(|err| err.into_inner());
        *guard = Some(Feed {
            fetched: Instant::now(),
            urls: urls.clone(),
        });
        Ok(urls)
    }

    async fn download(&self) -> Result<HashSet<String>, ProviderError> {
        let url = format!("{}/feed.txt", self.base_url.trim_end_matches('/'));
        let response = http::send(&self.gate, &Secret::new(""), || {
            self.client.get(&url).send()
        })
        .await?;
        let text = response.text().await.map_err(|_| ProviderError::Decode)?;
        Ok(parse_feed(&text))
    }
}

fn parse_feed(text: &str) -> HashSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(parse_ioc)
        .filter(|ioc| ioc.kind == IocType::Url)
        .map(|ioc| ioc.value)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Provider;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn feed_is_fetched_once_and_absence_is_unknown() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/feed.txt"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("https://phish.example/login\n# comment\nnot a url\n"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = OpenPhish::new(
            http::client(std::time::Duration::from_secs(5)).unwrap(),
            server.uri(),
            60_000,
        );
        let listed = client
            .lookup(&parse_ioc("https://phish.example/login").unwrap())
            .await
            .unwrap();
        assert_eq!(listed.verdict, Verdict::Malicious);
        let missing = client
            .lookup(&parse_ioc("https://other.example/a").unwrap())
            .await
            .unwrap();
        assert_eq!(missing.verdict, Verdict::Unknown);
        assert_eq!(missing.detail, "not in OpenPhish feed");
        server.verify().await;
    }
}
