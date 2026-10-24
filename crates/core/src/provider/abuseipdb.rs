//! AbuseIPDB v2 check API. Free tier, API key, IPv4 and IPv6.

use async_trait::async_trait;
use serde_json::Value;

use crate::config::Config;
use crate::ioc::{Ioc, IocType};
use crate::score::{Finding, Verdict};
use crate::secret::Secret;

use super::http::{self, IntervalGate};
use super::{
    configured_rate, key_or_skip, ready, AuthKind, Provider, ProviderError, ProviderMeta, Slot,
    Tier,
};

const DEFAULT_URL: &str = "https://api.abuseipdb.com";

/// AbuseIPDB provider identity.
pub const ABUSEIPDB_META: ProviderMeta = ProviderMeta {
    id: "abuseipdb",
    types: &[IocType::Ipv4, IocType::Ipv6],
    tier: Tier::Free,
    auth: AuthKind::ApiKey,
    default_rate_per_minute: 60,
};

/// AbuseIPDB check client.
pub struct AbuseIpdb {
    client: reqwest::Client,
    api_key: Secret,
    base_url: String,
    gate: IntervalGate,
}

impl AbuseIpdb {
    /// `base_url` is the origin, for example `https://api.abuseipdb.com`.
    pub fn new(
        client: reqwest::Client,
        api_key: Secret,
        base_url: impl Into<String>,
        rate_per_minute: u32,
    ) -> Self {
        Self {
            client,
            api_key,
            base_url: base_url.into(),
            gate: IntervalGate::per_minute(rate_per_minute),
        }
    }
}

pub(crate) fn slot(cfg: &Config, client: reqwest::Client) -> Slot {
    let key = match key_or_skip(cfg, ABUSEIPDB_META) {
        Ok(key) => key.clone(),
        Err(skipped) => return skipped,
    };
    let settings = cfg.provider(ABUSEIPDB_META.id);
    let base = settings
        .base_url
        .clone()
        .unwrap_or_else(|| DEFAULT_URL.to_string());
    let rate = configured_rate(ABUSEIPDB_META, settings.rate_per_minute);
    ready(AbuseIpdb::new(client, key, base, rate))
}

#[async_trait]
impl Provider for AbuseIpdb {
    fn meta(&self) -> ProviderMeta {
        ABUSEIPDB_META
    }

    async fn lookup(&self, ioc: &Ioc) -> Result<Finding, ProviderError> {
        let url = format!("{}/api/v2/check", self.base_url.trim_end_matches('/'));
        let response = http::send(&self.gate, &self.api_key, || {
            self.client
                .get(&url)
                .header("Key", self.api_key.as_header_value())
                .header(reqwest::header::ACCEPT, "application/json")
                .query(&[("ipAddress", ioc.value.as_str()), ("maxAgeInDays", "90")])
                .send()
        })
        .await?;
        let body: Value = response.json().await.map_err(|_| ProviderError::Decode)?;
        let data = body.get("data").ok_or(ProviderError::Decode)?;
        let score = data
            .get("abuseConfidenceScore")
            .and_then(Value::as_u64)
            .ok_or(ProviderError::Decode)?
            .min(100) as u8;
        let reports = data
            .get("totalReports")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let (verdict, confidence) = map_score(score);
        Ok(Finding {
            verdict,
            confidence,
            detail: format!("score {score}, {reports} reports"),
        })
    }
}

fn map_score(score: u8) -> (Verdict, u8) {
    if score >= 75 {
        (Verdict::Malicious, score)
    } else if score >= 25 {
        (Verdict::Suspicious, score)
    } else {
        (Verdict::Clean, 100 - score)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::parse_ioc;
    use crate::provider::Provider;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn key() -> Secret {
        Secret::new("bb-test-secret-key")
    }

    async fn provider(server: &MockServer) -> AbuseIpdb {
        AbuseIpdb::new(
            http::client(std::time::Duration::from_secs(5)).unwrap(),
            key(),
            server.uri(),
            60_000,
        )
    }

    #[tokio::test]
    async fn malicious_ip() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/check"))
            .and(header("Key", "bb-test-secret-key"))
            .and(header("Accept", "application/json"))
            .and(query_param("ipAddress", "192.0.2.1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "ipAddress": "192.0.2.1",
                    "abuseConfidenceScore": 100,
                    "totalReports": 12
                }
            })))
            .mount(&server)
            .await;
        let hit = provider(&server)
            .await
            .lookup(&parse_ioc("192.0.2.1").unwrap())
            .await
            .unwrap();
        assert_eq!(hit.verdict, Verdict::Malicious);
        assert_eq!(hit.confidence, 100);
        assert_eq!(hit.detail, "score 100, 12 reports");
    }

    #[tokio::test]
    async fn clean_ip() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/check"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "abuseConfidenceScore": 0, "totalReports": 0 }
            })))
            .mount(&server)
            .await;
        let hit = provider(&server)
            .await
            .lookup(&parse_ioc("192.0.2.2").unwrap())
            .await
            .unwrap();
        assert_eq!(hit.verdict, Verdict::Clean);
        assert_eq!(hit.confidence, 100);
    }

    #[tokio::test]
    async fn auth_error_hides_key() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let err = provider(&server)
            .await
            .lookup(&parse_ioc("192.0.2.1").unwrap())
            .await
            .unwrap_err();
        let rendered = err.to_string();
        assert_eq!(rendered, "authentication failed");
        assert!(!rendered.contains("secret-key"));
    }

    #[tokio::test]
    async fn error_body_is_redacted() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(422).set_body_string("bad bb-test-secret-key"))
            .mount(&server)
            .await;
        let err = provider(&server)
            .await
            .lookup(&parse_ioc("192.0.2.1").unwrap())
            .await
            .unwrap_err();
        assert!(!err.to_string().contains("secret-key"));
        assert!(err.to_string().contains("bb-t****"));
    }

    #[tokio::test]
    async fn retries_429() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/check"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "abuseConfidenceScore": 40, "totalReports": 1 }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v2/check"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let hit = provider(&server)
            .await
            .lookup(&parse_ioc("192.0.2.3").unwrap())
            .await
            .unwrap();
        assert_eq!(hit.verdict, Verdict::Suspicious);
    }
}
