//! abuse.ch ThreatFox search. Free Auth-Key.
//!
//! `no_result` is a weak clean vote, same as URLhaus.

use async_trait::async_trait;
use serde_json::Value;

use crate::config::Config;
use crate::ioc::{Ioc, IocType};
use crate::score::{Finding, Verdict};
use crate::secret::Secret;

use super::http::{self, IntervalGate};
use super::{
    key_or_skip, origin, rate_of, ready, AuthKind, Provider, ProviderError, ProviderMeta, Slot,
    Tier,
};

const DEFAULT_URL: &str = "https://threatfox-api.abuse.ch";

/// ThreatFox provider identity.
pub const THREATFOX_META: ProviderMeta = ProviderMeta {
    id: "threatfox",
    types: &[
        IocType::Ipv4,
        IocType::Domain,
        IocType::Url,
        IocType::Md5,
        IocType::Sha1,
        IocType::Sha256,
    ],
    tier: Tier::Free,
    auth: AuthKind::ApiKey,
    default_rate_per_minute: 60,
};

/// ThreatFox search client.
pub struct ThreatFox {
    client: reqwest::Client,
    api_key: Secret,
    base_url: String,
    gate: IntervalGate,
}

impl ThreatFox {
    /// `base_url` is the origin, for example `https://threatfox-api.abuse.ch`.
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
    let key = match key_or_skip(cfg, THREATFOX_META) {
        Ok(key) => key.clone(),
        Err(skipped) => return skipped,
    };
    ready(ThreatFox::new(
        client,
        key,
        origin(cfg, THREATFOX_META.id, DEFAULT_URL),
        rate_of(cfg, THREATFOX_META),
    ))
}

#[async_trait]
impl Provider for ThreatFox {
    fn meta(&self) -> ProviderMeta {
        THREATFOX_META
    }

    async fn lookup(&self, ioc: &Ioc) -> Result<Finding, ProviderError> {
        let url = format!("{}/api/v1/", self.base_url.trim_end_matches('/'));
        let payload = serde_json::json!({
            "query": "search_ioc",
            "search_term": ioc.value,
        });
        let response = http::send(&self.gate, &self.api_key, || {
            self.client
                .post(&url)
                .header("Auth-Key", self.api_key.as_header_value())
                .header(reqwest::header::ACCEPT, "application/json")
                .json(&payload)
                .send()
        })
        .await?;
        let body: Value = response.json().await.map_err(|_| ProviderError::Decode)?;
        map_body(&body)
    }
}

fn map_body(body: &Value) -> Result<Finding, ProviderError> {
    let status = body
        .get("query_status")
        .and_then(Value::as_str)
        .unwrap_or("");
    if status == "no_result" || status == "no_results" {
        return Ok(Finding {
            verdict: Verdict::Clean,
            confidence: 40,
            detail: "not listed".to_string(),
        });
    }
    if status != "ok" {
        return Ok(Finding {
            verdict: Verdict::Unknown,
            confidence: 0,
            detail: format!("query {status}"),
        });
    }
    let data = body
        .get("data")
        .and_then(Value::as_array)
        .ok_or(ProviderError::Decode)?;
    let mut confidence = 75u8;
    let mut malware = "listed".to_string();
    for row in data {
        if let Some(level) = row.get("confidence_level").and_then(Value::as_u64) {
            confidence = confidence.max(u8::try_from(level.min(100)).unwrap_or(100));
        }
        if malware == "listed" {
            if let Some(name) = row
                .get("malware_printable")
                .or_else(|| row.get("malware"))
                .and_then(Value::as_str)
            {
                malware = name.to_string();
            }
        }
    }
    Ok(Finding {
        verdict: Verdict::Malicious,
        confidence,
        detail: malware,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::parse_ioc;
    use crate::provider::Provider;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn provider(server: &MockServer) -> ThreatFox {
        ThreatFox::new(
            http::client(std::time::Duration::from_secs(5)).unwrap(),
            Secret::new("bb-test-secret-key"),
            server.uri(),
            60_000,
        )
    }

    #[tokio::test]
    async fn listed_and_missing() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/"))
            .and(header("Auth-Key", "bb-test-secret-key"))
            .and(body_string_contains("evil.example"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "query_status": "ok",
                "data": [{
                    "ioc": "evil.example",
                    "malware_printable": "Emotet",
                    "confidence_level": 80
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/"))
            .and(body_string_contains("clean.example"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "query_status": "no_result"
            })))
            .mount(&server)
            .await;
        let client = provider(&server).await;
        let hit = client
            .lookup(&parse_ioc("evil.example").unwrap())
            .await
            .unwrap();
        assert_eq!(hit.verdict, Verdict::Malicious);
        assert_eq!(hit.confidence, 80);
        assert_eq!(hit.detail, "Emotet");
        let missing = client
            .lookup(&parse_ioc("clean.example").unwrap())
            .await
            .unwrap();
        assert_eq!(missing.verdict, Verdict::Clean);
        assert_eq!(missing.confidence, 40);
    }
}
