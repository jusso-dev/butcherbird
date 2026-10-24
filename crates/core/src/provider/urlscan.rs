//! urlscan.io search API. Free API key.
//!
//! A scan that is not flagged is unknown. Being scanned is not a clean vote.

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

const DEFAULT_URL: &str = "https://urlscan.io";

/// urlscan.io provider identity.
pub const URLSCAN_META: ProviderMeta = ProviderMeta {
    id: "urlscan",
    types: &[IocType::Ipv4, IocType::Ipv6, IocType::Domain, IocType::Url],
    tier: Tier::Free,
    auth: AuthKind::ApiKey,
    default_rate_per_minute: 30,
};

/// urlscan.io search client.
pub struct Urlscan {
    client: reqwest::Client,
    api_key: Secret,
    base_url: String,
    gate: IntervalGate,
}

impl Urlscan {
    /// `base_url` is the origin, for example `https://urlscan.io`.
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
    let key = match key_or_skip(cfg, URLSCAN_META) {
        Ok(key) => key.clone(),
        Err(skipped) => return skipped,
    };
    ready(Urlscan::new(
        client,
        key,
        origin(cfg, URLSCAN_META.id, DEFAULT_URL),
        rate_of(cfg, URLSCAN_META),
    ))
}

#[async_trait]
impl Provider for Urlscan {
    fn meta(&self) -> ProviderMeta {
        URLSCAN_META
    }

    async fn lookup(&self, ioc: &Ioc) -> Result<Finding, ProviderError> {
        let q = match ioc.kind {
            IocType::Ipv4 | IocType::Ipv6 => format!("ip:{}", ioc.value),
            IocType::Domain => format!("domain:{}", ioc.value),
            IocType::Url => format!("page.url:\"{}\"", ioc.value),
            _ => {
                return Ok(Finding {
                    verdict: Verdict::Unknown,
                    confidence: 0,
                    detail: "unsupported type".to_string(),
                });
            }
        };
        let url = format!("{}/api/v1/search/", self.base_url.trim_end_matches('/'));
        let response = http::send(&self.gate, &self.api_key, || {
            self.client
                .get(&url)
                .header("API-Key", self.api_key.as_header_value())
                .header(reqwest::header::ACCEPT, "application/json")
                .query(&[("q", q.as_str())])
                .send()
        })
        .await?;
        let body: Value = response.json().await.map_err(|_| ProviderError::Decode)?;
        map_body(&body)
    }
}

fn map_body(body: &Value) -> Result<Finding, ProviderError> {
    let results = body
        .get("results")
        .and_then(Value::as_array)
        .ok_or(ProviderError::Decode)?;
    if results.is_empty() {
        return Ok(Finding {
            verdict: Verdict::Unknown,
            confidence: 0,
            detail: "no scans".to_string(),
        });
    }
    let mut malicious = false;
    let mut score_max = 0u8;
    for row in results {
        let overall = row.pointer("/verdicts/overall");
        let flagged = overall
            .and_then(|value| value.get("malicious"))
            .and_then(Value::as_bool)
            == Some(true)
            || row
                .pointer("/verdicts/urlscan/malicious")
                .and_then(Value::as_bool)
                == Some(true);
        if flagged {
            malicious = true;
        }
        if let Some(score) = overall
            .and_then(|value| value.get("score"))
            .and_then(Value::as_u64)
        {
            score_max = score_max.max(u8::try_from(score.min(100)).unwrap_or(100));
        }
    }
    let n = results.len();
    if malicious {
        return Ok(Finding {
            verdict: Verdict::Malicious,
            confidence: score_max.max(80),
            detail: format!("{n} scans, flagged"),
        });
    }
    Ok(Finding {
        verdict: Verdict::Unknown,
        confidence: 0,
        detail: format!("{n} scans, not flagged"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::parse_ioc;
    use crate::provider::Provider;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn provider(server: &MockServer) -> Urlscan {
        Urlscan::new(
            http::client(std::time::Duration::from_secs(5)).unwrap(),
            Secret::new("bb-test-secret-key"),
            server.uri(),
            60_000,
        )
    }

    #[tokio::test]
    async fn flagged_scan_is_malicious_and_empty_is_unknown() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/search/"))
            .and(header("API-Key", "bb-test-secret-key"))
            .and(query_param("q", "domain:evil.example"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [{
                    "verdicts": { "overall": { "malicious": true, "score": 92 } }
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(query_param("q", "ip:192.0.2.9"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": []
            })))
            .mount(&server)
            .await;
        let client = provider(&server).await;
        let hit = client
            .lookup(&parse_ioc("evil.example").unwrap())
            .await
            .unwrap();
        assert_eq!(hit.verdict, Verdict::Malicious);
        assert_eq!(hit.confidence, 92);
        let empty = client
            .lookup(&parse_ioc("192.0.2.9").unwrap())
            .await
            .unwrap();
        assert_eq!(empty.verdict, Verdict::Unknown);
        assert_eq!(empty.detail, "no scans");
    }
}
