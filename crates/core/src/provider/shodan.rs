//! Shodan host API. Free API key. Exposure data, not a reputation feed.
//!
//! Open ports do not vote. Malware or compromised tags vote malicious.
//! A honeypot tag or any vulnerability votes suspicious. Anything else is
//! unknown so a scanned host is not treated as clean.

use async_trait::async_trait;
use serde_json::Value;

use crate::config::Config;
use crate::ioc::{Ioc, IocType};
use crate::score::{Finding, Verdict};
use crate::secret::Secret;

use super::http::{self, IntervalGate};
use super::{
    is_not_found, key_or_skip, origin, rate_of, ready, AuthKind, Provider, ProviderError,
    ProviderMeta, Slot, Tier,
};

const DEFAULT_URL: &str = "https://api.shodan.io";

/// Shodan provider identity.
pub const SHODAN_META: ProviderMeta = ProviderMeta {
    id: "shodan",
    types: &[IocType::Ipv4, IocType::Ipv6],
    tier: Tier::Free,
    auth: AuthKind::ApiKey,
    default_rate_per_minute: 60,
};

/// Shodan host client.
pub struct Shodan {
    client: reqwest::Client,
    api_key: Secret,
    base_url: String,
    gate: IntervalGate,
}

impl Shodan {
    /// `base_url` is the origin, for example `https://api.shodan.io`.
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
    let key = match key_or_skip(cfg, SHODAN_META) {
        Ok(key) => key.clone(),
        Err(skipped) => return skipped,
    };
    ready(Shodan::new(
        client,
        key,
        origin(cfg, SHODAN_META.id, DEFAULT_URL),
        rate_of(cfg, SHODAN_META),
    ))
}

#[async_trait]
impl Provider for Shodan {
    fn meta(&self) -> ProviderMeta {
        SHODAN_META
    }

    async fn lookup(&self, ioc: &Ioc) -> Result<Finding, ProviderError> {
        let url = format!(
            "{}/shodan/host/{}",
            self.base_url.trim_end_matches('/'),
            http::encode_segment(&ioc.value)
        );
        let response = match http::send(&self.gate, &self.api_key, || {
            self.client
                .get(&url)
                .query(&[("key", self.api_key.as_header_value())])
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
        })
        .await
        {
            Err(err) if is_not_found(&err) => {
                return Ok(Finding {
                    verdict: Verdict::Unknown,
                    confidence: 0,
                    detail: "not in shodan".to_string(),
                });
            }
            other => other?,
        };
        let body: Value = response.json().await.map_err(|_| ProviderError::Decode)?;
        Ok(map_body(&body))
    }
}

fn map_body(body: &Value) -> Finding {
    let tags = strings(body.get("tags"));
    let vuln_count = match body.get("vulns") {
        Some(Value::Object(map)) => map.len(),
        Some(Value::Array(list)) => list.len(),
        _ => 0,
    };
    if tags
        .iter()
        .any(|tag| tag == "malware" || tag == "compromised")
    {
        return Finding {
            verdict: Verdict::Malicious,
            confidence: 80,
            detail: format!("tags {}", tags.join(", ")),
        };
    }
    if tags.iter().any(|tag| tag == "honeypot") {
        return Finding {
            verdict: Verdict::Suspicious,
            confidence: 60,
            detail: "honeypot".to_string(),
        };
    }
    if vuln_count > 0 {
        return Finding {
            verdict: Verdict::Suspicious,
            confidence: 55,
            detail: format!("{vuln_count} vulns"),
        };
    }
    let ports = body
        .get("ports")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(Value::as_u64)
                .map(|port| port.to_string())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    Finding {
        verdict: Verdict::Unknown,
        confidence: 0,
        detail: if ports.is_empty() {
            "seen".to_string()
        } else {
            format!("ports {ports}")
        },
    }
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::parse_ioc;
    use crate::provider::Provider;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn provider(server: &MockServer) -> Shodan {
        Shodan::new(
            http::client(std::time::Duration::from_secs(5)).unwrap(),
            Secret::new("bb-test-secret-key"),
            server.uri(),
            60_000,
        )
    }

    #[tokio::test]
    async fn malware_tag_and_ports_do_not_both_vote_clean() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/shodan/host/192.0.2.1"))
            .and(query_param("key", "bb-test-secret-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip_str": "192.0.2.1",
                "ports": [22],
                "tags": ["malware"]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/shodan/host/192.0.2.2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip_str": "192.0.2.2",
                "ports": [80, 443],
                "tags": []
            })))
            .mount(&server)
            .await;
        let client = provider(&server).await;
        let hit = client
            .lookup(&parse_ioc("192.0.2.1").unwrap())
            .await
            .unwrap();
        assert_eq!(hit.verdict, Verdict::Malicious);
        let seen = client
            .lookup(&parse_ioc("192.0.2.2").unwrap())
            .await
            .unwrap();
        assert_eq!(seen.verdict, Verdict::Unknown);
        assert_eq!(seen.detail, "ports 80,443");
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
}
