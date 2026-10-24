//! abuse.ch URLhaus URL and host lookup. Free, API key.

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

const DEFAULT_URL: &str = "https://urlhaus-api.abuse.ch";

/// URLhaus provider identity.
pub const URLHAUS_META: ProviderMeta = ProviderMeta {
    id: "urlhaus",
    types: &[IocType::Url, IocType::Domain, IocType::Ipv4, IocType::Ipv6],
    tier: Tier::Free,
    auth: AuthKind::ApiKey,
    default_rate_per_minute: 60,
};

/// URLhaus lookup client.
pub struct Urlhaus {
    client: reqwest::Client,
    api_key: Secret,
    base_url: String,
    gate: IntervalGate,
}

impl Urlhaus {
    /// `base_url` is the origin, for example `https://urlhaus-api.abuse.ch`.
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
    let key = match key_or_skip(cfg, URLHAUS_META) {
        Ok(key) => key.clone(),
        Err(skipped) => return skipped,
    };
    let settings = cfg.provider(URLHAUS_META.id);
    let base = settings
        .base_url
        .clone()
        .unwrap_or_else(|| DEFAULT_URL.to_string());
    ready(Urlhaus::new(
        client,
        key,
        base,
        configured_rate(URLHAUS_META, settings.rate_per_minute),
    ))
}

#[async_trait]
impl Provider for Urlhaus {
    fn meta(&self) -> ProviderMeta {
        URLHAUS_META
    }

    async fn lookup(&self, ioc: &Ioc) -> Result<Finding, ProviderError> {
        let (path, field) = match ioc.kind {
            IocType::Url => ("/v1/url/", "url"),
            IocType::Domain | IocType::Ipv4 | IocType::Ipv6 => ("/v1/host/", "host"),
            _ => {
                return Ok(Finding {
                    verdict: Verdict::Unknown,
                    confidence: 0,
                    detail: "unsupported type".to_string(),
                })
            }
        };
        let url = format!("{}{path}", self.base_url.trim_end_matches('/'));
        let response = http::send(&self.gate, &self.api_key, || {
            self.client
                .post(&url)
                .header("Auth-Key", self.api_key.as_header_value())
                .form(&[(field, ioc.value.as_str())])
                .send()
        })
        .await?;
        let body: Value = response.json().await.map_err(|_| ProviderError::Decode)?;
        map_body(ioc.kind, &body)
    }
}

fn map_body(kind: IocType, body: &Value) -> Result<Finding, ProviderError> {
    let status = body
        .get("query_status")
        .and_then(Value::as_str)
        .unwrap_or("");
    if status == "no_results" {
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
    if kind == IocType::Url {
        let url_status = body
            .get("url_status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let threat = body
            .get("threat")
            .and_then(Value::as_str)
            .unwrap_or("listed");
        return Ok(map_status(url_status, threat));
    }
    let urls = body.get("urls").and_then(Value::as_array);
    let online = urls.is_some_and(|rows| {
        rows.iter()
            .any(|row| row.get("url_status").and_then(Value::as_str) == Some("online"))
    });
    if online {
        return Ok(Finding {
            verdict: Verdict::Malicious,
            confidence: 90,
            detail: "host has an online url".to_string(),
        });
    }
    if urls.is_some_and(|rows| !rows.is_empty()) {
        return Ok(Finding {
            verdict: Verdict::Suspicious,
            confidence: 60,
            detail: "host listed, no online url".to_string(),
        });
    }
    Ok(Finding {
        verdict: Verdict::Suspicious,
        confidence: 50,
        detail: "host listed".to_string(),
    })
}

fn map_status(url_status: &str, threat: &str) -> Finding {
    match url_status {
        "online" => Finding {
            verdict: Verdict::Malicious,
            confidence: 90,
            detail: format!("listed online, {threat}"),
        },
        "offline" => Finding {
            verdict: Verdict::Suspicious,
            confidence: 60,
            detail: format!("listed offline, {threat}"),
        },
        other => Finding {
            verdict: Verdict::Suspicious,
            confidence: 45,
            detail: format!("listed ({other}), {threat}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::parse_ioc;
    use crate::provider::Provider;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn provider(server: &MockServer) -> Urlhaus {
        Urlhaus::new(
            http::client(std::time::Duration::from_secs(5)).unwrap(),
            Secret::new("bb-test-secret-key"),
            server.uri(),
            60_000,
        )
    }

    #[tokio::test]
    async fn online_url_is_malicious() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/url/"))
            .and(header("Auth-Key", "bb-test-secret-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "query_status": "ok",
                "url_status": "online",
                "threat": "malware_download"
            })))
            .mount(&server)
            .await;
        let hit = provider(&server)
            .await
            .lookup(&parse_ioc("https://bad.example/login").unwrap())
            .await
            .unwrap();
        assert_eq!(hit.verdict, Verdict::Malicious);
        assert!(hit.detail.contains("malware_download"));
    }

    #[tokio::test]
    async fn unknown_url_is_clean() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/url/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "query_status": "no_results"
            })))
            .mount(&server)
            .await;
        let hit = provider(&server)
            .await
            .lookup(&parse_ioc("https://clean.example/").unwrap())
            .await
            .unwrap();
        assert_eq!(hit.verdict, Verdict::Clean);
    }

    #[tokio::test]
    async fn host_with_online_url() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/host/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "query_status": "ok",
                "urls": [{ "url_status": "online", "url": "http://bad.example/a" }]
            })))
            .mount(&server)
            .await;
        let hit = provider(&server)
            .await
            .lookup(&parse_ioc("192.0.2.10").unwrap())
            .await
            .unwrap();
        assert_eq!(hit.verdict, Verdict::Malicious);
    }

    #[tokio::test]
    async fn auth_failure() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let err = provider(&server)
            .await
            .lookup(&parse_ioc("evil.example").unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::Auth));
        assert!(!err.to_string().contains("secret-key"));
    }
}
