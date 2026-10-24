//! GreyNoise Community API. Free API key. IPv4 only.

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

const DEFAULT_URL: &str = "https://api.greynoise.io";

/// GreyNoise provider identity.
pub const GREYNOISE_META: ProviderMeta = ProviderMeta {
    id: "greynoise",
    types: &[IocType::Ipv4],
    tier: Tier::Free,
    auth: AuthKind::ApiKey,
    default_rate_per_minute: 10,
};

/// GreyNoise Community client.
pub struct GreyNoise {
    client: reqwest::Client,
    api_key: Secret,
    base_url: String,
    gate: IntervalGate,
}

impl GreyNoise {
    /// `base_url` is the origin, for example `https://api.greynoise.io`.
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
    let key = match key_or_skip(cfg, GREYNOISE_META) {
        Ok(key) => key.clone(),
        Err(skipped) => return skipped,
    };
    ready(GreyNoise::new(
        client,
        key,
        origin(cfg, GREYNOISE_META.id, DEFAULT_URL),
        rate_of(cfg, GREYNOISE_META),
    ))
}

#[async_trait]
impl Provider for GreyNoise {
    fn meta(&self) -> ProviderMeta {
        GREYNOISE_META
    }

    async fn lookup(&self, ioc: &Ioc) -> Result<Finding, ProviderError> {
        let url = format!(
            "{}/v3/community/{}",
            self.base_url.trim_end_matches('/'),
            http::encode_segment(&ioc.value)
        );
        let response = match http::send(&self.gate, &self.api_key, || {
            self.client
                .get(&url)
                .header("key", self.api_key.as_header_value())
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
        })
        .await
        {
            Err(err) if is_not_found(&err) => {
                return Ok(Finding {
                    verdict: Verdict::Unknown,
                    confidence: 0,
                    detail: "not seen".to_string(),
                });
            }
            other => other?,
        };
        let body: Value = response.json().await.map_err(|_| ProviderError::Decode)?;
        Ok(map_body(&body))
    }
}

fn map_body(body: &Value) -> Finding {
    let class = body
        .get("classification")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let riot = body.get("riot").and_then(Value::as_bool).unwrap_or(false);
    let noise = body.get("noise").and_then(Value::as_bool).unwrap_or(false);
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if riot {
        return Finding {
            verdict: Verdict::Clean,
            confidence: 80,
            detail: format!("riot {name}"),
        };
    }
    match class {
        "malicious" => Finding {
            verdict: Verdict::Malicious,
            confidence: 85,
            detail: format!("classification malicious, {name}"),
        },
        "benign" => Finding {
            verdict: Verdict::Clean,
            confidence: 70,
            detail: format!("classification benign, {name}"),
        },
        _ if noise => Finding {
            verdict: Verdict::Suspicious,
            confidence: 50,
            detail: format!("noise, classification {class}"),
        },
        _ => Finding {
            verdict: Verdict::Unknown,
            confidence: 0,
            detail: format!("classification {class}"),
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

    async fn provider(server: &MockServer) -> GreyNoise {
        GreyNoise::new(
            http::client(std::time::Duration::from_secs(5)).unwrap(),
            Secret::new("bb-test-secret-key"),
            server.uri(),
            60_000,
        )
    }

    #[tokio::test]
    async fn malicious_classification() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v3/community/192.0.2.1"))
            .and(header("key", "bb-test-secret-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ip": "192.0.2.1",
                "noise": true,
                "riot": false,
                "classification": "malicious",
                "name": "unknown"
            })))
            .mount(&server)
            .await;
        let hit = provider(&server)
            .await
            .lookup(&parse_ioc("192.0.2.1").unwrap())
            .await
            .unwrap();
        assert_eq!(hit.verdict, Verdict::Malicious);
        assert_eq!(hit.confidence, 85);
    }

    #[tokio::test]
    async fn riot_is_clean_and_missing_is_unknown() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v3/community/192.0.2.2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "classification": "malicious",
                "riot": true,
                "name": "Example CDN"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/community/192.0.2.3"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let client = provider(&server).await;
        let riot = client
            .lookup(&parse_ioc("192.0.2.2").unwrap())
            .await
            .unwrap();
        assert_eq!(riot.verdict, Verdict::Clean);
        assert_eq!(riot.detail, "riot Example CDN");
        let missing = client
            .lookup(&parse_ioc("192.0.2.3").unwrap())
            .await
            .unwrap();
        assert_eq!(missing.verdict, Verdict::Unknown);
        assert_eq!(missing.detail, "not seen");
    }
}
