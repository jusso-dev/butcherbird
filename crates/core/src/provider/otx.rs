//! AlienVault OTX general indicator endpoint. Free API key.

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

const DEFAULT_URL: &str = "https://otx.alienvault.com";

/// OTX provider identity.
pub const OTX_META: ProviderMeta = ProviderMeta {
    id: "otx",
    types: &[
        IocType::Ipv4,
        IocType::Ipv6,
        IocType::Domain,
        IocType::Url,
        IocType::Email,
        IocType::Md5,
        IocType::Sha1,
        IocType::Sha256,
    ],
    tier: Tier::Free,
    auth: AuthKind::ApiKey,
    default_rate_per_minute: 30,
};

/// AlienVault OTX client.
pub struct Otx {
    client: reqwest::Client,
    api_key: Secret,
    base_url: String,
    gate: IntervalGate,
}

impl Otx {
    /// `base_url` is the origin, for example `https://otx.alienvault.com`.
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
    let key = match key_or_skip(cfg, OTX_META) {
        Ok(key) => key.clone(),
        Err(skipped) => return skipped,
    };
    ready(Otx::new(
        client,
        key,
        origin(cfg, OTX_META.id, DEFAULT_URL),
        rate_of(cfg, OTX_META),
    ))
}

#[async_trait]
impl Provider for Otx {
    fn meta(&self) -> ProviderMeta {
        OTX_META
    }

    async fn lookup(&self, ioc: &Ioc) -> Result<Finding, ProviderError> {
        let url = format!(
            "{}/api/v1/indicators/{}/{}/general",
            self.base_url.trim_end_matches('/'),
            section(ioc.kind),
            http::encode_segment(&ioc.value)
        );
        let response = match http::send(&self.gate, &self.api_key, || {
            self.client
                .get(&url)
                .header("X-OTX-API-KEY", self.api_key.as_header_value())
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
        })
        .await
        {
            // Zero pulses is unknown. A missing indicator is the same idea.
            Err(err) if is_not_found(&err) => {
                return Ok(Finding {
                    verdict: Verdict::Unknown,
                    confidence: 0,
                    detail: "not in pulses".to_string(),
                });
            }
            other => other?,
        };
        let body: Value = response.json().await.map_err(|_| ProviderError::Decode)?;
        map_body(&body)
    }
}

fn section(kind: IocType) -> &'static str {
    match kind {
        IocType::Ipv4 => "IPv4",
        IocType::Ipv6 => "IPv6",
        IocType::Domain => "domain",
        IocType::Url => "url",
        IocType::Email => "email",
        IocType::Md5 | IocType::Sha1 | IocType::Sha256 => "file",
        _ => "domain",
    }
}

fn map_body(body: &Value) -> Result<Finding, ProviderError> {
    let count = body
        .pointer("/pulse_info/count")
        .and_then(Value::as_u64)
        .or_else(|| {
            body.pointer("/pulse_info/pulses")
                .and_then(Value::as_array)
                .map(|pulses| pulses.len() as u64)
        })
        .ok_or(ProviderError::Decode)?;
    if count == 0 {
        return Ok(Finding {
            verdict: Verdict::Unknown,
            confidence: 0,
            detail: "not in pulses".to_string(),
        });
    }
    if count >= 3 {
        let confidence = u64_cap(50 + count * 5, 100);
        return Ok(Finding {
            verdict: Verdict::Malicious,
            confidence,
            detail: format!("{count} pulses"),
        });
    }
    Ok(Finding {
        verdict: Verdict::Suspicious,
        confidence: u64_cap(40 + count * 10, 90),
        detail: format!("{count} pulses"),
    })
}

fn u64_cap(value: u64, cap: u64) -> u8 {
    u8::try_from(value.min(cap)).unwrap_or(u8::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::parse_ioc;
    use crate::provider::Provider;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn key() -> Secret {
        Secret::new("bb-test-secret-key")
    }

    async fn provider(server: &MockServer) -> Otx {
        Otx::new(
            http::client(std::time::Duration::from_secs(5)).unwrap(),
            key(),
            server.uri(),
            60_000,
        )
    }

    #[tokio::test]
    async fn pulses_are_malicious() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/indicators/IPv4/192.0.2.1/general"))
            .and(header("X-OTX-API-KEY", "bb-test-secret-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "pulse_info": { "count": 4 }
            })))
            .mount(&server)
            .await;
        let hit = provider(&server)
            .await
            .lookup(&parse_ioc("192.0.2.1").unwrap())
            .await
            .unwrap();
        assert_eq!(hit.verdict, Verdict::Malicious);
        assert_eq!(hit.detail, "4 pulses");
    }

    #[tokio::test]
    async fn zero_pulses_are_unknown() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/indicators/domain/evil.example/general"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "pulse_info": { "count": 0 }
            })))
            .mount(&server)
            .await;
        let hit = provider(&server)
            .await
            .lookup(&parse_ioc("evil.example").unwrap())
            .await
            .unwrap();
        assert_eq!(hit.verdict, Verdict::Unknown);
    }

    #[tokio::test]
    async fn auth_error_hides_key() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401).set_body_string("bad bb-test-secret-key"))
            .mount(&server)
            .await;
        let err = provider(&server)
            .await
            .lookup(&parse_ioc("192.0.2.1").unwrap())
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "authentication failed");
        assert!(!err.to_string().contains("secret-key"));
    }
}
