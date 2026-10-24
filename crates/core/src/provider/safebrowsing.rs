//! Google Safe Browsing v4 threat match. Free API key.
//!
//! An empty match list is a clean vote. The API says the URL is not in the
//! lists it was asked about. Domains are queried as `http://domain/`.

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::config::Config;
use crate::ioc::{Ioc, IocType};
use crate::score::{Finding, Verdict};
use crate::secret::Secret;

use super::http::{self, IntervalGate};
use super::{
    key_or_skip, origin, rate_of, ready, AuthKind, Provider, ProviderError, ProviderMeta, Slot,
    Tier,
};

const DEFAULT_URL: &str = "https://safebrowsing.googleapis.com";

/// Safe Browsing provider identity.
pub const SAFEBROWSING_META: ProviderMeta = ProviderMeta {
    id: "safebrowsing",
    types: &[IocType::Url, IocType::Domain],
    tier: Tier::Free,
    auth: AuthKind::ApiKey,
    default_rate_per_minute: 60,
};

/// Safe Browsing lookup client.
pub struct SafeBrowsing {
    client: reqwest::Client,
    api_key: Secret,
    base_url: String,
    gate: IntervalGate,
}

impl SafeBrowsing {
    /// `base_url` is the origin, for example `https://safebrowsing.googleapis.com`.
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
    let key = match key_or_skip(cfg, SAFEBROWSING_META) {
        Ok(key) => key.clone(),
        Err(skipped) => return skipped,
    };
    ready(SafeBrowsing::new(
        client,
        key,
        origin(cfg, SAFEBROWSING_META.id, DEFAULT_URL),
        rate_of(cfg, SAFEBROWSING_META),
    ))
}

#[async_trait]
impl Provider for SafeBrowsing {
    fn meta(&self) -> ProviderMeta {
        SAFEBROWSING_META
    }

    async fn lookup(&self, ioc: &Ioc) -> Result<Finding, ProviderError> {
        let url = format!(
            "{}/v4/threatMatches:find",
            self.base_url.trim_end_matches('/')
        );
        let entry = threat_url(ioc);
        let payload = json!({
            "client": {
                "clientId": "butcherbird",
                "clientVersion": env!("CARGO_PKG_VERSION")
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{ "url": entry }]
            }
        });
        let response = http::send(&self.gate, &self.api_key, || {
            self.client
                .post(&url)
                .query(&[("key", self.api_key.as_header_value())])
                .header(reqwest::header::ACCEPT, "application/json")
                .json(&payload)
                .send()
        })
        .await?;
        let body: Value = response.json().await.map_err(|_| ProviderError::Decode)?;
        Ok(map_body(&body))
    }
}

fn threat_url(ioc: &Ioc) -> String {
    match ioc.kind {
        IocType::Domain => format!("http://{}/", ioc.value),
        _ => ioc.value.clone(),
    }
}

fn map_body(body: &Value) -> Finding {
    let matches = body.get("matches").and_then(Value::as_array);
    let Some(matches) = matches.filter(|rows| !rows.is_empty()) else {
        return Finding {
            verdict: Verdict::Clean,
            confidence: 70,
            detail: "no matches".to_string(),
        };
    };
    let kind = matches
        .first()
        .and_then(|row| row.get("threatType"))
        .and_then(Value::as_str)
        .unwrap_or("listed");
    Finding {
        verdict: Verdict::Malicious,
        confidence: 90,
        detail: kind.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::parse_ioc;
    use crate::provider::Provider;
    use wiremock::matchers::{body_string_contains, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn provider(server: &MockServer) -> SafeBrowsing {
        SafeBrowsing::new(
            http::client(std::time::Duration::from_secs(5)).unwrap(),
            Secret::new("bb-test-secret-key"),
            server.uri(),
            60_000,
        )
    }

    #[tokio::test]
    async fn match_and_empty_object() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v4/threatMatches:find"))
            .and(query_param("key", "bb-test-secret-key"))
            .and(body_string_contains("https://bad.example/a"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "matches": [{ "threatType": "SOCIAL_ENGINEERING" }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v4/threatMatches:find"))
            .and(body_string_contains("http://evil.example/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
        let client = provider(&server).await;
        let hit = client
            .lookup(&parse_ioc("https://bad.example/a").unwrap())
            .await
            .unwrap();
        assert_eq!(hit.verdict, Verdict::Malicious);
        assert_eq!(hit.detail, "SOCIAL_ENGINEERING");
        let clean = client
            .lookup(&parse_ioc("evil.example").unwrap())
            .await
            .unwrap();
        assert_eq!(clean.verdict, Verdict::Clean);
        assert_eq!(clean.confidence, 70);
    }
}
