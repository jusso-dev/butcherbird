//! abuse.ch URLhaus submission. URLs only.
//!
//! The lookup API and the submit API are different hosts. A configured
//! `base_url` is honoured for both (tests and proxies). Otherwise submit goes
//! to `https://urlhaus.abuse.ch/api/`.

use std::sync::Arc;

use async_trait::async_trait;

use crate::config::Config;
use crate::ioc::{Ioc, IocType};
use crate::provider::{http_send, rate_of, IntervalGate, URLHAUS_META};
use crate::secret::{redact, Secret};
use crate::ProviderError;

use super::{finish_body, take_key, ReportPlan, Reporter};

const DEFAULT_SUBMIT_URL: &str = "https://urlhaus.abuse.ch";

/// URLhaus submit client.
pub struct UrlhausReporter {
    client: reqwest::Client,
    api_key: Secret,
    base_url: String,
    gate: IntervalGate,
}

impl UrlhausReporter {
    /// `base_url` is the origin, for example `https://urlhaus.abuse.ch`.
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

pub(crate) fn build(cfg: &Config, client: reqwest::Client) -> Result<Arc<dyn Reporter>, String> {
    let api_key = take_key(cfg, URLHAUS_META.id)?;
    let base = cfg
        .provider(URLHAUS_META.id)
        .base_url
        .clone()
        .unwrap_or_else(|| DEFAULT_SUBMIT_URL.to_string());
    Ok(Arc::new(UrlhausReporter::new(
        client,
        api_key,
        base,
        rate_of(cfg, URLHAUS_META),
    )))
}

#[async_trait]
impl Reporter for UrlhausReporter {
    fn id(&self) -> &'static str {
        URLHAUS_META.id
    }

    fn supports(&self, kind: IocType) -> bool {
        kind == IocType::Url
    }

    fn prepare(&self, ioc: &Ioc) -> ReportPlan {
        if !self.supports(ioc.kind) {
            return ReportPlan::Unsupported;
        }
        let body = serde_json::json!({
            "anonymous": "0",
            "submission": [{
                "url": ioc.value,
                "threat": "malware_download",
            }],
        });
        ReportPlan::Ready {
            payload: redact(&body.to_string(), &self.api_key),
            destination: URLHAUS_META.id.to_string(),
        }
    }

    async fn send(&self, _ioc: &Ioc, payload: &str) -> Result<String, ProviderError> {
        let url = format!("{}/api/", self.base_url.trim_end_matches('/'));
        let response = http_send(&self.gate, &self.api_key, || {
            self.client
                .post(&url)
                .header("Auth-Key", self.api_key.as_header_value())
                .header(reqwest::header::ACCEPT, "application/json")
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(payload.to_string())
                .send()
        })
        .await?;
        let text = response.text().await.unwrap_or_default();
        finish_body(text, &self.api_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::parse_ioc;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn submit_posts_the_url() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/"))
            .and(header("Auth-Key", "bb-test-secret-key"))
            .and(body_string_contains("https://phish.example/login"))
            .and(body_string_contains("malware_download"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"query_status":"ok"}"#))
            .expect(1)
            .mount(&server)
            .await;

        let reporter = UrlhausReporter::new(
            reqwest::Client::new(),
            Secret::new("bb-test-secret-key"),
            server.uri(),
            60_000,
        );
        let ioc = parse_ioc("https://phish.example/login").unwrap();
        let ReportPlan::Ready { payload, .. } = reporter.prepare(&ioc) else {
            panic!("expected a payload");
        };
        assert!(!payload.contains("secret-key"));
        let body = reporter.send(&ioc, &payload).await.unwrap();
        assert!(body.contains("ok"));
        assert!(matches!(
            reporter.prepare(&parse_ioc("192.0.2.1").unwrap()),
            ReportPlan::Unsupported
        ));
    }
}
