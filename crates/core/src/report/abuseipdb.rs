//! AbuseIPDB v2 report API. IPv4 and IPv6.
//!
//! `POST {base}/api/v2/report` with form fields `ip` and `categories`.
//! Category `15` (Hacking) is the default. The API key stays in the `Key` header.

use std::sync::Arc;

use async_trait::async_trait;

use crate::config::Config;
use crate::ioc::{Ioc, IocType};
use crate::provider::{http_send, rate_of, IntervalGate, ABUSEIPDB_META};
use crate::secret::{redact, Secret};
use crate::ProviderError;

use super::{finish_body, take_key, ReportPlan, Reporter};

const DEFAULT_URL: &str = "https://api.abuseipdb.com";

/// AbuseIPDB report client.
pub struct AbuseIpdbReporter {
    client: reqwest::Client,
    api_key: Secret,
    base_url: String,
    gate: IntervalGate,
    categories: String,
    comment: String,
}

impl AbuseIpdbReporter {
    /// `base_url` is the origin, for example `https://api.abuseipdb.com`.
    pub fn new(
        client: reqwest::Client,
        api_key: Secret,
        base_url: impl Into<String>,
        rate_per_minute: u32,
        categories: impl Into<String>,
        comment: impl Into<String>,
    ) -> Self {
        Self {
            client,
            api_key,
            base_url: base_url.into(),
            gate: IntervalGate::per_minute(rate_per_minute),
            categories: categories.into(),
            comment: comment.into(),
        }
    }
}

pub(crate) fn build(cfg: &Config, client: reqwest::Client) -> Result<Arc<dyn Reporter>, String> {
    let api_key = take_key(cfg, ABUSEIPDB_META.id)?;
    Ok(Arc::new(AbuseIpdbReporter::new(
        client,
        api_key,
        cfg.provider(ABUSEIPDB_META.id)
            .base_url
            .clone()
            .unwrap_or_else(|| DEFAULT_URL.to_string()),
        rate_of(cfg, ABUSEIPDB_META),
        cfg.report.abuseipdb_categories.clone(),
        cfg.report.abuseipdb_comment.clone(),
    )))
}

#[async_trait]
impl Reporter for AbuseIpdbReporter {
    fn id(&self) -> &'static str {
        ABUSEIPDB_META.id
    }

    fn supports(&self, kind: IocType) -> bool {
        matches!(kind, IocType::Ipv4 | IocType::Ipv6)
    }

    fn prepare(&self, ioc: &Ioc) -> ReportPlan {
        if !self.supports(ioc.kind) {
            return ReportPlan::Unsupported;
        }
        let mut body = url::form_urlencoded::Serializer::new(String::new());
        body.append_pair("ip", &ioc.value);
        body.append_pair("categories", &self.categories);
        if !self.comment.is_empty() {
            body.append_pair("comment", &self.comment);
        }
        ReportPlan::Ready {
            payload: redact(&body.finish(), &self.api_key),
            destination: ABUSEIPDB_META.id.to_string(),
        }
    }

    async fn send(&self, _ioc: &Ioc, payload: &str) -> Result<String, ProviderError> {
        let url = format!("{}/api/v2/report", self.base_url.trim_end_matches('/'));
        let response = http_send(&self.gate, &self.api_key, || {
            self.client
                .post(&url)
                .header("Key", self.api_key.as_header_value())
                .header(reqwest::header::ACCEPT, "application/json")
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
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

    fn reporter(base: &str) -> AbuseIpdbReporter {
        AbuseIpdbReporter::new(
            reqwest::Client::new(),
            Secret::new("bb-test-secret-key"),
            base,
            60_000,
            "15",
            "",
        )
    }

    #[test]
    fn payload_is_the_form_body_without_the_key() {
        let planned =
            reporter("https://api.abuseipdb.com").prepare(&parse_ioc("192.0.2.1").unwrap());
        let ReportPlan::Ready { payload, .. } = planned else {
            panic!("expected a payload");
        };
        assert!(payload.contains("ip=192.0.2.1"));
        assert!(payload.contains("categories=15"));
        assert!(!payload.contains("secret-key"));
        assert!(!payload.contains("comment="));
    }

    #[tokio::test]
    async fn report_posts_the_address() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v2/report"))
            .and(header("Key", "bb-test-secret-key"))
            .and(body_string_contains("ip=192.0.2.1"))
            .and(body_string_contains("categories=15"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(
                    r#"{"data":{"ipAddress":"192.0.2.1","abuseConfidenceScore":0}}"#,
                ),
            )
            .expect(1)
            .mount(&server)
            .await;

        let reporter = reporter(&server.uri());
        let ioc = parse_ioc("192.0.2.1").unwrap();
        let ReportPlan::Ready { payload, .. } = reporter.prepare(&ioc) else {
            panic!("expected a payload");
        };
        let body = reporter.send(&ioc, &payload).await.unwrap();
        assert!(!body.contains("secret-key"));
        assert!(body.contains("abuseConfidenceScore"));
    }
}
