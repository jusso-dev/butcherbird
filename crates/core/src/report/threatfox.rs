//! abuse.ch ThreatFox `submit_ioc`. Same host as the lookup API.
//!
//! Official types are `url`, `domain`, `md5_hash`, `sha256_hash` and `ip:port`.
//! A bare IPv4 has no port. This reporter records a skip instead of inventing one.
//! SHA-1 is not a submission type.

use std::sync::Arc;

use async_trait::async_trait;

use crate::config::Config;
use crate::ioc::{Ioc, IocType};
use crate::provider::{http_send, rate_of, IntervalGate, THREATFOX_META};
use crate::secret::{redact, Secret};
use crate::ProviderError;

use super::{finish_body, take_key, ReportPlan, Reporter};

const DEFAULT_URL: &str = "https://threatfox-api.abuse.ch";

/// ThreatFox submit client.
pub struct ThreatFoxReporter {
    client: reqwest::Client,
    api_key: Secret,
    base_url: String,
    gate: IntervalGate,
    threat_type: String,
    malware: String,
    confidence: u8,
}

impl ThreatFoxReporter {
    /// `base_url` is the origin, for example `https://threatfox-api.abuse.ch`.
    pub fn new(
        client: reqwest::Client,
        api_key: Secret,
        base_url: impl Into<String>,
        rate_per_minute: u32,
        threat_type: impl Into<String>,
        malware: impl Into<String>,
        confidence: u8,
    ) -> Self {
        Self {
            client,
            api_key,
            base_url: base_url.into(),
            gate: IntervalGate::per_minute(rate_per_minute),
            threat_type: threat_type.into(),
            malware: malware.into(),
            confidence,
        }
    }
}

pub(crate) fn build(cfg: &Config, client: reqwest::Client) -> Result<Arc<dyn Reporter>, String> {
    let api_key = take_key(cfg, THREATFOX_META.id)?;
    Ok(Arc::new(ThreatFoxReporter::new(
        client,
        api_key,
        cfg.provider(THREATFOX_META.id)
            .base_url
            .clone()
            .unwrap_or_else(|| DEFAULT_URL.to_string()),
        rate_of(cfg, THREATFOX_META),
        cfg.report.threatfox_threat_type.clone(),
        cfg.report.threatfox_malware.clone(),
        cfg.report.threatfox_confidence,
    )))
}

#[async_trait]
impl Reporter for ThreatFoxReporter {
    fn id(&self) -> &'static str {
        THREATFOX_META.id
    }

    fn supports(&self, kind: IocType) -> bool {
        matches!(
            kind,
            IocType::Ipv4
                | IocType::Domain
                | IocType::Url
                | IocType::Md5
                | IocType::Sha1
                | IocType::Sha256
        )
    }

    fn prepare(&self, ioc: &Ioc) -> ReportPlan {
        let ioc_type = match ioc.kind {
            IocType::Url => "url",
            IocType::Domain => "domain",
            IocType::Md5 => "md5_hash",
            IocType::Sha256 => "sha256_hash",
            IocType::Ipv4 => {
                return ReportPlan::Skip {
                    reason: "bare ipv4 is not submitted; ThreatFox requires ip:port".into(),
                };
            }
            IocType::Sha1 => {
                return ReportPlan::Skip {
                    reason: "sha1 is not a ThreatFox submission type".into(),
                };
            }
            _ => return ReportPlan::Unsupported,
        };
        let body = serde_json::json!({
            "query": "submit_ioc",
            "threat_type": self.threat_type,
            "ioc_type": ioc_type,
            "malware": self.malware,
            "confidence_level": self.confidence,
            "reference": "",
            "comment": "",
            "anonymous": 0,
            "tags": [],
            "iocs": [ioc.value],
        });
        ReportPlan::Ready {
            payload: redact(&body.to_string(), &self.api_key),
        }
    }

    async fn send(&self, _ioc: &Ioc, payload: &str) -> Result<String, ProviderError> {
        let url = format!("{}/api/v1/", self.base_url.trim_end_matches('/'));
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
    async fn submit_posts_a_url_and_skips_a_bare_ip() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/"))
            .and(header("Auth-Key", "bb-test-secret-key"))
            .and(body_string_contains("https://phish.example/login"))
            .and(body_string_contains("submit_ioc"))
            .and(body_string_contains("payload_delivery"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"query_status":"ok"}"#))
            .expect(1)
            .mount(&server)
            .await;

        let reporter = ThreatFoxReporter::new(
            reqwest::Client::new(),
            Secret::new("bb-test-secret-key"),
            server.uri(),
            60_000,
            "payload_delivery",
            "unknown",
            50,
        );
        let url = parse_ioc("https://phish.example/login").unwrap();
        let ReportPlan::Ready { payload } = reporter.prepare(&url) else {
            panic!("expected a payload");
        };
        assert!(!payload.contains("secret-key"));
        assert!(payload.contains("\"ioc_type\":\"url\""));
        reporter.send(&url, &payload).await.unwrap();

        let ip = parse_ioc("192.0.2.1").unwrap();
        let ReportPlan::Skip { reason } = reporter.prepare(&ip) else {
            panic!("bare ipv4 must be skipped");
        };
        assert!(reason.contains("ip:port"));

        let sha1 = parse_ioc("da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap();
        assert!(matches!(reporter.prepare(&sha1), ReportPlan::Skip { .. }));
    }
}
