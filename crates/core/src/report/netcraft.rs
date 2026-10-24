//! Netcraft URL report.
//!
//! `POST /api/v3/report/urls`. `sandbox` uses `/api/v3/test/report/urls`, which
//! Netcraft documents as a non-destructive endpoint. The reporter's email is
//! the contact Netcraft sends the analysis to. It is not an API key.

use std::sync::Arc;

use async_trait::async_trait;

use crate::config::Config;
use crate::ioc::{Ioc, IocType};
use crate::provider::{http_send, IntervalGate};
use crate::secret::{redact, Secret};
use crate::ProviderError;

use super::{finish_body, ReportPlan, Reporter};

/// Netcraft report client.
pub struct NetcraftReporter {
    client: reqwest::Client,
    base_url: String,
    sandbox: bool,
    email: String,
    reason: String,
    gate: IntervalGate,
}

impl NetcraftReporter {
    /// `base_url` is the origin, for example `https://report.netcraft.com`.
    pub fn new(
        client: reqwest::Client,
        base_url: impl Into<String>,
        sandbox: bool,
        email: impl Into<String>,
        reason: impl Into<String>,
        rate_per_minute: u32,
    ) -> Self {
        Self {
            client,
            base_url: base_url.into(),
            sandbox,
            email: email.into(),
            reason: reason.into(),
            gate: IntervalGate::per_minute(rate_per_minute),
        }
    }
}

pub(crate) fn build(cfg: &Config, client: reqwest::Client) -> Result<Arc<dyn Reporter>, String> {
    if cfg.report.netcraft_email.trim().is_empty() {
        return Err("skipped netcraft: report.netcraft.email is not set".into());
    }
    Ok(Arc::new(NetcraftReporter::new(
        client,
        cfg.report.netcraft_base_url.clone(),
        cfg.report.netcraft_sandbox,
        cfg.report.netcraft_email.clone(),
        cfg.report.netcraft_reason.clone(),
        30,
    )))
}

#[async_trait]
impl Reporter for NetcraftReporter {
    fn id(&self) -> &'static str {
        "netcraft"
    }

    fn supports(&self, kind: IocType) -> bool {
        kind == IocType::Url
    }

    fn prepare(&self, ioc: &Ioc) -> ReportPlan {
        if !self.supports(ioc.kind) {
            return ReportPlan::Unsupported;
        }
        let body = serde_json::json!({
            "email": self.email,
            "urls": [{
                "url": ioc.value,
                "reason": self.reason,
            }],
        });
        ReportPlan::Ready {
            payload: redact(&body.to_string(), &Secret::new("")),
            destination: "netcraft".to_string(),
        }
    }

    async fn send(&self, _ioc: &Ioc, payload: &str) -> Result<String, ProviderError> {
        let path = if self.sandbox {
            "/api/v3/test/report/urls"
        } else {
            "/api/v3/report/urls"
        };
        let url = format!("{}{path}", self.base_url.trim_end_matches('/'));
        let response = http_send(&self.gate, &Secret::new(""), || {
            self.client
                .post(&url)
                .header(reqwest::header::ACCEPT, "application/json")
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(payload.to_string())
                .send()
        })
        .await?;
        let text = response.text().await.unwrap_or_default();
        finish_body(text, &Secret::new(""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::parse_ioc;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn sandbox_post_includes_the_url_and_the_contact() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v3/test/report/urls"))
            .and(body_string_contains("https://phish.example/login"))
            .and(body_string_contains("reports@example.com"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"uuid":"00000000-0000-4000-8000-000000000001"}"#),
            )
            .expect(1)
            .mount(&server)
            .await;
        let reporter = NetcraftReporter::new(
            reqwest::Client::new(),
            server.uri(),
            true,
            "reports@example.com",
            "Reported by Butcherbird",
            60_000,
        );
        let ioc = parse_ioc("https://phish.example/login").unwrap();
        let ReportPlan::Ready { payload, .. } = reporter.prepare(&ioc) else {
            panic!("expected a payload");
        };
        let body = reporter.send(&ioc, &payload).await.unwrap();
        assert!(body.contains("uuid"));
    }
}
