//! Abuse mail to the RDAP abuse contact.
//!
//! `plan` queries RDAP and renders the message. A dry run stops there.
//! `send` delivers that message over SMTP or an HTTP mail API.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::Config;
use crate::ioc::{Ioc, IocType};
use crate::provider::{http_send, origin, rate_of, IntervalGate, Rdap, RDAP_META};
use crate::secret::{redact, Secret};
use crate::ProviderError;

use super::template::{self, ABUSE_EMAIL};
use super::{finish_body, ReportPlan, Reporter};

const DEFAULT_RDAP: &str = "https://rdap.org";

struct SmtpSettings {
    host: String,
    port: u16,
    starttls: bool,
    username: Option<String>,
    password: Option<Secret>,
}

enum Transport {
    Smtp(SmtpSettings),
    Http {
        url: String,
        token: Option<Secret>,
        client: reqwest::Client,
        gate: IntervalGate,
    },
}

/// RDAP abuse-contact mail.
pub struct EmailReporter {
    rdap: Rdap,
    from: String,
    template: String,
    transport: Transport,
}

impl EmailReporter {
    fn new(rdap: Rdap, from: impl Into<String>, template: String, transport: Transport) -> Self {
        Self {
            rdap,
            from: from.into(),
            template,
            transport,
        }
    }
}

pub(crate) fn build(cfg: &Config, client: reqwest::Client) -> Result<Arc<dyn Reporter>, String> {
    if !cfg.provider("rdap").enabled {
        return Err("skipped email: rdap is disabled".into());
    }
    if cfg.report.email_from.trim().is_empty() {
        return Err("skipped email: report.email.from is not set".into());
    }
    let transport = match (&cfg.report.smtp_host, &cfg.report.mail_http_url) {
        (None, None) => {
            return Err(
                "skipped email: set report.email.smtp_host or report.email.http_url".into(),
            );
        }
        (Some(_), Some(_)) => {
            return Err("skipped email: report.email sets both smtp_host and http_url".into());
        }
        (Some(host), None) => Transport::Smtp(SmtpSettings {
            host: host.clone(),
            port: cfg.report.smtp_port,
            starttls: cfg.report.smtp_starttls,
            username: cfg.report.smtp_username.clone(),
            password: cfg.report.smtp_password.clone(),
        }),
        (None, Some(url)) => Transport::Http {
            url: url.clone(),
            token: cfg.report.mail_token.clone(),
            client: client.clone(),
            gate: IntervalGate::per_minute(30),
        },
    };
    let template = template::load_template(
        cfg.report.templates_dir.as_deref(),
        "abuse-email.hbs",
        ABUSE_EMAIL,
    )
    .map_err(|err| err.to_string())?;
    let rdap = Rdap::new(
        client,
        origin(cfg, "rdap", DEFAULT_RDAP),
        rate_of(cfg, RDAP_META),
    );
    Ok(Arc::new(EmailReporter::new(
        rdap,
        cfg.report.email_from.clone(),
        template,
        transport,
    )))
}

#[async_trait]
impl Reporter for EmailReporter {
    fn id(&self) -> &'static str {
        "email"
    }

    fn supports(&self, kind: IocType) -> bool {
        matches!(
            kind,
            IocType::Ipv4 | IocType::Ipv6 | IocType::Domain | IocType::Url
        )
    }

    fn prepare(&self, _ioc: &Ioc) -> ReportPlan {
        ReportPlan::Unsupported
    }

    async fn plan(&self, ioc: &Ioc) -> Result<ReportPlan, ProviderError> {
        if !self.supports(ioc.kind) {
            return Ok(ReportPlan::Unsupported);
        }
        let Some(contact) = self.rdap.abuse_contact(ioc).await? else {
            return Ok(ReportPlan::Skip {
                reason: "no abuse contact in rdap".into(),
            });
        };
        let body = template::render_template(
            &self.template,
            &serde_json::json!({
                "value": ioc.value,
                "type": ioc.kind.as_str(),
                "registrar": contact.registrar.unwrap_or_else(|| "unknown".to_string()),
            }),
        )
        .map_err(ProviderError::Rejected)?;
        Ok(ReportPlan::Ready {
            destination: format!("email:{}", contact.email),
            payload: envelope(&contact.email, ioc, &body),
        })
    }

    async fn send(&self, _ioc: &Ioc, payload: &str) -> Result<String, ProviderError> {
        let (to, subject, body) = parse_envelope(payload)?;
        match &self.transport {
            Transport::Http {
                url,
                token,
                client,
                gate,
            } => send_http(client, gate, url, token.as_ref(), &to, &subject, &body).await,
            Transport::Smtp(settings) => {
                send_smtp(settings, &self.from, &to, &subject, &body).await
            }
        }
    }
}

fn envelope(to: &str, ioc: &Ioc, body: &str) -> String {
    let subject = format!("Abuse report for {}", ioc.value.replace(['\r', '\n'], ""));
    format!("To: {to}\nSubject: {subject}\n\n{body}")
}

fn parse_envelope(payload: &str) -> Result<(String, String, String), ProviderError> {
    let mut lines = payload.split('\n');
    let to_line = lines.next().unwrap_or("").trim_end_matches('\r');
    let subject_line = lines.next().unwrap_or("").trim_end_matches('\r');
    let Some(to) = to_line.strip_prefix("To: ") else {
        return Err(ProviderError::Rejected("mail payload is missing To".into()));
    };
    let Some(subject) = subject_line.strip_prefix("Subject: ") else {
        return Err(ProviderError::Rejected(
            "mail payload is missing Subject".into(),
        ));
    };
    if !mailbox_ok(to) {
        return Err(ProviderError::Rejected(
            "mail payload has a bad recipient".into(),
        ));
    }
    let _blank = lines.next();
    let body = lines.collect::<Vec<_>>().join("\n");
    Ok((to.to_string(), subject.replace(['\r', '\n'], ""), body))
}

fn mailbox_ok(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && !value.chars().any(char::is_whitespace)
}

async fn send_http(
    client: &reqwest::Client,
    gate: &IntervalGate,
    url: &str,
    token: Option<&Secret>,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<String, ProviderError> {
    let secret = token.cloned().unwrap_or_else(|| Secret::new(""));
    let payload = serde_json::json!({
        "to": to,
        "subject": subject,
        "body": body,
    })
    .to_string();
    let response = http_send(gate, &secret, || {
        let mut request = client
            .post(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(payload.clone());
        if let Some(token) = token {
            if !token.as_header_value().is_empty() {
                request = request.bearer_auth(token.as_header_value());
            }
        }
        request.send()
    })
    .await?;
    let text = response.text().await.unwrap_or_default();
    finish_body(text, &secret)
}

async fn send_smtp(
    settings: &SmtpSettings,
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<String, ProviderError> {
    let mailer = smtp_mailer(settings)?;
    let message = Message::builder()
        .from(parse_mailbox(from)?)
        .to(parse_mailbox(to)?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body.to_string())
        .map_err(|err| rejected(&err, settings.password.as_ref()))?;
    mailer
        .send(message)
        .await
        .map_err(|err| rejected(&err, settings.password.as_ref()))?;
    Ok("sent".to_string())
}

fn smtp_mailer(
    settings: &SmtpSettings,
) -> Result<AsyncSmtpTransport<Tokio1Executor>, ProviderError> {
    let builder = if settings.starttls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&settings.host)
            .map_err(|err| rejected(&err, settings.password.as_ref()))?
            .port(settings.port)
            .timeout(Some(Duration::from_secs(10)))
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&settings.host)
            .port(settings.port)
            .timeout(Some(Duration::from_secs(10)))
    };
    let builder = if let Some(username) = &settings.username {
        let password = settings
            .password
            .as_ref()
            .map(|secret| secret.as_header_value().to_string())
            .unwrap_or_default();
        builder.credentials(Credentials::new(username.clone(), password))
    } else {
        builder
    };
    Ok(builder.build())
}

fn parse_mailbox(value: &str) -> Result<Mailbox, ProviderError> {
    value
        .parse()
        .map_err(|_| ProviderError::Rejected("bad mailbox".into()))
}

fn rejected(err: &impl std::fmt::Display, secret: Option<&Secret>) -> ProviderError {
    let mut text: String = err.to_string().chars().take(300).collect();
    if let Some(secret) = secret {
        text = redact(&text, secret);
    }
    ProviderError::Rejected(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::parse_ioc;
    use crate::report::ReportEngine;
    use crate::report::ReportStatus;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn rdap_body() -> serde_json::Value {
        serde_json::json!({
            "name": "evil.example",
            "entities": [{
                "roles": ["registrar"],
                "vcardArray": ["vcard", [
                    ["fn", {}, "text", "Example Registrar"]
                ]],
                "entities": [{
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [
                        ["email", {}, "text", "mailto:abuse@example.com"]
                    ]]
                }]
            }]
        })
    }

    fn http_reporter(server: &MockServer, token: Option<&str>) -> EmailReporter {
        EmailReporter::new(
            Rdap::new(reqwest::Client::new(), server.uri(), 60_000),
            "reports@example.com",
            ABUSE_EMAIL.to_string(),
            Transport::Http {
                url: format!("{}/send", server.uri()),
                token: token.map(Secret::new),
                client: reqwest::Client::new(),
                gate: IntervalGate::per_minute(60_000),
            },
        )
    }

    async fn engine(reporter: EmailReporter) -> (tempfile::TempDir, ReportEngine) {
        let dir = tempfile::tempdir().unwrap();
        let engine =
            ReportEngine::new(vec![Arc::new(reporter)], &dir.path().join("audit.sqlite")).unwrap();
        (dir, engine)
    }

    #[tokio::test]
    async fn dry_run_renders_mail_and_submit_posts_once() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/domain/evil.example"))
            .respond_with(ResponseTemplate::new(200).set_body_json(rdap_body()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/send"))
            .and(body_string_contains("abuse@example.com"))
            .and(body_string_contains("evil.example"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"ok":true}"#))
            .expect(1)
            .mount(&server)
            .await;

        let reporter = http_reporter(&server, Some("bb-test-secret-key"));
        let (_dir, engine) = engine(reporter).await;
        let ioc = parse_ioc("evil.example").unwrap();

        let dry = engine.run(std::slice::from_ref(&ioc), false).await.unwrap();
        assert_eq!(dry[0].status, ReportStatus::DryRun);
        assert_eq!(dry[0].destination, "email:abuse@example.com");
        assert!(dry[0].payload.contains("To: abuse@example.com"));
        assert!(dry[0].payload.contains("evil.example"));
        assert!(!dry[0].payload.contains("secret-key"));
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.method == "GET"));

        let sent = engine.run(std::slice::from_ref(&ioc), true).await.unwrap();
        assert_eq!(sent[0].status, ReportStatus::Submitted);
        assert!(!sent[0].detail.contains("secret-key"));

        let again = engine.run(std::slice::from_ref(&ioc), true).await.unwrap();
        assert_eq!(again[0].status, ReportStatus::Duplicate);
        let posts = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method == "POST")
            .count();
        assert_eq!(posts, 1);
    }

    #[tokio::test]
    async fn missing_contact_is_skipped() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ip/192.0.2.1"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let reporter = http_reporter(&server, None);
        let (_dir, engine) = engine(reporter).await;
        let rows = engine
            .run(&[parse_ioc("192.0.2.1").unwrap()], true)
            .await
            .unwrap();
        assert_eq!(rows[0].status, ReportStatus::Skipped);
        assert!(rows[0].detail.contains("no abuse contact"));
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.method == "GET"));
    }

    #[tokio::test]
    async fn smtp_refusal_is_an_error_and_is_not_deduped() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/domain/evil.example"))
            .respond_with(ResponseTemplate::new(200).set_body_json(rdap_body()))
            .mount(&server)
            .await;
        let reporter = EmailReporter::new(
            Rdap::new(reqwest::Client::new(), server.uri(), 60_000),
            "reports@example.com",
            ABUSE_EMAIL.to_string(),
            Transport::Smtp(SmtpSettings {
                host: "127.0.0.1".into(),
                port: 1,
                starttls: false,
                username: Some("reports".into()),
                password: Some(Secret::new("bb-test-secret-key")),
            }),
        );
        let (_dir, engine) = engine(reporter).await;
        let ioc = parse_ioc("evil.example").unwrap();
        let first = engine.run(std::slice::from_ref(&ioc), true).await.unwrap();
        assert_eq!(first[0].status, ReportStatus::Error);
        assert!(
            !first[0].detail.contains("secret-key"),
            "{}",
            first[0].detail
        );
        let second = engine.run(std::slice::from_ref(&ioc), true).await.unwrap();
        assert_eq!(second[0].status, ReportStatus::Error);
    }
}
