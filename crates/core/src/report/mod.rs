//! Pluggable abuse reporters.
//!
//! A dry run builds the payload and writes an audit row. It does not send and
//! it does not take a dedupe slot. A successful submit writes the dedupe row
//! and the audit row in one transaction. Errors and skips are audited and can
//! be retried.

mod abuseipdb;
mod audit;
mod threatfox;
mod urlhaus;

pub use abuseipdb::AbuseIpdbReporter;
pub use threatfox::ThreatFoxReporter;
pub use urlhaus::UrlhausReporter;

use std::sync::Arc;

use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;
use tokio::task::JoinSet;

use crate::config::Config;
use crate::ioc::{Ioc, IocType};
use crate::output::OutputFormat;
use crate::provider::{http_client, ProviderError};
use crate::secret::{redact_truncate, Secret};
use crate::Error;

use audit::AuditLog;

/// What a reporter would send, or why it will not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportPlan {
    /// Body to send. The API key is not in here.
    Ready {
        /// Request body.
        payload: String,
    },
    /// The type is in scope, but this value cannot be submitted.
    Skip {
        /// Shown in the audit log.
        reason: String,
    },
    /// This reporter does not handle the type.
    Unsupported,
}

/// Outbound report destination. Implementations must not put API keys in errors or payloads.
#[async_trait]
pub trait Reporter: Send + Sync {
    /// Dedupe key and config id.
    fn id(&self) -> &'static str;

    /// Whether `prepare` should be called for this type.
    fn supports(&self, kind: IocType) -> bool;

    /// Build the body. No network.
    fn prepare(&self, ioc: &Ioc) -> ReportPlan;

    /// Send a body from [`prepare`](Reporter::prepare). The returned text is stored redacted.
    async fn send(&self, ioc: &Ioc, payload: &str) -> Result<String, ProviderError>;
}

/// Outcome of one reporter against one indicator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReportRow {
    /// Reporter id.
    pub destination: String,
    /// Indicator type.
    pub ioc_type: IocType,
    /// Normalised indicator.
    pub ioc_value: String,
    /// What happened.
    pub status: ReportStatus,
    /// Request body, with any key masked. Empty when nothing was built.
    pub payload: String,
    /// Response, skip reason, or error text. Keys are masked.
    pub detail: String,
}

impl ReportRow {
    fn new(
        destination: &str,
        ioc: &Ioc,
        status: ReportStatus,
        payload: &str,
        detail: &str,
    ) -> Self {
        Self {
            destination: destination.to_string(),
            ioc_type: ioc.kind,
            ioc_value: ioc.value.clone(),
            status,
            payload: payload.to_string(),
            detail: detail.to_string(),
        }
    }
}

/// Audit status for one report attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    /// Payload built, nothing sent.
    DryRun,
    /// Destination accepted the report.
    Submitted,
    /// A previous successful submit already covers this indicator.
    Duplicate,
    /// The destination rejected the report, or the call failed. Not deduped.
    Error,
    /// In scope, but not sent. Not deduped.
    Skipped,
}

impl ReportStatus {
    /// Stable name stored in the audit log.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DryRun => "dry_run",
            Self::Submitted => "submitted",
            Self::Duplicate => "duplicate",
            Self::Error => "error",
            Self::Skipped => "skipped",
        }
    }
}

/// Runs the built-in reporters and writes the audit log.
pub struct ReportEngine {
    reporters: Vec<Arc<dyn Reporter>>,
    notices: Vec<String>,
    audit: Arc<AuditLog>,
}

impl ReportEngine {
    /// Engine over an explicit reporter list. `audit_path` is the SQLite file.
    pub fn new(
        reporters: Vec<Arc<dyn Reporter>>,
        audit_path: &std::path::Path,
    ) -> Result<Self, Error> {
        Ok(Self {
            reporters,
            notices: Vec::new(),
            audit: Arc::new(AuditLog::open(audit_path)?),
        })
    }

    /// AbuseIPDB, URLhaus and ThreatFox. Missing keys and disabled reporters are notices.
    pub fn from_config(cfg: &Config) -> Result<Self, Error> {
        let client = http_client(cfg.timeout)?;
        let mut notices = Vec::new();
        let mut reporters = Vec::new();
        for built in [
            abuseipdb::build(cfg, client.clone()),
            urlhaus::build(cfg, client.clone()),
            threatfox::build(cfg, client),
        ] {
            match built {
                Ok(reporter) => reporters.push(reporter),
                Err(notice) => notices.push(notice),
            }
        }
        let mut engine = Self::new(reporters, &cfg.cache.path)?;
        engine.notices = notices;
        Ok(engine)
    }

    /// One line per reporter that will not run.
    pub fn notices(&self) -> &[String] {
        &self.notices
    }

    /// Whether at least one reporter will run.
    pub fn has_reporters(&self) -> bool {
        !self.reporters.is_empty()
    }

    /// Report every indicator. `submit` false is a dry run.
    ///
    /// Rows come back grouped by reporter, in built-in order, then input order.
    pub async fn run(&self, iocs: &[Ioc], submit: bool) -> Result<Vec<ReportRow>, Error> {
        let mut tasks = JoinSet::new();
        for (order, reporter) in self.reporters.iter().cloned().enumerate() {
            let iocs = iocs.to_vec();
            let audit = Arc::clone(&self.audit);
            tasks.spawn(async move {
                let rows = dispatch(reporter, iocs, audit, submit).await?;
                Ok::<_, Error>((order, rows))
            });
        }
        let mut grouped = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            let (order, rows) =
                joined.map_err(|err| Error::Client(format!("report task: {err}")))??;
            grouped.push((order, rows));
        }
        grouped.sort_by_key(|(order, _)| *order);
        Ok(grouped.into_iter().flat_map(|(_, rows)| rows).collect())
    }
}

/// Exit code for a finished report run.
///
/// * `0` — dry run, submits, duplicates and skips, with no submit error
/// * `4` — at least one submit failed
pub fn report_exit_code(rows: &[ReportRow]) -> i32 {
    if rows.iter().any(|row| row.status == ReportStatus::Error) {
        4
    } else {
        0
    }
}

/// Render report rows. STIX is rejected: it is a check format.
pub fn render_reports(rows: &[ReportRow], format: OutputFormat) -> Result<String, Error> {
    match format {
        OutputFormat::Stix => Err(Error::Config("stix output is for check, not report".into())),
        OutputFormat::Table => Ok(render_table(rows)),
        OutputFormat::Json => {
            Ok(serde_json::to_string_pretty(rows).unwrap_or_else(|_| "[]".to_string()))
        }
        OutputFormat::Csv => Ok(render_csv(rows)),
        OutputFormat::Markdown => Ok(render_markdown(rows)),
    }
}

fn render_table(rows: &[ReportRow]) -> String {
    if rows.is_empty() {
        return "(no reports)\n".to_string();
    }
    let mut out = String::from("DESTINATION  TYPE  INDICATOR  STATUS  DETAIL\n");
    for row in rows {
        out.push_str(&format!(
            "{}  {}  {}  {}  {}\n",
            row.destination,
            row.ioc_type,
            row.ioc_value,
            row.status.as_str(),
            shown(row)
        ));
    }
    out
}

fn render_markdown(rows: &[ReportRow]) -> String {
    let mut out = String::from(
        "| Destination | Type | Indicator | Status | Detail |\n| --- | --- | --- | --- | --- |\n",
    );
    for row in rows {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            row.destination,
            row.ioc_type,
            row.ioc_value.replace('|', "\\|"),
            row.status.as_str(),
            shown(row).replace('|', "\\|").replace('\n', " ")
        ));
    }
    out
}

fn render_csv(rows: &[ReportRow]) -> String {
    let mut writer = csv::Writer::from_writer(Vec::new());
    let _ = writer.write_record([
        "destination",
        "type",
        "indicator",
        "status",
        "payload",
        "detail",
    ]);
    for row in rows {
        let _ = writer.write_record([
            row.destination.as_str(),
            row.ioc_type.as_str(),
            row.ioc_value.as_str(),
            row.status.as_str(),
            row.payload.as_str(),
            row.detail.as_str(),
        ]);
    }
    String::from_utf8(writer.into_inner().unwrap_or_default()).unwrap_or_default()
}

fn shown(row: &ReportRow) -> &str {
    if !row.payload.is_empty() && (row.status == ReportStatus::DryRun || row.detail.is_empty()) {
        &row.payload
    } else {
        &row.detail
    }
}

async fn dispatch(
    reporter: Arc<dyn Reporter>,
    iocs: Vec<Ioc>,
    audit: Arc<AuditLog>,
    submit: bool,
) -> Result<Vec<ReportRow>, Error> {
    let mut rows = Vec::new();
    for ioc in iocs {
        if let Some(row) = one(reporter.as_ref(), &ioc, audit.as_ref(), submit).await? {
            tracing::debug!(
                destination = row.destination,
                ioc = %row.ioc_value,
                status = row.status.as_str(),
                "report"
            );
            rows.push(row);
        }
    }
    Ok(rows)
}

async fn one(
    reporter: &dyn Reporter,
    ioc: &Ioc,
    audit: &AuditLog,
    submit: bool,
) -> Result<Option<ReportRow>, Error> {
    if !reporter.supports(ioc.kind) {
        return Ok(None);
    }
    if audit.is_duplicate(reporter.id(), ioc)? {
        let row = ReportRow::new(
            reporter.id(),
            ioc,
            ReportStatus::Duplicate,
            "",
            "already submitted",
        );
        audit.record(&row, false)?;
        return Ok(Some(row));
    }
    let payload = match reporter.prepare(ioc) {
        ReportPlan::Unsupported => return Ok(None),
        ReportPlan::Skip { reason } => {
            let row = ReportRow::new(reporter.id(), ioc, ReportStatus::Skipped, "", &reason);
            audit.record(&row, false)?;
            return Ok(Some(row));
        }
        ReportPlan::Ready { payload } => payload,
    };
    if !submit {
        let row = ReportRow::new(
            reporter.id(),
            ioc,
            ReportStatus::DryRun,
            &payload,
            "not sent",
        );
        audit.record(&row, false)?;
        return Ok(Some(row));
    }
    match reporter.send(ioc, &payload).await {
        Ok(response) => {
            let row = ReportRow::new(
                reporter.id(),
                ioc,
                ReportStatus::Submitted,
                &payload,
                &response,
            );
            audit.record(&row, true)?;
            Ok(Some(row))
        }
        Err(err) => {
            let row = ReportRow::new(
                reporter.id(),
                ioc,
                ReportStatus::Error,
                &payload,
                &err.to_string(),
            );
            audit.record(&row, false)?;
            Ok(Some(row))
        }
    }
}

pub(crate) fn take_key(cfg: &Config, id: &str) -> Result<Secret, String> {
    let settings = cfg.provider(id);
    if !settings.enabled {
        return Err(format!("skipped {id}: disabled"));
    }
    match &settings.api_key {
        Some(key) => Ok(key.clone()),
        None => {
            let env = settings
                .api_key_env
                .as_deref()
                .unwrap_or("the provider env var");
            Err(format!("skipped {id}: missing api key ({env})"))
        }
    }
}

pub(crate) fn finish_body(text: String, secret: &Secret) -> Result<String, ProviderError> {
    let stored = redact_truncate(&text, secret, 2_000);
    if let Some(reason) = query_rejection(&stored) {
        return Err(ProviderError::Http {
            status: 200,
            body: reason,
        });
    }
    Ok(stored)
}

fn query_rejection(body: &str) -> Option<String> {
    let value: Value = serde_json::from_str(body).ok()?;
    let status = value.get("query_status")?.as_str()?;
    match status {
        "ok" | "inserted" | "success" => None,
        other => {
            let message = value
                .get("message")
                .or_else(|| value.get("error"))
                .and_then(|item| item.as_str())
                .unwrap_or("");
            let reason = format!("{other} {message}");
            let reason = reason.trim();
            if reason.chars().count() > 180 {
                Some(reason.chars().take(180).collect())
            } else {
                Some(reason.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::ioc::parse_ioc;

    fn sample_iocs() -> Vec<Ioc> {
        [
            "192.0.2.1",
            "https://phish.example/login",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        ]
        .into_iter()
        .map(|value| parse_ioc(value).unwrap())
        .collect()
    }

    fn open_engine(base: &str) -> (tempfile::TempDir, ReportEngine) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.sqlite");
        let toml = format!(
            r#"
            [profiles.default.cache]
            enabled = false
            path = "{path}"

            [profiles.default.providers.abuseipdb]
            api_key = "bb-test-secret-key"
            base_url = "{base}"
            rate_per_minute = 60000

            [profiles.default.providers.urlhaus]
            api_key = "bb-test-secret-key"
            base_url = "{base}"
            rate_per_minute = 60000

            [profiles.default.providers.threatfox]
            api_key = "bb-test-secret-key"
            base_url = "{base}"
            rate_per_minute = 60000
            "#,
            path = path.display(),
        );
        let cfg = Config::from_toml_with_env(&toml, None, &HashMap::new()).unwrap();
        let engine = ReportEngine::from_config(&cfg).unwrap();
        (dir, engine)
    }

    fn statuses(rows: &[ReportRow], destination: &str) -> Vec<ReportStatus> {
        rows.iter()
            .filter(|row| row.destination == destination)
            .map(|row| row.status)
            .collect()
    }

    #[tokio::test]
    async fn dry_run_does_not_send_and_submit_then_dedupes() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/v2/report"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string(
                    r#"{"data":{"ipAddress":"192.0.2.1","abuseConfidenceScore":0}}"#,
                ),
            )
            .expect(1)
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string(r#"{"query_status":"ok"}"#),
            )
            .expect(1)
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/v1/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string(r#"{"query_status":"ok"}"#),
            )
            .expect(1)
            .mount(&server)
            .await;

        let (_dir, engine) = open_engine(&server.uri());
        let iocs = sample_iocs();
        let dry = engine.run(&iocs, false).await.unwrap();
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "dry run must not call the destination"
        );
        assert!(dry.iter().all(|row| !row.payload.contains("secret-key")));
        assert!(dry.iter().all(|row| !row.detail.contains("secret-key")));
        assert_eq!(statuses(&dry, "abuseipdb"), vec![ReportStatus::DryRun]);
        assert_eq!(statuses(&dry, "urlhaus"), vec![ReportStatus::DryRun]);
        assert_eq!(
            statuses(&dry, "threatfox"),
            vec![
                ReportStatus::Skipped,
                ReportStatus::DryRun,
                ReportStatus::Skipped
            ]
        );
        assert_eq!(engine.audit.count_dedupe().unwrap(), 0);

        let sent = engine.run(&iocs, true).await.unwrap();
        assert_eq!(statuses(&sent, "abuseipdb"), vec![ReportStatus::Submitted]);
        assert_eq!(statuses(&sent, "urlhaus"), vec![ReportStatus::Submitted]);
        assert_eq!(
            statuses(&sent, "threatfox"),
            vec![
                ReportStatus::Skipped,
                ReportStatus::Submitted,
                ReportStatus::Skipped
            ]
        );
        assert_eq!(engine.audit.count_dedupe().unwrap(), 3);
        assert_eq!(report_exit_code(&sent), 0);

        let again = engine.run(&iocs, true).await.unwrap();
        assert_eq!(statuses(&again, "abuseipdb"), vec![ReportStatus::Duplicate]);
        assert_eq!(statuses(&again, "urlhaus"), vec![ReportStatus::Duplicate]);
        assert_eq!(
            statuses(&again, "threatfox"),
            vec![
                ReportStatus::Skipped,
                ReportStatus::Duplicate,
                ReportStatus::Skipped
            ]
        );
        assert_eq!(engine.audit.count_dedupe().unwrap(), 3);
        assert_eq!(
            engine.audit.count_audit().unwrap(),
            (dry.len() + sent.len() + again.len()) as i64
        );
    }

    #[tokio::test]
    async fn failed_submit_is_not_deduped_and_hides_the_key() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/v2/report"))
            .respond_with(
                wiremock::ResponseTemplate::new(400).set_body_string("bad bb-test-secret-key"),
            )
            .expect(2)
            .mount(&server)
            .await;

        let (_dir, engine) = open_engine(&server.uri());
        let iocs = vec![parse_ioc("192.0.2.9").unwrap()];
        let first = engine.run(&iocs, true).await.unwrap();
        let abuse: Vec<_> = first
            .iter()
            .filter(|row| row.destination == "abuseipdb")
            .collect();
        assert_eq!(abuse.len(), 1);
        assert_eq!(abuse[0].status, ReportStatus::Error);
        assert!(
            !abuse[0].detail.contains("secret-key"),
            "{}",
            abuse[0].detail
        );
        assert!(abuse[0].detail.contains("bb-t****"), "{}", abuse[0].detail);
        assert_eq!(engine.audit.count_dedupe().unwrap(), 0);
        assert_eq!(report_exit_code(&first), 4);

        let second = engine.run(&iocs, true).await.unwrap();
        assert_eq!(statuses(&second, "abuseipdb"), vec![ReportStatus::Error]);
        assert_eq!(engine.audit.count_dedupe().unwrap(), 0);
    }

    #[test]
    fn missing_key_is_a_notice() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.sqlite");
        let toml = format!(
            r#"
            [profiles.default.cache]
            enabled = false
            path = "{path}"

            [profiles.default.providers.urlhaus]
            enabled = false
            "#,
            path = path.display(),
        );
        let cfg = Config::from_toml_with_env(&toml, None, &HashMap::new()).unwrap();
        let engine = ReportEngine::from_config(&cfg).unwrap();
        assert!(!engine.has_reporters());
        let notices = engine.notices().join("\n");
        assert!(notices.contains("skipped abuseipdb: missing api key"));
        assert!(notices.contains("skipped urlhaus: disabled"));
        assert!(notices.contains("skipped threatfox: missing api key"));
    }

    #[test]
    fn query_status_error_is_a_rejection() {
        let reason = query_rejection(r#"{"query_status":"unknown_auth_key"}"#).unwrap();
        assert!(reason.contains("unknown_auth_key"));
        assert!(query_rejection(r#"{"query_status":"ok"}"#).is_none());
        assert!(query_rejection(r#"{"data":{"ok":true}}"#).is_none());
    }
}
