//! Render check reports as a table, JSON, CSV, STIX 2.1 or Markdown.

use serde_json::{json, Value};

use crate::enrich::IocReport;
use crate::ioc::{Ioc, IocType};
use crate::score::{SourceStatus, Verdict};

/// Report renderings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Fixed-width text table.
    Table,
    /// Pretty JSON array of reports.
    Json,
    /// One CSV row per source.
    Csv,
    /// STIX 2.1 bundle of indicators.
    Stix,
    /// Markdown report.
    Markdown,
}

/// Render `reports`. CSV and JSON fall back to an empty document only if the
/// serializer fails, which these structs do not do.
pub fn render(reports: &[IocReport], format: OutputFormat) -> String {
    match format {
        OutputFormat::Table => render_table(reports),
        OutputFormat::Json => {
            serde_json::to_string_pretty(reports).unwrap_or_else(|_| "[]".to_string())
        }
        OutputFormat::Csv => render_csv(reports),
        OutputFormat::Stix => render_stix(reports),
        OutputFormat::Markdown => render_markdown(reports),
    }
}

fn render_table(reports: &[IocReport]) -> String {
    let rows: Vec<[String; 5]> = reports
        .iter()
        .map(|report| {
            [
                report.ioc.kind.to_string(),
                report.ioc.value.clone(),
                report.verdict.to_string(),
                report.confidence.to_string(),
                source_summary(report),
            ]
        })
        .collect();
    let headers = ["TYPE", "INDICATOR", "VERDICT", "CONF", "SOURCES"];
    let widths = [
        col_width(headers[0], rows.iter().map(|r| r[0].as_str())),
        col_width(headers[1], rows.iter().map(|r| r[1].as_str())).min(64),
        col_width(headers[2], rows.iter().map(|r| r[2].as_str())),
        col_width(headers[3], rows.iter().map(|r| r[3].as_str())),
        0,
    ];
    let mut out = String::new();
    push_row(&mut out, &headers.map(str::to_string), &widths);
    for row in rows {
        push_row(&mut out, &row, &widths);
    }
    if reports.is_empty() {
        out.push_str("(no indicators)\n");
    }
    out
}

fn col_width<'a>(header: &str, cells: impl Iterator<Item = &'a str>) -> usize {
    cells
        .map(|c| c.chars().count())
        .max()
        .unwrap_or(0)
        .max(header.chars().count())
}

fn push_row(out: &mut String, cells: &[String], widths: &[usize]) {
    for (idx, cell) in cells.iter().enumerate() {
        if idx > 0 {
            out.push_str("  ");
        }
        if widths[idx] == 0 {
            out.push_str(cell);
        } else {
            out.push_str(&pad(cell, widths[idx]));
        }
    }
    out.push('\n');
}

fn pad(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count > width {
        let mut clipped: String = text.chars().take(width.saturating_sub(1)).collect();
        clipped.push('…');
        clipped
    } else {
        format!("{text}{}", " ".repeat(width - count))
    }
}

fn source_summary(report: &IocReport) -> String {
    report
        .sources
        .iter()
        .map(|source| match source.status {
            SourceStatus::Ok => format!(
                "{}:{}({})",
                source.source,
                source.verdict.unwrap_or(Verdict::Unknown),
                source.confidence.unwrap_or(0)
            ),
            SourceStatus::Skipped => format!("{}:skipped", source.source),
            SourceStatus::Error => format!("{}:error", source.source),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn render_csv(reports: &[IocReport]) -> String {
    let mut writer = csv::Writer::from_writer(Vec::new());
    let _ = writer.write_record([
        "ioc",
        "type",
        "verdict",
        "confidence",
        "source",
        "source_status",
        "source_verdict",
        "source_confidence",
        "detail",
    ]);
    for report in reports {
        if report.sources.is_empty() {
            let _ = writer.write_record([
                report.ioc.value.as_str(),
                report.ioc.kind.as_str(),
                report.verdict.as_str(),
                &report.confidence.to_string(),
                "",
                "",
                "",
                "",
                "",
            ]);
            continue;
        }
        for source in &report.sources {
            let _ = writer.write_record([
                report.ioc.value.as_str(),
                report.ioc.kind.as_str(),
                report.verdict.as_str(),
                &report.confidence.to_string(),
                source.source.as_str(),
                status_str(source.status),
                source.verdict.map(|v| v.as_str()).unwrap_or(""),
                &source.confidence.map(|c| c.to_string()).unwrap_or_default(),
                source.detail.as_str(),
            ]);
        }
    }
    let bytes = writer.into_inner().unwrap_or_default();
    String::from_utf8(bytes).unwrap_or_default()
}

fn status_str(status: SourceStatus) -> &'static str {
    match status {
        SourceStatus::Ok => "ok",
        SourceStatus::Skipped => "skipped",
        SourceStatus::Error => "error",
    }
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Malicious => "malicious",
            Self::Suspicious => "suspicious",
            Self::Clean => "clean",
            Self::Unknown => "unknown",
        }
    }
}

fn render_markdown(reports: &[IocReport]) -> String {
    let mut out = String::from("# Butcherbird report\n\n");
    if reports.is_empty() {
        out.push_str("No indicators.\n");
        return out;
    }
    for report in reports {
        out.push_str(&format!("## {}\n\n", report.ioc.value));
        out.push_str(&format!("- Type: {}\n", report.ioc.kind));
        out.push_str(&format!("- Verdict: {}\n", report.verdict));
        out.push_str(&format!("- Confidence: {}\n\n", report.confidence));
        out.push_str("| Source | Status | Verdict | Confidence | Detail |\n");
        out.push_str("| --- | --- | --- | --- | --- |\n");
        for source in &report.sources {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                source.source,
                status_str(source.status),
                source.verdict.map(|v| v.as_str()).unwrap_or(""),
                source.confidence.map(|c| c.to_string()).unwrap_or_default(),
                escape_cell(&source.detail),
            ));
        }
        out.push('\n');
    }
    out
}

fn escape_cell(text: &str) -> String {
    text.replace('|', "/").replace('\n', " ")
}

fn render_stix(reports: &[IocReport]) -> String {
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let objects: Vec<Value> = reports
        .iter()
        .map(|report| stix_indicator(report, &now))
        .collect();
    let bundle = json!({
        "type": "bundle",
        "id": format!("bundle--{}", uuid::Uuid::new_v4()),
        "objects": objects,
    });
    serde_json::to_string_pretty(&bundle).unwrap_or_else(|_| "{}".to_string())
}

fn stix_indicator(report: &IocReport, now: &str) -> Value {
    let mut labels = Vec::new();
    match report.verdict {
        Verdict::Malicious => labels.push("malicious-activity"),
        Verdict::Suspicious => labels.push("anomalous-activity"),
        Verdict::Clean => labels.push("benign"),
        Verdict::Unknown => {}
    }
    json!({
        "type": "indicator",
        "spec_version": "2.1",
        "id": format!("indicator--{}", uuid::Uuid::new_v4()),
        "created": now,
        "modified": now,
        "pattern": stix_pattern(&report.ioc),
        "pattern_type": "stix",
        "valid_from": now,
        "confidence": report.confidence,
        "labels": labels,
    })
}

fn stix_pattern(ioc: &Ioc) -> String {
    let value = ioc.value.replace('\'', "\\'");
    match ioc.kind {
        IocType::Ipv4 => format!("[ipv4-addr:value = '{value}']"),
        IocType::Ipv6 => format!("[ipv6-addr:value = '{value}']"),
        IocType::Cidr if value.contains(':') => format!("[ipv6-addr:value = '{value}']"),
        IocType::Cidr => format!("[ipv4-addr:value = '{value}']"),
        IocType::Domain => format!("[domain-name:value = '{value}']"),
        IocType::Url => format!("[url:value = '{value}']"),
        IocType::Md5 => format!("[file:hashes.'MD5' = '{value}']"),
        IocType::Sha1 => format!("[file:hashes.'SHA-1' = '{value}']"),
        IocType::Sha256 => format!("[file:hashes.'SHA-256' = '{value}']"),
        IocType::Email => format!("[email-addr:value = '{value}']"),
        IocType::Asn => {
            let number = value.trim_start_matches("AS");
            format!("[autonomous-system:number = {number}]")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::parse_ioc;
    use crate::score::{SourceReport, SourceStatus};

    fn sample() -> IocReport {
        IocReport {
            ioc: parse_ioc("192.0.2.1").unwrap(),
            verdict: Verdict::Malicious,
            confidence: 90,
            sources: vec![SourceReport {
                source: "abuseipdb".to_string(),
                status: SourceStatus::Ok,
                verdict: Some(Verdict::Malicious),
                confidence: Some(90),
                detail: "score 90, 2 reports".to_string(),
            }],
        }
    }

    #[test]
    fn json_and_stix_and_csv_keep_the_indicator() {
        let report = sample();
        let json = render(std::slice::from_ref(&report), OutputFormat::Json);
        assert!(json.contains("192.0.2.1"));
        assert!(json.contains("malicious"));
        let csv = render(std::slice::from_ref(&report), OutputFormat::Csv);
        assert!(csv.contains("abuseipdb"));
        let stix: Value =
            serde_json::from_str(&render(std::slice::from_ref(&report), OutputFormat::Stix))
                .unwrap();
        assert_eq!(stix["type"], "bundle");
        assert!(stix["objects"][0]["pattern"]
            .as_str()
            .unwrap()
            .contains("192.0.2.1"));
    }
}
