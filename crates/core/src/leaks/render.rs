//! Table, JSON and Markdown renderings of a leak run.
//!
//! Breach titles, data classes and error text come from HIBP. They are
//! treated as untrusted: control characters are dropped for the table, and
//! Markdown cells are escaped so they cannot add links, HTML or rows.

use super::{LeakEvent, LeakReport};

/// Leak output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakOutput {
    /// Fixed-width text.
    Table,
    /// The run as JSON, with `events` in `butcherbird.leak.v1` shape.
    Json,
    /// One `butcherbird.leak.v1` event per line.
    Ndjson,
    /// Markdown summary for a ticket or chat message.
    Markdown,
}

/// Render `report`.
pub fn render_leaks(report: &LeakReport, format: LeakOutput) -> String {
    match format {
        LeakOutput::Table => table(report),
        LeakOutput::Json => {
            let mut out = serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into());
            out.push('\n');
            out
        }
        // Events only. Failed searches and warnings are on stderr and in the
        // exit code.
        LeakOutput::Ndjson => report
            .events
            .iter()
            .filter_map(|event| serde_json::to_string(event).ok())
            .map(|line| line + "\n")
            .collect(),
        LeakOutput::Markdown => markdown(report),
    }
}

/// Flags worth a reader's attention before the output is shared.
pub(crate) fn flags(event: &LeakEvent) -> Vec<&'static str> {
    let b = &event.breach;
    let mut out = Vec::new();
    if b.is_sensitive {
        out.push("sensitive");
    }
    if b.is_stealer_log {
        out.push("stealer-log");
    }
    if !b.is_verified {
        out.push("unverified");
    }
    if b.is_fabricated {
        out.push("fabricated");
    }
    if b.is_spam_list {
        out.push("spam-list");
    }
    out
}

/// Printable text on one line. Control characters (newlines, ANSI escapes)
/// become spaces.
fn plain(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn actions(event: &LeakEvent) -> String {
    event
        .recommended_actions
        .iter()
        .map(|action| action.id)
        .collect::<Vec<_>>()
        .join(", ")
}

fn table(report: &LeakReport) -> String {
    let headers = [
        "IDENTITY",
        "BREACH",
        "ADDED",
        "FIRST SEEN",
        "NEW",
        "FLAGS",
        "RECOMMENDED",
    ];
    let rows: Vec<[String; 7]> = report
        .events
        .iter()
        .map(|event| {
            [
                plain(&event.identity),
                plain(&event.breach.name),
                plain(event.breach.added_date.as_deref().unwrap_or("")),
                event.first_seen.clone(),
                if event.new { "yes" } else { "no" }.to_string(),
                flags(event).join(","),
                actions(event),
            ]
        })
        .collect();
    let mut widths = headers.map(|h| h.len());
    for row in &rows {
        for (idx, cell) in row.iter().enumerate() {
            widths[idx] = widths[idx].max(cell.chars().count());
        }
    }
    let mut out = String::new();
    let line = |cells: &[String], out: &mut String| {
        for (idx, cell) in cells.iter().enumerate() {
            if idx + 1 == cells.len() {
                out.push_str(cell);
            } else {
                out.push_str(&format!("{cell:<width$}  ", width = widths[idx]));
            }
        }
        out.push('\n');
    };
    if rows.is_empty() {
        out.push_str("(no new exposures)\n");
    } else {
        line(&headers.map(str::to_string), &mut out);
        for row in &rows {
            line(row, &mut out);
        }
    }
    for row in report.failed_checks() {
        out.push_str(&format!(
            "error: {} {}: {}\n",
            row.watch.kind.as_str(),
            plain(&row.watch.value),
            plain(&row.detail)
        ));
    }
    for warning in &report.warnings {
        out.push_str(&format!("warning: {}\n", plain(warning)));
    }
    out.push_str(&format!("{}\n", report.attribution));
    out
}

/// Escape a Markdown table cell. Every ASCII punctuation character that
/// Markdown or HTML gives meaning to is backslash-escaped, so a breach title
/// cannot open a link, an HTML tag, emphasis or a new column.
fn cell(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in plain(value).chars() {
        if "\\`*_{}[]()<>#!|~&\"'".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn markdown(report: &LeakReport) -> String {
    let mut out = String::from("# Leak monitor\n\n");
    out.push_str(&format!(
        "Run at {}. {} new exposures, {} shown.\n\n",
        report.generated_at,
        report.new_count(),
        report.events.len()
    ));
    out.push_str(
        "## Watch list\n\n| Kind | Entry | Status | Detail |\n| --- | --- | --- | --- |\n",
    );
    for row in &report.checks {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            row.watch.kind.as_str(),
            cell(&row.watch.value),
            row.status.as_str(),
            cell(&row.detail)
        ));
    }
    out.push_str("\n## Exposures\n\n");
    if report.events.is_empty() {
        out.push_str("No new exposures.\n");
    } else {
        out.push_str(
            "| Identity | Breach | Breach date | Added to source | First seen | New | Flags | Data classes |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n",
        );
        for event in &report.events {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
                cell(&event.identity),
                cell(event.breach.title.as_deref().unwrap_or(&event.breach.name)),
                cell(event.breach.breach_date.as_deref().unwrap_or("")),
                cell(event.breach.added_date.as_deref().unwrap_or("")),
                event.first_seen,
                if event.new { "yes" } else { "no" },
                flags(event).join(", "),
                cell(&event.breach.data_classes.join(", "))
            ));
        }
        if report.events.iter().any(|event| event.breach.is_sensitive) {
            out.push_str("\nSensitive breaches are listed. Share this report only with people who need it.\n");
        }
        out.push_str("\n## Recommended reset path\n\n");
        out.push_str("Advice only. Butcherbird has not changed any account.\n\n");
        for action in super::Action::ALL {
            let who: std::collections::BTreeSet<&str> = report
                .events
                .iter()
                .filter(|event| {
                    event
                        .recommended_actions
                        .iter()
                        .any(|step| step.id == action.id())
                })
                .map(|event| event.identity.as_str())
                .collect();
            if who.is_empty() {
                continue;
            }
            out.push_str(&format!(
                "- **{}**: {}. For: {}.\n",
                action.id(),
                action.summary(),
                who.into_iter().map(cell).collect::<Vec<_>>().join(", ")
            ));
        }
    }
    if !report.warnings.is_empty() {
        out.push_str("\n## Warnings\n\n");
        for warning in &report.warnings {
            out.push_str(&format!("- {}\n", cell(warning)));
        }
    }
    out.push_str(&format!("\n{}\n", report.attribution));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leaks::event::{WatchKind, WatchRef};
    use crate::leaks::{Breach, CheckRow, CheckStatus, LeakEvent, HIBP_ATTRIBUTION};

    fn report() -> LeakReport {
        let event = LeakEvent::new(
            "hibp",
            WatchRef::new(WatchKind::Domain, "example.com"),
            "alex@example.com".into(),
            Breach {
                title: Some("Quokka | [Reset](https://phish.example) <img src=x>".into()),
                is_verified: true,
                is_sensitive: true,
                added_date: Some("2026-11-20T03:00:00Z".into()),
                data_classes: vec!["Email addresses".into(), "Passwords".into()],
                ..Breach::named("Quokka")
            },
            1_795_000_000,
            1_795_000_000,
            true,
        );
        LeakReport {
            generated_at: "2026-11-18T08:26:40Z".into(),
            attribution: HIBP_ATTRIBUTION,
            checks: vec![
                CheckRow {
                    watch: WatchRef::new(WatchKind::Domain, "example.com"),
                    status: CheckStatus::Ok,
                    detail: "1 exposures".into(),
                },
                CheckRow {
                    watch: WatchRef::new(WatchKind::Vip, "vip@example.net"),
                    status: CheckStatus::Error,
                    detail: "http 500: line one\nline two \u{1b}[31m".into(),
                },
            ],
            warnings: vec!["breach Wombat metadata unavailable (transport error)".into()],
            events: vec![event],
            pending_seen: Vec::new(),
            pending_watch: Vec::new(),
        }
    }

    #[test]
    fn table_lists_exposure_errors_and_credit() {
        let out = render_leaks(&report(), LeakOutput::Table);
        assert!(out.starts_with("IDENTITY"), "{out}");
        assert!(out.contains("alex@example.com"), "{out}");
        assert!(
            out.contains("password_reset, session_revoke, phishing_watch"),
            "{out}"
        );
        assert!(
            out.contains("error: vip vip@example.net: http 500: line one line two  [31m"),
            "{out}"
        );
        assert!(!out.contains('\u{1b}'), "{out}");
        assert!(out.contains("warning: breach Wombat"), "{out}");
        assert!(out.contains("sensitive"), "{out}");
        assert!(out.contains("Have I Been Pwned"), "{out}");
    }

    #[test]
    fn markdown_has_reset_path_and_escapes_pipes() {
        let out = render_leaks(&report(), LeakOutput::Markdown);
        // Title cannot add a column, a link or HTML.
        assert!(
            out.contains("Quokka \\| \\[Reset\\]\\(https://phish.example\\) \\<img src=x\\>"),
            "{out}"
        );
        assert!(!out.contains("](https://phish"), "{out}");
        assert!(!out.replace("\\<", "").contains('<'), "{out}");
        let row = out.lines().find(|line| line.starts_with("| alex")).unwrap();
        // 8 columns means 9 unescaped pipes.
        let pipes = row.matches('|').count() - row.matches("\\|").count();
        assert_eq!(pipes, 9, "{row}");
        assert!(out.contains("| sensitive |"), "{out}");
        assert!(out.contains("Sensitive breaches are listed"), "{out}");
        assert!(out.contains("## Warnings"), "{out}");
        assert!(!out.contains('\u{1b}'), "{out}");
        assert!(out.contains("## Recommended reset path"), "{out}");
        assert!(
            out.contains("- **password_reset**: Reset the password"),
            "{out}"
        );
        assert!(out.contains("For: alex@example.com."), "{out}");
        assert!(out.contains("Have I Been Pwned"), "{out}");
        assert!(!out.contains('\u{2014}'), "{out}");
    }

    #[test]
    fn ndjson_is_one_event_per_line() {
        let out = render_leaks(&report(), LeakOutput::Ndjson);
        assert_eq!(out.lines().count(), 1);
        let value: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(value["schema"], "butcherbird.leak.v1");
    }
}
