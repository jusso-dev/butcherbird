//! Table, JSON and Markdown renderings of a leak run.

use super::{CheckStatus, LeakReport};

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
        LeakOutput::Ndjson => report
            .events
            .iter()
            .filter_map(|event| serde_json::to_string(event).ok())
            .map(|line| line + "\n")
            .collect(),
        LeakOutput::Markdown => markdown(report),
    }
}

fn actions(event: &super::LeakEvent) -> String {
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
        "RECOMMENDED",
    ];
    let rows: Vec<[String; 6]> = report
        .events
        .iter()
        .map(|event| {
            [
                event.identity.clone(),
                event.breach.name.clone(),
                event.breach.added_date.clone().unwrap_or_default(),
                event.first_seen.clone(),
                if event.new { "yes" } else { "no" }.to_string(),
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
    let skipped: Vec<String> = report
        .checks
        .iter()
        .filter(|row| row.status == CheckStatus::Error)
        .map(|row| {
            format!(
                "{} {}: {}",
                row.watch.kind.as_str(),
                row.watch.value,
                row.detail
            )
        })
        .collect();
    for line in skipped {
        out.push_str(&format!("error: {line}\n"));
    }
    out.push_str(&format!("{}\n", report.attribution));
    out
}

fn cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
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
            "| Identity | Breach | Breach date | Added to source | First seen | New | Data classes |\n| --- | --- | --- | --- | --- | --- | --- |\n",
        );
        for event in &report.events {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                cell(&event.identity),
                cell(event.breach.title.as_deref().unwrap_or(&event.breach.name)),
                cell(event.breach.breach_date.as_deref().unwrap_or("")),
                cell(event.breach.added_date.as_deref().unwrap_or("")),
                event.first_seen,
                if event.new { "yes" } else { "no" },
                cell(&event.breach.data_classes.join(", "))
            ));
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
                who.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    out.push_str(&format!("\n{}\n", report.attribution));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leaks::event::{WatchKind, WatchRef};
    use crate::leaks::{Breach, CheckRow, LeakEvent, HIBP_ATTRIBUTION};

    fn report() -> LeakReport {
        let event = LeakEvent::new(
            "hibp",
            WatchRef::new(WatchKind::Domain, "example.com"),
            "alex@example.com".into(),
            Breach {
                title: Some("Quokka | Forum".into()),
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
                    detail: "rate limit exceeded".into(),
                },
            ],
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
            out.contains("error: vip vip@example.net: rate limit exceeded"),
            "{out}"
        );
        assert!(out.contains("Have I Been Pwned"), "{out}");
    }

    #[test]
    fn markdown_has_reset_path_and_escapes_pipes() {
        let out = render_leaks(&report(), LeakOutput::Markdown);
        assert!(out.contains("Quokka \\| Forum"), "{out}");
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
