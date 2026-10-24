//! Local evidence pack. Nothing in here is submitted.

use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::ioc::Ioc;
use crate::Error;

use super::template::{self, EVIDENCE};

struct Portal {
    name: &'static str,
    url: &'static str,
    note: &'static str,
}

const PORTALS: &[Portal] = &[
    Portal {
        name: "ReportCyber",
        url: "https://www.cyber.gov.au/report",
        note: "Australian Signals Directorate. Reports are passed to police.",
    },
    Portal {
        name: "Scamwatch",
        url: "https://www.scamwatch.gov.au/report-a-scam",
        note: "National Anti-Scam Centre.",
    },
    Portal {
        name: "IC3",
        url: "https://www.ic3.gov/",
        note: "FBI Internet Crime Complaint Center. Type this address yourself. IC3 will not ask you to pay.",
    },
    Portal {
        name: "Report Fraud",
        url: "https://www.reportfraud.police.uk/",
        note: "Replaced Action Fraud for England, Wales and Northern Ireland.",
    },
    Portal {
        name: "Google Safe Browsing",
        url: "https://www.google.com/safebrowsing/report_phish/",
        note: "Phishing report form. Butcherbird does not submit this for you. There is no report API call.",
    },
];

#[derive(Serialize)]
struct PackIoc<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    value: &'a str,
}

#[derive(Serialize)]
struct PackPortal {
    name: &'static str,
    url: &'static str,
    note: &'static str,
}

#[derive(Serialize)]
struct PackData<'a> {
    iocs: Vec<PackIoc<'a>>,
    portals: Vec<PackPortal>,
}

/// Write `evidence.md`, `evidence.csv` and `evidence.pdf` into `dir`.
/// Overwrites those three files. Does not open a network connection.
pub fn write_evidence_pack(
    dir: &Path,
    templates_dir: Option<&Path>,
    iocs: &[Ioc],
) -> Result<(), Error> {
    fs::create_dir_all(dir).map_err(|err| Error::Config(format!("{}: {err}", dir.display())))?;
    let source = template::load_template(templates_dir, "evidence.md.hbs", EVIDENCE)?;
    let data = PackData {
        iocs: iocs
            .iter()
            .map(|ioc| PackIoc {
                kind: ioc.kind.as_str(),
                value: &ioc.value,
            })
            .collect(),
        portals: PORTALS
            .iter()
            .map(|portal| PackPortal {
                name: portal.name,
                url: portal.url,
                note: portal.note,
            })
            .collect(),
    };
    let markdown = template::render_template(&source, &data).map_err(Error::Config)?;
    write_file(&dir.join("evidence.md"), markdown.as_bytes())?;
    write_file(&dir.join("evidence.csv"), &render_csv(iocs))?;
    write_file(&dir.join("evidence.pdf"), &render_pdf(&markdown))?;
    Ok(())
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    fs::write(path, bytes).map_err(|err| Error::Config(format!("{}: {err}", path.display())))
}

fn render_csv(iocs: &[Ioc]) -> Vec<u8> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    let _ = writer.write_record(["type", "value"]);
    for ioc in iocs {
        let _ = writer.write_record([ioc.kind.as_str(), ioc.value.as_str()]);
    }
    writer.into_inner().unwrap_or_default()
}

fn render_pdf(text: &str) -> Vec<u8> {
    let lines: Vec<String> = text.lines().map(pdf_escape).collect();
    let chunks: Vec<&[String]> = if lines.is_empty() {
        vec![&[]]
    } else {
        lines.chunks(40).collect()
    };
    let page_count = chunks.len();
    let max_id = 3 + page_count * 2;
    let mut out = Vec::from(b"%PDF-1.4\n");
    let mut offsets = vec![0usize; max_id + 1];

    push_obj(
        &mut out,
        &mut offsets,
        1,
        "<< /Type /Catalog /Pages 2 0 R >>",
    );
    let kids = (0..page_count)
        .map(|index| format!("{} 0 R", 4 + index * 2))
        .collect::<Vec<_>>()
        .join(" ");
    push_obj(
        &mut out,
        &mut offsets,
        2,
        &format!("<< /Type /Pages /Kids [{kids}] /Count {page_count} >>"),
    );
    push_obj(
        &mut out,
        &mut offsets,
        3,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    );

    for (index, lines) in chunks.iter().enumerate() {
        let page_id = 4 + index * 2;
        let content_id = page_id + 1;
        push_obj(
            &mut out,
            &mut offsets,
            page_id,
            &format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {content_id} 0 R /Resources << /Font << /F1 3 0 R >> >> >>"
            ),
        );
        let stream = page_stream(lines);
        offsets[content_id] = out.len();
        out.extend(
            format!(
                "{content_id} 0 obj\n<< /Length {} >>\nstream\n",
                stream.len()
            )
            .into_bytes(),
        );
        out.extend(stream);
        out.extend(b"\nendstream\nendobj\n");
    }

    let xref = out.len();
    out.extend(format!("xref\n0 {}\n", max_id + 1).into_bytes());
    out.extend(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        out.extend(format!("{offset:010} 00000 n \n").into_bytes());
    }
    out.extend(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            max_id + 1
        )
        .into_bytes(),
    );
    out
}

fn push_obj(out: &mut Vec<u8>, offsets: &mut [usize], id: usize, body: &str) {
    offsets[id] = out.len();
    out.extend(format!("{id} 0 obj\n{body}\nendobj\n").into_bytes());
}

fn page_stream(lines: &[String]) -> Vec<u8> {
    let mut text = String::from("BT\n/F1 10 Tf\n48 760 Td\n14 TL\n");
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            text.push_str("T*\n");
        }
        text.push('(');
        text.push_str(line);
        text.push_str(") Tj\n");
    }
    text.push_str("ET\n");
    text.into_bytes()
}

fn pdf_escape(line: &str) -> String {
    let mut out = String::new();
    for ch in line.chars() {
        match ch {
            '\\' | '(' | ')' => {
                out.push('\\');
                out.push(ch);
            }
            ' '..='~' => out.push(ch),
            _ => out.push('?'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::IocType;

    fn sample() -> Vec<Ioc> {
        vec![Ioc {
            kind: IocType::Domain,
            value: "evil.example".into(),
            raw: "evil.example".into(),
        }]
    }

    #[test]
    fn pack_lists_portals_and_keeps_the_indicator_in_the_pdf() {
        let dir = tempfile::tempdir().unwrap();
        write_evidence_pack(dir.path(), None, &sample()).unwrap();
        let markdown = fs::read_to_string(dir.path().join("evidence.md")).unwrap();
        assert!(markdown.contains("evil.example"), "{markdown}");
        assert!(markdown.contains("did not submit"), "{markdown}");
        assert!(markdown.contains("cyber.gov.au"), "{markdown}");
        assert!(markdown.contains("scamwatch.gov.au"), "{markdown}");
        assert!(markdown.contains("ic3.gov"), "{markdown}");
        assert!(markdown.contains("reportfraud.police.uk"), "{markdown}");
        assert!(markdown.contains("Action Fraud"), "{markdown}");
        assert!(markdown.contains("safebrowsing"), "{markdown}");
        let csv = fs::read_to_string(dir.path().join("evidence.csv")).unwrap();
        assert!(csv.contains("domain"), "{csv}");
        assert!(csv.contains("evil.example"), "{csv}");
        let pdf = fs::read(dir.path().join("evidence.pdf")).unwrap();
        assert!(pdf.starts_with(b"%PDF"));
        assert!(pdf.windows(12).any(|window| window == b"evil.example"));
    }

    #[test]
    fn non_ascii_becomes_a_question_mark_in_the_pdf() {
        let dir = tempfile::tempdir().unwrap();
        let iocs = vec![Ioc {
            kind: IocType::Domain,
            value: "caf\u{e9}.example".into(),
            raw: "caf\u{e9}.example".into(),
        }];
        write_evidence_pack(dir.path(), None, &iocs).unwrap();
        let pdf = fs::read(dir.path().join("evidence.pdf")).unwrap();
        assert!(pdf.starts_with(b"%PDF"));
        assert!(pdf.windows(12).any(|window| window == b"caf?.example"));
        assert!(!pdf.windows(2).any(|window| window == [0xc3, 0xa9]));
    }

    #[test]
    fn template_file_replaces_the_built_in_body() {
        let dir = tempfile::tempdir().unwrap();
        let templates = dir.path().join("templates");
        fs::create_dir(&templates).unwrap();
        fs::write(
            templates.join("evidence.md.hbs"),
            "CUSTOM PACK {{#each iocs}}{{{this.value}}}{{/each}}\n",
        )
        .unwrap();
        let out = dir.path().join("out");
        write_evidence_pack(&out, Some(&templates), &sample()).unwrap();
        let markdown = fs::read_to_string(out.join("evidence.md")).unwrap();
        assert!(markdown.contains("CUSTOM PACK evil.example"), "{markdown}");
    }
}
