//! Pull indicators out of free text, including defanged forms.

use std::sync::LazyLock;

use regex::Regex;

use super::parse::{defang_mapped, parse_ioc};
use super::{dedupe, Ioc};

/// Extract and dedupe indicators from text. A line that is only one indicator
/// is taken as that indicator, so a URL does not also yield its host.
pub fn extract_iocs(text: &str) -> Vec<Ioc> {
    let mut found = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(ioc) = parse_ioc(trimmed) {
            found.push(ioc);
            continue;
        }
        found.extend(extract_prose(trimmed));
    }
    dedupe(found)
}

fn extract_prose(line: &str) -> Vec<Ioc> {
    let mapped = defang_mapped(line);
    let text = mapped.text.as_str();
    let mut occupied = Vec::new();
    let mut found = Vec::new();
    for (start, end) in candidate_spans(text) {
        if start >= end || overlaps(&occupied, start, end) {
            continue;
        }
        let (start, end) = trim_span(text, start, end);
        if start >= end || overlaps(&occupied, start, end) {
            continue;
        }
        let raw = &line[mapped.map[start]..mapped.map[end]];
        if let Some(ioc) = parse_ioc(raw) {
            occupied.push((start, end));
            found.push(ioc);
        }
    }
    found
}

fn candidate_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    push_regex(&mut spans, &URL, text);
    push_regex(&mut spans, &EMAIL, text);
    push_regex(&mut spans, &IPV4, text);
    push_ipv6(&mut spans, text);
    push_regex(&mut spans, &SHA256, text);
    push_regex(&mut spans, &SHA1, text);
    push_regex(&mut spans, &MD5, text);
    push_regex(&mut spans, &ASN, text);
    push_regex(&mut spans, &DOMAIN, text);
    spans
}

fn push_regex(out: &mut Vec<(usize, usize)>, re: &Regex, text: &str) {
    for m in re.find_iter(text) {
        out.push((m.start(), m.end()));
    }
}

fn push_ipv6(out: &mut Vec<(usize, usize)>, text: &str) {
    for cap in IPV6.captures_iter(text) {
        if let Some(m) = cap.get(1) {
            out.push((m.start(), m.end()));
        }
    }
}

fn overlaps(ranges: &[(usize, usize)], start: usize, end: usize) -> bool {
    ranges.iter().any(|&(s, e)| start < e && end > s)
}

fn trim_span(text: &str, start: usize, end: usize) -> (usize, usize) {
    let slice = &text[start..end];
    let end_trimmed = slice.trim_end_matches(['.', ',', ';', ':', ')', ']', '>', '"']);
    let end = start + end_trimmed.len();
    let slice = &text[start..end];
    let start_trimmed = slice.trim_start_matches(['(', '[', '<', '"', '\'']);
    let start = end - start_trimmed.len();
    (start, end)
}

static URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bhttps?://\S+").unwrap());
static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.-]+\.[a-z]{2,}\b").unwrap());
static IPV4: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b").unwrap());
static IPV6: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[^\da-f:])((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:/\d{1,3})?)").unwrap()
});
static SHA256: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b[a-f0-9]{64}\b").unwrap());
static SHA1: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b[a-f0-9]{40}\b").unwrap());
static MD5: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b[a-f0-9]{32}\b").unwrap());
static ASN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bAS(?:N)?\d{1,10}\b").unwrap());
static DOMAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b").unwrap()
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IocType;

    #[test]
    fn prose_extracts_and_dedupes() {
        let text = "\
Alert: host evil.example contacted 192.0.2.1 and 192.0.2.1.
hxxps://bad[.]example/login from user a(at)evil.example.
Hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ASN AS13335.
Ignore malware.exe.
";
        let iocs = extract_iocs(text);
        let values: Vec<_> = iocs.iter().map(|i| (i.kind, i.value.as_str())).collect();
        assert!(
            values.contains(&(IocType::Domain, "evil.example")),
            "{values:?}"
        );
        assert!(values.contains(&(IocType::Ipv4, "192.0.2.1")), "{values:?}");
        assert_eq!(values.iter().filter(|(_, v)| *v == "192.0.2.1").count(), 1);
        assert!(
            values.contains(&(IocType::Url, "https://bad.example/login")),
            "{values:?}"
        );
        assert!(
            values.contains(&(IocType::Email, "a@evil.example")),
            "{values:?}"
        );
        assert!(values.contains(&(
            IocType::Sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )));
        assert!(values.contains(&(IocType::Asn, "AS13335")));
        assert!(!values.iter().any(|(_, v)| *v == "malware.exe"));
    }

    #[test]
    fn url_line_does_not_also_emit_its_host() {
        let iocs = extract_iocs("https://evil.example/a\n");
        assert_eq!(iocs.len(), 1);
        assert_eq!(iocs[0].kind, IocType::Url);
    }

    #[test]
    fn example_file_parses() {
        let text = include_str!("../../../../examples/iocs.txt");
        let iocs = extract_iocs(text);
        assert!(iocs.len() >= 8, "got {}", iocs.len());
    }
}
