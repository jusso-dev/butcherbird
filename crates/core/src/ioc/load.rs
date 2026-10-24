//! Bulk input: text, CSV, JSON and STIX 2.1 bundles.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use super::extract::extract_iocs;
use super::parse::parse_ioc;
use super::{dedupe, InputError, Ioc};

/// How to read a blob of indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputFormat {
    /// JSON object/array, STIX bundle, CSV header, or text.
    Auto,
    /// One indicator per line, or free text.
    Text,
    /// Comma-separated rows.
    Csv,
    /// A JSON array or object of indicators.
    Json,
    /// A STIX 2.1 bundle or indicator object.
    Stix,
}

/// Load, normalise and dedupe indicators from `input`.
pub fn load_iocs(input: &str, format: InputFormat) -> Result<Vec<Ioc>, InputError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let format = match format {
        InputFormat::Auto => detect(trimmed)?,
        other => other,
    };
    let iocs = match format {
        InputFormat::Text | InputFormat::Auto => extract_iocs(trimmed),
        InputFormat::Csv => parse_csv(trimmed)?,
        InputFormat::Json => parse_json(trimmed)?,
        InputFormat::Stix => parse_stix(trimmed)?,
    };
    Ok(dedupe(iocs))
}

fn detect(input: &str) -> Result<InputFormat, InputError> {
    let trimmed = input.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        let value: Value =
            serde_json::from_str(trimmed).map_err(|e| InputError::Json(e.to_string()))?;
        return Ok(if is_stix(&value) {
            InputFormat::Stix
        } else {
            InputFormat::Json
        });
    }
    if looks_like_csv(input) {
        Ok(InputFormat::Csv)
    } else {
        Ok(InputFormat::Text)
    }
}

fn looks_like_csv(input: &str) -> bool {
    first_line(input).is_some_and(line_is_header)
}

fn first_line(input: &str) -> Option<&str> {
    input.lines().map(str::trim).find(|line| !line.is_empty())
}

fn line_is_header(line: &str) -> bool {
    split_csv_line(line).iter().any(|cell| {
        matches!(
            cell.to_ascii_lowercase().as_str(),
            "ioc"
                | "indicator"
                | "value"
                | "observable"
                | "ip"
                | "domain"
                | "url"
                | "hash"
                | "email"
                | "type"
        )
    })
}

fn split_csv_line(line: &str) -> Vec<String> {
    line.split(',')
        .map(|c| c.trim().trim_matches('"').trim().to_string())
        .collect()
}

fn parse_csv(input: &str) -> Result<Vec<Ioc>, InputError> {
    let has_headers = first_line(input).is_some_and(line_is_header);
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(has_headers)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(input.as_bytes());
    let idx = if has_headers {
        let headers = reader
            .headers()
            .map_err(|e| InputError::Csv(e.to_string()))?;
        header_index(headers)
    } else {
        0
    };
    let mut found = Vec::new();
    for record in reader.records() {
        let record = record.map_err(|e| InputError::Csv(e.to_string()))?;
        let Some(field) = record.get(idx) else {
            continue;
        };
        if field.is_empty() {
            continue;
        }
        if let Some(ioc) = parse_ioc(field) {
            found.push(ioc);
        } else {
            found.extend(extract_iocs(field));
        }
    }
    Ok(found)
}

fn header_index(headers: &csv::StringRecord) -> usize {
    const NAMES: &[&str] = &[
        "ioc",
        "indicator",
        "value",
        "observable",
        "ip",
        "domain",
        "url",
        "hash",
        "email",
    ];
    headers
        .iter()
        .position(|h| NAMES.contains(&h.trim().to_ascii_lowercase().as_str()))
        .unwrap_or(0)
}

fn parse_json(input: &str) -> Result<Vec<Ioc>, InputError> {
    let value: Value = serde_json::from_str(input).map_err(|e| InputError::Json(e.to_string()))?;
    Ok(iocs_from_json(&value))
}

fn iocs_from_json(value: &Value) -> Vec<Ioc> {
    match value {
        Value::Array(items) => items.iter().flat_map(iocs_from_json_item).collect(),
        Value::Object(map) => {
            for key in ["iocs", "indicators", "data", "observables"] {
                if let Some(items) = map.get(key).and_then(Value::as_array) {
                    return items.iter().flat_map(iocs_from_json_item).collect();
                }
            }
            iocs_from_json_item(value)
        }
        Value::String(text) => iocs_from_text(text),
        _ => Vec::new(),
    }
}

fn iocs_from_json_item(value: &Value) -> Vec<Ioc> {
    match value {
        Value::String(text) => iocs_from_text(text),
        Value::Object(map) => {
            for key in ["ioc", "indicator", "value", "observable"] {
                if let Some(text) = map.get(key).and_then(Value::as_str) {
                    return iocs_from_text(text);
                }
            }
            Vec::new()
        }
        _ => Vec::new(),
    }
}

fn iocs_from_text(text: &str) -> Vec<Ioc> {
    if let Some(ioc) = parse_ioc(text) {
        vec![ioc]
    } else {
        extract_iocs(text)
    }
}

fn parse_stix(input: &str) -> Result<Vec<Ioc>, InputError> {
    let value: Value = serde_json::from_str(input).map_err(|e| InputError::Stix(e.to_string()))?;
    if !is_stix(&value) {
        return Err(InputError::Stix("not a STIX 2.1 bundle or object".into()));
    }
    Ok(iocs_from_stix(&value))
}

fn is_stix(value: &Value) -> bool {
    let Some(kind) = value.get("type").and_then(Value::as_str) else {
        return false;
    };
    matches!(
        kind,
        "bundle"
            | "indicator"
            | "ipv4-addr"
            | "ipv6-addr"
            | "domain-name"
            | "url"
            | "email-addr"
            | "file"
            | "autonomous-system"
    )
}

fn iocs_from_stix(value: &Value) -> Vec<Ioc> {
    let Some(kind) = value.get("type").and_then(Value::as_str) else {
        return Vec::new();
    };
    if kind == "bundle" {
        return value
            .get("objects")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .flat_map(iocs_from_stix)
            .collect();
    }
    match kind {
        "indicator" => value
            .get("pattern")
            .and_then(Value::as_str)
            .map(iocs_from_pattern)
            .unwrap_or_default(),
        "ipv4-addr" | "ipv6-addr" | "domain-name" | "url" | "email-addr" => value
            .get("value")
            .and_then(Value::as_str)
            .map(iocs_from_text)
            .unwrap_or_default(),
        "file" => value
            .get("hashes")
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|map| map.values())
            .filter_map(Value::as_str)
            .flat_map(iocs_from_text)
            .collect(),
        "autonomous-system" => {
            let number = value.get("number").and_then(json_number);
            number
                .map(|n| format!("AS{n}"))
                .and_then(|s| parse_ioc(&s))
                .into_iter()
                .collect()
        }
        _ => Vec::new(),
    }
}

fn json_number(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}

fn iocs_from_pattern(pattern: &str) -> Vec<Ioc> {
    let mut found = Vec::new();
    for cap in QUOTED.captures_iter(pattern) {
        found.extend(iocs_from_text(&cap[1]));
    }
    for cap in ASN_PATTERN.captures_iter(pattern) {
        if let Some(ioc) = parse_ioc(&format!("AS{}", &cap[1])) {
            found.push(ioc);
        }
    }
    found
}

static QUOTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"'([^']+)'").unwrap());
static ASN_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)autonomous-system:number\s*=\s*(\d+)").unwrap());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IocType;

    #[test]
    fn auto_json_array() {
        let iocs = load_iocs(r#"["192.0.2.1", "evil.example"]"#, InputFormat::Auto).unwrap();
        assert_eq!(iocs.len(), 2);
        assert_eq!(iocs[0].kind, IocType::Ipv4);
        assert_eq!(iocs[1].value, "evil.example");
    }

    #[test]
    fn auto_csv_uses_indicator_column() {
        let csv = "note,indicator\nscanner,192.0.2.8\n";
        let iocs = load_iocs(csv, InputFormat::Auto).unwrap();
        assert_eq!(iocs.len(), 1);
        assert_eq!(iocs[0].value, "192.0.2.8");
    }

    #[test]
    fn stix_bundle() {
        let bundle = r#"{
            "type": "bundle",
            "id": "bundle--11111111-1111-4111-8111-111111111111",
            "objects": [
                {"type": "indicator", "pattern": "[ipv4-addr:value = '192.0.2.9']", "pattern_type": "stix"},
                {"type": "domain-name", "value": "Bad.Example"},
                {"type": "file", "hashes": {"SHA-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}},
                {"type": "autonomous-system", "number": 13335},
                {"type": "indicator", "pattern": "[autonomous-system:number = 64496]", "pattern_type": "stix"}
            ]
        }"#;
        let iocs = load_iocs(bundle, InputFormat::Auto).unwrap();
        let values: Vec<_> = iocs.iter().map(|i| i.value.as_str()).collect();
        assert!(values.contains(&"192.0.2.9"), "{values:?}");
        assert!(values.contains(&"bad.example"), "{values:?}");
        assert!(
            values.contains(&"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert!(values.contains(&"AS13335"));
        assert!(values.contains(&"AS64496"));
    }

    #[test]
    fn wrapped_json_object() {
        let iocs = load_iocs(
            r#"{"iocs":[{"value":"198.51.100.4"},{"ioc":"hxxps://bad[.]example/x"}]}"#,
            InputFormat::Json,
        )
        .unwrap();
        assert_eq!(iocs.len(), 2);
        assert_eq!(iocs[1].value, "https://bad.example/x");
    }
}
