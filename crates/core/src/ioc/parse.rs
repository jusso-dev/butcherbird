//! Single-token classification, defang and normalisation.

use std::net::{Ipv4Addr, Ipv6Addr};

use url::Url;

use super::{Ioc, IocType};

/// Parse one token. Returns `None` when it is not an indicator.
pub fn parse_ioc(raw: &str) -> Option<Ioc> {
    let original = raw.trim();
    if original.is_empty() {
        return None;
    }
    let defanged = defang(original);
    let token = strip_trailer(defanged.trim());
    if token.is_empty() {
        return None;
    }
    let (kind, value) = classify(token)?;
    let stored_raw = if url_has_userinfo(original) {
        value.clone()
    } else {
        original.to_string()
    };
    Some(Ioc {
        kind,
        value,
        raw: stored_raw,
    })
}

fn url_has_userinfo(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    (lower.contains("http://") || lower.contains("https://") || lower.contains("hxxp"))
        && raw.contains('@')
}

pub(crate) fn defang(input: &str) -> String {
    defang_mapped(input).text
}

pub(crate) struct Mapped {
    pub(crate) text: String,
    /// `map[new_byte] = old_byte`, plus a trailing sentinel at `text.len()`.
    pub(crate) map: Vec<usize>,
}

pub(crate) fn defang_mapped(input: &str) -> Mapped {
    const TOKENS: &[(&str, &str)] = &[
        ("hxxps[:]//", "https://"),
        ("hxxp[:]//", "http://"),
        ("https[:]//", "https://"),
        ("http[:]//", "http://"),
        ("hxxps://", "https://"),
        ("hxxp://", "http://"),
        ("[://]", "://"),
        ("[dot]", "."),
        ("(dot)", "."),
        ("{dot}", "."),
        ("[.]", "."),
        ("(.)", "."),
        ("{.}", "."),
        ("[at]", "@"),
        ("(at)", "@"),
        ("{at}", "@"),
        ("[@]", "@"),
        ("[:]", ":"),
    ];

    let bytes = input.as_bytes();
    let mut text = String::with_capacity(input.len());
    let mut map = Vec::with_capacity(input.len() + 1);
    let mut i = 0;
    while i < bytes.len() {
        if let Some((consumed, replacement)) = match_token(bytes, i, TOKENS) {
            for _ in 0..replacement.len() {
                map.push(i);
            }
            text.push_str(replacement);
            i += consumed;
            continue;
        }
        let ch = input[i..].chars().next().expect("i is on a char boundary");
        let len = ch.len_utf8();
        text.push(ch);
        for _ in 0..len {
            map.push(i);
        }
        i += len;
    }
    map.push(bytes.len());
    debug_assert_eq!(map.len(), text.len() + 1);
    Mapped { text, map }
}

fn match_token<'a>(
    bytes: &[u8],
    i: usize,
    tokens: &[(&'a str, &'a str)],
) -> Option<(usize, &'a str)> {
    for (from, to) in tokens {
        if bytes[i..].len() >= from.len()
            && bytes[i..i + from.len()].eq_ignore_ascii_case(from.as_bytes())
        {
            return Some((from.len(), *to));
        }
    }
    None
}

fn strip_trailer(s: &str) -> &str {
    s.trim_matches(['"', '\'', '`', '<', '>'])
        .trim_end_matches(['.', ',', ';', ':', ')', ']'])
        .trim_start_matches(['(', '['])
}

fn classify(token: &str) -> Option<(IocType, String)> {
    if let Some(url) = as_url(token) {
        return Some((IocType::Url, url));
    }
    if let Some(email) = as_email(token) {
        return Some((IocType::Email, email));
    }
    if let Some(asn) = as_asn(token) {
        return Some((IocType::Asn, asn));
    }
    if let Some(cidr) = as_cidr(token) {
        return Some((IocType::Cidr, cidr));
    }
    if let Some(ip) = as_ipv4(token) {
        return Some((IocType::Ipv4, ip));
    }
    if let Some(ip) = as_ipv6(token) {
        return Some((IocType::Ipv6, ip));
    }
    if let Some(hash) = as_hash(token) {
        return Some(hash);
    }
    if let Some(domain) = as_domain(token) {
        return Some((IocType::Domain, domain));
    }
    None
}

fn as_url(token: &str) -> Option<String> {
    if token.chars().any(char::is_whitespace) {
        return None;
    }
    let lower = token.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return None;
    }
    let mut url = Url::parse(token).ok()?;
    url.host()?;
    url.set_fragment(None);
    let _ = url.set_username("");
    let _ = url.set_password(None);
    Some(url.to_string())
}

fn as_email(token: &str) -> Option<String> {
    let lower = token.to_ascii_lowercase();
    let (local, domain) = lower.split_once('@')?;
    if local.is_empty() || local.len() > 64 || domain.is_empty() {
        return None;
    }
    if !local
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-'))
    {
        return None;
    }
    let domain = as_domain(domain)?;
    Some(format!("{local}@{domain}"))
}

fn as_asn(token: &str) -> Option<String> {
    let lower = token.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("asn")
        .or_else(|| lower.strip_prefix("as"))?;
    if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_digit()) || rest.len() > 10 {
        return None;
    }
    let number: u64 = rest.parse().ok()?;
    if number == 0 || number > u64::from(u32::MAX) {
        return None;
    }
    Some(format!("AS{number}"))
}

fn as_cidr(token: &str) -> Option<String> {
    let (addr, pref) = token.split_once('/')?;
    let prefix: u8 = pref.parse().ok()?;
    if addr.contains(':') {
        let ip: Ipv6Addr = addr.parse().ok()?;
        if prefix > 128 {
            return None;
        }
        Some(format!("{}/{prefix}", mask_v6(ip, prefix)))
    } else {
        let ip: Ipv4Addr = addr.parse().ok()?;
        if prefix > 32 {
            return None;
        }
        Some(format!("{}/{prefix}", mask_v4(ip, prefix)))
    }
}

fn mask_v4(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    let mask = u32::MAX << (32 - prefix);
    Ipv4Addr::from(u32::from(ip) & mask)
}

fn mask_v6(ip: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    if prefix == 0 {
        return Ipv6Addr::UNSPECIFIED;
    }
    let mask = u128::MAX << (128 - prefix);
    Ipv6Addr::from(u128::from(ip) & mask)
}

fn as_ipv4(token: &str) -> Option<String> {
    token.parse::<Ipv4Addr>().ok().map(|ip| ip.to_string())
}

fn as_ipv6(token: &str) -> Option<String> {
    let trimmed = token.trim_matches(|c| c == '[' || c == ']');
    trimmed.parse::<Ipv6Addr>().ok().map(|ip| ip.to_string())
}

fn as_hash(token: &str) -> Option<(IocType, String)> {
    if !token.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let kind = match token.len() {
        32 => IocType::Md5,
        40 => IocType::Sha1,
        64 => IocType::Sha256,
        _ => return None,
    };
    Some((kind, token.to_ascii_lowercase()))
}

fn as_domain(token: &str) -> Option<String> {
    let name = token.trim_end_matches('.').to_ascii_lowercase();
    if name.len() > 253 || name.is_empty() || !name.is_ascii() {
        return None;
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    if !labels.iter().all(|label| valid_label(label)) {
        return None;
    }
    let tld = *labels.last()?;
    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) || is_file_ext(tld) {
        return None;
    }
    if name.parse::<Ipv4Addr>().is_ok() {
        return None;
    }
    Some(name)
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn is_file_ext(tld: &str) -> bool {
    matches!(
        tld,
        "exe"
            | "dll"
            | "pdf"
            | "doc"
            | "docx"
            | "xls"
            | "xlsx"
            | "ppt"
            | "pptx"
            | "txt"
            | "csv"
            | "json"
            | "xml"
            | "zip"
            | "rar"
            | "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "html"
            | "htm"
            | "js"
            | "css"
            | "md"
            | "yml"
            | "yaml"
            | "toml"
            | "log"
            | "dat"
            | "bin"
            | "iso"
            | "7z"
            | "gz"
            | "tar"
            | "ps1"
            | "bat"
            | "cmd"
            | "sh"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_tokens() {
        let cases = [
            ("192.0.2.1", IocType::Ipv4, "192.0.2.1"),
            ("192.0.2.10/24", IocType::Cidr, "192.0.2.0/24"),
            ("2001:db8::1", IocType::Ipv6, "2001:db8::1"),
            (
                "2001:0DB8:0000:0000:0000:0000:0000:0001",
                IocType::Ipv6,
                "2001:db8::1",
            ),
            ("2001:db8::/32", IocType::Cidr, "2001:db8::/32"),
            ("Evil.Example", IocType::Domain, "evil.example"),
            ("evil.example.", IocType::Domain, "evil.example"),
            (
                "hxxps://bad[.]example/a",
                IocType::Url,
                "https://bad.example/a",
            ),
            (
                "hxxp[:]//bad[.]example/b",
                IocType::Url,
                "http://bad.example/b",
            ),
            (
                "user(at)evil[.]example",
                IocType::Email,
                "user@evil.example",
            ),
            ("AS13335", IocType::Asn, "AS13335"),
            ("asn13335", IocType::Asn, "AS13335"),
            (
                "D41D8CD98F00B204E9800998ECF8427E",
                IocType::Md5,
                "d41d8cd98f00b204e9800998ecf8427e",
            ),
            (
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                IocType::Sha1,
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            ),
            (
                "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
                IocType::Sha256,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
        ];
        for (raw, kind, value) in cases {
            let ioc = parse_ioc(raw).unwrap_or_else(|| panic!("parse {raw}"));
            assert_eq!(ioc.kind, kind, "{raw}");
            assert_eq!(ioc.value, value, "{raw}");
        }
    }

    #[test]
    fn rejects_noise() {
        for raw in ["", "hello", "999.1.1.1", "malware.exe", "AS0", "::::"] {
            assert!(parse_ioc(raw).is_none(), "{raw}");
        }
    }

    #[test]
    fn strips_url_userinfo_from_value_and_raw() {
        let ioc = parse_ioc("https://user:secretpass@evil.example/a").unwrap();
        assert_eq!(ioc.value, "https://evil.example/a");
        assert!(!ioc.raw.contains("secretpass"));
        assert!(!ioc.value.contains("secretpass"));
    }

    #[test]
    fn defang_map_round_trip_span() {
        let original = "see bad[.]example now";
        let mapped = defang_mapped(original);
        assert_eq!(mapped.text, "see bad.example now");
        let start = mapped.text.find("bad.example").unwrap();
        let end = start + "bad.example".len();
        let raw = &original[mapped.map[start]..mapped.map[end]];
        assert_eq!(raw, "bad[.]example");
    }
}
