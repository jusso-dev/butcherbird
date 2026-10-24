//! WHOIS lookup via port 43. No API key.
//!
//! The first query goes to `whois.iana.org`. One `refer:` hop is followed
//! when the referral is a plain hostname. The row is unknown: a registrar
//! is contact data, not a reputation vote. URLs are queried by host.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::Config;
use crate::ioc::{Ioc, IocType};
use crate::score::{Finding, Verdict};

use super::http::IntervalGate;
use super::{
    clip_detail, enabled_or_skip, host_of, rate_of, ready, AuthKind, Provider, ProviderError,
    ProviderMeta, Slot, Tier,
};

const IANA: &str = "whois.iana.org";

/// WHOIS provider identity.
pub const WHOIS_META: ProviderMeta = ProviderMeta {
    id: "whois",
    types: &[
        IocType::Domain,
        IocType::Url,
        IocType::Ipv4,
        IocType::Ipv6,
        IocType::Cidr,
        IocType::Asn,
    ],
    tier: Tier::Free,
    auth: AuthKind::None,
    default_rate_per_minute: 10,
};

#[async_trait]
trait WhoisTransport: Send + Sync {
    async fn query(&self, server: &str, query: &str) -> Result<String, ProviderError>;
}

struct TcpWhois;

#[async_trait]
impl WhoisTransport for TcpWhois {
    async fn query(&self, server: &str, query: &str) -> Result<String, ProviderError> {
        let fut = async {
            let mut stream = tokio::net::TcpStream::connect((server, 43)).await?;
            stream.write_all(query.as_bytes()).await?;
            stream.write_all(b"\r\n").await?;
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                if buf.len() >= 65_536 {
                    break;
                }
                let read = stream.read(&mut tmp).await?;
                if read == 0 {
                    break;
                }
                let room = 65_536 - buf.len();
                buf.extend_from_slice(&tmp[..read.min(room)]);
            }
            Ok::<Vec<u8>, std::io::Error>(buf)
        };
        match tokio::time::timeout(Duration::from_secs(10), fut).await {
            Ok(Ok(buf)) => Ok(String::from_utf8_lossy(&buf).into_owned()),
            _ => Err(ProviderError::Transport),
        }
    }
}

/// WHOIS client.
pub struct Whois {
    transport: Arc<dyn WhoisTransport>,
    server: String,
    gate: IntervalGate,
}

impl Whois {
    /// Queries `whois.iana.org`, then one referral.
    pub fn new(rate_per_minute: u32) -> Self {
        Self::with_transport(Arc::new(TcpWhois), IANA, rate_per_minute)
    }

    fn with_transport(
        transport: Arc<dyn WhoisTransport>,
        server: impl Into<String>,
        rate_per_minute: u32,
    ) -> Self {
        Self {
            transport,
            server: server.into(),
            gate: IntervalGate::per_minute(rate_per_minute),
        }
    }
}

pub(crate) fn slot(cfg: &Config) -> Slot {
    if let Err(skipped) = enabled_or_skip(cfg, WHOIS_META) {
        return skipped;
    }
    ready(Whois::new(rate_of(cfg, WHOIS_META)))
}

#[async_trait]
impl Provider for Whois {
    fn meta(&self) -> ProviderMeta {
        WHOIS_META
    }

    async fn lookup(&self, ioc: &Ioc) -> Result<Finding, ProviderError> {
        let query = whois_query(ioc);
        self.gate.wait().await;
        let first = self.transport.query(&self.server, &query).await?;
        let parsed = parse_record(&first);
        let body = if let Some(refer) = parsed.refer.as_deref().and_then(referral_host) {
            if refer != self.server {
                self.gate.wait().await;
                match self.transport.query(&refer, &query).await {
                    Ok(body) => body,
                    Err(_) => first,
                }
            } else {
                first
            }
        } else {
            first
        };
        Ok(finding_from_record(&body))
    }
}

struct Parsed {
    registrar: Option<String>,
    abuse: Option<String>,
    asn: Option<String>,
    refer: Option<String>,
}

fn whois_query(ioc: &Ioc) -> String {
    let value = match ioc.kind {
        IocType::Url => host_of(&ioc.value).unwrap_or_else(|| ioc.value.clone()),
        IocType::Cidr => ioc
            .value
            .split('/')
            .next()
            .unwrap_or(ioc.value.as_str())
            .to_string(),
        _ => ioc.value.clone(),
    };
    value.replace(['\r', '\n'], "")
}

fn parse_record(body: &str) -> Parsed {
    let mut parsed = Parsed {
        registrar: None,
        abuse: None,
        asn: None,
        refer: None,
    };
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('%') || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.as_str() {
            "refer" | "whois" if parsed.refer.is_none() => parsed.refer = Some(value.to_string()),
            "registrar" | "registrar name" if parsed.registrar.is_none() => {
                parsed.registrar = Some(value.to_string());
            }
            "orgabuseemail"
            | "abuse-mailbox"
            | "org-abuse-email"
            | "registrar abuse contact email"
                if parsed.abuse.is_none() && value.contains('@') =>
            {
                parsed.abuse = Some(value.to_string());
            }
            "origin" | "originas" if parsed.asn.is_none() => {
                parsed.asn = parse_asn(value);
            }
            _ => {}
        }
    }
    parsed
}

fn parse_asn(value: &str) -> Option<String> {
    let digits: String = value
        .trim()
        .trim_start_matches(['A', 'S', 'a', 's'])
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        None
    } else {
        Some(format!("AS{digits}"))
    }
}

fn referral_host(value: &str) -> Option<String> {
    let host = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || host.contains("..")
        || !host
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-')
    {
        return None;
    }
    Some(host)
}

fn finding_from_record(body: &str) -> Finding {
    let parsed = parse_record(body);
    if parsed.registrar.is_none() && parsed.abuse.is_none() && parsed.asn.is_none() {
        return Finding {
            verdict: Verdict::Unknown,
            confidence: 0,
            detail: "no registrar or abuse contact".to_string(),
        };
    }
    let mut parts = Vec::new();
    if let Some(registrar) = parsed.registrar {
        parts.push(format!("registrar: {registrar}"));
    }
    if let Some(abuse) = parsed.abuse {
        parts.push(format!("abuse: {abuse}"));
    }
    if let Some(asn) = parsed.asn {
        parts.push(format!("asn: {asn}"));
    }
    Finding {
        verdict: Verdict::Unknown,
        confidence: 0,
        detail: clip_detail(&parts.join("; ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::parse_ioc;
    use crate::provider::Provider;

    struct Scripted;

    #[async_trait]
    impl WhoisTransport for Scripted {
        async fn query(&self, server: &str, query: &str) -> Result<String, ProviderError> {
            assert_eq!(query, "evil.example");
            match server {
                "whois.iana.org" => Ok("refer: whois.example\n".to_string()),
                "whois.example" => Ok(
                    "Registrar: Example Registrar\nRegistrar Abuse Contact Email: abuse@example.com\nOrigin: AS64500\n"
                        .to_string(),
                ),
                _ => Err(ProviderError::Transport),
            }
        }
    }

    #[test]
    fn referral_rejects_urls() {
        assert!(referral_host("whois.example").is_some());
        assert!(referral_host("https://whois.example/path").is_none());
    }

    #[tokio::test]
    async fn follows_one_referral_and_does_not_vote() {
        let client = Whois::with_transport(Arc::new(Scripted), IANA, 60_000);
        let hit = client
            .lookup(&parse_ioc("evil.example").unwrap())
            .await
            .unwrap();
        assert_eq!(hit.verdict, Verdict::Unknown);
        assert!(
            hit.detail.contains("registrar: Example Registrar"),
            "{}",
            hit.detail
        );
        assert!(
            hit.detail.contains("abuse: abuse@example.com"),
            "{}",
            hit.detail
        );
        assert!(hit.detail.contains("asn: AS64500"), "{}", hit.detail);
    }
}
