//! VirusTotal v3 lookup. Free API key. IPs, domains, URLs and file hashes.

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;

use crate::config::Config;
use crate::ioc::{Ioc, IocType};
use crate::score::{Finding, Verdict};
use crate::secret::Secret;

use super::http::{self, IntervalGate};
use super::{
    configured_rate, key_or_skip, ready, AuthKind, Provider, ProviderError, ProviderMeta, Slot,
    Tier,
};

const DEFAULT_URL: &str = "https://www.virustotal.com";

/// VirusTotal provider identity.
pub const VIRUSTOTAL_META: ProviderMeta = ProviderMeta {
    id: "virustotal",
    types: &[
        IocType::Ipv4,
        IocType::Ipv6,
        IocType::Domain,
        IocType::Url,
        IocType::Md5,
        IocType::Sha1,
        IocType::Sha256,
    ],
    tier: Tier::Free,
    auth: AuthKind::ApiKey,
    default_rate_per_minute: 4,
};

/// VirusTotal v3 client.
pub struct VirusTotal {
    client: reqwest::Client,
    api_key: Secret,
    base_url: String,
    gate: IntervalGate,
}

impl VirusTotal {
    /// `base_url` is the origin, for example `https://www.virustotal.com`.
    pub fn new(
        client: reqwest::Client,
        api_key: Secret,
        base_url: impl Into<String>,
        rate_per_minute: u32,
    ) -> Self {
        Self {
            client,
            api_key,
            base_url: base_url.into(),
            gate: IntervalGate::per_minute(rate_per_minute),
        }
    }
}

pub(crate) fn slot(cfg: &Config, client: reqwest::Client) -> Slot {
    let key = match key_or_skip(cfg, VIRUSTOTAL_META) {
        Ok(key) => key.clone(),
        Err(skipped) => return skipped,
    };
    let settings = cfg.provider(VIRUSTOTAL_META.id);
    let base = settings
        .base_url
        .clone()
        .unwrap_or_else(|| DEFAULT_URL.to_string());
    ready(VirusTotal::new(
        client,
        key,
        base,
        configured_rate(VIRUSTOTAL_META, settings.rate_per_minute),
    ))
}

#[async_trait]
impl Provider for VirusTotal {
    fn meta(&self) -> ProviderMeta {
        VIRUSTOTAL_META
    }

    async fn lookup(&self, ioc: &Ioc) -> Result<Finding, ProviderError> {
        let path = object_path(ioc);
        let url = format!("{}{path}", self.base_url.trim_end_matches('/'));
        let response = http::send(&self.gate, &self.api_key, || {
            self.client
                .get(&url)
                .header("x-apikey", self.api_key.as_header_value())
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
        })
        .await;
        let response = match response {
            Err(ProviderError::Http { status: 404, .. }) => {
                return Ok(Finding {
                    verdict: Verdict::Unknown,
                    confidence: 0,
                    detail: "not seen".to_string(),
                });
            }
            other => other?,
        };
        let body: Value = response.json().await.map_err(|_| ProviderError::Decode)?;
        let stats = body
            .pointer("/data/attributes/last_analysis_stats")
            .ok_or(ProviderError::Decode)?;
        Ok(map_stats(stats))
    }
}

fn object_path(ioc: &Ioc) -> String {
    match ioc.kind {
        IocType::Ipv4 | IocType::Ipv6 => {
            format!("/api/v3/ip_addresses/{}", encode_segment(&ioc.value))
        }
        IocType::Domain => format!("/api/v3/domains/{}", encode_segment(&ioc.value)),
        IocType::Url => format!(
            "/api/v3/urls/{}",
            URL_SAFE_NO_PAD.encode(ioc.value.as_bytes())
        ),
        IocType::Md5 | IocType::Sha1 | IocType::Sha256 => {
            format!("/api/v3/files/{}", encode_segment(&ioc.value))
        }
        _ => "/api/v3/".to_string(),
    }
}

fn encode_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn stat(stats: &Value, name: &str) -> u64 {
    stats.get(name).and_then(Value::as_u64).unwrap_or(0)
}

fn map_stats(stats: &Value) -> Finding {
    let malicious = stat(stats, "malicious");
    let suspicious = stat(stats, "suspicious");
    let harmless = stat(stats, "harmless");
    let detail = format!("malicious {malicious}, suspicious {suspicious}, harmless {harmless}");
    if malicious >= 3 {
        Finding {
            verdict: Verdict::Malicious,
            confidence: u64_conf(50 + malicious * 5, 100),
            detail,
        }
    } else if malicious >= 1 || suspicious >= 1 {
        Finding {
            verdict: Verdict::Suspicious,
            confidence: u64_conf(30 + malicious * 10 + suspicious * 5, 90),
            detail,
        }
    } else if harmless > 0 {
        Finding {
            verdict: Verdict::Clean,
            confidence: 70,
            detail,
        }
    } else {
        Finding {
            verdict: Verdict::Unknown,
            confidence: 0,
            detail: "no analysis stats".to_string(),
        }
    }
}

fn u64_conf(value: u64, cap: u64) -> u8 {
    value.min(cap).min(100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::parse_ioc;
    use crate::provider::Provider;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn provider(server: &MockServer) -> VirusTotal {
        VirusTotal::new(
            http::client(std::time::Duration::from_secs(5)).unwrap(),
            Secret::new("bb-test-secret-key"),
            server.uri(),
            60_000,
        )
    }

    fn stats(malicious: u64, suspicious: u64, harmless: u64) -> serde_json::Value {
        serde_json::json!({
            "data": {
                "attributes": {
                    "last_analysis_stats": { "malicious": malicious, "suspicious": suspicious, "harmless": harmless, "undetected": 0 }
                }
            }
        })
    }

    #[tokio::test]
    async fn ip_malicious() {
        let server = MockServer::start().await;
        let ioc = parse_ioc("192.0.2.5").unwrap();
        Mock::given(method("GET"))
            .and(path(object_path(&ioc)))
            .and(header("x-apikey", "bb-test-secret-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(stats(8, 1, 40)))
            .mount(&server)
            .await;
        let hit = provider(&server).await.lookup(&ioc).await.unwrap();
        assert_eq!(hit.verdict, Verdict::Malicious);
        assert!(hit.confidence >= 50);
    }

    #[tokio::test]
    async fn not_seen_is_unknown() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404).set_body_string("missing bb-test-secret-key"))
            .mount(&server)
            .await;
        let hit = provider(&server)
            .await
            .lookup(&parse_ioc("198.51.100.8").unwrap())
            .await
            .unwrap();
        assert_eq!(hit.verdict, Verdict::Unknown);
        assert_eq!(hit.detail, "not seen");
    }

    #[tokio::test]
    async fn url_id_is_base64_and_clean() {
        let server = MockServer::start().await;
        let ioc = parse_ioc("https://evil.example/a").unwrap();
        Mock::given(method("GET"))
            .and(path(object_path(&ioc)))
            .respond_with(ResponseTemplate::new(200).set_body_json(stats(0, 0, 20)))
            .mount(&server)
            .await;
        let hit = provider(&server).await.lookup(&ioc).await.unwrap();
        assert_eq!(hit.verdict, Verdict::Clean);
        assert!(object_path(&ioc).contains("/api/v3/urls/"));
    }

    #[tokio::test]
    async fn hash_lookup() {
        let server = MockServer::start().await;
        let ioc = parse_ioc("d41d8cd98f00b204e9800998ecf8427e").unwrap();
        Mock::given(method("GET"))
            .and(path(object_path(&ioc)))
            .respond_with(ResponseTemplate::new(200).set_body_json(stats(1, 0, 10)))
            .mount(&server)
            .await;
        let hit = provider(&server).await.lookup(&ioc).await.unwrap();
        assert_eq!(hit.verdict, Verdict::Suspicious);
    }
}
