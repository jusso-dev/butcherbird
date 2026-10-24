//! RDAP bootstrap lookup. No API key.
//!
//! RDAP is contact data. The row is unknown so a registrar name does not
//! vote clean or malicious. URLs are looked up by host.

use async_trait::async_trait;
use serde_json::Value;

use crate::config::Config;
use crate::ioc::{Ioc, IocType};
use crate::score::{Finding, Verdict};
use crate::secret::Secret;

use super::http::{self, IntervalGate};
use super::{
    clip_detail, enabled_or_skip, host_of, is_not_found, origin, rate_of, ready, AuthKind,
    Provider, ProviderError, ProviderMeta, Slot, Tier,
};

const DEFAULT_URL: &str = "https://rdap.org";

/// RDAP provider identity.
pub const RDAP_META: ProviderMeta = ProviderMeta {
    id: "rdap",
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
    default_rate_per_minute: 30,
};

/// Abuse mailbox found on an RDAP object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AbuseContact {
    /// Mailbox, without a `mailto:` prefix.
    pub email: String,
    /// Registrar name when the record had one.
    pub registrar: Option<String>,
}

/// RDAP client.
pub struct Rdap {
    client: reqwest::Client,
    base_url: String,
    gate: IntervalGate,
}

impl Rdap {
    /// `base_url` is the origin, for example `https://rdap.org`.
    pub fn new(client: reqwest::Client, base_url: impl Into<String>, rate_per_minute: u32) -> Self {
        Self {
            client,
            base_url: base_url.into(),
            gate: IntervalGate::per_minute(rate_per_minute),
        }
    }
}

pub(crate) fn slot(cfg: &Config, client: reqwest::Client) -> Slot {
    if let Err(skipped) = enabled_or_skip(cfg, RDAP_META) {
        return skipped;
    }
    ready(Rdap::new(
        client,
        origin(cfg, RDAP_META.id, DEFAULT_URL),
        rate_of(cfg, RDAP_META),
    ))
}

#[async_trait]
impl Provider for Rdap {
    fn meta(&self) -> ProviderMeta {
        RDAP_META
    }

    async fn lookup(&self, ioc: &Ioc) -> Result<Finding, ProviderError> {
        match self.fetch(ioc).await? {
            Some(body) => Ok(map_body(&body)),
            None => Ok(Finding {
                verdict: Verdict::Unknown,
                confidence: 0,
                detail: "no rdap record".to_string(),
            }),
        }
    }
}

impl Rdap {
    /// Abuse mailbox for an indicator, if RDAP lists one.
    pub(crate) async fn abuse_contact(
        &self,
        ioc: &Ioc,
    ) -> Result<Option<AbuseContact>, ProviderError> {
        let Some(body) = self.fetch(ioc).await? else {
            return Ok(None);
        };
        let mut registrar = None;
        let mut abuse = None;
        walk(&body, &mut registrar, &mut abuse);
        Ok(abuse.map(|email| AbuseContact { email, registrar }))
    }

    async fn fetch(&self, ioc: &Ioc) -> Result<Option<Value>, ProviderError> {
        let path = rdap_path(ioc);
        let url = format!("{}/{}", self.base_url.trim_end_matches('/'), path);
        let response = match http::send(&self.gate, &Secret::new(""), || {
            self.client
                .get(&url)
                .header(reqwest::header::ACCEPT, "application/rdap+json")
                .send()
        })
        .await
        {
            Err(err) if is_not_found(&err) => return Ok(None),
            other => other?,
        };
        let body: Value = response.json().await.map_err(|_| ProviderError::Decode)?;
        Ok(Some(body))
    }
}

fn rdap_path(ioc: &Ioc) -> String {
    match ioc.kind {
        IocType::Ipv4 | IocType::Ipv6 => format!("ip/{}", http::encode_segment(&ioc.value)),
        IocType::Cidr => format!("ip/{}", ioc.value),
        IocType::Domain => format!("domain/{}", http::encode_segment(&ioc.value)),
        IocType::Asn => {
            let number = ioc.value.trim_start_matches(['A', 'S', 'a', 's']);
            format!("autnum/{number}")
        }
        IocType::Url => match host_of(&ioc.value) {
            Some(host) if host.parse::<std::net::IpAddr>().is_ok() => {
                format!("ip/{}", http::encode_segment(&host))
            }
            Some(host) => format!("domain/{}", http::encode_segment(&host)),
            None => format!("domain/{}", http::encode_segment(&ioc.value)),
        },
        _ => format!("domain/{}", http::encode_segment(&ioc.value)),
    }
}

fn map_body(body: &Value) -> Finding {
    let mut registrar = None;
    let mut abuse = None;
    walk(body, &mut registrar, &mut abuse);
    let asn = body
        .get("startAutnum")
        .and_then(Value::as_u64)
        .map(|number| format!("AS{number}"));
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    if registrar.is_none() && abuse.is_none() && asn.is_none() && name.is_none() {
        return Finding {
            verdict: Verdict::Unknown,
            confidence: 0,
            detail: "no registrar or abuse contact".to_string(),
        };
    }
    let mut parts = Vec::new();
    if let Some(name) = name {
        parts.push(format!("name: {name}"));
    }
    if let Some(registrar) = registrar {
        parts.push(format!("registrar: {registrar}"));
    }
    if let Some(abuse) = abuse {
        parts.push(format!("abuse: {abuse}"));
    }
    if let Some(asn) = asn {
        parts.push(format!("asn: {asn}"));
    }
    Finding {
        verdict: Verdict::Unknown,
        confidence: 0,
        detail: clip_detail(&parts.join("; ")),
    }
}

fn walk(value: &Value, registrar: &mut Option<String>, abuse: &mut Option<String>) {
    let Some(entities) = value.get("entities").and_then(Value::as_array) else {
        return;
    };
    for entity in entities {
        let roles: Vec<String> = entity
            .get("roles")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(Value::as_str)
                    .map(|role| role.to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default();
        let (fn_name, email) = vcard(entity);
        if roles.iter().any(|role| role == "registrar") && registrar.is_none() {
            *registrar = fn_name;
        }
        if roles.iter().any(|role| role == "abuse") && abuse.is_none() {
            *abuse = email;
        }
        walk(entity, registrar, abuse);
    }
}

fn vcard(entity: &Value) -> (Option<String>, Option<String>) {
    let mut fn_name = None;
    let mut email = None;
    let Some(rows) = entity.pointer("/vcardArray/1").and_then(Value::as_array) else {
        return (None, None);
    };
    for row in rows {
        let Some(items) = row.as_array() else {
            continue;
        };
        let kind = items.first().and_then(Value::as_str).unwrap_or("");
        let text = items.get(3).and_then(Value::as_str);
        match kind {
            "fn" if fn_name.is_none() => fn_name = text.map(str::to_string),
            "email" if email.is_none() => {
                email = text
                    .map(|value| value.trim_start_matches("mailto:").to_string())
                    .filter(|value| value.contains('@'));
            }
            _ => {}
        }
    }
    (fn_name, email)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::parse_ioc;
    use crate::provider::Provider;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn domain_contact_does_not_vote_and_404_is_unknown() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/domain/evil.example"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "evil.example",
                "entities": [{
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [
                        ["fn", {}, "text", "Example Registrar"]
                    ]],
                    "entities": [{
                        "roles": ["abuse"],
                        "vcardArray": ["vcard", [
                            ["email", {}, "text", "mailto:abuse@example.com"]
                        ]]
                    }]
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/ip/192.0.2.1"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let client = Rdap::new(
            http::client(std::time::Duration::from_secs(5)).unwrap(),
            server.uri(),
            60_000,
        );
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
        let missing = client
            .lookup(&parse_ioc("192.0.2.1").unwrap())
            .await
            .unwrap();
        assert_eq!(missing.detail, "no rdap record");
    }
}
