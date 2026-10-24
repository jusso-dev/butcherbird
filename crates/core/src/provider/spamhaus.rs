//! Spamhaus ZEN and DBL over DNS. No API key.
//!
//! Not listed is a clean vote. PBL return codes (127.0.0.10 and 127.0.0.11)
//! are policy listings, so they vote suspicious rather than malicious.
//! 127.255.255.0/24 means the resolver refused the query. That is unknown,
//! not a listing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::config::Config;
use crate::ioc::{Ioc, IocType};
use crate::score::{Finding, Verdict};

use super::http::IntervalGate;
use super::{
    enabled_or_skip, rate_of, ready, AuthKind, Provider, ProviderError, ProviderMeta, Slot, Tier,
};

const ZEN_ZONE: &str = "zen.spamhaus.org";
const DBL_ZONE: &str = "dbl.spamhaus.org";

/// Spamhaus ZEN provider identity.
pub const SPAMHAUS_ZEN_META: ProviderMeta = ProviderMeta {
    id: "spamhaus-zen",
    types: &[IocType::Ipv4, IocType::Ipv6],
    tier: Tier::Free,
    auth: AuthKind::None,
    default_rate_per_minute: 30,
};

/// Spamhaus DBL provider identity.
pub const SPAMHAUS_DBL_META: ProviderMeta = ProviderMeta {
    id: "spamhaus-dbl",
    types: &[IocType::Domain],
    tier: Tier::Free,
    auth: AuthKind::None,
    default_rate_per_minute: 30,
};

#[async_trait]
trait DnsA: Send + Sync {
    async fn lookup_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, ProviderError>;
}

struct SystemDns;

#[async_trait]
impl DnsA for SystemDns {
    async fn lookup_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, ProviderError> {
        let query = format!("{name}:0");
        let looked =
            tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host(query)).await;
        match looked {
            Err(_) => Err(ProviderError::Transport),
            Ok(Err(err)) if nxdomain(&err) => Ok(Vec::new()),
            Ok(Err(_)) => Err(ProviderError::Transport),
            Ok(Ok(addresses)) => Ok(addresses
                .filter_map(|address| match address.ip() {
                    IpAddr::V4(ip) => Some(ip),
                    IpAddr::V6(_) => None,
                })
                .collect()),
        }
    }
}

fn nxdomain(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::NotFound {
        return true;
    }
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("not known")
        || msg.contains("nxdomain")
        || msg.contains("no such host")
        || msg.contains("nodename nor servname")
        || msg.contains("name or service not known")
}

/// Spamhaus ZEN client.
pub struct SpamhausZen {
    dns: Arc<dyn DnsA>,
    zone: String,
    gate: IntervalGate,
}

/// Spamhaus DBL client.
pub struct SpamhausDbl {
    dns: Arc<dyn DnsA>,
    zone: String,
    gate: IntervalGate,
}

impl SpamhausZen {
    /// `zone` defaults to `zen.spamhaus.org`.
    pub fn new(rate_per_minute: u32) -> Self {
        Self::with_dns(Arc::new(SystemDns), ZEN_ZONE, rate_per_minute)
    }

    fn with_dns(dns: Arc<dyn DnsA>, zone: impl Into<String>, rate_per_minute: u32) -> Self {
        Self {
            dns,
            zone: zone.into(),
            gate: IntervalGate::per_minute(rate_per_minute),
        }
    }
}

impl SpamhausDbl {
    /// `zone` defaults to `dbl.spamhaus.org`.
    pub fn new(rate_per_minute: u32) -> Self {
        Self::with_dns(Arc::new(SystemDns), DBL_ZONE, rate_per_minute)
    }

    fn with_dns(dns: Arc<dyn DnsA>, zone: impl Into<String>, rate_per_minute: u32) -> Self {
        Self {
            dns,
            zone: zone.into(),
            gate: IntervalGate::per_minute(rate_per_minute),
        }
    }
}

pub(crate) fn zen_slot(cfg: &Config) -> Slot {
    if let Err(skipped) = enabled_or_skip(cfg, SPAMHAUS_ZEN_META) {
        return skipped;
    }
    ready(SpamhausZen::new(rate_of(cfg, SPAMHAUS_ZEN_META)))
}

pub(crate) fn dbl_slot(cfg: &Config) -> Slot {
    if let Err(skipped) = enabled_or_skip(cfg, SPAMHAUS_DBL_META) {
        return skipped;
    }
    ready(SpamhausDbl::new(rate_of(cfg, SPAMHAUS_DBL_META)))
}

#[async_trait]
impl Provider for SpamhausZen {
    fn meta(&self) -> ProviderMeta {
        SPAMHAUS_ZEN_META
    }

    async fn lookup(&self, ioc: &Ioc) -> Result<Finding, ProviderError> {
        let Some(name) = zen_name(&ioc.value, &self.zone) else {
            return Ok(Finding {
                verdict: Verdict::Unknown,
                confidence: 0,
                detail: "unsupported address".to_string(),
            });
        };
        self.gate.wait().await;
        let answers = self.dns.lookup_a(&name).await?;
        Ok(classify(&answers))
    }
}

#[async_trait]
impl Provider for SpamhausDbl {
    fn meta(&self) -> ProviderMeta {
        SPAMHAUS_DBL_META
    }

    async fn lookup(&self, ioc: &Ioc) -> Result<Finding, ProviderError> {
        let Some(name) = dbl_name(&ioc.value, &self.zone) else {
            return Ok(Finding {
                verdict: Verdict::Unknown,
                confidence: 0,
                detail: "unsupported name".to_string(),
            });
        };
        self.gate.wait().await;
        let answers = self.dns.lookup_a(&name).await?;
        Ok(classify(&answers))
    }
}

fn zen_name(value: &str, zone: &str) -> Option<String> {
    if let Ok(ip) = value.parse::<Ipv4Addr>() {
        let octets = ip.octets();
        return Some(format!(
            "{}.{}.{}.{}.{zone}",
            octets[3], octets[2], octets[1], octets[0]
        ));
    }
    let ip = value.parse::<Ipv6Addr>().ok()?;
    let expanded: String = ip
        .octets()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let reversed = expanded
        .chars()
        .rev()
        .map(|ch| ch.to_string())
        .collect::<Vec<_>>()
        .join(".");
    Some(format!("{reversed}.{zone}"))
}

fn dbl_name(value: &str, zone: &str) -> Option<String> {
    if value.is_empty() || value.contains(['/', ' ', '\\']) {
        return None;
    }
    Some(format!("{value}.{zone}"))
}

fn classify(answers: &[Ipv4Addr]) -> Finding {
    if answers.is_empty() {
        return Finding {
            verdict: Verdict::Clean,
            confidence: 60,
            detail: "not listed".to_string(),
        };
    }
    let mut malicious = false;
    let mut suspicious = false;
    let mut blocked = false;
    let mut codes = Vec::new();
    for ip in answers {
        codes.push(ip.to_string());
        let octets = ip.octets();
        if octets[0] == 127 && octets[1] == 255 && octets[2] == 255 {
            blocked = true;
            continue;
        }
        if octets[0] != 127 || octets[1] != 0 {
            continue;
        }
        match (octets[2], octets[3]) {
            (0, 10) | (0, 11) => suspicious = true,
            (0, _) | (1, _) => malicious = true,
            _ => suspicious = true,
        }
    }
    let listed = codes.join(", ");
    if malicious {
        return Finding {
            verdict: Verdict::Malicious,
            confidence: 90,
            detail: format!("return {listed}"),
        };
    }
    if suspicious {
        return Finding {
            verdict: Verdict::Suspicious,
            confidence: 60,
            detail: format!("return {listed}"),
        };
    }
    if blocked {
        return Finding {
            verdict: Verdict::Unknown,
            confidence: 0,
            detail: format!("query blocked ({listed})"),
        };
    }
    Finding {
        verdict: Verdict::Unknown,
        confidence: 0,
        detail: format!("return {listed}"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::ioc::parse_ioc;
    use crate::provider::Provider;

    struct MapDns(HashMap<String, Vec<Ipv4Addr>>);

    #[async_trait]
    impl DnsA for MapDns {
        async fn lookup_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, ProviderError> {
            Ok(self.0.get(name).cloned().unwrap_or_default())
        }
    }

    #[test]
    fn names_reverse_the_indicator() {
        assert_eq!(
            zen_name("192.0.2.1", ZEN_ZONE).as_deref(),
            Some("1.2.0.192.zen.spamhaus.org")
        );
        let v6 = zen_name("2001:db8::1", ZEN_ZONE).unwrap();
        assert!(v6.ends_with(".8.b.d.0.1.0.0.2.zen.spamhaus.org"), "{v6}");
        assert!(v6.starts_with("1.0.0.0."), "{v6}");
        assert_eq!(
            dbl_name("evil.example", DBL_ZONE).as_deref(),
            Some("evil.example.dbl.spamhaus.org")
        );
    }

    #[test]
    fn return_codes() {
        assert_eq!(
            classify(&[Ipv4Addr::new(127, 0, 0, 2)]).verdict,
            Verdict::Malicious
        );
        assert_eq!(
            classify(&[Ipv4Addr::new(127, 0, 0, 10)]).verdict,
            Verdict::Suspicious
        );
        assert_eq!(classify(&[]).verdict, Verdict::Clean);
        let blocked = classify(&[Ipv4Addr::new(127, 255, 255, 254)]);
        assert_eq!(blocked.verdict, Verdict::Unknown);
        assert!(blocked.detail.contains("query blocked"));
    }

    #[tokio::test]
    async fn zen_asks_the_reversed_name() {
        let mut map = HashMap::new();
        map.insert(
            "1.2.0.192.zen.spamhaus.org".to_string(),
            vec![Ipv4Addr::new(127, 0, 0, 4)],
        );
        let client = SpamhausZen::with_dns(Arc::new(MapDns(map)), ZEN_ZONE, 60_000);
        let hit = client
            .lookup(&parse_ioc("192.0.2.1").unwrap())
            .await
            .unwrap();
        assert_eq!(hit.verdict, Verdict::Malicious);
        assert_eq!(hit.detail, "return 127.0.0.4");
    }
}
