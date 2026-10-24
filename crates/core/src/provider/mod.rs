//! Pluggable enrichment providers.

mod abuseipdb;
mod greynoise;
mod http;
mod malwarebazaar;
mod openphish;
mod otx;
mod rdap;
mod safebrowsing;
mod shodan;
mod spamhaus;
mod threatfox;
mod urlhaus;
mod urlscan;
mod virustotal;
mod whois;

pub use abuseipdb::{AbuseIpdb, ABUSEIPDB_META};
pub use greynoise::{GreyNoise, GREYNOISE_META};
pub use malwarebazaar::{MalwareBazaar, MALWAREBAZAAR_META};
pub use openphish::{OpenPhish, OPENPHISH_META};
pub use otx::{Otx, OTX_META};
pub use rdap::{Rdap, RDAP_META};
pub use safebrowsing::{SafeBrowsing, SAFEBROWSING_META};
pub use shodan::{Shodan, SHODAN_META};
pub use spamhaus::{SpamhausDbl, SpamhausZen, SPAMHAUS_DBL_META, SPAMHAUS_ZEN_META};
pub use threatfox::{ThreatFox, THREATFOX_META};
pub use urlhaus::{Urlhaus, URLHAUS_META};
pub use urlscan::{Urlscan, URLSCAN_META};
pub use virustotal::{VirusTotal, VIRUSTOTAL_META};
pub use whois::{Whois, WHOIS_META};

pub(crate) use http::{client as http_client, send as http_send, IntervalGate};

use std::sync::Arc;

use async_trait::async_trait;

use crate::config::Config;
use crate::ioc::{Ioc, IocType};
use crate::score::Finding;
use crate::secret::Secret;
use crate::Error;

/// Whether the provider's data set is usable without a paid plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Free API, usually key-gated and rate limited.
    Free,
    /// Paid API.
    Paid,
}

/// How the provider authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    /// No credential.
    None,
    /// API key from the environment or config.
    ApiKey,
}

/// Static description of a provider.
#[derive(Debug, Clone, Copy)]
pub struct ProviderMeta {
    /// Stable id, used in config and output.
    pub id: &'static str,
    /// Indicator types this provider can look up.
    pub types: &'static [IocType],
    /// Free or paid.
    pub tier: Tier,
    /// Credential shape.
    pub auth: AuthKind,
    /// Default client-side budget, requests per minute.
    pub default_rate_per_minute: u32,
}

/// One configured provider, or a reason it will not be called.
#[derive(Clone)]
pub enum Slot {
    /// Live provider.
    Ready(Arc<dyn Provider>),
    /// Recorded on matching indicators and not called.
    Skipped {
        /// Provider identity.
        meta: ProviderMeta,
        /// Why it was skipped.
        reason: String,
    },
}

impl Slot {
    /// Identity, including for skipped providers.
    pub fn meta(&self) -> ProviderMeta {
        match self {
            Self::Ready(provider) => provider.meta(),
            Self::Skipped { meta, .. } => *meta,
        }
    }

    /// Whether this slot should appear in the breakdown for `kind`.
    pub fn supports(&self, kind: IocType) -> bool {
        self.meta().types.contains(&kind)
    }

    /// Skip reason when this slot will not call out.
    pub fn skip_reason(&self) -> Option<&str> {
        match self {
            Self::Skipped { reason, .. } => Some(reason),
            Self::Ready(_) => None,
        }
    }
}

/// Enrichment source. Implementations must not put API keys in errors.
#[async_trait]
pub trait Provider: Send + Sync {
    /// Identity and capabilities.
    fn meta(&self) -> ProviderMeta;

    /// Look up one indicator. The caller has already checked the type.
    async fn lookup(&self, ioc: &Ioc) -> Result<Finding, ProviderError>;
}

/// Provider failure safe to print.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// The key was rejected.
    #[error("authentication failed")]
    Auth,
    /// The provider kept returning 429.
    #[error("rate limit exceeded")]
    RateLimited,
    /// HTTP status other than success, with a redacted body.
    #[error("http {status}: {body}")]
    Http {
        /// Status code.
        status: u16,
        /// Truncated, redacted body.
        body: String,
    },
    /// DNS, TLS, or connection failure. The message omits the URL.
    #[error("transport error")]
    Transport,
    /// The body was not the documented shape.
    #[error("invalid response")]
    Decode,
}

/// Build the built-in providers, skipping ones that are disabled or have no key.
pub fn builtin_slots(cfg: &Config) -> Result<Vec<Slot>, Error> {
    let client = http::client(cfg.timeout)?;
    Ok(vec![
        abuseipdb::slot(cfg, client.clone()),
        urlhaus::slot(cfg, client.clone()),
        virustotal::slot(cfg, client.clone()),
        otx::slot(cfg, client.clone()),
        greynoise::slot(cfg, client.clone()),
        shodan::slot(cfg, client.clone()),
        urlscan::slot(cfg, client.clone()),
        threatfox::slot(cfg, client.clone()),
        malwarebazaar::slot(cfg, client.clone()),
        safebrowsing::slot(cfg, client.clone()),
        openphish::slot(cfg, client.clone()),
        spamhaus::zen_slot(cfg),
        spamhaus::dbl_slot(cfg),
        rdap::slot(cfg, client),
        whois::slot(cfg),
    ])
}

pub(crate) fn ready<P: Provider + 'static>(provider: P) -> Slot {
    Slot::Ready(Arc::new(provider))
}

pub(crate) fn skipped(meta: ProviderMeta, reason: impl Into<String>) -> Slot {
    Slot::Skipped {
        meta,
        reason: reason.into(),
    }
}

pub(crate) fn configured_rate(meta: ProviderMeta, configured: Option<u32>) -> u32 {
    match configured {
        Some(0) | None => meta.default_rate_per_minute,
        Some(rate) => rate,
    }
}

pub(crate) fn origin(cfg: &Config, id: &str, default: &str) -> String {
    cfg.provider(id)
        .base_url
        .clone()
        .unwrap_or_else(|| default.to_string())
}

pub(crate) fn rate_of(cfg: &Config, meta: ProviderMeta) -> u32 {
    configured_rate(meta, cfg.provider(meta.id).rate_per_minute)
}

/// Keyless providers still honour `enabled = false`.
pub(crate) fn enabled_or_skip(cfg: &Config, meta: ProviderMeta) -> Result<(), Slot> {
    if cfg.provider(meta.id).enabled {
        Ok(())
    } else {
        Err(skipped(meta, "disabled"))
    }
}

pub(crate) fn is_not_found(err: &ProviderError) -> bool {
    matches!(err, ProviderError::Http { status: 404, .. })
}

/// Host from a URL, without brackets on IPv6.
pub(crate) fn host_of(value: &str) -> Option<String> {
    let url = url::Url::parse(value).ok()?;
    url.host_str()
        .map(|host| host.trim_matches(['[', ']']).to_string())
}

pub(crate) fn clip_detail(detail: &str) -> String {
    let mut clipped: String = detail.chars().take(180).collect();
    if detail.chars().count() > 180 {
        clipped.push('…');
    }
    clipped
}

/// Key-gated providers share this skip decision.
pub(crate) fn key_or_skip(cfg: &Config, meta: ProviderMeta) -> Result<&Secret, Slot> {
    let settings = cfg.provider(meta.id);
    if !settings.enabled {
        return Err(skipped(meta, "disabled"));
    }
    match settings.api_key.as_ref() {
        Some(key) => Ok(key),
        None => {
            let env = settings
                .api_key_env
                .as_deref()
                .unwrap_or("the provider env var");
            Err(skipped(meta, format!("missing api key ({env})")))
        }
    }
}
