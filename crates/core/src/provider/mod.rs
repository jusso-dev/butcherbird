//! Pluggable enrichment providers.

mod abuseipdb;
mod http;
mod urlhaus;
mod virustotal;

pub use abuseipdb::{AbuseIpdb, ABUSEIPDB_META};
pub use urlhaus::{Urlhaus, URLHAUS_META};
pub use virustotal::{VirusTotal, VIRUSTOTAL_META};

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
        virustotal::slot(cfg, client),
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
