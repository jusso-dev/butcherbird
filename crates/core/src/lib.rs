//! Indicator parsing, enrichment and scoring for Butcherbird.
//!
//! Lookups send indicators to third-party services. Reporting lives in later
//! crates and is dry-run unless a caller opts in.

#![forbid(unsafe_code)]

pub mod config;
pub mod enrich;
pub mod ioc;
pub mod output;
pub mod provider;
pub mod score;
pub mod secret;

pub use config::Config;
pub use enrich::{exit_code, Engine, IocReport};
pub use ioc::{extract_iocs, load_iocs, parse_ioc, InputFormat, Ioc, IocType};
pub use output::{render, OutputFormat};
pub use provider::{AuthKind, Provider, ProviderError, ProviderMeta, Slot, Tier};
pub use score::{Finding, SourceReport, SourceStatus, Verdict};
pub use secret::Secret;

/// Failures a caller can show without leaking credentials.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Config file, profile, or setting is unusable.
    #[error("config: {0}")]
    Config(String),
    /// Bulk input could not be read or parsed.
    #[error("input: {0}")]
    Input(#[from] ioc::InputError),
    /// HTTP client could not be built.
    #[error("http client: {0}")]
    Client(String),
}
